//! Self-update.
//!
//! 1. The server offers a version. The agent refuses unless it's newer than itself, the
//!    agent was built with a release key (`RMM_UPDATE_PUBKEY`), and it runs as a service.
//! 2. The binary is pulled in chunks over the agent socket into `rmm-agent.new` next to the
//!    running binary, then its SHA-256 and ed25519 signature are checked.
//! 3. Once no jobs are running (or after [`MAX_IDLE_WAIT`]), the current binary is copied to
//!    `rmm-agent.old` and that copy is started as a watchdog outside the agent's service
//!    (a transient systemd unit, or a detached process on Windows), so restarting the
//!    service doesn't kill it.
//! 4. The watchdog swaps the new binary in and restarts the service. The new version marks
//!    the update confirmed once it has authenticated to the server. Without that within
//!    [`CONFIRM_TIMEOUT`], the watchdog restores the old binary and restarts it again.
//!
//! Progress lives in `update.toml` next to the agent config, so it survives the restarts.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use rmm_proto::update::{current_platform, is_newer, signed_message};
use rmm_proto::{AgentMsg, UpdateState};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::collect::AGENT_VERSION;

/// Release public key (hex), fixed at build time. Without one, updates are refused.
/// (Empty counts as unset: Docker build args are always defined.)
pub const PUBKEY: Option<&str> = match option_env!("RMM_UPDATE_PUBKEY") {
    Some(k) if !k.is_empty() => Some(k),
    _ => None,
};

pub const CONFIRM_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_IDLE_WAIT: Duration = Duration::from_secs(30 * 60);
const MAX_PATCH_WAIT: Duration = Duration::from_secs(4 * 3600);
const MAX_SIZE: u64 = 200 * 1024 * 1024;
#[cfg(target_os = "linux")]
const UNIT: &str = "rmm-agent.service";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// The watchdog is swapping binaries and waiting for the new one to check in.
    Pending,
    /// The new version authenticated to the server.
    Confirmed,
    /// The new version never checked in; the old one was restored.
    RolledBack,
}

/// `update.toml`: shared between the old agent, the watchdog and the new agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    pub from_version: String,
    pub to_version: String,
    pub phase: Phase,
    #[serde(default)]
    pub detail: Option<String>,
    pub exe: PathBuf,
    pub staged: PathBuf,
    pub backup: PathBuf,
}

impl State {
    pub fn path(config: &Path) -> PathBuf {
        config.with_file_name("update.toml")
    }

    pub fn load(config: &Path) -> Result<Option<Self>> {
        match std::fs::read_to_string(Self::path(config)) {
            Ok(raw) => Ok(Some(toml::from_str(&raw).context("parsing update.toml")?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self, config: &Path) -> Result<()> {
        let path = Self::path(config);
        let tmp = path.with_extension("toml.tmp");
        create_private(&tmp, 0o600)?.write_all(toml::to_string_pretty(self)?.as_bytes())?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    /// Before the watchdog acts on the paths (it copies `backup` over `exe` and runs from
    /// `backup`): they must be exactly what [`handoff`] writes, the staged and backup
    /// siblings of `exe`, and `running` (the watchdog's own binary, the backup copy) must be
    /// that backup. That ties `exe` to the binary this agent is installed as. The file sits
    /// in a root/SYSTEM-only directory; this is defence in depth.
    fn check_paths(&self, running: &Path) -> Result<()> {
        let exe = crate::fsutil::checked_absolute(&self.exe).context("update.toml: exe")?;
        if exe.file_name().is_none() {
            bail!("update.toml: exe {} isn't a file name", exe.display());
        }
        if self.staged != sibling(&exe, "new") {
            bail!("update.toml: staged {} isn't {}", self.staged.display(), sibling(&exe, "new").display());
        }
        if self.backup != sibling(&exe, "old") {
            bail!("update.toml: backup {} isn't {}", self.backup.display(), sibling(&exe, "old").display());
        }
        if running != self.backup {
            bail!("update.toml: the watchdog runs as {}, not as the backup {}", running.display(), self.backup.display());
        }
        Ok(())
    }

    fn clear(config: &Path) {
        let _ = std::fs::remove_file(Self::path(config));
    }
}

struct Download {
    version: String,
    size: u64,
    sha256: String,
    signature: String,
    path: PathBuf,
    file: std::fs::File,
    received: u64,
    hasher: Sha256,
}

pub struct Updater {
    config: PathBuf,
    tracker: std::sync::Arc<crate::jobs::Tracker>,
    patches: std::sync::Arc<crate::patch::Manager>,
    download: Mutex<Option<Download>>,
    /// Set from the offer until the restart (or a failure), so offers don't pile up.
    busy: AtomicBool,
    link: Mutex<Option<mpsc::Sender<AgentMsg>>>,
}

impl Updater {
    pub fn new(config: PathBuf, tracker: std::sync::Arc<crate::jobs::Tracker>, patches: std::sync::Arc<crate::patch::Manager>) -> Self {
        Self { config, tracker, patches, download: Mutex::default(), busy: AtomicBool::new(false), link: Mutex::default() }
    }

    fn link(&self) -> Option<mpsc::Sender<AgentMsg>> {
        self.link.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    async fn status(&self, version: &str, state: UpdateState, detail: Option<String>) {
        if let Some(tx) = self.link() {
            let _ = tx.send(AgentMsg::UpdateStatus { version: version.into(), state, detail }).await;
        }
    }

    async fn fail(&self, version: &str, why: String) {
        warn!(version, "update failed: {why}");
        self.busy.store(false, Ordering::SeqCst);
        self.status(version, UpdateState::Failed, Some(why)).await;
    }

    /// New connection. Reports how a previous update went, confirming it if this process is
    /// the version the watchdog is waiting for.
    pub async fn attach(&self, tx: mpsc::Sender<AgentMsg>) {
        *self.link.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);
        let state = match State::load(&self.config) {
            Ok(Some(s)) => s,
            Ok(None) => return,
            Err(e) => {
                warn!("reading update state: {e:#}");
                State::clear(&self.config);
                return;
            }
        };
        match state.phase {
            Phase::Pending if state.to_version == AGENT_VERSION => {
                let confirmed = State { phase: Phase::Confirmed, ..state.clone() };
                if let Err(e) = confirmed.save(&self.config) {
                    warn!("confirming update: {e:#}");
                    return;
                }
                info!(from = %state.from_version, to = %state.to_version, "update confirmed");
                self.status(&state.to_version, UpdateState::Completed, Some(format!("updated from {}", state.from_version))).await;
            }
            // The watchdog is mid-swap, or we are the old version it's about to replace.
            Phase::Pending => {}
            Phase::RolledBack => {
                self.status(&state.to_version, UpdateState::RolledBack, state.detail.clone()).await;
                State::clear(&self.config);
            }
            // The watchdog has seen the confirmation (or died); nothing left to report.
            Phase::Confirmed => {
                if state.to_version == AGENT_VERSION {
                    State::clear(&self.config);
                }
            }
        }
    }

    /// Connection gone: an unfinished download can't continue on the next one.
    pub fn detach(&self) {
        *self.link.lock().unwrap_or_else(|e| e.into_inner()) = None;
        if let Some(d) = self.download.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = std::fs::remove_file(&d.path);
            self.busy.store(false, Ordering::SeqCst);
        }
    }

    pub async fn offer(&self, version: String, size: u64, sha256: String, signature: String) {
        if self.busy.swap(true, Ordering::SeqCst) {
            return; // already updating
        }
        if let Err(e) = self.start(&version, size, sha256, signature) {
            return self.fail(&version, format!("{e:#}")).await;
        }
        info!(%version, size, "downloading update");
        self.status(&version, UpdateState::Downloading, None).await;
        if let Some(tx) = self.link() {
            let _ = tx.send(AgentMsg::UpdateFetch { version, offset: 0 }).await;
        }
    }

    fn start(&self, version: &str, size: u64, sha256: String, signature: String) -> Result<()> {
        if PUBKEY.is_none() {
            bail!("this agent was built without a release key (RMM_UPDATE_PUBKEY), so it can't verify updates");
        }
        if !is_newer(version, AGENT_VERSION) {
            bail!("{version} is not newer than the running {AGENT_VERSION}");
        }
        if size == 0 || size > MAX_SIZE {
            bail!("implausible update size {size}");
        }
        supervised()?;
        let exe = current_exe()?;
        let path = sibling(&exe, "new");
        let file = create_private(&path, 0o700).with_context(|| format!("creating {}", path.display()))?;
        *self.download.lock().unwrap_or_else(|e| e.into_inner()) = Some(Download {
            version: version.into(),
            size,
            sha256,
            signature,
            path,
            file,
            received: 0,
            hasher: Sha256::new(),
        });
        Ok(())
    }

    pub async fn chunk(self: &std::sync::Arc<Self>, version: String, offset: u64, data: Vec<u8>) {
        enum Next {
            Fetch(u64),
            Done(Box<Download>),
            Fail(String),
        }
        let next = {
            let mut guard = self.download.lock().unwrap_or_else(|e| e.into_inner());
            let Some(d) = guard.as_mut().filter(|d| d.version == version) else { return };
            if offset != d.received || data.is_empty() || d.received + data.len() as u64 > d.size {
                let _ = std::fs::remove_file(&d.path);
                guard.take();
                Next::Fail(format!("unexpected chunk at offset {offset}"))
            } else if let Err(e) = d.file.write_all(&data) {
                let _ = std::fs::remove_file(&d.path);
                guard.take();
                Next::Fail(format!("writing update: {e}"))
            } else {
                d.hasher.update(&data);
                d.received += data.len() as u64;
                if d.received < d.size { Next::Fetch(d.received) } else { Next::Done(Box::new(guard.take().expect("present"))) }
            }
        };
        match next {
            Next::Fetch(offset) => {
                if let Some(tx) = self.link() {
                    let _ = tx.send(AgentMsg::UpdateFetch { version, offset }).await;
                }
            }
            Next::Fail(why) => self.fail(&version, why).await,
            Next::Done(d) => {
                if let Err(e) = verify(&d) {
                    let _ = std::fs::remove_file(&d.path);
                    return self.fail(&version, format!("{e:#}")).await;
                }
                info!(%version, "update downloaded and verified");
                let me = self.clone();
                tokio::spawn(async move { me.install(*d).await });
            }
        }
    }

    async fn install(&self, d: Download) {
        let tracker = &self.tracker;
        // Jobs get MAX_IDLE_WAIT. A patch install is waited out (up to MAX_PATCH_WAIT):
        // restarting the service would kill the package manager halfway through.
        let blocked = |started: Instant| async move {
            (tracker.running().await > 0 && started.elapsed() < MAX_IDLE_WAIT)
                || (self.patches.busy().await && started.elapsed() < MAX_PATCH_WAIT)
        };
        let started = Instant::now();
        if blocked(started).await {
            self.status(&d.version, UpdateState::Waiting, Some("waiting for running jobs and patch installs to finish".into())).await;
            while blocked(started).await {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
        self.status(&d.version, UpdateState::Applying, None).await;
        if let Err(e) = handoff(&self.config, &d) {
            let _ = std::fs::remove_file(&d.path);
            return self.fail(&d.version, format!("{e:#}")).await;
        }
        // The watchdog restarts the service shortly; this process ends with it.
        info!(version = %d.version, "handed over to the update watchdog");
    }
}

fn verify(d: &Download) -> Result<()> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let actual = hex::encode(d.hasher.clone().finalize());
    if actual != d.sha256.to_ascii_lowercase() {
        bail!("checksum mismatch: got {actual}, expected {}", d.sha256);
    }
    let pk: [u8; 32] = hex::decode(PUBKEY.unwrap_or_default().trim())
        .ok()
        .and_then(|v| v.try_into().ok())
        .context("built-in release key is malformed")?;
    let pk = VerifyingKey::from_bytes(&pk).context("built-in release key is invalid")?;
    let sig: [u8; 64] = hex::decode(&d.signature).ok().and_then(|v| v.try_into().ok()).context("malformed signature")?;
    pk.verify(&signed_message(&current_platform(), &d.version, &actual), &Signature::from_bytes(&sig))
        .context("signature check failed: this binary wasn't signed by the release key")?;
    Ok(())
}

/// Stage the new binary and start the watchdog.
fn handoff(config: &Path, d: &Download) -> Result<()> {
    d.file.sync_all()?;
    let exe = current_exe()?;
    let backup = sibling(&exe, "old");
    copy_private(&exe, &backup).with_context(|| format!("backing up to {}", backup.display()))?;
    make_executable(&backup)?;
    make_executable(&d.path)?;
    State {
        from_version: AGENT_VERSION.into(),
        to_version: d.version.clone(),
        phase: Phase::Pending,
        detail: None,
        exe,
        staged: d.path.clone(),
        backup: backup.clone(),
    }
    .save(config)?;
    launch_watchdog(&backup, config)
}

/// `rmm-agent update-watchdog`, running from the backup copy of the old binary.
pub fn watchdog(config: &Path) -> Result<()> {
    let state = State::load(config)?.context("no update in progress")?;
    if state.phase != Phase::Pending {
        bail!("update state is {:?}, not pending", state.phase);
    }
    state.check_paths(&current_exe()?)?;
    info!(from = %state.from_version, to = %state.to_version, "watchdog: swapping in the new version");
    // Let the old agent send its last status before the restart cuts it off.
    std::thread::sleep(Duration::from_secs(2));
    if let Err(e) = swap_in(&state.staged, &state.exe) {
        return roll_back(config, state, format!("installing the new binary failed: {e:#}"));
    }
    let deadline = Instant::now() + CONFIRM_TIMEOUT;
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_secs(2));
        if State::load(config).ok().flatten().is_some_and(|s| s.phase == Phase::Confirmed) {
            info!(version = %state.to_version, "watchdog: new version confirmed");
            return Ok(());
        }
    }
    let why = format!("{} didn't connect to the server within {} s", state.to_version, CONFIRM_TIMEOUT.as_secs());
    roll_back(config, state, why)
}

fn roll_back(config: &Path, state: State, why: String) -> Result<()> {
    warn!("watchdog: rolling back to {}: {why}", state.from_version);
    // Recorded first: the restored agent reports it as soon as it connects.
    State { phase: Phase::RolledBack, detail: Some(why), ..state.clone() }.save(config)?;
    restore(&state.backup, &state.exe)
}

fn sibling(exe: &Path, tag: &str) -> PathBuf {
    let stem = exe.file_stem().and_then(|s| s.to_str()).unwrap_or("rmm-agent");
    match exe.extension().and_then(|e| e.to_str()) {
        Some(ext) => exe.with_file_name(format!("{stem}.{tag}.{ext}")),
        None => exe.with_file_name(format!("{stem}.{tag}")),
    }
}

fn current_exe() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("locating the agent binary")?;
    Ok(std::fs::canonicalize(&exe).unwrap_or(exe))
}

/// Restart-safe updates need a supervisor that brings the service back.
fn supervised() -> Result<()> {
    #[cfg(target_os = "linux")]
    if std::env::var_os("INVOCATION_ID").is_none() {
        bail!("not running under systemd; install the agent as a service (or update it by hand)");
    }
    #[cfg(windows)]
    if !crate::service::running_as_service() {
        bail!("not running as the Windows service; update it by hand");
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    bail!("self-update isn't supported on this OS yet");
    #[allow(unreachable_code)]
    Ok(())
}

/// A fresh file at `path` (whatever was there is removed first, and never written through),
/// created with `mode` on unix.
fn create_private(path: &Path, mode: u32) -> std::io::Result<std::fs::File> {
    let _ = std::fs::remove_file(path);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    opts.open(path)
}

/// Copies `from` to a fresh file at `to` (see [`create_private`]).
fn copy_private(from: &Path, to: &Path) -> std::io::Result<()> {
    let mut src = std::fs::File::open(from)?;
    let mut dst = create_private(to, 0o700)?;
    std::io::copy(&mut src, &mut dst)?;
    dst.sync_all()
}

fn make_executable(_path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(_path, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn launch_watchdog(backup: &Path, config: &Path) -> Result<()> {
    // A transient unit of its own: `systemctl restart rmm-agent` kills everything in the
    // agent's cgroup, which would include a plain child process.
    let unit = format!("rmm-agent-update-{}", chrono::Utc::now().format("%Y%m%d%H%M%S"));
    let st = std::process::Command::new("systemd-run")
        .args(["--unit", &unit, "--collect", "--quiet", "--description=RMM agent update watchdog"])
        .arg(backup)
        .arg("--config")
        .arg(config)
        .arg("update-watchdog")
        .status()
        .context("running systemd-run")?;
    if !st.success() {
        bail!("systemd-run failed: {st}");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn systemctl(args: &[&str]) -> Result<()> {
    let st = std::process::Command::new("systemctl").args(args).status().context("running systemctl")?;
    if !st.success() {
        bail!("systemctl {} failed: {st}", args.join(" "));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn swap_in(staged: &Path, exe: &Path) -> Result<()> {
    std::fs::rename(staged, exe).with_context(|| format!("moving {} to {}", staged.display(), exe.display()))?;
    systemctl(&["restart", UNIT])
}

#[cfg(target_os = "linux")]
fn restore(backup: &Path, exe: &Path) -> Result<()> {
    // Copy, then rename over: the running watchdog is the backup itself.
    let tmp = sibling(exe, "restore");
    copy_private(backup, &tmp).with_context(|| format!("copying {} to {}", backup.display(), tmp.display()))?;
    make_executable(&tmp)?;
    std::fs::rename(&tmp, exe)?;
    systemctl(&["restart", UNIT])
}

#[cfg(windows)]
fn launch_watchdog(backup: &Path, config: &Path) -> Result<()> {
    use std::os::windows::process::CommandExt;
    // Detached, in its own process group: stopping the service doesn't touch it.
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    std::process::Command::new(backup)
        .arg("--config")
        .arg(config)
        .arg("update-watchdog")
        .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("starting the update watchdog")?;
    Ok(())
}

#[cfg(windows)]
fn swap_in(staged: &Path, exe: &Path) -> Result<()> {
    // A running .exe can't be replaced, so stop the service first.
    crate::service::stop_service()?;
    // A remote desktop helper (a separate process running this .exe) notices the service is
    // gone within a fraction of a second; until it exits the file is still in use.
    let mut moved = std::fs::rename(staged, exe);
    for _ in 0..20 {
        if moved.is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
        moved = std::fs::rename(staged, exe);
    }
    let moved = moved.with_context(|| format!("moving {} to {}", staged.display(), exe.display()));
    crate::service::start_service()?;
    moved
}

#[cfg(windows)]
fn restore(backup: &Path, exe: &Path) -> Result<()> {
    crate::service::stop_service()?;
    let mut copied = std::fs::copy(backup, exe).map(|_| ());
    for _ in 0..20 {
        if copied.is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
        copied = std::fs::copy(backup, exe).map(|_| ());
    }
    let copied = copied.with_context(|| format!("restoring {}", exe.display()));
    crate::service::start_service()?;
    copied
}

#[cfg(not(any(target_os = "linux", windows)))]
fn launch_watchdog(_: &Path, _: &Path) -> Result<()> {
    bail!("self-update isn't supported on this OS yet")
}
#[cfg(not(any(target_os = "linux", windows)))]
fn swap_in(_: &Path, _: &Path) -> Result<()> {
    bail!("self-update isn't supported on this OS yet")
}
#[cfg(not(any(target_os = "linux", windows)))]
fn restore(_: &Path, _: &Path) -> Result<()> {
    bail!("self-update isn't supported on this OS yet")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sibling_names() {
        assert_eq!(sibling(Path::new("/usr/local/bin/rmm-agent"), "new"), Path::new("/usr/local/bin/rmm-agent.new"));
        assert_eq!(sibling(Path::new("C:/RMM/rmm-agent.exe"), "old"), Path::new("C:/RMM/rmm-agent.old.exe"));
    }

    #[test]
    fn state_roundtrip() {
        let dir = std::env::temp_dir().join(format!("rmm-update-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("agent.toml");
        assert!(State::load(&cfg).unwrap().is_none());
        let s = State {
            from_version: "0.1.0".into(),
            to_version: "0.2.0".into(),
            phase: Phase::Pending,
            detail: None,
            exe: "/usr/local/bin/rmm-agent".into(),
            staged: "/usr/local/bin/rmm-agent.new".into(),
            backup: "/usr/local/bin/rmm-agent.old".into(),
        };
        s.save(&cfg).unwrap();
        let back = State::load(&cfg).unwrap().unwrap();
        assert_eq!(back.phase, Phase::Pending);
        assert_eq!(back.to_version, "0.2.0");
        State::clear(&cfg);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn watchdog_only_acts_on_the_paths_handoff_writes() {
        let exe = if cfg!(windows) { PathBuf::from("C:\\RMM\\rmm-agent.exe") } else { PathBuf::from("/usr/local/bin/rmm-agent") };
        let good = State {
            from_version: "0.1.0".into(),
            to_version: "0.2.0".into(),
            phase: Phase::Pending,
            detail: None,
            staged: sibling(&exe, "new"),
            backup: sibling(&exe, "old"),
            exe: exe.clone(),
        };
        let running = good.backup.clone();
        good.check_paths(&running).unwrap();
        assert!(good.check_paths(&exe).is_err(), "the watchdog runs from the backup");
        let elsewhere = if cfg!(windows) { PathBuf::from("C:\\Users\\x\\rmm-agent.old.exe") } else { PathBuf::from("/tmp/rmm-agent.old") };
        let bad = [
            State { backup: elsewhere.clone(), ..good.clone() },
            State { staged: elsewhere.with_file_name("x"), ..good.clone() },
            State { exe: "rmm-agent".into(), staged: "rmm-agent.new".into(), backup: "rmm-agent.old".into(), ..good.clone() },
            State { exe: exe.parent().unwrap().join("..").join("bin").join("rmm-agent"), ..good.clone() },
        ];
        for s in bad {
            assert!(s.check_paths(&s.backup.clone()).is_err() && s.check_paths(&running).is_err(), "{s:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn state_and_restore_copies_dont_write_through_links() {
        let dir = std::env::temp_dir().join(format!("rmm-update-links-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("victim");
        std::fs::write(&victim, b"precious").unwrap();
        let cfg = dir.join("agent.toml");
        std::os::unix::fs::symlink(&victim, State::path(&cfg).with_extension("toml.tmp")).unwrap();
        let s = State {
            from_version: "0.1.0".into(),
            to_version: "0.2.0".into(),
            phase: Phase::Pending,
            detail: None,
            exe: dir.join("rmm-agent"),
            staged: dir.join("rmm-agent.new"),
            backup: dir.join("rmm-agent.old"),
        };
        s.save(&cfg).unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"precious");
        assert_eq!(State::load(&cfg).unwrap().unwrap().to_version, "0.2.0");

        std::fs::write(&s.backup, b"old agent").unwrap();
        let tmp = sibling(&s.exe, "restore");
        std::os::unix::fs::symlink(&victim, &tmp).unwrap();
        copy_private(&s.backup, &tmp).unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"precious");
        assert_eq!(std::fs::read(&tmp).unwrap(), b"old agent");
        assert!(!std::fs::symlink_metadata(&tmp).unwrap().file_type().is_symlink());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn download(dir: &Path, body: &[u8], version: &str, signature: String) -> Download {
        let path = dir.join("rmm-agent.new");
        let mut hasher = Sha256::new();
        hasher.update(body);
        Download {
            version: version.into(),
            size: body.len() as u64,
            sha256: hex::encode(Sha256::digest(body)),
            signature,
            file: std::fs::File::create(&path).unwrap(),
            path,
            received: body.len() as u64,
            hasher,
        }
    }

    /// Only meaningful when built with a key; otherwise checks that nothing verifies.
    #[test]
    fn verify_requires_valid_signature() {
        let dir = std::env::temp_dir().join(format!("rmm-update-verify-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let d = download(&dir, b"new agent", "9.9.9", "00".repeat(64));
        assert!(verify(&d).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
