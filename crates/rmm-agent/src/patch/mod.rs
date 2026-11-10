//! Patch management: scanning for and installing OS updates.
//!
//! Each OS's update mechanism sits behind [`PatchProvider`]: the Windows Update Agent (with
//! PSWindowsUpdate as a fallback), apt, dnf/yum, pacman and softwareupdate. Providers are
//! synchronous and run on blocking threads, because package managers and the WUA COM API
//! are blocking by nature.
//!
//! The [`Manager`] runs one operation at a time (package managers lock anyway). Install
//! results are kept until the server acknowledges them and resent after reconnects, like job
//! results; the run ids are listed in `Auth` so the server knows which installs are still
//! alive. After every install the agent rescans and sends the fresh list unasked.

#[cfg(any(target_os = "linux", test))]
mod apt;
pub(crate) mod cmd;
#[cfg(debug_assertions)]
mod fake;
#[cfg(any(target_os = "linux", test))]
mod dnf;
#[cfg(any(target_os = "linux", test))]
mod pacman;
#[cfg(any(target_os = "macos", test))]
mod softwareupdate;
mod winparse;
#[cfg(windows)]
mod wua;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use rmm_proto::AgentMsg;
use rmm_proto::patch::{OUTPUT_MAX, PatchItemResult, PatchOutcome, PatchStage, PatchUpdate, RebootPolicy, tail};
use tokio::sync::mpsc;
use tracing::{info, warn};
use uuid::Uuid;

pub use cmd::Log;

/// Unacknowledged results are dropped after this long (an older server never acks).
const KEEP_UNACKED: Duration = Duration::from_secs(7 * 24 * 3600);
/// How long to wait for the server to store a result before rebooting anyway.
const ACK_BEFORE_REBOOT: Duration = Duration::from_secs(60);

/// Progress callback handed to providers: stage, message, overall percent.
pub type Progress<'a> = &'a (dyn Fn(PatchStage, Option<String>, Option<u8>) + Send + Sync);

pub struct Installed {
    /// Per-update results. Empty means "work it out from a rescan": anything requested that
    /// is no longer offered was installed.
    pub results: Vec<PatchItemResult>,
    pub reboot_required: bool,
}

pub trait PatchProvider: Send + Sync {
    /// Reported to the server: `apt`, `dnf`, `pacman`, `softwareupdate`, `wua`...
    fn name(&self) -> &'static str;

    /// Installs everything or nothing; the requested ids are ignored (pacman).
    fn all_or_nothing(&self) -> bool {
        false
    }

    /// Available updates. `refresh` first updates package lists / contacts the update
    /// service; the rescan right after an install skips that.
    fn scan(&self, log: &Log, progress: Progress, refresh: bool) -> Result<Vec<PatchUpdate>>;

    fn install(&self, ids: &[String], log: &Log, progress: Progress) -> Result<Installed>;

    /// A reboot is pending from an earlier install.
    fn reboot_pending(&self) -> bool;
}

/// Picks the provider for this machine, if any.
pub fn detect() -> Option<Box<dyn PatchProvider>> {
    #[cfg(debug_assertions)]
    if let Some(path) = std::env::var_os("RMM_PATCH_FAKE") {
        return Some(Box::new(fake::FileProvider(path.into())));
    }
    #[cfg(windows)]
    {
        Some(wua::provider())
    }
    #[cfg(target_os = "macos")]
    {
        Some(Box::new(softwareupdate::SoftwareUpdate))
    }
    #[cfg(target_os = "linux")]
    {
        if cmd::which("apt-get") {
            Some(Box::new(apt::Apt))
        } else if cmd::which("dnf") || cmd::which("dnf5") {
            Some(Box::new(dnf::Dnf::new()))
        } else if cmd::which("yum") {
            Some(Box::new(dnf::Dnf::yum()))
        } else if cmd::which("pacman") {
            Some(Box::new(pacman::Pacman))
        } else {
            None
        }
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        None
    }
}

struct Pending {
    outcome: PatchOutcome,
    /// None while the install is still running.
    finished: Option<Instant>,
}

pub struct Manager {
    provider: Option<Arc<dyn PatchProvider>>,
    /// One scan or install at a time.
    op: tokio::sync::Mutex<()>,
    /// Scans waiting for `op`; further requests while one waits are folded into it.
    scan_waiting: std::sync::atomic::AtomicBool,
    runs: tokio::sync::Mutex<HashMap<Uuid, Pending>>,
    link: std::sync::Mutex<Option<mpsc::Sender<AgentMsg>>>,
}

impl Manager {
    pub fn new() -> Self {
        let provider: Option<Arc<dyn PatchProvider>> = detect().map(Arc::from);
        match &provider {
            Some(p) => info!(provider = p.name(), "patch management available"),
            None => info!("no supported package manager; patch scans will report an error"),
        }
        Self::with_provider(provider)
    }

    fn with_provider(provider: Option<Arc<dyn PatchProvider>>) -> Self {
        Manager {
            provider,
            op: Default::default(),
            scan_waiting: Default::default(),
            runs: Default::default(),
            link: Default::default(),
        }
    }

    fn link(&self) -> Option<mpsc::Sender<AgentMsg>> {
        self.link.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    async fn emit(&self, msg: AgentMsg) {
        if let Some(tx) = self.link() {
            let _ = tx.send(msg).await;
        }
    }

    /// Installs still held (running or unacknowledged), for `Auth`.
    pub async fn ids(&self) -> Vec<Uuid> {
        let mut runs = self.runs.lock().await;
        prune(&mut runs);
        runs.keys().copied().collect()
    }

    /// Whether an install is running (the self-updater waits for it).
    pub async fn busy(&self) -> bool {
        self.runs.lock().await.values().any(|p| p.finished.is_none())
    }

    /// New connection: resend finished results the server hasn't stored.
    pub async fn attach(&self, tx: mpsc::Sender<AgentMsg>) {
        let runs = self.runs.lock().await;
        for p in runs.values().filter(|p| p.finished.is_some()) {
            let _ = tx.send(AgentMsg::PatchResult(p.outcome.clone())).await;
        }
        *self.link.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);
        drop(runs);
    }

    pub fn detach(&self) {
        *self.link.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    pub async fn ack(&self, run_id: Uuid) {
        let mut runs = self.runs.lock().await;
        if runs.get(&run_id).is_some_and(|p| p.finished.is_some()) {
            runs.remove(&run_id);
        }
    }

    async fn acked(&self, run_id: Uuid) -> bool {
        !self.runs.lock().await.contains_key(&run_id)
    }

    fn name(&self) -> String {
        self.provider.as_ref().map_or("none", |p| p.name()).to_string()
    }

    /// Scans and sends the result. Runs after any operation in progress.
    pub async fn scan(self: Arc<Self>, request_id: Option<Uuid>) {
        use std::sync::atomic::Ordering;
        if self.scan_waiting.swap(true, Ordering::SeqCst) {
            // Another scan is already waiting its turn; it will answer for both.
            return;
        }
        let _op = self.op.lock().await;
        self.scan_waiting.store(false, Ordering::SeqCst);
        let msg = self.scan_now(request_id, true).await;
        self.emit(msg).await;
    }

    /// Needs `op` held.
    async fn scan_now(&self, request_id: Option<Uuid>, refresh: bool) -> AgentMsg {
        let provider = self.name();
        let Some(p) = self.provider.clone() else {
            return AgentMsg::PatchScanResult {
                request_id,
                provider,
                all_or_nothing: false,
                error: Some(no_provider()),
                updates: vec![],
                reboot_pending: false,
            };
        };
        let started = Instant::now();
        let res = tokio::task::spawn_blocking(move || {
            let log = Log::default();
            let updates = p.scan(&log, &|_, _, _| {}, refresh);
            (updates, p.reboot_pending(), p.all_or_nothing(), log)
        })
        .await;
        let (updates, reboot_pending, all_or_nothing, log) = match res {
            Ok(r) => r,
            Err(e) => (Err(anyhow::anyhow!("scan panicked: {e}")), false, false, Log::default()),
        };
        match updates {
            Ok(updates) => {
                info!(provider, updates = updates.len(), reboot_pending, secs = started.elapsed().as_secs(), "patch scan done");
                AgentMsg::PatchScanResult { request_id, provider, all_or_nothing, error: None, updates, reboot_pending }
            }
            Err(e) => {
                warn!(provider, "patch scan failed: {e:#}");
                let detail = log.text();
                let error = if detail.trim().is_empty() {
                    format!("{e:#}")
                } else {
                    format!("{e:#}\n\n{}", tail(&detail, 4000))
                };
                AgentMsg::PatchScanResult { request_id, provider, all_or_nothing, error: Some(error), updates: vec![], reboot_pending }
            }
        }
    }

    /// Installs, reports, rescans, then reboots if the policy says so.
    pub async fn install(self: Arc<Self>, run_id: Uuid, ids: Vec<String>, reboot: RebootPolicy) {
        {
            let mut runs = self.runs.lock().await;
            prune(&mut runs);
            if runs.contains_key(&run_id) {
                warn!(%run_id, "patch install already received; ignoring the duplicate");
                return;
            }
            let outcome = PatchOutcome {
                run_id,
                results: vec![],
                error: None,
                reboot_required: false,
                rebooting: false,
                output: String::new(),
                duration_ms: 0,
            };
            runs.insert(run_id, Pending { outcome, finished: None });
        }
        let progress = |stage: PatchStage, message: Option<String>| AgentMsg::PatchProgress { run_id, stage, message, percent: None };
        let op = match self.op.try_lock() {
            Ok(g) => g,
            Err(_) => {
                self.emit(progress(PatchStage::Queued, Some("waiting for another scan or install to finish".into()))).await;
                self.op.lock().await
            }
        };
        let started = Instant::now();
        info!(%run_id, updates = ids.len(), reboot = reboot.as_str(), "installing patches");
        let mut outcome = self.run_install(run_id, &ids).await;

        // Rescan without refreshing: per-update results for providers that don't give them,
        // and the server gets the new state right away.
        let rescan = self.scan_now(None, false).await;
        if outcome.error.is_none() && outcome.results.is_empty() {
            let still: Option<Vec<&PatchUpdate>> = match &rescan {
                AgentMsg::PatchScanResult { error: None, updates, .. } => Some(updates.iter().collect()),
                _ => None,
            };
            outcome.results = ids
                .iter()
                .map(|id| match &still {
                    Some(list) if list.iter().any(|u| &u.id == id) => {
                        PatchItemResult { id: id.clone(), ok: false, message: Some("still offered after the install".into()) }
                    }
                    Some(_) => PatchItemResult { id: id.clone(), ok: true, message: None },
                    None => PatchItemResult { id: id.clone(), ok: false, message: Some("couldn't verify: the rescan failed".into()) },
                })
                .collect();
        }
        if let AgentMsg::PatchScanResult { reboot_pending: true, .. } = &rescan {
            outcome.reboot_required = true;
        }
        let changed = outcome.succeeded() > 0;
        outcome.rebooting = match reboot {
            RebootPolicy::Never => false,
            RebootPolicy::IfRequired => outcome.reboot_required,
            RebootPolicy::Always => changed || outcome.reboot_required,
        };
        outcome.duration_ms = started.elapsed().as_millis() as u64;
        info!(%run_id, ok = outcome.succeeded(), requested = ids.len(), reboot_required = outcome.reboot_required, rebooting = outcome.rebooting, "patch install done");

        let rebooting = outcome.rebooting;
        {
            let mut runs = self.runs.lock().await;
            runs.insert(run_id, Pending { outcome: outcome.clone(), finished: Some(Instant::now()) });
        }
        self.emit(AgentMsg::PatchResult(outcome)).await;
        self.emit(rescan).await;
        drop(op);

        if rebooting {
            // Give the server a chance to store the result first; it's resent after the
            // reboot otherwise, but only if this process gets to keep it (it won't).
            let deadline = Instant::now() + ACK_BEFORE_REBOOT;
            while Instant::now() < deadline && !self.acked(run_id).await {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            self.emit(progress(PatchStage::Rebooting, Some("restarting in about a minute to finish installing updates".into()))).await;
            if let Err(e) = tokio::task::spawn_blocking(cmd::reboot).await.unwrap_or_else(|e| Err(anyhow::anyhow!("{e}"))) {
                warn!("reboot failed: {e:#}");
            }
        }
    }

    async fn run_install(&self, run_id: Uuid, ids: &[String]) -> PatchOutcome {
        let mut outcome =
            PatchOutcome { run_id, results: vec![], error: None, reboot_required: false, rebooting: false, output: String::new(), duration_ms: 0 };
        let Some(p) = self.provider.clone() else {
            outcome.error = Some(no_provider());
            return outcome;
        };
        if ids.is_empty() && !p.all_or_nothing() {
            outcome.error = Some("no updates requested".into());
            return outcome;
        }
        let tx = self.link.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let ids_owned = ids.to_vec();
        let res = tokio::task::spawn_blocking(move || {
            let log = Log::default();
            // Progress goes out on whichever connection was current when the install began;
            // it's only informational, so losing some across a reconnect is fine.
            let report = move |stage: PatchStage, message: Option<String>, percent: Option<u8>| {
                if let Some(tx) = &tx {
                    let _ = tx.try_send(AgentMsg::PatchProgress { run_id, stage, message, percent });
                }
            };
            let r = p.install(&ids_owned, &log, &report);
            (r, log)
        })
        .await;
        let (r, log) = match res {
            Ok(r) => r,
            Err(e) => (Err(anyhow::anyhow!("install panicked: {e}")), Log::default()),
        };
        outcome.output = tail(&log.text(), OUTPUT_MAX).to_string();
        match r {
            Ok(i) => {
                outcome.results = i.results;
                outcome.reboot_required = i.reboot_required;
            }
            Err(e) => {
                warn!(%run_id, "patch install failed: {e:#}");
                outcome.error = Some(format!("{e:#}"));
                outcome.results =
                    ids.iter().map(|id| PatchItemResult { id: id.clone(), ok: false, message: Some(format!("{e:#}")) }).collect();
            }
        }
        outcome
    }
}

/// `rmm-agent patches`: scan (or install) in the foreground, printing JSON and progress.
pub fn cli(install: &[String], refresh: bool) -> Result<()> {
    let p = detect().ok_or_else(|| anyhow::anyhow!(no_provider()))?;
    let log = Log::default();
    let progress = |stage: PatchStage, msg: Option<String>, pct: Option<u8>| {
        eprintln!("[{}{}] {}", stage.as_str(), pct.map(|p| format!(" {p}%")).unwrap_or_default(), msg.unwrap_or_default());
    };
    let out = if install.is_empty() {
        let updates = p.scan(&log, &progress, refresh);
        if let Err(e) = &updates {
            eprintln!("{}", log.text());
            anyhow::bail!("scan failed: {e:#}");
        }
        serde_json::json!({ "provider": p.name(), "all_or_nothing": p.all_or_nothing(), "reboot_pending": p.reboot_pending(), "updates": updates? })
    } else {
        let r = p.install(install, &log, &progress);
        eprintln!("{}", log.text());
        let r = r?;
        serde_json::json!({ "results": r.results, "reboot_required": r.reboot_required })
    };
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

fn no_provider() -> String {
    if cfg!(target_os = "linux") {
        "no supported package manager found (apt, dnf, yum or pacman)".into()
    } else {
        "patching isn't supported on this OS".into()
    }
}

fn prune(runs: &mut HashMap<Uuid, Pending>) {
    runs.retain(|_, p| p.finished.is_none_or(|at| at.elapsed() < KEEP_UNACKED));
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
/// Packages whose update usually only takes full effect after a reboot. Package managers
/// don't say; this is a heuristic for the dashboard's "requires reboot" column.
pub fn likely_needs_reboot(package: &str) -> bool {
    let name = package.split([':', '.']).next().unwrap_or(package);
    const PREFIXES: &[&str] = &["linux-image", "linux-modules", "linux-signed", "linux-generic", "linux-firmware", "kernel"];
    const EXACT: &[&str] =
        &["linux", "linux-lts", "linux-zen", "linux-hardened", "glibc", "libc6", "systemd", "dbus", "dbus-broker", "intel-microcode", "amd-ucode", "amd64-microcode", "microcode_ctl"];
    EXACT.contains(&name) || PREFIXES.iter().any(|p| name.starts_with(p) && !name.contains("headers") && !name.contains("devel") && !name.contains("doc"))
}

/// The running kernel's modules are gone: a kernel update replaced it (Arch, and any distro
/// after the old kernel package was removed).
#[cfg(target_os = "linux")]
pub fn running_kernel_removed() -> bool {
    let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") else { return false };
    let dir = std::path::Path::new("/usr/lib/modules").join(release.trim());
    std::path::Path::new("/usr/lib/modules").is_dir() && !dir.exists() && !std::path::Path::new("/lib/modules").join(release.trim()).exists()
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub fn running_kernel_removed() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Fake {
        offered: Mutex<Vec<&'static str>>,
        fail: bool,
    }

    impl PatchProvider for Fake {
        fn name(&self) -> &'static str {
            "fake"
        }
        fn scan(&self, _: &Log, _: Progress, _: bool) -> Result<Vec<PatchUpdate>> {
            Ok(self
                .offered
                .lock()
                .unwrap()
                .iter()
                .map(|id| PatchUpdate {
                    id: id.to_string(),
                    title: id.to_string(),
                    kb: None,
                    severity: None,
                    category: rmm_proto::patch::Category::Update,
                    size: None,
                    requires_reboot: false,
                    version: None,
                    current_version: None,
                })
                .collect())
        }
        fn install(&self, ids: &[String], log: &Log, progress: Progress) -> Result<Installed> {
            progress(PatchStage::Installing, None, None);
            log.push("installing\n");
            if self.fail {
                anyhow::bail!("dpkg was interrupted");
            }
            // Installs everything except "stubborn".
            self.offered.lock().unwrap().retain(|o| *o == "stubborn" || !ids.iter().any(|i| i == o));
            Ok(Installed { results: vec![], reboot_required: false })
        }
        fn reboot_pending(&self) -> bool {
            false
        }
    }

    async fn drain(rx: &mut mpsc::Receiver<AgentMsg>) -> Vec<AgentMsg> {
        let mut out = vec![];
        while let Ok(m) = rx.try_recv() {
            out.push(m);
        }
        out
    }

    #[tokio::test]
    async fn install_derives_results_from_rescan_and_waits_for_ack() {
        let fake = Fake { offered: Mutex::new(vec!["openssl", "curl", "stubborn"]), fail: false };
        let m = Arc::new(Manager::with_provider(Some(Arc::new(fake))));
        let (tx, mut rx) = mpsc::channel(64);
        m.attach(tx).await;
        let run = Uuid::new_v4();
        m.clone().install(run, vec!["openssl".into(), "stubborn".into()], RebootPolicy::Never).await;
        let msgs = drain(&mut rx).await;
        let outcome = msgs
            .iter()
            .find_map(|m| if let AgentMsg::PatchResult(o) = m { Some(o.clone()) } else { None })
            .expect("a result");
        assert_eq!(outcome.results.len(), 2);
        assert!(outcome.results.iter().find(|r| r.id == "openssl").unwrap().ok);
        assert!(!outcome.results.iter().find(|r| r.id == "stubborn").unwrap().ok);
        assert!(!outcome.rebooting);
        assert!(outcome.output.contains("installing"));
        match msgs.last() {
            Some(AgentMsg::PatchScanResult { request_id: None, updates, .. }) => {
                assert_eq!(updates.iter().map(|u| u.id.as_str()).collect::<Vec<_>>(), ["curl", "stubborn"])
            }
            other => panic!("expected a rescan last, got {other:?}"),
        }

        // Unacked results are held and resent on the next connection.
        assert_eq!(m.ids().await, vec![run]);
        m.detach();
        let (tx2, mut rx2) = mpsc::channel(64);
        m.attach(tx2).await;
        assert!(matches!(drain(&mut rx2).await.as_slice(), [AgentMsg::PatchResult(o)] if o.run_id == run));
        m.ack(run).await;
        assert!(m.ids().await.is_empty());

        // A duplicate delivery after the ack would run again, but one still held is ignored.
        m.clone().install(run, vec!["curl".into()], RebootPolicy::Never).await;
        let n = m.ids().await.len();
        m.clone().install(run, vec!["curl".into()], RebootPolicy::Never).await;
        assert_eq!(m.ids().await.len(), n);
    }

    #[tokio::test]
    async fn failed_install_reports_every_id() {
        let fake = Fake { offered: Mutex::new(vec!["a"]), fail: true };
        let m = Arc::new(Manager::with_provider(Some(Arc::new(fake))));
        let (tx, mut rx) = mpsc::channel(64);
        m.attach(tx).await;
        m.clone().install(Uuid::new_v4(), vec!["a".into()], RebootPolicy::IfRequired).await;
        let o = drain(&mut rx)
            .await
            .into_iter()
            .find_map(|m| if let AgentMsg::PatchResult(o) = m { Some(o) } else { None })
            .unwrap();
        assert!(o.error.as_deref().unwrap().contains("dpkg"));
        assert!(!o.results[0].ok && !o.rebooting);
    }

    #[tokio::test]
    async fn no_provider_scan_reports_error() {
        let m = Arc::new(Manager::with_provider(None));
        let (tx, mut rx) = mpsc::channel(8);
        m.attach(tx).await;
        let id = Uuid::new_v4();
        m.clone().scan(Some(id)).await;
        assert!(matches!(drain(&mut rx).await.as_slice(), [AgentMsg::PatchScanResult { request_id: Some(r), error: Some(_), .. }] if *r == id));
    }

    #[test]
    fn reboot_heuristic() {
        for yes in ["linux-image-6.8.0-45-generic", "linux", "kernel-core.x86_64", "glibc.x86_64", "libc6:amd64", "systemd", "linux-firmware"] {
            assert!(likely_needs_reboot(yes), "{yes}");
        }
        for no in ["linux-headers-6.8.0-45", "kernel-headers.x86_64", "openssl", "curl", "systemd-devel", "linux-api-headers"] {
            assert!(!likely_needs_reboot(no), "{no}");
        }
    }
}
