//! Software deployment: installing, upgrading and removing catalog packages, and reporting what
//! is installed and what newer version is on offer (docs/design/software.md).
//!
//! Each way of handling a package sits behind [`Provider`]: winget and Chocolatey and uploaded
//! MSI/EXE installers on Windows, apt and dnf/yum on Linux (`parse` holds the output parsers).
//! A package lists its ids for each; the agent uses the first provider that is here and has
//! an id. The [`Manager`] works like the patch manager: runs one operation at a time (sharing
//! its lock, since package managers lock anyway), keeps results until the server acknowledges
//! them, resends them after reconnects, and rescans the package after every run.

#[cfg(any(target_os = "linux", test))]
mod apt;
#[cfg(any(target_os = "linux", test))]
mod dnf;
#[cfg(debug_assertions)]
mod fake;
#[cfg(any(windows, test))]
mod installer;
pub(crate) mod parse;
#[cfg(any(windows, test))]
mod winget;
#[cfg(any(windows, test))]
mod choco;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use rmm_proto::AgentMsg;
use rmm_proto::patch::{PatchStage, tail};
use rmm_proto::software::{OUTPUT_MAX, Op, Outcome, Package, Status, valid_token};
use tokio::sync::mpsc;
use tracing::{info, warn};
use uuid::Uuid;

use crate::patch::Log;

/// Unacknowledged results are dropped after this long (an older server never acks).
const KEEP_UNACKED: Duration = Duration::from_secs(7 * 24 * 3600);

pub type Progress<'a> = &'a (dyn Fn(PatchStage, Option<String>) + Send + Sync);

/// What a run needs from the connection: where the server is, and how to prove who we are
/// when downloading an uploaded installer.
#[derive(Clone, Default)]
#[cfg_attr(not(windows), allow(dead_code))] // only the Windows installer downloads
pub struct Server {
    pub url: String,
    pub agent_id: Uuid,
    pub secret: String,
}

#[cfg_attr(not(windows), allow(dead_code))]
pub struct RunCtx<'a> {
    pub server: &'a Server,
    pub bootstrap_choco: bool,
    pub log: &'a Log,
    pub progress: Progress<'a>,
}

#[derive(Default)]
pub struct Done {
    pub reboot_required: bool,
    /// Said by the provider when it could tell (`already installed`...).
    pub note: Option<String>,
}

pub trait Provider: Send + Sync {
    /// Reported to the server: `winget`, `choco`, `apt`, `dnf`, `installer`...
    fn name(&self) -> &'static str;

    /// This machine has the tool (or, for Chocolatey, could get it).
    fn available(&self) -> bool;

    /// The package has what this provider needs (an id for it).
    fn handles(&self, pkg: &Package) -> bool;

    /// A provider that isn't installed yet but can be: Chocolatey, when the policy allows.
    fn can_bootstrap(&self) -> bool {
        false
    }

    /// Installed and available versions of these packages (all handled by this provider).
    /// `refresh` first updates package lists, where that applies.
    fn scan(&self, pkgs: &[&Package], log: &Log, refresh: bool) -> Result<Vec<Status>>;

    fn run(&self, op: Op, pkg: &Package, ctx: &RunCtx) -> Result<Done>;
}

/// Providers in preference order for this machine.
pub fn detect() -> Vec<Box<dyn Provider>> {
    #[cfg(debug_assertions)]
    if let Some(path) = std::env::var_os("RMM_SOFTWARE_FAKE") {
        return vec![Box::new(fake::FileProvider(path.into()))];
    }
    #[cfg(windows)]
    {
        vec![Box::new(winget::Winget::new()), Box::new(choco::Choco::new()), Box::new(installer::Installer)]
    }
    #[cfg(target_os = "linux")]
    {
        use crate::patch::cmd::which;
        if which("apt-get") {
            vec![Box::new(apt::Apt)]
        } else if which("dnf") || which("dnf5") {
            vec![Box::new(dnf::Dnf::new())]
        } else if which("yum") {
            vec![Box::new(dnf::Dnf::yum())]
        } else {
            vec![]
        }
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        vec![]
    }
}

/// Ids and versions go onto command lines; refuse anything odd before any provider sees it.
fn check_package(pkg: &Package) -> Result<()> {
    for (what, v) in [("winget id", &pkg.winget), ("Chocolatey id", &pkg.choco), ("apt package", &pkg.apt), ("dnf package", &pkg.dnf), ("version", &pkg.version)] {
        if let Some(v) = v
            && !valid_token(v)
        {
            bail!("the {what} {v:?} contains characters that aren't allowed");
        }
    }
    Ok(())
}

struct Pending {
    outcome: Outcome,
    /// None while the run is still going.
    finished: Option<Instant>,
}

pub struct Manager {
    providers: Vec<Arc<dyn Provider>>,
    server: Server,
    /// The patch manager's lock.
    op: Arc<tokio::sync::Mutex<()>>,
    runs: tokio::sync::Mutex<HashMap<Uuid, Pending>>,
    link: std::sync::Mutex<Option<mpsc::Sender<AgentMsg>>>,
}

impl Manager {
    pub fn new(server: Server, op: Arc<tokio::sync::Mutex<()>>) -> Self {
        let providers: Vec<Arc<dyn Provider>> = detect().into_iter().map(Arc::from).collect();
        let names: Vec<&str> = providers.iter().filter(|p| p.available()).map(|p| p.name()).collect();
        if names.is_empty() {
            info!("no supported software provider; software scans will report an error");
        } else {
            info!(providers = %names.join(","), "software deployment available");
        }
        Self::with_providers(providers, server, op)
    }

    fn with_providers(providers: Vec<Arc<dyn Provider>>, server: Server, op: Arc<tokio::sync::Mutex<()>>) -> Self {
        Manager { providers, server, op, runs: Default::default(), link: Default::default() }
    }

    fn link(&self) -> Option<mpsc::Sender<AgentMsg>> {
        self.link.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    async fn emit(&self, msg: AgentMsg) {
        if let Some(tx) = self.link() {
            let _ = tx.send(msg).await;
        }
    }

    /// Runs still held (running or unacknowledged), for `Auth`.
    pub async fn ids(&self) -> Vec<Uuid> {
        let mut runs = self.runs.lock().await;
        prune(&mut runs);
        runs.keys().copied().collect()
    }

    /// New connection: resend finished results the server hasn't stored.
    pub async fn attach(&self, tx: mpsc::Sender<AgentMsg>) {
        let runs = self.runs.lock().await;
        for p in runs.values().filter(|p| p.finished.is_some()) {
            let _ = tx.send(AgentMsg::SoftwareResult(p.outcome.clone())).await;
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

    fn available_names(&self) -> Vec<String> {
        self.providers.iter().filter(|p| p.available()).map(|p| p.name().to_string()).collect()
    }

    /// The provider that will handle `pkg`: the first that is here and has an id for it, else
    /// (when allowed) one that can be bootstrapped.
    fn pick(&self, pkg: &Package, bootstrap: bool) -> Option<Arc<dyn Provider>> {
        self.providers
            .iter()
            .find(|p| p.handles(pkg) && (p.available() || (bootstrap && p.can_bootstrap())))
            .cloned()
    }

    /// Reports what is installed of `packages`. Runs after any operation in progress.
    pub async fn scan(self: Arc<Self>, request_id: Option<Uuid>, packages: Vec<Package>) {
        let _op = self.op.lock().await;
        let msg = self.scan_now(request_id, &packages, true).await;
        self.emit(msg).await;
    }

    /// Needs the op lock held.
    async fn scan_now(self: &Arc<Self>, request_id: Option<Uuid>, packages: &[Package], refresh: bool) -> AgentMsg {
        let providers = self.available_names();
        if self.providers.iter().all(|p| !p.available()) {
            return AgentMsg::SoftwareScanResult { request_id, providers, error: Some(no_provider()), items: vec![] };
        }
        let started = Instant::now();
        let me = self.clone();
        let pkgs = packages.to_vec();
        let res = tokio::task::spawn_blocking(move || {
            let log = Log::default();
            let mut items = Vec::new();
            let mut errors = Vec::new();
            let mut claimed = std::collections::HashSet::new();
            for p in me.providers.iter().filter(|p| p.available()) {
                let mine: Vec<&Package> = pkgs.iter().filter(|k| !claimed.contains(&k.id) && check_package(k).is_ok() && p.handles(k)).collect();
                if mine.is_empty() {
                    continue;
                }
                match p.scan(&mine, &log, refresh) {
                    Ok(s) => {
                        claimed.extend(mine.iter().map(|k| k.id));
                        items.extend(s);
                    }
                    // Leave these packages for the next provider that handles them.
                    Err(e) => errors.push(format!("{}: {e:#}", p.name())),
                }
            }
            // Packages nobody could look at: unknown, not "absent".
            for k in pkgs.iter().filter(|k| !claimed.contains(&k.id)) {
                items.push(Status { package_id: k.id, installed: None, available: None, provider: None });
            }
            (items, errors, log)
        })
        .await;
        match res {
            Ok((items, errors, _)) => {
                info!(packages = packages.len(), found = items.iter().filter(|i| i.installed.is_some()).count(), secs = started.elapsed().as_secs(), "software scan done");
                let error = (!errors.is_empty()).then(|| errors.join("\n"));
                AgentMsg::SoftwareScanResult { request_id, providers, error, items }
            }
            Err(e) => AgentMsg::SoftwareScanResult { request_id, providers, error: Some(format!("scan panicked: {e}")), items: vec![] },
        }
    }

    /// Does one run, reports, and rescans the package.
    pub async fn run(self: Arc<Self>, run_id: Uuid, op: Op, pkg: Package, bootstrap: bool) {
        {
            let mut runs = self.runs.lock().await;
            prune(&mut runs);
            if runs.contains_key(&run_id) {
                warn!(%run_id, "software run already received; ignoring the duplicate");
                return;
            }
            let outcome = Outcome {
                run_id,
                ok: false,
                message: None,
                provider: None,
                installed_version: None,
                reboot_required: false,
                output: String::new(),
                duration_ms: 0,
            };
            runs.insert(run_id, Pending { outcome, finished: None });
        }
        let progress = |stage: PatchStage, message: Option<String>| AgentMsg::SoftwareProgress { run_id, stage, message };
        let guard = match self.op.try_lock() {
            Ok(g) => g,
            Err(_) => {
                self.emit(progress(PatchStage::Queued, Some("waiting for another package operation to finish".into()))).await;
                self.op.lock().await
            }
        };
        let started = Instant::now();
        info!(%run_id, op = op.as_str(), package = %pkg.name, "software run");
        let mut outcome = self.run_now(run_id, op, &pkg, bootstrap).await;

        // The rescan is authoritative about what is installed now.
        let one = [pkg.clone()];
        let rescan = self.scan_now(None, &one, false).await;
        if let AgentMsg::SoftwareScanResult { error: None, items, .. } = &rescan
            && let Some(s) = items.iter().find(|s| s.package_id == pkg.id)
            && s.provider.is_some()
        {
            outcome.installed_version = s.installed.clone();
            if outcome.ok {
                match op {
                    Op::Uninstall if s.installed.is_some() => {
                        outcome.ok = false;
                        outcome.message = Some("it's still installed after the uninstall".into());
                    }
                    Op::Install | Op::Upgrade if s.installed.is_none() => {
                        outcome.ok = false;
                        outcome.message = Some("it isn't installed after the install (the provider reported success)".into());
                    }
                    _ => {}
                }
            }
        }
        outcome.duration_ms = started.elapsed().as_millis() as u64;
        info!(%run_id, ok = outcome.ok, version = ?outcome.installed_version, "software run done");
        {
            let mut runs = self.runs.lock().await;
            runs.insert(run_id, Pending { outcome: outcome.clone(), finished: Some(Instant::now()) });
        }
        self.emit(AgentMsg::SoftwareResult(outcome)).await;
        self.emit(rescan).await;
        drop(guard);
    }

    async fn run_now(self: &Arc<Self>, run_id: Uuid, op: Op, pkg: &Package, bootstrap: bool) -> Outcome {
        let mut outcome =
            Outcome { run_id, ok: false, message: None, provider: None, installed_version: None, reboot_required: false, output: String::new(), duration_ms: 0 };
        if let Err(e) = check_package(pkg) {
            outcome.message = Some(format!("{e:#}"));
            return outcome;
        }
        let Some(p) = self.pick(pkg, bootstrap) else {
            outcome.message = Some(no_way(pkg, &self.providers));
            return outcome;
        };
        outcome.provider = Some(p.name().to_string());
        let tx = self.link();
        let (pkg, server) = (pkg.clone(), self.server.clone());
        let res = tokio::task::spawn_blocking(move || {
            let log = Log::default();
            // Progress goes out on the connection current when the run began; it's only
            // informational.
            let report = move |stage: PatchStage, message: Option<String>| {
                if let Some(tx) = &tx {
                    let _ = tx.try_send(AgentMsg::SoftwareProgress { run_id, stage, message });
                }
            };
            let r = p.run(op, &pkg, &RunCtx { server: &server, bootstrap_choco: bootstrap, log: &log, progress: &report });
            (r, log)
        })
        .await;
        let (r, log) = match res {
            Ok(r) => r,
            Err(e) => (Err(anyhow::anyhow!("run panicked: {e}")), Log::default()),
        };
        outcome.output = tail(&log.text(), OUTPUT_MAX).to_string();
        match r {
            Ok(d) => {
                outcome.ok = true;
                outcome.reboot_required = d.reboot_required;
                outcome.message = d.note;
            }
            Err(e) => {
                warn!(%run_id, "software run failed: {e:#}");
                outcome.message = Some(format!("{e:#}"));
            }
        }
        outcome
    }
}

fn no_provider() -> String {
    if cfg!(windows) {
        "no package provider found (winget, Chocolatey)".into()
    } else if cfg!(target_os = "linux") {
        "no supported package manager found (apt, dnf or yum)".into()
    } else {
        "software deployment isn't supported on this OS".into()
    }
}

/// Why no provider could take the package.
fn no_way(pkg: &Package, providers: &[Arc<dyn Provider>]) -> String {
    let has_ids = providers.iter().any(|p| p.handles(pkg));
    if !has_ids {
        format!("{} has no package id or installer for this kind of machine", pkg.name)
    } else {
        let missing: Vec<&str> = providers.iter().filter(|p| p.handles(pkg) && !p.available()).map(|p| p.name()).collect();
        format!("{} needs {}, which isn't available on this machine", pkg.name, missing.join(" or "))
    }
}

fn prune(runs: &mut HashMap<Uuid, Pending>) {
    runs.retain(|_, p| p.finished.is_none_or(|at| at.elapsed() < KEEP_UNACKED));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Installed versions held in memory; "stubborn" never installs.
    struct Mem {
        installed: Mutex<HashMap<String, String>>,
        available: HashMap<String, String>,
    }

    impl Provider for Mem {
        fn name(&self) -> &'static str {
            "mem"
        }
        fn available(&self) -> bool {
            true
        }
        fn handles(&self, pkg: &Package) -> bool {
            pkg.apt.is_some()
        }
        fn scan(&self, pkgs: &[&Package], _: &Log, _: bool) -> Result<Vec<Status>> {
            let inst = self.installed.lock().unwrap();
            Ok(pkgs
                .iter()
                .map(|p| {
                    let id = p.apt.clone().unwrap();
                    Status { package_id: p.id, installed: inst.get(&id).cloned(), available: self.available.get(&id).cloned(), provider: Some("mem".into()) }
                })
                .collect())
        }
        fn run(&self, op: Op, pkg: &Package, ctx: &RunCtx) -> Result<Done> {
            let id = pkg.apt.clone().unwrap();
            (ctx.progress)(PatchStage::Installing, Some(format!("{} {id}", op.as_str())));
            ctx.log.push(&format!("{} {id}\n", op.as_str()));
            if id == "broken" {
                bail!("dpkg was interrupted");
            }
            let mut inst = self.installed.lock().unwrap();
            match op {
                Op::Uninstall => {
                    inst.remove(&id);
                }
                Op::Install | Op::Upgrade if id != "stubborn" => {
                    inst.insert(id.clone(), pkg.version.clone().or_else(|| self.available.get(&id).cloned()).unwrap_or_else(|| "1.0".into()));
                }
                _ => {}
            }
            Ok(Done::default())
        }
    }

    fn pkg(apt: &str, version: Option<&str>) -> Package {
        Package { id: Uuid::new_v4(), name: apt.into(), version: version.map(Into::into), winget: None, choco: None, apt: Some(apt.into()), dnf: None, installer: None }
    }

    fn manager(installed: &[(&str, &str)]) -> Arc<Manager> {
        let mem = Mem {
            installed: Mutex::new(installed.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()),
            available: [("htop".to_string(), "3.3".to_string())].into(),
        };
        Arc::new(Manager::with_providers(vec![Arc::new(mem)], Server::default(), Default::default()))
    }

    async fn drain(rx: &mut mpsc::Receiver<AgentMsg>) -> Vec<AgentMsg> {
        let mut out = vec![];
        while let Ok(m) = rx.try_recv() {
            out.push(m);
        }
        out
    }

    #[tokio::test]
    async fn scan_reports_installed_and_available_and_unknowns() {
        let m = manager(&[("htop", "3.2")]);
        let (tx, mut rx) = mpsc::channel(16);
        m.attach(tx).await;
        let (htop, none) = (pkg("htop", None), pkg("vim", None));
        let nothing = Package { apt: None, ..pkg("x", None) };
        let id = Uuid::new_v4();
        m.clone().scan(Some(id), vec![htop.clone(), none.clone(), nothing.clone()]).await;
        let msgs = drain(&mut rx).await;
        let AgentMsg::SoftwareScanResult { request_id, providers, error, items } = &msgs[0] else { panic!("{msgs:?}") };
        assert_eq!((*request_id, providers.as_slice(), error.as_deref()), (Some(id), ["mem".to_string()].as_slice(), None));
        let by = |p: &Package| items.iter().find(|s| s.package_id == p.id).unwrap();
        assert_eq!((by(&htop).installed.as_deref(), by(&htop).available.as_deref()), (Some("3.2"), Some("3.3")));
        assert_eq!(by(&none).installed, None);
        assert_eq!(by(&none).provider.as_deref(), Some("mem"));
        assert_eq!(by(&nothing).provider, None, "no provider handles it: unknown, not absent");
    }

    #[tokio::test]
    async fn install_verifies_with_a_rescan_and_holds_the_result_until_acked() {
        let m = manager(&[]);
        let (tx, mut rx) = mpsc::channel(32);
        m.attach(tx).await;
        let (run, p) = (Uuid::new_v4(), pkg("htop", None));
        m.clone().run(run, Op::Install, p.clone(), false).await;
        let msgs = drain(&mut rx).await;
        let out = msgs.iter().find_map(|m| if let AgentMsg::SoftwareResult(o) = m { Some(o.clone()) } else { None }).expect("a result");
        assert!(out.ok, "{out:?}");
        assert_eq!((out.provider.as_deref(), out.installed_version.as_deref()), (Some("mem"), Some("3.3")));
        assert!(out.output.contains("install htop"));
        assert!(matches!(msgs.last(), Some(AgentMsg::SoftwareScanResult { request_id: None, items, .. }) if items[0].installed.as_deref() == Some("3.3")));

        // Held and resent after a reconnect, until acknowledged.
        assert_eq!(m.ids().await, vec![run]);
        m.detach();
        let (tx2, mut rx2) = mpsc::channel(8);
        m.attach(tx2).await;
        assert!(matches!(drain(&mut rx2).await.as_slice(), [AgentMsg::SoftwareResult(o)] if o.run_id == run));
        m.ack(run).await;
        assert!(m.ids().await.is_empty());
    }

    #[tokio::test]
    async fn success_without_the_package_is_a_failure() {
        let m = manager(&[]);
        let (tx, mut rx) = mpsc::channel(32);
        m.attach(tx).await;
        m.clone().run(Uuid::new_v4(), Op::Install, pkg("stubborn", None), false).await;
        let out = drain(&mut rx).await.into_iter().find_map(|m| if let AgentMsg::SoftwareResult(o) = m { Some(o) } else { None }).unwrap();
        assert!(!out.ok && out.message.as_deref().unwrap().contains("isn't installed"), "{out:?}");
    }

    #[tokio::test]
    async fn failures_and_bad_ids_are_reported() {
        let m = manager(&[]);
        let (tx, mut rx) = mpsc::channel(32);
        m.attach(tx).await;
        m.clone().run(Uuid::new_v4(), Op::Install, pkg("broken", None), false).await;
        m.clone().run(Uuid::new_v4(), Op::Install, pkg("--force-yes", None), false).await;
        m.clone().run(Uuid::new_v4(), Op::Install, Package { apt: None, ..pkg("x", None) }, false).await;
        let results: Vec<Outcome> = drain(&mut rx).await.into_iter().filter_map(|m| if let AgentMsg::SoftwareResult(o) = m { Some(o) } else { None }).collect();
        assert!(results[0].message.as_deref().unwrap().contains("dpkg"));
        assert!(results[1].message.as_deref().unwrap().contains("aren't allowed"));
        assert!(results[2].message.as_deref().unwrap().contains("no package id"));
        assert!(results.iter().all(|r| !r.ok));
    }

    #[tokio::test]
    async fn uninstall_and_duplicate_runs() {
        let m = manager(&[("htop", "3.2")]);
        let (tx, mut rx) = mpsc::channel(32);
        m.attach(tx).await;
        let (run, p) = (Uuid::new_v4(), pkg("htop", None));
        m.clone().run(run, Op::Uninstall, p.clone(), false).await;
        let out = drain(&mut rx).await.into_iter().find_map(|m| if let AgentMsg::SoftwareResult(o) = m { Some(o) } else { None }).unwrap();
        assert!(out.ok && out.installed_version.is_none(), "{out:?}");
        // A run still held is ignored when delivered again.
        m.clone().run(run, Op::Install, p, false).await;
        assert!(drain(&mut rx).await.is_empty());
    }

    #[tokio::test]
    async fn no_provider_scan_reports_an_error() {
        let m = Arc::new(Manager::with_providers(vec![], Server::default(), Default::default()));
        let (tx, mut rx) = mpsc::channel(8);
        m.attach(tx).await;
        m.clone().scan(Some(Uuid::new_v4()), vec![pkg("htop", None)]).await;
        assert!(matches!(drain(&mut rx).await.as_slice(), [AgentMsg::SoftwareScanResult { error: Some(_), .. }]));
    }
}
