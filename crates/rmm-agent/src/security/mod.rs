//! Endpoint protection (Phase 8, milestone 1): the state of the antivirus the OS already has,
//! and scans and signature updates started from the console.
//!
//! Each OS's product sits behind [`Provider`]: Microsoft Defender plus Windows Security
//! Center, ClamAV, XProtect. Providers are synchronous (PowerShell, `clamscan`) and run on
//! blocking threads.
//!
//! The [`Manager`] outlives connections: a full scan can take hours. It runs one scan or
//! update at a time, keeps finished results (on disk, so they survive a restart) for an hour
//! and resends them after a reconnect (the server ignores repeats), and lists running and
//! unsent actions in `Auth`.
//!
//! Milestones 2-7: our own sensor runs as a separate process ([`supervisor`]); response
//! actions ([`response`], [`isolation`], [`quarantine`]) run here in the agent.

#[cfg(any(target_os = "linux", test))]
mod clamav;
#[cfg(any(windows, test))]
mod defender;
#[cfg(debug_assertions)]
mod fake;
pub mod isolation;
pub mod quarantine;
pub mod response;
pub mod supervisor;
#[cfg(any(target_os = "macos", test))]
mod xprotect;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use chrono::{DateTime, Utc};
use rmm_proto::AgentMsg;
use rmm_proto::security::{Action, ActionState, MESSAGE_MAX, ProductKind, Report, ResponseAction, TRIAGE_CHUNK};
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, mpsc};
use tracing::{info, warn};
use uuid::Uuid;

/// How often the state is re-read. Only changes are sent.
const POLL: Duration = Duration::from_secs(300);
/// Finished results are resent after reconnects for this long.
const KEEP_FINISHED: Duration = Duration::from_secs(3600);

pub trait Provider: Send + Sync {
    /// Never fails as a whole: problems go in `Report::error`.
    fn status(&self) -> Report;
    /// Runs the action to completion and describes the outcome.
    fn run(&self, product: ProductKind, action: Action) -> Result<String>;
}

/// How long an action may run before it's stopped.
pub fn timeout(action: Action) -> Duration {
    match action {
        Action::QuickScan => Duration::from_secs(4 * 3600),
        Action::FullScan => Duration::from_secs(24 * 3600),
        Action::UpdateSignatures => Duration::from_secs(3600),
    }
}

/// No protection product on this machine (Linux without ClamAV, other OSes).
#[allow(dead_code)]
struct Nothing;

impl Provider for Nothing {
    fn status(&self) -> Report {
        Report::default()
    }

    fn run(&self, _: ProductKind, _: Action) -> Result<String> {
        anyhow::bail!("no supported antivirus is installed on this machine")
    }
}

pub fn detect() -> Arc<dyn Provider> {
    #[cfg(debug_assertions)]
    if let Some(path) = std::env::var_os("RMM_SECURITY_FAKE") {
        return Arc::new(fake::FileProvider(path.into()));
    }
    #[cfg(windows)]
    {
        Arc::new(defender::Defender)
    }
    #[cfg(target_os = "macos")]
    {
        Arc::new(xprotect::Xprotect)
    }
    #[cfg(target_os = "linux")]
    {
        match clamav::Clamav::detect() {
            Some(c) => Arc::new(c),
            None => Arc::new(Nothing),
        }
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        Arc::new(Nothing)
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Finished {
    state: ActionState,
    message: Option<String>,
    #[serde(default)]
    data: Option<String>,
    at: DateTime<Utc>,
}

fn results_path() -> Option<std::path::PathBuf> {
    crate::config::state_subdir("security").ok().map(|d| d.join("results.json"))
}

pub struct Manager {
    provider: Arc<dyn Provider>,
    sensor: Arc<supervisor::Supervisor>,
    server_url: String,
    /// The scan or update running now, if any.
    busy: Mutex<Option<Uuid>>,
    /// Response actions running now.
    running: Mutex<std::collections::HashSet<Uuid>>,
    finished: Mutex<HashMap<Uuid, Finished>>,
    link: Mutex<Option<mpsc::Sender<AgentMsg>>>,
    /// Makes the watcher read and send the state now.
    refresh: Notify,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Manager {
    pub fn new(sensor: Arc<supervisor::Supervisor>, server_url: String) -> Self {
        Self::with_provider(detect(), sensor, server_url)
    }

    fn with_provider(provider: Arc<dyn Provider>, sensor: Arc<supervisor::Supervisor>, server_url: String) -> Self {
        let finished = results_path().and_then(|p| std::fs::read(p).ok()).and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        Manager {
            provider,
            sensor,
            server_url,
            busy: Default::default(),
            running: Default::default(),
            finished: Mutex::new(finished),
            link: Default::default(),
            refresh: Notify::new(),
        }
    }

    fn fresh(f: &Finished) -> bool {
        Utc::now() - f.at < chrono::Duration::from_std(KEEP_FINISHED).unwrap_or_default()
    }

    /// Actions to list in `Auth`: running, or finished within the hour.
    pub fn ids(&self) -> Vec<Uuid> {
        let mut f = lock(&self.finished);
        f.retain(|_, v| Self::fresh(v));
        lock(&self.busy).iter().copied().chain(lock(&self.running).iter().copied()).chain(f.keys().copied()).collect()
    }

    fn finish(&self, request_id: Uuid, state: ActionState, message: String, data: Option<String>) -> AgentMsg {
        let message: String = message.chars().take(MESSAGE_MAX).collect();
        let mut f = lock(&self.finished);
        f.insert(request_id, Finished { state, message: Some(message.clone()), data: data.clone(), at: Utc::now() });
        f.retain(|_, v| Self::fresh(v));
        if let Some(p) = results_path() {
            let _ = std::fs::write(p, serde_json::to_vec(&*f).unwrap_or_default());
        }
        AgentMsg::SecurityActionResult { request_id, state, message: Some(message), data }
    }

    /// New connection: resend recent results, then report the state.
    pub async fn attach(&self, tx: mpsc::Sender<AgentMsg>) {
        let resend: Vec<AgentMsg> = lock(&self.finished)
            .iter()
            .filter(|(_, v)| Self::fresh(v))
            .map(|(id, v)| AgentMsg::SecurityActionResult { request_id: *id, state: v.state, message: v.message.clone(), data: v.data.clone() })
            .collect();
        for m in resend {
            let _ = tx.send(m).await;
        }
        *lock(&self.link) = Some(tx);
    }

    pub fn detach(&self) {
        *lock(&self.link) = None;
    }

    pub fn refresh(&self) {
        self.refresh.notify_one();
    }

    async fn emit(&self, msg: AgentMsg) {
        let tx = lock(&self.link).clone();
        if let Some(tx) = tx {
            let _ = tx.send(msg).await;
        }
    }

    /// Sends the state now, then again whenever it changes, until the connection closes.
    pub async fn watch(self: Arc<Self>, tx: mpsc::Sender<AgentMsg>) {
        let mut last: Option<Report> = None;
        let mut tick = tokio::time::interval(POLL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let forced = tokio::select! {
                _ = tick.tick() => last.is_none(),
                _ = self.refresh.notified() => true,
                _ = self.sensor.changed.notified() => false,
                _ = tx.closed() => return,
            };
            let p = self.provider.clone();
            let Ok(mut report) = tokio::task::spawn_blocking(move || p.status()).await else { continue };
            report.products.extend(self.sensor.product());
            if !forced && last.as_ref() == Some(&report) {
                continue;
            }
            if tx.send(AgentMsg::SecurityStatus(report.clone())).await.is_err() {
                return;
            }
            last = Some(report);
        }
    }

    /// Runs a scan or update and reports on it. One at a time: a second request while one
    /// runs fails at once.
    pub async fn action(self: Arc<Self>, request_id: Uuid, product: ProductKind, action: Action) {
        let free = {
            let mut busy = lock(&self.busy);
            let free = busy.is_none();
            if free {
                *busy = Some(request_id);
            }
            free
        };
        if !free {
            let message = Some("another scan or signature update is already running on this machine".to_string());
            self.emit(AgentMsg::SecurityActionResult { request_id, state: ActionState::Failed, message, data: None }).await;
            return;
        }
        info!(%request_id, product = product.as_str(), action = action.as_str(), "security action started");
        self.emit(AgentMsg::SecurityActionResult { request_id, state: ActionState::Running, message: None, data: None }).await;
        let res = if product == ProductKind::Rmm {
            let kind = if action == Action::FullScan { crate::sensor::scan::Kind::Full } else { crate::sensor::scan::Kind::Quick };
            Ok(self.sensor.scan(kind, None).await)
        } else {
            let p = self.provider.clone();
            tokio::task::spawn_blocking(move || p.run(product, action)).await
        };
        let (state, message) = match res {
            Ok(Ok(m)) => (ActionState::Succeeded, m),
            Ok(Err(e)) => (ActionState::Failed, format!("{e:#}")),
            Err(e) => (ActionState::Failed, format!("the {} crashed: {e}", action.label())),
        };
        if state == ActionState::Failed {
            warn!(%request_id, action = action.as_str(), "security action failed: {message}");
        }
        let msg = self.finish(request_id, state, message, None);
        *lock(&self.busy) = None;
        self.emit(msg).await;
        self.refresh();
    }

    /// Runs a response action. These don't wait for scans: killing a process during a full
    /// scan must work.
    pub async fn respond(self: Arc<Self>, request_id: Uuid, action: ResponseAction) {
        if !lock(&self.running).insert(request_id) {
            return;
        }
        info!(%request_id, action = action.name(), "response action");
        self.emit(AgentMsg::SecurityActionResult { request_id, state: ActionState::Running, message: None, data: None }).await;
        let name = action.name();
        let res: Result<(String, serde_json::Value)> = match action {
            ResponseAction::KillProcess { pid, tree } => blocking(move || response::kill_process(pid, tree)).await,
            ResponseAction::QuarantineFile { path } => blocking(move || response::quarantine_file(&path)).await,
            ResponseAction::RestoreFile { id } => blocking(move || response::restore_file(id)).await,
            ResponseAction::DeleteQuarantined { id } => blocking(move || response::delete_quarantined(id)).await,
            ResponseAction::Isolate { allow } => {
                let url = self.server_url.clone();
                blocking(move || isolation::isolate(&url, &allow).map(|m| (m, serde_json::json!({ "isolated": true })))).await
            }
            ResponseAction::Release => blocking(move || isolation::release().map(|m| (m, serde_json::json!({ "isolated": false })))).await,
            ResponseAction::ScanPath { path } => {
                self.sensor.scan(crate::sensor::scan::Kind::Path, Some(path)).await.map(|m| (m, serde_json::Value::Null))
            }
            ResponseAction::CollectTriage => self.triage(request_id).await,
        };
        let (state, message, data) = match res {
            Ok((m, d)) => (ActionState::Succeeded, m, (!d.is_null()).then(|| d.to_string())),
            Err(e) => {
                warn!(%request_id, action = name, "response action failed: {e:#}");
                (ActionState::Failed, format!("{e:#}"), None)
            }
        };
        let msg = self.finish(request_id, state, message, data);
        lock(&self.running).remove(&request_id);
        self.emit(msg).await;
        match name {
            "quarantine_file" | "restore_file" | "delete_quarantined" => self.sensor.quarantine_changed(),
            "isolate" | "release" => self.sensor.report_status(),
            _ => {}
        }
    }

    /// Builds the triage package and streams it to the server.
    async fn triage(&self, request_id: Uuid) -> Result<(String, serde_json::Value)> {
        let sensor = serde_json::to_value(self.sensor.status()).unwrap_or_default();
        let pkg = tokio::task::spawn_blocking(move || response::collect_triage(sensor)).await??;
        let sha = response::sha256(&pkg);
        let tx = lock(&self.link).clone().ok_or_else(|| anyhow::anyhow!("disconnected while collecting"))?;
        let mut offset = 0usize;
        while offset < pkg.len() || offset == 0 {
            let end = (offset + TRIAGE_CHUNK).min(pkg.len());
            let done = end >= pkg.len();
            tx.send(AgentMsg::TriageChunk { request_id, offset: offset as u64, data: pkg[offset..end].to_vec(), done })
                .await
                .map_err(|_| anyhow::anyhow!("disconnected while sending the package"))?;
            offset = end;
            if done {
                break;
            }
        }
        Ok((format!("Collected a {} KB triage package", pkg.len().div_ceil(1024)), serde_json::json!({ "size": pkg.len(), "sha256": sha })))
    }
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f).await.map_err(|e| anyhow::anyhow!("crashed: {e}"))?
}

impl Manager {
    pub fn sensor(&self) -> &Arc<supervisor::Supervisor> {
        &self.sensor
    }
}

/// `rmm-agent security [--run ACTION]`.
pub fn cli(run: Option<&str>) -> Result<()> {
    let provider = detect();
    if let Some(a) = run {
        let action = Action::parse(a).ok_or_else(|| anyhow::anyhow!("unknown action {a}: quick_scan, full_scan or update_signatures"))?;
        let report = provider.status();
        let product = report
            .products
            .iter()
            .find(|p| p.actions.contains(&action))
            .ok_or_else(|| anyhow::anyhow!("no product on this machine can run a {}", action.label()))?;
        eprintln!("running a {} with {}...", action.label(), product.name);
        println!("{}", provider.run(product.kind, action)?);
        return Ok(());
    }
    println!("{}", serde_json::to_string_pretty(&provider.status())?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmm_proto::security::Product;

    struct Slow;

    impl Provider for Slow {
        fn status(&self) -> Report {
            let mut p = Product::new(ProductKind::Clamav, "ClamAV");
            p.enabled = Some(true);
            Report { products: vec![p], ..Default::default() }
        }

        fn run(&self, _: ProductKind, action: Action) -> Result<String> {
            std::thread::sleep(Duration::from_millis(300));
            if action == Action::FullScan { anyhow::bail!("disk on fire") } else { Ok("clean".into()) }
        }
    }

    async fn next(rx: &mut mpsc::Receiver<AgentMsg>) -> AgentMsg {
        tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.expect("a message").expect("open channel")
    }

    #[tokio::test]
    async fn one_action_at_a_time_and_results_are_resent() {
        let m = Arc::new(Manager::with_provider(Arc::new(Slow), supervisor::Supervisor::new(), "http://127.0.0.1:1".into()));
        let (tx, mut rx) = mpsc::channel(16);
        m.attach(tx.clone()).await;
        let watcher = tokio::spawn(m.clone().watch(tx.clone()));
        assert!(matches!(next(&mut rx).await, AgentMsg::SecurityStatus(r) if r.products.len() == 1), "state on connect");

        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let first = tokio::spawn(m.clone().action(a, ProductKind::Clamav, Action::QuickScan));
        assert!(matches!(next(&mut rx).await, AgentMsg::SecurityActionResult { request_id, state: ActionState::Running, .. } if request_id == a));
        assert_eq!(m.ids(), [a]);
        m.clone().action(b, ProductKind::Clamav, Action::FullScan).await;
        assert!(matches!(next(&mut rx).await, AgentMsg::SecurityActionResult { request_id, state: ActionState::Failed, .. } if request_id == b));
        first.await.unwrap();
        match next(&mut rx).await {
            AgentMsg::SecurityActionResult { request_id, state: ActionState::Succeeded, message, .. } => {
                assert_eq!((request_id, message.as_deref()), (a, Some("clean")))
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(matches!(next(&mut rx).await, AgentMsg::SecurityStatus(_)), "fresh state after an action");

        // A failing action reports its error.
        let c = Uuid::new_v4();
        m.clone().action(c, ProductKind::Clamav, Action::FullScan).await;
        let _running = next(&mut rx).await;
        assert!(matches!(next(&mut rx).await, AgentMsg::SecurityActionResult { state: ActionState::Failed, message: Some(msg), .. } if msg == "disk on fire"));

        // Reconnect: the finished results come again, and are listed in Auth.
        watcher.abort();
        m.detach();
        let (tx2, mut rx2) = mpsc::channel(16);
        m.attach(tx2).await;
        let mut resent = vec![];
        while let Ok(msg) = rx2.try_recv() {
            if let AgentMsg::SecurityActionResult { request_id, .. } = msg {
                resent.push(request_id);
            }
        }
        resent.sort();
        let mut ids = m.ids();
        ids.sort();
        assert_eq!(resent, ids);
        assert!(ids.contains(&a) && ids.contains(&c));
    }
}
