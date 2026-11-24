//! Disk encryption status (BitLocker, FileVault, LUKS) and BitLocker recovery passwords for
//! the server's escrow (docs/design/disk-encryption.md).
//!
//! The [`Manager`] reports after connecting, whenever the state changes (it is re-read every
//! [`POLL`]), at least every [`REPORT_SECS`] and when the server asks. Reports carry protector
//! ids, never keys: the server asks for one recovery password at a time, and the agent keeps
//! nothing on disk.
//!
//! Debug builds: `RMM_DISKENC_FAKE=<file>` reports the state in that JSON file while it exists
//! ([`fake`]).

#[cfg(any(windows, test))]
mod bitlocker;
#[cfg(debug_assertions)]
mod fake;
#[cfg(any(target_os = "macos", test))]
mod filevault;
#[cfg(any(target_os = "linux", test))]
mod luks;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use rmm_proto::AgentMsg;
use rmm_proto::diskenc::{MAX_VOLUMES, ProtectorOp, REPORT_SECS, Report};
use rmm_proto::localadmin::Secret;
use tokio::sync::{Notify, mpsc};
use tracing::{info, warn};
use uuid::Uuid;

/// How often the state is re-read; only changes are sent between keep-alives.
const POLL: Duration = Duration::from_secs(900);

pub trait Provider: Send + Sync {
    /// Never fails as a whole: problems go in `Report::error`.
    fn report(&self) -> Report;
    /// The recovery password of a volume's numerical password protector.
    fn recovery_key(&self, volume_id: &str, protector_id: &str) -> Result<String>;
    /// Adds or rotates a volume's recovery password; describes what was done.
    fn protector(&self, volume_id: &str, op: ProtectorOp) -> Result<String>;
}

/// Platforms without a reader, and where none of the products applies.
#[allow(dead_code)]
struct Nothing;

impl Provider for Nothing {
    fn report(&self) -> Report {
        Report { error: Some("disk encryption isn't read on this platform".into()), ..Default::default() }
    }

    fn recovery_key(&self, _: &str, _: &str) -> Result<String> {
        anyhow::bail!("recovery keys are escrowed for BitLocker only")
    }

    fn protector(&self, _: &str, _: ProtectorOp) -> Result<String> {
        anyhow::bail!("recovery passwords can be added for BitLocker only")
    }
}

fn platform() -> Arc<dyn Provider> {
    #[cfg(windows)]
    {
        Arc::new(bitlocker::Bitlocker)
    }
    #[cfg(target_os = "macos")]
    {
        Arc::new(filevault::Filevault)
    }
    #[cfg(target_os = "linux")]
    {
        Arc::new(luks::Luks)
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        Arc::new(Nothing)
    }
}

pub fn detect() -> Arc<dyn Provider> {
    let real = platform();
    #[cfg(debug_assertions)]
    if let Some(path) = std::env::var_os("RMM_DISKENC_FAKE") {
        return Arc::new(fake::FileProvider { path: path.into(), real });
    }
    real
}

pub struct Manager {
    provider: Arc<dyn Provider>,
    link: Mutex<Option<mpsc::Sender<AgentMsg>>>,
    refresh: Notify,
    /// One protector change at a time.
    busy: tokio::sync::Mutex<()>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Manager {
    pub fn new() -> Self {
        Manager { provider: detect(), link: Default::default(), refresh: Notify::new(), busy: Default::default() }
    }

    pub fn attach(&self, tx: mpsc::Sender<AgentMsg>) {
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

    async fn read(&self) -> Option<Report> {
        let p = self.provider.clone();
        let mut r = tokio::task::spawn_blocking(move || p.report()).await.ok()?;
        r.volumes.truncate(MAX_VOLUMES);
        Some(r)
    }

    /// Sends the state now, then on change, on request and at least every 6 hours, until the
    /// connection closes.
    pub async fn watch(self: Arc<Self>, tx: mpsc::Sender<AgentMsg>) {
        let mut last: Option<Report> = None;
        let mut sent_at = tokio::time::Instant::now();
        let mut tick = tokio::time::interval(POLL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let forced = tokio::select! {
                _ = tick.tick() => last.is_none(),
                _ = self.refresh.notified() => true,
                _ = tx.closed() => return,
            };
            let Some(report) = self.read().await else { continue };
            if !forced && last.as_ref() == Some(&report) && sent_at.elapsed() < Duration::from_secs(REPORT_SECS) {
                continue;
            }
            if tx.send(AgentMsg::DiskEncryption(report.clone())).await.is_err() {
                return;
            }
            sent_at = tokio::time::Instant::now();
            last = Some(report);
        }
    }

    /// The server asks for one recovery password.
    pub async fn recovery_key(self: Arc<Self>, request_id: Uuid, volume_id: String, protector_id: String) {
        let p = self.provider.clone();
        let (v, pid) = (volume_id.clone(), protector_id.clone());
        let res = tokio::task::spawn_blocking(move || p.recovery_key(&v, &pid)).await;
        let (key, error) = match res {
            Ok(Ok(k)) => (Some(Secret(k)), None),
            Ok(Err(e)) => (None, Some(format!("{e:#}"))),
            Err(e) => (None, Some(format!("reading the recovery key crashed: {e}"))),
        };
        if let Some(e) = &error {
            warn!(%request_id, volume = %volume_id, "recovery key not read: {e}");
        } else {
            info!(%request_id, volume = %volume_id, "recovery key sent for escrow");
        }
        self.emit(AgentMsg::DiskRecoveryKey { request_id, volume_id, protector_id, key, error }).await;
    }

    /// Adds or rotates a recovery password, answers, then reports the new state.
    pub async fn protector(self: Arc<Self>, request_id: Uuid, volume_id: String, op: ProtectorOp) {
        let _one = self.busy.lock().await;
        let p = self.provider.clone();
        let v = volume_id.clone();
        let res = tokio::task::spawn_blocking(move || p.protector(&v, op)).await;
        let (ok, message) = match res {
            Ok(Ok(m)) => (true, m),
            Ok(Err(e)) => (false, format!("{e:#}")),
            Err(e) => (false, format!("changing the protector crashed: {e}")),
        };
        info!(%request_id, volume = %volume_id, op = op.as_str(), ok, "recovery protector: {message}");
        let message: String = message.chars().take(1000).collect();
        self.emit(AgentMsg::DiskProtectorResult { request_id, ok, message }).await;
        self.refresh();
    }
}
