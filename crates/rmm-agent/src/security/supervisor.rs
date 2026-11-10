//! Supervises the sensor process (`rmm-agent sensor`): starts it when the policy turns it on,
//! restarts it with backoff when it dies (and reports the crashes), stops it when the policy
//! turns it off, and relays between it and the server.
//!
//! Content bundles are verified here against the release key before the sensor ever sees
//! them, and kept on disk with their signature so the sensor runs with them after a reboot
//! even before the server is reachable. Detections are kept on disk until the server
//! acknowledges them.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Utc};
use rmm_proto::AgentMsg;
use rmm_proto::security::{Action, Product, ProductKind, SensorDetection, SensorHealth, SensorPolicy, SensorStatus};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{Notify, mpsc, oneshot};
use tracing::{info, warn};
use uuid::Uuid;

use crate::sensor::{FromSensor, ToSensor, scan};

/// Unacknowledged detections kept on disk, at most.
const PENDING_MAX: usize = 1000;

#[derive(Clone, Serialize, Deserialize)]
struct StoredContent {
    version: String,
    signature: String,
    created_at: DateTime<Utc>,
}

#[derive(Default)]
struct Inner {
    policy: SensorPolicy,
    /// (meta, bundle JSON)
    content: Option<(StoredContent, String)>,
    running: bool,
    restarts: u32,
    error: Option<String>,
    health: Option<SensorHealth>,
    cmd: Option<mpsc::UnboundedSender<ToSensor>>,
    scans: HashMap<Uuid, oneshot::Sender<(bool, String)>>,
    pending: Vec<SensorDetection>,
}

pub struct Supervisor {
    inner: Mutex<Inner>,
    link: Mutex<Option<mpsc::Sender<AgentMsg>>>,
    wake: Notify,
    /// The sensor started, stopped or got new content: the protection report (which lists
    /// the sensor as a product) should be re-read.
    pub changed: Notify,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn dir() -> Result<PathBuf> {
    crate::config::state_subdir("security")
}

/// The key content must be signed with: the release key the agent was built with. Debug
/// builds also take `RMM_CONTENT_PUBKEY`, so tests can sign their own bundles.
fn pubkey() -> Option<String> {
    #[cfg(debug_assertions)]
    if let Ok(k) = std::env::var("RMM_CONTENT_PUBKEY") {
        return Some(k);
    }
    crate::update::PUBKEY.map(str::to_string)
}

impl Supervisor {
    pub fn new() -> Arc<Self> {
        let mut inner = Inner::default();
        if let Ok(d) = dir() {
            inner.policy = std::fs::read(d.join("policy.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
            inner.pending = std::fs::read(d.join("pending-detections.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
            let stored = std::fs::read(d.join("content.json")).ok().and_then(|b| serde_json::from_slice::<StoredContent>(&b).ok());
            if let (Some(meta), Ok(json)) = (stored, std::fs::read(d.join("content.bundle"))) {
                match Self::verify(&meta.version, &json, &meta.signature) {
                    Ok(b) => inner.content = Some((StoredContent { created_at: b.created_at, ..meta }, String::from_utf8_lossy(&json).into_owned())),
                    Err(e) => warn!("stored security content rejected: {e:#}"),
                }
            }
        }
        Arc::new(Supervisor { inner: Mutex::new(inner), link: Mutex::new(None), wake: Notify::new(), changed: Notify::new() })
    }

    fn verify(version: &str, json: &[u8], signature: &str) -> Result<rmm_content::Bundle> {
        let key = pubkey().ok_or_else(|| anyhow!("this agent was built without a release key (RMM_UPDATE_PUBKEY), so it can't verify detection content"))?;
        Ok(rmm_content::verify(json, version, signature, &key)?)
    }

    pub fn attach(&self, tx: mpsc::Sender<AgentMsg>) {
        let pending = lock(&self.inner).pending.clone();
        for d in pending {
            let _ = tx.try_send(AgentMsg::SensorDetection(d));
        }
        let _ = tx.try_send(AgentMsg::SensorStatus(self.status()));
        let _ = tx.try_send(quarantine_list());
        *lock(&self.link) = Some(tx);
    }

    pub fn detach(&self) {
        *lock(&self.link) = None;
    }

    fn send(&self, msg: AgentMsg) {
        if let Some(tx) = lock(&self.link).clone() {
            let _ = tx.try_send(msg);
        }
    }

    pub fn status(&self) -> SensorStatus {
        let i = lock(&self.inner);
        SensorStatus {
            enabled: i.policy.enabled,
            running: i.running,
            restarts: i.restarts,
            content_version: i.content.as_ref().map(|c| c.0.version.clone()),
            error: i.error.clone(),
            isolated: super::isolation::state().isolated,
            health: i.health.clone(),
        }
    }

    pub fn report_status(&self) {
        self.send(AgentMsg::SensorStatus(self.status()));
    }

    pub fn quarantine_changed(&self) {
        self.send(quarantine_list());
    }

    /// Our sensor, as one of the machine's protection products.
    pub fn product(&self) -> Option<Product> {
        let i = lock(&self.inner);
        if !i.policy.enabled {
            return None;
        }
        let mut p = Product::new(ProductKind::Rmm, "RMM sensor");
        p.version = Some(crate::collect::AGENT_VERSION.to_string());
        p.enabled = Some(i.running);
        p.realtime = Some(i.running && i.content.is_some());
        if let Some((c, _)) = &i.content {
            p.signature_version = Some(c.version.clone());
            p.signatures_updated_at = Some(c.created_at);
        }
        let sched: serde_json::Value = crate::config::state_dir()
            .join("sensor/schedule.json")
            .to_str()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        p.last_quick_scan = sched.get("last_quick").and_then(|v| serde_json::from_value(v.clone()).ok());
        p.last_full_scan = sched.get("last_full").and_then(|v| serde_json::from_value(v.clone()).ok());
        if i.running && i.content.is_some() {
            p.actions = vec![Action::QuickScan, Action::FullScan];
        }
        p.detail = i.error.clone().or_else(|| (i.content.is_none()).then(|| "Waiting for signed detection content from the server".to_string()));
        Some(p)
    }

    fn persist_pending(i: &Inner) {
        if let Ok(d) = dir() {
            let _ = std::fs::write(d.join("pending-detections.json"), serde_json::to_vec(&i.pending).unwrap_or_default());
        }
    }

    pub fn ack(&self, id: &str) {
        let mut i = lock(&self.inner);
        let before = i.pending.len();
        i.pending.retain(|d| d.id != id);
        if i.pending.len() != before {
            Self::persist_pending(&i);
        }
    }

    pub fn set_policy(&self, policy: SensorPolicy) {
        let mut i = lock(&self.inner);
        if i.policy == policy {
            return;
        }
        if let Ok(d) = dir() {
            let _ = std::fs::write(d.join("policy.json"), serde_json::to_vec(&policy).unwrap_or_default());
        }
        i.policy = policy.clone();
        if let Some(cmd) = &i.cmd {
            let _ = cmd.send(ToSensor::Configure { policy, content: None });
        }
        drop(i);
        self.wake.notify_one();
        self.changed.notify_one();
        self.report_status();
    }

    /// A content bundle from the server: verified, kept, and handed to the sensor.
    pub fn set_content(&self, version: String, bundle: Vec<u8>, signature: String) {
        let res: Result<rmm_content::Bundle> = (|| {
            let b = Self::verify(&version, &bundle, &signature)?;
            let d = dir()?;
            std::fs::write(d.join("content.bundle"), &bundle)?;
            std::fs::write(d.join("content.json"), serde_json::to_vec(&StoredContent { version: version.clone(), signature: signature.clone(), created_at: b.created_at })?)?;
            Ok(b)
        })();
        let mut i = lock(&self.inner);
        match res {
            Ok(b) => {
                info!(%version, rules = b.rule_count(), "security content installed");
                let json = String::from_utf8_lossy(&bundle).into_owned();
                i.content = Some((StoredContent { version, signature, created_at: b.created_at }, json.clone()));
                i.error = None;
                if let Some(cmd) = &i.cmd {
                    let _ = cmd.send(ToSensor::Configure { policy: i.policy.clone(), content: Some(json) });
                }
            }
            Err(e) => {
                warn!(%version, "security content rejected: {e:#}");
                i.error = Some(format!("content {version} rejected: {e:#}"));
            }
        }
        drop(i);
        self.changed.notify_one();
        self.report_status();
    }

    /// Runs a scan in the sensor and waits for it.
    pub async fn scan(&self, kind: scan::Kind, path: Option<String>) -> Result<String> {
        let (tx, rx) = oneshot::channel();
        let id = Uuid::new_v4();
        {
            let mut i = lock(&self.inner);
            let Some(cmd) = i.cmd.clone() else { bail!("the sensor isn't running (it's switched off in this client's security policy, or starting)") };
            if i.content.is_none() {
                bail!("no detection content yet: upload and roll out a signed bundle first");
            }
            i.scans.insert(id, tx);
            cmd.send(ToSensor::Scan { request_id: Some(id), kind, path }).map_err(|_| anyhow!("the sensor stopped"))?;
        }
        let limit = match kind {
            scan::Kind::Full => super::timeout(Action::FullScan),
            _ => super::timeout(Action::QuickScan),
        };
        match tokio::time::timeout(limit, rx).await {
            Ok(Ok((true, msg))) => Ok(msg),
            Ok(Ok((false, msg))) => Err(anyhow!(msg)),
            Ok(Err(_)) => Err(anyhow!("the sensor stopped during the scan")),
            Err(_) => {
                lock(&self.inner).scans.remove(&id);
                Err(anyhow!("the scan didn't finish in time"))
            }
        }
    }

    /// Keeps the sensor running while the policy says so. Runs for the agent's lifetime.
    pub async fn run(self: Arc<Self>) {
        let mut backoff = Duration::from_secs(5);
        loop {
            if !lock(&self.inner).policy.enabled {
                self.wake.notified().await;
                continue;
            }
            let started = std::time::Instant::now();
            match self.clone().run_child().await {
                Ok(true) => continue, // stopped on purpose
                Ok(false) => warn!("sensor exited"),
                Err(e) => warn!("sensor: {e:#}"),
            }
            {
                let mut i = lock(&self.inner);
                i.restarts += 1;
                if i.error.is_none() {
                    i.error = Some("the sensor stopped unexpectedly; restarting".into());
                }
            }
            self.report_status();
            if started.elapsed() > Duration::from_secs(600) {
                backoff = Duration::from_secs(5);
            }
            tokio::select! {
                _ = tokio::time::sleep(backoff) => {}
                _ = self.wake.notified() => {}
            }
            backoff = (backoff * 2).min(Duration::from_secs(300));
        }
    }

    /// One sensor process, start to exit. `Ok(true)` when we stopped it.
    async fn run_child(self: Arc<Self>) -> Result<bool> {
        let exe = std::env::current_exe().context("finding our own binary")?;
        let mut child = tokio::process::Command::new(exe)
            .arg("sensor")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .context("starting the sensor")?;
        let mut stdin = child.stdin.take().context("sensor stdin")?;
        let mut lines = BufReader::new(child.stdout.take().context("sensor stdout")?).lines();
        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<ToSensor>();
        {
            let mut i = lock(&self.inner);
            let _ = cmd_tx.send(ToSensor::Configure { policy: i.policy.clone(), content: i.content.as_ref().map(|c| c.1.clone()) });
            i.cmd = Some(cmd_tx);
            i.running = true;
            if i.error.as_deref().is_some_and(|e| e.contains("stopped unexpectedly")) {
                i.error = None;
            }
        }
        info!("sensor started");
        self.changed.notify_one();
        self.report_status();
        let mut stopped = false;
        let result = loop {
            tokio::select! {
                line = lines.next_line() => match line {
                    Ok(Some(l)) => self.handle(&l),
                    Ok(None) | Err(_) => break Ok(stopped),
                },
                Some(cmd) = cmd_rx.recv() => {
                    let mut buf = serde_json::to_vec(&cmd)?;
                    buf.push(b'\n');
                    if stdin.write_all(&buf).await.is_err() {
                        break Ok(stopped);
                    }
                    let _ = stdin.flush().await;
                }
                _ = self.wake.notified(), if !stopped => {
                    let policy = lock(&self.inner).policy.clone();
                    if !policy.enabled {
                        stopped = true;
                        // The policy first, so the sensor knows it's being switched off (and
                        // takes its decoys away), not just restarted.
                        let mut buf = serde_json::to_vec(&ToSensor::Configure { policy, content: None })?;
                        buf.push(b'\n');
                        buf.extend(serde_json::to_vec(&ToSensor::Shutdown)?);
                        buf.push(b'\n');
                        let _ = stdin.write_all(&buf).await;
                        let _ = stdin.flush().await;
                    }
                }
            }
        };
        if tokio::time::timeout(Duration::from_secs(10), child.wait()).await.is_err() {
            let _ = child.kill().await;
        }
        let scans: Vec<_> = {
            let mut i = lock(&self.inner);
            i.cmd = None;
            i.running = false;
            i.health = None;
            i.scans.drain().map(|(_, tx)| tx).collect()
        };
        for tx in scans {
            let _ = tx.send((false, "the sensor stopped".into()));
        }
        info!(stopped, "sensor stopped");
        self.changed.notify_one();
        self.report_status();
        result
    }

    fn handle(&self, line: &str) {
        let msg: FromSensor = match serde_json::from_str(line) {
            Ok(m) => m,
            Err(e) => return warn!("sensor: bad message: {e}"),
        };
        match msg {
            FromSensor::Ready => {}
            FromSensor::Health(h) => {
                lock(&self.inner).health = Some(h);
                self.report_status();
            }
            FromSensor::Detection(d) => {
                let d = *d;
                {
                    let mut i = lock(&self.inner);
                    i.pending.retain(|p| p.id != d.id);
                    i.pending.push(d.clone());
                    if i.pending.len() > PENDING_MAX {
                        let extra = i.pending.len() - PENDING_MAX;
                        i.pending.drain(..extra);
                    }
                    Self::persist_pending(&i);
                }
                self.send(AgentMsg::SensorDetection(d));
            }
            FromSensor::ScanDone { request_id, ok, message } => {
                if let Some(id) = request_id
                    && let Some(tx) = lock(&self.inner).scans.remove(&id)
                {
                    let _ = tx.send((ok, message));
                } else {
                    info!(ok, "scheduled scan finished: {message}");
                }
            }
            FromSensor::QuarantineChanged => self.quarantine_changed(),
        }
    }
}

pub fn quarantine_list() -> AgentMsg {
    AgentMsg::QuarantineList { items: super::quarantine::Store::open().map(|s| s.list()).unwrap_or_default() }
}
