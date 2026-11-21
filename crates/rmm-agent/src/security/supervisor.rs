//! Supervises the sensor process (`rmm-agent sensor`): starts it when the policy turns it on,
//! restarts it with backoff when it dies (and reports the crashes), stops it when the policy
//! turns it off, and relays between it and the server.
//!
//! Content bundles are verified here against the release key before the sensor ever sees
//! them, and kept on disk with their signature so the sensor runs with them after a reboot
//! even before the server is reachable. Detections are kept on disk until the server
//! acknowledges them.
//!
//! Signature databases are offered over the socket (version, size, hash) and downloaded over
//! HTTPS from the server (`/api/agent/databases/{version}`, resumable), into
//! `security/db/<hash>.part`; checked for size, hash and the release key's signature; then
//! renamed into place. The one it replaces stays as the fallback (and is what a rollback
//! returns to, without a download); older files are deleted.
//!
//! Reputation lookup (antivirus milestone 5): the sensor reports each program hash its own
//! content found nothing in; they're asked about once each (the asked set is kept on disk), in
//! batches, off the decision path. A hash the server knows is reported as an alert only:
//! server answers aren't signed, so they never kill, deny or quarantine anything.
//!
//! A sensor that says nothing for [`QUIET`] is killed and restarted: with real-time
//! protection on, programs could be waiting on it (a stopped process keeps its fanotify
//! descriptor open; a killed one releases every pending decision). It says it's alive every
//! [`ALIVE_EVERY`] from a thread of its own, so a long scan or database load doesn't count as
//! silence. A check that comes late (the machine slept, or the agent itself wasn't scheduled)
//! starts the count again instead of killing: see [`Quiet`].

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
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::sensor::{DbFile, DbSet, FromSensor, ToSensor, scan};
use rmm_proto::security::DatabaseOffer;

/// A signature database kept on disk.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct StoredDb {
    version: String,
    sha256: String,
    size: u64,
    created_at: DateTime<Utc>,
}

impl StoredDb {
    fn path(&self) -> Option<PathBuf> {
        db_dir().ok().map(|d| d.join(format!("{}.rmmdb", &self.sha256[..self.sha256.len().min(32)])))
    }

    fn file(&self) -> Option<DbFile> {
        Some(DbFile { version: self.version.clone(), path: self.path()? })
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct DbState {
    current: Option<StoredDb>,
    previous: Option<StoredDb>,
}

impl DbState {
    fn set(&self) -> DbSet {
        DbSet { current: self.current.as_ref().and_then(StoredDb::file), previous: self.previous.as_ref().and_then(StoredDb::file) }
    }
}

fn db_dir() -> Result<PathBuf> {
    crate::config::state_subdir("security/db")
}

/// Waits between download attempts; after the last one the failure is reported.
const DB_RETRIES: [u64; 3] = [30, 120, 600];

/// Unacknowledged detections kept on disk, at most.
const PENDING_MAX: usize = 1000;

/// How often the sensor says it's alive (from its tick thread).
pub const ALIVE_EVERY: Duration = Duration::from_secs(2);
/// This much silence and it's killed: five missed messages. It was 30 s, which a stopped
/// sensor could hold every exec on the machine for; the message comes from a thread that does
/// nothing else (raised back to normal priority where the sensor may), so a busy sensor still
/// sends it, and a late check never kills (see [`Quiet`]).
pub const QUIET: Duration = Duration::from_secs(10);
/// How often the agent checks.
const CHECK_EVERY: Duration = Duration::from_secs(2);

/// When the sensor was last heard from, and whether its silence means it's stuck.
///
/// Silence is only counted while the agent itself was running: a check that comes much later
/// than [`CHECK_EVERY`] means the machine was asleep (or the agent wasn't scheduled either),
/// and then the sensor gets a fresh [`QUIET`] to speak. Without that, a clock that counts
/// suspended time (Windows' `Instant`, from QueryPerformanceCounter, may; Linux's
/// CLOCK_MONOTONIC doesn't) would kill a healthy sensor on every wake from sleep.
#[derive(Debug, Clone, Copy)]
pub struct Quiet {
    heard: std::time::Instant,
    checked: std::time::Instant,
}

impl Quiet {
    pub fn new(now: std::time::Instant) -> Self {
        Quiet { heard: now, checked: now }
    }

    pub fn heard(&mut self, now: std::time::Instant) {
        self.heard = now;
    }

    /// True when the sensor should be killed.
    pub fn check(&mut self, now: std::time::Instant) -> bool {
        let gap = now.saturating_duration_since(self.checked);
        self.checked = now;
        if gap > CHECK_EVERY * 3 {
            self.heard = now;
            return false;
        }
        now.saturating_duration_since(self.heard) > QUIET
    }
}
/// Hashes waiting to be asked are sent this long after the first of them at most.
const REPUTATION_WAIT: Duration = Duration::from_secs(10);
/// Hashes remembered as asked; past that the set starts over (asking twice is harmless).
const ASKED_MAX: usize = 200_000;

#[derive(Default)]
struct Reputation {
    asked: std::collections::HashSet<[u8; 32]>,
    queue: Vec<rmm_proto::security::HashSeen>,
    since: Option<std::time::Instant>,
    /// Paths of hashes sent and not answered yet, for the detection.
    paths: HashMap<String, Option<String>>,
}

fn asked_path() -> Option<PathBuf> {
    dir().ok().map(|d| d.join("reputation-asked.bin"))
}

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
    db: DbState,
    /// What the sensor says it loaded.
    db_loaded: Option<String>,
    /// A download in progress (its version).
    db_fetching: Option<String>,
    /// Where to download from: server URL, agent id, secret.
    server: Option<(String, Uuid, String)>,
    rep: Reputation,
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
pub(crate) fn pubkey() -> Option<String> {
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
            inner.db = std::fs::read(d.join("database.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
            if let Some(b) = asked_path().and_then(|p| std::fs::read(p).ok()) {
                inner.rep.asked = b.as_chunks::<32>().0.iter().copied().collect();
            }
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

    /// Credentials for database downloads (the agent's own, as on the socket).
    pub fn set_server(&self, url: String, agent_id: Uuid, secret: String) {
        lock(&self.inner).server = Some((url, agent_id, secret));
    }

    pub fn attach(&self, tx: mpsc::Sender<AgentMsg>) {
        {
            // A new connection: a download that gave up may be offered again.
            let mut i = lock(&self.inner);
            if i.error.as_deref().is_some_and(|e| e.contains("couldn't be downloaded")) {
                i.error = None;
            }
        }
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
            // What the sensor runs; with the sensor stopped, what it would run.
            database_version: if i.running { i.db_loaded.clone() } else { i.db.current.as_ref().map(|d| d.version.clone()) },
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
        // On-access protection as it runs; with the policy's real-time protection off, unsaid
        // (the sensor still scans every program just after it starts).
        p.realtime = match i.health.as_ref().and_then(|h| h.realtime.as_ref()) {
            Some(r) if r.mode != rmm_proto::security::RealtimeMode::Off => Some(i.running && r.state == "on"),
            Some(_) => None,
            None if i.policy.realtime != rmm_proto::security::RealtimeMode::Off => Some(false),
            None => None,
        };
        if let Some((c, _)) = &i.content {
            p.signature_version = Some(c.version.clone());
            p.signatures_updated_at = Some(c.created_at);
        }
        // The signature database is what "signature age" means once there is one.
        if let Some(d) = i.db.current.as_ref().filter(|d| i.db_loaded.as_deref() == Some(d.version.as_str()) || !i.running) {
            p.signature_version = Some(d.version.clone());
            p.signatures_updated_at = Some(d.created_at);
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
        p.detail = i.error.clone().or_else(|| (i.content.is_none() && i.db.current.is_none()).then(|| "Waiting for signed detection content from the server".to_string()));
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
            let _ = cmd.send(ToSensor::Configure { policy, content: None, database: None });
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
                    let _ = cmd.send(ToSensor::Configure { policy: i.policy.clone(), content: Some(json), database: None });
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

    fn persist_db(i: &Inner) {
        if let Ok(d) = dir() {
            let _ = std::fs::write(d.join("database.json"), serde_json::to_vec(&i.db).unwrap_or_default());
        }
    }

    /// Deletes database files that are neither current nor previous.
    fn prune_db(i: &Inner) {
        let keep: Vec<PathBuf> = [&i.db.current, &i.db.previous].into_iter().flatten().filter_map(StoredDb::path).collect();
        if let Ok(d) = db_dir() {
            for e in std::fs::read_dir(d).into_iter().flatten().flatten() {
                let p = e.path();
                if p.extension().is_some_and(|x| x == "rmmdb") && !keep.contains(&p) {
                    let _ = std::fs::remove_file(&p);
                }
            }
        }
    }

    /// The database set changed: tell the sensor, the server, the protection report.
    fn db_changed(&self, mut i: std::sync::MutexGuard<'_, Inner>) {
        Self::persist_db(&i);
        Self::prune_db(&i);
        if let Some(cmd) = &i.cmd {
            let _ = cmd.send(ToSensor::Configure { policy: i.policy.clone(), content: None, database: Some(i.db.set()) });
        }
        i.db_loaded = None;
        drop(i);
        self.changed.notify_one();
        self.report_status();
    }

    /// The server's offer: nothing to do, a switch back to the previous version, no database
    /// at all, or a download.
    pub fn set_database(self: &Arc<Self>, offer: Option<DatabaseOffer>) {
        let mut i = lock(&self.inner);
        let Some(o) = offer else {
            if i.db.current.is_some() {
                info!("signature database withdrawn by the server");
                i.db.previous = i.db.current.take();
                self.db_changed(i);
            }
            return;
        };
        if i.db.current.as_ref().is_some_and(|c| c.sha256.eq_ignore_ascii_case(&o.sha256)) {
            return;
        }
        if i.db.previous.as_ref().is_some_and(|p| p.sha256.eq_ignore_ascii_case(&o.sha256)) && i.db.previous.as_ref().and_then(StoredDb::path).is_some_and(|p| p.exists()) {
            info!(version = %o.version, "signature database: back to the previous version");
            let db = &mut i.db;
            std::mem::swap(&mut db.current, &mut db.previous);
            self.db_changed(i);
            return;
        }
        if i.db_fetching.as_deref() == Some(o.version.as_str()) || i.error.as_deref().is_some_and(|e| e.contains(&o.version)) {
            return;
        }
        let Some(server) = i.server.clone() else { return };
        i.db_fetching = Some(o.version.clone());
        drop(i);
        let me = self.clone();
        tokio::spawn(async move {
            let res = me.fetch_db(&o, server).await;
            let mut i = lock(&me.inner);
            i.db_fetching = None;
            match res {
                Ok(stored) => {
                    info!(version = %o.version, "signature database installed");
                    i.error = None;
                    if i.db.current.as_ref() != Some(&stored) {
                        i.db.previous = i.db.current.take();
                    }
                    i.db.current = Some(stored);
                    me.db_changed(i);
                }
                Err(e) => {
                    warn!(version = %o.version, "signature database: {e:#}");
                    i.error = Some(format!("{e:#}"));
                    drop(i);
                    me.report_status();
                }
            }
        });
    }

    /// Downloads (retrying, resuming), checks and installs one database file.
    async fn fetch_db(&self, o: &DatabaseOffer, (url, agent_id, secret): (String, Uuid, String)) -> Result<StoredDb> {
        let key = pubkey().ok_or_else(|| anyhow!("database {}: this agent was built without a release key, so it can't verify signature databases", o.version))?;
        if o.sha256.len() != 64 || !o.sha256.bytes().all(|b| b.is_ascii_hexdigit()) || !o.version.bytes().all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b)) {
            bail!("database {}: malformed offer", o.version);
        }
        let d = db_dir()?;
        let part = d.join(format!("{}.part", &o.sha256[..32]));
        let link = format!("{}/api/agent/databases/{}", url.trim_end_matches('/'), o.version);
        let headers = [("X-Rmm-Agent", agent_id.to_string()), ("Authorization", format!("Bearer {secret}"))];
        let mut last = None;
        for (n, wait) in std::iter::once(0).chain(DB_RETRIES).enumerate() {
            if wait > 0 {
                tokio::time::sleep(Duration::from_secs(wait)).await;
            }
            match crate::fetch::download(&link, &headers, &part, o.size).await {
                Ok(()) => {
                    last = None;
                    break;
                }
                Err(e) => {
                    warn!(version = %o.version, attempt = n + 1, "signature database download: {e:#}");
                    last = Some(e);
                }
            }
        }
        if let Some(e) = last {
            bail!("database {} couldn't be downloaded: {e:#}", o.version);
        }
        // Hash and signature, off the async threads (a big database takes a moment).
        let (p, want, version) = (part.clone(), o.clone(), o.version.clone());
        let checked = tokio::task::spawn_blocking(move || -> Result<StoredDb> {
            let db = rmm_scan::db::Database::open(&p, &key).map_err(|e| anyhow!("{e}"))?;
            if !db.sha256().eq_ignore_ascii_case(&want.sha256) {
                bail!("its sha256 isn't the one offered");
            }
            if db.version() != want.version {
                bail!("the file says version {}", db.version());
            }
            Ok(StoredDb { version: want.version.clone(), sha256: want.sha256.to_ascii_lowercase(), size: want.size, created_at: db.meta().created_at })
        })
        .await
        .map_err(|e| anyhow!("{e}"))?;
        let stored = match checked {
            Ok(s) => s,
            Err(e) => {
                let _ = std::fs::remove_file(&part);
                bail!("database {version} rejected: {e:#}");
            }
        };
        let dest = stored.path().context("database path")?;
        std::fs::rename(&part, &dest).context("installing the database")?;
        Ok(stored)
    }

    /// Runs a scan in the sensor and waits for it.
    pub async fn scan(&self, kind: scan::Kind, path: Option<String>) -> Result<String> {
        let (tx, rx) = oneshot::channel();
        let id = Uuid::new_v4();
        {
            let mut i = lock(&self.inner);
            let Some(cmd) = i.cmd.clone() else { bail!("the sensor isn't running (it's switched off in this client's security policy, or starting)") };
            if i.content.is_none() && i.db.current.is_none() {
                bail!("no detection content yet: upload and roll out a signed bundle or signature database first");
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
            let _ = cmd_tx.send(ToSensor::Configure { policy: i.policy.clone(), content: i.content.as_ref().map(|c| c.1.clone()), database: Some(i.db.set()) });
            i.db_loaded = None;
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
        let mut quiet = Quiet::new(std::time::Instant::now());
        let mut every = tokio::time::interval(CHECK_EVERY);
        // After a pause, one tick (late), not a burst of them.
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let result = loop {
            tokio::select! {
                line = lines.next_line() => match line {
                    Ok(Some(l)) => {
                        quiet.heard(std::time::Instant::now());
                        self.handle(&l)
                    }
                    Ok(None) | Err(_) => break Ok(stopped),
                },
                _ = every.tick() => {
                    if quiet.check(std::time::Instant::now()) && !stopped {
                        warn!(quiet_secs = QUIET.as_secs(), "the sensor stopped answering; killing it so nothing waits on it");
                        lock(&self.inner).error = Some("the sensor stopped answering and was restarted".into());
                        let _ = child.kill().await;
                        break Ok(false);
                    }
                    self.flush_reputation(false);
                }
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
                        let mut buf = serde_json::to_vec(&ToSensor::Configure { policy, content: None, database: None })?;
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
                let state = |h: Option<&SensorHealth>| h.and_then(|h| h.realtime.as_ref()).map(|r| (r.mode, r.state.clone()));
                let changed = {
                    let mut i = lock(&self.inner);
                    let before = state(i.health.as_ref());
                    i.health = Some(*h);
                    before != state(i.health.as_ref())
                };
                // Real-time state is part of the protection report.
                if changed {
                    self.changed.notify_one();
                }
                self.report_status();
            }
            FromSensor::Detection(d) => self.keep_and_send(*d),
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
            FromSensor::Alive => {}
            FromSensor::Seen { sha256, path } => {
                let Some(d) = hex::decode(&sha256).ok().and_then(|b| <[u8; 32]>::try_from(b).ok()) else { return };
                let mut i = lock(&self.inner);
                let r = &mut i.rep;
                if r.asked.contains(&d) || r.queue.len() >= 5 * rmm_proto::security::REPUTATION_BATCH {
                    return;
                }
                r.asked.insert(d);
                r.since.get_or_insert_with(std::time::Instant::now);
                r.queue.push(rmm_proto::security::HashSeen { sha256, path: Some(path) });
                let full = r.queue.len() >= rmm_proto::security::REPUTATION_BATCH;
                drop(i);
                if full {
                    self.flush_reputation(true);
                }
            }
            FromSensor::Database { version, error } => {
                {
                    let mut i = lock(&self.inner);
                    i.db_loaded = version;
                    if let Some(e) = error {
                        i.error = Some(e);
                    } else if i.error.as_deref().is_some_and(|e| e.starts_with("database ")) {
                        i.error = None;
                    }
                }
                self.changed.notify_one();
                self.report_status();
            }
        }
    }
}

impl Supervisor {
    /// Sends waiting hashes when there's a batch or they've waited long enough, and the server
    /// answers lookups.
    fn flush_reputation(&self, now: bool) {
        let mut i = lock(&self.inner);
        if !i.policy.reputation || i.rep.queue.is_empty() || !(now || i.rep.since.is_some_and(|t| t.elapsed() >= REPUTATION_WAIT)) {
            return;
        }
        let Some(tx) = lock(&self.link).clone() else { return };
        let n = i.rep.queue.len().min(rmm_proto::security::REPUTATION_BATCH);
        let batch: Vec<_> = i.rep.queue.drain(..n).collect();
        if tx.try_send(AgentMsg::ReputationQuery { hashes: batch.clone() }).is_err() {
            // Busy socket: try again next time.
            debug!(n, "reputation lookup deferred: the connection is busy");
            i.rep.queue.splice(0..0, batch);
            return;
        }
        debug!(n, "reputation lookup sent");
        if i.rep.paths.len() > 10_000 {
            i.rep.paths.clear();
        }
        for h in batch {
            i.rep.paths.insert(h.sha256, h.path);
        }
        i.rep.since = (!i.rep.queue.is_empty()).then(std::time::Instant::now);
        if i.rep.asked.len() > ASKED_MAX {
            i.rep.asked.clear();
        }
        if let Some(p) = asked_path() {
            let flat: Vec<u8> = i.rep.asked.iter().flatten().copied().collect();
            let _ = std::fs::write(p, flat);
        }
    }

    /// The server's answer: an alert for each hash it knows. Never acted on.
    pub fn reputation(&self, known: Vec<rmm_proto::security::HashKnown>) {
        debug!(known = known.len(), "reputation answer");
        for k in known {
            let path = lock(&self.inner).rep.paths.remove(&k.sha256).flatten();
            let d = SensorDetection {
                id: format!("RMM-REPUTATION:{}", k.sha256),
                source: "file".into(),
                rule_id: Some("RMM-REPUTATION".into()),
                name: format!("{} (server reputation)", k.name),
                severity: k.severity,
                mitre: vec![],
                status: rmm_proto::security::ThreatStatus::Active,
                audit: false,
                action_taken: Some(format!("reported only: reputation answers aren't signed, so they never block or quarantine ({})", k.source)),
                resources: path.into_iter().collect(),
                sha256: Some(k.sha256),
                process: None,
                user: None,
                detected_at: Utc::now(),
                content_version: None,
                database_version: None,
                part: None,
                context: vec![],
                quarantine_id: None,
                found_by: Some(rmm_proto::security::found_by::REPUTATION.into()),
                denied: false,
            };
            self.keep_and_send(d);
        }
    }

    fn keep_and_send(&self, d: SensorDetection) {
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
}

/// `rmm-agent supervise-sensor`: the supervisor alone, without a server, on the policy,
/// content and database stored in the state directory, printing its status as one JSON line
/// every half second. For tests of the real supervisor (`tests/onaccess.rs`); the sensor stops
/// when this process does (its stdin closes).
pub fn standalone() -> Result<()> {
    let rt = crate::runtime()?;
    rt.block_on(async {
        let sup = Supervisor::new();
        tokio::spawn(sup.clone().run());
        use std::io::Write;
        let mut out = std::io::stdout();
        loop {
            let mut line = serde_json::to_vec(&sup.status())?;
            line.push(b'\n');
            // One short line to a pipe: a blocking write is fine here.
            if out.write_all(&line).is_err() {
                return Ok(());
            }
            let _ = out.flush();
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
}

pub fn quarantine_list() -> AgentMsg {
    AgentMsg::QuarantineList { items: super::quarantine::Store::open().map(|s| s.list()).unwrap_or_default() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn a_silent_sensor_is_killed_after_quiet_but_not_after_a_sleep() {
        let t0 = Instant::now();
        let mut q = Quiet::new(t0);
        // Checked on time, heard every few seconds: never killed.
        for i in 1..=30u64 {
            let now = t0 + CHECK_EVERY * i as u32;
            if i % 2 == 0 {
                q.heard(now);
            }
            assert!(!q.check(now), "check {i}");
        }
        // Then silent, checked on time: killed once QUIET has passed, not before.
        let last = t0 + CHECK_EVERY * 30;
        let mut killed_at = None;
        for i in 1..=10u32 {
            let now = last + CHECK_EVERY * i;
            if q.check(now) {
                killed_at = Some(now - last);
                break;
            }
        }
        let k = killed_at.expect("killed");
        assert!(k > QUIET && k <= QUIET + CHECK_EVERY, "{k:?}");

        // The machine sleeps for an hour: the first check after waking comes an hour late, and
        // the sensor's message comes a moment after it. It isn't killed.
        let mut q = Quiet::new(t0);
        q.heard(t0);
        assert!(!q.check(t0 + CHECK_EVERY));
        let woke = t0 + CHECK_EVERY + Duration::from_secs(3600);
        assert!(!q.check(woke), "a late check starts the count again");
        assert!(!q.check(woke + CHECK_EVERY));
        q.heard(woke + CHECK_EVERY + Duration::from_millis(500));
        assert!(!q.check(woke + CHECK_EVERY * 2));
        // But a sensor that stays silent after the wake is still killed.
        let mut killed = false;
        for i in 3..12u32 {
            killed |= q.check(woke + CHECK_EVERY * i);
        }
        assert!(killed, "silent after waking: killed");
    }
}
