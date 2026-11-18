//! The sensor (Phase 8, milestones 2-4 and 7): `rmm-agent sensor`, a separate process the
//! agent starts and supervises, so a fault here can't take down remote access and it can be
//! switched off per client.
//!
//! It records telemetry into a local, size-capped store, runs behaviour rules on every event,
//! scans files (on demand, on a schedule, and every program as it starts) with the scan engine
//! (`rmm-scan`: the signed signature database, plus the content bundle's legacy hashes and
//! file rules), watches ransomware decoys, and in block mode stops what high-confidence rules
//! catch. It talks to the agent over stdin/stdout, one JSON message per line.
//!
//! On Linux as root, real-time protection decides every exec before it runs and scans files
//! after they're written (`onaccess`, fanotify); elsewhere, and where fanotify isn't available,
//! programs are scanned just after they start.
//!
//! The database arrives as a path (the agent downloads and verifies it, see
//! `security::supervisor`), with the previous version as a fallback: if the newest doesn't
//! load, the sensor runs the one before and says so.

pub mod netconn;
#[cfg(target_os = "linux")]
pub mod onaccess;
pub mod policy;
pub mod procs;
pub mod scan;
pub mod store;
pub mod watch;

use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use chrono::{DateTime, Utc};
use rmm_content::files::FileMatcher;
use rmm_content::Bundle;
use rmm_scan::cache::Cache;
use rmm_scan::{Engine, Match};
use rmm_proto::security::{RealtimeHealth, RealtimeMode, RuleMode, SensorDetection, SensorHealth, SensorPolicy, ThreatSeverity, ThreatStatus, found_by};
use rmm_proto::telemetry::{Event, EventKind, NetEvent, Proc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::security::quarantine;
use policy::{Exclusions, effective_mode};

pub(crate) use watch::expand as watch_expand;

/// Agent -> sensor.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ToSensor {
    /// The policy, the verified content bundle (JSON) and the signature database (`None`:
    /// unchanged). Sent first, and on every change.
    Configure {
        policy: SensorPolicy,
        content: Option<String>,
        #[serde(default)]
        database: Option<DbSet>,
    },
    Scan { request_id: Option<Uuid>, kind: scan::Kind, path: Option<String> },
    Shutdown,
}

/// The signature database to load, and the one to fall back on.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DbSet {
    pub current: Option<DbFile>,
    pub previous: Option<DbFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DbFile {
    pub version: String,
    pub path: std::path::PathBuf,
}

/// Sensor -> agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum FromSensor {
    Ready,
    Health(Box<SensorHealth>),
    Detection(Box<SensorDetection>),
    ScanDone { request_id: Option<Uuid>, ok: bool, message: String },
    /// Something was quarantined: the agent re-sends the list.
    QuarantineChanged,
    /// Which signature database is loaded now, and why the newer one isn't if it isn't.
    Database { version: Option<String>, error: Option<String> },
    /// Every few seconds: the agent kills a sensor that goes quiet (stopped or wedged), since
    /// with real-time protection on, programs could be waiting on it.
    Alive,
    /// A program ran whose hash the local content found nothing in: for the reputation lookup.
    Seen { sha256: String, path: String },
}

type Out = Arc<Mutex<std::io::Stdout>>;

fn emit(out: &Out, msg: &FromSensor) {
    if let Ok(mut line) = serde_json::to_vec(msg) {
        line.push(b'\n');
        let mut o = out.lock().unwrap_or_else(|e| e.into_inner());
        let _ = o.write_all(&line);
        let _ = o.flush();
    }
}

enum Input {
    Cmd(ToSensor),
    Live(procs::Live),
    Tick,
    ScanFinished(scan::Kind),
    #[cfg(target_os = "linux")]
    OnAccess(onaccess::Hit),
}

/// The behaviour content in use.
struct Content {
    bundle: Bundle,
}

fn cache_path() -> Option<std::path::PathBuf> {
    crate::config::state_subdir("sensor").ok().map(|d| d.join("verdicts.bin"))
}

/// Clean verdicts kept, at most (16 bytes each).
const CACHE_ENTRIES: usize = 500_000;

#[derive(Default, Serialize, Deserialize)]
struct Schedule {
    last_quick: Option<DateTime<Utc>>,
    last_full: Option<DateTime<Utc>>,
}

fn schedule_path() -> Option<std::path::PathBuf> {
    crate::config::state_subdir("sensor").ok().map(|d| d.join("schedule.json"))
}

fn lower_priority() {
    #[cfg(unix)]
    // SAFETY: plain syscall changing our own scheduling priority.
    unsafe {
        libc::setpriority(libc::PRIO_PROCESS, 0, 10);
    }
    #[cfg(windows)]
    // SAFETY: changes the priority class of our own process.
    unsafe {
        use windows::Win32::System::Threading::{BELOW_NORMAL_PRIORITY_CLASS, GetCurrentProcess, SetPriorityClass};
        let _ = SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS);
    }
}

/// Puts the calling thread back at normal priority, where the OS lets us (root on Linux).
pub(crate) fn normal_thread_priority() {
    #[cfg(target_os = "linux")]
    // SAFETY: changes this thread's own nice value.
    unsafe {
        libc::setpriority(libc::PRIO_PROCESS, libc::gettid() as libc::id_t, 0);
    }
    #[cfg(windows)]
    // SAFETY: changes the priority of the calling thread (a pseudo handle, never closed).
    unsafe {
        use windows::Win32::System::Threading::{GetCurrentThread, SetThreadPriority, THREAD_PRIORITY_ABOVE_NORMAL};
        // In a below-normal process, "above normal" is one step under a normal thread.
        let _ = SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
    }
}

pub fn main() -> Result<()> {
    lower_priority();
    let out: Out = Arc::new(Mutex::new(std::io::stdout()));
    let (tx, rx) = mpsc::channel::<Input>();
    {
        let tx = tx.clone();
        std::thread::Builder::new().name("stdin".into()).spawn(move || {
            let stdin = std::io::stdin();
            for line in stdin.lock().lines() {
                let Ok(line) = line else { break };
                match serde_json::from_str::<ToSensor>(&line) {
                    Ok(cmd) => {
                        if tx.send(Input::Cmd(cmd)).is_err() {
                            return;
                        }
                    }
                    Err(e) => tracing::warn!("sensor: bad command: {e}"),
                }
            }
            // The agent went away: stop too.
            let _ = tx.send(Input::Cmd(ToSensor::Shutdown));
        })?;
    }
    {
        let tx = tx.clone();
        let out = out.clone();
        std::thread::Builder::new().name("tick".into()).spawn(move || {
            // The agent kills a sensor it doesn't hear from: this thread must get the CPU on a
            // busy machine, although the sensor runs at low priority.
            normal_thread_priority();
            let alive = crate::security::supervisor::ALIVE_EVERY.as_secs().max(1);
            for n in 1u64.. {
                std::thread::sleep(Duration::from_secs(1));
                // From this thread, not the main loop: a long scan there isn't a hang.
                if n.is_multiple_of(alive) {
                    emit(&out, &FromSensor::Alive);
                }
                if tx.send(Input::Tick).is_err() {
                    return;
                }
            }
        })?;
    }
    let (live_tx, live_rx) = mpsc::channel();
    let realtime = procs::proc_connector(live_tx).is_ok();
    {
        let tx = tx.clone();
        std::thread::Builder::new().name("live".into()).spawn(move || {
            for l in live_rx {
                if tx.send(Input::Live(l)).is_err() {
                    return;
                }
            }
        })?;
    }
    emit(&out, &FromSensor::Ready);
    let mut s = Sensor::new(out, tx, realtime)?;
    s.run(rx)
}

struct Sensor {
    out: Out,
    tx: Sender<Input>,
    policy: SensorPolicy,
    overrides: HashMap<String, RuleMode>,
    excl: Exclusions,
    content: Option<Arc<Content>>,
    /// The signature database (verified) and the scan engine over it and the bundle.
    db: Option<Arc<rmm_scan::db::Database>>,
    scanner: Option<Arc<Engine>>,
    cache: Arc<Mutex<Cache>>,
    files_scanned: Arc<AtomicU64>,
    cache_hits: Arc<AtomicU64>,
    engine: rmm_content::engine::Engine,
    table: procs::Table,
    poller: procs::Poller,
    hashes: procs::HashCache,
    /// sha256 -> already checked at exec (and what was found).
    exec_checked: HashMap<String, bool>,
    users: sysinfo::Users,
    realtime: bool,
    store: store::Writer,
    ring: VecDeque<Event>,
    seq: u64,
    events_total: u64,
    minute: VecDeque<Instant>,
    net: netconn::Tracker,
    files: watch::FileWatch,
    registry: watch::RegistryWatch,
    modules: watch::ModuleWatch,
    canaries: watch::Canaries,
    reported: HashMap<String, Instant>,
    scanning: Arc<AtomicBool>,
    /// What real-time decisions are made with (swapped on every content or policy change).
    #[cfg(target_os = "linux")]
    rt_rules: Arc<std::sync::RwLock<Arc<onaccess::Rules>>>,
    #[cfg(target_os = "linux")]
    onaccess: Option<onaccess::Handle>,
    /// Why real-time protection isn't on when the policy wants it.
    rt_error: Option<String>,
    /// Hashes already passed on for the reputation lookup, and ones the local content matched.
    seen: std::collections::HashSet<String>,
    local_hits: std::collections::HashSet<String>,
    schedule: Schedule,
    ticks: u64,
    /// Polling slows down (x2, x4...) when the sensor uses too much CPU.
    slow: u64,
    cpu: f32,
    rss: u64,
    store_bytes: u64,
}

impl Sensor {
    fn new(out: Out, tx: Sender<Input>, realtime: bool) -> Result<Sensor> {
        let schedule = schedule_path().and_then(|p| std::fs::read(p).ok()).and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        Ok(Sensor {
            out,
            tx,
            policy: SensorPolicy::default(),
            overrides: HashMap::new(),
            excl: Exclusions::default(),
            content: None,
            db: None,
            scanner: None,
            cache: Arc::new(Mutex::new(Cache::new([0; 16], CACHE_ENTRIES))),
            files_scanned: Arc::new(AtomicU64::new(0)),
            cache_hits: Arc::new(AtomicU64::new(0)),
            engine: rmm_content::engine::Engine::new(&[]),
            table: procs::Table::default(),
            poller: procs::Poller::new()?,
            hashes: procs::HashCache::default(),
            exec_checked: HashMap::new(),
            users: sysinfo::Users::new_with_refreshed_list()?,
            realtime,
            store: store::Writer::open(store::dir()?, 64 * 1024 * 1024)?,
            ring: VecDeque::with_capacity(2048),
            seq: 0,
            events_total: 0,
            minute: VecDeque::new(),
            net: netconn::Tracker::default(),
            files: watch::FileWatch::default(),
            registry: watch::RegistryWatch::default(),
            modules: watch::ModuleWatch::default(),
            canaries: watch::Canaries::default(),
            reported: HashMap::new(),
            scanning: Arc::new(AtomicBool::new(false)),
            #[cfg(target_os = "linux")]
            rt_rules: Arc::new(std::sync::RwLock::new(Arc::new(onaccess::Rules {
                engine: None,
                policy: SensorPolicy::default(),
                overrides: HashMap::new(),
                excl: Exclusions::default(),
            }))),
            #[cfg(target_os = "linux")]
            onaccess: None,
            rt_error: None,
            seen: Default::default(),
            local_hits: Default::default(),
            schedule,
            ticks: 0,
            slow: 1,
            cpu: 0.0,
            rss: 0,
            store_bytes: 0,
        })
    }

    fn run(&mut self, rx: Receiver<Input>) -> Result<()> {
        for p in self.poller.all() {
            self.table.insert(p);
        }
        // Baselines, so what already exists isn't reported as new.
        self.files.poll();
        self.registry.poll();
        self.modules.poll();
        let _ = self.net.diff(netconn::list());
        for input in rx {
            match input {
                Input::Cmd(ToSensor::Configure { policy, content, database }) => self.configure(policy, content, database),
                Input::Cmd(ToSensor::Scan { request_id, kind, path }) => self.start_scan(request_id, kind, path),
                Input::Cmd(ToSensor::Shutdown) => {
                    #[cfg(target_os = "linux")]
                    drop(self.onaccess.take());
                    self.store.flush();
                    self.save_cache();
                    if !self.policy.enabled {
                        self.canaries.remove_all();
                    }
                    return Ok(());
                }
                Input::Live(procs::Live::Exec(pid)) => {
                    if let Some(p) = procs::read_proc(pid, &self.users) {
                        self.started(p);
                    }
                }
                Input::Live(procs::Live::Exit(pid)) => self.ended(pid),
                Input::Tick => self.tick(),
                #[cfg(target_os = "linux")]
                Input::OnAccess(hit) => self.on_access(hit),
                Input::ScanFinished(kind) => {
                    match kind {
                        scan::Kind::Quick => self.schedule.last_quick = Some(Utc::now()),
                        scan::Kind::Full => self.schedule.last_full = Some(Utc::now()),
                        scan::Kind::Path => {}
                    }
                    if let Some(p) = schedule_path() {
                        let _ = std::fs::write(p, serde_json::to_vec(&self.schedule).unwrap_or_default());
                    }
                }
            }
        }
        Ok(())
    }

    fn configure(&mut self, policy: SensorPolicy, content: Option<String>, database: Option<DbSet>) {
        self.overrides = policy.rule_modes.iter().cloned().collect();
        self.excl = Exclusions::from_policy(&policy);
        self.store.set_max(u64::from(policy.telemetry_mb.clamp(16, 4096)) * 1024 * 1024);
        let mut rebuild = policy.archive_depth != self.policy.archive_depth && self.scanner.is_some();
        self.policy = policy.clone();
        if let Some(json) = content {
            match Bundle::parse(json.as_bytes()) {
                Ok(b) => {
                    tracing::info!(version = %b.version, rules = b.rule_count(), "sensor content loaded");
                    self.engine = rmm_content::engine::Engine::new(&b.behaviour_rules);
                    self.content = Some(Arc::new(Content { bundle: b }));
                    rebuild = true;
                }
                Err(e) => tracing::error!("sensor: content rejected: {e}"),
            }
        }
        if let Some(set) = database {
            self.load_database(set);
        } else if rebuild && let Err(e) = self.rebuild_scanner() {
            tracing::error!("sensor: file rules: {e}");
        }
        if policy.enabled && policy.canaries {
            self.canaries.plant();
        } else {
            self.canaries.remove_all();
        }
        self.sync_rules();
        self.sync_realtime();
        // So the console sees the new real-time state now, not at the next minute.
        self.health();
    }

    /// Hands the current engine and policy to the real-time workers.
    fn sync_rules(&mut self) {
        #[cfg(target_os = "linux")]
        {
            let r = onaccess::Rules { engine: self.scanner.clone(), policy: self.policy.clone(), overrides: self.overrides.clone(), excl: self.excl.clone() };
            *self.rt_rules.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(r);
        }
    }

    /// Starts, restarts or stops on-access protection to match the policy.
    fn sync_realtime(&mut self) {
        let want = self.policy.enabled && self.policy.realtime != RealtimeMode::Off;
        #[cfg(target_os = "linux")]
        {
            if !want {
                if self.onaccess.take().is_some() {
                    tracing::info!("on-access protection off");
                }
                self.rt_error = None;
                return;
            }
            if self.onaccess.as_ref().is_some_and(|h| h.scan_on_write == self.policy.scan_on_write) {
                return;
            }
            drop(self.onaccess.take());
            let (hits, rx) = mpsc::channel();
            let tx = self.tx.clone();
            let _ = std::thread::Builder::new().name("onaccess-hits".into()).spawn(move || {
                for h in rx {
                    if tx.send(Input::OnAccess(h)).is_err() {
                        return;
                    }
                }
            });
            match onaccess::start(self.rt_rules.clone(), self.cache.clone(), hits, self.policy.scan_on_write) {
                Ok(h) => {
                    self.onaccess = Some(h);
                    self.rt_error = None;
                }
                Err(e) => {
                    if self.rt_error.as_deref() != Some(&e) {
                        tracing::warn!("on-access protection unavailable, scanning programs after they start instead: {e}");
                    }
                    self.rt_error = Some(e);
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.rt_error = want.then(|| "on-access protection is Linux only; programs are scanned after they start".to_string());
        }
    }

    /// Exec permission events decided this program before it ran.
    fn decided(&self, p: &Proc) -> bool {
        #[cfg(target_os = "linux")]
        return self.onaccess.as_ref().is_some_and(|h| p.exe.as_deref().is_some_and(|e| h.decides(e)));
        #[cfg(not(target_os = "linux"))]
        {
            let _ = p;
            false
        }
    }

    /// The scan engine over the current database and bundle. The verdict cache follows its
    /// generation: a new engine starts from the clean verdicts of that same generation only.
    fn rebuild_scanner(&mut self) -> Result<(), String> {
        let legacy = match &self.content {
            Some(c) => Some((c.bundle.version.clone(), FileMatcher::new(&c.bundle).map_err(|e| e.to_string())?)),
            None => None,
        };
        let mut limits = rmm_scan::Limits::default();
        if self.policy.archive_depth > 0 {
            limits.max_depth = self.policy.archive_depth.min(20);
        }
        let engine = Engine::new(self.db.clone(), legacy, limits)?;
        self.exec_checked.clear();
        if !engine.has_signatures() {
            self.scanner = None;
            self.sync_rules();
            return Ok(());
        }
        let generation = rmm_scan::cache::generation(&[&engine.generation()]);
        let mut c = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if c.generation() != generation {
            let _ = c.save();
            *c = match cache_path() {
                Some(p) => Cache::load(&p, generation, CACHE_ENTRIES),
                None => Cache::new(generation, CACHE_ENTRIES),
            };
        }
        drop(c);
        if engine.yara_unsupported() {
            tracing::warn!("this agent was built without YARA: the database's rules are skipped, its hashes still match");
        }
        self.scanner = Some(Arc::new(engine));
        self.sync_rules();
        Ok(())
    }

    /// Loads the newest database that verifies and compiles, else the previous one.
    fn load_database(&mut self, set: DbSet) {
        let key = crate::security::supervisor::pubkey();
        let mut errors = Vec::new();
        let old = self.db.take();
        let mut loaded = None;
        for f in [set.current, set.previous].into_iter().flatten() {
            let opened = key
                .as_deref()
                .ok_or_else(|| "this agent was built without a release key".to_string())
                .and_then(|k| rmm_scan::db::Database::open(&f.path, k).map_err(|e| e.to_string()))
                .and_then(|d| if d.version() == f.version { Ok(d) } else { Err(format!("the file says version {}", d.version())) });
            let started = Instant::now();
            match opened {
                Ok(d) => {
                    self.db = Some(Arc::new(d));
                    match self.rebuild_scanner() {
                        Ok(()) => {
                            tracing::info!(version = %f.version, secs = started.elapsed().as_secs_f32(), yara = self.scanner.as_ref().map_or(0, |s| s.yara_rules()), "signature database loaded");
                            loaded = Some(f.version.clone());
                            break;
                        }
                        Err(e) => errors.push(format!("database {}: {e}", f.version)),
                    }
                }
                Err(e) => errors.push(format!("database {}: {e}", f.version)),
            }
            self.db = None;
        }
        if loaded.is_none() && !errors.is_empty() {
            // Neither loads: keep running what we had.
            self.db = old;
            let _ = self.rebuild_scanner();
            loaded = self.db.as_ref().map(|d| d.version().to_string());
        } else if loaded.is_none() {
            let _ = self.rebuild_scanner();
        }
        for e in &errors {
            tracing::error!("sensor: {e}");
        }
        emit(&self.out, &FromSensor::Database { version: loaded, error: (!errors.is_empty()).then(|| errors.join("; ")) });
    }

    fn save_cache(&self) {
        if let Err(e) = self.cache.lock().unwrap_or_else(|e| e.into_inner()).save() {
            tracing::warn!("verdict cache: {e}");
        }
    }

    fn every(&self, secs: u64) -> bool {
        self.ticks.is_multiple_of(secs * self.slow)
    }

    fn tick(&mut self) {
        self.ticks += 1;
        let poll_every = if self.realtime { 10 } else { 2 };
        if self.every(poll_every) {
            let (started, ended) = self.poller.poll();
            for p in started {
                // The connector already reported it (same pid and start).
                if self.realtime && self.table.get(p.pid).is_some_and(|t| t.command_line == p.command_line) {
                    continue;
                }
                self.started(p);
            }
            for pid in ended {
                self.ended(pid);
            }
        }
        if self.every(10) {
            for c in self.net.diff(netconn::list()) {
                self.network(c);
            }
            for e in self.files.poll() {
                self.file_changed(e);
            }
        }
        if self.every(15) {
            for e in self.registry.poll() {
                self.event(e);
            }
        }
        if self.every(60) {
            for e in self.modules.poll() {
                self.event(e);
            }
        }
        if self.policy.canaries && self.ticks.is_multiple_of(5) {
            for t in self.canaries.check() {
                self.canary(t);
            }
            if self.ticks.is_multiple_of(600) {
                self.canaries.plant();
            }
        }
        self.store.flush();
        if self.ticks.is_multiple_of(60) {
            self.scheduled_scans();
            self.health();
            self.save_cache();
        }
        if self.ticks.is_multiple_of(3600) {
            self.users.refresh();
            let cutoff = Instant::now() - Duration::from_secs(3600);
            self.reported.retain(|_, t| *t > cutoff);
        }
    }

    fn health(&mut self) {
        let (cpu, rss) = self.poller.cpu_and_rss(std::process::id());
        self.cpu = cpu;
        self.rss = rss;
        self.store_bytes = self.store.bytes();
        // Performance budget: back off polling when the sensor uses more than ~5% of a CPU.
        if cpu > 5.0 && self.slow < 8 {
            self.slow *= 2;
            tracing::warn!(cpu, slow = self.slow, "sensor over its CPU budget; polling less often");
        } else if cpu < 1.5 && self.slow > 1 {
            self.slow /= 2;
        }
        let cutoff = Instant::now() - Duration::from_secs(60);
        while self.minute.front().is_some_and(|t| *t < cutoff) {
            self.minute.pop_front();
        }
        let mut collectors = vec![
            ("process".to_string(), if self.realtime { "proc-connector".to_string() } else { "poll".to_string() }),
            ("network".into(), "poll".into()),
            ("file".into(), "poll".into()),
            ("module".into(), "poll".into()),
        ];
        if cfg!(windows) {
            collectors.push(("registry".into(), "poll".into()));
        }
        if self.scanner.is_some() {
            collectors.push(("scan".into(), if rmm_scan::YARA { "rmm-scan".into() } else { "rmm-scan (no YARA)".into() }));
        }
        let realtime = self.realtime_health();
        if let Some(r) = &realtime
            && r.mode != RealtimeMode::Off
        {
            collectors.push(("realtime".into(), r.mechanism.clone()));
        }
        let yara = self.scanner.as_ref().map_or(0, |s| s.yara_rules() as u32);
        let rules = self.content.as_ref().map_or(0, |c| c.bundle.rule_count() as u32) + yara;
        let h = SensorHealth {
            events_total: self.events_total,
            events_per_min: self.minute.len() as f64,
            store_bytes: self.store_bytes,
            cpu_percent: self.cpu,
            rss_bytes: self.rss,
            rules,
            collectors,
            canaries: self.canaries.count() as u32,
            last_scan: self.schedule.last_quick.max(self.schedule.last_full),
            database_version: self.db.as_ref().map(|d| d.version().to_string()),
            yara_rules: yara,
            hash_signatures: self.db.as_ref().map_or(0, |d| d.meta().sha256 + d.meta().md5 + d.meta().sha1),
            files_scanned: self.files_scanned.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            realtime,
        };
        emit(&self.out, &FromSensor::Health(Box::new(h)));
    }

    fn realtime_health(&self) -> Option<RealtimeHealth> {
        let mode = self.policy.realtime;
        let mut r = RealtimeHealth { mode, scan_on_write: self.policy.scan_on_write, error: self.rt_error.clone(), ..Default::default() };
        #[cfg(target_os = "linux")]
        if let Some(h) = &self.onaccess {
            let s = &h.stats;
            let n = |a: &AtomicU64| a.load(Ordering::Relaxed);
            (r.p50_us, r.p99_us) = s.percentiles();
            r.state = "on".into();
            r.mechanism = "fanotify".into();
            r.filesystems = h.filesystems.load(Ordering::Relaxed) as u32;
            (r.decisions, r.denied, r.cache_hits, r.timeouts, r.overloaded) = (n(&s.decisions), n(&s.denied), n(&s.cache_hits), n(&s.timeouts), n(&s.overloaded));
            (r.write_scans, r.write_dropped) = (n(&s.write_scans), n(&s.write_dropped));
            return Some(r);
        }
        r.state = if mode == RealtimeMode::Off { "off".into() } else { "unavailable".into() };
        r.mechanism = "scan-after-start".into();
        Some(r)
    }

    fn scheduled_scans(&mut self) {
        let now = Utc::now();
        let due = |last: Option<DateTime<Utc>>, every: chrono::Duration| last.is_none_or(|l| now - l >= every);
        if self.policy.full_scan_days > 0 && due(self.schedule.last_full, chrono::Duration::days(self.policy.full_scan_days.into())) {
            self.start_scan(None, scan::Kind::Full, None);
        } else if self.policy.quick_scan_hours > 0 && due(self.schedule.last_quick, chrono::Duration::hours(self.policy.quick_scan_hours.into())) {
            self.start_scan(None, scan::Kind::Quick, None);
        }
    }

    // --- events ----------------------------------------------------------------------------

    fn started(&mut self, mut p: Proc) {
        if let Some(exe) = &p.exe {
            p.sha256 = self.hashes.get(exe);
        }
        let parent = self.table.get(p.ppid).cloned();
        self.table.insert(p.clone());
        // With exec permission events, it was decided before it ran (unless it's on a
        // filesystem they don't cover: network, FUSE).
        if !self.decided(&p) {
            self.exec_check(&p);
        }
        self.seen(&p);
        self.event(procs::start_event(p, parent));
    }

    /// Passes a program's hash on for the reputation lookup, once, unless our own content
    /// already matched it.
    fn seen(&mut self, p: &Proc) {
        let (Some(sha), Some(exe)) = (&p.sha256, &p.exe) else { return };
        if !self.policy.reputation || self.local_hits.contains(sha) || self.seen.contains(sha) {
            return;
        }
        if self.seen.len() > 200_000 {
            self.seen.clear();
        }
        self.seen.insert(sha.clone());
        emit(&self.out, &FromSensor::Seen { sha256: sha.clone(), path: exe.clone() });
    }

    fn ended(&mut self, pid: u32) {
        let p = self.table.get(pid).cloned();
        self.table.remove(pid);
        if p.is_some() {
            self.event(procs::exit_event(p, pid));
        }
    }

    fn network(&mut self, c: netconn::Conn) {
        let mut e = Event::new(EventKind::Network, if c.state == "listen" { "listen" } else { "connect" });
        e.process = c.pid.and_then(|pid| self.table.get(pid).cloned());
        e.parent = e.process.as_ref().and_then(|p| self.table.get(p.ppid).cloned());
        e.network = Some(NetEvent { protocol: c.protocol, local_addr: c.local_addr, local_port: c.local_port, remote_addr: c.remote_addr, remote_port: c.remote_port });
        self.event(e);
    }

    fn file_changed(&mut self, mut e: Event) {
        if let Some(f) = &mut e.file
            && e.action != "delete"
        {
            f.sha256 = procs::sha256_file(Path::new(&f.path)).filter(|_| std::fs::metadata(&f.path).is_ok_and(|m| m.len() <= 8 * 1024 * 1024));
            // Files dropped into watched places are scanned as they appear.
            let path = f.path.clone();
            self.scan_one(Path::new(&path));
        }
        self.event(e);
    }

    /// Records an event and runs the behaviour rules on it.
    fn event(&mut self, mut e: Event) {
        self.seq += 1;
        e.seq = self.seq;
        self.events_total += 1;
        self.minute.push_back(Instant::now());
        if let Err(err) = self.store.append(&e) {
            tracing::warn!("telemetry store: {err:#}");
        }
        if self.ring.len() >= 2000 {
            self.ring.pop_front();
        }
        self.ring.push_back(e.clone());
        if self.engine.is_empty() || e.process.as_ref().is_some_and(|p| self.excl.process(p)) {
            return;
        }
        let (policy, overrides, excl) = (&self.policy, &self.overrides, &self.excl);
        let fired: Vec<(rmm_content::BehaviourRule, RuleMode)> = self
            .engine
            .evaluate(&e, |r| effective_mode(policy, overrides, excl, &r.id, r.mode, r.confidence) == RuleMode::Disabled)
            .into_iter()
            .map(|r| (r.clone(), effective_mode(policy, overrides, excl, &r.id, r.mode, r.confidence)))
            .collect();
        for (rule, mode) in fired {
            self.behaviour(&rule, mode, &e);
        }
    }

    fn content_version(&self) -> Option<String> {
        self.content.as_ref().map(|c| c.bundle.version.clone())
    }

    fn database_version(&self) -> Option<String> {
        self.db.as_ref().map(|d| d.version().to_string())
    }

    fn scanner<'a>(&'a self, engine: &'a Engine) -> scan::Scanner<'a> {
        scan::Scanner::new(engine, &self.excl, Some(&self.cache))
    }

    fn count(&self, s: &scan::Scanner) {
        self.files_scanned.fetch_add(s.scanned, Ordering::Relaxed);
        self.cache_hits.fetch_add(s.cached, Ordering::Relaxed);
    }

    /// The process, its ancestors, then related recent events (same process tree, last 10
    /// minutes), newest last.
    fn context(&self, e: &Event) -> Vec<Event> {
        let mut out = vec![e.clone()];
        if let Some(p) = &e.process {
            for a in self.table.ancestry(p.pid, 8) {
                let mut x = Event::new(EventKind::Process, "running");
                x.ts = a.started_at.unwrap_or(e.ts);
                x.process = Some(a);
                out.push(x);
            }
            let tree = self.table.tree(p.pid);
            let cutoff = e.ts - chrono::Duration::minutes(10);
            let related: Vec<Event> = self
                .ring
                .iter()
                .rev()
                .filter(|r| r.seq != e.seq && r.ts >= cutoff && r.process.as_ref().is_some_and(|rp| tree.contains(&rp.pid) || rp.pid == p.ppid))
                .take(30)
                .cloned()
                .collect();
            out.extend(related);
        }
        out
    }

    fn report(&mut self, d: SensorDetection) {
        if let Some(h) = d.sha256.as_ref().filter(|_| d.source == "file") {
            if self.local_hits.len() > 100_000 {
                self.local_hits.clear();
            }
            self.local_hits.insert(h.clone());
        }
        if self.reported.get(&d.id).is_some_and(|t| t.elapsed() < Duration::from_secs(600)) {
            return;
        }
        self.reported.insert(d.id.clone(), Instant::now());
        // Whoever investigates this will query the events around it right away.
        self.store.flush();
        tracing::info!(rule = d.rule_id.as_deref().unwrap_or(""), name = %d.name, audit = d.audit, "detection");
        emit(&self.out, &FromSensor::Detection(Box::new(d)));
    }

    fn behaviour(&mut self, rule: &rmm_content::BehaviourRule, mode: RuleMode, e: &Event) {
        let key = match e.kind {
            EventKind::Process | EventKind::Network => {
                let p = e.process.as_ref();
                format!("{}:{}", p.map_or(0, |p| p.pid), p.and_then(|p| p.started_at).map_or(0, |t| t.timestamp()))
            }
            EventKind::File => e.file.as_ref().map(|f| f.path.clone()).unwrap_or_default(),
            EventKind::Registry => e.registry.as_ref().map(|r| format!("{}\\{}", r.key, r.value)).unwrap_or_default(),
            EventKind::Module => e.module.as_ref().map(|m| m.name.clone()).unwrap_or_default(),
        };
        // Thresholded rules fire for a process, not an event.
        let key = if rule.threshold.is_some() { e.process.as_ref().map(|p| p.pid.to_string()).unwrap_or(key) } else { key };
        let resource = match e.kind {
            EventKind::File => e.file.as_ref().map(|f| f.path.clone()),
            EventKind::Registry => e.registry.as_ref().map(|r| format!("{}\\{}", r.key, r.value)),
            EventKind::Network => e.network.as_ref().map(|n| format!("{}:{}", n.remote_addr, n.remote_port)),
            EventKind::Module => e.module.as_ref().map(|m| m.name.clone()),
            EventKind::Process => e.process.as_ref().and_then(|p| p.exe.clone()),
        };
        let mut action_taken = None;
        let mut status = ThreatStatus::Active;
        let mut quarantine_id = None;
        if mode == RuleMode::Block {
            match e.kind {
                EventKind::Process | EventKind::Network => {
                    if let Some(p) = &e.process {
                        action_taken = Some(kill(p));
                        if action_taken.as_deref() == Some("killed") {
                            status = ThreatStatus::Blocked;
                        }
                    }
                }
                EventKind::File => {
                    if let Some(f) = e.file.as_ref().filter(|_| e.action != "delete") {
                        match quarantine::Store::open().and_then(|s| s.quarantine(Path::new(&f.path), Some(rule.name.clone()), None)) {
                            Ok(item) => {
                                action_taken = Some("quarantined".into());
                                status = ThreatStatus::Quarantined;
                                quarantine_id = Some(item.id);
                                emit(&self.out, &FromSensor::QuarantineChanged);
                            }
                            Err(err) => action_taken = Some(format!("couldn't quarantine: {err:#}")),
                        }
                    }
                }
                _ => action_taken = Some("reported only: this kind of change can't be blocked".into()),
            }
        }
        let d = SensorDetection {
            id: format!("{}:{key}", rule.id),
            source: "behaviour".into(),
            rule_id: Some(rule.id.clone()),
            name: rule.name.clone(),
            severity: rule.severity,
            mitre: rule.mitre.clone(),
            status,
            audit: mode == RuleMode::Audit,
            action_taken,
            resources: resource.into_iter().collect(),
            sha256: e.process.as_ref().and_then(|p| p.sha256.clone()).or_else(|| e.file.as_ref().and_then(|f| f.sha256.clone())),
            process: e.process.as_ref().map(|p| if p.command_line.is_empty() { p.name.clone() } else { p.command_line.clone() }),
            user: e.process.as_ref().and_then(|p| p.user.clone()),
            detected_at: e.ts,
            content_version: self.content_version(),
            database_version: self.database_version(),
            part: None,
            context: self.context(e),
            quarantine_id,
            found_by: None,
            denied: false,
        };
        self.report(d);
    }

    fn canary(&mut self, t: watch::Tripped) {
        let now = Utc::now();
        // What started recently is the best hint at the culprit.
        let recent: Vec<Event> = self.ring.iter().rev().filter(|e| e.kind == EventKind::Process && e.action == "start" && now - e.ts < chrono::Duration::minutes(2)).take(30).cloned().collect();
        let mut trigger = watch::file_event(if t.what == "modified" { "modify" } else if t.what == "renamed" { "rename" } else { "delete" }, &t.path);
        trigger.ts = now;
        self.event(trigger.clone());
        let d = SensorDetection {
            id: format!("RMM-CANARY:{}:{}", t.path.display(), now.timestamp() / 3600),
            source: "behaviour".into(),
            rule_id: Some("RMM-CANARY".into()),
            name: format!("Ransomware decoy file {}", t.what),
            severity: ThreatSeverity::Severe,
            mitre: vec!["T1486".into()],
            status: ThreatStatus::Active,
            audit: false,
            action_taken: None,
            resources: vec![t.path.to_string_lossy().into_owned()],
            sha256: None,
            process: None,
            user: None,
            detected_at: now,
            content_version: self.content_version(),
            database_version: self.database_version(),
            part: None,
            context: std::iter::once(trigger).chain(recent).collect(),
            quarantine_id: None,
            found_by: None,
            denied: false,
        };
        self.report(d);
    }

    // --- files -------------------------------------------------------------------------------

    /// Checks a program just after it starts, once per image hash (where real-time protection
    /// doesn't decide it before it runs).
    fn exec_check(&mut self, p: &Proc) {
        let (Some(engine), Some(exe), Some(sha)) = (self.scanner.clone(), p.exe.clone(), p.sha256.clone()) else { return };
        if self.excl.process(p) || self.exec_checked.get(&sha) == Some(&false) {
            return;
        }
        let mut s = self.scanner(&engine);
        let found = s.file(Path::new(&exe));
        self.count(&s);
        let Some(f) = found else {
            self.exec_checked.insert(sha, false);
            return;
        };
        self.exec_detection(p, &f, false, None, true);
    }

    /// A program that matched as it was started. `denied`: refused before it ran. `hold`: why
    /// nothing may be done (audit mode). `running`: it runs (so a blocking verdict kills it).
    fn exec_detection(&mut self, p: &Proc, f: &scan::Finding, denied: bool, hold: Option<&str>, running: bool) {
        let Some((m, mode)) = best(f, &self.policy, &self.overrides, &self.excl) else { return };
        let exe = f.path.to_string_lossy().into_owned();
        let (rule_id, name, severity, mitre) = (m.id.clone(), m.name.clone(), m.severity, m.mitre.clone());
        let mut actions: Vec<String> = Vec::new();
        let mut status = ThreatStatus::Active;
        let mut quarantine_id = None;
        let would_quarantine = mode == RuleMode::Block || (mode == RuleMode::Alert && self.policy.auto_quarantine && severity <= ThreatSeverity::High);
        if denied {
            actions.push("denied before it ran".into());
            status = ThreatStatus::Blocked;
        } else if let Some(why) = hold.filter(|_| mode == RuleMode::Block || would_quarantine) {
            actions.push(format!("nothing done: {why}"));
        } else if mode == RuleMode::Block && running {
            let k = kill(p);
            if k == "killed" {
                status = ThreatStatus::Blocked;
            }
            actions.push(k);
        }
        if hold.is_none() && would_quarantine {
            if let Some(why) = quarantine::guarded(&f.path) {
                actions.push(format!("not quarantined: {why}"));
            } else {
                match quarantine::Store::open().and_then(|q| q.quarantine(&f.path, Some(name.clone()), None)) {
                    Ok(item) => {
                        quarantine_id = Some(item.id);
                        status = ThreatStatus::Quarantined;
                        actions.push("quarantined".into());
                        emit(&self.out, &FromSensor::QuarantineChanged);
                    }
                    Err(e) => actions.push(format!("couldn't quarantine: {e:#}")),
                }
            }
        }
        let mut ev = procs::start_event(p.clone(), self.table.get(p.ppid).cloned());
        ev.seq = self.seq;
        let d = SensorDetection {
            id: format!("{}:{}", rule_id, f.sha256),
            source: "file".into(),
            rule_id: Some(rule_id),
            name,
            severity,
            mitre,
            status,
            audit: mode == RuleMode::Audit,
            action_taken: (!actions.is_empty()).then(|| actions.join(", ")),
            resources: vec![exe],
            sha256: Some(f.sha256.clone()),
            process: Some(if p.command_line.is_empty() { p.name.clone() } else { p.command_line.clone() }),
            user: p.user.clone(),
            detected_at: Utc::now(),
            content_version: self.content_version(),
            database_version: self.database_version(),
            part: m.part.clone(),
            context: self.context(&ev),
            quarantine_id,
            found_by: Some(found_by::ON_EXEC.into()),
            denied,
        };
        self.report(d);
    }

    /// What a real-time worker found.
    #[cfg(target_os = "linux")]
    fn on_access(&mut self, h: onaccess::Hit) {
        let audit = (self.policy.realtime != RealtimeMode::Block).then_some("real-time protection is in audit mode");
        match h.what {
            onaccess::HitKind::Exec { pid, denied, late, ino, size } => {
                // Denied: the process still runs what it ran before. Allowed after the
                // deadline: it runs the file now, unless the pid is already something else.
                let mut p = procs::read_proc(pid, &self.users).unwrap_or(Proc { pid, ..Default::default() });
                let running = late && onaccess::runs(pid, ino, size);
                if late {
                    tracing::info!(pid, running, path = %h.finding.path.display(), "on-access: verdict after the deadline");
                }
                p.sha256 = Some(h.finding.sha256.clone());
                self.exec_detection(&p, &h.finding, denied, audit, running);
            }
            onaccess::HitKind::Write { package_manager } => {
                let hold = audit.or(package_manager.then_some("written by the package manager"));
                if let Some(d) = file_detection(&h.finding, &self.policy, &self.overrides, &self.excl, (self.content_version(), self.database_version()), found_by::ON_WRITE, hold) {
                    if d.quarantine_id.is_some() {
                        emit(&self.out, &FromSensor::QuarantineChanged);
                    }
                    self.report(d);
                }
            }
        }
    }

    /// One file, outside a scan (it just appeared in a watched place).
    fn scan_one(&mut self, path: &Path) {
        let Some(engine) = self.scanner.clone() else { return };
        let mut s = self.scanner(&engine);
        let found = s.file(path);
        self.count(&s);
        if let Some(f) = found {
            let d = file_detection(&f, &self.policy, &self.overrides, &self.excl, (self.content_version(), self.database_version()), found_by::ON_WRITE, None);
            if let Some(d) = d {
                if d.quarantine_id.is_some() {
                    emit(&self.out, &FromSensor::QuarantineChanged);
                }
                self.report(d);
            }
        }
    }

    fn start_scan(&mut self, request_id: Option<Uuid>, kind: scan::Kind, path: Option<String>) {
        let Some(engine) = self.scanner.clone() else {
            emit(&self.out, &FromSensor::ScanDone { request_id, ok: false, message: "no detection content yet: the server hasn't sent a signed bundle or signature database".into() });
            return;
        };
        if self.scanning.swap(true, Ordering::SeqCst) {
            emit(&self.out, &FromSensor::ScanDone { request_id, ok: false, message: "a scan is already running".into() });
            return;
        }
        let roots: Vec<std::path::PathBuf> = match (kind, path) {
            (scan::Kind::Path, Some(p)) => vec![p.into()],
            (scan::Kind::Path, None) => {
                self.scanning.store(false, Ordering::SeqCst);
                emit(&self.out, &FromSensor::ScanDone { request_id, ok: false, message: "no path given".into() });
                return;
            }
            (k, _) => scan::roots(k),
        };
        let (out, policy, overrides, excl, busy, tx) =
            (self.out.clone(), self.policy.clone(), self.overrides.clone(), self.excl.clone(), self.scanning.clone(), self.tx.clone());
        let (cache, files_scanned, cache_hits) = (self.cache.clone(), self.files_scanned.clone(), self.cache_hits.clone());
        let version = (self.content_version(), self.database_version());
        tracing::info!(?kind, roots = roots.len(), "scan started");
        let _ = std::thread::Builder::new().name("scan".into()).spawn(move || {
            let started = Instant::now();
            let mut s = scan::Scanner::new(&engine, &excl, Some(&cache));
            let mut found = 0u32;
            let mut quarantined = 0u32;
            let mut n = 0u64;
            for root in &roots {
                s.walk(
                    root,
                    &mut |f| {
                        if let Some(d) = file_detection(&f, &policy, &overrides, &excl, version.clone(), found_by::SCAN, None) {
                            found += 1;
                            if d.quarantine_id.is_some() {
                                quarantined += 1;
                                emit(&out, &FromSensor::QuarantineChanged);
                            }
                            emit(&out, &FromSensor::Detection(Box::new(d)));
                        }
                    },
                    &mut || {
                        n += 1;
                        // Pace: about 2,000 files a second at most, so the machine stays usable.
                        if n.is_multiple_of(20) {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        true
                    },
                );
            }
            files_scanned.fetch_add(s.scanned, Ordering::Relaxed);
            cache_hits.fetch_add(s.cached, Ordering::Relaxed);
            let _ = cache.lock().unwrap_or_else(|e| e.into_inner()).save();
            let files = match s.cached {
                0 => format!("{} files", s.scanned),
                c => format!("{} files, {c} unchanged since a clean scan", s.scanned + c),
            };
            let mut message = match found {
                0 => format!("No threats found ({files} in {}s)", started.elapsed().as_secs()),
                n => format!("Found {n} threat{} ({files} in {}s)", if n == 1 { "" } else { "s" }, started.elapsed().as_secs()),
            };
            if quarantined > 0 {
                message.push_str(&format!("; {quarantined} quarantined"));
            }
            busy.store(false, Ordering::SeqCst);
            let _ = tx.send(Input::ScanFinished(kind));
            emit(&out, &FromSensor::ScanDone { request_id, ok: true, message });
        });
    }
}

/// The match a finding is reported as, and the mode it runs in: the one that acts most
/// (block, then alert, then audit; disabled ones never), then the most severe, then hashes
/// before rules before heuristics. `None` when every match is switched off.
fn best<'a>(f: &'a scan::Finding, policy: &SensorPolicy, overrides: &HashMap<String, RuleMode>, excl: &Exclusions) -> Option<(&'a Match, RuleMode)> {
    let rank = |k: rmm_scan::Kind| match k {
        rmm_scan::Kind::Hash | rmm_scan::Kind::BundleHash => 0,
        rmm_scan::Kind::Yara | rmm_scan::Kind::BundleRule => 1,
        rmm_scan::Kind::Heuristic => 2,
    };
    f.matches
        .iter()
        .map(|m| (m, effective_mode(policy, overrides, excl, &m.id, m.mode, m.confidence)))
        .filter(|(_, mode)| *mode != RuleMode::Disabled)
        // Severity orders most severe first.
        .min_by_key(|(m, mode)| (std::cmp::Reverse(*mode), m.severity, rank(m.kind)))
}

/// A detection for a file a scan found, quarantining it when the policy says so, unless
/// `hold` says why it mustn't be.
fn file_detection(
    f: &scan::Finding,
    policy: &SensorPolicy,
    overrides: &HashMap<String, RuleMode>,
    excl: &Exclusions,
    (version, database_version): (Option<String>, Option<String>),
    how: &str,
    hold: Option<&str>,
) -> Option<SensorDetection> {
    let (m, mode) = best(f, policy, overrides, excl)?;
    let (rule_id, name, severity, mitre) = (m.id.clone(), m.name.clone(), m.severity, m.mitre.clone());
    let path = f.path.to_string_lossy().into_owned();
    let mut status = ThreatStatus::Active;
    let mut action = None;
    let mut quarantine_id = None;
    // Severity orders most severe first: `<= High` means high or severe.
    let quarantine = mode == RuleMode::Block || (mode == RuleMode::Alert && policy.auto_quarantine && severity <= ThreatSeverity::High);
    let id = format!("{rule_id}:{}", f.sha256);
    if let Some(why) = hold.filter(|_| quarantine) {
        action = Some(format!("not quarantined: {why}"));
    } else if let Some(why) = quarantine.then(|| quarantine::guarded(&f.path)).flatten() {
        action = Some(format!("not quarantined: {why}"));
    } else if quarantine {
        match quarantine::Store::open().and_then(|q| q.quarantine(&f.path, Some(name.clone()), Some(id.clone()))) {
            Ok(item) => {
                status = ThreatStatus::Quarantined;
                action = Some("quarantined".into());
                quarantine_id = Some(item.id);
            }
            Err(e) => action = Some(format!("couldn't quarantine: {e:#}")),
        }
    }
    let mut ev = watch::file_event(if how == found_by::SCAN { "scan" } else { "write" }, &f.path);
    ev.file.as_mut().unwrap().sha256 = Some(f.sha256.clone());
    Some(SensorDetection {
        id: format!("{id}:{path}"),
        source: "file".into(),
        rule_id: Some(rule_id),
        name,
        severity,
        mitre,
        status,
        audit: mode == RuleMode::Audit,
        action_taken: action,
        resources: vec![path],
        sha256: Some(f.sha256.clone()),
        process: None,
        user: None,
        detected_at: Utc::now(),
        content_version: version,
        database_version,
        part: m.part.clone(),
        context: vec![ev],
        quarantine_id,
        found_by: Some(how.into()),
        denied: false,
    })
}

/// Kills a process (never a protected one). Returns what happened, for `action_taken`.
pub fn kill(p: &Proc) -> String {
    if procs::protected(p) {
        return format!("not killed: {} is protected", p.name);
    }
    let Ok(mut sys) = sysinfo::System::new() else { return "couldn't read the process list".into() };
    let pid = sysinfo::Pid::from_u32(p.pid);
    sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
    match sys.process(pid) {
        Some(x) if x.kill() => "killed".into(),
        Some(_) => "couldn't kill it".into(),
        None => "already exited".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmm_content::Confidence;
    use rmm_proto::security::Exclusion;

    fn m(id: &str, kind: rmm_scan::Kind, severity: ThreatSeverity, mode: RuleMode, confidence: Confidence) -> Match {
        Match { kind, id: id.into(), name: id.into(), severity, confidence, mode, mitre: vec![], part: None }
    }

    #[test]
    fn the_reported_match_and_its_mode() {
        use rmm_scan::Kind::*;
        let f = scan::Finding {
            path: "/tmp/x".into(),
            sha256: "00".repeat(32),
            matches: vec![
                m("RMM-H-0002", Heuristic, ThreatSeverity::Moderate, RuleMode::Audit, Confidence::Medium),
                m("Y-ALERT", Yara, ThreatSeverity::Moderate, RuleMode::Alert, Confidence::Medium),
                m("Y-BLOCK", Yara, ThreatSeverity::Low, RuleMode::Block, Confidence::High),
                m("Y-SEVERE", Yara, ThreatSeverity::Severe, RuleMode::Alert, Confidence::Medium),
            ],
        };
        let none = HashMap::new();
        let id = |p: &SensorPolicy, o: &HashMap<String, RuleMode>, e: &Exclusions| best(&f, p, o, e).map(|(m, mode)| (m.id.clone(), mode));
        let off = SensorPolicy::default();
        assert_eq!(id(&off, &none, &Exclusions::default()), Some(("Y-SEVERE".into(), RuleMode::Alert)), "without prevention nothing blocks: most severe alert");
        let on = SensorPolicy { prevention: true, ..Default::default() };
        assert_eq!(id(&on, &none, &Exclusions::default()), Some(("Y-BLOCK".into(), RuleMode::Block)), "high confidence, prevention on: it blocks");
        let kill: HashMap<String, RuleMode> = [("Y-BLOCK".to_string(), RuleMode::Disabled), ("Y-SEVERE".into(), RuleMode::Disabled), ("Y-ALERT".into(), RuleMode::Disabled)].into();
        assert_eq!(id(&on, &kill, &Exclusions::default()), Some(("RMM-H-0002".into(), RuleMode::Audit)), "the kill switch leaves the audit heuristic");
        let excl = Exclusions::from_policy(&SensorPolicy { exclusions: vec![Exclusion { kind: rmm_proto::security::ExclusionKind::Rule, value: "RMM-H-0002".into() }], ..Default::default() });
        assert_eq!(id(&on, &kill, &excl), None, "every match switched off: no detection");
    }
}
