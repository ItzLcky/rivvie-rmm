//! The sensor (Phase 8, milestones 2-4 and 7): `rmm-agent sensor`, a separate process the
//! agent starts and supervises, so a fault here can't take down remote access and it can be
//! switched off per client.
//!
//! It records telemetry into a local, size-capped store, runs behaviour rules on every event,
//! scans files (on demand, on a schedule, and every program as it starts) against the signed
//! content bundle, watches ransomware decoys, and in block mode stops what high-confidence
//! rules catch. It talks to the agent over stdin/stdout, one JSON message per line.

pub mod netconn;
pub mod policy;
pub mod procs;
pub mod scan;
pub mod store;
pub mod watch;

use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use chrono::{DateTime, Utc};
use rmm_content::engine::Engine;
use rmm_content::files::FileMatcher;
use rmm_content::{Bundle, Confidence};
use rmm_proto::security::{RuleMode, SensorDetection, SensorHealth, SensorPolicy, ThreatSeverity, ThreatStatus};
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
    /// The policy and the verified content bundle (JSON). Sent first, and on every change.
    Configure { policy: SensorPolicy, content: Option<String> },
    Scan { request_id: Option<Uuid>, kind: scan::Kind, path: Option<String> },
    Shutdown,
}

/// Sensor -> agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum FromSensor {
    Ready,
    Health(SensorHealth),
    Detection(Box<SensorDetection>),
    ScanDone { request_id: Option<Uuid>, ok: bool, message: String },
    /// Something was quarantined: the agent re-sends the list.
    QuarantineChanged,
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
}

/// Content compiled for use.
struct Content {
    bundle: Bundle,
    matcher: FileMatcher,
}

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
        std::thread::Builder::new().name("tick".into()).spawn(move || {
            loop {
                std::thread::sleep(Duration::from_secs(1));
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
    engine: Engine,
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
            engine: Engine::new(&[]),
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
                Input::Cmd(ToSensor::Configure { policy, content }) => self.configure(policy, content),
                Input::Cmd(ToSensor::Scan { request_id, kind, path }) => self.start_scan(request_id, kind, path),
                Input::Cmd(ToSensor::Shutdown) => {
                    self.store.flush();
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

    fn configure(&mut self, policy: SensorPolicy, content: Option<String>) {
        self.overrides = policy.rule_modes.iter().cloned().collect();
        self.excl = Exclusions::from_policy(&policy);
        self.store.set_max(u64::from(policy.telemetry_mb.clamp(16, 4096)) * 1024 * 1024);
        if let Some(json) = content {
            match Bundle::parse(json.as_bytes()).and_then(|b| Ok(Content { matcher: FileMatcher::new(&b)?, bundle: b })) {
                Ok(c) => {
                    tracing::info!(version = %c.bundle.version, rules = c.bundle.rule_count(), "sensor content loaded");
                    self.engine = Engine::new(&c.bundle.behaviour_rules);
                    self.exec_checked.clear();
                    self.content = Some(Arc::new(c));
                }
                Err(e) => tracing::error!("sensor: content rejected: {e}"),
            }
        }
        if policy.enabled && policy.canaries {
            self.canaries.plant();
        } else {
            self.canaries.remove_all();
        }
        self.policy = policy;
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
        let rules = self.content.as_ref().map_or(0, |c| c.bundle.rule_count() as u32);
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
        };
        emit(&self.out, &FromSensor::Health(h));
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
        self.exec_check(&p);
        self.event(procs::start_event(p, parent));
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
            context: self.context(e),
            quarantine_id,
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
            context: std::iter::once(trigger).chain(recent).collect(),
            quarantine_id: None,
        };
        self.report(d);
    }

    // --- files -------------------------------------------------------------------------------

    /// Checks a program as it starts, once per image hash.
    fn exec_check(&mut self, p: &Proc) {
        let (Some(content), Some(exe), Some(sha)) = (self.content.clone(), p.exe.clone(), p.sha256.clone()) else { return };
        if self.excl.process(p) || self.exec_checked.get(&sha) == Some(&false) {
            return;
        }
        let mut s = scan::Scanner { matcher: &content.matcher, excl: &self.excl, scanned: 0 };
        let Some(f) = s.file(Path::new(&exe)) else {
            self.exec_checked.insert(sha, false);
            return;
        };
        let (rule_id, name, severity, mode, mitre) = finding_meta(&f, &self.policy, &self.overrides, &self.excl);
        if mode == RuleMode::Disabled {
            return;
        }
        let mut action = None;
        let mut status = ThreatStatus::Active;
        let mut quarantine_id = None;
        if mode == RuleMode::Block {
            action = Some(kill(p));
            if action.as_deref() == Some("killed") {
                status = ThreatStatus::Blocked;
            }
        }
        if mode == RuleMode::Block || (mode == RuleMode::Alert && self.policy.auto_quarantine && severity <= ThreatSeverity::High) {
            match quarantine::Store::open().and_then(|q| q.quarantine(Path::new(&exe), Some(name.clone()), None)) {
                Ok(item) => {
                    quarantine_id = Some(item.id);
                    status = ThreatStatus::Quarantined;
                    action = Some(action.map_or("quarantined".to_string(), |a| format!("{a}, quarantined")));
                    emit(&self.out, &FromSensor::QuarantineChanged);
                }
                Err(e) => action = Some(format!("{}couldn't quarantine: {e:#}", action.map(|a| format!("{a}; ")).unwrap_or_default())),
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
            action_taken: action,
            resources: vec![exe],
            sha256: Some(f.sha256.clone()),
            process: Some(p.command_line.clone()),
            user: p.user.clone(),
            detected_at: Utc::now(),
            content_version: self.content_version(),
            context: self.context(&ev),
            quarantine_id,
        };
        self.report(d);
    }

    /// One file, outside a scan (it just appeared in a watched place).
    fn scan_one(&mut self, path: &Path) {
        let Some(content) = self.content.clone() else { return };
        let mut s = scan::Scanner { matcher: &content.matcher, excl: &self.excl, scanned: 0 };
        if let Some(f) = s.file(path) {
            let d = file_detection(&f, &self.policy, &self.overrides, &self.excl, self.content_version());
            if let Some(d) = d {
                if d.quarantine_id.is_some() {
                    emit(&self.out, &FromSensor::QuarantineChanged);
                }
                self.report(d);
            }
        }
    }

    fn start_scan(&mut self, request_id: Option<Uuid>, kind: scan::Kind, path: Option<String>) {
        let Some(content) = self.content.clone() else {
            emit(&self.out, &FromSensor::ScanDone { request_id, ok: false, message: "no detection content yet: the server hasn't sent a signed bundle".into() });
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
        let version = self.content_version();
        tracing::info!(?kind, roots = roots.len(), "scan started");
        let _ = std::thread::Builder::new().name("scan".into()).spawn(move || {
            let started = Instant::now();
            let mut s = scan::Scanner { matcher: &content.matcher, excl: &excl, scanned: 0 };
            let mut found = 0u32;
            let mut quarantined = 0u32;
            let mut n = 0u64;
            for root in &roots {
                s.walk(
                    root,
                    &mut |f| {
                        if let Some(d) = file_detection(&f, &policy, &overrides, &excl, version.clone()) {
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
            let mut message = match found {
                0 => format!("No threats found ({} files in {}s)", s.scanned, started.elapsed().as_secs()),
                n => format!("Found {n} threat{} ({} files in {}s)", if n == 1 { "" } else { "s" }, s.scanned, started.elapsed().as_secs()),
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

fn finding_meta(f: &scan::Finding, policy: &SensorPolicy, overrides: &HashMap<String, RuleMode>, excl: &Exclusions) -> (String, String, ThreatSeverity, RuleMode, Vec<String>) {
    match &f.hit {
        // Known-bad hashes are as certain as it gets.
        scan::Hit::Hash(h) => {
            ("RMM-HASH".to_string(), h.name.clone(), h.severity, effective_mode(policy, overrides, excl, "RMM-HASH", RuleMode::Alert, Confidence::High), vec![])
        }
        scan::Hit::Rule(r) => (r.id.clone(), r.name.clone(), r.severity, effective_mode(policy, overrides, excl, &r.id, r.mode, r.confidence), r.mitre.clone()),
    }
}

/// A detection for a file a scan found, quarantining it when the policy says so.
fn file_detection(f: &scan::Finding, policy: &SensorPolicy, overrides: &HashMap<String, RuleMode>, excl: &Exclusions, version: Option<String>) -> Option<SensorDetection> {
    let (rule_id, name, severity, mode, mitre) = finding_meta(f, policy, overrides, excl);
    if mode == RuleMode::Disabled {
        return None;
    }
    let path = f.path.to_string_lossy().into_owned();
    let mut status = ThreatStatus::Active;
    let mut action = None;
    let mut quarantine_id = None;
    // Severity orders most severe first: `<= High` means high or severe.
    let quarantine = mode == RuleMode::Block || (mode == RuleMode::Alert && policy.auto_quarantine && severity <= ThreatSeverity::High);
    let id = format!("{rule_id}:{}", f.sha256);
    if quarantine {
        match quarantine::Store::open().and_then(|q| q.quarantine(&f.path, Some(name.clone()), Some(id.clone()))) {
            Ok(item) => {
                status = ThreatStatus::Quarantined;
                action = Some("quarantined".into());
                quarantine_id = Some(item.id);
            }
            Err(e) => action = Some(format!("couldn't quarantine: {e:#}")),
        }
    }
    let mut ev = watch::file_event("scan", &f.path);
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
        context: vec![ev],
        quarantine_id,
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
