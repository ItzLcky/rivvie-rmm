//! Runs the checks the server sends ([`ServerMsg::Checks`]): uptime monitors and backup
//! jobs. Each check runs at its interval, at most [`MAX_IN_FLIGHT`] at a time and never two of
//! the same check at once. Results are sent in batches every [`FLUSH_SECS`], and at once when a
//! check's outcome flips, it reports for the first time, or the server asked for the run.
//! Checks keep running while the agent is disconnected; meanwhile only each check's latest
//! result is kept. Nothing is written down.
//!
//! [`ServerMsg::Checks`]: rmm_proto::ServerMsg::Checks

pub mod backup;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Utc;
use rmm_checks::allow_all;
use rmm_proto::AgentMsg;
use rmm_proto::checks::{CheckData, CheckKind, CheckResult, CheckSpec, FLUSH_SECS, MAX_CHECKS, MAX_IN_FLIGHT};
use tokio::sync::{Notify, Semaphore, mpsc};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, info};
use uuid::Uuid;

/// Results held while waiting to be sent.
const MAX_PENDING: usize = 1000;

#[derive(Default)]
struct Shared {
    pending: Mutex<Vec<CheckResult>>,
    last_ok: Mutex<HashMap<Uuid, bool>>,
    link: Mutex<Option<mpsc::Sender<AgentMsg>>>,
    flush_now: Notify,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Shared {
    /// `asked`: the server asked for this run ("check now"), so someone is waiting for it.
    fn record(&self, r: CheckResult, asked: bool) {
        let flipped = lock(&self.last_ok).insert(r.check_id, r.ok) != Some(r.ok) || asked;
        {
            let mut p = lock(&self.pending);
            p.push(r);
            if p.len() > MAX_PENDING {
                let over = p.len() - MAX_PENDING;
                p.drain(..over);
            }
        }
        if flipped {
            self.flush_now.notify_one();
        }
    }

    async fn flush(&self) {
        let link = lock(&self.link).clone();
        let Some(tx) = link else {
            // Disconnected: only the latest of each check is worth sending later.
            let mut p = lock(&self.pending);
            let mut seen = HashSet::new();
            let mut keep: Vec<CheckResult> = p.drain(..).rev().filter(|r| seen.insert(r.check_id)).collect();
            keep.reverse();
            *p = keep;
            return;
        };
        let results: Vec<CheckResult> = std::mem::take(&mut *lock(&self.pending));
        if !results.is_empty() && tx.send(AgentMsg::CheckResults { results }).await.is_err() {
            debug!("connection gone while sending check results");
        }
    }
}

/// Owns the scheduler. Lives for the agent's lifetime; connections attach and detach.
#[derive(Default)]
pub struct Checks {
    current: tokio::sync::Mutex<Current>,
    shared: Arc<Shared>,
    flusher: Mutex<Option<JoinHandle<()>>>,
}

#[derive(Default)]
struct Current {
    specs: Vec<CheckSpec>,
    task: Option<JoinHandle<()>>,
    run_now: Option<mpsc::UnboundedSender<Uuid>>,
}

impl Checks {
    pub fn attach(&self, tx: mpsc::Sender<AgentMsg>) {
        *lock(&self.shared.link) = Some(tx);
        let mut f = lock(&self.flusher);
        if f.is_none() {
            let shared = self.shared.clone();
            *f = Some(tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_secs(FLUSH_SECS));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    tokio::select! {
                        _ = tick.tick() => {}
                        _ = shared.flush_now.notified() => {
                            // Let results that finish together go in one message.
                            tokio::time::sleep(Duration::from_millis(250)).await;
                        }
                    }
                    shared.flush().await;
                }
            }));
        }
        // Whatever was kept while disconnected goes now.
        self.shared.flush_now.notify_one();
    }

    pub fn detach(&self) {
        *lock(&self.shared.link) = None;
    }

    /// Replaces the set. The scheduler restarts only if it changed; `run_now` checks run at once.
    pub async fn set(&self, mut specs: Vec<CheckSpec>, run_now: Vec<Uuid>) {
        specs.truncate(MAX_CHECKS);
        let mut cur = self.current.lock().await;
        let running = cur.task.as_ref().is_some_and(|t| !t.is_finished());
        if cur.specs != specs || (!running && !specs.is_empty()) {
            if let Some(t) = cur.task.take() {
                t.abort();
            }
            let ids: HashSet<Uuid> = specs.iter().map(|s| s.id).collect();
            lock(&self.shared.last_ok).retain(|id, _| ids.contains(id));
            info!(checks = specs.len(), "check set replaced");
            cur.specs = specs.clone();
            cur.run_now = None;
            if !specs.is_empty() {
                let (tx, rx) = mpsc::unbounded_channel();
                cur.task = Some(tokio::spawn(schedule(specs, rx, self.shared.clone())));
                cur.run_now = Some(tx);
            }
        }
        if let Some(tx) = &cur.run_now {
            for id in run_now {
                let _ = tx.send(id);
            }
        }
    }
}

async fn schedule(specs: Vec<CheckSpec>, mut run_now: mpsc::UnboundedReceiver<Uuid>, shared: Arc<Shared>) {
    let specs: Vec<Arc<CheckSpec>> = specs.into_iter().map(Arc::new).collect();
    let sem = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
    let busy: Arc<Mutex<HashSet<Uuid>>> = Arc::default();
    // Spread the first runs over a few seconds rather than starting everything at once.
    let start = Instant::now();
    let mut due: Vec<Instant> = (0..specs.len()).map(|i| start + Duration::from_millis(50 * i as u64)).collect();
    let mut asked: HashSet<Uuid> = HashSet::new();
    loop {
        let next = due.iter().min().copied().unwrap_or(start + Duration::from_secs(3600));
        tokio::select! {
            _ = tokio::time::sleep_until(next) => {}
            Some(id) = run_now.recv() => {
                if let Some(i) = specs.iter().position(|s| s.id == id) {
                    due[i] = Instant::now();
                    asked.insert(id);
                }
            }
        }
        let now = Instant::now();
        for (i, spec) in specs.iter().enumerate() {
            if due[i] > now {
                continue;
            }
            let every = Duration::from_secs(u64::from(spec.interval_secs.clamp(rmm_proto::checks::MIN_INTERVAL_SECS, rmm_proto::checks::MAX_INTERVAL_SECS)));
            due[i] = now + every;
            if !lock(&busy).insert(spec.id) {
                continue; // still running from last time
            }
            let urgent = asked.remove(&spec.id);
            let (spec, sem, busy, shared) = (spec.clone(), sem.clone(), busy.clone(), shared.clone());
            tokio::spawn(async move {
                let Ok(_permit) = sem.acquire().await else { return };
                let r = run(&spec).await;
                lock(&busy).remove(&spec.id);
                shared.record(r, urgent);
            });
        }
    }
}

/// One run of one check: backups here, network checks in [`rmm_checks::run`] (reaching
/// private space is the agent's purpose, so every address is allowed).
pub async fn run(spec: &CheckSpec) -> CheckResult {
    let CheckKind::Backup { providers, sources } = &spec.kind else { return rmm_checks::run::run(spec, allow_all).await };
    let mut r = CheckResult { check_id: spec.id, at: Utc::now(), ok: false, latency_ms: None, value: None, message: String::new(), data: None };
    let found = backup::collect(providers, sources).await;
    let failed = found.jobs.iter().filter(|j| j.last_result == rmm_proto::checks::BackupResult::Failed).count();
    r.ok = found.errors.is_empty() || !found.jobs.is_empty();
    r.value = Some(found.jobs.len() as f64);
    r.message = match (found.jobs.len(), failed, found.errors.first()) {
        (0, _, Some((p, e))) => format!("{p}: {e}"),
        (0, _, None) => "no backup jobs found".into(),
        (n, 0, _) => format!("{n} job{}", if n == 1 { "" } else { "s" }),
        (n, f, _) => format!("{n} job{}, {f} failed", if n == 1 { "" } else { "s" }),
    };
    r.data = Some(CheckData::Backups { jobs: found.jobs, errors: found.errors });
    r.at = Utc::now();
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmm_proto::checks::HttpMethod;

    fn spec(kind: CheckKind) -> CheckSpec {
        CheckSpec { id: Uuid::new_v4(), interval_secs: 30, timeout_secs: 10, kind }
    }

    #[tokio::test]
    async fn tcp_and_http_checks() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            loop {
                let (mut s, _) = l.accept().await.unwrap();
                let mut b = [0u8; 2048];
                let _ = s.read(&mut b).await;
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nall is well").await;
            }
        });
        let r = run(&spec(CheckKind::Tcp { host: "127.0.0.1".into(), port })).await;
        assert!(r.ok && r.latency_ms.is_some(), "{r:?}");
        let http = |keyword: Option<&str>, absent: bool, statuses: Vec<u16>| {
            spec(CheckKind::Http { url: format!("http://127.0.0.1:{port}/health"), method: HttpMethod::Get, statuses, keyword: keyword.map(String::from), keyword_absent: absent, verify_tls: true })
        };
        let r = run(&http(Some("WELL"), false, vec![])).await;
        assert!(r.ok && r.value == Some(200.0) && r.message == "HTTP 200", "{r:?}");
        let r = run(&http(Some("broken"), false, vec![])).await;
        assert!(!r.ok && r.message.contains("keyword not found"), "{r:?}");
        let r = run(&http(Some("well"), true, vec![])).await;
        assert!(!r.ok && r.message.contains("keyword found"), "{r:?}");
        let r = run(&http(None, false, vec![204])).await;
        assert!(!r.ok && r.message.contains("not an expected status"), "{r:?}");
        let r = run(&spec(CheckKind::Tcp { host: "127.0.0.1".into(), port: 1 })).await;
        assert!(!r.ok && r.message.contains("refused"), "{r:?}");
        let r = run(&spec(CheckKind::Dns { name: "x.example".into(), record: "SOA".into(), server: None, expect: vec![] })).await;
        assert!(!r.ok && r.message.contains("record type"), "{r:?}");
    }

    #[tokio::test]
    async fn results_are_batched_and_flips_go_at_once() {
        let checks = Checks::default();
        let (tx, mut rx) = mpsc::channel(16);
        checks.attach(tx);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let s = spec(CheckKind::Tcp { host: "127.0.0.1".into(), port });
        let id = s.id;
        checks.set(vec![s.clone()], vec![]).await;
        // The first result is a change (from nothing): sent without waiting for the batch.
        let first = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap();
        match first {
            AgentMsg::CheckResults { results } => assert!(results.len() == 1 && results[0].check_id == id && results[0].ok),
            other => panic!("{other:?}"),
        }
        // Check now, with the port closed: a flip, sent at once.
        drop(l);
        checks.set(vec![s], vec![id]).await;
        match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap() {
            AgentMsg::CheckResults { results } => assert!(!results.last().unwrap().ok),
            other => panic!("{other:?}"),
        }
        // Disconnected: only the latest result per check is kept.
        checks.detach();
        for ok in [true, false, true] {
            checks.shared.record(CheckResult { check_id: id, at: Utc::now(), ok, latency_ms: None, value: None, message: String::new(), data: None }, false);
        }
        checks.shared.flush().await;
        assert_eq!(lock(&checks.shared.pending).len(), 1);
        checks.set(vec![], vec![]).await;
        assert!(checks.current.lock().await.task.is_none(), "an empty set stops the scheduler");
    }
}
