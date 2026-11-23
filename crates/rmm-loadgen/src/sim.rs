//! One simulated agent: the real protocol (`rmm-proto`) over a real WebSocket, sending what
//! `rmm-agent` sends at the intervals it sends it (see `crates/rmm-agent/src/conn.rs`):
//!
//! - on connect: a heartbeat and an inventory at once (the agent's periodic tasks fire
//!   immediately), another inventory when the server asks, the service list, and the
//!   protection state;
//! - a heartbeat every `heartbeat_secs` (from `AuthOk`), an inventory every `inventory_secs`;
//! - the service list again when it changes (here: every `--services-change-secs`), the
//!   protection state again hourly (the agent's keepalive);
//! - answers to what the server asks for: patch scans, scripts (output, then the result,
//!   kept until the server's `JobAck`), service lists, protection refreshes, pings.
//!
//! The time-compression factor divides every agent-side interval, so a day of heartbeats can
//! be written in minutes. The server's own timers are not compressed.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use rmm_proto::{AgentMsg, DiskInfo, DiskUsage, Inventory, Metrics, NetInterface, OsFamily, PROTOCOL_VERSION, ServerMsg, ServiceInfo, Software, SystemInfo};
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

use crate::stats::Stats;

pub type Ws = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Cred {
    pub agent_id: Uuid,
    pub secret: String,
    pub hostname: String,
    pub windows: bool,
}

pub struct Shape {
    pub ws_url: String,
    pub compression: f64,
    pub software: usize,
    pub services: usize,
    pub services_change_secs: u64,
    pub patch_updates: usize,
}

/// How long bulk jobs take to reach agents: the dispatcher notes when it asked for each job,
/// the agent when the job arrived, and whichever comes second records the difference (a job
/// often arrives before the API has answered).
#[derive(Default)]
pub struct Dispatch {
    asked: HashMap<Uuid, Instant>,
    arrived: HashMap<Uuid, Instant>,
}

pub type Dispatched = Arc<std::sync::Mutex<Dispatch>>;

impl Dispatch {
    pub fn asked(&mut self, job: Uuid, at: Instant) -> Option<Duration> {
        match self.arrived.remove(&job) {
            Some(arrived) => Some(arrived.saturating_duration_since(at)),
            None => {
                self.asked.insert(job, at);
                None
            }
        }
    }

    pub fn arrived(&mut self, job: Uuid) -> Option<Duration> {
        match self.asked.remove(&job) {
            Some(at) => Some(at.elapsed()),
            None => {
                self.arrived.insert(job, Instant::now());
                None
            }
        }
    }
}

fn rand_u64() -> u64 {
    Uuid::new_v4().as_u64_pair().0
}

/// A uniformly random duration in [0, d).
fn jitter(d: Duration) -> Duration {
    if d.is_zero() { d } else { Duration::from_micros(rand_u64() % d.as_micros().max(1) as u64) }
}

fn scaled(secs: u64, shape: &Shape) -> Duration {
    Duration::from_secs_f64((secs as f64 / shape.compression).max(0.05))
}

pub async fn connect(url: &str) -> Result<Ws> {
    let (ws, _) = tokio::time::timeout(Duration::from_secs(30), tokio_tungstenite::connect_async(url))
        .await
        .map_err(|_| anyhow!("timed out connecting"))?
        .context("connecting")?;
    Ok(ws)
}

async fn recv(ws: &mut Ws) -> Result<ServerMsg> {
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(30), ws.next()).await.map_err(|_| anyhow!("timed out waiting for the server"))?;
        match frame.ok_or_else(|| anyhow!("closed"))?? {
            Message::Binary(b) => return Ok(rmm_proto::decode(&b)?),
            Message::Close(c) => bail!("closed: {c:?}"),
            _ => continue,
        }
    }
}

pub fn system(hostname: &str, windows: bool) -> SystemInfo {
    SystemInfo {
        hostname: hostname.to_string(),
        os_family: if windows { OsFamily::Windows } else { OsFamily::Linux },
        os_name: if windows { "Windows 11 Pro".into() } else { "Ubuntu 24.04.1 LTS".into() },
        os_version: if windows { "10.0.26100".into() } else { "24.04".into() },
        kernel_version: if windows { "26100".into() } else { "6.8.0-48-generic".into() },
        arch: "x86_64".into(),
        agent_version: "0.1.0".into(),
        machine_id: Some(format!("loadgen-{hostname}")),
        platform: Some(if windows { rmm_proto::Platform::Workstation } else { rmm_proto::Platform::Server }),
    }
}

pub async fn enroll(url: &str, token: &str, hostname: &str, windows: bool) -> Result<Cred> {
    let mut ws = connect(url).await?;
    let msg = AgentMsg::Enroll { protocol: PROTOCOL_VERSION, token: token.into(), system: system(hostname, windows), previous: None };
    ws.send(Message::Binary(rmm_proto::encode(&msg)?.into())).await?;
    match recv(&mut ws).await? {
        ServerMsg::Enrolled { agent_id, secret } => {
            let _ = ws.close(None).await;
            Ok(Cred { agent_id, secret, hostname: hostname.into(), windows })
        }
        ServerMsg::AuthFailed { reason } => bail!("enrollment refused: {reason}"),
        other => bail!("unexpected reply: {other:?}"),
    }
}

/// About 2% of agents run hot (CPU over 90%), so threshold policies have alerts to open.
fn hot(id: Uuid) -> bool {
    id.as_bytes()[0] < 5
}

fn metrics(started: Instant, n: u64, hot: bool) -> Metrics {
    let r = rand_u64();
    let gib = 1024 * 1024 * 1024u64;
    Metrics {
        ts: Utc::now(),
        uptime_secs: 86_400 + started.elapsed().as_secs(),
        cpu_percent: if hot { 92.0 + (r % 700) as f32 / 100.0 } else { (r % 6000) as f32 / 100.0 },
        load_avg: Some([0.4, 0.5, 0.6]),
        mem_total: 16 * gib,
        mem_used: 6 * gib + (r >> 8) % (4 * gib),
        swap_total: 2 * gib,
        swap_used: 0,
        disks: vec![
            DiskUsage { mount: "/".into(), total: 512 * gib, available: 200 * gib + (r >> 16) % gib },
            DiskUsage { mount: "/boot/efi".into(), total: gib / 2, available: gib / 3 },
            DiskUsage { mount: "/data".into(), total: 2048 * gib, available: 900 * gib },
        ],
        net_rx_bytes: n * 150_000,
        net_tx_bytes: n * 40_000,
        process_count: 180 + (r % 60) as u32,
    }
}

fn inventory(cred: &Cred, shape: &Shape) -> Inventory {
    let gib = 1024 * 1024 * 1024u64;
    Inventory {
        collected_at: Utc::now(),
        system: system(&cred.hostname, cred.windows),
        cpu_brand: "Intel(R) Core(TM) i7-1265U".into(),
        cpu_cores_physical: Some(10),
        cpu_cores_logical: 12,
        mem_total: 16 * gib,
        disks: vec![
            DiskInfo { name: "nvme0n1p2".into(), mount: "/".into(), fs: "ext4".into(), kind: "SSD".into(), removable: false, total: 512 * gib },
            DiskInfo { name: "nvme0n1p1".into(), mount: "/boot/efi".into(), fs: "vfat".into(), kind: "SSD".into(), removable: false, total: gib / 2 },
        ],
        network: vec![NetInterface { name: "eth0".into(), mac: "52:54:00:12:34:56".into(), addrs: vec!["10.0.0.23/24".into(), "fe80::5054:ff:fe12:3456/64".into()] }],
        software: (0..shape.software)
            .map(|i| Software {
                name: format!("package-{i:04}-{}", if i % 3 == 0 { "runtime-libraries" } else { "tools" }),
                version: format!("{}.{}.{}-1ubuntu{}", i % 7, i % 13, i % 100, i % 4),
                publisher: Some(if i % 2 == 0 { "Ubuntu Developers".into() } else { "Example Software Ltd".into() }),
                source: if cred.windows { "registry".into() } else { "dpkg".into() },
            })
            .collect(),
        logged_in_users: vec!["alice".into()],
    }
}

fn services(shape: &Shape, generation: u64) -> Vec<ServiceInfo> {
    use rmm_proto::{ServiceState, StartMode};
    (0..shape.services)
        .map(|i| ServiceInfo {
            name: format!("service-{i:03}.service"),
            display_name: format!("Example service number {i}"),
            // One service flips with each "change".
            state: if (i as u64) == generation % shape.services.max(1) as u64 { ServiceState::Stopped } else { ServiceState::Running },
            start_mode: if i % 5 == 0 { StartMode::Manual } else { StartMode::Auto },
        })
        .collect()
}

fn security() -> rmm_proto::security::Report {
    use rmm_proto::security::{Action, Product, ProductKind, Report};
    let mut p = Product::new(ProductKind::Defender, "Microsoft Defender Antivirus");
    p.version = Some("4.18.24090.11".into());
    p.enabled = Some(true);
    p.realtime = Some(true);
    p.signature_version = Some("1.419.163.0".into());
    p.signatures_updated_at = Some(Utc::now() - chrono::Duration::hours(3));
    p.last_quick_scan = Some(Utc::now() - chrono::Duration::hours(20));
    p.tamper_protection = Some(true);
    p.actions = vec![Action::QuickScan, Action::FullScan, Action::UpdateSignatures];
    Report { products: vec![p], detections: vec![], error: None }
}

fn patch_scan(shape: &Shape, request_id: Uuid) -> AgentMsg {
    use rmm_proto::patch::{Category, PatchUpdate, Severity};
    let updates = (0..shape.patch_updates)
        .map(|i| PatchUpdate {
            id: format!("libexample{i}"),
            title: format!("libexample{i} security update"),
            kb: None,
            severity: Some(if i % 4 == 0 { Severity::Critical } else { Severity::Important }),
            category: if i % 4 == 0 { Category::Security } else { Category::Update },
            size: Some(1_200_000),
            requires_reboot: i == 0,
            version: Some(format!("1.2.{i}")),
            current_version: Some(format!("1.1.{i}")),
        })
        .collect();
    AgentMsg::PatchScanResult { request_id: Some(request_id), provider: "apt".into(), all_or_nothing: false, error: None, updates, reboot_pending: false }
}

/// Keeps one agent connected until `stop`, reconnecting (with backoff, like the real agent)
/// whenever the session ends.
pub async fn run(cred: Cred, shape: Arc<Shape>, stats: Arc<Stats>, dispatched: Dispatched, mut stop: watch::Receiver<bool>) {
    let started = Instant::now();
    let mut backoff = Duration::from_secs(1);
    loop {
        if *stop.borrow() {
            return;
        }
        let t = Instant::now();
        let res = tokio::select! {
            r = session(&cred, &shape, &stats, &dispatched, started, t) => r,
            _ = stop.changed() => return,
        };
        if *stop.borrow() {
            return;
        }
        if let Err(e) = res {
            stats.error(format!("agent session: {e:#}"));
        }
        let wait = backoff + jitter(Duration::from_secs(1));
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = stop.changed() => return,
        }
        backoff = (backoff * 2).min(Duration::from_secs(60));
    }
}

async fn session(cred: &Cred, shape: &Shape, stats: &Stats, dispatched: &Dispatched, started: Instant, t: Instant) -> Result<()> {
    let mut ws = match connect(&shape.ws_url).await {
        Ok(ws) => ws,
        Err(e) => {
            Stats::inc(&stats.connect_failed);
            return Err(e);
        }
    };
    let auth = AgentMsg::Auth {
        protocol: PROTOCOL_VERSION,
        agent_id: cred.agent_id,
        secret: cred.secret.clone(),
        agent_version: "0.1.0".into(),
        jobs: vec![],
        capabilities: vec![rmm_proto::patch::CAPABILITY.into(), rmm_proto::security::CAPABILITY.into(), rmm_proto::tools::CAPABILITY.into()],
        patch_runs: vec![],
        security_actions: vec![],
        software_runs: vec![],
    };
    ws.send(Message::Binary(rmm_proto::encode(&auth)?.into())).await?;
    let (heartbeat_secs, inventory_secs) = match recv(&mut ws).await {
        Ok(ServerMsg::AuthOk { heartbeat_secs, inventory_secs }) => (heartbeat_secs, inventory_secs),
        Ok(ServerMsg::AuthFailed { reason }) => {
            Stats::inc(&stats.connect_failed);
            bail!("auth refused: {reason}");
        }
        Ok(other) => {
            Stats::inc(&stats.connect_failed);
            bail!("unexpected reply to auth: {other:?}");
        }
        Err(e) => {
            Stats::inc(&stats.connect_failed);
            return Err(e);
        }
    };
    stats.sample("connect", t.elapsed());
    Stats::inc(&stats.connected);
    Stats::inc(&stats.online);
    let res = connected(ws, cred, shape, stats, dispatched, started, heartbeat_secs, inventory_secs).await;
    stats.online.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    Stats::inc(&stats.dropped);
    res
}

#[allow(clippy::too_many_arguments)]
async fn connected(
    ws: Ws,
    cred: &Cred,
    shape: &Shape,
    stats: &Stats,
    dispatched: &Dispatched,
    started: Instant,
    heartbeat_secs: u32,
    inventory_secs: u32,
) -> Result<()> {
    let (mut sink, mut stream) = ws.split();
    let (tx, mut rx) = mpsc::channel::<AgentMsg>(256);
    let writer = async {
        while let Some(m) = rx.recv().await {
            let buf = rmm_proto::encode(&m)?;
            Stats::inc(&stats.sent_msgs);
            Stats::add(&stats.sent_bytes, buf.len() as u64);
            sink.send(Message::Binary(buf.into())).await?;
        }
        anyhow::Ok(())
    };

    let hb_every = scaled(heartbeat_secs.max(5).into(), shape);
    let inv_every = scaled(inventory_secs.max(300).into(), shape);
    let sec_every = scaled(3600, shape);
    let svc_every = scaled(shape.services_change_secs.max(1), shape);
    // The real agent's first heartbeat and inventory go out at once; spread the later ticks
    // so a fleet that connected together doesn't heartbeat in lockstep forever.
    let mut hb = tokio::time::interval_at(tokio::time::Instant::now() + jitter(hb_every), hb_every);
    let mut inv = tokio::time::interval_at(tokio::time::Instant::now() + inv_every + jitter(inv_every), inv_every);
    let mut sec = tokio::time::interval_at(tokio::time::Instant::now() + sec_every + jitter(sec_every), sec_every);
    let mut svc = tokio::time::interval_at(tokio::time::Instant::now() + svc_every + jitter(svc_every), svc_every);
    for t in [&mut hb, &mut inv, &mut sec, &mut svc] {
        t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    }
    let mut beats = 0u64;
    let mut generation = 0u64;
    tx.send(AgentMsg::Heartbeat(metrics(started, beats, hot(cred.agent_id)))).await?;
    tx.send(AgentMsg::Inventory(inventory(cred, shape))).await?;
    tx.send(AgentMsg::Services { services: services(shape, generation) }).await?;
    tx.send(AgentMsg::SecurityStatus(security())).await?;

    // Results waiting for the server's JobAck: job id -> when the result was sent.
    let mut unacked: HashMap<Uuid, Instant> = HashMap::new();
    let (done_tx, mut done_rx) = mpsc::channel::<Uuid>(64);
    let reader = async {
        loop {
            tokio::select! {
                frame = tokio::time::timeout(Duration::from_secs(100), stream.next()) => {
                    let frame = match frame {
                        Err(_) => bail!("nothing from the server for 100s"),
                        Ok(None) => bail!("server closed the connection"),
                        Ok(Some(Err(e))) => bail!("socket: {e}"),
                        Ok(Some(Ok(f))) => f,
                    };
                    let b = match frame {
                        Message::Binary(b) => b,
                        Message::Close(c) => bail!("server closed the connection: {c:?}"),
                        _ => continue,
                    };
                    Stats::inc(&stats.recv_msgs);
                    Stats::add(&stats.recv_bytes, b.len() as u64);
                    match rmm_proto::decode::<ServerMsg>(&b)? {
                        ServerMsg::Ping { nonce } => tx.send(AgentMsg::Pong { nonce }).await?,
                        ServerMsg::RequestInventory => tx.send(AgentMsg::Inventory(inventory(cred, shape))).await?,
                        ServerMsg::RequestServices => tx.send(AgentMsg::Services { services: services(shape, generation) }).await?,
                        ServerMsg::SecurityRefresh => tx.send(AgentMsg::SecurityStatus(security())).await?,
                        ServerMsg::PatchScan { request_id } => {
                            Stats::inc(&stats.scans_requested);
                            // A scan takes a while on a real machine.
                            let (tx, msg) = (tx.clone(), patch_scan(shape, request_id));
                            let wait = scaled(5, shape) + jitter(scaled(25, shape));
                            tokio::spawn(async move {
                                tokio::time::sleep(wait).await;
                                let _ = tx.send(msg).await;
                            });
                        }
                        ServerMsg::RunScript(job) => {
                            Stats::inc(&stats.jobs_received);
                            let took = dispatched.lock().unwrap().arrived(job.job_id);
                            if let Some(d) = took {
                                stats.sample("job_dispatch", d);
                            }
                            let (tx, done) = (tx.clone(), done_tx.clone());
                            tokio::spawn(async move {
                                tokio::time::sleep(Duration::from_millis(200 + rand_u64() % 800)).await;
                                let data = format!("hello from {}\n", job.job_id).into_bytes();
                                let _ = tx.send(AgentMsg::JobOutput { job_id: job.job_id, stream: rmm_proto::OutputStream::Stdout, data }).await;
                                let fin = AgentMsg::JobFinished { job_id: job.job_id, status: rmm_proto::JobStatus::Succeeded, exit_code: Some(0), duration_ms: 400 };
                                if tx.send(fin).await.is_ok() {
                                    let _ = done.send(job.job_id).await;
                                }
                            });
                        }
                        ServerMsg::JobAck { job_id } => {
                            if let Some(at) = unacked.remove(&job_id) {
                                stats.sample("job_result_ack", at.elapsed());
                                Stats::inc(&stats.jobs_acked);
                            }
                        }
                        _ => {}
                    }
                }
                Some(id) = done_rx.recv() => { unacked.insert(id, Instant::now()); }
                _ = hb.tick() => {
                    beats += 1;
                    tx.send(AgentMsg::Heartbeat(metrics(started, beats, hot(cred.agent_id)))).await?;
                }
                _ = inv.tick() => tx.send(AgentMsg::Inventory(inventory(cred, shape))).await?,
                _ = sec.tick() => tx.send(AgentMsg::SecurityStatus(security())).await?,
                _ = svc.tick() => {
                    generation += 1;
                    tx.send(AgentMsg::Services { services: services(shape, generation) }).await?;
                }
            }
        }
    };
    tokio::select! {
        r = writer => r.and_then(|_| Err(anyhow!("writer ended"))),
        r = reader => r,
    }
}

/// Encoded sizes of the messages, for the report.
pub fn message_sizes(shape: &Shape) -> serde_json::Value {
    let cred = Cred { agent_id: Uuid::nil(), secret: String::new(), hostname: "lg-000-00000".into(), windows: false };
    let size = |m: &AgentMsg| rmm_proto::encode(m).map(|b| b.len()).unwrap_or(0);
    serde_json::json!({
        "heartbeat": size(&AgentMsg::Heartbeat(metrics(Instant::now(), 1, false))),
        "inventory": size(&AgentMsg::Inventory(inventory(&cred, shape))),
        "services": size(&AgentMsg::Services { services: services(shape, 0) }),
        "security_status": size(&AgentMsg::SecurityStatus(security())),
        "patch_scan_result": size(&patch_scan(shape, Uuid::nil())),
    })
}
