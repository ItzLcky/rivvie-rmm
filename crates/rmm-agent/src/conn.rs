//! Server connection: enrollment, auth, and the main dispatch loop.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use futures_util::{SinkExt, StreamExt};
use rmm_proto::{AgentMsg, PROTOCOL_VERSION, PreviousCredential, ServerMsg};
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::collect::{AGENT_VERSION, Collector, system_info};
use crate::config::{self, Config};
use crate::desktop::DesktopSession;
use crate::shell::ShellSession;
use crate::update::Updater;
use crate::logwatch::LogWatchers;
use crate::{deploy, jobs, patch, security, services, shell};

type Ws = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
/// The server pings every 30s. Hearing nothing for this long means the connection is dead
/// (NAT timeout, server crash without a FIN) even if the OS still thinks it's open.
const READ_IDLE_TIMEOUT: Duration = Duration::from_secs(100);

async fn connect(url: &str) -> Result<Ws> {
    let (ws, _resp) = tokio::time::timeout(HANDSHAKE_TIMEOUT, tokio_tungstenite::connect_async(url))
        .await
        .map_err(|_| anyhow!("timed out connecting to {url}"))?
        .with_context(|| format!("connecting to {url}"))?;
    Ok(ws)
}

async fn send(ws: &mut Ws, msg: &AgentMsg) -> Result<()> {
    ws.send(Message::Binary(rmm_proto::encode(msg)?.into())).await?;
    Ok(())
}

async fn recv(ws: &mut Ws) -> Result<ServerMsg> {
    loop {
        let frame = tokio::time::timeout(HANDSHAKE_TIMEOUT, ws.next())
            .await
            .map_err(|_| anyhow!("timed out waiting for server"))?
            .ok_or_else(|| anyhow!("server closed connection"))??;
        match frame {
            Message::Binary(b) => return Ok(rmm_proto::decode(&b)?),
            Message::Close(c) => bail!("server closed connection: {c:?}"),
            _ => continue,
        }
    }
}

/// Exchanges an enrollment token for a permanent agent credential. Passing the existing
/// credential (re-enrolling the same machine) keeps its agent record and history.
pub async fn enroll(server_url: &str, token: &str, previous: Option<&Config>) -> Result<Config> {
    let url = config::ws_url(server_url);
    let mut ws = connect(&url).await?;
    let previous = previous.map(|c| PreviousCredential { agent_id: c.agent_id, secret: c.secret.clone() });
    send(&mut ws, &AgentMsg::Enroll { protocol: PROTOCOL_VERSION, token: token.to_string(), system: system_info(), previous })
        .await?;
    match recv(&mut ws).await? {
        ServerMsg::Enrolled { agent_id, secret } => {
            let _ = ws.close(None).await;
            Ok(Config { server_url: server_url.trim_end_matches('/').to_string(), agent_id, secret })
        }
        ServerMsg::AuthFailed { reason } => bail!("enrollment rejected: {reason}"),
        other => bail!("unexpected reply to enrollment: {other:?}"),
    }
}

/// Stay connected until `shutdown` flips to true, reconnecting with backoff.
pub async fn run_forever(cfg: Config, config_path: std::path::PathBuf, mut shutdown: watch::Receiver<bool>) {
    let tracker = Arc::new(jobs::Tracker::open());
    let watchers = Arc::new(LogWatchers::default());
    let checks = Arc::new(crate::checks::Checks::default());
    let patches = Arc::new(patch::Manager::new());
    let software = Arc::new(deploy::Manager::new(
        deploy::Server { url: cfg.server_url.clone(), agent_id: cfg.agent_id, secret: cfg.secret.clone() },
        patches.op_lock(),
    ));
    let sensor = security::supervisor::Supervisor::new();
    sensor.set_server(cfg.server_url.clone(), cfg.agent_id, cfg.secret.clone());
    tokio::spawn(sensor.clone().run());
    tokio::spawn(keep_isolation(cfg.server_url.clone()));
    let security = Arc::new(security::Manager::new(sensor, cfg.server_url.clone()));
    let updater = Arc::new(Updater::new(config_path, tracker.clone(), patches.clone()));
    let collector = match Collector::new() {
        Ok(c) => Arc::new(Mutex::new(c)),
        Err(e) => {
            error!("cannot initialise system collector: {e}");
            return;
        }
    };
    let mut backoff = Duration::from_secs(1);
    loop {
        let started = std::time::Instant::now();
        tokio::select! {
            res = session(&cfg, collector.clone(), tracker.clone(), updater.clone(), watchers.clone(), checks.clone(), patches.clone(), software.clone(), security.clone()) => match res {
                Ok(()) => info!("connection closed"),
                Err(e) => warn!("connection error: {e:#}"),
            },
            _ = shutdown.changed() => {}
        }
        if *shutdown.borrow() {
            info!("shutting down");
            return;
        }
        // A connection that lived a while resets the backoff.
        if started.elapsed() > Duration::from_secs(60) {
            backoff = Duration::from_secs(1);
        }
        let jitter = Duration::from_millis(u64::from(Uuid::new_v4().as_bytes()[0]) * 4);
        let wait = backoff + jitter;
        info!("reconnecting in {:.1}s", wait.as_secs_f32());
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = shutdown.changed() => if *shutdown.borrow() { return },
        }
        backoff = (backoff * 2).min(Duration::from_secs(60));
    }
}

#[allow(clippy::too_many_arguments)]
async fn session(
    cfg: &Config,
    collector: Arc<Mutex<Collector>>,
    tracker: Arc<jobs::Tracker>,
    updater: Arc<Updater>,
    watchers: Arc<LogWatchers>,
    checks: Arc<crate::checks::Checks>,
    patches: Arc<patch::Manager>,
    software: Arc<deploy::Manager>,
    security: Arc<security::Manager>,
) -> Result<()> {
    let mut ws = connect(&cfg.ws_url()).await?;
    send(
        &mut ws,
        &AgentMsg::Auth {
            protocol: PROTOCOL_VERSION,
            agent_id: cfg.agent_id,
            secret: cfg.secret.clone(),
            agent_version: AGENT_VERSION.to_string(),
            jobs: tracker.ids().await,
            capabilities: capabilities(),
            patch_runs: patches.ids().await,
            security_actions: security.ids(),
            software_runs: software.ids().await,
        },
    )
    .await?;
    let (heartbeat_secs, inventory_secs) = match recv(&mut ws).await? {
        ServerMsg::AuthOk { heartbeat_secs, inventory_secs } => (heartbeat_secs, inventory_secs),
        ServerMsg::AuthFailed { reason } => bail!("authentication rejected: {reason}"),
        other => bail!("unexpected reply to auth: {other:?}"),
    };
    info!(agent_id = %cfg.agent_id, "connected to {}", cfg.server_url);

    let (mut sink, mut stream) = ws.split();
    let (tx, mut rx) = mpsc::channel::<AgentMsg>(1024);

    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let buf = match rmm_proto::encode(&msg) {
                Ok(b) => b,
                Err(e) => {
                    error!("encode failed: {e}");
                    continue;
                }
            };
            if sink.send(Message::Binary(buf.into())).await.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });

    // Before anything else is queued, so resent job state precedes new output.
    tracker.attach(tx.clone()).await;
    updater.attach(tx.clone()).await;
    patches.attach(tx.clone()).await;
    software.attach(tx.clone()).await;
    security.attach(tx.clone()).await;
    security.sensor().attach(tx.clone());
    let security_watch = tokio::spawn(security.clone().watch(tx.clone()));
    let heartbeat = tokio::spawn(periodic(tx.clone(), collector.clone(), heartbeat_secs.max(5), false));
    let inventory = tokio::spawn(periodic(tx.clone(), collector.clone(), inventory_secs.max(300), true));
    watchers.attach(tx.clone());
    checks.attach(tx.clone());
    let (services_refresh, refresh_rx) = mpsc::channel(4);
    let services = tokio::spawn(services::watch(tx.clone(), refresh_rx));
    let ctx = Ctx { tx: tx.clone(), collector, tracker: tracker.clone(), updater: updater.clone(), watchers: watchers.clone(), checks: checks.clone(), patches: patches.clone(), software: software.clone(), security: security.clone(), services_refresh };

    let mut shells: HashMap<Uuid, ShellSession> = HashMap::new();
    let mut desktops: HashMap<Uuid, DesktopSession> = HashMap::new();
    let result = loop {
        let frame = match tokio::time::timeout(READ_IDLE_TIMEOUT, stream.next()).await {
            Err(_) => break Err(anyhow!("nothing from the server for {}s; reconnecting", READ_IDLE_TIMEOUT.as_secs())),
            Ok(None) => break Ok(()),
            Ok(Some(Err(e))) => break Err(e.into()),
            Ok(Some(Ok(f))) => f,
        };
        let msg: ServerMsg = match frame {
            Message::Binary(b) => match rmm_proto::decode(&b) {
                Ok(m) => m,
                Err(e) => {
                    warn!("undecodable frame from server: {e}");
                    continue;
                }
            },
            Message::Close(_) => break Ok(()),
            _ => continue,
        };
        handle(msg, &ctx, &mut shells, &mut desktops).await;
    };

    // Running jobs keep going; their output is buffered until the next connection.
    tracker.detach();
    updater.detach();
    watchers.detach();
    checks.detach();
    services.abort();
    security_watch.abort();
    security.detach();
    security.sensor().detach();
    drop(ctx);
    patches.detach();
    software.detach();
    heartbeat.abort();
    inventory.abort();
    drop(shells);
    drop(desktops);
    drop(tx);
    // A dead socket can stall the writer mid-send. Give it a moment to flush, then move on.
    let abort = writer.abort_handle();
    if tokio::time::timeout(Duration::from_secs(5), writer).await.is_err() {
        abort.abort();
    }
    result
}

/// What a connection's message handler works with.
struct Ctx {
    tx: mpsc::Sender<AgentMsg>,
    collector: Arc<Mutex<Collector>>,
    tracker: Arc<jobs::Tracker>,
    updater: Arc<Updater>,
    watchers: Arc<LogWatchers>,
    checks: Arc<crate::checks::Checks>,
    patches: Arc<patch::Manager>,
    software: Arc<deploy::Manager>,
    security: Arc<security::Manager>,
    /// Makes the service watcher send its list now.
    services_refresh: mpsc::Sender<()>,
}

async fn handle(msg: ServerMsg, ctx: &Ctx, shells: &mut HashMap<Uuid, ShellSession>, desktops: &mut HashMap<Uuid, DesktopSession>) {
    let Ctx { tx, collector, tracker, updater, .. } = ctx;
    match msg {
        ServerMsg::Ping { nonce } => {
            let _ = tx.send(AgentMsg::Pong { nonce }).await;
        }
        ServerMsg::RequestInventory => {
            let (tx, c) = (tx.clone(), collector.clone());
            tokio::spawn(async move {
                if let Ok(inv) = tokio::task::spawn_blocking(move || c.lock().unwrap().inventory()).await {
                    let _ = tx.send(AgentMsg::Inventory(inv)).await;
                }
            });
        }
        ServerMsg::RunScript(job) => {
            tokio::spawn(jobs::run(job, tracker.clone()));
        }
        ServerMsg::JobAck { job_id } => tracker.ack(job_id).await,
        ServerMsg::UpdateOffer { version, size, sha256, signature } => updater.offer(version, size, sha256, signature).await,
        ServerMsg::UpdateChunk { version, offset, data } => updater.chunk(version, offset, data).await,
        ServerMsg::ShellOpen { session_id, cols, rows } => match shell::ShellSession::open(session_id, cols, rows, tx.clone()) {
            Ok(s) => {
                info!(%session_id, "shell opened");
                shells.insert(session_id, s);
                let _ = tx.send(AgentMsg::ShellOpened { session_id }).await;
            }
            Err(e) => {
                warn!(%session_id, "shell open failed: {e:#}");
                let _ = tx.send(AgentMsg::ShellClosed { session_id, reason: Some(format!("{e:#}")) }).await;
            }
        },
        ServerMsg::ShellInput { session_id, data } => {
            if let Some(s) = shells.get_mut(&session_id)
                && let Err(e) = s.write(&data) {
                    debug!(%session_id, "shell write failed: {e}");
                    shells.remove(&session_id);
                }
        }
        ServerMsg::ShellResize { session_id, cols, rows } => {
            if let Some(s) = shells.get(&session_id) {
                let _ = s.resize(cols, rows);
            }
        }
        ServerMsg::ShellClose { session_id } => {
            if shells.remove(&session_id).is_some() {
                info!(%session_id, "shell closed by server");
            }
        }
        ServerMsg::RequestServices => {
            let _ = ctx.services_refresh.try_send(());
        }
        ServerMsg::ServiceControl { request_id, name, action } => {
            info!(service = %name, action = action.as_str(), "service control");
            tokio::spawn(services::control(request_id, name, action, tx.clone(), ctx.services_refresh.clone()));
        }
        ServerMsg::Watchers { watchers } => ctx.watchers.set(watchers).await,
        ServerMsg::Checks { checks, run_now } => ctx.checks.set(checks, run_now).await,
        ServerMsg::PatchScan { request_id } => {
            tokio::spawn(ctx.patches.clone().scan(Some(request_id)));
        }
        ServerMsg::PatchInstall { run_id, ids, reboot_policy } => {
            tokio::spawn(ctx.patches.clone().install(run_id, ids, reboot_policy));
        }
        ServerMsg::PatchAck { run_id } => ctx.patches.ack(run_id).await,
        ServerMsg::SoftwareScan { request_id, packages } => {
            tokio::spawn(ctx.software.clone().scan(Some(request_id), packages));
        }
        ServerMsg::SoftwareRun { run_id, op, package, bootstrap_choco } => {
            tokio::spawn(ctx.software.clone().run(run_id, op, package, bootstrap_choco));
        }
        ServerMsg::SoftwareAck { run_id } => ctx.software.ack(run_id).await,
        ServerMsg::SecurityRefresh => ctx.security.refresh(),
        ServerMsg::SecurityAction { request_id, product, action } => {
            tokio::spawn(ctx.security.clone().action(request_id, product, action));
        }
        ServerMsg::Content { version, bundle, signature } => {
            let s = ctx.security.sensor().clone();
            tokio::task::spawn_blocking(move || s.set_content(version, bundle, signature));
        }
        ServerMsg::SensorPolicy(p) => ctx.security.sensor().set_policy(p),
        ServerMsg::Database { offer } => ctx.security.sensor().set_database(offer),
        ServerMsg::SensorDetectionAck { id } => ctx.security.sensor().ack(&id),
        ServerMsg::ReputationResult { known } => ctx.security.sensor().reputation(known),
        ServerMsg::Response { request_id, action } => {
            tokio::spawn(ctx.security.clone().respond(request_id, action));
        }
        ServerMsg::TelemetryQuery { request_id, query } => {
            let tx = tx.clone();
            tokio::spawn(async move {
                let res = tokio::task::spawn_blocking(move || crate::sensor::store::dir().map(|d| crate::sensor::store::query(&d, &query))).await;
                let msg = match res {
                    Ok(Ok((events, truncated))) => AgentMsg::TelemetryResult { request_id, events, truncated, error: None },
                    Ok(Err(e)) => AgentMsg::TelemetryResult { request_id, events: vec![], truncated: false, error: Some(format!("{e:#}")) },
                    Err(e) => AgentMsg::TelemetryResult { request_id, events: vec![], truncated: false, error: Some(e.to_string()) },
                };
                let _ = tx.send(msg).await;
            });
        }
        ServerMsg::Tool { request_id, request } => {
            let tx = tx.clone();
            tokio::spawn(async move {
                let reply = tokio::task::spawn_blocking(move || crate::tools::handle(request))
                    .await
                    .unwrap_or_else(|e| rmm_proto::tools::Reply::Error(e.to_string()));
                let _ = tx.send(AgentMsg::ToolReply { request_id, reply }).await;
            });
        }
        ServerMsg::NetScan { scan_id, spec } => {
            tokio::spawn(crate::net::scan(scan_id, spec, tx.clone()));
        }
        ServerMsg::SnmpPoll { poll_id, targets } => {
            tokio::spawn(crate::net::snmp_poll(poll_id, targets, tx.clone()));
        }
        ServerMsg::DesktopOpen { session_id, settings, consent } => {
            if desktops.len() >= MAX_DESKTOPS {
                let reason = Some(format!("this machine already has {MAX_DESKTOPS} remote desktop sessions open"));
                let _ = tx.send(AgentMsg::DesktopClosed { session_id, reason }).await;
            } else {
                info!(%session_id, consent = consent.is_some(), "desktop session requested");
                desktops.insert(session_id, DesktopSession::open(session_id, settings, consent, tx.clone()));
            }
        }
        ServerMsg::DesktopSettings { session_id, settings } => {
            if let Some(d) = desktops.get(&session_id) {
                d.settings(settings);
            }
        }
        ServerMsg::DesktopInput { session_id, events } => {
            if let Some(d) = desktops.get(&session_id) {
                d.input(events);
            }
        }
        ServerMsg::DesktopAck { session_id, seq } => {
            if let Some(d) = desktops.get(&session_id) {
                d.ack(seq);
            }
        }
        ServerMsg::DesktopClose { session_id } => {
            if desktops.remove(&session_id).is_some() {
                info!(%session_id, "desktop closed by server");
            }
        }
        ServerMsg::Enrolled { .. } | ServerMsg::AuthOk { .. } | ServerMsg::AuthFailed { .. } => {}
    }
}

/// Concurrent remote desktop sessions per machine.
const MAX_DESKTOPS: usize = 3;

/// Optional features to announce in `Auth`.
fn capabilities() -> Vec<String> {
    let mut caps = vec![
        rmm_proto::patch::CAPABILITY.to_string(),
        rmm_proto::software::CAPABILITY.to_string(),
        rmm_proto::security::CAPABILITY.to_string(),
        rmm_proto::security::SENSOR_CAPABILITY.to_string(),
        rmm_proto::security::SIGDB_CAPABILITY.to_string(),
        rmm_proto::tools::CAPABILITY.to_string(),
        rmm_proto::net::CAPABILITY.to_string(),
        rmm_proto::checks::CAPABILITY.to_string(),
    ];
    if cfg!(any(target_os = "linux", windows)) || std::env::var_os("RMM_DESKTOP_FAKE").is_some() {
        caps.push(rmm_proto::desktop::CAPABILITY.to_string());
    }
    caps
}

/// Puts network isolation back after a restart, and follows the server's address while
/// isolated (so a DNS change can't cut the management channel).
async fn keep_isolation(server_url: String) {
    loop {
        let url = server_url.clone();
        let _ = tokio::task::spawn_blocking(move || security::isolation::reapply(&url)).await;
        tokio::time::sleep(Duration::from_secs(300)).await;
    }
}

async fn periodic(tx: mpsc::Sender<AgentMsg>, collector: Arc<Mutex<Collector>>, every_secs: u32, inventory: bool) {
    let mut tick = tokio::time::interval(Duration::from_secs(every_secs.into()));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let c = collector.clone();
        let msg = tokio::task::spawn_blocking(move || {
            let mut c = c.lock().unwrap();
            if inventory { AgentMsg::Inventory(c.inventory()) } else { AgentMsg::Heartbeat(c.metrics()) }
        })
        .await;
        match msg {
            Ok(m) => {
                if tx.send(m).await.is_err() {
                    return;
                }
            }
            Err(e) => error!("collector panicked: {e}"),
        }
    }
}
