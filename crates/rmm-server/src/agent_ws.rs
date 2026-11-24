//! `/api/agent/ws`: the single endpoint every agent connects to.

use sqlx::AssertSqlSafe;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::response::Response;
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use rmm_proto::{
    AgentMsg, Interpreter, Inventory, JobStatus, Metrics, OutputStream, PROTOCOL_VERSION, PreviousCredential, ScriptJob, ServerMsg,
    SystemInfo, UpdateState,
};
use subtle::ConstantTimeEq;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::auth::{random_token, token_hash};
use crate::hub::{AgentHandle, DesktopEvent, Event, ShellEvent};
use crate::ratelimit::ClientIp;
use crate::state::AppState;

const MAX_FRAME: usize = 16 * 1024 * 1024;
const JOB_OUTPUT_CAP: i32 = 1024 * 1024;
const FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(15);
const PING_EVERY: Duration = Duration::from_secs(30);

/// Read buffer per agent connection. tungstenite allocates 128 KiB by default; with 8 KiB the
/// server holding 10,000 agents went from 1.76 GB to 1.02 GB resident (load test,
/// docs/research/load-test-2026-11.md). Heartbeats are under 1 KiB; larger messages
/// (inventory, ~30 KiB) just take a few reads.
const READ_BUFFER: usize = 8 * 1024;

pub async fn handler(ws: WebSocketUpgrade, State(state): State<Arc<AppState>>, ClientIp(ip): ClientIp) -> Response {
    ws.max_message_size(MAX_FRAME).read_buffer_size(READ_BUFFER).on_upgrade(move |socket| async move {
        if let Err(e) = handle(socket, state, ip).await {
            debug!("agent socket ended: {e:#}");
        }
    })
}

async fn send(ws: &mut WebSocket, msg: &ServerMsg) -> anyhow::Result<()> {
    ws.send(Message::Binary(rmm_proto::encode(msg)?.into())).await?;
    Ok(())
}

async fn handle(mut ws: WebSocket, state: Arc<AppState>, ip: IpAddr) -> anyhow::Result<()> {
    let first = match tokio::time::timeout(FIRST_FRAME_TIMEOUT, ws.recv()).await {
        Ok(Some(Ok(Message::Binary(b)))) => rmm_proto::decode::<AgentMsg>(&b)?,
        _ => return Ok(()),
    };
    match first {
        AgentMsg::Enroll { protocol, token, system, previous } => {
            // Bad tokens from one address share a budget. Agent auth isn't limited: secrets
            // are 256-bit, and a few deleted agents retrying behind a site's NAT must not
            // lock out the healthy ones.
            let ip_key = ip.to_string();
            if let Err(wait) = state.limits.enroll_ip.check(&ip_key) {
                let reason = format!("too many failed enrollments from {ip}; try again in {} seconds", wait.as_secs());
                send(&mut ws, &ServerMsg::AuthFailed { reason }).await?;
                return Ok(());
            }
            let reply = match enroll(&state, protocol, &token, &system, previous.as_ref()).await {
                Ok((agent_id, secret)) => ServerMsg::Enrolled { agent_id, secret },
                Err(reason) => {
                    state.limits.enroll_ip.fail(&ip_key);
                    ServerMsg::AuthFailed { reason }
                }
            };
            send(&mut ws, &reply).await?;
            let _ = ws.close().await;
            Ok(())
        }
        AgentMsg::Auth { protocol, agent_id, secret, agent_version, jobs, capabilities, patch_runs, security_actions, software_runs } => {
            if protocol != PROTOCOL_VERSION {
                send(&mut ws, &ServerMsg::AuthFailed { reason: format!("unsupported protocol {protocol}") }).await?;
                return Ok(());
            }
            if !authenticate(&state, agent_id, &secret).await? {
                crate::metrics::inc(&crate::metrics::M.agent_auth_failures);
                warn!(%agent_id, %ip, "agent auth failed");
                send(&mut ws, &ServerMsg::AuthFailed { reason: "invalid credentials".into() }).await?;
                return Ok(());
            }
            send(
                &mut ws,
                &ServerMsg::AuthOk { heartbeat_secs: state.cfg.heartbeat_secs, inventory_secs: state.cfg.inventory_secs },
            )
            .await?;
            crate::metrics::inc(&crate::metrics::M.agent_connects);
            let held = Held { jobs, patch_runs, security_actions, software_runs };
            run_session(ws, state, agent_id, agent_version, held, capabilities).await
        }
        _ => Ok(()),
    }
}

async fn enroll(
    state: &AppState,
    protocol: u32,
    token: &str,
    sys: &SystemInfo,
    previous: Option<&PreviousCredential>,
) -> Result<(Uuid, String), String> {
    if protocol != PROTOCOL_VERSION {
        return Err(format!("unsupported protocol {protocol}"));
    }
    let db_err = |e: sqlx::Error| {
        tracing::error!("enroll db error: {e}");
        "server error".to_string()
    };
    let mut tx = state.db.begin().await.map_err(db_err)?;

    // Atomically consume one use of the token.
    let row: Option<(Uuid, Option<Uuid>)> = sqlx::query_as(
        "UPDATE enrollment_tokens SET uses = uses + 1
          WHERE token_hash = $1
            AND (expires_at IS NULL OR expires_at > now())
            AND (max_uses IS NULL OR uses < max_uses)
          RETURNING site_id, category_id",
    )
    .bind(token_hash(token))
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;
    let Some((site_id, category)) = row else {
        return Err("invalid or expired enrollment token".into());
    };

    // Reuse the existing record only if the agent proves it owns it, and only within the
    // token's site. A bare token never touches an existing agent's credential.
    let reuse = match previous {
        Some(p) => {
            let stored: Option<Vec<u8>> = sqlx::query_scalar("SELECT secret_hash FROM agents WHERE id = $1 AND site_id = $2")
                .bind(p.agent_id)
                .bind(site_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_err)?;
            stored.is_some_and(|h| bool::from(h.ct_eq(&token_hash(&p.secret)))).then_some(p.agent_id)
        }
        None => None,
    };

    let secret = random_token();
    // The trigger on agents places it in its category (the token's, else the built-in one for
    // its OS and platform) and resolves its policy set.
    let agent_id: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (id, site_id, secret_hash, machine_id, hostname, os_family, os_name, os_version, kernel_version, arch, agent_version,
                             platform, category_id, category_manual)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13 IS NOT NULL)
         ON CONFLICT (id)
         DO UPDATE SET secret_hash = EXCLUDED.secret_hash, machine_id = EXCLUDED.machine_id, hostname = EXCLUDED.hostname,
                       os_family = EXCLUDED.os_family, os_name = EXCLUDED.os_name, os_version = EXCLUDED.os_version,
                       kernel_version = EXCLUDED.kernel_version, arch = EXCLUDED.arch, agent_version = EXCLUDED.agent_version,
                       platform = EXCLUDED.platform,
                       category_id = coalesce($13, agents.category_id), category_manual = agents.category_manual OR $13 IS NOT NULL
         RETURNING id",
    )
    .bind(reuse.unwrap_or_else(Uuid::new_v4))
    .bind(site_id)
    .bind(token_hash(&secret))
    .bind(&sys.machine_id)
    .bind(&sys.hostname)
    .bind(sys.os_family.as_str())
    .bind(&sys.os_name)
    .bind(&sys.os_version)
    .bind(&sys.kernel_version)
    .bind(&sys.arch)
    .bind(&sys.agent_version)
    .bind(sys.platform.map(|p| p.as_str()))
    .bind(category)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;

    // The old credential is now invalid; drop its live connection, if any.
    if reuse.is_some() {
        state.hub.kick(agent_id);
    }
    info!(%agent_id, hostname = %sys.hostname, %site_id, reused = reuse.is_some(), "agent enrolled");
    crate::auth::audit(
        &state.db,
        None,
        "agent.enroll",
        Some(("agent", agent_id)),
        serde_json::json!({ "hostname": sys.hostname, "reused": reuse.is_some() }),
    )
    .await;
    Ok((agent_id, secret))
}

pub(crate) async fn authenticate(state: &AppState, agent_id: Uuid, secret: &str) -> anyhow::Result<bool> {
    let stored: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT secret_hash FROM agents WHERE id = $1").bind(agent_id).fetch_optional(&state.db).await?;
    Ok(stored.is_some_and(|h| bool::from(h.ct_eq(&token_hash(secret)))))
}

/// What a reconnecting agent says it still holds: anything else it was sent can't report.
struct Held {
    jobs: Vec<Uuid>,
    patch_runs: Vec<Uuid>,
    security_actions: Vec<Uuid>,
    software_runs: Vec<Uuid>,
}

async fn run_session(
    ws: WebSocket,
    state: Arc<AppState>,
    agent_id: Uuid,
    agent_version: String,
    held: Held,
    capabilities: Vec<String>,
) -> anyhow::Result<()> {
    let conn_id = Uuid::new_v4();
    let (tx, mut rx) = mpsc::channel::<ServerMsg>(1024);
    // The agent resends output and results for the jobs it still holds; anything else marked
    // `sent` can never finish. Do this before registering: a job created in between sees the
    // agent offline, stays queued, and is dispatched below.
    let lost = mark_lost(&state.db, agent_id, &held.jobs).await?;
    if let Some(old) = state.hub.register(agent_id, AgentHandle { conn_id, tx: tx.clone() }) {
        debug!(%agent_id, old = %old.conn_id, "replacing stale connection");
    }
    // What it was before this connection: automations fire on the first one, and on coming back
    // after a while away.
    let (first_connect, last_seen): (bool, Option<chrono::DateTime<chrono::Utc>>) = sqlx::query_as(
        "UPDATE agents a SET online = true, last_seen_at = now(), connected_at = now(), agent_version = $2,
                first_connected_at = coalesce(a.first_connected_at, now())
           FROM (SELECT id, first_connected_at, last_seen_at FROM agents WHERE id = $1) old
          WHERE a.id = old.id
      RETURNING old.first_connected_at IS NULL, old.last_seen_at",
    )
    .bind(agent_id)
    .bind(&agent_version)
    .fetch_one(&state.db)
    .await?;
    info!(%agent_id, %agent_version, "agent online");
    // Agents don't move between clients, so this holds for the whole connection.
    let client_id: Uuid =
        sqlx::query_scalar("SELECT s.client_id FROM agents a JOIN sites s ON s.id = a.site_id WHERE a.id = $1")
            .bind(agent_id)
            .fetch_one(&state.db)
            .await?;
    state.hub.publish(Event::Agent { id: agent_id, client_id, online: true, last_metrics: None });

    let (mut sink, mut stream) = ws.split();
    let writer = tokio::spawn(async move {
        let mut ping = tokio::time::interval(PING_EVERY);
        ping.tick().await;
        loop {
            let frame = tokio::select! {
                m = rx.recv() => match m {
                    Some(m) => match rmm_proto::encode(&m) {
                        Ok(b) => Message::Binary(b.into()),
                        Err(_) => continue,
                    },
                    None => break,
                },
                _ = ping.tick() => Message::Ping(Vec::new().into()),
            };
            if sink.send(frame).await.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });

    // Ask for fresh inventory and flush anything queued while the agent was offline.
    let _ = tx.send(ServerMsg::RequestInventory).await;
    let _ = tx.send(ServerMsg::Watchers { watchers: crate::alerts::watchers_for(&state, agent_id).await }).await;
    crate::alerts::agent_online(&state, agent_id).await;
    {
        let state = state.clone();
        tokio::spawn(async move { crate::automation::on_connect(&state, agent_id, first_connect, last_seen).await });
    }
    let dispatched = dispatch_queued(&state, agent_id, &tx).await.unwrap_or_else(|e| {
        warn!(%agent_id, "dispatching queued jobs: {e}");
        0
    });
    if lost > 0 || dispatched > 0 {
        state.hub.publish(Event::Jobs);
    }
    if let Err(e) = crate::patches::on_connect(&state, agent_id, client_id, &capabilities, &held.patch_runs, &tx).await {
        warn!(%agent_id, "patch state on connect: {e:#}");
    }
    if let Err(e) = crate::software::on_connect(&state, agent_id, client_id, &capabilities, &held.software_runs).await {
        warn!(%agent_id, "software state on connect: {e:#}");
    }
    if let Err(e) = crate::security::on_connect(&state, agent_id, client_id, &capabilities, &held.security_actions).await {
        warn!(%agent_id, "security state on connect: {e:#}");
    }
    crate::checks::on_connect(&state, agent_id, &capabilities, &tx).await;
    // Replies to this connection only (job acks). Weak, so the writer still ends when the
    // hub drops the agent (kick) and every other sender is gone.
    let reply = tx.downgrade();
    drop(tx);

    // Idle timeout: 3 missed pings and we consider the agent gone.
    let idle = PING_EVERY * 3;
    let mut auto_update_checked = false;
    loop {
        let frame = match tokio::time::timeout(idle, stream.next()).await {
            Ok(Some(Ok(f))) => f,
            Ok(Some(Err(_))) | Ok(None) | Err(_) => break,
        };
        let msg = match frame {
            Message::Binary(b) => match rmm_proto::decode::<AgentMsg>(&b) {
                Ok(m) => {
                    let metrics = &crate::metrics::M;
                    metrics.agent_message_bytes.fetch_add(b.len() as u64, std::sync::atomic::Ordering::Relaxed);
                    crate::metrics::inc(&metrics.agent_messages[message_type(&m)]);
                    m
                }
                Err(e) => {
                    warn!(%agent_id, "bad frame: {e}");
                    continue;
                }
            },
            Message::Close(_) => break,
            _ => continue,
        };
        // Auto-update waits for the first heartbeat: the agent reports how its last update
        // went (e.g. rolled back) before it, so that's already recorded when we decide.
        let first_heartbeat = !auto_update_checked && matches!(msg, AgentMsg::Heartbeat(_));
        if let Err(e) = on_message(&state, agent_id, client_id, &reply, msg).await {
            warn!(%agent_id, "handling message: {e:#}");
        }
        if first_heartbeat {
            auto_update_checked = true;
            crate::updates::auto_offer(&state, agent_id).await;
        }
    }

    writer.abort();
    // In-flight jobs stay `sent`: the agent keeps running them and reports on reconnect.
    // If it never comes back, the housekeeping timeout reaper marks them `lost`.
    if state.hub.unregister(agent_id, conn_id) {
        state.hub.drop_agent_shells(agent_id);
        let _ = sqlx::query("UPDATE agents SET online = false, last_seen_at = now() WHERE id = $1")
            .bind(agent_id)
            .execute(&state.db)
            .await;
        state.hub.publish(Event::Agent { id: agent_id, client_id, online: false, last_metrics: None });
        info!(%agent_id, "agent offline");
    }
    Ok(())
}

/// Jobs dispatched to the agent that it doesn't hold any more (it restarted, or the job was
/// lost in transit with a dying connection) will never report.
pub async fn mark_lost(db: &sqlx::PgPool, agent_id: Uuid, held: &[Uuid]) -> sqlx::Result<u64> {
    let n = sqlx::query(
        "UPDATE jobs SET status = 'lost', finished_at = now(),
                stderr = stderr || E'\\n[rmm] the agent has no record of this job: it restarted, or the job never reached it\\n'
          WHERE agent_id = $1 AND status = 'sent' AND NOT (id = ANY($2))",
    )
    .bind(agent_id)
    .bind(held)
    .execute(db)
    .await?
    .rows_affected();
    if n > 0 {
        info!(%agent_id, jobs = n, "in-flight jobs lost");
    }
    Ok(n)
}

/// Sends every queued job to a freshly connected agent; returns how many.
pub async fn dispatch_queued(state: &AppState, agent_id: Uuid, tx: &mpsc::Sender<ServerMsg>) -> anyhow::Result<usize> {
    let rows: Vec<(Uuid, String, String, serde_json::Value, i32)> = sqlx::query_as(
        "UPDATE jobs SET status = 'sent', sent_at = now()
          WHERE agent_id = $1 AND status = 'queued'
          RETURNING id, interpreter, body, args, timeout_secs",
    )
    .bind(agent_id)
    .fetch_all(&state.db)
    .await?;
    let n = rows.len();
    for (job_id, interp, body, args, timeout) in rows {
        let Some(interpreter) = parse_interpreter(&interp) else { continue };
        let job = ScriptJob {
            job_id,
            interpreter,
            script: body,
            args: serde_json::from_value(args).unwrap_or_default(),
            timeout_secs: timeout.max(1) as u32,
        };
        let _ = tx.send(ServerMsg::RunScript(job)).await;
    }
    Ok(n)
}

pub fn parse_interpreter(s: &str) -> Option<Interpreter> {
    Some(match s {
        "sh" => Interpreter::Sh,
        "bash" => Interpreter::Bash,
        "powershell" => Interpreter::PowerShell,
        "cmd" => Interpreter::Cmd,
        "python" => Interpreter::Python,
        _ => return None,
    })
}

async fn on_message(
    state: &Arc<AppState>,
    agent_id: Uuid,
    client_id: Uuid,
    reply: &mpsc::WeakSender<ServerMsg>,
    msg: AgentMsg,
) -> anyhow::Result<()> {
    // Job rows changed by this message, announced once it's stored.
    let job_event = |id: Uuid, status: Option<String>, output: bool| {
        if let Some(status) = status {
            state.hub.publish(Event::Job { id, agent_id, client_id, status, output });
        }
    };
    match msg {
        AgentMsg::Heartbeat(m) => {
            store_metrics(state, agent_id, &m).await?;
            state.hub.publish(Event::Agent { id: agent_id, client_id, online: true, last_metrics: serde_json::to_value(&m).ok() });
        }
        AgentMsg::Inventory(inv) => store_inventory(state, agent_id, &inv).await?,
        AgentMsg::JobOutput { job_id, stream, data } => {
            let col = match stream {
                OutputStream::Stdout => "stdout",
                OutputStream::Stderr => "stderr",
            };
            // Cap stored output so a chatty script can't bloat the DB.
            let sql = format!(
                "UPDATE jobs SET {col} = {col} || left($3, GREATEST(0, $4 - length({col})))
                  WHERE id = $1 AND agent_id = $2 RETURNING status"
            );
            let status = sqlx::query_scalar(AssertSqlSafe(sql))
                .bind(job_id)
                .bind(agent_id)
                .bind(String::from_utf8_lossy(&data).as_ref())
                .bind(JOB_OUTPUT_CAP)
                .fetch_optional(&state.db)
                .await?;
            job_event(job_id, status, true);
        }
        AgentMsg::JobFinished { job_id, status, exit_code, duration_ms } => {
            let status: Option<String> = sqlx::query_scalar(
                // `lost` too: the timeout reaper may have given up on a job that then finished.
                "UPDATE jobs SET status = $3, exit_code = $4, duration_ms = $5, finished_at = now()
                  WHERE id = $1 AND agent_id = $2 AND status IN ('sent', 'lost') RETURNING status",
            )
            .bind(job_id)
            .bind(agent_id)
            .bind(status_str(status))
            .bind(exit_code)
            .bind(duration_ms as i64)
            .fetch_optional(&state.db)
            .await?;
            if let Some(s) = &status {
                crate::alerts::job_finished(state, agent_id, job_id, s).await;
                crate::tickets::job_finished(state, job_id).await;
                if s == "succeeded" {
                    crate::fields::apply_job_output(state, agent_id, job_id).await;
                }
                crate::automation::job_finished(state, job_id).await;
            }
            job_event(job_id, status, false);
            // Stored (or already final from an earlier delivery): the agent can forget it.
            if let Some(tx) = reply.upgrade() {
                let _ = tx.send(ServerMsg::JobAck { job_id }).await;
            }
        }
        AgentMsg::JobSync { job_id, stdout, stderr } => {
            // Replaces what arrived before the reconnect; the agent's copy is a superset.
            let status = sqlx::query_scalar(
                "UPDATE jobs SET stdout = left($3, $5), stderr = left($4, $5)
                  WHERE id = $1 AND agent_id = $2 AND status NOT IN ('queued', 'expired') RETURNING status",
            )
            .bind(job_id)
            .bind(agent_id)
            .bind(String::from_utf8_lossy(&stdout).as_ref())
            .bind(String::from_utf8_lossy(&stderr).as_ref())
            .bind(JOB_OUTPUT_CAP)
            .fetch_optional(&state.db)
            .await?;
            job_event(job_id, status, true);
        }
        AgentMsg::ShellOpened { session_id } => state.hub.route_shell(agent_id, session_id, ShellEvent::Opened).await,
        AgentMsg::ShellOutput { session_id, data } => state.hub.route_shell(agent_id, session_id, ShellEvent::Output(data)).await,
        AgentMsg::ShellClosed { session_id, reason } => {
            state.hub.route_shell(agent_id, session_id, ShellEvent::Closed(reason)).await
        }
        AgentMsg::DesktopInfo { session_id, monitors, monitor } => {
            state.hub.route_desktop(agent_id, session_id, DesktopEvent::Info { monitors, monitor })
        }
        AgentMsg::DesktopFrame { session_id, frame } => state.hub.route_desktop(agent_id, session_id, DesktopEvent::Frame(frame)),
        AgentMsg::DesktopClosed { session_id, reason } => {
            state.hub.route_desktop(agent_id, session_id, DesktopEvent::Closed(reason))
        }
        AgentMsg::UpdateFetch { version, offset } => {
            let chunk = crate::updates::chunk(state, agent_id, &version, offset).await;
            if let Some(tx) = reply.upgrade() {
                let _ = tx.send(chunk).await;
            }
        }
        AgentMsg::UpdateStatus { version, state: phase, detail } => {
            let detail = detail.map(|d| d.chars().take(1000).collect::<String>());
            sqlx::query(
                "UPDATE agents SET update_version = $2, update_state = $3, update_detail = $4, update_at = now() WHERE id = $1",
            )
            .bind(agent_id)
            .bind(&version)
            .bind(phase.as_str())
            .bind(&detail)
            .execute(&state.db)
            .await?;
            if matches!(phase, UpdateState::Completed | UpdateState::RolledBack | UpdateState::Failed) {
                info!(%agent_id, %version, state = phase.as_str(), detail = detail.as_deref().unwrap_or(""), "agent update");
                crate::auth::audit(
                    &state.db,
                    None,
                    &format!("agent.update_{}", phase.as_str()),
                    Some(("agent", agent_id)),
                    serde_json::json!({ "version": version, "detail": detail }),
                )
                .await;
            }
        }
        AgentMsg::Services { services } => {
            let mut services = services;
            services.truncate(5000);
            sqlx::query("UPDATE agents SET services = $2, services_at = now() WHERE id = $1")
                .bind(agent_id)
                .bind(serde_json::to_value(&services)?)
                .execute(&state.db)
                .await?;
            state.hub.publish(Event::Services { agent_id, client_id });
            crate::alerts::services_reported(state, agent_id, &services).await;
        }
        AgentMsg::ServiceControlResult { request_id, ok, message } => {
            state.hub.complete_control(agent_id, request_id, (ok, message.chars().take(2000).collect()));
        }
        AgentMsg::LogMatches { watcher_id, entries, suppressed } => {
            crate::alerts::log_matched(state, agent_id, watcher_id, entries, suppressed).await;
        }
        AgentMsg::PatchScanResult { request_id: _, provider, all_or_nothing, error, updates, reboot_pending } => {
            crate::patches::ingest_scan(state, agent_id, client_id, &provider, all_or_nothing, error, &updates, reboot_pending).await?
        }
        AgentMsg::PatchProgress { run_id, stage, message, percent } => {
            crate::patches::ingest_progress(state, agent_id, client_id, run_id, stage, message, percent).await?
        }
        AgentMsg::PatchResult(outcome) => {
            crate::patches::ingest_result(state, agent_id, client_id, &outcome).await?;
            // Stored (or already final): the agent can forget it.
            if let Some(tx) = reply.upgrade() {
                let _ = tx.send(ServerMsg::PatchAck { run_id: outcome.run_id }).await;
            }
        }
        AgentMsg::SoftwareScanResult { request_id: _, providers, error, items } => {
            crate::software::ingest_scan(state, agent_id, client_id, providers, error, &items).await?
        }
        AgentMsg::SoftwareProgress { run_id, stage, message } => {
            crate::software::ingest_progress(state, agent_id, client_id, run_id, stage, message).await?
        }
        AgentMsg::SoftwareResult(outcome) => {
            crate::software::ingest_result(state, agent_id, client_id, &outcome).await?;
            if let Some(tx) = reply.upgrade() {
                let _ = tx.send(ServerMsg::SoftwareAck { run_id: outcome.run_id }).await;
            }
        }
        AgentMsg::SecurityStatus(report) => crate::security::ingest_report(state, agent_id, client_id, report).await?,
        AgentMsg::SecurityActionResult { request_id, state: phase, message, data } => {
            crate::security::ingest_action(state, agent_id, client_id, request_id, phase, message, data).await?
        }
        AgentMsg::SensorStatus(s) => crate::security::ingest_status(state, agent_id, client_id, s).await?,
        AgentMsg::SensorDetection(d) => {
            crate::security::ingest_detection(state, agent_id, client_id, &d).await?;
            if let Some(tx) = reply.upgrade() {
                let _ = tx.send(ServerMsg::SensorDetectionAck { id: d.id }).await;
            }
        }
        AgentMsg::QuarantineList { items } => crate::security::ingest_quarantine(state, agent_id, client_id, &items).await?,
        AgentMsg::TelemetryResult { request_id, events, truncated, error } => {
            state.hub.complete_query(agent_id, request_id, (events, truncated, error));
        }
        AgentMsg::TriageChunk { request_id, offset, data, done: _ } => {
            crate::security::ingest_triage_chunk(state, agent_id, request_id, offset, data).await?
        }
        AgentMsg::ToolReply { request_id, reply } => state.hub.complete_tool(agent_id, request_id, reply),
        AgentMsg::ReputationQuery { hashes } => {
            let known = crate::security::reputation_query(state, agent_id, &hashes).await?;
            if let Some(tx) = reply.upgrade() {
                let _ = tx.send(ServerMsg::ReputationResult { known }).await;
            }
        }
        AgentMsg::NetScanResult { scan_id, subnets, scanned, hosts, error, duration_ms: _ } => {
            crate::netmon::ingest_scan(state, agent_id, scan_id, subnets, scanned, hosts, error).await?
        }
        AgentMsg::SnmpPollResult { poll_id, results } => crate::netmon::ingest_poll(state, agent_id, poll_id, results).await,
        AgentMsg::CheckResults { results } => crate::checks::ingest(state, agent_id, results).await?,
        AgentMsg::Pong { .. } => {}
        AgentMsg::Enroll { .. } | AgentMsg::Auth { .. } => {}
    }
    Ok(())
}

/// Index into [`crate::metrics::AGENT_MESSAGE_TYPES`].
fn message_type(m: &AgentMsg) -> usize {
    match m {
        AgentMsg::Enroll { .. } => 0,
        AgentMsg::Auth { .. } => 1,
        AgentMsg::Heartbeat(_) => 2,
        AgentMsg::Inventory(_) => 3,
        AgentMsg::JobOutput { .. } => 4,
        AgentMsg::JobFinished { .. } => 5,
        AgentMsg::JobSync { .. } => 6,
        AgentMsg::UpdateFetch { .. } => 7,
        AgentMsg::UpdateStatus { .. } => 8,
        AgentMsg::ShellOpened { .. } => 9,
        AgentMsg::ShellOutput { .. } => 10,
        AgentMsg::ShellClosed { .. } => 11,
        AgentMsg::Pong { .. } => 12,
        AgentMsg::Services { .. } => 13,
        AgentMsg::ServiceControlResult { .. } => 14,
        AgentMsg::LogMatches { .. } => 15,
        AgentMsg::PatchScanResult { .. } => 16,
        AgentMsg::PatchProgress { .. } => 17,
        AgentMsg::PatchResult(_) => 18,
        AgentMsg::DesktopInfo { .. } => 19,
        AgentMsg::DesktopFrame { .. } => 20,
        AgentMsg::DesktopClosed { .. } => 21,
        AgentMsg::SecurityStatus(_) => 22,
        AgentMsg::SecurityActionResult { .. } => 23,
        AgentMsg::SensorStatus(_) => 24,
        AgentMsg::SensorDetection(_) => 25,
        AgentMsg::QuarantineList { .. } => 26,
        AgentMsg::TelemetryResult { .. } => 27,
        AgentMsg::TriageChunk { .. } => 28,
        AgentMsg::ToolReply { .. } => 29,
        AgentMsg::ReputationQuery { .. } => 30,
        AgentMsg::SoftwareScanResult { .. } => 31,
        AgentMsg::SoftwareProgress { .. } => 32,
        AgentMsg::SoftwareResult(_) => 33,
        AgentMsg::NetScanResult { .. } => 34,
        AgentMsg::SnmpPollResult { .. } => 35,
        AgentMsg::CheckResults { .. } => 36,
    }
}

fn status_str(s: JobStatus) -> &'static str {
    s.as_str()
}

async fn store_metrics(state: &AppState, agent_id: Uuid, m: &Metrics) -> anyhow::Result<()> {
    let disk_max_pct = m
        .disks
        .iter()
        .filter(|d| d.total > 0)
        .map(|d| 100.0 * (d.total - d.available.min(d.total)) as f32 / d.total as f32)
        .fold(0.0f32, f32::max);
    let mut tx = state.db.begin().await?;
    // Heartbeats are most of what the server writes (one per agent every 30 seconds), and a
    // sample isn't worth an fsync: commit without waiting for the WAL flush. A crash can lose
    // the last fraction of a second of samples, never anything else. At 10,000 agents on a
    // SATA SSD (~150 fsyncs/s) waiting for it held every pooled connection in COMMIT
    // (load test, docs/research/load-test-2026-11.md).
    sqlx::query("SET LOCAL synchronous_commit = off").execute(&mut *tx).await?;
    sqlx::query("UPDATE agents SET last_seen_at = now(), online = true, last_metrics = $2 WHERE id = $1")
        .bind(agent_id)
        .bind(serde_json::to_value(m)?)
        .execute(&mut *tx)
        .await?;
    // Use server time: agent clocks drift, and the PK must not collide on clock jumps.
    sqlx::query(
        "INSERT INTO agent_metrics (agent_id, ts, cpu_percent, mem_used, mem_total, disk_max_pct, net_rx_bytes, net_tx_bytes)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING",
    )
    .bind(agent_id)
    .bind(Utc::now())
    .bind(m.cpu_percent)
    .bind(m.mem_used as i64)
    .bind(m.mem_total as i64)
    .bind(disk_max_pct)
    .bind(m.net_rx_bytes as i64)
    .bind(m.net_tx_bytes as i64)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Also where the server learns the agent's platform on every connect (inventory is requested
/// then): a change of OS or platform can move an automatically placed agent to another
/// category, and so to another policy set.
async fn store_inventory(state: &Arc<AppState>, agent_id: Uuid, inv: &Inventory) -> anyhow::Result<()> {
    let s = &inv.system;
    let (before, after): (Uuid, Uuid) = sqlx::query_as(
        "WITH old AS (SELECT id, policy_set_id FROM agents WHERE id = $1 FOR UPDATE)
         UPDATE agents a SET inventory = $2, inventory_at = now(), hostname = $3, os_family = $4, os_name = $5,
                os_version = $6, kernel_version = $7, arch = $8, platform = $9, last_seen_at = now()
           FROM old WHERE a.id = old.id
          RETURNING old.policy_set_id, a.policy_set_id",
    )
    .bind(agent_id)
    .bind(serde_json::to_value(inv)?)
    .bind(&s.hostname)
    .bind(s.os_family.as_str())
    .bind(&s.os_name)
    .bind(&s.os_version)
    .bind(&s.kernel_version)
    .bind(&s.arch)
    .bind(s.platform.map(|p| p.as_str()))
    .fetch_one(&state.db)
    .await?;
    if before != after {
        info!(%agent_id, from = %before, to = %after, "agent moved to another policy set");
        crate::policy::changed(state, crate::policy::Change::agents(vec![agent_id])).await;
    }
    Ok(())
}
