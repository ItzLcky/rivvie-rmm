//! Endpoint protection, server side (Phase 8, milestone 1): storing what agents report about
//! their antivirus, tracking scans and signature updates started from the console, and the
//! protection state shown in the fleet view.
//!
//! A report replaces the agent's products. Detections are kept per (agent, product, the
//! product's id) and follow the product's status; one is open while active and resolved once
//! it's been dealt with or the product stops listing it.

use rmm_proto::ServerMsg;
use rmm_proto::security::{Action, ActionState, ProductKind, Report, ThreatStatus};
use tracing::{info, warn};
use uuid::Uuid;

use crate::hub::Event;
use crate::state::AppState;

/// An action the agent never started (lost on the way) is given up on after this long.
const START_TIMEOUT_MINUTES: i32 = 10;
/// The agent stops a full scan after 24 hours; a result later than this isn't coming.
const RUN_TIMEOUT_HOURS: i32 = 25;

fn publish(st: &AppState, agent_id: Uuid, client_id: Uuid) {
    st.hub.publish(Event::Security { agent_id, client_id });
}

fn clip(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// A freshly authenticated agent: actions it no longer holds can't report any more. (It
/// sends its protection state by itself.)
pub async fn on_connect(st: &AppState, agent_id: Uuid, client_id: Uuid, capabilities: &[String], held: &[Uuid]) -> sqlx::Result<()> {
    if !capabilities.iter().any(|c| c == rmm_proto::security::CAPABILITY) {
        return Ok(());
    }
    sensor_connect(st, agent_id, capabilities).await?;
    let n = sqlx::query(
        "UPDATE security_actions SET status = 'lost', finished_at = now(),
                message = coalesce(message, 'the agent restarted before reporting on it')
          WHERE agent_id = $1 AND status IN ('sent', 'running') AND NOT (id = ANY($2))",
    )
    .bind(agent_id)
    .bind(held)
    .execute(&st.db)
    .await?
    .rows_affected();
    if n > 0 {
        info!(%agent_id, actions = n, "security actions lost");
        publish(st, agent_id, client_id);
    }
    Ok(())
}

/// Stores a report and runs the security alert policies against it.
pub async fn ingest_report(st: &AppState, agent_id: Uuid, client_id: Uuid, report: Report) -> anyhow::Result<()> {
    // Reading the state failed outright (PowerShell timed out, say): that says nothing about
    // the protection, so keep the last known state rather than flap to "no antivirus".
    if report.products.is_empty()
        && let Some(e) = &report.error
    {
        sqlx::query("UPDATE agents SET security_error = $2 WHERE id = $1").bind(agent_id).bind(clip(e, 1000)).execute(&st.db).await?;
        publish(st, agent_id, client_id);
        return Ok(());
    }
    let mut tx = st.db.begin().await?;
    sqlx::query("DELETE FROM security_products WHERE agent_id = $1").bind(agent_id).execute(&mut *tx).await?;
    let mut names = std::collections::HashSet::new();
    for p in report.products.iter().take(20) {
        let name = clip(p.name.trim(), 200);
        // The key is (kind, name); a duplicate from a confused product is dropped.
        if !names.insert((p.kind, name.clone())) {
            continue;
        }
        let actions: Vec<&str> = p.actions.iter().map(|a| a.as_str()).collect();
        sqlx::query(
            "INSERT INTO security_products (agent_id, kind, name, version, enabled, realtime, signature_version, signatures_updated_at,
                                            signatures_current, last_quick_scan_at, last_full_scan_at, tamper_protection, actions, detail)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
        )
        .bind(agent_id)
        .bind(p.kind.as_str())
        .bind(&name)
        .bind(p.version.as_deref().map(|v| clip(v, 100)))
        .bind(p.enabled)
        .bind(p.realtime)
        .bind(p.signature_version.as_deref().map(|v| clip(v, 100)))
        .bind(p.signatures_updated_at)
        .bind(p.signatures_current)
        .bind(p.last_quick_scan)
        .bind(p.last_full_scan)
        .bind(p.tamper_protection)
        .bind(&actions)
        .bind(p.detail.as_deref().map(|d| clip(d, 500)))
        .execute(&mut *tx)
        .await?;
    }

    let mut seen: Vec<Uuid> = Vec::new();
    let mut new: Vec<Uuid> = Vec::new();
    for d in report.detections.iter().take(rmm_proto::security::MAX_DETECTIONS) {
        if d.id.trim().is_empty() {
            continue;
        }
        let resources: Vec<String> = d.resources.iter().take(20).map(|r| clip(r, 1000)).collect();
        let (id, inserted): (Uuid, bool) = sqlx::query_as(
            "INSERT INTO security_detections (id, agent_id, product, external_id, name, severity, status, resources, process, username,
                                              detected_at, resolved_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, CASE WHEN $7 = 'active' THEN NULL ELSE now() END)
             ON CONFLICT (agent_id, product, external_id) DO UPDATE SET
                 name = EXCLUDED.name, severity = EXCLUDED.severity, status = EXCLUDED.status, resources = EXCLUDED.resources,
                 process = EXCLUDED.process, username = EXCLUDED.username, detected_at = EXCLUDED.detected_at, last_seen_at = now(),
                 resolved_at = CASE WHEN EXCLUDED.status = 'active' THEN NULL ELSE coalesce(security_detections.resolved_at, now()) END
             RETURNING id, (xmax = 0)",
        )
        .bind(Uuid::new_v4())
        .bind(agent_id)
        .bind(d.product.as_str())
        .bind(clip(d.id.trim(), 200))
        .bind(clip(&d.name, 300))
        .bind(d.severity.as_str())
        .bind(d.status.as_str())
        .bind(&resources)
        .bind(d.process.as_deref().map(|p| clip(p, 500)))
        .bind(d.user.as_deref().map(|u| clip(u, 200)))
        .bind(d.detected_at.map(|t| t.min(chrono::Utc::now())))
        .fetch_one(&mut *tx)
        .await?;
        seen.push(id);
        if inserted {
            new.push(id);
            if d.status == ThreatStatus::Active {
                info!(%agent_id, threat = %d.name, "active threat reported");
            }
        }
    }
    // Detections the products no longer list are gone from the machine.
    // (The sensor's own detections arrive separately and aren't part of the report.)
    sqlx::query(
        "UPDATE security_detections SET resolved_at = now() WHERE agent_id = $1 AND resolved_at IS NULL AND product <> 'rmm' AND NOT (id = ANY($2))",
    )
        .bind(agent_id)
        .bind(&seen)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE agents SET security_at = now(), security_error = $2 WHERE id = $1")
        .bind(agent_id)
        .bind(report.error.as_deref().map(|e| clip(e, 1000)))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    publish(st, agent_id, client_id);
    crate::alerts::security_reported(st, agent_id, &new).await;
    Ok(())
}

/// An action started or ended. Repeats (resent after a reconnect) change nothing.
pub async fn ingest_action(
    st: &AppState,
    agent_id: Uuid,
    client_id: Uuid,
    request_id: Uuid,
    state: ActionState,
    message: Option<String>,
    data: Option<String>,
) -> anyhow::Result<()> {
    let message = message.map(|m| clip(&m, rmm_proto::security::MESSAGE_MAX));
    let data: Option<serde_json::Value> = data.and_then(|d| serde_json::from_str(&d).ok());
    let changed = match state {
        ActionState::Running => sqlx::query(
            "UPDATE security_actions SET status = 'running', started_at = now() WHERE id = $1 AND agent_id = $2 AND status = 'sent'",
        )
        .bind(request_id)
        .bind(agent_id)
        .execute(&st.db)
        .await?
        .rows_affected()
            > 0,
        ActionState::Succeeded | ActionState::Failed => {
            // `lost` too: the sweep may have given up on an action that then finished.
            let row: Option<(String, String, serde_json::Value)> = sqlx::query_as(
                "UPDATE security_actions SET status = $3, message = $4, result = $5, finished_at = now(), started_at = coalesce(started_at, now())
                  WHERE id = $1 AND agent_id = $2 AND status IN ('sent', 'running', 'lost')
                  RETURNING action, product, params",
            )
            .bind(request_id)
            .bind(agent_id)
            .bind(state.as_str())
            .bind(&message)
            .bind(&data)
            .fetch_optional(&st.db)
            .await?;
            if let Some((action, _, params)) = &row {
                response_done(st, agent_id, request_id, action, params, state, data.as_ref()).await?;
            }
            if let Some((action, product, _)) = &row {
                crate::auth::audit(
                    &st.db,
                    None,
                    &format!("security.{}", state.as_str()),
                    Some(("agent", agent_id)),
                    serde_json::json!({ "action": action, "product": product, "message": message }),
                )
                .await;
            }
            row.is_some()
        }
    };
    if changed {
        publish(st, agent_id, client_id);
    }
    Ok(())
}

pub enum StartError {
    Offline,
    Unsupported(String),
    Busy,
    Db(sqlx::Error),
}

impl From<sqlx::Error> for StartError {
    fn from(e: sqlx::Error) -> Self {
        StartError::Db(e)
    }
}

/// Starts an action on one agent. `product` None picks the first product that can run it.
pub async fn start(
    st: &AppState,
    agent_id: Uuid,
    product: Option<ProductKind>,
    action: Action,
    by: Uuid,
) -> Result<(Uuid, ProductKind), StartError> {
    if !st.hub.is_online(agent_id) {
        return Err(StartError::Offline);
    }
    let capable: bool = sqlx::query_scalar("SELECT $2 = ANY(capabilities) FROM agents WHERE id = $1")
        .bind(agent_id)
        .bind(rmm_proto::security::CAPABILITY)
        .fetch_optional(&st.db)
        .await?
        .unwrap_or(false);
    if !capable {
        return Err(StartError::Unsupported("this agent version can't run antivirus actions; update the agent".into()));
    }
    let kinds: Vec<String> = sqlx::query_scalar(
        "SELECT kind FROM security_products WHERE agent_id = $1 AND $2 = ANY(actions) AND ($3::text IS NULL OR kind = $3) ORDER BY kind",
    )
    .bind(agent_id)
    .bind(action.as_str())
    .bind(product.map(|p| p.as_str()))
    .fetch_all(&st.db)
    .await?;
    let Some(kind) = kinds.first().and_then(|k| ProductKind::parse(k)) else {
        return Err(StartError::Unsupported(format!("no antivirus on this machine can run a {} from here", action.label())));
    };
    let id = Uuid::new_v4();
    // One live action per agent: the agent runs one at a time anyway.
    let inserted = sqlx::query(
        "INSERT INTO security_actions (id, agent_id, product, action, created_by)
         SELECT $1, $2, $3, $4, $5
          WHERE NOT EXISTS (SELECT 1 FROM security_actions WHERE agent_id = $2 AND status IN ('sent', 'running'))",
    )
    .bind(id)
    .bind(agent_id)
    .bind(kind.as_str())
    .bind(action.as_str())
    .bind(by)
    .execute(&st.db)
    .await?
    .rows_affected();
    if inserted == 0 {
        return Err(StartError::Busy);
    }
    if !st.hub.send(agent_id, ServerMsg::SecurityAction { request_id: id, product: kind, action }).await {
        sqlx::query("UPDATE security_actions SET status = 'failed', finished_at = now(), message = 'the agent went offline' WHERE id = $1")
            .bind(id)
            .execute(&st.db)
            .await?;
        return Err(StartError::Offline);
    }
    if let Ok(Some(client_id)) =
        sqlx::query_scalar::<_, Uuid>("SELECT s.client_id FROM agents a JOIN sites s ON s.id = a.site_id WHERE a.id = $1")
            .bind(agent_id)
            .fetch_optional(&st.db)
            .await
    {
        publish(st, agent_id, client_id);
    }
    Ok((id, kind))
}

/// Ask an online agent for its state now.
pub async fn refresh(st: &AppState, agent_id: Uuid) -> Result<(), StartError> {
    let capable: bool = sqlx::query_scalar("SELECT $2 = ANY(capabilities) FROM agents WHERE id = $1")
        .bind(agent_id)
        .bind(rmm_proto::security::CAPABILITY)
        .fetch_optional(&st.db)
        .await?
        .unwrap_or(false);
    if !capable {
        return Err(StartError::Unsupported("this agent version doesn't report its antivirus; update the agent".into()));
    }
    if !st.hub.send(agent_id, ServerMsg::SecurityRefresh).await {
        return Err(StartError::Offline);
    }
    Ok(())
}

/// Housekeeping: actions that will never report.
pub async fn sweep(st: &AppState) -> sqlx::Result<()> {
    let rows: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "UPDATE security_actions sa SET status = 'lost', finished_at = now(),
                message = CASE WHEN sa.status = 'sent' THEN 'the agent never started it' ELSE 'no result from the agent' END
           FROM agents a JOIN sites s ON s.id = a.site_id
          WHERE a.id = sa.agent_id
            AND ((sa.status = 'sent' AND sa.created_at < now() - make_interval(mins => $1))
              OR (sa.status = 'running' AND sa.started_at < now() - make_interval(hours => $2)))
          RETURNING sa.agent_id, s.client_id",
    )
    .bind(START_TIMEOUT_MINUTES)
    .bind(RUN_TIMEOUT_HOURS)
    .fetch_all(&st.db)
    .await?;
    for (agent_id, client_id) in rows {
        warn!(%agent_id, "security action lost");
        publish(st, agent_id, client_id);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Sensor (milestones 2-7): policy, content, detections, response
// ---------------------------------------------------------------------------

use rmm_proto::security::{ResponseAction, SensorDetection, SensorPolicy, SensorStatus};

#[derive(sqlx::FromRow)]
struct PolicyRow {
    sensor_enabled: bool,
    quick_scan_hours: i32,
    full_scan_days: i32,
    auto_quarantine: bool,
    prevention: bool,
    canaries: bool,
    telemetry_mb: i32,
}

/// The policy that applies to the agent (site, else client, else MSP-wide), with the
/// exclusions for its client and the server's rule overrides.
pub async fn sensor_policy(st: &AppState, agent_id: Uuid) -> sqlx::Result<SensorPolicy> {
    let p: Option<PolicyRow> = sqlx::query_as(
        "SELECT p.sensor_enabled, p.quick_scan_hours, p.full_scan_days, p.auto_quarantine, p.prevention, p.canaries, p.telemetry_mb
           FROM security_policies p, agents a JOIN sites s ON s.id = a.site_id
          WHERE a.id = $1 AND (p.site_id = a.site_id OR (p.site_id IS NULL AND p.client_id = s.client_id) OR p.client_id IS NULL)
          ORDER BY (p.site_id IS NOT NULL) DESC, (p.client_id IS NOT NULL) DESC LIMIT 1",
    )
    .bind(agent_id)
    .fetch_optional(&st.db)
    .await?;
    let exclusions: Vec<(String, String)> = sqlx::query_as(
        "SELECT e.kind, e.value FROM security_exclusions e, agents a JOIN sites s ON s.id = a.site_id
          WHERE a.id = $1 AND (e.client_id IS NULL OR e.client_id = s.client_id)",
    )
    .bind(agent_id)
    .fetch_all(&st.db)
    .await?;
    let overrides: Vec<(String, String)> = sqlx::query_as("SELECT rule_id, mode FROM security_rule_overrides").fetch_all(&st.db).await?;
    let p = p.unwrap_or(PolicyRow {
        sensor_enabled: false,
        quick_scan_hours: 24,
        full_scan_days: 7,
        auto_quarantine: true,
        prevention: false,
        canaries: true,
        telemetry_mb: 128,
    });
    Ok(SensorPolicy {
        enabled: p.sensor_enabled,
        quick_scan_hours: p.quick_scan_hours.max(0) as u32,
        full_scan_days: p.full_scan_days.max(0) as u32,
        auto_quarantine: p.auto_quarantine,
        prevention: p.prevention,
        telemetry_mb: p.telemetry_mb.max(16) as u32,
        canaries: p.canaries,
        exclusions: exclusions
            .into_iter()
            .filter_map(|(k, v)| Some(rmm_proto::security::Exclusion { kind: rmm_proto::security::ExclusionKind::parse(&k)?, value: v }))
            .collect(),
        rule_modes: overrides.into_iter().filter_map(|(id, m)| Some((id, rmm_proto::security::RuleMode::parse(&m)?))).collect(),
    })
}

async fn online_sensor_agents(st: &AppState) -> sqlx::Result<Vec<Uuid>> {
    let ids: Vec<Uuid> = sqlx::query_scalar("SELECT a.id FROM agents a WHERE a.online AND 'sensor' = ANY(a.capabilities)").fetch_all(&st.db).await?;
    Ok(ids.into_iter().filter(|id| st.hub.is_online(*id)).collect())
}

/// Re-sends the effective policy to every online agent with a sensor (after a policy,
/// exclusion or rule override changed).
pub async fn push_policies(st: &AppState) {
    let res: sqlx::Result<()> = async {
        for id in online_sensor_agents(st).await? {
            let p = sensor_policy(st, id).await?;
            st.hub.send(id, ServerMsg::SensorPolicy(p)).await;
        }
        Ok(())
    }
    .await;
    if let Err(e) = res {
        warn!("pushing security policies: {e}");
    }
}

/// The content an agent should run: the newest general version, or the newest canary one
/// for canary clients.
pub async fn target_content(st: &AppState, agent_id: Uuid) -> sqlx::Result<Option<(String, Vec<u8>, String)>> {
    sqlx::query_as(
        "SELECT cv.version, cv.bundle, cv.signature
           FROM content_versions cv, agents a JOIN sites s ON s.id = a.site_id JOIN clients c ON c.id = s.client_id
          WHERE a.id = $1 AND (cv.stage = 'general' OR (cv.stage = 'canary' AND c.security_canary))
          ORDER BY cv.uploaded_at DESC LIMIT 1",
    )
    .bind(agent_id)
    .fetch_optional(&st.db)
    .await
}

/// Sends the target content if the agent runs something else (and hasn't already refused it).
async fn sync_content(st: &AppState, agent_id: Uuid, reported: Option<&str>, error: Option<&str>) -> sqlx::Result<()> {
    let Some((version, bundle, signature)) = target_content(st, agent_id).await? else { return Ok(()) };
    if reported == Some(version.as_str()) || error.is_some_and(|e| e.contains(&version)) {
        return Ok(());
    }
    info!(%agent_id, %version, "sending security content");
    st.hub.send(agent_id, ServerMsg::Content { version, bundle, signature }).await;
    Ok(())
}

/// After a rollout change: every online agent gets what it should now run.
pub async fn push_content(st: &AppState) {
    let res: sqlx::Result<()> = async {
        let rows: Vec<(Uuid, Option<String>)> =
            sqlx::query_as("SELECT a.id, a.content_version FROM agents a WHERE a.online AND 'sensor' = ANY(a.capabilities)").fetch_all(&st.db).await?;
        for (id, v) in rows {
            sync_content(st, id, v.as_deref(), None).await?;
        }
        Ok(())
    }
    .await;
    if let Err(e) = res {
        warn!("pushing security content: {e}");
    }
}

/// Sensor-capable agent connected: its policy, and content if it needs it.
pub async fn sensor_connect(st: &AppState, agent_id: Uuid, capabilities: &[String]) -> sqlx::Result<()> {
    if !capabilities.iter().any(|c| c == rmm_proto::security::SENSOR_CAPABILITY) {
        return Ok(());
    }
    st.hub.send(agent_id, ServerMsg::SensorPolicy(sensor_policy(st, agent_id).await?)).await;
    let v: Option<String> = sqlx::query_scalar("SELECT content_version FROM agents WHERE id = $1").bind(agent_id).fetch_one(&st.db).await?;
    sync_content(st, agent_id, v.as_deref(), None).await
}

pub async fn ingest_status(st: &AppState, agent_id: Uuid, client_id: Uuid, s: SensorStatus) -> anyhow::Result<()> {
    sqlx::query("UPDATE agents SET sensor = $2, sensor_at = now(), content_version = $3, isolated = $4 WHERE id = $1")
        .bind(agent_id)
        .bind(serde_json::to_value(&s)?)
        .bind(&s.content_version)
        .bind(s.isolated)
        .execute(&st.db)
        .await?;
    publish(st, agent_id, client_id);
    sync_content(st, agent_id, s.content_version.as_deref(), s.error.as_deref()).await?;
    crate::alerts::security_reported(st, agent_id, &[]).await;
    Ok(())
}

fn external_id(id: &str) -> String {
    if id.len() <= 200 { id.to_string() } else { format!("h:{}", hex::encode(<sha2::Sha256 as sha2::Digest>::digest(id.as_bytes()))) }
}

/// A sensor detection. Stored (or updated), then the agent can forget it.
pub async fn ingest_detection(st: &AppState, agent_id: Uuid, client_id: Uuid, d: &SensorDetection) -> anyhow::Result<()> {
    let ctx = serde_json::to_vec(&d.context.iter().take(60).collect::<Vec<_>>())?;
    let (ctx, encrypted) = crate::crypto::store(st.cfg.data_key.as_ref(), &ctx);
    let resources: Vec<String> = d.resources.iter().take(20).map(|r| clip(r, 1000)).collect();
    let mitre: Vec<String> = d.mitre.iter().take(10).map(|m| clip(m, 20)).collect();
    let source = if d.source == "file" { "file" } else { "behaviour" };
    let (id, inserted): (Uuid, bool) = sqlx::query_as(
        "INSERT INTO security_detections (id, agent_id, product, external_id, name, severity, status, resources, process, username, detected_at,
                                          resolved_at, source, rule_id, mitre, audit, action_taken, sha256, context, context_encrypted,
                                          content_version, quarantine_id)
         VALUES ($1, $2, 'rmm', $3, $4, $5, $6, $7, $8, $9, $10, CASE WHEN $6 = 'active' AND NOT $14 THEN NULL ELSE now() END,
                 $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
         ON CONFLICT (agent_id, product, external_id) DO UPDATE SET
             status = EXCLUDED.status, action_taken = coalesce(EXCLUDED.action_taken, security_detections.action_taken),
             resources = EXCLUDED.resources, last_seen_at = now(), quarantine_id = coalesce(EXCLUDED.quarantine_id, security_detections.quarantine_id),
             resolved_at = CASE WHEN security_detections.verdict IS NOT NULL THEN security_detections.resolved_at
                                WHEN EXCLUDED.status = 'active' AND NOT EXCLUDED.audit THEN NULL
                                ELSE coalesce(security_detections.resolved_at, now()) END
         RETURNING id, (xmax = 0)",
    )
    .bind(Uuid::new_v4())
    .bind(agent_id)
    .bind(external_id(&d.id))
    .bind(clip(&d.name, 300))
    .bind(d.severity.as_str())
    .bind(d.status.as_str())
    .bind(&resources)
    .bind(d.process.as_deref().map(|p| clip(p, 2000)))
    .bind(d.user.as_deref().map(|u| clip(u, 200)))
    .bind(d.detected_at.min(chrono::Utc::now()))
    .bind(source)
    .bind(d.rule_id.as_deref().map(|r| clip(r, 100)))
    .bind(&mitre)
    .bind(d.audit)
    .bind(d.action_taken.as_deref().map(|a| clip(a, 500)))
    .bind(d.sha256.as_deref().map(|h| clip(h, 64)))
    .bind(&ctx)
    .bind(encrypted)
    .bind(d.content_version.as_deref().map(|v| clip(v, 64)))
    .bind(d.quarantine_id)
    .fetch_one(&st.db)
    .await?;
    if inserted {
        info!(%agent_id, rule = d.rule_id.as_deref().unwrap_or(""), name = %d.name, audit = d.audit, "sensor detection");
        if !d.audit {
            crate::alerts::security_reported(st, agent_id, &[id]).await;
        }
    }
    publish(st, agent_id, client_id);
    Ok(())
}

pub async fn ingest_quarantine(st: &AppState, agent_id: Uuid, client_id: Uuid, items: &[rmm_proto::security::QuarantineItem]) -> anyhow::Result<()> {
    let mut tx = st.db.begin().await?;
    let mut ids = Vec::new();
    for i in items.iter().take(5000) {
        ids.push(i.id);
        sqlx::query(
            "INSERT INTO quarantine_items (id, agent_id, path, sha256, size, reason, detection_ref, quarantined_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (id) DO UPDATE SET state = 'quarantined', updated_at = now() WHERE quarantine_items.agent_id = EXCLUDED.agent_id",
        )
        .bind(i.id)
        .bind(agent_id)
        .bind(clip(&i.path, 2000))
        .bind(clip(&i.sha256, 64))
        .bind(i.size as i64)
        .bind(i.reason.as_deref().map(|r| clip(r, 500)))
        .bind(i.detection_id.as_deref().map(external_id))
        .bind(i.quarantined_at.min(chrono::Utc::now()))
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query("UPDATE quarantine_items SET state = 'gone', updated_at = now() WHERE agent_id = $1 AND state = 'quarantined' AND NOT (id = ANY($2))")
        .bind(agent_id)
        .bind(&ids)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    publish(st, agent_id, client_id);
    Ok(())
}

/// A piece of a triage package. Pieces arrive in order on the one socket.
pub async fn ingest_triage_chunk(st: &AppState, agent_id: Uuid, request_id: Uuid, offset: u64, data: Vec<u8>) -> anyhow::Result<()> {
    let ok: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM security_actions WHERE id = $1 AND agent_id = $2 AND action = 'collect_triage' AND status IN ('sent', 'running'))",
    )
    .bind(request_id)
    .bind(agent_id)
    .fetch_one(&st.db)
    .await?;
    if !ok {
        return Ok(());
    }
    let mut t = st.triage.lock().unwrap_or_else(|e| e.into_inner());
    let buf = t.entry(request_id).or_default();
    if offset == 0 {
        buf.clear();
    }
    if buf.len() as u64 != offset || buf.len() as u64 + data.len() as u64 > rmm_proto::security::TRIAGE_MAX {
        warn!(%agent_id, %request_id, "triage package out of order or too large; dropped");
        t.remove(&request_id);
        return Ok(());
    }
    buf.extend_from_slice(&data);
    Ok(())
}

/// Bookkeeping after a response action finished.
async fn response_done(
    st: &AppState,
    agent_id: Uuid,
    request_id: Uuid,
    action: &str,
    params: &serde_json::Value,
    state: ActionState,
    data: Option<&serde_json::Value>,
) -> anyhow::Result<()> {
    let ok = state == ActionState::Succeeded;
    match action {
        "isolate" | "release" if ok => {
            sqlx::query("UPDATE agents SET isolated = $2 WHERE id = $1").bind(agent_id).bind(action == "isolate").execute(&st.db).await?;
        }
        "restore_file" | "delete_quarantined" if ok => {
            if let Some(id) = params.get("id").and_then(|v| v.as_str()).and_then(|s| s.parse::<Uuid>().ok()) {
                sqlx::query("UPDATE quarantine_items SET state = $3, updated_at = now() WHERE id = $1 AND agent_id = $2")
                    .bind(id)
                    .bind(agent_id)
                    .bind(if action == "restore_file" { "restored" } else { "deleted" })
                    .execute(&st.db)
                    .await?;
            }
        }
        "collect_triage" => {
            let pkg = st.triage.lock().unwrap_or_else(|e| e.into_inner()).remove(&request_id);
            if ok {
                let want = data.and_then(|d| d.get("sha256")).and_then(|v| v.as_str()).unwrap_or_default();
                match pkg {
                    Some(p) if hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&p)) == want => {
                        let key = format!("triage/{agent_id}/{request_id}.tar.gz");
                        st.storage.put(&key, p, "application/gzip").await?;
                        sqlx::query("UPDATE security_actions SET storage_key = $2 WHERE id = $1").bind(request_id).bind(&key).execute(&st.db).await?;
                    }
                    _ => {
                        sqlx::query("UPDATE security_actions SET status = 'failed', message = 'the package arrived incomplete' WHERE id = $1")
                            .bind(request_id)
                            .execute(&st.db)
                            .await?;
                    }
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/// Starts a response action on one agent.
pub async fn respond(st: &AppState, agent_id: Uuid, action: ResponseAction, by: Uuid, detection_id: Option<Uuid>) -> Result<Uuid, StartError> {
    if !st.hub.is_online(agent_id) {
        return Err(StartError::Offline);
    }
    let capable: bool = sqlx::query_scalar("SELECT $2 = ANY(capabilities) FROM agents WHERE id = $1")
        .bind(agent_id)
        .bind(rmm_proto::security::SENSOR_CAPABILITY)
        .fetch_optional(&st.db)
        .await?
        .unwrap_or(false);
    if !capable {
        return Err(StartError::Unsupported("this agent version can't run response actions; update the agent".into()));
    }
    let id = Uuid::new_v4();
    let params = serde_json::to_value(&action).unwrap_or_default();
    sqlx::query("INSERT INTO security_actions (id, agent_id, product, action, params, created_by, detection_id) VALUES ($1, $2, 'rmm', $3, $4, $5, $6)")
        .bind(id)
        .bind(agent_id)
        .bind(action.name())
        .bind(&params)
        .bind(by)
        .bind(detection_id)
        .execute(&st.db)
        .await?;
    if !st.hub.send(agent_id, ServerMsg::Response { request_id: id, action }).await {
        sqlx::query("UPDATE security_actions SET status = 'failed', finished_at = now(), message = 'the agent went offline' WHERE id = $1")
            .bind(id)
            .execute(&st.db)
            .await?;
        return Err(StartError::Offline);
    }
    if let Ok(Some(client_id)) =
        sqlx::query_scalar::<_, Uuid>("SELECT s.client_id FROM agents a JOIN sites s ON s.id = a.site_id WHERE a.id = $1").bind(agent_id).fetch_optional(&st.db).await
    {
        publish(st, agent_id, client_id);
    }
    Ok(id)
}

/// Asks one agent's local telemetry store. Waits up to 30 seconds.
pub async fn telemetry_query(st: &AppState, agent_id: Uuid, query: rmm_proto::telemetry::Query) -> Result<crate::hub::QueryResult, String> {
    let request_id = Uuid::new_v4();
    let answer = st.hub.await_query(request_id, agent_id);
    if !st.hub.send(agent_id, ServerMsg::TelemetryQuery { request_id, query }).await {
        st.hub.forget_query(request_id);
        return Err("agent is offline".into());
    }
    let res = tokio::time::timeout(std::time::Duration::from_secs(30), answer).await;
    st.hub.forget_query(request_id);
    match res {
        Ok(Ok(r)) => Ok(r),
        Ok(Err(_)) => Err("the agent disconnected before answering".into()),
        Err(_) => Err("no answer from the agent within 30 seconds".into()),
    }
}

// ---------------------------------------------------------------------------
// Content: upload and staged rollout
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct SignatureFile {
    pub version: String,
    pub sha256: String,
    pub signature: String,
}

/// Rule summary kept with each version: what the rules view shows, and a digest to tell
/// which rules a new version changed.
fn rules_summary(b: &rmm_content::Bundle) -> serde_json::Value {
    let digest = |v: &serde_json::Value| hex::encode(<sha2::Sha256 as sha2::Digest>::digest(v.to_string().as_bytes()))[..16].to_string();
    let mut out = Vec::new();
    for r in &b.behaviour_rules {
        let v = serde_json::to_value(r).unwrap_or_default();
        out.push(serde_json::json!({ "id": r.id, "name": r.name, "description": r.description, "kind": "behaviour", "event": r.event,
            "severity": r.severity, "confidence": r.confidence, "mode": r.mode, "mitre": r.mitre, "digest": digest(&v) }));
    }
    for r in &b.file_rules {
        let v = serde_json::to_value(r).unwrap_or_default();
        out.push(serde_json::json!({ "id": r.id, "name": r.name, "description": "", "kind": "file", "event": null,
            "severity": r.severity, "confidence": r.confidence, "mode": r.mode, "mitre": r.mitre, "digest": digest(&v) }));
    }
    serde_json::Value::Array(out)
}

/// Checks and stores a signed bundle as a canary version.
pub async fn upload_content(st: &AppState, json: Vec<u8>, sig: SignatureFile, by: Uuid) -> Result<(Uuid, String), String> {
    let b = rmm_content::Bundle::parse(&json).map_err(|e| e.to_string())?;
    let sha = rmm_content::Bundle::sha256(&json);
    if !sig.sha256.eq_ignore_ascii_case(&sha) {
        return Err("the signature file is for a different bundle (sha256 differs)".into());
    }
    if sig.version != b.version {
        return Err(format!("the signature is for version {}, the bundle says {}", sig.version, b.version));
    }
    if let Some(pk) = &st.cfg.content_pubkey {
        rmm_content::verify(&json, &b.version, &sig.signature, pk).map_err(|e| e.to_string())?;
    } else if hex::decode(sig.signature.trim()).map(|s| s.len()).unwrap_or(0) != 64 {
        return Err("malformed signature".into());
    }
    let report = rmm_content::test::run(&b, &rmm_content::test::benign_corpus());
    if !report.ok() {
        return Err(format!("the bundle's tests fail: {}", report.summary()));
    }
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO content_versions (id, version, sha256, signature, bundle, description, rules, hashes, uploaded_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(id)
    .bind(&b.version)
    .bind(&sha)
    .bind(sig.signature.trim())
    .bind(&json)
    .bind(clip(&b.description, 2000))
    .bind(rules_summary(&b))
    .bind(b.hashes.len() as i32)
    .bind(by)
    .execute(&st.db)
    .await
    .map_err(|e| if matches!(&e, sqlx::Error::Database(d) if d.is_unique_violation()) { format!("version {} was already uploaded", b.version) } else { e.to_string() })?;
    push_content(st).await;
    Ok((id, b.version))
}

/// Moves a version to `general` (retiring the previous general) or `rolled_back`.
pub async fn set_stage(st: &AppState, id: Uuid, stage: &str, reason: &str, by: Option<Uuid>) -> sqlx::Result<bool> {
    let mut tx = st.db.begin().await?;
    if stage == "general" {
        sqlx::query("UPDATE content_versions SET stage = 'retired', stage_changed_at = now() WHERE stage = 'general' AND id <> $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    let n = sqlx::query("UPDATE content_versions SET stage = $2, stage_reason = $3, stage_changed_at = now() WHERE id = $1 AND stage <> $2")
        .bind(id)
        .bind(stage)
        .bind(reason)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    tx.commit().await?;
    if n > 0 {
        let version: String = sqlx::query_scalar("SELECT version FROM content_versions WHERE id = $1").bind(id).fetch_one(&st.db).await?;
        info!(%version, stage, reason, "security content stage changed");
        crate::auth::audit(&st.db, by, &format!("security.content_{stage}"), None, serde_json::json!({ "version": version, "reason": reason })).await;
        push_content(st).await;
    }
    Ok(n > 0)
}

#[derive(Debug, PartialEq, Eq)]
pub enum Rollout {
    Wait,
    Promote,
    Rollback(String),
}

/// The canary verdict for one version. `on` canary agents run it; `crashed` of them have a
/// sensor that's down or restarting; `fp_agents` saw rules this version added or changed
/// fire; `fp_verdicts` such detections were marked false positives.
pub fn decide(on: i64, crashed: i64, fp_agents: i64, fp_verdicts: i64, soaked: bool) -> Rollout {
    if crashed > 0 && crashed * 5 >= on.max(1) {
        return Rollout::Rollback(format!("the sensor crashed or stopped on {crashed} of {on} canary agents"));
    }
    if fp_verdicts > 0 {
        return Rollout::Rollback(format!("{fp_verdicts} detections from new or changed rules were marked false positives"));
    }
    if fp_agents >= 3 && fp_agents * 10 >= on {
        return Rollout::Rollback(format!("new or changed rules fired on {fp_agents} of {on} canary agents"));
    }
    if soaked { Rollout::Promote } else { Rollout::Wait }
}

pub async fn rollout_tick(st: &AppState) -> sqlx::Result<()> {
    let canaries: Vec<(Uuid, String, serde_json::Value, chrono::DateTime<chrono::Utc>)> =
        sqlx::query_as("SELECT id, version, rules, stage_changed_at FROM content_versions WHERE stage = 'canary' ORDER BY uploaded_at").fetch_all(&st.db).await?;
    for (id, version, rules, since) in canaries {
        let general: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT rules FROM content_versions WHERE stage = 'general' ORDER BY uploaded_at DESC LIMIT 1").fetch_optional(&st.db).await?;
        let old: std::collections::HashSet<String> =
            general.iter().flat_map(|g| g.as_array().cloned().unwrap_or_default()).filter_map(|r| r.get("digest").and_then(|d| d.as_str()).map(str::to_string)).collect();
        let changed: Vec<String> = rules
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|r| r.get("digest").and_then(|d| d.as_str()).is_none_or(|d| !old.contains(d)))
            .filter_map(|r| r.get("id").and_then(|i| i.as_str()).map(str::to_string))
            .collect();
        let (on, crashed): (i64, i64) = sqlx::query_as(
            "SELECT count(*), count(*) FILTER (WHERE coalesce((a.sensor->>'enabled')::bool, false)
                                                 AND (NOT coalesce((a.sensor->>'running')::bool, false) OR coalesce((a.sensor->>'restarts')::int, 0) >= 3))
               FROM agents a JOIN sites s ON s.id = a.site_id JOIN clients c ON c.id = s.client_id
              WHERE c.security_canary AND a.content_version = $1",
        )
        .bind(&version)
        .fetch_one(&st.db)
        .await?;
        let (fp_agents, fp_verdicts): (i64, i64) = sqlx::query_as(
            "SELECT count(DISTINCT d.agent_id), count(*) FILTER (WHERE d.verdict = 'false_positive')
               FROM security_detections d
              WHERE d.content_version = $1 AND d.rule_id = ANY($2) AND d.first_seen_at >= $3",
        )
        .bind(&version)
        .bind(&changed)
        .bind(since)
        .fetch_one(&st.db)
        .await?;
        let soaked = chrono::Utc::now() - since >= chrono::Duration::minutes(st.cfg.content_soak_minutes.into());
        match decide(on, crashed, fp_agents, fp_verdicts, soaked) {
            Rollout::Wait => {}
            Rollout::Promote => {
                let why = if on == 0 { "soak time passed (no canary agents ran it)".to_string() } else { format!("{on} canary agents ran it without problems") };
                set_stage(st, id, "general", &why, None).await?;
            }
            Rollout::Rollback(why) => {
                warn!(%version, "rolling back security content: {why}");
                set_stage(st, id, "rolled_back", &why, None).await?;
            }
        }
    }
    Ok(())
}

pub async fn rollout_loop(st: std::sync::Arc<AppState>) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(st.cfg.alert_eval_secs.max(5).into()));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        if let Err(e) = rollout_tick(&st).await {
            warn!("security content rollout: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rollout_decisions() {
        assert_eq!(decide(10, 0, 0, 0, false), Rollout::Wait);
        assert_eq!(decide(10, 0, 0, 0, true), Rollout::Promote);
        assert_eq!(decide(0, 0, 0, 0, true), Rollout::Promote, "no canary agents: soak time alone");
        assert!(matches!(decide(10, 2, 0, 0, false), Rollout::Rollback(r) if r.contains("crashed")));
        assert_eq!(decide(10, 1, 0, 0, true), Rollout::Promote, "one restart in ten isn't a pattern");
        assert!(matches!(decide(10, 0, 0, 1, false), Rollout::Rollback(r) if r.contains("false positives")));
        assert!(matches!(decide(20, 0, 3, 0, false), Rollout::Rollback(_)));
        assert_eq!(decide(100, 0, 3, 0, true), Rollout::Promote, "3 of 100 is an outbreak, not a bad rule");
    }
}
