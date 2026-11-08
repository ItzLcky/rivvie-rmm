use std::sync::Arc;

use sqlx::AssertSqlSafe;
use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, Duration, Utc};
use rmm_proto::ServerMsg;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::auth::{self, Role, User};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

#[derive(Serialize, sqlx::FromRow)]
pub struct AgentSummary {
    id: Uuid,
    hostname: String,
    os_family: String,
    os_name: String,
    os_version: String,
    arch: String,
    agent_version: String,
    online: bool,
    last_seen_at: Option<DateTime<Utc>>,
    enrolled_at: DateTime<Utc>,
    site_id: Uuid,
    site_name: String,
    client_id: Uuid,
    client_name: String,
    last_metrics: Option<serde_json::Value>,
    /// Self-update progress: offered / downloading / waiting / applying / completed / rolled_back / failed.
    update_state: Option<String>,
    update_version: Option<String>,
    update_detail: Option<String>,
    update_at: Option<DateTime<Utc>>,
}

const SUMMARY_COLS: &str = "a.id, a.hostname, a.os_family, a.os_name, a.os_version, a.arch, a.agent_version, a.online,
       a.last_seen_at, a.enrolled_at, a.site_id, s.name AS site_name, c.id AS client_id, c.name AS client_name, a.last_metrics,
       a.update_state, a.update_version, a.update_detail, a.update_at";

#[derive(Deserialize)]
pub struct ListQuery {
    client_id: Option<Uuid>,
    site_id: Option<Uuid>,
    q: Option<String>,
    online: Option<bool>,
    os: Option<String>,
}

pub async fn list(State(st): State<Arc<AppState>>, u: User, Query(q): Query<ListQuery>) -> ApiResult<Json<Vec<AgentSummary>>> {
    let sql = format!(
        "SELECT {SUMMARY_COLS}
           FROM agents a JOIN sites s ON s.id = a.site_id JOIN clients c ON c.id = s.client_id
          WHERE ($1::uuid IS NULL OR c.id = $1)
            AND ($2::uuid IS NULL OR s.id = $2)
            AND ($3::text IS NULL OR a.hostname ILIKE '%' || $3 || '%')
            AND ($4::bool IS NULL OR a.online = $4)
            AND ($5::text IS NULL OR a.os_family = $5)
            AND ($6::uuid[] IS NULL OR c.id = ANY($6))
          ORDER BY c.name, a.hostname"
    );
    Ok(Json(
        sqlx::query_as(AssertSqlSafe(sql))
            .bind(q.client_id)
            .bind(q.site_id)
            .bind(q.q.filter(|s| !s.is_empty()))
            .bind(q.online)
            .bind(q.os.filter(|s| !s.is_empty()))
            .bind(u.scope())
            .fetch_all(&st.db)
            .await?,
    ))
}

#[derive(Serialize)]
pub struct AgentDetail {
    #[serde(flatten)]
    summary: AgentSummary,
    kernel_version: String,
    machine_id: Option<String>,
    inventory: Option<serde_json::Value>,
    inventory_at: Option<DateTime<Utc>>,
}

pub async fn get(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<AgentDetail>> {
    let sql = format!(
        "SELECT {SUMMARY_COLS}
           FROM agents a JOIN sites s ON s.id = a.site_id JOIN clients c ON c.id = s.client_id
          WHERE a.id = $1 AND ($2::uuid[] IS NULL OR c.id = ANY($2))"
    );
    let summary: AgentSummary = sqlx::query_as(AssertSqlSafe(sql))
        .bind(id)
        .bind(u.scope())
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("agent"))?;
    let (kernel_version, machine_id, inventory, inventory_at): (String, Option<String>, Option<serde_json::Value>, Option<DateTime<Utc>>) =
        sqlx::query_as("SELECT kernel_version, machine_id, inventory, inventory_at FROM agents WHERE id = $1")
            .bind(id)
            .fetch_one(&st.db)
            .await?;
    Ok(Json(AgentDetail { summary, kernel_version, machine_id, inventory, inventory_at }))
}

pub async fn remove(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<serde_json::Value>> {
    u.require(Role::Admin)?;
    super::access::agent(&st, &u, id).await?;
    let n = sqlx::query("DELETE FROM agents WHERE id = $1").bind(id).execute(&st.db).await?.rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound("agent"));
    }
    // Its credential is gone, so reconnects are rejected; drop the live socket too.
    st.hub.kick(id);
    auth::audit(&st.db, Some(u.id), "agent.delete", Some(("agent", id)), json!({})).await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct MetricsQuery {
    hours: Option<i64>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct MetricPoint {
    ts: DateTime<Utc>,
    cpu_percent: f32,
    mem_used: i64,
    mem_total: i64,
    disk_max_pct: f32,
    net_rx_bytes: i64,
    net_tx_bytes: i64,
}

pub async fn metrics(
    State(st): State<Arc<AppState>>,
    u: User,
    Path(id): Path<Uuid>,
    Query(q): Query<MetricsQuery>,
) -> ApiResult<Json<Vec<MetricPoint>>> {
    super::access::agent(&st, &u, id).await?;
    let hours = q.hours.unwrap_or(24).clamp(1, 24 * 30);
    // Bucket so a 30-day chart is ~500 points regardless of heartbeat rate.
    let bucket_secs = ((hours * 3600) / 500).max(60);
    Ok(Json(
        sqlx::query_as(
            "SELECT to_timestamp(floor(extract(epoch FROM ts) / $3) * $3) AS ts,
                    avg(cpu_percent)::real AS cpu_percent,
                    avg(mem_used)::bigint AS mem_used,
                    max(mem_total) AS mem_total,
                    max(disk_max_pct) AS disk_max_pct,
                    max(net_rx_bytes) AS net_rx_bytes,
                    max(net_tx_bytes) AS net_tx_bytes
               FROM agent_metrics
              WHERE agent_id = $1 AND ts > $2
              GROUP BY 1 ORDER BY 1",
        )
        .bind(id)
        .bind(Utc::now() - Duration::hours(hours))
        .bind(bucket_secs as f64)
        .fetch_all(&st.db)
        .await?,
    ))
}

pub async fn refresh_inventory(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<serde_json::Value>> {
    u.require(Role::Technician)?;
    super::access::agent(&st, &u, id).await?;
    let sent = st.hub.send(id, ServerMsg::RequestInventory).await;
    if !sent {
        return Err(ApiError::Conflict("agent is offline".into()));
    }
    Ok(Json(json!({ "ok": true })))
}

#[derive(Serialize)]
pub struct Dashboard {
    agents_total: i64,
    agents_online: i64,
    clients: i64,
    by_os: serde_json::Value,
    jobs_24h: serde_json::Value,
    high_disk: Vec<AgentSummary>,
}

pub async fn dashboard(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Dashboard>> {
    // Every figure is limited to the clients the user can see ($1 NULL = all).
    const SCOPED_AGENTS: &str = "agents a JOIN sites s ON s.id = a.site_id WHERE ($1::uuid[] IS NULL OR s.client_id = ANY($1))";
    let scope = u.scope();
    let (agents_total, agents_online): (i64, i64) =
        sqlx::query_as(AssertSqlSafe(format!("SELECT count(*), count(*) FILTER (WHERE a.online) FROM {SCOPED_AGENTS}")))
            .bind(scope)
            .fetch_one(&st.db)
            .await?;
    let clients: i64 = sqlx::query_scalar("SELECT count(*) FROM clients WHERE ($1::uuid[] IS NULL OR id = ANY($1))")
        .bind(scope)
        .fetch_one(&st.db)
        .await?;
    let by_os: serde_json::Value = sqlx::query_scalar(AssertSqlSafe(format!(
        "SELECT coalesce(jsonb_object_agg(os_family, n), '{{}}') FROM (SELECT a.os_family, count(*) n FROM {SCOPED_AGENTS} GROUP BY 1) t"
    )))
    .bind(scope)
    .fetch_one(&st.db)
    .await?;
    let jobs_24h: serde_json::Value = sqlx::query_scalar(
        "SELECT coalesce(jsonb_object_agg(status, n), '{}')
           FROM (SELECT j.status, count(*) n
                   FROM jobs j JOIN agents a ON a.id = j.agent_id JOIN sites s ON s.id = a.site_id
                  WHERE ($1::uuid[] IS NULL OR s.client_id = ANY($1)) AND j.created_at > now() - interval '24 hours'
                  GROUP BY 1) t",
    )
    .bind(scope)
    .fetch_one(&st.db)
    .await?;
    let sql = format!(
        "SELECT {SUMMARY_COLS}
           FROM agents a JOIN sites s ON s.id = a.site_id JOIN clients c ON c.id = s.client_id
          WHERE ($1::uuid[] IS NULL OR c.id = ANY($1))
            AND EXISTS (
                SELECT 1 FROM jsonb_array_elements(a.last_metrics->'disks') d
                 WHERE (d->>'total')::numeric > 0
                   AND 1 - (d->>'available')::numeric / (d->>'total')::numeric > 0.9)
          ORDER BY a.hostname LIMIT 20"
    );
    let high_disk = sqlx::query_as(AssertSqlSafe(sql)).bind(scope).fetch_all(&st.db).await?;
    Ok(Json(Dashboard { agents_total, agents_online, clients, by_os, jobs_24h, high_disk }))
}

/// Offer the newest signed release to one agent (admins: it replaces the agent binary).
pub async fn update(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<serde_json::Value>> {
    u.require(Role::Admin)?;
    super::access::agent(&st, &u, id).await?;
    let version = crate::updates::offer(&st, id).await.map_err(ApiError::Conflict)?;
    auth::audit(&st.db, Some(u.id), "agent.update_offer", Some(("agent", id)), json!({ "version": version })).await;
    Ok(Json(json!({ "ok": true, "version": version })))
}

#[derive(Serialize)]
pub struct ReleaseInfo {
    platform: String,
    version: String,
    sha256: String,
    size: usize,
    /// Agents on this platform running something older.
    outdated: i64,
}

/// Signed releases this server can push, with how many visible agents are behind.
pub async fn releases(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<serde_json::Value>> {
    let mut out = Vec::new();
    for platform in super::agent_platforms() {
        let Some(r) = st.releases.get(&st, platform) else { continue };
        let versions: Vec<String> = sqlx::query_scalar(
            "SELECT a.agent_version FROM agents a JOIN sites s ON s.id = a.site_id
              WHERE a.os_family || '-' || a.arch = $1 AND ($2::uuid[] IS NULL OR s.client_id = ANY($2))",
        )
        .bind(platform)
        .bind(u.scope())
        .fetch_all(&st.db)
        .await?;
        let outdated = versions.iter().filter(|v| rmm_proto::update::is_newer(&r.manifest.version, v)).count() as i64;
        out.push(ReleaseInfo {
            platform: platform.to_string(),
            version: r.manifest.version.clone(),
            sha256: r.manifest.sha256.clone(),
            size: r.bytes.len(),
            outdated,
        });
    }
    Ok(Json(json!({ "releases": out, "auto_update": st.company().auto_update_agents })))
}

#[derive(Deserialize)]
pub struct Rollout {
    /// Omitted: every online agent the user can see.
    agent_ids: Option<Vec<Uuid>>,
}

/// Offer updates to many agents at once. Agents already current are skipped.
pub async fn rollout(State(st): State<Arc<AppState>>, u: User, Json(b): Json<Rollout>) -> ApiResult<Json<serde_json::Value>> {
    u.require(Role::Admin)?;
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT a.id FROM agents a JOIN sites s ON s.id = a.site_id
          WHERE a.online AND ($1::uuid[] IS NULL OR a.id = ANY($1)) AND ($2::uuid[] IS NULL OR s.client_id = ANY($2))",
    )
    .bind(b.agent_ids.as_deref())
    .bind(u.scope())
    .fetch_all(&st.db)
    .await?;
    let mut offered = 0;
    for id in &ids {
        if crate::updates::offer(&st, *id).await.is_ok() {
            offered += 1;
        }
    }
    auth::audit(&st.db, Some(u.id), "agent.update_rollout", None, json!({ "offered": offered, "considered": ids.len() })).await;
    Ok(Json(json!({ "offered": offered, "skipped": ids.len() - offered })))
}
