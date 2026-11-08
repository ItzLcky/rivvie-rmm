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
use crate::paging::{self, Page, PageQuery, Plan, SortKey};
use crate::state::AppState;

/// Fullest disk, in percent, from the last heartbeat (0 if none).
macro_rules! disk_pct {
    () => {
        "coalesce((SELECT max(100 * (1 - (d->>'available')::float8 / (d->>'total')::float8))
                     FROM jsonb_array_elements(a.last_metrics->'disks') d WHERE (d->>'total')::float8 > 0), 0)"
    };
}
/// Jobs on this agent that failed, errored, timed out or were lost in the last 24 hours.
macro_rules! failed_24h {
    () => {
        "(SELECT count(*) FROM jobs fj WHERE fj.agent_id = a.id AND fj.created_at > now() - interval '24 hours'
             AND fj.status IN ('failed', 'error', 'timed_out', 'lost'))"
    };
}
/// Health rank: 0 healthy, 1 unknown (never reported), 2 needs attention, 3 unhealthy.
/// Online/offline is separate: a workstation that is switched off isn't unhealthy.
macro_rules! health_rank {
    () => {
        concat!(
            "(CASE WHEN a.last_metrics IS NULL THEN 1 WHEN ", disk_pct!(), " >= 95 THEN 3 WHEN ", disk_pct!(), " >= 90 OR ",
            failed_24h!(), " > 0 OR (a.update_state IN ('failed', 'rolled_back') AND a.update_at > now() - interval '7 days') ",
            "THEN 2 ELSE 0 END)"
        )
    };
}
macro_rules! health_name {
    () => {
        concat!("(ARRAY['healthy', 'unknown', 'attention', 'unhealthy'])[", health_rank!(), " + 1]")
    };
}

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
    /// healthy / attention / unhealthy / unknown: see `health_rank!`.
    health: String,
    disk_max_pct: f64,
    failed_jobs_24h: i64,
    #[sqlx(default)]
    #[serde(skip)]
    sort_key: String,
}

pub(crate) const SUMMARY_COLS: &str = concat!(
    "a.id, a.hostname, a.os_family, a.os_name, a.os_version, a.arch, a.agent_version, a.online,
       a.last_seen_at, a.enrolled_at, a.site_id, s.name AS site_name, c.id AS client_id, c.name AS client_name, a.last_metrics,
       a.update_state, a.update_version, a.update_detail, a.update_at, ",
    health_name!(),
    " AS health, ",
    disk_pct!(),
    " AS disk_max_pct, ",
    failed_24h!(),
    " AS failed_jobs_24h"
);
const AGENT_FROM: &str = "FROM agents a JOIN sites s ON s.id = a.site_id JOIN clients c ON c.id = s.client_id";

const SORT_KEYS: &[SortKey] = &[
    SortKey { name: "hostname", expr: "lower(a.hostname)", ty: "text" },
    SortKey { name: "client", expr: "lower(c.name || ' / ' || s.name || ' / ' || a.hostname)", ty: "text" },
    SortKey { name: "os", expr: "lower(a.os_family || ' ' || a.os_name)", ty: "text" },
    SortKey { name: "status", expr: "a.online::int", ty: "int" },
    SortKey { name: "health", expr: health_rank!(), ty: "int" },
    SortKey { name: "last_seen", expr: "coalesce(a.last_seen_at, 'epoch'::timestamptz)", ty: "timestamptz" },
    SortKey { name: "enrolled", expr: "a.enrolled_at", ty: "timestamptz" },
    SortKey { name: "cpu", expr: "coalesce((a.last_metrics->>'cpu_percent')::float8, -1)", ty: "float8" },
    SortKey {
        name: "mem",
        expr: "coalesce((a.last_metrics->>'mem_used')::float8 / nullif((a.last_metrics->>'mem_total')::float8, 0), -1)",
        ty: "float8",
    },
    SortKey { name: "disk", expr: disk_pct!(), ty: "float8" },
    SortKey { name: "version", expr: "a.agent_version", ty: "text" },
];

#[derive(Deserialize)]
pub struct ListQuery {
    client_id: Option<Uuid>,
    site_id: Option<Uuid>,
    /// Hostname, OS, IP address or logged-in user.
    q: Option<String>,
    online: Option<bool>,
    os: Option<String>,
    /// Comma-separated health states.
    health: Option<String>,
    /// Enrolled in the last N days.
    new_days: Option<i32>,
}

/// Matches hostname, OS name, an IP address prefix or a logged-in user. `$n` is the search text.
pub(crate) fn agent_search(n: usize) -> String {
    format!(
        "(a.hostname ILIKE '%' || ${n} || '%' OR a.os_name ILIKE '%' || ${n} || '%'
          OR EXISTS (SELECT 1 FROM jsonb_array_elements(coalesce(a.inventory->'network', '[]')) nic,
                            jsonb_array_elements_text(coalesce(nic->'addrs', '[]')) ip
                      WHERE ip LIKE ${n} || '%')
          OR EXISTS (SELECT 1 FROM jsonb_array_elements_text(coalesce(a.inventory->'logged_in_users', '[]')) lu
                      WHERE lu ILIKE ${n} || '%'))"
    )
}

pub async fn list(
    State(st): State<Arc<AppState>>,
    u: User,
    Query(q): Query<ListQuery>,
    Query(page): Query<PageQuery>,
) -> ApiResult<Json<Page<AgentSummary>>> {
    let plan = Plan::new(SORT_KEYS, ("hostname", false), &page, "a.id", "uuid", 9)?;
    let health: Option<Vec<String>> =
        q.health.as_deref().filter(|h| !h.is_empty()).map(|h| h.split(',').map(str::to_string).collect());
    let filters = format!(
        "{AGENT_FROM}
          WHERE ($1::uuid IS NULL OR c.id = $1)
            AND ($2::uuid IS NULL OR s.id = $2)
            AND ($3::text IS NULL OR {search})
            AND ($4::bool IS NULL OR a.online = $4)
            AND ($5::text IS NULL OR a.os_family = $5)
            AND ($6::uuid[] IS NULL OR c.id = ANY($6))
            AND ($7::text[] IS NULL OR {health} = ANY($7))
            AND ($8::int IS NULL OR a.enrolled_at > now() - make_interval(days => $8))",
        search = agent_search(3),
        health = health_name!(),
    );
    let sql = format!("SELECT {SUMMARY_COLS}, {} {filters} {} {} {}", plan.key_select, plan.keyset, plan.order, plan.limit_sql());
    let search = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let os = q.os.as_deref().filter(|s| !s.is_empty());
    macro_rules! bind_filters {
        ($query:expr) => {
            $query.bind(q.client_id).bind(q.site_id).bind(search).bind(q.online).bind(os).bind(u.scope()).bind(&health).bind(q.new_days)
        };
    }
    let mut rows = bind_filters!(sqlx::query_as::<_, AgentSummary>(AssertSqlSafe(sql)));
    if let Some((k, id)) = &plan.cursor {
        rows = rows.bind(k).bind(id);
    }
    let rows = rows.fetch_all(&st.db).await?;
    let total: i64 = bind_filters!(sqlx::query_scalar(AssertSqlSafe(paging::count_sql(&filters)))).fetch_one(&st.db).await?;
    Ok(Json(plan.finish(rows, |r| (r.sort_key.clone(), r.id.to_string()), total)))
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
    let sql = format!("SELECT {SUMMARY_COLS} {AGENT_FROM} WHERE a.id = $1 AND ($2::uuid[] IS NULL OR c.id = ANY($2))");
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
    /// Agents per health state.
    health: serde_json::Value,
    jobs_24h: serde_json::Value,
    /// Most recently gone offline first.
    offline: Vec<AgentSummary>,
    /// Disks at 90% or more, fullest first.
    high_disk: Vec<AgentSummary>,
    failed_jobs: Vec<super::jobs::JobRow>,
    /// One row per client, worst first.
    client_health: Vec<ClientHealth>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct ClientHealth {
    id: Uuid,
    name: String,
    agents: i64,
    online: i64,
    attention: i64,
    unhealthy: i64,
    failed_jobs_24h: i64,
}

#[derive(Deserialize)]
pub struct DashboardQuery {
    /// Narrow to one client (the dashboard's client switcher).
    client_id: Option<Uuid>,
}

/// The user's client scope, narrowed to `client_id` if given. `Some(vec![])` never happens for
/// an inaccessible client: that's a 404 instead.
pub(crate) fn narrow(u: &User, client_id: Option<Uuid>) -> ApiResult<Option<Vec<Uuid>>> {
    match client_id {
        Some(c) => {
            super::access::client(u, c)?;
            Ok(Some(vec![c]))
        }
        None => Ok(u.scope().map(<[Uuid]>::to_vec)),
    }
}

pub async fn dashboard(State(st): State<Arc<AppState>>, u: User, Query(q): Query<DashboardQuery>) -> ApiResult<Json<Dashboard>> {
    // Every figure is limited to the clients the user can see ($1 NULL = all).
    let scope = narrow(&u, q.client_id)?;
    let scope = scope.as_deref();
    let scoped = format!("{AGENT_FROM} WHERE ($1::uuid[] IS NULL OR c.id = ANY($1))");
    let (agents_total, agents_online): (i64, i64) =
        sqlx::query_as(AssertSqlSafe(format!("SELECT count(*), count(*) FILTER (WHERE a.online) {scoped}")))
            .bind(scope)
            .fetch_one(&st.db)
            .await?;
    let clients: i64 = sqlx::query_scalar("SELECT count(*) FROM clients WHERE ($1::uuid[] IS NULL OR id = ANY($1))")
        .bind(scope)
        .fetch_one(&st.db)
        .await?;
    let by_os: serde_json::Value = sqlx::query_scalar(AssertSqlSafe(format!(
        "SELECT coalesce(jsonb_object_agg(os_family, n), '{{}}') FROM (SELECT a.os_family, count(*) n {scoped} GROUP BY 1) t"
    )))
    .bind(scope)
    .fetch_one(&st.db)
    .await?;
    let health: serde_json::Value = sqlx::query_scalar(AssertSqlSafe(format!(
        "SELECT coalesce(jsonb_object_agg(h, n), '{{}}') FROM (SELECT {} AS h, count(*) n {scoped} GROUP BY 1) t",
        health_name!()
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
    let offline = sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {SUMMARY_COLS} {scoped} AND NOT a.online ORDER BY a.last_seen_at DESC NULLS LAST LIMIT 10"
    )))
    .bind(scope)
    .fetch_all(&st.db)
    .await?;
    let high_disk = sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {SUMMARY_COLS} {scoped} AND {disk} >= 90 ORDER BY {disk} DESC, a.hostname LIMIT 10",
        disk = disk_pct!()
    )))
    .bind(scope)
    .fetch_all(&st.db)
    .await?;
    let failed_jobs = super::jobs::recent_failures(&st, scope).await?;
    let client_health = sqlx::query_as(AssertSqlSafe(format!(
        "SELECT c.id, c.name,
                count(a.id) AS agents,
                count(a.id) FILTER (WHERE a.online) AS online,
                count(a.id) FILTER (WHERE {rank} = 2) AS attention,
                count(a.id) FILTER (WHERE {rank} = 3) AS unhealthy,
                coalesce(sum({failed}), 0)::bigint AS failed_jobs_24h
           FROM clients c LEFT JOIN sites s ON s.client_id = c.id LEFT JOIN agents a ON a.site_id = s.id
          WHERE ($1::uuid[] IS NULL OR c.id = ANY($1))
          GROUP BY c.id
          ORDER BY 6 DESC, 5 DESC, count(a.id) - count(a.id) FILTER (WHERE a.online) DESC, lower(c.name)",
        rank = health_rank!(),
        failed = failed_24h!(),
    )))
    .bind(scope)
    .fetch_all(&st.db)
    .await?;
    Ok(Json(Dashboard {
        agents_total,
        agents_online,
        clients,
        by_os,
        health,
        jobs_24h,
        offline,
        high_disk,
        failed_jobs,
        client_health,
    }))
}

/// The audit trail for one agent (deletes, update offers, update results...), newest first.
pub async fn activity(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Vec<super::users::AuditRow>>> {
    super::access::agent(&st, &u, id).await?;
    Ok(Json(
        sqlx::query_as(
            "SELECT l.id, l.ts, u.name AS user_name, l.action, l.target_type, l.target_id, l.details
               FROM audit_log l LEFT JOIN users u ON u.id = l.user_id
              WHERE l.target_type = 'agent' AND l.target_id = $1
              ORDER BY l.ts DESC LIMIT 200",
        )
        .bind(id)
        .fetch_all(&st.db)
        .await?,
    ))
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
