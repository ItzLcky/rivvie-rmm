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

// Health is stored on the agent (migration 0026): the inputs (open alerts, failed jobs, overdue
// and failed patches, the fullest disk), and the rank worked out from them, are kept current
// by triggers and a periodic reconcile (`refresh_health`), so listing agents and the dashboard
// only read columns. The rules themselves are the SQL function `agent_health_rank`:
// 0 healthy, 1 unknown (never reported), 2 needs attention, 3 unhealthy.
// Online/offline is separate: a workstation that is switched off isn't unhealthy (unless an
// offline alert policy says so). Open critical alerts make an agent unhealthy, warnings make it
// need attention.
macro_rules! health_name {
    () => {
        "(ARRAY['healthy', 'unknown', 'attention', 'unhealthy'])[a.health_rank + 1]"
    };
}

/// Works the stored health of every agent out again from the tables (alerts, jobs, patches) and
/// the clock. Triggers keep it current as those change; this catches what time alone changes (a
/// failed job passing 24 hours, a reboot pending for a day) and is a safety net for anything
/// the triggers missed. Cheap when nothing changed: only differing rows are written.
pub async fn refresh_health(db: &sqlx::PgPool) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT refresh_agent_health()").execute(db).await?;
    Ok(())
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
    /// healthy / attention / unhealthy / unknown: see `agent_health_rank` (migration 0026).
    health: String,
    disk_max_pct: f64,
    failed_jobs_24h: i64,
    /// Unresolved alerts.
    open_alerts: i64,
    /// Security or critical updates missing for more than a week, not declined.
    patches_overdue: i64,
    patches_failed: i64,
    reboot_pending: bool,
    reboot_pending_since: Option<DateTime<Utc>>,
    /// Alerts are held back right now (maintenance window or snooze).
    alerts_muted: bool,
    /// workstation / server.
    platform: String,
    category_id: Uuid,
    category_name: String,
    /// The policy set it uses (see `/agents/{id}/policy` for why).
    policy_set_id: Uuid,
    policy_set_name: String,
    /// `[{id, name, color}]`, by name.
    tags: serde_json::Value,
    /// Disk encryption of its fixed volumes: `encrypted` (all), `partial`, `none`; None until it reports.
    encryption: Option<String>,
    #[sqlx(default)]
    #[serde(skip)]
    sort_key: String,
}

pub(crate) const SUMMARY_COLS: &str = concat!(
    "a.id, a.hostname, a.os_family, a.os_name, a.os_version, a.arch, a.agent_version, a.online,
       a.last_seen_at, a.enrolled_at, a.site_id, s.name AS site_name, c.id AS client_id, c.name AS client_name, a.last_metrics,
       a.update_state, a.update_version, a.update_detail, a.update_at, ",
    health_name!(),
    " AS health, a.disk_max_pct, a.failed_jobs_24h::bigint AS failed_jobs_24h, a.open_alerts::bigint AS open_alerts,
       a.patches_overdue::bigint AS patches_overdue, a.patches_failed::bigint AS patches_failed, a.reboot_pending, a.reboot_pending_since, agent_muted(a.id, now()) AS alerts_muted, a.platform, a.category_id,
       (SELECT dc.name FROM device_categories dc WHERE dc.id = a.category_id) AS category_name, a.policy_set_id,
       (SELECT ps.name FROM policy_sets ps WHERE ps.id = a.policy_set_id) AS policy_set_name,
       coalesce((SELECT jsonb_agg(jsonb_build_object('id', t.id, 'name', t.name, 'color', t.color) ORDER BY lower(t.name))
                   FROM agent_tags atg JOIN tags t ON t.id = atg.tag_id WHERE atg.agent_id = a.id), '[]'::jsonb) AS tags,
       a.diskenc_status AS encryption"
);
const AGENT_FROM: &str = "FROM agents a JOIN sites s ON s.id = a.site_id JOIN clients c ON c.id = s.client_id";

const SORT_KEYS: &[SortKey] = &[
    SortKey { name: "hostname", expr: "lower(a.hostname)", ty: "text" },
    SortKey { name: "client", expr: "lower(c.name || ' / ' || s.name || ' / ' || a.hostname)", ty: "text" },
    SortKey { name: "os", expr: "lower(a.os_family || ' ' || a.os_name)", ty: "text" },
    SortKey { name: "status", expr: "a.online::int", ty: "int" },
    SortKey { name: "health", expr: "a.health_rank::int", ty: "int" },
    SortKey { name: "last_seen", expr: "coalesce(a.last_seen_at, 'epoch'::timestamptz)", ty: "timestamptz" },
    SortKey { name: "enrolled", expr: "a.enrolled_at", ty: "timestamptz" },
    SortKey { name: "cpu", expr: "coalesce((a.last_metrics->>'cpu_percent')::float8, -1)", ty: "float8" },
    SortKey {
        name: "mem",
        expr: "coalesce((a.last_metrics->>'mem_used')::float8 / nullif((a.last_metrics->>'mem_total')::float8, 0), -1)",
        ty: "float8",
    },
    SortKey { name: "disk", expr: "a.disk_max_pct", ty: "float8" },
    SortKey { name: "version", expr: "a.agent_version", ty: "text" },
    SortKey { name: "category", expr: "(SELECT lower(dc.name) FROM device_categories dc WHERE dc.id = a.category_id)", ty: "text" },
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
    category_id: Option<Uuid>,
    policy_set_id: Option<Uuid>,
    /// Comma-separated tag ids: agents that have all of them.
    tag: Option<String>,
    /// A custom field of agents (its id): agents with a value for it...
    cf: Option<Uuid>,
    /// ...and, with `cf`, that value: matched exactly, or as a case-insensitive substring for text fields.
    cfv: Option<String>,
    /// Comma-separated disk encryption summaries: `encrypted`, `partial`, `none`, `unknown` (never reported).
    encryption: Option<String>,
}

/// Matches hostname, OS name, an IP address prefix or a logged-in user. `$n` is the search text.
/// Each part is an index lookup (trigram indexes on the hostname, the OS name and the stored
/// addresses and users in `agent_search_terms`, migration 0026), not a scan of the fleet's
/// inventories.
pub(crate) fn agent_search(n: usize) -> String {
    format!(
        "a.id IN (SELECT m.id FROM agents m WHERE m.hostname ILIKE '%' || ${n} || '%'
                  UNION SELECT m.id FROM agents m WHERE m.os_name ILIKE '%' || ${n} || '%'
                  UNION SELECT t.agent_id FROM agent_search_terms t WHERE t.kind = 'ip' AND t.term LIKE ${n} || '%'
                  UNION SELECT t.agent_id FROM agent_search_terms t WHERE t.kind = 'user' AND t.term ILIKE ${n} || '%')"
    )
}

pub async fn list(
    State(st): State<Arc<AppState>>,
    u: User,
    Query(q): Query<ListQuery>,
    Query(page): Query<PageQuery>,
) -> ApiResult<Json<Page<AgentSummary>>> {
    let plan = Plan::new(SORT_KEYS, ("hostname", false), &page, "a.id", "uuid", 15)?;
    let tags = super::tags::parse_filter(q.tag.as_deref())?;
    let cf = super::fields::filter(&st, &u, q.cf, q.cfv.as_deref()).await?;
    let health: Option<Vec<String>> =
        q.health.as_deref().filter(|h| !h.is_empty()).map(|h| h.split(',').map(str::to_string).collect());
    let encryption: Option<Vec<String>> = q.encryption.as_deref().filter(|h| !h.is_empty()).map(|h| h.split(',').map(|s| s.trim().to_string()).collect());
    if let Some(bad) = encryption.iter().flatten().find(|e| !["encrypted", "partial", "none", "unknown"].contains(&e.as_str())) {
        return Err(ApiError::BadRequest(format!("unknown encryption state {bad}: encrypted, partial, none or unknown")));
    }
    let filters = format!(
        "{AGENT_FROM}
          WHERE ($1::uuid IS NULL OR c.id = $1)
            AND ($2::uuid IS NULL OR s.id = $2)
            AND ($3::text IS NULL OR {search})
            AND ($4::bool IS NULL OR a.online = $4)
            AND ($5::text IS NULL OR a.os_family = $5)
            AND ($6::uuid[] IS NULL OR c.id = ANY($6))
            AND ($7::text[] IS NULL OR {health} = ANY($7))
            AND ($8::int IS NULL OR a.enrolled_at > now() - make_interval(days => $8))
            AND ($9::uuid IS NULL OR a.category_id = $9)
            AND ($10::uuid IS NULL OR a.policy_set_id = $10)
            AND ($11::uuid[] IS NULL OR (SELECT count(*) FROM agent_tags x WHERE x.agent_id = a.id AND x.tag_id = ANY($11)) = cardinality($11))
            AND ($12::uuid IS NULL OR EXISTS (SELECT 1 FROM custom_field_values v WHERE v.field_id = $12 AND v.agent_id = a.id
                   AND ($13::jsonb IS NULL OR v.value = $13)
                   AND ($14::text IS NULL OR strpos(lower(v.value #>> '{{}}'), lower($14)) > 0)))
            AND ($15::text[] IS NULL OR coalesce(a.diskenc_status, 'unknown') = ANY($15))",
        search = agent_search(3),
        health = health_name!(),
    );
    let sql = format!("SELECT {SUMMARY_COLS}, {} {filters} {} {} {}", plan.key_select, plan.keyset, plan.order, plan.limit_sql());
    let search = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let os = q.os.as_deref().filter(|s| !s.is_empty());
    macro_rules! bind_filters {
        ($query:expr) => {
            $query.bind(q.client_id).bind(q.site_id).bind(search).bind(q.online).bind(os).bind(u.scope()).bind(&health).bind(q.new_days).bind(q.category_id).bind(q.policy_set_id).bind(&tags).bind(cf.field).bind(&cf.exact).bind(&cf.contains).bind(&encryption)
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
    /// Optional features its build supports, as of its last connection (`patch`, `desktop`).
    capabilities: Vec<String>,
    /// The pinned note, shown in the header.
    pinned_note: Option<super::notes::Note>,
}

pub async fn get(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<AgentDetail>> {
    let sql = format!("SELECT {SUMMARY_COLS} {AGENT_FROM} WHERE a.id = $1 AND ($2::uuid[] IS NULL OR c.id = ANY($2))");
    let summary: AgentSummary = sqlx::query_as(AssertSqlSafe(sql))
        .bind(id)
        .bind(u.scope())
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("agent"))?;
    #[allow(clippy::type_complexity)]
    let (kernel_version, machine_id, inventory, inventory_at, capabilities): (
        String,
        Option<String>,
        Option<serde_json::Value>,
        Option<DateTime<Utc>>,
        Vec<String>,
    ) = sqlx::query_as("SELECT kernel_version, machine_id, inventory, inventory_at, capabilities FROM agents WHERE id = $1")
        .bind(id)
        .fetch_one(&st.db)
        .await?;
    let pinned_note = super::notes::pinned(&st, &u, id).await?;
    Ok(Json(AgentDetail { summary, kernel_version, machine_id, inventory, inventory_at, capabilities, pinned_note }))
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
    let hours = q.hours.unwrap_or(24).clamp(1, 24 * 366);
    // Bucket so a chart is ~500 points regardless of heartbeat rate. Beyond two days the
    // hourly rollups are used: raw samples are only kept for RMM_METRICS_RAW_DAYS.
    let bucket_secs = ((hours * 3600) / 500).max(60);
    let sql = if hours <= 48 {
        "SELECT to_timestamp(floor(extract(epoch FROM ts) / $3) * $3) AS ts,
                avg(cpu_percent)::real AS cpu_percent,
                avg(mem_used)::bigint AS mem_used,
                max(mem_total) AS mem_total,
                max(disk_max_pct) AS disk_max_pct,
                max(net_rx_bytes) AS net_rx_bytes,
                max(net_tx_bytes) AS net_tx_bytes
           FROM agent_metrics
          WHERE agent_id = $1 AND ts > $2
          GROUP BY 1 ORDER BY 1"
    } else {
        "SELECT to_timestamp(floor(extract(epoch FROM hour) / $3) * $3) AS ts,
                (sum(cpu_avg * samples) / sum(samples))::real AS cpu_percent,
                (sum(mem_used_avg::float8 * samples) / sum(samples))::bigint AS mem_used,
                max(mem_total) AS mem_total,
                max(disk_max_pct) AS disk_max_pct,
                max(net_rx_bytes) AS net_rx_bytes,
                max(net_tx_bytes) AS net_tx_bytes
           FROM agent_metrics_hourly
          WHERE agent_id = $1 AND hour > $2
          GROUP BY 1 ORDER BY 1"
    };
    let bucket = if hours <= 48 { bucket_secs } else { bucket_secs.max(3600) / 3600 * 3600 };
    Ok(Json(sqlx::query_as(sql).bind(id).bind(Utc::now() - Duration::hours(hours)).bind(bucket as f64).fetch_all(&st.db).await?))
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
    /// Unresolved alerts by severity.
    alerts: serde_json::Value,
    /// The worst and newest unresolved alerts.
    open_alerts: Vec<super::alerts::AlertRow>,
}

#[derive(Serialize)]
pub struct ClientHealth {
    id: Uuid,
    name: String,
    agents: i64,
    online: i64,
    attention: i64,
    unhealthy: i64,
    failed_jobs_24h: i64,
    open_alerts: i64,
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
        "SELECT {SUMMARY_COLS} {scoped} AND a.disk_max_pct >= 90 ORDER BY a.disk_max_pct DESC, a.hostname LIMIT 10"
    )))
    .bind(scope)
    .fetch_all(&st.db)
    .await?;
    let failed_jobs = super::jobs::recent_failures(&st, scope).await?;
    // Health is stored on each agent (see `refresh_health`): count it, for both the per-client
    // rows and the totals.
    #[derive(sqlx::FromRow)]
    struct ClientRow {
        id: Uuid,
        name: String,
        agents: i64,
        online: i64,
        ranks: Vec<i64>,
        failed_jobs_24h: i64,
        open_alerts: i64,
    }
    let rows: Vec<ClientRow> = sqlx::query_as(AssertSqlSafe(format!(
        "WITH r AS (SELECT s.client_id, a.online, a.health_rank AS rank, a.failed_jobs_24h AS failed, a.open_alerts {scoped})
         SELECT c.id, c.name, count(r.client_id) AS agents, count(r.client_id) FILTER (WHERE r.online) AS online,
                ARRAY[count(r.client_id) FILTER (WHERE r.rank = 0), count(r.client_id) FILTER (WHERE r.rank = 1),
                      count(r.client_id) FILTER (WHERE r.rank = 2), count(r.client_id) FILTER (WHERE r.rank = 3)] AS ranks,
                coalesce(sum(r.failed), 0)::bigint AS failed_jobs_24h, coalesce(sum(r.open_alerts), 0)::bigint AS open_alerts
           FROM clients c LEFT JOIN r ON r.client_id = c.id
          WHERE ($1::uuid[] IS NULL OR c.id = ANY($1))
          GROUP BY c.id
          ORDER BY count(r.client_id) FILTER (WHERE r.rank = 3) DESC, count(r.client_id) FILTER (WHERE r.rank = 2) DESC, 7 DESC,
                   count(r.client_id) - count(r.client_id) FILTER (WHERE r.online) DESC, lower(c.name)"
    )))
    .bind(scope)
    .fetch_all(&st.db)
    .await?;
    let mut totals = [0i64; 4];
    for r in &rows {
        for (t, n) in totals.iter_mut().zip(&r.ranks) {
            *t += n;
        }
    }
    let health: serde_json::Map<String, serde_json::Value> =
        ["healthy", "unknown", "attention", "unhealthy"].iter().zip(totals).filter(|(_, n)| *n > 0).map(|(h, n)| (h.to_string(), n.into())).collect();
    let health = serde_json::Value::Object(health);
    let client_health: Vec<ClientHealth> = rows
        .into_iter()
        .map(|r| ClientHealth {
            id: r.id,
            name: r.name,
            agents: r.agents,
            online: r.online,
            attention: r.ranks[2],
            unhealthy: r.ranks[3],
            failed_jobs_24h: r.failed_jobs_24h,
            open_alerts: r.open_alerts,
        })
        .collect();
    let alerts = super::alerts::summary(&st, scope).await?;
    let open_alerts = super::alerts::recent_open(&st, scope).await?;
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
        alerts,
        open_alerts,
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
    // All devices' setting; sets below may override it (the agent policy).
    let auto_update: bool = sqlx::query_scalar("SELECT coalesce((config ->> 'auto_update')::boolean, false) FROM policy_items WHERE id = $1")
        .bind(crate::policy::AGENT_ITEM)
        .fetch_one(&st.db)
        .await?;
    Ok(Json(json!({ "releases": out, "auto_update": auto_update })))
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

/// Migration 0026 against the expressions it replaced: the stored health and the indexed search
/// must give what computing them from the inventories, alerts, jobs and patches gives.
///
/// Needs only a Postgres it can `CREATE DATABASE` on (the same `RMM_E2E_DATABASE_URL` as the e2e
/// suite):
/// `RMM_E2E_DATABASE_URL=postgres://rmm:rmm@localhost:5432/postgres cargo test -p rmm-server stored_columns -- --ignored --nocapture`
#[cfg(test)]
mod tests {
    use serde_json::Value;
    use sqlx::Connection;

    use super::agent_search;

    /// The health expressions as they were before the columns (one per input), the reference.
    const OLD_DISK: &str = "coalesce((SELECT max(100 * (1 - (d->>'available')::float8 / (d->>'total')::float8))
                     FROM jsonb_array_elements(a.last_metrics->'disks') d WHERE (d->>'total')::float8 > 0), 0)";
    const OLD_FAILED: &str = "(SELECT count(*) FROM jobs fj WHERE fj.agent_id = a.id AND fj.created_at > now() - interval '24 hours'
             AND fj.status IN ('failed', 'error', 'timed_out', 'lost'))";
    const OLD_OPEN_ALERTS: &str = "(SELECT count(*) FROM alerts oa WHERE oa.agent_id = a.id AND oa.resolved_at IS NULL)";
    const OLD_OVERDUE: &str = "(SELECT count(*) FROM patches pp WHERE pp.agent_id = a.id AND pp.state <> 'installed' AND pp.approval <> 'declined'
             AND (pp.category IN ('security', 'critical') OR pp.severity = 'critical') AND pp.first_seen_at < now() - interval '7 days')";
    const OLD_PATCHES_FAILED: &str = "(SELECT count(*) FROM patches pp WHERE pp.agent_id = a.id AND pp.state = 'failed' AND pp.approval <> 'declined')";

    fn old_alert(sev: &str) -> String {
        format!("EXISTS (SELECT 1 FROM alerts oa WHERE oa.agent_id = a.id AND oa.resolved_at IS NULL AND NOT oa.suppressed AND oa.severity = '{sev}')")
    }
    fn old_rank() -> String {
        format!(
            "(CASE WHEN {crit} THEN 3 WHEN a.last_metrics IS NULL THEN 1 WHEN {OLD_DISK} >= 95 THEN 3 WHEN
             {OLD_DISK} >= 90 OR {warn} OR {OLD_FAILED} > 0 OR (a.update_state IN ('failed', 'rolled_back') AND a.update_at > now() - interval '7 days') OR
             EXISTS (SELECT 1 FROM patches pp WHERE pp.agent_id = a.id AND pp.state <> 'installed' AND pp.approval <> 'declined'
               AND (pp.state = 'failed' OR ((pp.category IN ('security', 'critical') OR pp.severity = 'critical')
                                            AND pp.first_seen_at < now() - interval '7 days'))) OR
             (a.reboot_pending AND a.reboot_pending_since < now() - interval '24 hours')
             THEN 2 ELSE 0 END)",
            crit = old_alert("critical"),
            warn = old_alert("warning"),
        )
    }
    /// The old per-agent figures, and the stored ones, as one JSON object per agent.
    fn figures(live: bool) -> String {
        let (rank, disk, failed, alerts, overdue, pfailed) = if live {
            (old_rank(), OLD_DISK.to_string(), OLD_FAILED.to_string(), OLD_OPEN_ALERTS.to_string(), OLD_OVERDUE.to_string(), OLD_PATCHES_FAILED.to_string())
        } else {
            (
                "a.health_rank".into(),
                "a.disk_max_pct".into(),
                "a.failed_jobs_24h".into(),
                "a.open_alerts".into(),
                "a.patches_overdue".into(),
                "a.patches_failed".into(),
            )
        };
        format!(
            "SELECT a.hostname, jsonb_build_object('rank', {rank}, 'disk', {disk}, 'failed', {failed}, 'alerts', {alerts},
                                                    'overdue', {overdue}, 'patches_failed', {pfailed})
               FROM agents a ORDER BY a.hostname"
        )
    }
    async fn all(db: &sqlx::PgPool, sql: String) -> Vec<(String, Value)> {
        sqlx::query_as(sqlx::AssertSqlSafe(sql)).fetch_all(db).await.unwrap()
    }
    /// Stored health equals the live expressions, for every agent; returns how many differ in
    /// rank from "healthy", so the test can see it isn't comparing all-zero.
    async fn health_matches(db: &sqlx::PgPool, what: &str) {
        let live = all(db, figures(true)).await;
        let stored = all(db, figures(false)).await;
        assert_eq!(live.len(), stored.len());
        for (l, s) in live.iter().zip(&stored) {
            assert_eq!(l, s, "{what}: stored health of {} differs from the expressions", l.0);
        }
    }
    /// The indexed search finds the agents the old scan of the inventories found.
    async fn search_matches(db: &sqlx::PgPool, what: &str) -> usize {
        let old = "(a.hostname ILIKE '%' || $1 || '%' OR a.os_name ILIKE '%' || $1 || '%'
          OR EXISTS (SELECT 1 FROM jsonb_array_elements(coalesce(a.inventory->'network', '[]')) nic,
                            jsonb_array_elements_text(coalesce(nic->'addrs', '[]')) ip
                      WHERE ip LIKE $1 || '%')
          OR EXISTS (SELECT 1 FROM jsonb_array_elements_text(coalesce(a.inventory->'logged_in_users', '[]')) lu
                      WHERE lu ILIKE $1 || '%'))";
        let mut found = 0;
        for q in [
            "host", "HOST", "Host-0", "srv_", "_", "%", "sr%1", "10.0", "10.0.1.", "10.0.1.1", "fe80", "FE80", "alice", "ALICE", "Ali", "ice", "bob1", "bo", "b",
            "windows", "UBUNTU", "22.04", "nomatch", "x_y", "\\", "10.0.2.%", "%.1/24", "admin", "root",
        ] {
            let mut ids = vec![];
            for cond in [old.to_string(), agent_search(1)] {
                let rows: Vec<(String,)> = sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT a.hostname FROM agents a WHERE {cond} ORDER BY a.hostname")))
                    .bind(q)
                    .fetch_all(db)
                    .await
                    .unwrap_or_else(|e| panic!("{what}: searching for {q:?}: {e}"));
                ids.push(rows);
            }
            assert_eq!(ids[0], ids[1], "{what}: search for {q:?}");
            found += ids[0].len();
        }
        found
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs Postgres: see the module docs"]
    async fn stored_columns_match_the_live_expressions() {
        let admin_url = std::env::var("RMM_E2E_DATABASE_URL").expect("set RMM_E2E_DATABASE_URL (see the module docs)");
        let db_name = format!("rmm_stored_{}", uuid::Uuid::new_v4().simple());
        let mut admin_conn = sqlx::PgConnection::connect(&admin_url).await.unwrap();
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {db_name}"))).execute(&mut admin_conn).await.unwrap();
        let db = sqlx::PgPool::connect(&format!("{}/{db_name}", admin_url.rsplit_once('/').unwrap().0)).await.unwrap();

        let all_migrations = sqlx::migrate!("./migrations");
        let mut before = sqlx::migrate!("./migrations");
        before.migrations = std::borrow::Cow::Owned(all_migrations.migrations.iter().filter(|m| m.version < 26).cloned().collect());
        before.run(&db).await.unwrap();

        // --- agents of every shape, before the migration ----------------------------------------------------------
        sqlx::raw_sql(
            r#"
            INSERT INTO clients (id, name) VALUES ('c1000000-0000-4000-8000-000000000000', 'Stored Co');
            INSERT INTO sites (id, client_id, name) VALUES ('51000000-0000-4000-8000-000000000000', 'c1000000-0000-4000-8000-000000000000', 'HQ');
            INSERT INTO agents (id, site_id, secret_hash, hostname, os_family, os_name, last_metrics, inventory, update_state, update_at, reboot_pending, reboot_pending_since)
            SELECT ('a0000000-0000-4000-8000-' || lpad(i::text, 12, '0'))::uuid, '51000000-0000-4000-8000-000000000000', '\x00',
                   (ARRAY['host-', 'HOST-', 'srv_', 'Host-', 'x_y-'])[i % 5 + 1] || lpad(i::text, 3, '0'),
                   CASE WHEN i % 3 = 0 THEN 'linux' ELSE 'windows' END,
                   CASE WHEN i % 3 = 0 THEN 'Ubuntu 22.04' ELSE 'Windows 11 Pro' END,
                   -- never reported / disks of every fill, none, or with a zero size / no disks key
                   CASE WHEN i % 6 = 0 THEN NULL
                        WHEN i % 9 = 0 THEN jsonb_build_object('cpu_percent', 5, 'disks', jsonb_build_array(jsonb_build_object('total', 100, 'available', 3), jsonb_build_object('total', 100, 'available', 90)))
                        WHEN i % 9 = 1 THEN jsonb_build_object('cpu_percent', 5, 'disks', jsonb_build_array(jsonb_build_object('total', 1000, 'available', 90)))
                        WHEN i % 9 = 2 THEN jsonb_build_object('cpu_percent', 5, 'disks', jsonb_build_array(jsonb_build_object('total', 0, 'available', 0)))
                        WHEN i % 9 = 3 THEN jsonb_build_object('cpu_percent', 5)
                        WHEN i % 9 = 4 THEN jsonb_build_object('cpu_percent', 5, 'disks', '[]'::jsonb)
                        ELSE jsonb_build_object('cpu_percent', 5, 'disks', jsonb_build_array(jsonb_build_object('total', 100, 'available', 80))) END,
                   -- no inventory yet / empty / addresses and users in varied case, with duplicates
                   CASE WHEN i % 5 = 0 THEN NULL
                        WHEN i % 11 = 0 THEN '{}'::jsonb
                        ELSE jsonb_build_object(
                            'network', jsonb_build_array(
                                jsonb_build_object('name', 'eth0', 'addrs', jsonb_build_array('10.0.' || (i % 4) || '.' || i || '/24', 'fe80::' || i || '/64')),
                                jsonb_build_object('name', 'lo', 'addrs', jsonb_build_array('127.0.0.1/8', '10.0.' || (i % 4) || '.' || i || '/24')),
                                jsonb_build_object('name', 'dead')),
                            'logged_in_users', jsonb_build_array(CASE WHEN i % 2 = 0 THEN 'Alice' ELSE 'alice' END, 'bob' || (i % 3), 'DOMAIN\\user_' || i)) END,
                   CASE WHEN i % 10 = 7 THEN 'failed' WHEN i % 10 = 8 THEN 'completed' END,
                   CASE WHEN i % 20 = 7 THEN now() - interval '8 days' WHEN i % 10 = 7 THEN now() - interval '1 day' END,
                   i % 13 = 0,
                   CASE WHEN i % 26 = 0 THEN now() - interval '3 days' WHEN i % 13 = 0 THEN now() - interval '2 hours' END
              FROM generate_series(1, 60) i;
            -- alerts: critical / warning / info open, held back, resolved
            INSERT INTO alerts (id, agent_id, kind, severity, title, resolved_at)
            SELECT gen_random_uuid(), ('a0000000-0000-4000-8000-' || lpad(i::text, 12, '0'))::uuid, 'cpu',
                   (ARRAY['critical', 'warning', 'info'])[i % 3 + 1], 'alert ' || i, CASE WHEN i % 7 = 0 THEN now() END
              FROM generate_series(1, 60) i WHERE i % 2 = 0 OR i % 5 = 0;
            UPDATE alerts SET suppressed = true WHERE title IN ('alert 6', 'alert 12', 'alert 30', 'alert 5');
            INSERT INTO alerts (id, agent_id, kind, severity, title) -- a second open one on some agents
            SELECT gen_random_uuid(), ('a0000000-0000-4000-8000-' || lpad(i::text, 12, '0'))::uuid, 'disk', 'warning', 'disk ' || i FROM generate_series(1, 60, 4) i;
            INSERT INTO jobs (id, agent_id, interpreter, body, timeout_secs, status, created_at)
            SELECT gen_random_uuid(), ('a0000000-0000-4000-8000-' || lpad(i::text, 12, '0'))::uuid, 'bash', 'true', 60,
                   (ARRAY['queued', 'sent', 'succeeded', 'failed', 'timed_out', 'error', 'lost', 'cancelled', 'expired'])[(i + j) % 9 + 1],
                   now() - (j * interval '9 hours')
              FROM generate_series(1, 60) i, generate_series(0, 4) j WHERE (i + j) % 3 <> 0;
            INSERT INTO patches (agent_id, update_id, title, category, severity, state, approval, first_seen_at)
            SELECT ('a0000000-0000-4000-8000-' || lpad(i::text, 12, '0'))::uuid, 'KB' || j, 'update ' || j,
                   (ARRAY['security', 'critical', 'other', 'driver'])[(i + j) % 4 + 1],
                   (ARRAY[NULL, 'critical', 'low'])[(i * j) % 3 + 1],
                   (ARRAY['missing', 'installing', 'installed', 'failed'])[(i + 2 * j) % 4 + 1],
                   (ARRAY['pending', 'approved', 'declined'])[(i + j) % 3 + 1],
                   now() - (((i * j) % 12) * interval '1 day')
              FROM generate_series(1, 60) i, generate_series(1, 3) j WHERE (i + j) % 2 = 0;
            "#,
        )
        .execute(&db)
        .await
        .unwrap();

        // The migration: stored columns backfilled from what is there.
        all_migrations.run(&db).await.unwrap();
        health_matches(&db, "after the migration").await;
        let found = search_matches(&db, "after the migration").await;
        assert!(found > 100, "the search patterns find something to compare: {found}");
        let spread: Vec<(i16, i64)> =
            sqlx::query_as("SELECT health_rank, count(*) FROM agents GROUP BY 1 ORDER BY 1").fetch_all(&db).await.unwrap();
        assert_eq!(spread.iter().map(|(r, _)| *r).collect::<Vec<_>>(), [0, 1, 2, 3], "the data covers every health rank: {spread:?}");

        // --- incremental: each change through the tables the health comes from ------------------------------------
        let agent = |i: i32| format!("'a0000000-0000-4000-8000-{i:012}'");
        let run = |sql: String| {
            let db = db.clone();
            async move { sqlx::raw_sql(sqlx::AssertSqlSafe(sql)).execute(&db).await.unwrap() }
        };
        // Alerts: resolve, hold back, release, re-rate, open, delete.
        run("UPDATE alerts SET resolved_at = now() WHERE severity = 'critical' AND resolved_at IS NULL AND title IN ('alert 2', 'alert 8')".into()).await;
        health_matches(&db, "alerts resolved").await;
        run("UPDATE alerts SET suppressed = NOT suppressed WHERE title IN ('alert 4', 'alert 6', 'alert 10')".into()).await;
        health_matches(&db, "alerts held back / released").await;
        run("UPDATE alerts SET severity = 'critical' WHERE title IN ('alert 16', 'alert 20', 'alert 22')".into()).await;
        health_matches(&db, "alerts re-rated").await;
        run(format!(
            "INSERT INTO alerts (id, agent_id, kind, severity, title) VALUES (gen_random_uuid(), {}, 'cpu', 'critical', 'new'), (gen_random_uuid(), {}, 'cpu', 'warning', 'new')",
            agent(1),
            agent(3)
        ))
        .await;
        health_matches(&db, "alerts opened").await;
        run("DELETE FROM alerts WHERE title IN ('alert 10', 'alert 24', 'new')".into()).await;
        health_matches(&db, "alerts deleted").await;
        run("DELETE FROM alerts WHERE resolved_at IS NOT NULL".into()).await;
        health_matches(&db, "resolved alerts pruned").await;
        // Jobs: results arrive, new ones are queued (a bulk run), old ones are pruned.
        run("UPDATE jobs SET status = 'failed' WHERE status = 'sent'".into()).await;
        health_matches(&db, "jobs failed").await;
        run("UPDATE jobs SET status = 'succeeded' WHERE status IN ('error', 'lost') AND created_at > now() - interval '12 hours'".into()).await;
        health_matches(&db, "jobs recovered").await;
        run("INSERT INTO jobs (id, agent_id, interpreter, body, timeout_secs, status) SELECT gen_random_uuid(), id, 'bash', 'true', 60, 'queued' FROM agents".into()).await;
        health_matches(&db, "jobs queued for every agent").await;
        run("UPDATE jobs SET status = 'timed_out' WHERE status = 'queued' AND agent_id IN (SELECT id FROM agents ORDER BY hostname LIMIT 7)".into()).await;
        health_matches(&db, "queued jobs timed out").await;
        run("DELETE FROM jobs WHERE status IN ('failed', 'cancelled')".into()).await;
        health_matches(&db, "failed jobs pruned").await;
        // Patches: a scan's upserts, installs, declines, new ones.
        run("UPDATE patches SET state = 'installed' WHERE state = 'failed' AND update_id = 'KB2'".into()).await;
        health_matches(&db, "patches installed").await;
        run("UPDATE patches SET approval = 'declined' WHERE state = 'missing' AND update_id = 'KB1'".into()).await;
        health_matches(&db, "patches declined").await;
        run("UPDATE patches SET state = 'failed', approval = 'approved' WHERE state = 'installing'".into()).await;
        health_matches(&db, "installs failed").await;
        run(format!("INSERT INTO patches (agent_id, update_id, title, category, state, first_seen_at) VALUES ({}, 'KBnew', 'new', 'security', 'missing', now() - interval '9 days')", agent(1))).await;
        health_matches(&db, "an old security update seen").await;
        run(format!(
            "INSERT INTO patches (agent_id, update_id, title, category, state) VALUES ({}, 'KBfresh', 'new', 'security', 'missing')
             ON CONFLICT (agent_id, update_id) DO UPDATE SET state = 'missing', last_seen_at = now()",
            agent(1)
        ))
        .await;
        run(format!("UPDATE patches SET first_seen_at = now() - interval '2 days' WHERE agent_id = {} AND update_id = 'KBnew'", agent(1))).await;
        health_matches(&db, "an update's first sighting moved").await;
        run("DELETE FROM patches WHERE state = 'installed'".into()).await;
        health_matches(&db, "installed patches pruned").await;
        // The agent row itself: heartbeats (disks), update state, reboot flag, inventory.
        run("UPDATE agents SET last_metrics = jsonb_build_object('cpu_percent', 9, 'disks', jsonb_build_array(jsonb_build_object('total', 100, 'available', 2)))
              WHERE hostname LIKE 'host-%'"
            .into())
        .await;
        health_matches(&db, "heartbeats with full disks").await;
        run("UPDATE agents SET last_metrics = jsonb_build_object('cpu_percent', 9, 'disks', jsonb_build_array(jsonb_build_object('total', 100, 'available', 60)))
              WHERE last_metrics IS NULL"
            .into())
        .await;
        health_matches(&db, "first heartbeats").await;
        run("UPDATE agents SET update_state = 'rolled_back', update_at = now() WHERE hostname LIKE 'srv_%'".into()).await;
        run("UPDATE agents SET update_state = 'failed', update_at = now() - interval '9 days' WHERE hostname LIKE 'x_y-%'".into()).await;
        health_matches(&db, "self-update failures").await;
        run("UPDATE agents SET reboot_pending = true, reboot_pending_since = now() - interval '30 hours' WHERE hostname LIKE 'Host-%'".into()).await;
        run("UPDATE agents SET reboot_pending = false WHERE hostname LIKE 'HOST-%'".into()).await;
        health_matches(&db, "reboot flags").await;
        run("UPDATE agents SET online = NOT online".into()).await;
        health_matches(&db, "online flags (not an input)").await;
        // Inventory: addresses and users change, one agent's inventory goes away.
        run(format!(
            "UPDATE agents SET inventory = jsonb_build_object('network', jsonb_build_array(jsonb_build_object('addrs', jsonb_build_array('192.168.7.7/24'))),
                                                              'logged_in_users', jsonb_build_array('Carol'))
              WHERE id IN ({}, {}, {})",
            agent(1),
            agent(2),
            agent(3)
        ))
        .await;
        run(format!("UPDATE agents SET inventory = NULL WHERE id = {}", agent(4))).await;
        run(format!("UPDATE agents SET hostname = 'renamed-host', os_name = 'Fedora 41' WHERE id = {}", agent(7))).await;
        let after_inv = search_matches(&db, "inventory changed").await;
        assert!(after_inv > 50);
        let carol: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT count(*) FROM agents a WHERE {}",
            agent_search(1)
        )))
        .bind("carol")
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(carol, 3, "the new logged-in user is found");
        let gone: i64 = sqlx::query_scalar("SELECT count(*) FROM agent_search_terms WHERE agent_id = 'a0000000-0000-4000-8000-000000000004'")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(gone, 0, "an agent without an inventory has no terms");
        health_matches(&db, "inventory changes").await;
        // An agent with alerts, jobs, patches and terms goes away.
        run(format!("DELETE FROM agents WHERE id = {}", agent(2))).await;
        health_matches(&db, "an agent deleted").await;
        search_matches(&db, "an agent deleted").await;
        // A malformed inventory (the old search failed outright on it) just has no terms.
        run(format!("UPDATE agents SET inventory = '{{\"network\": null, \"logged_in_users\": \"nobody\"}}' WHERE id = {}", agent(6))).await;
        let nobody: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM agents a WHERE {}", agent_search(1))))
            .bind("nobody")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(nobody, 0);
        // A new agent: unknown until it reports.
        run("INSERT INTO agents (id, site_id, secret_hash, hostname, os_family) VALUES ('a0000000-0000-4000-8000-0000000000ff', '51000000-0000-4000-8000-000000000000', '\\x00', 'brand-new', 'linux')".into()).await;
        health_matches(&db, "a new agent").await;
        let rank: i16 = sqlx::query_scalar("SELECT health_rank FROM agents WHERE hostname = 'brand-new'").fetch_one(&db).await.unwrap();
        assert_eq!(rank, 1);

        // --- the reconcile: what only time changes, and anything that drifted ---------------------------------------
        run("UPDATE jobs SET created_at = now() - interval '30 hours' WHERE status IN ('timed_out', 'error', 'lost')".into()).await;
        let live = all(&db, figures(true)).await;
        let stored = all(&db, figures(false)).await;
        assert_ne!(live, stored, "jobs aging out of the 24 hours are not seen by a trigger");
        super::refresh_health(&db).await.unwrap();
        health_matches(&db, "reconciled after time passed").await;
        run("UPDATE agents SET health_rank = 0, open_alerts = 99, failed_jobs_24h = 7, patches_overdue = 3 WHERE hostname LIKE 'host-%'".into()).await;
        assert_ne!(all(&db, figures(true)).await, all(&db, figures(false)).await);
        super::refresh_health(&db).await.unwrap();
        health_matches(&db, "reconciled after drift").await;
        // A reconcile that finds nothing rewrites nothing.
        let versions = "SELECT array_agg(xmin::text ORDER BY id) FROM agents";
        let before: Vec<String> = sqlx::query_scalar(versions).fetch_one(&db).await.unwrap();
        super::refresh_health(&db).await.unwrap();
        let after: Vec<String> = sqlx::query_scalar(versions).fetch_one(&db).await.unwrap();
        assert_eq!(before, after, "a reconcile that finds nothing new rewrites no agent rows");

        db.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!("DROP DATABASE IF EXISTS {db_name} WITH (FORCE)"))).execute(&mut admin_conn).await.unwrap();
        println!("stored columns: ok");
    }
}
