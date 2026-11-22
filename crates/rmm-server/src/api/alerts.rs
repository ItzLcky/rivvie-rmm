//! Alerts (incidents). What raises them is `alert` items of the policy sets (`api::policies`).

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::AssertSqlSafe;
use uuid::Uuid;

use crate::auth::{self, Role, User};
use crate::error::{ApiError, ApiResult};
use crate::hub::Event;
use crate::paging::{self, Page, PageQuery, Plan, SortKey};
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Alerts
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct AlertRow {
    id: Uuid,
    policy_id: Option<Uuid>,
    policy_name: Option<String>,
    agent_id: Uuid,
    hostname: String,
    client_id: Uuid,
    client_name: String,
    site_name: String,
    kind: String,
    severity: String,
    title: String,
    details: Value,
    occurrences: i32,
    /// open / acknowledged / resolved
    state: String,
    opened_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    acknowledged_at: Option<DateTime<Utc>>,
    acknowledged_by_name: Option<String>,
    resolved_at: Option<DateTime<Utc>>,
    resolved_by_name: Option<String>,
    resolution: Option<String>,
    /// Opened during a maintenance window or snooze: nobody was notified (yet).
    suppressed: bool,
    /// The job its policy's `run_script_id` started when it opened.
    script_job_id: Option<Uuid>,
    /// A monitored network device it is about (`hostname` is the agent that reads it).
    device_id: Option<Uuid>,
    device_name: Option<String>,
    #[sqlx(default)]
    #[serde(skip)]
    sort_key: String,
}

const STATE: &str = "(CASE WHEN al.resolved_at IS NOT NULL THEN 'resolved' WHEN al.acknowledged_at IS NOT NULL THEN 'acknowledged' ELSE 'open' END)";
const SEVERITY_RANK: &str = "(CASE al.severity WHEN 'critical' THEN 3 WHEN 'warning' THEN 2 ELSE 1 END)";

fn alert_cols() -> String {
    format!(
        "al.id, al.policy_id, p.name AS policy_name, al.agent_id, a.hostname, s.client_id, c.name AS client_name, s.name AS site_name,
         al.kind, al.severity, al.title, al.details, al.occurrences, {STATE} AS state, al.opened_at, al.last_seen_at,
         al.acknowledged_at, ua.name AS acknowledged_by_name, al.resolved_at, ur.name AS resolved_by_name, al.resolution, al.suppressed,
         al.script_job_id, al.device_id, nd.name AS device_name"
    )
}
const ALERT_FROM: &str = "FROM alerts al JOIN agents a ON a.id = al.agent_id JOIN sites s ON s.id = a.site_id
       JOIN clients c ON c.id = s.client_id LEFT JOIN policy_items p ON p.id = al.policy_id
       LEFT JOIN users ua ON ua.id = al.acknowledged_by LEFT JOIN users ur ON ur.id = al.resolved_by
       LEFT JOIN net_devices nd ON nd.id = al.device_id";

const SORT_KEYS: &[SortKey] = &[
    SortKey { name: "opened", expr: "al.opened_at", ty: "timestamptz" },
    SortKey { name: "last_seen", expr: "al.last_seen_at", ty: "timestamptz" },
    SortKey { name: "severity", expr: SEVERITY_RANK, ty: "int" },
    SortKey { name: "hostname", expr: "lower(a.hostname)", ty: "text" },
    SortKey { name: "title", expr: "lower(al.title)", ty: "text" },
];

#[derive(Deserialize)]
pub struct ListQuery {
    /// `active` (open + acknowledged, the default), `open`, `acknowledged`, `resolved` or `all`.
    state: Option<String>,
    /// Comma-separated.
    severity: Option<String>,
    client_id: Option<Uuid>,
    agent_id: Option<Uuid>,
    policy_id: Option<Uuid>,
    kind: Option<String>,
    /// Hostname or title.
    q: Option<String>,
}

pub async fn list(
    State(st): State<Arc<AppState>>,
    u: User,
    Query(q): Query<ListQuery>,
    Query(page): Query<PageQuery>,
) -> ApiResult<Json<Page<AlertRow>>> {
    let plan = Plan::new(SORT_KEYS, ("opened", true), &page, "al.id", "uuid", 9)?;
    let states: Option<Vec<&str>> = match q.state.as_deref().unwrap_or("active") {
        "active" => Some(vec!["open", "acknowledged"]),
        "all" => None,
        s @ ("open" | "acknowledged" | "resolved") => Some(vec![s]),
        other => return Err(ApiError::BadRequest(format!("unknown state {other}"))),
    };
    let severity: Option<Vec<String>> =
        q.severity.as_deref().filter(|s| !s.is_empty()).map(|s| s.split(',').map(str::to_string).collect());
    let filters = format!(
        "{ALERT_FROM}
          WHERE ($1::uuid[] IS NULL OR s.client_id = ANY($1))
            AND ($2::text[] IS NULL OR {STATE} = ANY($2))
            AND ($3::text[] IS NULL OR al.severity = ANY($3))
            AND ($4::uuid IS NULL OR s.client_id = $4)
            AND ($5::uuid IS NULL OR al.agent_id = $5)
            AND ($6::uuid IS NULL OR al.policy_id = $6)
            AND ($7::text IS NULL OR al.kind = $7)
            AND ($8::text IS NULL OR a.hostname ILIKE '%' || $8 || '%' OR al.title ILIKE '%' || $8 || '%')"
    );
    let search = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let kind = q.kind.as_deref().filter(|s| !s.is_empty());
    macro_rules! bind_filters {
        ($query:expr) => {
            $query
                .bind(u.scope())
                .bind(&states)
                .bind(&severity)
                .bind(q.client_id)
                .bind(q.agent_id)
                .bind(q.policy_id)
                .bind(kind)
                .bind(search)
        };
    }
    let sql = format!("SELECT {}, {} {filters} {} {} {}", alert_cols(), plan.key_select, plan.keyset, plan.order, plan.limit_sql());
    let mut rows = bind_filters!(sqlx::query_as::<_, AlertRow>(AssertSqlSafe(sql)));
    if let Some((k, id)) = &plan.cursor {
        rows = rows.bind(k).bind(id);
    }
    let rows = rows.fetch_all(&st.db).await?;
    let total: i64 = bind_filters!(sqlx::query_scalar(AssertSqlSafe(paging::count_sql(&filters)))).fetch_one(&st.db).await?;
    Ok(Json(plan.finish(rows, |r| (r.sort_key.clone(), r.id.to_string()), total)))
}

async fn fetch(st: &AppState, u: &User, id: Uuid) -> ApiResult<AlertRow> {
    sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {} {ALERT_FROM} WHERE al.id = $1 AND ($2::uuid[] IS NULL OR s.client_id = ANY($2))",
        alert_cols()
    )))
    .bind(id)
    .bind(u.scope())
    .fetch_optional(&st.db)
    .await?
    .ok_or(ApiError::NotFound("alert"))
}

#[derive(Serialize, sqlx::FromRow)]
pub struct Delivery {
    id: i64,
    channel_name: String,
    channel_kind: String,
    event: String,
    status: String,
    attempts: i32,
    last_error: Option<String>,
    created_at: DateTime<Utc>,
    sent_at: Option<DateTime<Utc>>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct LogEventRow {
    id: i64,
    ts: DateTime<Utc>,
    level: String,
    source: String,
    event_id: Option<i32>,
    message: String,
    policy_name: Option<String>,
}

#[derive(Serialize)]
pub struct AlertDetail {
    #[serde(flatten)]
    alert: AlertRow,
    notifications: Vec<Delivery>,
    log_events: Vec<LogEventRow>,
    /// The ticket its policy opened for it, if any.
    ticket: Option<Value>,
}

pub async fn get(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<AlertDetail>> {
    let alert = fetch(&st, &u, id).await?;
    let notifications = sqlx::query_as(
        "SELECT n.id, ch.name AS channel_name, ch.kind AS channel_kind, n.event, n.status, n.attempts, n.last_error, n.created_at, n.sent_at
           FROM notifications n JOIN notification_channels ch ON ch.id = n.channel_id
          WHERE n.alert_id = $1 ORDER BY n.id",
    )
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    let log_events = sqlx::query_as(
        "SELECT l.id, l.ts, l.level, l.source, l.event_id, l.message, p.name AS policy_name
           FROM log_events l LEFT JOIN policy_items p ON p.id = l.policy_id
          WHERE l.alert_id = $1 ORDER BY l.id DESC LIMIT 50",
    )
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    let ticket: Option<Value> = sqlx::query_scalar(
        "SELECT jsonb_build_object('id', t.id, 'number', t.number) FROM alerts al JOIN tickets t
             ON t.alert_policy_id = al.policy_id AND t.alert_agent_id = al.agent_id AND t.alert_key = al.key
          WHERE al.id = $1 AND t.created_at <= coalesce(al.resolved_at, now()) + interval '1 minute'
          ORDER BY t.created_at DESC LIMIT 1",
    )
    .bind(id)
    .fetch_optional(&st.db)
    .await?;
    Ok(Json(AlertDetail { alert, notifications, log_events, ticket }))
}

#[derive(Deserialize)]
pub struct Bulk {
    ids: Vec<Uuid>,
    /// `acknowledge` or `resolve`.
    action: String,
}

/// Acknowledges or resolves alerts the user can see. Resolving announces "resolved" on the
/// policy's channels, like a condition clearing.
async fn act(st: &AppState, u: &User, ids: &[Uuid], action: &str) -> ApiResult<usize> {
    u.require(Role::Technician)?;
    if ids.is_empty() || ids.len() > 1000 {
        return Err(ApiError::BadRequest("pick 1-1000 alerts".into()));
    }
    let sql = match action {
        "acknowledge" => {
            "UPDATE alerts al SET acknowledged_at = now(), acknowledged_by = $3
               FROM agents a JOIN sites s ON s.id = a.site_id
              WHERE a.id = al.agent_id AND al.id = ANY($1) AND ($2::uuid[] IS NULL OR s.client_id = ANY($2))
                AND al.resolved_at IS NULL AND al.acknowledged_at IS NULL
              RETURNING al.id, al.agent_id, s.client_id, al.policy_id"
        }
        "resolve" => {
            "UPDATE alerts al SET resolved_at = now(), resolved_by = $3, resolution = 'manual'
               FROM agents a JOIN sites s ON s.id = a.site_id
              WHERE a.id = al.agent_id AND al.id = ANY($1) AND ($2::uuid[] IS NULL OR s.client_id = ANY($2))
                AND al.resolved_at IS NULL
              RETURNING al.id, al.agent_id, s.client_id, al.policy_id"
        }
        other => return Err(ApiError::BadRequest(format!("unknown action {other}"))),
    };
    let rows: Vec<(Uuid, Uuid, Uuid, Option<Uuid>)> =
        sqlx::query_as(sql).bind(ids).bind(u.scope()).bind(u.id).fetch_all(&st.db).await?;
    let state = if action == "resolve" { "resolved" } else { "acknowledged" };
    let mut woke = false;
    for (id, agent_id, client_id, policy_id) in &rows {
        st.hub.publish(Event::Alert { id: *id, agent_id: *agent_id, client_id: *client_id, state: state.into() });
        crate::webhooks::alert_event(st, *id, if action == "resolve" { "alert.resolved" } else { "alert.acknowledged" }).await;
        if action == "resolve" {
            crate::tickets::alert_resolved(st, *id).await;
        }
        if action == "resolve"
            && let Some(pid) = policy_id
        {
            let config: Option<Value> = sqlx::query_scalar("SELECT policy_config($1, $2)").bind(pid).bind(agent_id).fetch_one(&st.db).await?;
            let p = config.and_then(|c| serde_json::from_value::<crate::policy::AlertConfig>(c).ok());
            if let Some(crate::policy::AlertConfig { channel_ids: channels, notify_resolved: true, .. }) = p {
                crate::notify::enqueue(st, *id, "resolved", &channels).await;
                woke |= !channels.is_empty();
            }
        }
    }
    if woke {
        st.notify_wake.notify_one();
    }
    if !rows.is_empty() {
        auth::audit(&st.db, Some(u.id), &format!("alert.{action}"), None, json!({ "alerts": rows.len() })).await;
    }
    Ok(rows.len())
}

pub async fn acknowledge(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<AlertRow>> {
    fetch(&st, &u, id).await?;
    act(&st, &u, &[id], "acknowledge").await?;
    Ok(Json(fetch(&st, &u, id).await?))
}

pub async fn resolve(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<AlertRow>> {
    fetch(&st, &u, id).await?;
    act(&st, &u, &[id], "resolve").await?;
    Ok(Json(fetch(&st, &u, id).await?))
}

pub async fn bulk(State(st): State<Arc<AppState>>, u: User, Json(b): Json<Bulk>) -> ApiResult<Json<Value>> {
    let changed = act(&st, &u, &b.ids, &b.action).await?;
    Ok(Json(json!({ "changed": changed })))
}

/// Open (unresolved) alerts by severity, for the sidebar badge and the dashboard.
pub async fn summary(st: &AppState, scope: Option<&[Uuid]>) -> ApiResult<Value> {
    Ok(sqlx::query_scalar(
        "SELECT coalesce(jsonb_object_agg(severity, n), '{}') FROM (
            SELECT al.severity, count(*) n FROM alerts al JOIN agents a ON a.id = al.agent_id JOIN sites s ON s.id = a.site_id
             WHERE al.resolved_at IS NULL AND ($1::uuid[] IS NULL OR s.client_id = ANY($1)) GROUP BY 1) t",
    )
    .bind(scope)
    .fetch_one(&st.db)
    .await?)
}

#[derive(Deserialize)]
pub struct SummaryQuery {
    client_id: Option<Uuid>,
}

pub async fn summary_handler(State(st): State<Arc<AppState>>, u: User, Query(q): Query<SummaryQuery>) -> ApiResult<Json<Value>> {
    let scope = super::agents::narrow(&u, q.client_id)?;
    Ok(Json(summary(&st, scope.as_deref()).await?))
}

/// The latest open alerts, worst first, for the dashboard.
pub async fn recent_open(st: &AppState, scope: Option<&[Uuid]>) -> ApiResult<Vec<AlertRow>> {
    Ok(sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {} {ALERT_FROM} WHERE al.resolved_at IS NULL AND ($1::uuid[] IS NULL OR s.client_id = ANY($1))
          ORDER BY {SEVERITY_RANK} DESC, al.opened_at DESC LIMIT 10",
        alert_cols()
    )))
    .bind(scope)
    .fetch_all(&st.db)
    .await?)
}
