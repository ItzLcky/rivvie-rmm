//! Alerts (incidents) and alert policies (what raises them).

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::AssertSqlSafe;
use uuid::Uuid;

use crate::alerts::Rule;
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
         al.acknowledged_at, ua.name AS acknowledged_by_name, al.resolved_at, ur.name AS resolved_by_name, al.resolution, al.suppressed"
    )
}
const ALERT_FROM: &str = "FROM alerts al JOIN agents a ON a.id = al.agent_id JOIN sites s ON s.id = a.site_id
       JOIN clients c ON c.id = s.client_id LEFT JOIN alert_policies p ON p.id = al.policy_id
       LEFT JOIN users ua ON ua.id = al.acknowledged_by LEFT JOIN users ur ON ur.id = al.resolved_by";

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
           FROM log_events l LEFT JOIN alert_policies p ON p.id = l.policy_id
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
        if action == "resolve" {
            crate::tickets::alert_resolved(st, *id).await;
        }
        if action == "resolve"
            && let Some(pid) = policy_id
        {
            let p: Option<(Vec<Uuid>, bool)> = sqlx::query_as("SELECT channel_ids, notify_resolved FROM alert_policies WHERE id = $1")
                .bind(pid)
                .fetch_optional(&st.db)
                .await?;
            if let Some((channels, true)) = p {
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

// ---------------------------------------------------------------------------
// Policies
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct PolicyRow {
    id: Uuid,
    name: String,
    kind: String,
    params: Value,
    severity: String,
    client_id: Option<Uuid>,
    client_name: Option<String>,
    site_id: Option<Uuid>,
    site_name: Option<String>,
    os_family: Option<String>,
    channel_ids: Vec<Uuid>,
    notify_resolved: bool,
    enabled: bool,
    /// Open tickets on this board for its alerts (None = no tickets).
    ticket_board_id: Option<Uuid>,
    ticket_priority: i16,
    /// Resolve the ticket when the alert clears, if nobody has worked it.
    ticket_auto_resolve: bool,
    /// Remind the channels this often while an alert stays open and unacknowledged.
    renotify_minutes: Option<i32>,
    /// Agents left out: `[{id, hostname}]` (those the user can see).
    excluded: Value,
    open_alerts: i64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

const POLICY_SELECT: &str = "SELECT p.id, p.name, p.kind, p.params, p.severity, p.client_id, c.name AS client_name, p.site_id,
       si.name AS site_name, p.os_family, p.channel_ids, p.notify_resolved, p.enabled, p.ticket_board_id, p.ticket_priority,
       p.ticket_auto_resolve, p.renotify_minutes,
       (SELECT coalesce(jsonb_agg(jsonb_build_object('id', xa.id, 'hostname', xa.hostname) ORDER BY lower(xa.hostname)), '[]')
          FROM agents xa JOIN sites xs ON xs.id = xa.site_id
         WHERE xa.id = ANY(p.excluded_agents) AND ($1::uuid[] IS NULL OR xs.client_id = ANY($1))) AS excluded,
       (SELECT count(*) FROM alerts al WHERE al.policy_id = p.id AND al.resolved_at IS NULL) AS open_alerts,
       p.created_at, p.updated_at
  FROM alert_policies p LEFT JOIN clients c ON c.id = p.client_id LEFT JOIN sites si ON si.id = p.site_id";
/// MSP-wide policies plus those of the clients the user can see ($1 NULL = all).
const POLICY_VISIBLE: &str = "(p.client_id IS NULL OR $1::uuid[] IS NULL OR p.client_id = ANY($1))";

async fn fetch_policy(st: &AppState, u: &User, id: Uuid) -> ApiResult<PolicyRow> {
    sqlx::query_as(AssertSqlSafe(format!("{POLICY_SELECT} WHERE {POLICY_VISIBLE} AND p.id = $2")))
        .bind(u.scope())
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("policy"))
}

pub async fn list_policies(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Vec<PolicyRow>>> {
    Ok(Json(
        sqlx::query_as(AssertSqlSafe(format!("{POLICY_SELECT} WHERE {POLICY_VISIBLE} ORDER BY lower(p.name), c.name NULLS FIRST")))
            .bind(u.scope())
            .fetch_all(&st.db)
            .await?,
    ))
}

pub async fn get_policy(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<PolicyRow>> {
    Ok(Json(fetch_policy(&st, &u, id).await?))
}

#[derive(Deserialize)]
pub struct PolicyIn {
    name: String,
    kind: String,
    #[serde(default)]
    params: Value,
    severity: String,
    client_id: Option<Uuid>,
    site_id: Option<Uuid>,
    os_family: Option<String>,
    #[serde(default)]
    channel_ids: Vec<Uuid>,
    #[serde(default = "yes")]
    notify_resolved: bool,
    #[serde(default = "yes")]
    enabled: bool,
    ticket_board_id: Option<Uuid>,
    #[serde(default = "p3")]
    ticket_priority: i16,
    #[serde(default)]
    ticket_auto_resolve: bool,
    renotify_minutes: Option<i32>,
}

fn p3() -> i16 {
    3
}

fn yes() -> bool {
    true
}

/// Checks what client/site/OS-scoped objects (policies, schedules) share: the site belongs
/// to the client, the OS is one we know.
pub(crate) async fn check_target(st: &AppState, u: &User, client_id: Option<Uuid>, site_id: Option<Uuid>, os: Option<&str>) -> ApiResult<()> {
    if let Some(site) = site_id {
        let site_client = super::access::site(st, u, site).await?;
        if Some(site_client) != client_id {
            return Err(ApiError::BadRequest("the site must belong to the chosen client".into()));
        }
    }
    if let Some(c) = client_id {
        super::access::client(u, c)?;
        let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM clients WHERE id = $1)").bind(c).fetch_one(&st.db).await?;
        if !exists {
            return Err(ApiError::NotFound("client"));
        }
    }
    if os.is_some_and(|o| !matches!(o, "linux" | "windows" | "macos")) {
        return Err(ApiError::BadRequest("os_family must be linux, windows or macos".into()));
    }
    Ok(())
}

impl PolicyIn {
    async fn validate(&self, st: &AppState, u: &User) -> ApiResult<Rule> {
        let name = self.name.trim();
        if name.is_empty() || name.chars().count() > 200 {
            return Err(ApiError::BadRequest("name must be 1-200 characters".into()));
        }
        if !matches!(self.severity.as_str(), "critical" | "warning" | "info") {
            return Err(ApiError::BadRequest("severity must be critical, warning or info".into()));
        }
        let params = if self.params.is_null() { json!({}) } else { self.params.clone() };
        let rule = Rule::parse(&self.kind, &params).map_err(ApiError::BadRequest)?;
        rule.validate().map_err(ApiError::BadRequest)?;
        check_target(st, u, self.client_id, self.site_id, self.os_family.as_deref()).await?;
        if self.renotify_minutes.is_some_and(|m| !(15..=10080).contains(&m)) {
            return Err(ApiError::BadRequest("reminders must be every 15 minutes to 7 days".into()));
        }
        if !(1..=4).contains(&self.ticket_priority) {
            return Err(ApiError::BadRequest("ticket priority must be 1-4".into()));
        }
        if let Some(b) = self.ticket_board_id {
            let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM boards WHERE id = $1)").bind(b).fetch_one(&st.db).await?;
            if !exists {
                return Err(ApiError::NotFound("board"));
            }
        }
        if self.channel_ids.len() > 20 {
            return Err(ApiError::BadRequest("at most 20 channels".into()));
        }
        let known: i64 = sqlx::query_scalar("SELECT count(*) FROM notification_channels WHERE id = ANY($1)")
            .bind(&self.channel_ids)
            .fetch_one(&st.db)
            .await?;
        if known as usize != self.channel_ids.iter().collect::<std::collections::HashSet<_>>().len() {
            return Err(ApiError::BadRequest("unknown notification channel".into()));
        }
        // A client's own script can only be watched by a policy for that client.
        if let Rule::JobFailed { script_id: Some(sid) } = &rule {
            let script_client: Option<Option<Uuid>> =
                sqlx::query_scalar("SELECT client_id FROM scripts WHERE id = $1").bind(sid).fetch_optional(&st.db).await?;
            match script_client {
                None => return Err(ApiError::NotFound("script")),
                Some(Some(c)) if !u.can_see_client(c) => return Err(ApiError::NotFound("script")),
                Some(Some(c)) if self.client_id != Some(c) => {
                    return Err(ApiError::BadRequest("that script belongs to another client".into()));
                }
                _ => {}
            }
        }
        Ok(rule)
    }
}

fn dedup(ids: &[Uuid]) -> Vec<Uuid> {
    let mut out: Vec<Uuid> = Vec::with_capacity(ids.len());
    for id in ids {
        if !out.contains(id) {
            out.push(*id);
        }
    }
    out
}

pub async fn create_policy(State(st): State<Arc<AppState>>, u: User, Json(b): Json<PolicyIn>) -> ApiResult<Json<PolicyRow>> {
    super::scripts::may_edit(&u, b.client_id)?;
    let rule = b.validate(&st, &u).await?;
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO alert_policies (id, name, kind, params, severity, client_id, site_id, os_family, channel_ids, notify_resolved, enabled, created_by,
                                     ticket_board_id, ticket_priority, ticket_auto_resolve, renotify_minutes)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)",
    )
    .bind(id)
    .bind(b.name.trim())
    .bind(rule.kind())
    .bind(rule.params())
    .bind(&b.severity)
    .bind(b.client_id)
    .bind(b.site_id)
    .bind(&b.os_family)
    .bind(dedup(&b.channel_ids))
    .bind(b.notify_resolved)
    .bind(b.enabled)
    .bind(u.id)
    .bind(b.ticket_board_id)
    .bind(b.ticket_priority)
    .bind(b.ticket_auto_resolve)
    .bind(b.renotify_minutes)
    .execute(&st.db)
    .await?;
    auth::audit(&st.db, Some(u.id), "policy.create", Some(("policy", id)), json!({ "name": b.name.trim(), "kind": rule.kind() })).await;
    crate::alerts::policy_changed(&st, id).await;
    Ok(Json(fetch_policy(&st, &u, id).await?))
}

pub async fn update_policy(
    State(st): State<Arc<AppState>>,
    u: User,
    Path(id): Path<Uuid>,
    Json(b): Json<PolicyIn>,
) -> ApiResult<Json<PolicyRow>> {
    let current = fetch_policy(&st, &u, id).await?;
    super::scripts::may_edit(&u, current.client_id)?;
    super::scripts::may_edit(&u, b.client_id)?;
    let rule = b.validate(&st, &u).await?;
    if rule.kind() != current.kind {
        // Open alerts were raised by the old rule and mean something else.
        return Err(ApiError::BadRequest("a policy's type can't change; create a new policy instead".into()));
    }
    sqlx::query(
        "UPDATE alert_policies SET name = $2, params = $3, severity = $4, client_id = $5, site_id = $6, os_family = $7,
                channel_ids = $8, notify_resolved = $9, enabled = $10, ticket_board_id = $11, ticket_priority = $12,
                ticket_auto_resolve = $13, renotify_minutes = $14, updated_at = now()
          WHERE id = $1",
    )
    .bind(id)
    .bind(b.name.trim())
    .bind(rule.params())
    .bind(&b.severity)
    .bind(b.client_id)
    .bind(b.site_id)
    .bind(&b.os_family)
    .bind(dedup(&b.channel_ids))
    .bind(b.notify_resolved)
    .bind(b.enabled)
    .bind(b.ticket_board_id)
    .bind(b.ticket_priority)
    .bind(b.ticket_auto_resolve)
    .bind(b.renotify_minutes)
    .execute(&st.db)
    .await?;
    // Open alerts take the new severity.
    sqlx::query("UPDATE alerts SET severity = $2 WHERE policy_id = $1 AND resolved_at IS NULL").bind(id).bind(&b.severity).execute(&st.db).await?;
    auth::audit(&st.db, Some(u.id), "policy.update", Some(("policy", id)), json!({ "name": b.name.trim(), "enabled": b.enabled })).await;
    crate::alerts::policy_changed(&st, id).await;
    Ok(Json(fetch_policy(&st, &u, id).await?))
}

pub async fn remove_policy(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let current = fetch_policy(&st, &u, id).await?;
    super::scripts::may_edit(&u, current.client_id)?;
    // Close its alerts first (quietly): once the policy is gone they'd have no owner.
    sqlx::query("UPDATE alerts SET resolved_at = now(), resolution = 'policy' WHERE policy_id = $1 AND resolved_at IS NULL")
        .bind(id)
        .execute(&st.db)
        .await?;
    sqlx::query("DELETE FROM alert_policies WHERE id = $1").bind(id).execute(&st.db).await?;
    auth::audit(&st.db, Some(u.id), "policy.delete", Some(("policy", id)), json!({ "name": current.name })).await;
    crate::alerts::policy_changed(&st, id).await;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Per-agent exclusions
// ---------------------------------------------------------------------------

/// Leaves one agent out of a policy (`excluded: true`) or puts it back. The policy's open
/// alerts on that agent close quietly.
async fn set_excluded(st: &Arc<AppState>, u: &User, policy_id: Uuid, agent_id: Uuid, excluded: bool) -> ApiResult<PolicyRow> {
    let p = fetch_policy(st, u, policy_id).await?;
    // Changing who a policy covers is editing it; the agent must be one the user can manage.
    super::scripts::may_edit(u, p.client_id)?;
    super::access::agent(st, u, agent_id).await?;
    let sql = if excluded {
        "UPDATE alert_policies SET excluded_agents = array_append(excluded_agents, $2), updated_at = now()
          WHERE id = $1 AND NOT ($2 = ANY(excluded_agents))"
    } else {
        "UPDATE alert_policies SET excluded_agents = array_remove(excluded_agents, $2), updated_at = now() WHERE id = $1"
    };
    sqlx::query(sql).bind(policy_id).bind(agent_id).execute(&st.db).await?;
    // Agents that were deleted don't need to stay listed.
    sqlx::query(
        "UPDATE alert_policies SET excluded_agents = ARRAY(SELECT x FROM unnest(excluded_agents) x WHERE EXISTS (SELECT 1 FROM agents WHERE id = x))
          WHERE id = $1",
    )
    .bind(policy_id)
    .execute(&st.db)
    .await?;
    auth::audit(
        &st.db,
        Some(u.id),
        if excluded { "policy.exclude_agent" } else { "policy.include_agent" },
        Some(("agent", agent_id)),
        json!({ "policy": policy_id, "name": p.name }),
    )
    .await;
    crate::alerts::policy_changed(st, policy_id).await;
    fetch_policy(st, u, policy_id).await
}

pub async fn exclude(State(st): State<Arc<AppState>>, u: User, Path((id, agent_id)): Path<(Uuid, Uuid)>) -> ApiResult<Json<PolicyRow>> {
    Ok(Json(set_excluded(&st, &u, id, agent_id, true).await?))
}

pub async fn include(State(st): State<Arc<AppState>>, u: User, Path((id, agent_id)): Path<(Uuid, Uuid)>) -> ApiResult<Json<PolicyRow>> {
    Ok(Json(set_excluded(&st, &u, id, agent_id, false).await?))
}

#[derive(Serialize, sqlx::FromRow)]
pub struct CoveringPolicy {
    id: Uuid,
    name: String,
    kind: String,
    severity: String,
    enabled: bool,
    /// "msp", "client" or "site": where it's set.
    level: String,
    excluded: bool,
    /// The user may edit it (and so exclude the agent from it).
    #[sqlx(default)]
    editable: bool,
    open_alerts: i64,
}

/// The alert policies whose client/site/OS cover this agent, excluded or not.
pub async fn for_agent(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Vec<CoveringPolicy>>> {
    super::access::agent(&st, &u, id).await?;
    let mut rows: Vec<CoveringPolicy> = sqlx::query_as(
        "SELECT p.id, p.name, p.kind, p.severity, p.enabled,
                CASE WHEN p.site_id IS NOT NULL THEN 'site' WHEN p.client_id IS NOT NULL THEN 'client' ELSE 'msp' END AS level,
                a.id = ANY(p.excluded_agents) AS excluded,
                (SELECT count(*) FROM alerts al WHERE al.policy_id = p.id AND al.agent_id = a.id AND al.resolved_at IS NULL) AS open_alerts
           FROM alert_policies p, agents a JOIN sites s ON s.id = a.site_id
          WHERE a.id = $1 AND (p.client_id IS NULL OR p.client_id = s.client_id) AND (p.site_id IS NULL OR p.site_id = a.site_id)
            AND (p.os_family IS NULL OR p.os_family = a.os_family)
          ORDER BY p.enabled DESC, lower(p.name)",
    )
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    for r in &mut rows {
        let client: Option<Uuid> = sqlx::query_scalar("SELECT client_id FROM alert_policies WHERE id = $1").bind(r.id).fetch_one(&st.db).await?;
        r.editable = super::scripts::may_edit(&u, client).is_ok();
    }
    Ok(Json(rows))
}
