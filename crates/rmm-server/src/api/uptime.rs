//! Uptime monitors: CRUD, "check now", history and a summary. See [`crate::uptime`] and
//! docs/design/uptime.md. Reads: anyone who can see the client; changes: technicians, audited
//! as `uptime.*`.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::AssertSqlSafe;
use uuid::Uuid;

use crate::auth::{self, Role, User};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use crate::uptime;

#[derive(Serialize, sqlx::FromRow)]
pub struct MonitorRow {
    id: Uuid,
    client_id: Uuid,
    client_name: String,
    site_id: Uuid,
    site_name: String,
    name: String,
    kind: String,
    config: Value,
    runner: String,
    /// The agent the monitor names; None: the site's designated agent.
    agent_id: Option<Uuid>,
    /// The agent that runs it now (None when the server does).
    runner_agent_id: Option<Uuid>,
    runner_hostname: Option<String>,
    runner_online: bool,
    interval_secs: i32,
    timeout_secs: i32,
    enabled: bool,
    state: String,
    state_since: DateTime<Utc>,
    fail_count: i32,
    last_at: Option<DateTime<Utc>>,
    last_ms: Option<i32>,
    last_message: Option<String>,
    last_value: Option<f64>,
    cert_not_after: Option<DateTime<Utc>>,
    cert: Option<Value>,
    created_at: DateTime<Utc>,
    open_alerts: i64,
    #[sqlx(skip)]
    target: String,
    /// Percent of checks that passed.
    #[sqlx(skip)]
    uptime_24h: Option<f64>,
    #[sqlx(skip)]
    uptime_30d: Option<f64>,
}

const SELECT: &str = "SELECT * FROM (
  SELECT m.id, m.client_id, c.name AS client_name, m.site_id, s.name AS site_name, m.name, m.kind, m.config, m.runner, m.agent_id,
         a.id AS runner_agent_id, a.hostname AS runner_hostname, CASE WHEN m.runner = 'server' THEN true ELSE coalesce(a.online, false) END AS runner_online,
         m.interval_secs, m.timeout_secs, m.enabled, m.state, m.state_since, m.fail_count, m.last_at, m.last_ms, m.last_message, m.last_value,
         m.cert_not_after, m.cert, m.created_at,
         (SELECT count(*) FROM alerts al WHERE al.monitor_id = m.id AND al.resolved_at IS NULL) AS open_alerts
    FROM uptime_monitors m JOIN sites s ON s.id = m.site_id JOIN clients c ON c.id = m.client_id
         LEFT JOIN site_network sn ON sn.site_id = m.site_id LEFT JOIN agents a ON a.id = coalesce(m.agent_id, sn.agent_id) AND m.runner = 'agent'
   WHERE ($1::uuid[] IS NULL OR m.client_id = ANY($1)) AND ($2::uuid IS NULL OR m.client_id = $2) AND ($3::uuid IS NULL OR m.site_id = $3)
) x";

async fn with_availability(st: &AppState, mut rows: Vec<MonitorRow>) -> ApiResult<Vec<MonitorRow>> {
    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    let now = Utc::now();
    let day = uptime::availability(&st.db, &ids, now - Duration::hours(24)).await?;
    let month = uptime::availability(&st.db, &ids, now - Duration::days(30)).await?;
    for r in &mut rows {
        r.target = uptime::target(&r.kind, &r.config);
        r.uptime_24h = day.get(&r.id).and_then(|(c, f)| uptime::percent(*c, *f));
        r.uptime_30d = month.get(&r.id).and_then(|(c, f)| uptime::percent(*c, *f));
    }
    Ok(rows)
}

async fn monitor_client(st: &AppState, u: &User, id: Uuid) -> ApiResult<Uuid> {
    let c: Option<Uuid> = sqlx::query_scalar("SELECT client_id FROM uptime_monitors WHERE id = $1").bind(id).fetch_optional(&st.db).await?;
    c.filter(|c| u.can_see_client(*c)).ok_or(ApiError::NotFound("monitor"))
}

#[derive(Deserialize)]
pub struct ListQuery {
    client_id: Option<Uuid>,
    site_id: Option<Uuid>,
    /// `up`, `down` or `unknown`.
    state: Option<String>,
    kind: Option<String>,
    q: Option<String>,
}

pub async fn list(State(st): State<Arc<AppState>>, u: User, Query(q): Query<ListQuery>) -> ApiResult<Json<Vec<MonitorRow>>> {
    if let Some(c) = q.client_id {
        super::access::client(&u, c)?;
    }
    let pat = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(|s| format!("%{}%", s.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")));
    let rows: Vec<MonitorRow> = sqlx::query_as(AssertSqlSafe(format!(
        "{SELECT} WHERE ($4::text IS NULL OR x.state = $4) AND ($5::text IS NULL OR x.kind = $5)
            AND ($6::text IS NULL OR x.name ILIKE $6 OR x.config::text ILIKE $6 OR x.client_name ILIKE $6)
          ORDER BY CASE WHEN NOT x.enabled THEN 3 WHEN x.state = 'down' THEN 0 WHEN x.state = 'unknown' THEN 1 ELSE 2 END, lower(x.name) LIMIT 2000"
    )))
    .bind(u.scope())
    .bind(q.client_id)
    .bind(q.site_id)
    .bind(q.state.filter(|s| !s.is_empty()))
    .bind(q.kind.filter(|s| !s.is_empty()))
    .bind(pat)
    .fetch_all(&st.db)
    .await?;
    Ok(Json(with_availability(&st, rows).await?))
}

#[derive(Serialize)]
pub struct Detail {
    #[serde(flatten)]
    monitor: MonitorRow,
    /// The last 90 days (UTC), oldest first: checks and failures per day.
    days: Vec<Value>,
    alerts: Vec<Value>,
    /// The latest results, newest first.
    recent: Vec<Value>,
}

pub async fn get(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Detail>> {
    monitor_client(&st, &u, id).await?;
    let rows: Vec<MonitorRow> = sqlx::query_as(AssertSqlSafe(format!("{SELECT} WHERE x.id = $4"))).bind(u.scope()).bind(None::<Uuid>).bind(None::<Uuid>).bind(id).fetch_all(&st.db).await?;
    let monitor = with_availability(&st, rows).await?.pop().ok_or(ApiError::NotFound("monitor"))?;
    let days: Vec<(DateTime<Utc>, i64, i64)> = sqlx::query_as(
        "WITH h AS (SELECT hour, checks, failures FROM uptime_hourly WHERE monitor_id = $1 AND hour >= date_trunc('day', now()) - interval '89 days'),
              r AS (SELECT date_trunc('hour', ts) AS hour, count(*)::int AS checks, (count(*) FILTER (WHERE NOT ok))::int AS failures
                      FROM uptime_results WHERE monitor_id = $1
                       AND ts >= coalesce((SELECT max(hour) + interval '1 hour' FROM h), date_trunc('day', now()) - interval '89 days') GROUP BY 1)
         SELECT date_trunc('day', hour, 'UTC') AS day, sum(checks)::bigint, sum(failures)::bigint FROM (SELECT * FROM h UNION ALL SELECT * FROM r) x GROUP BY 1 ORDER BY 1",
    )
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    let days = days.into_iter().map(|(day, checks, failures)| json!({ "day": day, "checks": checks, "failures": failures, "uptime": uptime::percent(checks, failures) })).collect();
    type AlertRow = (Uuid, String, String, String, DateTime<Utc>, Option<DateTime<Utc>>);
    let alerts: Vec<AlertRow> = sqlx::query_as(
        "SELECT id, title, severity, kind, opened_at, acknowledged_at FROM alerts WHERE monitor_id = $1 AND resolved_at IS NULL ORDER BY opened_at DESC LIMIT 50",
    )
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    let alerts = alerts.into_iter().map(|(id, title, severity, kind, opened_at, ack)| json!({ "id": id, "title": title, "severity": severity, "kind": kind, "opened_at": opened_at, "acknowledged_at": ack })).collect();
    let recent: Vec<(DateTime<Utc>, bool, Option<i32>, String)> =
        sqlx::query_as("SELECT ts, ok, ms, message FROM uptime_results WHERE monitor_id = $1 ORDER BY ts DESC LIMIT 20").bind(id).fetch_all(&st.db).await?;
    let recent = recent.into_iter().map(|(ts, ok, ms, message)| json!({ "ts": ts, "ok": ok, "ms": ms, "message": message })).collect();
    Ok(Json(Detail { monitor, days, alerts, recent }))
}

#[derive(Deserialize)]
pub struct MonitorIn {
    site_id: Option<Uuid>,
    name: Option<String>,
    kind: Option<String>,
    config: Option<Value>,
    runner: Option<String>,
    /// None (or absent): the site's designated agent.
    #[serde(default, with = "double_option")]
    agent_id: Option<Option<Uuid>>,
    interval_secs: Option<i32>,
    timeout_secs: Option<i32>,
    enabled: Option<bool>,
}

/// Tells "absent" (keep) from `null` (clear) for an optional field.
mod double_option {
    use serde::{Deserialize, Deserializer};
    pub fn deserialize<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<Option<T>>, D::Error> {
        Ok(Some(Option::deserialize(d)?))
    }
}

struct Valid {
    site_id: Uuid,
    client_id: Uuid,
    name: String,
    kind: String,
    config: Value,
    /// `agent` or `server`.
    runner: String,
    agent_id: Option<Uuid>,
    interval_secs: i32,
    timeout_secs: i32,
    enabled: bool,
}

/// Checks a monitor as it would be after `b` is applied to `old` (None: a new one).
async fn validate(st: &AppState, u: &User, b: MonitorIn, old: Option<Valid>) -> ApiResult<Valid> {
    let bad = |m: String| ApiError::BadRequest(m);
    let site_id = b.site_id.or(old.as_ref().map(|o| o.site_id)).ok_or_else(|| bad("pick a site".into()))?;
    let client_id = super::access::site(st, u, site_id).await?;
    if old.as_ref().is_some_and(|o| o.client_id != client_id) {
        return Err(bad("a monitor can't move to another client".into()));
    }
    let name = b.name.map(|n| n.trim().to_string()).or(old.as_ref().map(|o| o.name.clone())).unwrap_or_default();
    if name.is_empty() || name.chars().count() > 100 {
        return Err(bad("name must be 1-100 characters".into()));
    }
    let kind = b.kind.or(old.as_ref().map(|o| o.kind.clone())).unwrap_or_default();
    let config = b.config.or(old.as_ref().map(|o| o.config.clone())).unwrap_or(json!({}));
    let check = uptime::check_kind(&kind, &config).map_err(bad)?;
    let runner = b.runner.or(old.as_ref().map(|o| o.runner.clone())).unwrap_or_else(|| "agent".into());
    if !matches!(runner.as_str(), "agent" | "server") {
        return Err(bad(format!("unknown runner {runner:?}")));
    }
    let agent_id = match b.agent_id {
        Some(a) => a,
        None => old.as_ref().and_then(|o| o.agent_id),
    };
    // The server runs it: no agent, and (unless allowed) no address it may not reach.
    let agent_id = if runner == "server" {
        if !st.cfg.uptime_allow_private {
            uptime::refuse_private_literal(&check).map_err(bad)?;
        }
        None
    } else {
        agent_id
    };
    if let Some(a) = agent_id {
        let c: Option<Uuid> = sqlx::query_scalar("SELECT s.client_id FROM agents a JOIN sites s ON s.id = a.site_id WHERE a.id = $1").bind(a).fetch_optional(&st.db).await?;
        if c != Some(client_id) {
            return Err(bad("the agent must belong to the monitor's client".into()));
        }
    }
    let interval_secs = b.interval_secs.or(old.as_ref().map(|o| o.interval_secs)).unwrap_or(60);
    if !(30..=86400).contains(&interval_secs) {
        return Err(bad("the interval must be 30-86400 seconds".into()));
    }
    let timeout_secs = b.timeout_secs.or(old.as_ref().map(|o| o.timeout_secs)).unwrap_or(10);
    if !(1..=120).contains(&timeout_secs) || timeout_secs > interval_secs {
        return Err(bad("the timeout must be 1-120 seconds, and no longer than the interval".into()));
    }
    let enabled = b.enabled.or(old.as_ref().map(|o| o.enabled)).unwrap_or(true);
    Ok(Valid { site_id, client_id, name, kind, config: uptime::clean_config(&check), runner, agent_id, interval_secs, timeout_secs, enabled })
}

fn conflict(e: sqlx::Error) -> ApiError {
    match &e {
        sqlx::Error::Database(d) if d.constraint().is_some_and(|c| c.contains("name")) => ApiError::Conflict("the client already has a monitor with that name".into()),
        _ => e.into(),
    }
}

pub async fn create(State(st): State<Arc<AppState>>, u: User, Json(b): Json<MonitorIn>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    let v = validate(&st, &u, b, None).await?;
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO uptime_monitors (id, client_id, site_id, name, kind, config, agent_id, interval_secs, timeout_secs, enabled, created_by, runner)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
    )
    .bind(id)
    .bind(v.client_id)
    .bind(v.site_id)
    .bind(&v.name)
    .bind(&v.kind)
    .bind(&v.config)
    .bind(v.agent_id)
    .bind(v.interval_secs)
    .bind(v.timeout_secs)
    .bind(v.enabled)
    .bind(u.id)
    .bind(&v.runner)
    .execute(&st.db)
    .await
    .map_err(conflict)?;
    auth::audit(
        &st.db,
        Some(u.id),
        "uptime.create",
        Some(("uptime_monitor", id)),
        json!({ "name": v.name, "kind": v.kind, "runner": v.runner, "target": uptime::target(&v.kind, &v.config) }),
    )
    .await;
    if let Some(r) = uptime::runner_of(&st, id).await? {
        crate::checks::push(&st, Some(&[r]), &[id]).await;
    }
    if v.runner == "server" && v.enabled {
        uptime::run_server_now(&st, id);
    }
    Ok(Json(json!({ "id": id })))
}

async fn load(st: &AppState, id: Uuid) -> ApiResult<(Valid, Option<Uuid>)> {
    type Row = (Uuid, Uuid, String, String, Value, Option<Uuid>, i32, i32, bool, String);
    let r: Row = sqlx::query_as("SELECT site_id, client_id, name, kind, config, agent_id, interval_secs, timeout_secs, enabled, runner FROM uptime_monitors WHERE id = $1")
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("monitor"))?;
    let runner = uptime::runner_of(st, id).await?;
    Ok((Valid { site_id: r.0, client_id: r.1, name: r.2, kind: r.3, config: r.4, agent_id: r.5, interval_secs: r.6, timeout_secs: r.7, enabled: r.8, runner: r.9 }, runner))
}

pub async fn update(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<MonitorIn>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    monitor_client(&st, &u, id).await?;
    let (old, old_runner) = load(&st, id).await?;
    let (was_enabled, old_kind, old_runner_kind) = (old.enabled, old.kind.clone(), old.runner.clone());
    let v = validate(&st, &u, b, Some(old)).await?;
    sqlx::query(
        "UPDATE uptime_monitors SET site_id = $2, name = $3, kind = $4, config = $5, agent_id = $6, interval_secs = $7, timeout_secs = $8,
                enabled = $9, runner = $10, updated_at = now(),
                state = CASE WHEN $9 AND kind = $4 AND runner = $10 THEN state ELSE 'unknown' END,
                fail_count = CASE WHEN $9 AND kind = $4 AND runner = $10 THEN fail_count ELSE 0 END,
                cert_not_after = CASE WHEN kind = $4 THEN cert_not_after END, cert = CASE WHEN kind = $4 THEN cert END
          WHERE id = $1",
    )
    .bind(id)
    .bind(v.site_id)
    .bind(&v.name)
    .bind(&v.kind)
    .bind(&v.config)
    .bind(v.agent_id)
    .bind(v.interval_secs)
    .bind(v.timeout_secs)
    .bind(v.enabled)
    .bind(&v.runner)
    .execute(&st.db)
    .await
    .map_err(conflict)?;
    if (was_enabled && !v.enabled) || old_kind != v.kind {
        uptime::close_monitor(&st, id).await;
    }
    auth::audit(
        &st.db,
        Some(u.id),
        "uptime.update",
        Some(("uptime_monitor", id)),
        json!({ "name": v.name, "kind": v.kind, "runner": v.runner, "enabled": v.enabled }),
    )
    .await;
    let runner = uptime::runner_of(&st, id).await?;
    let agents: Vec<Uuid> = old_runner.into_iter().chain(runner).collect();
    crate::checks::push(&st, Some(&agents), &[id]).await;
    uptime::evaluate(&st, id).await;
    if v.runner == "server" && v.enabled && (old_runner_kind != v.runner || !was_enabled || old_kind != v.kind) {
        uptime::run_server_now(&st, id);
    }
    Ok(Json(json!({ "ok": true })))
}

pub async fn remove(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    monitor_client(&st, &u, id).await?;
    let runner = uptime::runner_of(&st, id).await?;
    // Quietly, before the rows go (the cascade would delete them unannounced).
    uptime::close_monitor(&st, id).await;
    let name: Option<String> = sqlx::query_scalar("DELETE FROM uptime_monitors WHERE id = $1 RETURNING name").bind(id).fetch_optional(&st.db).await?;
    auth::audit(&st.db, Some(u.id), "uptime.delete", Some(("uptime_monitor", id)), json!({ "name": name })).await;
    if let Some(r) = runner {
        crate::checks::push(&st, Some(&[r]), &[]).await;
    }
    Ok(Json(json!({ "ok": true })))
}

pub async fn check_now(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    monitor_client(&st, &u, id).await?;
    let row: (bool, Option<Uuid>, bool, bool, bool) = sqlx::query_as(
        "SELECT m.enabled, a.id, coalesce(a.online, false), coalesce($2 = ANY(a.capabilities), false), m.runner = 'server'
           FROM uptime_monitors m LEFT JOIN site_network sn ON sn.site_id = m.site_id LEFT JOIN agents a ON a.id = coalesce(m.agent_id, sn.agent_id)
          WHERE m.id = $1",
    )
    .bind(id)
    .bind(rmm_proto::checks::CAPABILITY)
    .fetch_one(&st.db)
    .await?;
    if row.0 && row.4 {
        uptime::run_server_now(&st, id);
        auth::audit(&st.db, Some(u.id), "uptime.check", Some(("uptime_monitor", id)), json!({})).await;
        return Ok(Json(json!({ "ok": true })));
    }
    let agent = match (row.0, row.1, row.2, row.3) {
        (false, ..) => return Err(ApiError::Conflict("the monitor is switched off".into())),
        (_, None, ..) => return Err(ApiError::Conflict("no agent runs this monitor: pick one, or designate one for the site".into())),
        (_, Some(_), false, _) => return Err(ApiError::Conflict("the agent that runs this monitor is offline".into())),
        (_, Some(_), _, false) => return Err(ApiError::Conflict("the agent that runs this monitor is too old to run checks; update it".into())),
        (_, Some(a), true, true) => a,
    };
    crate::checks::push(&st, Some(&[agent]), &[id]).await;
    auth::audit(&st.db, Some(u.id), "uptime.check", Some(("uptime_monitor", id)), json!({})).await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct RangeQuery {
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct Point {
    ts: DateTime<Utc>,
    checks: i64,
    failures: i64,
    avg_ms: Option<f64>,
    max_ms: Option<i32>,
}

/// About 500 points over `from`-`to` (default the last 24 hours): raw results up to 48 hours
/// back, hourly rollups beyond.
pub async fn results(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Query(q): Query<RangeQuery>) -> ApiResult<Json<Vec<Point>>> {
    monitor_client(&st, &u, id).await?;
    let to = q.to.unwrap_or_else(Utc::now);
    let from = q.from.unwrap_or(to - Duration::hours(24));
    if from >= to || to - from > Duration::days(400) {
        return Err(ApiError::BadRequest("from must be before to, and at most 400 days before it".into()));
    }
    let secs = (to - from).num_seconds();
    let raw = from >= Utc::now() - Duration::hours(48);
    let bucket = (secs / 500).max(if raw { 60 } else { 3600 });
    let bucket = if raw { bucket } else { bucket / 3600 * 3600 };
    let sql = if raw {
        "SELECT to_timestamp(floor(extract(epoch FROM ts) / $4) * $4) AS ts, count(*) AS checks, count(*) FILTER (WHERE NOT ok) AS failures,
                (avg(ms) FILTER (WHERE ok))::float8 AS avg_ms, max(ms) FILTER (WHERE ok) AS max_ms
           FROM uptime_results WHERE monitor_id = $1 AND ts >= $2 AND ts < $3 GROUP BY 1 ORDER BY 1"
    } else {
        "SELECT to_timestamp(floor(extract(epoch FROM hour) / $4) * $4) AS ts, sum(checks)::bigint AS checks, sum(failures)::bigint AS failures,
                (sum(avg_ms * (checks - failures)) / nullif(sum(checks - failures), 0))::float8 AS avg_ms, max(max_ms) AS max_ms
           FROM uptime_hourly WHERE monitor_id = $1 AND hour >= $2 AND hour < $3 GROUP BY 1 ORDER BY 1"
    };
    Ok(Json(sqlx::query_as(sql).bind(id).bind(from).bind(to).bind(bucket as f64).fetch_all(&st.db).await?))
}

#[derive(Deserialize)]
pub struct SummaryQuery {
    client_id: Option<Uuid>,
}

pub async fn summary(State(st): State<Arc<AppState>>, u: User, Query(q): Query<SummaryQuery>) -> ApiResult<Json<Value>> {
    if let Some(c) = q.client_id {
        super::access::client(&u, c)?;
    }
    let (total, up, down, unknown, disabled, ids): (i64, i64, i64, i64, i64, Vec<Uuid>) = sqlx::query_as(
        "SELECT count(*), count(*) FILTER (WHERE enabled AND state = 'up'), count(*) FILTER (WHERE enabled AND state = 'down'),
                count(*) FILTER (WHERE enabled AND state = 'unknown'), count(*) FILTER (WHERE NOT enabled), coalesce(array_agg(id), '{}')
           FROM uptime_monitors WHERE ($1::uuid[] IS NULL OR client_id = ANY($1)) AND ($2::uuid IS NULL OR client_id = $2)",
    )
    .bind(u.scope())
    .bind(q.client_id)
    .fetch_one(&st.db)
    .await?;
    let month = uptime::availability(&st.db, &ids, Utc::now() - Duration::days(30)).await?;
    let (c, f) = month.values().fold((0, 0), |(c, f), (a, b)| (c + a, f + b));
    Ok(Json(json!({ "monitors": total, "up": up, "down": down, "unknown": unknown, "disabled": disabled, "uptime_30d": uptime::percent(c, f) })))
}
