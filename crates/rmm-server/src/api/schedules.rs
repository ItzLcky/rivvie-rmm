//! Scheduled scripts.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::AssertSqlSafe;
use uuid::Uuid;

use crate::auth::{self, User};
use crate::error::{ApiError, ApiResult};
use crate::scheduler;
use crate::state::AppState;

#[derive(Serialize, sqlx::FromRow)]
pub struct ScheduleRow {
    id: Uuid,
    name: String,
    script_id: Uuid,
    script_name: String,
    interpreter: String,
    client_id: Option<Uuid>,
    client_name: Option<String>,
    site_id: Option<Uuid>,
    site_name: Option<String>,
    os_family: Option<String>,
    cron: String,
    timezone: String,
    args: Value,
    timeout_secs: Option<i32>,
    retain_days: i32,
    enabled: bool,
    next_run_at: Option<DateTime<Utc>>,
    last_run_at: Option<DateTime<Utc>>,
    /// Job statuses of the latest run, e.g. {"succeeded": 12, "failed": 1}.
    last_run: Value,
    created_by_name: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

const SELECT: &str = "SELECT sc.id, sc.name, sc.script_id, s.name AS script_name, s.interpreter, sc.client_id, c.name AS client_name,
       sc.site_id, si.name AS site_name, sc.os_family, sc.cron, sc.timezone, sc.args, sc.timeout_secs, sc.retain_days, sc.enabled,
       sc.next_run_at, sc.last_run_at,
       coalesce((SELECT jsonb_object_agg(status, n) FROM (
           SELECT j.status, count(*) n FROM jobs j
            WHERE j.schedule_id = sc.id AND sc.last_run_at IS NOT NULL AND j.created_at >= sc.last_run_at - interval '1 minute'
            GROUP BY 1) t), '{}') AS last_run,
       u.name AS created_by_name, sc.created_at, sc.updated_at
  FROM schedules sc JOIN scripts s ON s.id = sc.script_id LEFT JOIN clients c ON c.id = sc.client_id
  LEFT JOIN sites si ON si.id = sc.site_id LEFT JOIN users u ON u.id = sc.created_by";
/// MSP-wide schedules plus those of the clients the user can see ($1 NULL = all).
const VISIBLE: &str = "(sc.client_id IS NULL OR $1::uuid[] IS NULL OR sc.client_id = ANY($1))";

async fn fetch(st: &AppState, u: &User, id: Uuid) -> ApiResult<ScheduleRow> {
    sqlx::query_as(AssertSqlSafe(format!("{SELECT} WHERE {VISIBLE} AND sc.id = $2")))
        .bind(u.scope())
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("schedule"))
}

pub async fn list(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Vec<ScheduleRow>>> {
    Ok(Json(
        sqlx::query_as(AssertSqlSafe(format!("{SELECT} WHERE {VISIBLE} ORDER BY lower(sc.name), c.name NULLS FIRST")))
            .bind(u.scope())
            .fetch_all(&st.db)
            .await?,
    ))
}

pub async fn get(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<ScheduleRow>> {
    Ok(Json(fetch(&st, &u, id).await?))
}

#[derive(Deserialize)]
pub struct ScheduleIn {
    name: String,
    script_id: Uuid,
    client_id: Option<Uuid>,
    site_id: Option<Uuid>,
    os_family: Option<String>,
    cron: String,
    #[serde(default = "utc")]
    timezone: String,
    #[serde(default)]
    args: Vec<String>,
    timeout_secs: Option<i32>,
    #[serde(default = "thirty")]
    retain_days: i32,
    #[serde(default = "yes")]
    enabled: bool,
}

fn utc() -> String {
    "UTC".into()
}
fn thirty() -> i32 {
    30
}
fn yes() -> bool {
    true
}

impl ScheduleIn {
    /// Returns the next run time.
    async fn validate(&self, st: &AppState, u: &User) -> ApiResult<DateTime<Utc>> {
        let name = self.name.trim();
        if name.is_empty() || name.chars().count() > 200 {
            return Err(ApiError::BadRequest("name must be 1-200 characters".into()));
        }
        if !(1..=3650).contains(&self.retain_days) {
            return Err(ApiError::BadRequest("keep runs for 1-3650 days".into()));
        }
        if self.timeout_secs.is_some_and(|t| !(1..=86400).contains(&t)) {
            return Err(ApiError::BadRequest("timeout must be 1-86400 seconds".into()));
        }
        if self.args.len() > 50 {
            return Err(ApiError::BadRequest("at most 50 arguments".into()));
        }
        super::alerts::check_target(st, u, self.client_id, self.site_id, self.os_family.as_deref()).await?;
        // The same rule as running a script by hand: a client's script only on its own agents.
        let script_client: Option<Option<Uuid>> =
            sqlx::query_scalar("SELECT client_id FROM scripts WHERE id = $1").bind(self.script_id).fetch_optional(&st.db).await?;
        match script_client {
            None => return Err(ApiError::NotFound("script")),
            Some(Some(c)) if !u.can_see_client(c) => return Err(ApiError::NotFound("script")),
            Some(Some(c)) if self.client_id != Some(c) => {
                return Err(ApiError::BadRequest("that script belongs to another client".into()));
            }
            _ => {}
        }
        scheduler::next_run(&self.cron, &self.timezone, Utc::now()).map_err(ApiError::BadRequest)
    }
}

pub async fn create(State(st): State<Arc<AppState>>, u: User, Json(b): Json<ScheduleIn>) -> ApiResult<Json<ScheduleRow>> {
    super::scripts::may_edit(&u, b.client_id)?;
    let next = b.validate(&st, &u).await?;
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO schedules (id, name, script_id, client_id, site_id, os_family, cron, timezone, args, timeout_secs, retain_days,
                                enabled, next_run_at, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
    )
    .bind(id)
    .bind(b.name.trim())
    .bind(b.script_id)
    .bind(b.client_id)
    .bind(b.site_id)
    .bind(&b.os_family)
    .bind(b.cron.trim())
    .bind(b.timezone.trim())
    .bind(json!(b.args))
    .bind(b.timeout_secs)
    .bind(b.retain_days)
    .bind(b.enabled)
    .bind(next)
    .bind(u.id)
    .execute(&st.db)
    .await?;
    auth::audit(&st.db, Some(u.id), "schedule.create", Some(("schedule", id)), json!({ "name": b.name.trim(), "cron": b.cron })).await;
    Ok(Json(fetch(&st, &u, id).await?))
}

pub async fn update(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<ScheduleIn>) -> ApiResult<Json<ScheduleRow>> {
    let current = fetch(&st, &u, id).await?;
    super::scripts::may_edit(&u, current.client_id)?;
    super::scripts::may_edit(&u, b.client_id)?;
    let next = b.validate(&st, &u).await?;
    sqlx::query(
        "UPDATE schedules SET name = $2, script_id = $3, client_id = $4, site_id = $5, os_family = $6, cron = $7, timezone = $8,
                args = $9, timeout_secs = $10, retain_days = $11, enabled = $12, next_run_at = $13, updated_at = now()
          WHERE id = $1",
    )
    .bind(id)
    .bind(b.name.trim())
    .bind(b.script_id)
    .bind(b.client_id)
    .bind(b.site_id)
    .bind(&b.os_family)
    .bind(b.cron.trim())
    .bind(b.timezone.trim())
    .bind(json!(b.args))
    .bind(b.timeout_secs)
    .bind(b.retain_days)
    .bind(b.enabled)
    .bind(next)
    .execute(&st.db)
    .await?;
    auth::audit(&st.db, Some(u.id), "schedule.update", Some(("schedule", id)), json!({ "name": b.name.trim(), "enabled": b.enabled }))
        .await;
    Ok(Json(fetch(&st, &u, id).await?))
}

pub async fn remove(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let current = fetch(&st, &u, id).await?;
    super::scripts::may_edit(&u, current.client_id)?;
    sqlx::query("DELETE FROM schedules WHERE id = $1").bind(id).execute(&st.db).await?;
    auth::audit(&st.db, Some(u.id), "schedule.delete", Some(("schedule", id)), json!({ "name": current.name })).await;
    Ok(Json(json!({ "ok": true })))
}

/// Runs the schedule now, outside its cadence (the next scheduled run is unchanged).
pub async fn run_now(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<scheduler::RunResult>> {
    let current = fetch(&st, &u, id).await?;
    super::scripts::may_edit(&u, current.client_id)?;
    sqlx::query("UPDATE schedules SET last_run_at = now() WHERE id = $1").bind(id).execute(&st.db).await?;
    let result = scheduler::run_schedule(&st, id, Some(u.id)).await?;
    auth::audit(&st.db, Some(u.id), "schedule.run", Some(("schedule", id)), json!({ "sent": result.sent, "queued": result.queued })).await;
    Ok(Json(result))
}

#[derive(Deserialize)]
pub struct Preview {
    cron: String,
    #[serde(default = "utc")]
    timezone: String,
}

/// The next five run times of a cron expression, for the editor.
pub async fn preview(_u: User, axum::extract::Query(q): axum::extract::Query<Preview>) -> ApiResult<Json<Value>> {
    let mut at = Utc::now();
    let mut runs = Vec::new();
    for _ in 0..5 {
        match scheduler::next_run(&q.cron, &q.timezone, at) {
            Ok(t) => {
                runs.push(t);
                at = t;
            }
            Err(e) if runs.is_empty() => return Ok(Json(json!({ "error": e, "runs": [] }))),
            Err(_) => break,
        }
    }
    Ok(Json(json!({ "runs": runs })))
}
