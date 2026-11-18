//! Scheduled scripts: the `schedule` items of every policy set, read-only here (they are
//! created and edited in their set, `api::policies`), with when they ran and run next.

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
    /// The set it's defined in.
    set_id: Uuid,
    set_name: String,
    script_id: Uuid,
    script_name: String,
    interpreter: String,
    /// The limit.
    client_id: Option<Uuid>,
    client_name: Option<String>,
    site_id: Option<Uuid>,
    site_name: Option<String>,
    cron: String,
    timezone: String,
    args: Value,
    timeout_secs: Option<i32>,
    retain_days: i32,
    /// At its own set (overrides may differ below).
    enabled: bool,
    /// Agents it runs on now (enabled there, within the limit), of those the user can see.
    agents: i64,
    next_run_at: Option<DateTime<Utc>>,
    last_run_at: Option<DateTime<Utc>>,
    /// Job statuses of the latest run, e.g. {"succeeded": 12, "failed": 1}.
    last_run: Value,
    created_by_name: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

const SELECT: &str = "SELECT i.id, i.name, i.set_id, ps.name AS set_name, (i.config ->> 'script_id')::uuid AS script_id, s.name AS script_name,
       s.interpreter, i.client_id, c.name AS client_name, i.site_id, si.name AS site_name, i.config ->> 'cron' AS cron,
       coalesce(i.config ->> 'timezone', 'UTC') AS timezone, coalesce(i.config -> 'args', '[]') AS args,
       (i.config ->> 'timeout_secs')::int AS timeout_secs, coalesce((i.config ->> 'retain_days')::int, 30) AS retain_days, i.enabled,
       (SELECT count(*) FROM agent_policy ap JOIN agents xa ON xa.id = ap.agent_id JOIN sites xs ON xs.id = xa.site_id
         WHERE ap.item_id = i.id AND ap.enabled AND ($1::uuid[] IS NULL OR xs.client_id = ANY($1))) AS agents,
       ss.next_run_at, ss.last_run_at,
       coalesce((SELECT jsonb_object_agg(status, n) FROM (
           SELECT j.status, count(*) n FROM jobs j
            WHERE j.schedule_id = i.id AND ss.last_run_at IS NOT NULL AND j.created_at >= ss.last_run_at - interval '1 minute'
            GROUP BY 1) t), '{}') AS last_run,
       u.name AS created_by_name, i.created_at, i.updated_at
  FROM policy_items i JOIN policy_sets ps ON ps.id = i.set_id JOIN scripts s ON s.id = (i.config ->> 'script_id')::uuid
  LEFT JOIN policy_schedule_state ss ON ss.item_id = i.id LEFT JOIN clients c ON c.id = i.client_id
  LEFT JOIN sites si ON si.id = i.site_id LEFT JOIN users u ON u.id = i.created_by";
/// Schedules in sets the user can see, limited to clients the user can see ($1 NULL = all).
const VISIBLE: &str = "i.module = 'schedule' AND ($1::uuid[] IS NULL OR ((ps.client_id IS NULL OR ps.client_id = ANY($1))
                                                                     AND (i.client_id IS NULL OR i.client_id = ANY($1))))";

async fn fetch(st: &AppState, u: &User, id: Uuid) -> ApiResult<ScheduleRow> {
    sqlx::query_as(AssertSqlSafe(format!("{SELECT} WHERE {VISIBLE} AND i.id = $2")))
        .bind(u.scope())
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("schedule"))
}

pub async fn list(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Vec<ScheduleRow>>> {
    Ok(Json(
        sqlx::query_as(AssertSqlSafe(format!("{SELECT} WHERE {VISIBLE} ORDER BY lower(i.name), c.name NULLS FIRST")))
            .bind(u.scope())
            .fetch_all(&st.db)
            .await?,
    ))
}

pub async fn get(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<ScheduleRow>> {
    Ok(Json(fetch(&st, &u, id).await?))
}

/// Runs the schedule now, outside its cadence (the next scheduled run is unchanged). The same
/// people who may edit it may run it.
pub async fn run_now(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<scheduler::RunResult>> {
    let current = fetch(&st, &u, id).await?;
    super::policies::may_edit_item(&st, &u, id).await?;
    sqlx::query("UPDATE policy_schedule_state SET last_run_at = now() WHERE item_id = $1").bind(id).execute(&st.db).await?;
    let result = scheduler::run_schedule(&st, id, Some(u.id)).await?;
    auth::audit(
        &st.db,
        Some(u.id),
        "schedule.run",
        Some(("schedule", id)),
        json!({ "name": current.name, "sent": result.sent, "queued": result.queued }),
    )
    .await;
    Ok(Json(result))
}

#[derive(Deserialize)]
pub struct Preview {
    cron: String,
    #[serde(default = "utc")]
    timezone: String,
}

fn utc() -> String {
    "UTC".into()
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
