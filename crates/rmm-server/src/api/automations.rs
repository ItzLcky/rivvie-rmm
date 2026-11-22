//! What automations did (docs/design/automations.md): an agent's history, an automation's
//! per-device state, and the reset that lets a run-once automation run again. The automations
//! themselves are `automation` items of the policy sets and are edited there
//! (`api::policies`).

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::auth::{self, User};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

use super::policies::{fetch_item, may_edit_item};

#[derive(Serialize, sqlx::FromRow)]
pub struct RunRow {
    id: Uuid,
    item_id: Uuid,
    item_name: String,
    agent_id: Uuid,
    hostname: String,
    /// enrollment, agent_online, alert_opened, patch_reboot_pending or run_once.
    trigger: String,
    /// waiting, pending, succeeded, failed or skipped.
    status: String,
    /// Why it waits, was skipped or failed: maintenance_window, rate_limited, cooldown,
    /// expired, no_longer_applies, script_missing, or the job's own end (timed_out, lost, ...).
    reason: Option<String>,
    /// What fired it (the alert, the patch run, how long the agent was offline).
    context: Value,
    job_id: Option<Uuid>,
    script_id: Option<Uuid>,
    script_name: Option<String>,
    exit_code: Option<i32>,
    attempts: i32,
    created_at: DateTime<Utc>,
    started_at: Option<DateTime<Utc>>,
    finished_at: Option<DateTime<Utc>>,
}

const COLS: &str = "r.id, r.item_id, i.name AS item_name, r.agent_id, a.hostname, r.trigger, r.status, r.reason, r.context, r.job_id,
       (i.config ->> 'script_id')::uuid AS script_id, sc.name AS script_name, j.exit_code, r.attempts, r.created_at, r.started_at, r.finished_at";
const FROM: &str = "FROM automation_runs r JOIN policy_items i ON i.id = r.item_id JOIN agents a ON a.id = r.agent_id JOIN sites s ON s.id = a.site_id
       LEFT JOIN jobs j ON j.id = r.job_id LEFT JOIN scripts sc ON sc.id = (i.config ->> 'script_id')::uuid";

/// `GET /agents/{id}/automations`: the latest 200 runs on the agent, newest first.
pub async fn for_agent(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Vec<RunRow>>> {
    super::access::agent(&st, &u, id).await?;
    let sql = format!("SELECT {COLS} {FROM} WHERE r.agent_id = $1 ORDER BY r.created_at DESC LIMIT 200");
    Ok(Json(sqlx::query_as(sqlx::AssertSqlSafe(sql)).bind(id).fetch_all(&st.db).await?))
}

#[derive(Deserialize)]
pub struct RunsQuery {
    /// One of the statuses.
    status: Option<String>,
    /// Hostname.
    q: Option<String>,
    limit: Option<i64>,
}

#[derive(Serialize)]
pub struct ItemRuns {
    /// Runs per status, on the agents the user can see.
    counts: Value,
    runs: Vec<RunRow>,
}

/// `GET /policy-items/{id}/runs`: every device's state for an automation (for the once-per-device
/// triggers one row each; event triggers list their runs, newest first).
pub async fn for_item(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Query(q): Query<RunsQuery>) -> ApiResult<Json<ItemRuns>> {
    let item = fetch_item(&st, &u, id).await?;
    if item.module != "automation" {
        return Err(ApiError::NotFound("automation"));
    }
    if q.status.as_deref().is_some_and(|s| !["waiting", "pending", "succeeded", "failed", "skipped"].contains(&s)) {
        return Err(ApiError::BadRequest("status is waiting, pending, succeeded, failed or skipped".into()));
    }
    let search = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let filter = "WHERE r.item_id = $1 AND ($2::uuid[] IS NULL OR s.client_id = ANY($2))";
    let sql = format!(
        "SELECT {COLS} {FROM} {filter} AND ($3::text IS NULL OR r.status = $3) AND ($4::text IS NULL OR a.hostname ILIKE '%' || $4 || '%')
          ORDER BY r.created_at DESC, r.id LIMIT $5"
    );
    let runs: Vec<RunRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(id)
        .bind(u.scope())
        .bind(q.status.as_deref())
        .bind(search)
        .bind(q.limit.unwrap_or(200).clamp(1, 1000))
        .fetch_all(&st.db)
        .await?;
    let counts: Value = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT jsonb_build_object('waiting', count(*) FILTER (WHERE r.status = 'waiting'), 'pending', count(*) FILTER (WHERE r.status = 'pending'),
                                   'succeeded', count(*) FILTER (WHERE r.status = 'succeeded'), 'failed', count(*) FILTER (WHERE r.status = 'failed'),
                                   'skipped', count(*) FILTER (WHERE r.status = 'skipped'))
           {FROM} {filter}"
    )))
    .bind(id)
    .bind(u.scope())
    .fetch_one(&st.db)
    .await?;
    Ok(Json(ItemRuns { counts, runs }))
}

#[derive(Deserialize)]
pub struct ResetBody {
    /// These devices only; omitted: every device the user can see.
    agent_ids: Option<Vec<Uuid>>,
    /// Only the devices where it failed (the retry button), not the ones where it succeeded.
    #[serde(default)]
    failed_only: bool,
}

/// `POST /policy-items/{id}/runs/reset`: forgets the run of a run-once automation on these
/// devices (runs still in flight are left alone), so the next worker pass runs it again,
/// within the automation's hourly budget.
pub async fn reset(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<ResetBody>) -> ApiResult<Json<Value>> {
    may_edit_item(&st, &u, id).await?;
    let item = fetch_item(&st, &u, id).await?;
    if item.module != "automation" || item.config.get("trigger").and_then(Value::as_str) != Some("run_once") {
        return Err(ApiError::BadRequest("only run-once automations can be reset: the other triggers fire on events".into()));
    }
    if b.agent_ids.as_ref().is_some_and(|a| a.is_empty() || a.len() > 10000) {
        return Err(ApiError::BadRequest("agent_ids must name 1-10000 devices, or be left out for all of them".into()));
    }
    let n = sqlx::query(
        "DELETE FROM automation_runs r USING agents a, sites s
          WHERE a.id = r.agent_id AND s.id = a.site_id AND r.item_id = $1 AND r.status NOT IN ('pending')
            AND ($2::uuid[] IS NULL OR s.client_id = ANY($2)) AND ($3::uuid[] IS NULL OR r.agent_id = ANY($3))
            AND (NOT $4 OR r.status = 'failed')",
    )
    .bind(id)
    .bind(u.scope())
    .bind(b.agent_ids.as_deref())
    .bind(b.failed_only)
    .execute(&st.db)
    .await?
    .rows_affected();
    auth::audit(
        &st.db,
        Some(u.id),
        "automation.reset",
        Some(("policy", id)),
        json!({ "name": item.name, "devices": n, "failed_only": b.failed_only, "agent_ids": b.agent_ids.as_ref().map(Vec::len) }),
    )
    .await;
    Ok(Json(json!({ "reset": n })))
}
