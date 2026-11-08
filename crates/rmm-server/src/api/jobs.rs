use std::sync::Arc;

use sqlx::AssertSqlSafe;
use axum::Json;
use axum::extract::{Path, State};
use chrono::{DateTime, Utc};
use rmm_proto::{ScriptJob, ServerMsg};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::agent_ws::parse_interpreter;
use crate::auth::{self, Role, User};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

#[derive(Serialize, sqlx::FromRow)]
pub struct JobRow {
    id: Uuid,
    agent_id: Uuid,
    hostname: String,
    script_id: Option<Uuid>,
    script_name: Option<String>,
    interpreter: String,
    status: String,
    exit_code: Option<i32>,
    created_by_name: Option<String>,
    created_at: DateTime<Utc>,
    sent_at: Option<DateTime<Utc>>,
    finished_at: Option<DateTime<Utc>>,
    duration_ms: Option<i64>,
}

const JOB_COLS: &str = "j.id, j.agent_id, a.hostname, j.script_id, sc.name AS script_name, j.interpreter, j.status, j.exit_code,
       u.name AS created_by_name, j.created_at, j.sent_at, j.finished_at, j.duration_ms";
const JOB_FROM: &str = "FROM jobs j JOIN agents a ON a.id = j.agent_id JOIN sites s ON s.id = a.site_id
       LEFT JOIN scripts sc ON sc.id = j.script_id LEFT JOIN users u ON u.id = j.created_by";

pub async fn list_for_agent(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Vec<JobRow>>> {
    super::access::agent(&st, &u, id).await?;
    let sql = format!("SELECT {JOB_COLS} {JOB_FROM} WHERE j.agent_id = $1 ORDER BY j.created_at DESC LIMIT 100");
    Ok(Json(sqlx::query_as(AssertSqlSafe(sql)).bind(id).fetch_all(&st.db).await?))
}

pub async fn list_recent(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Vec<JobRow>>> {
    let sql = format!(
        "SELECT {JOB_COLS} {JOB_FROM} WHERE ($1::uuid[] IS NULL OR s.client_id = ANY($1)) ORDER BY j.created_at DESC LIMIT 200"
    );
    Ok(Json(sqlx::query_as(AssertSqlSafe(sql)).bind(u.scope()).fetch_all(&st.db).await?))
}

#[derive(Serialize)]
pub struct JobDetail {
    #[serde(flatten)]
    row: JobRow,
    body: String,
    args: serde_json::Value,
    timeout_secs: i32,
    stdout: String,
    stderr: String,
}

pub async fn get(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<JobDetail>> {
    let sql = format!("SELECT {JOB_COLS} {JOB_FROM} WHERE j.id = $1 AND ($2::uuid[] IS NULL OR s.client_id = ANY($2))");
    let row: JobRow = sqlx::query_as(AssertSqlSafe(sql))
        .bind(id)
        .bind(u.scope())
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("job"))?;
    let (body, args, timeout_secs, stdout, stderr): (String, serde_json::Value, i32, String, String) =
        sqlx::query_as("SELECT body, args, timeout_secs, stdout, stderr FROM jobs WHERE id = $1").bind(id).fetch_one(&st.db).await?;
    Ok(Json(JobDetail { row, body, args, timeout_secs, stdout, stderr }))
}

#[derive(Deserialize)]
pub struct NewJob {
    agent_ids: Vec<Uuid>,
    /// Run a saved script...
    script_id: Option<Uuid>,
    /// ...or an ad-hoc one.
    interpreter: Option<String>,
    body: Option<String>,
    #[serde(default)]
    args: Vec<String>,
    timeout_secs: Option<i32>,
}

pub async fn create(State(st): State<Arc<AppState>>, u: User, Json(b): Json<NewJob>) -> ApiResult<Json<serde_json::Value>> {
    u.require(Role::Technician)?;
    if b.agent_ids.is_empty() || b.agent_ids.len() > 5000 {
        return Err(ApiError::BadRequest("agent_ids must contain 1-5000 agents".into()));
    }

    // A client's own script only runs on that client's agents.
    let (interp, body, default_timeout, script_client) = match b.script_id {
        Some(sid) => {
            let (i, body, t, client): (String, String, i32, Option<Uuid>) =
                sqlx::query_as("SELECT interpreter, body, timeout_secs, client_id FROM scripts WHERE id = $1")
                    .bind(sid)
                    .fetch_optional(&st.db)
                    .await?
                    .filter(|r: &(String, String, i32, Option<Uuid>)| r.3.is_none_or(|c| u.can_see_client(c)))
                    .ok_or(ApiError::NotFound("script"))?;
            (i, body, t, client)
        }
        None => (
            b.interpreter.ok_or_else(|| ApiError::BadRequest("interpreter required".into()))?,
            b.body.ok_or_else(|| ApiError::BadRequest("body required".into()))?,
            300,
            None,
        ),
    };
    let interpreter = parse_interpreter(&interp).ok_or_else(|| ApiError::BadRequest(format!("unknown interpreter {interp}")))?;
    let timeout = b.timeout_secs.unwrap_or(default_timeout).clamp(1, 86400);
    let args = serde_json::to_value(&b.args).unwrap_or_default();

    let mut jobs = Vec::with_capacity(b.agent_ids.len());
    let mut skipped = Vec::new();
    for agent_id in &b.agent_ids {
        let job_id = Uuid::new_v4();
        // Agents that don't exist, that the user can't see, or that belong to a different
        // client than the script are skipped and reported back.
        let inserted = sqlx::query(
            "INSERT INTO jobs (id, agent_id, script_id, interpreter, body, args, timeout_secs, created_by)
             SELECT $1, $2, $3, $4, $5, $6, $7, $8
              WHERE EXISTS (SELECT 1 FROM agents a JOIN sites s ON s.id = a.site_id
                             WHERE a.id = $2 AND ($9::uuid[] IS NULL OR s.client_id = ANY($9))
                               AND ($10::uuid IS NULL OR s.client_id = $10))",
        )
        .bind(job_id)
        .bind(agent_id)
        .bind(b.script_id)
        .bind(&interp)
        .bind(&body)
        .bind(&args)
        .bind(timeout)
        .bind(u.id)
        .bind(u.scope())
        .bind(script_client)
        .execute(&st.db)
        .await?
        .rows_affected();
        if inserted == 0 {
            skipped.push(*agent_id);
            continue;
        }

        // Online agents get it now; offline ones pick it up on reconnect.
        let msg = ServerMsg::RunScript(ScriptJob {
            job_id,
            interpreter,
            script: body.clone(),
            args: b.args.clone(),
            timeout_secs: timeout as u32,
        });
        let delivered = st.hub.is_online(*agent_id) && {
            // Claim the job first so a concurrent reconnect can't dispatch it twice.
            let claimed = sqlx::query("UPDATE jobs SET status = 'sent', sent_at = now() WHERE id = $1 AND status = 'queued'")
                .bind(job_id)
                .execute(&st.db)
                .await?
                .rows_affected()
                == 1;
            if claimed && !st.hub.send(*agent_id, msg).await {
                sqlx::query("UPDATE jobs SET status = 'queued', sent_at = NULL WHERE id = $1").bind(job_id).execute(&st.db).await?;
                false
            } else {
                claimed
            }
        };
        jobs.push(json!({ "job_id": job_id, "agent_id": agent_id, "status": if delivered { "sent" } else { "queued" } }));
    }
    if jobs.is_empty() {
        return Err(ApiError::BadRequest(
            "none of the selected agents can run this: they don't exist, or belong to a different client than the script".into(),
        ));
    }

    auth::audit(
        &st.db,
        Some(u.id),
        "job.create",
        b.script_id.map(|s| ("script", s)),
        json!({ "agents": jobs.len(), "skipped": skipped.len(), "interpreter": interp }),
    )
    .await;
    Ok(Json(json!({ "jobs": jobs, "skipped": skipped })))
}
