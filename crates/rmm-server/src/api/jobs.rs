use std::sync::Arc;

use sqlx::AssertSqlSafe;
use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, Utc};
use rmm_proto::{ScriptJob, ServerMsg};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::agent_ws::parse_interpreter;
use crate::auth::{self, Role, User};
use crate::error::{ApiError, ApiResult};
use crate::hub::Event;
use crate::paging::{self, Page, PageQuery, Plan, SortKey};
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
    #[sqlx(default)]
    #[serde(skip)]
    sort_key: String,
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

const SORT_KEYS: &[SortKey] = &[
    SortKey { name: "created", expr: "j.created_at", ty: "timestamptz" },
    SortKey { name: "hostname", expr: "lower(a.hostname)", ty: "text" },
    SortKey { name: "script", expr: "lower(coalesce(sc.name, '~ ad-hoc ' || j.interpreter))", ty: "text" },
    SortKey { name: "status", expr: "j.status", ty: "text" },
    SortKey { name: "duration", expr: "coalesce(j.duration_ms, -1)", ty: "bigint" },
];

/// Statuses that count as a failure on the dashboard and in health.
pub const FAILED: &[&str] = &["failed", "error", "timed_out", "lost"];

#[derive(Deserialize)]
pub struct ListQuery {
    /// Comma-separated; `failed` also matches error, timed_out and lost.
    status: Option<String>,
    script_id: Option<Uuid>,
    client_id: Option<Uuid>,
    agent_id: Option<Uuid>,
    /// Hostname or script name.
    q: Option<String>,
}

pub async fn list_recent(
    State(st): State<Arc<AppState>>,
    u: User,
    Query(q): Query<ListQuery>,
    Query(page): Query<PageQuery>,
) -> ApiResult<Json<Page<JobRow>>> {
    let plan = Plan::new(SORT_KEYS, ("created", true), &page, "j.id", "uuid", 7)?;
    let status: Option<Vec<String>> = q.status.as_deref().filter(|s| !s.is_empty()).map(|s| {
        s.split(',')
            .flat_map(|x| if x == "failed" { FAILED.to_vec() } else { vec![x] })
            .map(str::to_string)
            .collect()
    });
    let filters = format!(
        "{JOB_FROM}
          WHERE ($1::uuid[] IS NULL OR s.client_id = ANY($1))
            AND ($2::text[] IS NULL OR j.status = ANY($2))
            AND ($3::uuid IS NULL OR j.script_id = $3)
            AND ($4::uuid IS NULL OR s.client_id = $4)
            AND ($5::uuid IS NULL OR j.agent_id = $5)
            AND ($6::text IS NULL OR a.hostname ILIKE '%' || $6 || '%' OR sc.name ILIKE '%' || $6 || '%')"
    );
    let search = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty());
    macro_rules! bind_filters {
        ($query:expr) => {
            $query.bind(u.scope()).bind(&status).bind(q.script_id).bind(q.client_id).bind(q.agent_id).bind(search)
        };
    }
    let sql = format!("SELECT {JOB_COLS}, {} {filters} {} {} {}", plan.key_select, plan.keyset, plan.order, plan.limit_sql());
    let mut rows = bind_filters!(sqlx::query_as::<_, JobRow>(AssertSqlSafe(sql)));
    if let Some((k, id)) = &plan.cursor {
        rows = rows.bind(k).bind(id);
    }
    let rows = rows.fetch_all(&st.db).await?;
    let total: i64 = bind_filters!(sqlx::query_scalar(AssertSqlSafe(paging::count_sql(&filters)))).fetch_one(&st.db).await?;
    Ok(Json(plan.finish(rows, |r| (r.sort_key.clone(), r.id.to_string()), total)))
}

/// The latest failed jobs of the last 24 hours, for the dashboard.
pub async fn recent_failures(st: &AppState, scope: Option<&[Uuid]>) -> ApiResult<Vec<JobRow>> {
    let sql = format!(
        "SELECT {JOB_COLS} {JOB_FROM}
          WHERE ($1::uuid[] IS NULL OR s.client_id = ANY($1)) AND j.status = ANY($2)
            AND j.created_at > now() - interval '24 hours'
          ORDER BY j.created_at DESC LIMIT 10"
    );
    Ok(sqlx::query_as(AssertSqlSafe(sql)).bind(scope).bind(FAILED).fetch_all(&st.db).await?)
}

#[derive(Serialize)]
pub struct JobDetail {
    #[serde(flatten)]
    row: JobRow,
    body: String,
    args: serde_json::Value,
    timeout_secs: i32,
    /// Output from character `since_stdout` on (all of it by default)...
    stdout: String,
    stderr: String,
    /// ...and its full length in characters, to pass back as `since_*` for the next chunk.
    stdout_len: i32,
    stderr_len: i32,
}

#[derive(Deserialize)]
pub struct OutputQuery {
    #[serde(default)]
    since_stdout: i32,
    #[serde(default)]
    since_stderr: i32,
}

/// A job with its output. A live job page passes `since_stdout`/`since_stderr` (the lengths
/// it already has) to fetch only what's new.
pub async fn get(
    State(st): State<Arc<AppState>>,
    u: User,
    Path(id): Path<Uuid>,
    Query(o): Query<OutputQuery>,
) -> ApiResult<Json<JobDetail>> {
    let sql = format!("SELECT {JOB_COLS} {JOB_FROM} WHERE j.id = $1 AND ($2::uuid[] IS NULL OR s.client_id = ANY($2))");
    let row: JobRow = sqlx::query_as(AssertSqlSafe(sql))
        .bind(id)
        .bind(u.scope())
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("job"))?;
    #[allow(clippy::type_complexity)]
    let (body, args, timeout_secs, stdout, stderr, stdout_len, stderr_len): (String, serde_json::Value, i32, String, String, i32, i32) =
        sqlx::query_as(
            "SELECT body, args, timeout_secs, substr(stdout, $2 + 1), substr(stderr, $3 + 1), length(stdout), length(stderr)
               FROM jobs WHERE id = $1",
        )
        .bind(id)
        .bind(o.since_stdout.clamp(0, i32::MAX - 1))
        .bind(o.since_stderr.clamp(0, i32::MAX - 1))
        .fetch_one(&st.db)
        .await?;
    Ok(Json(JobDetail { row, body, args, timeout_secs, stdout, stderr, stdout_len, stderr_len }))
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
        let client_id: Option<Uuid> = sqlx::query_scalar(
            "INSERT INTO jobs (id, agent_id, script_id, interpreter, body, args, timeout_secs, created_by)
             SELECT $1, $2, $3, $4, $5, $6, $7, $8
               FROM agents a JOIN sites s ON s.id = a.site_id
              WHERE a.id = $2 AND ($9::uuid[] IS NULL OR s.client_id = ANY($9))
                AND ($10::uuid IS NULL OR s.client_id = $10)
             RETURNING (SELECT s.client_id FROM agents a JOIN sites s ON s.id = a.site_id WHERE a.id = $2)",
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
        .fetch_optional(&st.db)
        .await?;
        let Some(client_id) = client_id else {
            skipped.push(*agent_id);
            continue;
        };

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
        let status = if delivered { "sent" } else { "queued" };
        st.hub.publish(Event::Job { id: job_id, agent_id: *agent_id, client_id, status: status.into(), output: false });
        jobs.push(json!({ "job_id": job_id, "agent_id": agent_id, "status": status }));
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
