//! Backup jobs as the agents last reported them: the fleet view (paged) and one device's.
//! See [`crate::backups`] and docs/design/backups.md.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::AssertSqlSafe;
use uuid::Uuid;

use crate::auth::{self, Role, User};
use crate::error::{ApiError, ApiResult};
use crate::paging::{self, Page, PageQuery, Plan, SortKey};
use crate::state::AppState;

#[derive(Serialize, sqlx::FromRow)]
pub struct JobRow {
    agent_id: Uuid,
    hostname: String,
    online: bool,
    client_id: Uuid,
    client_name: String,
    site_name: String,
    provider: String,
    job: String,
    last_run_at: Option<DateTime<Utc>>,
    last_success_at: Option<DateTime<Utc>>,
    /// `success`, `warning`, `failed`, `running` or `unknown`.
    last_result: String,
    message: String,
    size_bytes: Option<i64>,
    updated_at: DateTime<Utc>,
    /// A backup alert is open for this job.
    alerting: bool,
    #[sqlx(default)]
    #[serde(skip)]
    sort_key: String,
    #[sqlx(default)]
    #[serde(skip)]
    row_id: String,
}

const COLS: &str = "b.agent_id, a.hostname, a.online, s.client_id, c.name AS client_name, s.name AS site_name, b.provider, b.job, b.last_run_at,
       b.last_success_at, b.last_result, b.message, b.size_bytes, b.updated_at,
       EXISTS (SELECT 1 FROM alerts al WHERE al.agent_id = b.agent_id AND al.kind = 'backup' AND al.resolved_at IS NULL
                  AND al.key = 'backup:' || b.provider || ':' || b.job) AS alerting,
       (b.agent_id::text || '/' || b.provider || '/' || b.job) AS row_id";
const FROM: &str = "FROM backup_jobs b JOIN agents a ON a.id = b.agent_id JOIN sites s ON s.id = a.site_id JOIN clients c ON c.id = s.client_id";

const SORT_KEYS: &[SortKey] = &[
    SortKey { name: "last_success", expr: "coalesce(b.last_success_at, 'epoch'::timestamptz)", ty: "timestamptz" },
    SortKey { name: "last_run", expr: "coalesce(b.last_run_at, 'epoch'::timestamptz)", ty: "timestamptz" },
    SortKey { name: "hostname", expr: "lower(a.hostname)", ty: "text" },
    SortKey { name: "job", expr: "lower(b.job)", ty: "text" },
    SortKey { name: "result", expr: "(CASE b.last_result WHEN 'failed' THEN 0 WHEN 'warning' THEN 1 WHEN 'unknown' THEN 2 WHEN 'running' THEN 3 ELSE 4 END)", ty: "int" },
];

#[derive(Deserialize)]
pub struct ListQuery {
    client_id: Option<Uuid>,
    /// Comma-separated results.
    result: Option<String>,
    provider: Option<String>,
    /// Only jobs with an open alert.
    alerting: Option<bool>,
    /// Hostname or job.
    q: Option<String>,
}

pub async fn list(State(st): State<Arc<AppState>>, u: User, Query(q): Query<ListQuery>, Query(page): Query<PageQuery>) -> ApiResult<Json<Page<JobRow>>> {
    if let Some(c) = q.client_id {
        super::access::client(&u, c)?;
    }
    let plan = Plan::new(SORT_KEYS, ("result", false), &page, "(b.agent_id::text || '/' || b.provider || '/' || b.job)", "text", 7)?;
    let results: Option<Vec<String>> = q.result.as_deref().filter(|s| !s.is_empty()).map(|s| s.split(',').map(|r| r.trim().to_string()).collect());
    if let Some(bad) = results.iter().flatten().find(|r| !["success", "warning", "failed", "running", "unknown"].contains(&r.as_str())) {
        return Err(ApiError::BadRequest(format!("unknown result {bad}")));
    }
    let search = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(String::from);
    let filters = format!(
        "{FROM} WHERE ($1::uuid[] IS NULL OR s.client_id = ANY($1)) AND ($2::uuid IS NULL OR s.client_id = $2)
           AND ($3::text[] IS NULL OR b.last_result = ANY($3)) AND ($4::text IS NULL OR b.provider = $4)
           AND ($5::bool IS NULL OR $5 = EXISTS (SELECT 1 FROM alerts al WHERE al.agent_id = b.agent_id AND al.kind = 'backup' AND al.resolved_at IS NULL
                                                   AND al.key = 'backup:' || b.provider || ':' || b.job))
           AND ($6::text IS NULL OR a.hostname ILIKE '%' || $6 || '%' OR b.job ILIKE '%' || $6 || '%')"
    );
    let provider = q.provider.as_deref().filter(|s| !s.is_empty());
    macro_rules! bind_filters {
        ($query:expr) => {
            $query.bind(u.scope()).bind(q.client_id).bind(&results).bind(provider).bind(q.alerting).bind(&search)
        };
    }
    let sql = format!("SELECT {COLS}, {} {filters} {} {} {}", plan.key_select, plan.keyset, plan.order, plan.limit_sql());
    let mut rows = bind_filters!(sqlx::query_as::<_, JobRow>(AssertSqlSafe(sql)));
    if let Some((k, id)) = &plan.cursor {
        rows = rows.bind(k).bind(id);
    }
    let rows = rows.fetch_all(&st.db).await?;
    let total: i64 = bind_filters!(sqlx::query_scalar(AssertSqlSafe(paging::count_sql(&filters)))).fetch_one(&st.db).await?;
    Ok(Json(plan.finish(rows, |r| (r.sort_key.clone(), r.row_id.clone()), total)))
}

/// Reads the device's backup jobs now (its `backup` items' checks run at once).
pub async fn check_now(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<axum::Json<serde_json::Value>> {
    u.require(Role::Technician)?;
    super::access::agent(&st, &u, id).await?;
    let (online, capable): (bool, bool) = sqlx::query_as("SELECT online, $2 = ANY(capabilities) FROM agents WHERE id = $1")
        .bind(id)
        .bind(rmm_proto::checks::CAPABILITY)
        .fetch_one(&st.db)
        .await?;
    if !online {
        return Err(ApiError::Conflict("the agent is offline".into()));
    }
    if !capable {
        return Err(ApiError::Conflict("the agent is too old to read backups; update it".into()));
    }
    let items: Vec<Uuid> = crate::backups::specs_for(&st, &[id]).await?.remove(&id).unwrap_or_default().into_iter().map(|s| s.id).collect();
    if items.is_empty() {
        return Err(ApiError::Conflict("no Backups alert item reaches this device".into()));
    }
    crate::checks::push(&st, Some(&[id]), &items).await;
    auth::audit(&st.db, Some(u.id), "backup.check", Some(("agent", id)), serde_json::json!({ "items": items })).await;
    Ok(Json(serde_json::json!({ "ok": true, "checks": items.len() })))
}

pub async fn for_agent(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Vec<JobRow>>> {
    super::access::agent(&st, &u, id).await?;
    let rows: Vec<JobRow> = sqlx::query_as(AssertSqlSafe(format!("SELECT {COLS} {FROM} WHERE b.agent_id = $1 ORDER BY b.provider, lower(b.job)")))
        .bind(id)
        .fetch_all(&st.db)
        .await?;
    Ok(Json(rows))
}
