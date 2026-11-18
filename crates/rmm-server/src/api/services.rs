//! An agent's services and matched log entries.

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, Utc};
use rmm_proto::{ServiceAction, ServerMsg};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::auth::{self, Role, User};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

#[derive(Serialize)]
pub struct Services {
    /// null until the agent reports (older agents never do).
    services: Option<Value>,
    services_at: Option<DateTime<Utc>>,
    /// Service names with an open alert on this agent.
    alerting: Vec<String>,
}

pub async fn list(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Services>> {
    super::access::agent(&st, &u, id).await?;
    let (services, services_at): (Option<Value>, Option<DateTime<Utc>>) =
        sqlx::query_as("SELECT services, services_at FROM agents WHERE id = $1").bind(id).fetch_one(&st.db).await?;
    let alerting = sqlx::query_scalar("SELECT key FROM alerts WHERE agent_id = $1 AND kind = 'service' AND resolved_at IS NULL")
        .bind(id)
        .fetch_all(&st.db)
        .await?;
    Ok(Json(Services { services, services_at, alerting }))
}

#[derive(Deserialize)]
pub struct Control {
    name: String,
    action: ServiceAction,
}

/// Starts, stops or restarts a service and waits (up to 2 minutes) for the agent's answer.
pub async fn control(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<Control>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    super::access::agent(&st, &u, id).await?;
    let name = b.name.trim().to_string();
    if name.is_empty() || name.len() > 256 {
        return Err(ApiError::BadRequest("service name required".into()));
    }
    let request_id = Uuid::new_v4();
    let answer = st.hub.await_control(request_id, id);
    let msg = ServerMsg::ServiceControl { request_id, name: name.clone(), action: b.action };
    if !st.hub.send(id, msg).await {
        st.hub.forget_control(request_id);
        return Err(ApiError::Conflict("agent is offline".into()));
    }
    let result = tokio::time::timeout(Duration::from_secs(120), answer).await;
    st.hub.forget_control(request_id);
    let (ok, message) = match result {
        Ok(Ok(r)) => r,
        Ok(Err(_)) => (false, "the agent disconnected before answering".into()),
        Err(_) => (false, "no answer from the agent within 2 minutes".into()),
    };
    auth::audit(
        &st.db,
        Some(u.id),
        &format!("service.{}", b.action.as_str()),
        Some(("agent", id)),
        json!({ "service": name, "ok": ok, "message": message }),
    )
    .await;
    Ok(Json(json!({ "ok": ok, "message": message })))
}

#[derive(Deserialize)]
pub struct LogQuery {
    /// Entries older than this id (paging back).
    before: Option<i64>,
    level: Option<String>,
    q: Option<String>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct LogEventRow {
    id: i64,
    ts: DateTime<Utc>,
    received_at: DateTime<Utc>,
    level: String,
    source: String,
    event_id: Option<i32>,
    message: String,
    policy_id: Option<Uuid>,
    policy_name: Option<String>,
    alert_id: Option<Uuid>,
}

/// Log entries that matched this agent's watchers, newest first, 200 at a time.
pub async fn log_events(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Query(q): Query<LogQuery>) -> ApiResult<Json<Vec<LogEventRow>>> {
    super::access::agent(&st, &u, id).await?;
    let search = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let level = q.level.as_deref().filter(|s| !s.is_empty());
    Ok(Json(
        sqlx::query_as(
            "SELECT l.id, l.ts, l.received_at, l.level, l.source, l.event_id, l.message, l.policy_id, p.name AS policy_name, l.alert_id
               FROM log_events l LEFT JOIN policy_items p ON p.id = l.policy_id
              WHERE l.agent_id = $1 AND ($2::bigint IS NULL OR l.id < $2) AND ($3::text IS NULL OR l.level = $3)
                AND ($4::text IS NULL OR l.message ILIKE '%' || $4 || '%' OR l.source ILIKE '%' || $4 || '%')
              ORDER BY l.id DESC LIMIT 200",
        )
        .bind(id)
        .bind(q.before)
        .bind(level)
        .bind(search)
        .fetch_all(&st.db)
        .await?,
    ))
}

/// Ask the agent for a fresh list now.
pub async fn refresh(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Readonly)?;
    super::access::agent(&st, &u, id).await?;
    if !st.hub.send(id, ServerMsg::RequestServices).await {
        return Err(ApiError::Conflict("agent is offline".into()));
    }
    Ok(Json(json!({ "ok": true })))
}
