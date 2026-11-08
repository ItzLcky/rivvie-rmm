use std::sync::Arc;

use sqlx::AssertSqlSafe;
use axum::Json;
use axum::extract::{Path, State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::agent_ws::parse_interpreter;
use crate::auth::{self, Role, User};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

#[derive(Serialize, sqlx::FromRow)]
pub struct Script {
    id: Uuid,
    name: String,
    description: String,
    interpreter: String,
    body: String,
    timeout_secs: i32,
    /// `None` = MSP-wide script; otherwise it belongs to (and only runs on) this client.
    client_id: Option<Uuid>,
    client_name: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Deserialize)]
pub struct ScriptIn {
    name: String,
    #[serde(default)]
    description: String,
    interpreter: String,
    body: String,
    timeout_secs: Option<i32>,
    #[serde(default)]
    client_id: Option<Uuid>,
}

impl ScriptIn {
    fn validate(&self) -> ApiResult<()> {
        if self.name.trim().is_empty() {
            return Err(ApiError::BadRequest("name required".into()));
        }
        if parse_interpreter(&self.interpreter).is_none() {
            return Err(ApiError::BadRequest(format!("unknown interpreter {}", self.interpreter)));
        }
        Ok(())
    }
}

/// MSP-wide scripts are admin-only to change (they run on every client); a client's own
/// scripts can be changed by technicians who can see that client.
fn may_edit(u: &User, client_id: Option<Uuid>) -> ApiResult<()> {
    match client_id {
        None => u.require(Role::Admin),
        Some(c) => {
            u.require(Role::Technician)?;
            super::access::client(u, c)
        }
    }
}

const COLS: &str = "sc.id, sc.name, sc.description, sc.interpreter, sc.body, sc.timeout_secs, sc.client_id,
       c.name AS client_name, sc.created_at, sc.updated_at";
const FROM: &str = "FROM scripts sc LEFT JOIN clients c ON c.id = sc.client_id";
/// MSP-wide scripts plus those of the clients the user can see ($1 NULL = all).
const VISIBLE: &str = "(sc.client_id IS NULL OR $1::uuid[] IS NULL OR sc.client_id = ANY($1))";

async fn fetch(st: &AppState, u: &User, id: Uuid) -> ApiResult<Script> {
    sqlx::query_as(AssertSqlSafe(format!("SELECT {COLS} {FROM} WHERE {VISIBLE} AND sc.id = $2")))
        .bind(u.scope())
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("script"))
}

pub async fn list(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Vec<Script>>> {
    Ok(Json(
        sqlx::query_as(AssertSqlSafe(format!("SELECT {COLS} {FROM} WHERE {VISIBLE} ORDER BY sc.name, c.name NULLS FIRST")))
            .bind(u.scope())
            .fetch_all(&st.db)
            .await?,
    ))
}

pub async fn get(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Script>> {
    Ok(Json(fetch(&st, &u, id).await?))
}

fn conflict(e: sqlx::Error) -> ApiError {
    match e {
        sqlx::Error::Database(d) if d.is_unique_violation() => {
            ApiError::Conflict("a script with that name already exists for this client (or MSP-wide)".into())
        }
        sqlx::Error::Database(d) if d.is_foreign_key_violation() => ApiError::NotFound("client"),
        e => e.into(),
    }
}

pub async fn create(State(st): State<Arc<AppState>>, u: User, Json(b): Json<ScriptIn>) -> ApiResult<Json<Script>> {
    may_edit(&u, b.client_id)?;
    b.validate()?;
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO scripts (id, name, description, interpreter, body, timeout_secs, created_by, client_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(id)
    .bind(b.name.trim())
    .bind(&b.description)
    .bind(&b.interpreter)
    .bind(&b.body)
    .bind(b.timeout_secs.unwrap_or(300).clamp(1, 86400))
    .bind(u.id)
    .bind(b.client_id)
    .execute(&st.db)
    .await
    .map_err(conflict)?;
    auth::audit(&st.db, Some(u.id), "script.create", Some(("script", id)), json!({ "name": b.name.trim(), "client_id": b.client_id }))
        .await;
    Ok(Json(fetch(&st, &u, id).await?))
}

pub async fn update(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<ScriptIn>) -> ApiResult<Json<Script>> {
    // Moving a script between scopes needs permission on both.
    let current = fetch(&st, &u, id).await?;
    may_edit(&u, current.client_id)?;
    may_edit(&u, b.client_id)?;
    b.validate()?;
    sqlx::query(
        "UPDATE scripts SET name = $2, description = $3, interpreter = $4, body = $5, timeout_secs = $6, client_id = $7,
                updated_at = now()
          WHERE id = $1",
    )
    .bind(id)
    .bind(b.name.trim())
    .bind(&b.description)
    .bind(&b.interpreter)
    .bind(&b.body)
    .bind(b.timeout_secs.unwrap_or(300).clamp(1, 86400))
    .bind(b.client_id)
    .execute(&st.db)
    .await
    .map_err(conflict)?;
    auth::audit(&st.db, Some(u.id), "script.update", Some(("script", id)), json!({ "client_id": b.client_id })).await;
    Ok(Json(fetch(&st, &u, id).await?))
}

pub async fn remove(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<serde_json::Value>> {
    let current = fetch(&st, &u, id).await?;
    may_edit(&u, current.client_id)?;
    sqlx::query("DELETE FROM scripts WHERE id = $1").bind(id).execute(&st.db).await?;
    auth::audit(&st.db, Some(u.id), "script.delete", Some(("script", id)), json!({ "name": current.name })).await;
    Ok(Json(json!({ "ok": true })))
}
