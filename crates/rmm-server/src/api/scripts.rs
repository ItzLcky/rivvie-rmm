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

const COLS: &str = "id, name, description, interpreter, body, timeout_secs, created_at, updated_at";

pub async fn list(State(st): State<Arc<AppState>>, _u: User) -> ApiResult<Json<Vec<Script>>> {
    Ok(Json(sqlx::query_as(AssertSqlSafe(format!("SELECT {COLS} FROM scripts ORDER BY name"))).fetch_all(&st.db).await?))
}

pub async fn get(State(st): State<Arc<AppState>>, _u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Script>> {
    sqlx::query_as(AssertSqlSafe(format!("SELECT {COLS} FROM scripts WHERE id = $1")))
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .map(Json)
        .ok_or(ApiError::NotFound("script"))
}

pub async fn create(State(st): State<Arc<AppState>>, u: User, Json(b): Json<ScriptIn>) -> ApiResult<Json<Script>> {
    u.require(Role::Technician)?;
    b.validate()?;
    let s: Script = sqlx::query_as(AssertSqlSafe(format!(
        "INSERT INTO scripts (id, name, description, interpreter, body, timeout_secs, created_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING {COLS}"
    )))
    .bind(Uuid::new_v4())
    .bind(b.name.trim())
    .bind(&b.description)
    .bind(&b.interpreter)
    .bind(&b.body)
    .bind(b.timeout_secs.unwrap_or(300).clamp(1, 86400))
    .bind(u.id)
    .fetch_one(&st.db)
    .await?;
    auth::audit(&st.db, Some(u.id), "script.create", Some(("script", s.id)), json!({ "name": s.name })).await;
    Ok(Json(s))
}

pub async fn update(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<ScriptIn>) -> ApiResult<Json<Script>> {
    u.require(Role::Technician)?;
    b.validate()?;
    let s: Script = sqlx::query_as(AssertSqlSafe(format!(
        "UPDATE scripts SET name = $2, description = $3, interpreter = $4, body = $5, timeout_secs = $6, updated_at = now()
          WHERE id = $1 RETURNING {COLS}"
    )))
    .bind(id)
    .bind(b.name.trim())
    .bind(&b.description)
    .bind(&b.interpreter)
    .bind(&b.body)
    .bind(b.timeout_secs.unwrap_or(300).clamp(1, 86400))
    .fetch_optional(&st.db)
    .await?
    .ok_or(ApiError::NotFound("script"))?;
    auth::audit(&st.db, Some(u.id), "script.update", Some(("script", id)), json!({})).await;
    Ok(Json(s))
}

pub async fn remove(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<serde_json::Value>> {
    u.require(Role::Technician)?;
    sqlx::query("DELETE FROM scripts WHERE id = $1").bind(id).execute(&st.db).await?;
    auth::audit(&st.db, Some(u.id), "script.delete", Some(("script", id)), json!({})).await;
    Ok(Json(json!({ "ok": true })))
}
