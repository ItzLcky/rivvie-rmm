use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::auth::{self, Role, User};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

#[derive(Serialize, sqlx::FromRow)]
pub struct UserRow {
    id: Uuid,
    email: String,
    name: String,
    role: String,
    disabled: bool,
    created_at: DateTime<Utc>,
    last_login_at: Option<DateTime<Utc>>,
}

pub async fn list(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Vec<UserRow>>> {
    u.require(Role::Admin)?;
    Ok(Json(
        sqlx::query_as("SELECT id, email, name, role, disabled, created_at, last_login_at FROM users ORDER BY email")
            .fetch_all(&st.db)
            .await?,
    ))
}

#[derive(Deserialize)]
pub struct NewUser {
    email: String,
    name: String,
    password: String,
    role: String,
}

pub async fn create(State(st): State<Arc<AppState>>, u: User, Json(b): Json<NewUser>) -> ApiResult<Json<serde_json::Value>> {
    u.require(Role::Admin)?;
    let role = Role::parse(&b.role).ok_or_else(|| ApiError::BadRequest("role must be admin, technician or readonly".into()))?;
    let id = create_user(&st.db, &b.email, &b.name, &b.password, role).await?;
    auth::audit(&st.db, Some(u.id), "user.create", Some(("user", id)), json!({ "email": b.email, "role": b.role })).await;
    Ok(Json(json!({ "id": id })))
}

pub async fn create_user(db: &sqlx::PgPool, email: &str, name: &str, password: &str, role: Role) -> ApiResult<Uuid> {
    let email = email.trim().to_lowercase();
    if !email.contains('@') {
        return Err(ApiError::BadRequest("invalid email".into()));
    }
    if password.len() < 12 {
        // Report the received length: a mangled env var (e.g. `$` expanded by compose) is the usual cause.
        return Err(ApiError::BadRequest(format!(
            "password must be at least 12 characters (got {})",
            password.chars().count()
        )));
    }
    let pw = password.to_string();
    let hash = tokio::task::spawn_blocking(move || auth::hash_password(&pw)).await.map_err(anyhow::Error::from)??;
    let role = match role {
        Role::Admin => "admin",
        Role::Technician => "technician",
        Role::Readonly => "readonly",
    };
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO users (id, email, name, password_hash, role) VALUES ($1,$2,$3,$4,$5)")
        .bind(id)
        .bind(&email)
        .bind(name.trim())
        .bind(hash)
        .bind(role)
        .execute(db)
        .await?;
    Ok(id)
}

pub async fn disable(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<serde_json::Value>> {
    u.require(Role::Admin)?;
    if id == u.id {
        return Err(ApiError::BadRequest("you cannot disable yourself".into()));
    }
    let mut tx = st.db.begin().await?;
    sqlx::query("UPDATE users SET disabled = true WHERE id = $1").bind(id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM user_sessions WHERE user_id = $1").bind(id).execute(&mut *tx).await?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "user.disable", Some(("user", id)), json!({})).await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Serialize, sqlx::FromRow)]
pub struct AuditRow {
    id: i64,
    ts: DateTime<Utc>,
    user_name: Option<String>,
    action: String,
    target_type: Option<String>,
    target_id: Option<Uuid>,
    details: serde_json::Value,
}

pub async fn audit_log(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Vec<AuditRow>>> {
    u.require(Role::Admin)?;
    Ok(Json(
        sqlx::query_as(
            "SELECT l.id, l.ts, u.name AS user_name, l.action, l.target_type, l.target_id, l.details
               FROM audit_log l LEFT JOIN users u ON u.id = l.user_id
              ORDER BY l.ts DESC LIMIT 500",
        )
        .fetch_all(&st.db)
        .await?,
    ))
}
