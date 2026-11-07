use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, header};
use axum::response::{AppendHeaders, IntoResponse};
use axum::Json;
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::json;

use crate::auth::{self, User};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

#[derive(Deserialize)]
pub struct Login {
    email: String,
    password: String,
}

/// Verified against when the email is unknown so response timing doesn't reveal which accounts exist.
fn dummy_hash() -> String {
    static H: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    H.get_or_init(|| auth::hash_password("not-a-real-password").unwrap_or_default()).clone()
}

pub async fn login(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<Login>) -> ApiResult<impl IntoResponse> {
    let row: Option<(uuid::Uuid, String, bool)> =
        sqlx::query_as("SELECT id, password_hash, disabled FROM users WHERE lower(email) = lower($1)")
            .bind(body.email.trim())
            .fetch_optional(&st.db)
            .await?;

    let pw = body.password.clone();
    let hash = row.as_ref().map(|r| r.1.clone()).unwrap_or_else(dummy_hash);
    let ok = tokio::task::spawn_blocking(move || auth::verify_password(&pw, &hash)).await.unwrap_or(false);
    let Some((user_id, _, disabled)) = row.filter(|_| ok) else {
        auth::audit(&st.db, None, "auth.login_failed", None, json!({ "email": body.email })).await;
        return Err(ApiError::Unauthorized);
    };
    if disabled {
        return Err(ApiError::Unauthorized);
    }

    let token = auth::random_token();
    let ua = headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).map(|s| s.chars().take(200).collect::<String>());
    sqlx::query("INSERT INTO user_sessions (token_hash, user_id, expires_at, user_agent) VALUES ($1,$2,$3,$4)")
        .bind(auth::token_hash(&token))
        .bind(user_id)
        .bind(Utc::now() + Duration::days(auth::SESSION_DAYS))
        .bind(ua)
        .execute(&st.db)
        .await?;
    sqlx::query("UPDATE users SET last_login_at = now() WHERE id = $1").bind(user_id).execute(&st.db).await?;
    auth::audit(&st.db, Some(user_id), "auth.login", None, json!({})).await;

    let user: User = sqlx::query_as("SELECT id, email, name, role FROM users WHERE id = $1").bind(user_id).fetch_one(&st.db).await?;
    Ok((
        AppendHeaders([(header::SET_COOKIE, auth::session_cookie(&token, st.cfg.secure_cookies()))]),
        // Token is also returned for non-browser API clients.
        Json(json!({ "user": user, "token": token })),
    ))
}

pub async fn logout(State(st): State<Arc<AppState>>, headers: HeaderMap) -> ApiResult<impl IntoResponse> {
    let token = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|kv| kv.trim().strip_prefix(&format!("{}=", auth::COOKIE)).map(str::to_string))
        .or_else(|| {
            headers.get(header::AUTHORIZATION)?.to_str().ok()?.strip_prefix("Bearer ").map(|s| s.trim().to_string())
        });
    if let Some(t) = token {
        sqlx::query("DELETE FROM user_sessions WHERE token_hash = $1").bind(auth::token_hash(&t)).execute(&st.db).await?;
    }
    Ok((AppendHeaders([(header::SET_COOKIE, auth::clear_cookie())]), Json(json!({ "ok": true }))))
}

pub async fn me(user: User) -> Json<User> {
    Json(user)
}
