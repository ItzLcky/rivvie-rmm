//! Self-service TOTP two-factor auth. Admins always need it; Company settings can require it
//! for everyone. Until a required user sets it up, their session only reaches these endpoints.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::auth::{self, User};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use crate::totp;

pub enum Factor {
    Totp,
    Recovery { remaining: i64 },
}

/// Check a TOTP code (each time step is accepted once) or a single-use recovery code.
pub async fn check_code(db: &sqlx::PgPool, user_id: Uuid, secret: &[u8], code: &str) -> ApiResult<Option<Factor>> {
    if totp::is_totp_shaped(code) {
        let Some(step) = totp::verify(secret, code, Utc::now().timestamp()) else { return Ok(None) };
        let n = sqlx::query(
            "UPDATE users SET totp_last_step = $2 WHERE id = $1 AND (totp_last_step IS NULL OR totp_last_step < $2)",
        )
        .bind(user_id)
        .bind(step)
        .execute(db)
        .await?
        .rows_affected();
        return Ok((n == 1).then_some(Factor::Totp));
    }
    let hash = auth::token_hash(&totp::normalize_recovery_code(code));
    let n = sqlx::query("DELETE FROM user_recovery_codes WHERE user_id = $1 AND code_hash = $2")
        .bind(user_id)
        .bind(hash)
        .execute(db)
        .await?
        .rows_affected();
    if n == 0 {
        return Ok(None);
    }
    let (remaining,): (i64,) = sqlx::query_as("SELECT count(*) FROM user_recovery_codes WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(db)
        .await?;
    Ok(Some(Factor::Recovery { remaining }))
}

async fn verify_password(st: &AppState, u: &User, password: &str) -> ApiResult<()> {
    let (hash,): (String,) =
        sqlx::query_as("SELECT password_hash FROM users WHERE id = $1").bind(u.id).fetch_one(&st.db).await?;
    if auth::verify_password_async(password, hash).await {
        Ok(())
    } else {
        Err(ApiError::BadRequest("password is incorrect".into()))
    }
}

/// Check the code against the user's active secret, auditing a failure.
async fn verify_own_code(st: &AppState, u: &User, code: &str) -> ApiResult<Factor> {
    let secret: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT totp_secret FROM users WHERE id = $1").bind(u.id).fetch_one(&st.db).await?;
    let secret = secret.ok_or_else(|| ApiError::BadRequest("two-factor authentication is not enabled".into()))?;
    match check_code(&st.db, u.id, &secret, code).await? {
        Some(f) => Ok(f),
        None => {
            auth::audit(&st.db, Some(u.id), "auth.mfa_failed", Some(("user", u.id)), json!({})).await;
            Err(ApiError::BadRequest("invalid two-factor code".into()))
        }
    }
}

/// Replace the user's recovery codes; returns the new plaintext codes (shown once).
async fn replace_recovery_codes(tx: &mut sqlx::PgConnection, user_id: Uuid) -> ApiResult<Vec<String>> {
    let codes = totp::new_recovery_codes();
    sqlx::query("DELETE FROM user_recovery_codes WHERE user_id = $1").bind(user_id).execute(&mut *tx).await?;
    let hashes: Vec<Vec<u8>> = codes.iter().map(|c| auth::token_hash(&totp::normalize_recovery_code(c))).collect();
    sqlx::query("INSERT INTO user_recovery_codes (user_id, code_hash) SELECT $1, unnest($2::bytea[])")
        .bind(user_id)
        .bind(hashes)
        .execute(&mut *tx)
        .await?;
    Ok(codes)
}

#[derive(Serialize)]
pub struct Status {
    enabled: bool,
    required: bool,
    recovery_codes_left: i64,
}

pub async fn status(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Status>> {
    let (left,): (i64,) = sqlx::query_as("SELECT count(*) FROM user_recovery_codes WHERE user_id = $1")
        .bind(u.id)
        .fetch_one(&st.db)
        .await?;
    Ok(Json(Status {
        enabled: u.totp_enabled,
        required: u.role() == auth::Role::Admin || st.company().require_2fa_all,
        recovery_codes_left: left,
    }))
}

#[derive(Deserialize)]
pub struct Setup {
    password: String,
}

#[derive(Serialize)]
pub struct SetupView {
    secret: String,
    uri: String,
    qr_svg: String,
}

/// Start enrolment: a new pending secret, confirmed by `enable`. Calling it again replaces it.
pub async fn setup(State(st): State<Arc<AppState>>, u: User, Json(b): Json<Setup>) -> ApiResult<Json<SetupView>> {
    if u.totp_enabled {
        return Err(ApiError::Conflict("two-factor authentication is already on; turn it off first".into()));
    }
    verify_password(&st, &u, &b.password).await?;
    let secret = totp::new_secret();
    sqlx::query("UPDATE users SET totp_pending = $2 WHERE id = $1").bind(u.id).bind(&secret).execute(&st.db).await?;
    let company = st.company().company_name;
    let issuer = if company.is_empty() { "RMM".to_string() } else { format!("{company} RMM") };
    let uri = totp::otpauth_uri(&secret, &issuer, &u.email);
    Ok(Json(SetupView { secret: totp::encode_secret(&secret), qr_svg: totp::qr_svg(&uri)?, uri }))
}

#[derive(Deserialize)]
pub struct Code {
    code: String,
}

/// Confirm the pending secret with a first code. Signs out your other sessions, which were
/// opened with a password alone, and returns fresh recovery codes.
pub async fn enable(State(st): State<Arc<AppState>>, u: User, Json(b): Json<Code>) -> ApiResult<Json<serde_json::Value>> {
    if u.totp_enabled {
        return Err(ApiError::Conflict("two-factor authentication is already on".into()));
    }
    let pending: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT totp_pending FROM users WHERE id = $1").bind(u.id).fetch_one(&st.db).await?;
    let pending = pending.ok_or_else(|| ApiError::BadRequest("start setup first".into()))?;
    let step = totp::verify(&pending, &b.code, Utc::now().timestamp())
        .ok_or_else(|| ApiError::BadRequest("that code doesn't match; check the time on your phone".into()))?;

    let mut tx = st.db.begin().await?;
    let n = sqlx::query(
        "UPDATE users SET totp_secret = totp_pending, totp_pending = NULL, totp_last_step = $2, totp_enabled_at = now()
          WHERE id = $1 AND totp_secret IS NULL AND totp_pending = $3",
    )
    .bind(u.id)
    .bind(step)
    .bind(&pending)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if n == 0 {
        return Err(ApiError::Conflict("setup changed in another tab; start again".into()));
    }
    let codes = replace_recovery_codes(&mut tx, u.id).await?;
    let revoked = sqlx::query("DELETE FROM user_sessions WHERE user_id = $1 AND id <> $2")
        .bind(u.id)
        .bind(u.session_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "auth.mfa_enable", Some(("user", u.id)), json!({ "sessions_revoked": revoked })).await;
    Ok(Json(json!({ "recovery_codes": codes, "sessions_revoked": revoked })))
}

#[derive(Deserialize)]
pub struct Disable {
    password: String,
    code: String,
}

/// Turn 2FA off (password plus a current or recovery code). If 2FA is required for this
/// account, the session drops straight back into the set-up-required state.
pub async fn disable(State(st): State<Arc<AppState>>, u: User, Json(b): Json<Disable>) -> ApiResult<Json<serde_json::Value>> {
    verify_password(&st, &u, &b.password).await?;
    verify_own_code(&st, &u, &b.code).await?;
    let mut tx = st.db.begin().await?;
    clear(&mut tx, u.id).await?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "auth.mfa_disable", Some(("user", u.id)), json!({})).await;
    Ok(Json(json!({ "ok": true })))
}

/// New recovery codes, invalidating the old ones. Needs a current code.
pub async fn regenerate_recovery(
    State(st): State<Arc<AppState>>,
    u: User,
    Json(b): Json<Code>,
) -> ApiResult<Json<serde_json::Value>> {
    verify_own_code(&st, &u, &b.code).await?;
    let mut tx = st.db.begin().await?;
    let codes = replace_recovery_codes(&mut tx, u.id).await?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "auth.mfa_recovery_regenerate", Some(("user", u.id)), json!({})).await;
    Ok(Json(json!({ "recovery_codes": codes })))
}

/// Remove a user's 2FA and recovery codes. Shared by self-service disable, admin reset and the CLI.
pub async fn clear(tx: &mut sqlx::PgConnection, user_id: Uuid) -> ApiResult<u64> {
    let n = sqlx::query(
        "UPDATE users SET totp_secret = NULL, totp_pending = NULL, totp_last_step = NULL, totp_enabled_at = NULL WHERE id = $1",
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    sqlx::query("DELETE FROM user_recovery_codes WHERE user_id = $1").bind(user_id).execute(&mut *tx).await?;
    Ok(n)
}
