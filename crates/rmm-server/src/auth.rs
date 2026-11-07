//! Dashboard user auth: argon2 password hashes + opaque, revocable session tokens.
//!
//! Browsers get an HttpOnly SameSite=Strict cookie (which also authenticates the
//! terminal WebSocket); API clients can send `Authorization: Bearer <token>`.

use std::sync::Arc;

use argon2::Argon2;
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use axum::extract::FromRequestParts;
use axum::http::header;
use axum::http::request::Parts;
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::ApiError;
use crate::state::AppState;

pub const COOKIE: &str = "rmm_session";
pub const SESSION_DAYS: i64 = 7;

/// 256-bit random token, hex encoded.
pub fn random_token() -> String {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("OS RNG unavailable");
    hex::encode(buf)
}

/// Tokens/secrets are high-entropy, so a plain SHA-256 is an appropriate at-rest hash.
pub fn token_hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

pub fn hash_password(pw: &str) -> anyhow::Result<String> {
    Argon2::default()
        .hash_password(pw.as_bytes())
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("hashing password: {e}"))
}

pub fn verify_password(pw: &str, hash: &str) -> bool {
    PasswordHash::new(hash).is_ok_and(|h| Argon2::default().verify_password(pw.as_bytes(), &h).is_ok())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Readonly,
    Technician,
    Admin,
}

impl Role {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "admin" => Some(Role::Admin),
            "technician" => Some(Role::Technician),
            "readonly" => Some(Role::Readonly),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    pub role: String,
}

impl User {
    pub fn role(&self) -> Role {
        // The CHECK constraint guarantees a valid value; fall back to least privilege anyway.
        Role::parse(&self.role).unwrap_or(Role::Readonly)
    }

    pub fn require(&self, min: Role) -> Result<(), ApiError> {
        if self.role() >= min { Ok(()) } else { Err(ApiError::Forbidden) }
    }
}

fn extract_token(parts: &Parts) -> Option<String> {
    if let Some(v) = parts.headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok())
        && let Some(t) = v.strip_prefix("Bearer ") {
            return Some(t.trim().to_string());
        }
    parts
        .headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|kv| kv.trim().strip_prefix(&format!("{COOKIE}=")).map(str::to_string))
}

impl FromRequestParts<Arc<AppState>> for User {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<AppState>) -> Result<Self, ApiError> {
        let token = extract_token(parts).ok_or(ApiError::Unauthorized)?;
        sqlx::query_as::<_, User>(
            "SELECT u.id, u.email, u.name, u.role
               FROM user_sessions s JOIN users u ON u.id = s.user_id
              WHERE s.token_hash = $1 AND s.expires_at > now() AND NOT u.disabled",
        )
        .bind(token_hash(&token))
        .fetch_optional(&state.db)
        .await?
        .ok_or(ApiError::Unauthorized)
    }
}

pub fn session_cookie(token: &str, secure: bool) -> String {
    format!(
        "{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{}",
        SESSION_DAYS * 86400,
        if secure { "; Secure" } else { "" }
    )
}

pub fn clear_cookie() -> String {
    format!("{COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
}

pub async fn audit(
    db: &sqlx::PgPool,
    user: Option<Uuid>,
    action: &str,
    target: Option<(&str, Uuid)>,
    details: serde_json::Value,
) {
    let res = sqlx::query("INSERT INTO audit_log (user_id, action, target_type, target_id, details) VALUES ($1,$2,$3,$4,$5)")
        .bind(user)
        .bind(action)
        .bind(target.map(|t| t.0))
        .bind(target.map(|t| t.1))
        .bind(details)
        .execute(db)
        .await;
    if let Err(e) = res {
        tracing::error!("audit log write failed: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_roundtrip() {
        let h = hash_password("correct horse").unwrap();
        assert!(verify_password("correct horse", &h));
        assert!(!verify_password("wrong", &h));
    }

    #[test]
    fn role_order() {
        assert!(Role::Admin > Role::Technician && Role::Technician > Role::Readonly);
    }
}
