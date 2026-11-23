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

pub const MIN_PASSWORD: usize = 12;

pub fn validate_password(pw: &str) -> Result<(), ApiError> {
    let n = pw.chars().count();
    if n < MIN_PASSWORD {
        // Report the received length: a mangled env var (e.g. `$` expanded by compose) is the usual cause.
        return Err(ApiError::BadRequest(format!("password must be at least {MIN_PASSWORD} characters (got {n})")));
    }
    if n > 1024 {
        return Err(ApiError::BadRequest("password must be at most 1024 characters".into()));
    }
    Ok(())
}

/// Validate and hash off the async runtime (argon2 is deliberately slow).
pub async fn hash_password_async(pw: &str) -> Result<String, ApiError> {
    validate_password(pw)?;
    let pw = pw.to_string();
    Ok(tokio::task::spawn_blocking(move || hash_password(&pw)).await.map_err(anyhow::Error::from)??)
}

pub async fn verify_password_async(pw: &str, hash: String) -> bool {
    let pw = pw.to_string();
    tokio::task::spawn_blocking(move || verify_password(&pw, &hash)).await.unwrap_or(false)
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
    pub totp_enabled: bool,
    /// A second factor is set up: an authenticator app or a passkey.
    pub mfa_enabled: bool,
    /// 2FA is required for this account but not set up yet: until it is, the session can
    /// only reach the 2FA setup endpoints.
    pub mfa_setup_required: bool,
    /// This session was opened through single sign-on (the identity provider did the second factor).
    pub sso_session: bool,
    /// The account was created by SSO and has no password anyone knows.
    pub sso_only: bool,
    /// The clients this user may see, or `None` for all of them (admins, and accounts with
    /// `all_clients` set).
    pub client_ids: Option<Vec<Uuid>>,
    /// Explicit permission set, replacing the role's defaults (`None` = defaults).
    #[serde(skip)]
    pub permissions: Option<Vec<String>>,
    /// The session this request authenticated with.
    #[serde(skip)]
    pub session_id: Uuid,
    /// Set when the request authenticated with an API key rather than a session: the key's id.
    /// The `User` is then already narrowed to what the key allows (see `crate::apikeys`).
    #[sqlx(skip)]
    #[serde(skip)]
    pub api_key: Option<Uuid>,
}

impl User {
    pub fn role(&self) -> Role {
        // The CHECK constraint guarantees a valid value; fall back to least privilege anyway.
        Role::parse(&self.role).unwrap_or(Role::Readonly)
    }

    /// Whether this session has had a second factor: set up on the account, or done by the
    /// identity provider for an SSO session. The vault asks for it.
    pub fn second_factor(&self) -> bool {
        self.mfa_enabled || self.sso_session
    }

    pub fn require(&self, min: Role) -> Result<(), ApiError> {
        if self.role() >= min { Ok(()) } else { Err(ApiError::Forbidden) }
    }

    /// Bind this as `$n::uuid[]` in `($n::uuid[] IS NULL OR <client id> = ANY($n))`.
    pub fn scope(&self) -> Option<&[Uuid]> {
        self.client_ids.as_deref()
    }

    pub fn can_see_client(&self, client_id: Uuid) -> bool {
        self.scope().is_none_or(|ids| ids.contains(&client_id))
    }

    /// Whether the user holds a named permission. Admins hold all of them.
    pub fn has(&self, perm: Perm) -> bool {
        if self.role() == Role::Admin {
            return true;
        }
        match &self.permissions {
            Some(list) => list.iter().any(|p| p == perm.as_str()),
            None => perm.default_for(self.role()),
        }
    }

    pub fn need(&self, perm: Perm) -> Result<(), ApiError> {
        if self.has(perm) { Ok(()) } else { Err(ApiError::Forbidden) }
    }

    /// Every permission the user holds, for the dashboard.
    pub fn effective_permissions(&self) -> Vec<&'static str> {
        Perm::ALL.into_iter().filter(|p| self.has(*p)).map(Perm::as_str).collect()
    }
}

/// Named permissions (the permission sets the roadmap asked for before endpoint response).
/// Roles grant defaults; an admin can give a user an explicit set instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Perm {
    /// See protection state, detections, quarantine and telemetry.
    SecurityRead,
    /// Scans, kill, quarantine and restore, isolate, triage, verdicts.
    SecurityRespond,
    /// Security policies, exclusions, rule modes, content uploads and rollout.
    SecurityManage,
    /// See rates, contracts, invoices and money in reports.
    BillingRead,
    /// Contracts, products, rates, invoice runs, finalising and sending invoices, accounting.
    BillingManage,
    /// Approve and reject other people's timesheets.
    TimeApprove,
    /// See a client's vault: credential details, revealed passwords and notes, TOTP codes.
    VaultRead,
    /// Create, edit and delete vault credentials.
    VaultManage,
    /// Read and export the audit log (the dashboard page and `/api/v1/audit*`).
    AuditRead,
}

impl Perm {
    pub const ALL: [Perm; 9] = [
        Perm::SecurityRead,
        Perm::SecurityRespond,
        Perm::SecurityManage,
        Perm::BillingRead,
        Perm::BillingManage,
        Perm::TimeApprove,
        Perm::VaultRead,
        Perm::VaultManage,
        Perm::AuditRead,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Perm::SecurityRead => "security.read",
            Perm::SecurityRespond => "security.respond",
            Perm::SecurityManage => "security.manage",
            Perm::BillingRead => "billing.read",
            Perm::BillingManage => "billing.manage",
            Perm::TimeApprove => "time.approve",
            Perm::VaultRead => "vault.read",
            Perm::VaultManage => "vault.manage",
            Perm::AuditRead => "audit.read",
        }
    }

    pub fn parse(s: &str) -> Option<Perm> {
        Perm::ALL.into_iter().find(|p| p.as_str() == s)
    }

    /// What a role holds without an explicit permission set.
    pub fn role_defaults(role: Role) -> Vec<Perm> {
        Perm::ALL.into_iter().filter(|p| p.default_for(role)).collect()
    }

    fn default_for(self, role: Role) -> bool {
        match self {
            Perm::SecurityRead => true,
            Perm::SecurityRespond | Perm::VaultRead | Perm::VaultManage => role >= Role::Technician,
            // Money stays with admins unless someone is given it explicitly.
            Perm::SecurityManage | Perm::BillingRead | Perm::BillingManage | Perm::TimeApprove | Perm::AuditRead => role >= Role::Admin,
        }
    }
}

/// SQL select list for [`User`] from a `users u` row, given the placeholder bound to
/// `require_2fa_all`, the session id expression and a boolean expression for "this session
/// was opened by SSO". Expands to a `&'static str`.
macro_rules! user_columns {
    ($require_all:literal, $session_id:literal, $sso:literal) => {
        concat!(
            "u.id, u.email, u.name, u.role, u.totp_secret IS NOT NULL AS totp_enabled, ",
            "(u.totp_secret IS NOT NULL OR EXISTS (SELECT 1 FROM user_passkeys m WHERE m.user_id = u.id)) AS mfa_enabled, ",
            // A second factor is a TOTP secret or a passkey. A session the identity provider
            // vouched for (with its own MFA) doesn't have to set one up here.
            "(u.totp_secret IS NULL AND NOT EXISTS (SELECT 1 FROM user_passkeys k WHERE k.user_id = u.id) ",
            "AND NOT (", $sso, ") AND (u.role = 'admin' OR ", $require_all, ")) AS mfa_setup_required, ",
            "(", $sso, ") AS sso_session, u.sso_only, ",
            "CASE WHEN u.role = 'admin' OR u.all_clients THEN NULL ",
            "ELSE ARRAY(SELECT uc.client_id FROM user_clients uc WHERE uc.user_id = u.id) END AS client_ids, u.permissions, ",
            $session_id, " AS session_id"
        )
    };
}
pub(crate) use user_columns;

/// Whether a session whose account still has to set up 2FA may call this path:
/// only `me`, `logout` and the `/auth/totp` and `/auth/passkeys` endpoints.
fn allowed_before_mfa_setup(path: &str) -> bool {
    let path = path.strip_prefix("/api").unwrap_or(path);
    matches!(path, "/auth/me" | "/auth/logout" | "/auth/totp" | "/auth/passkeys")
        || path.starts_with("/auth/totp/")
        || path.starts_with("/auth/passkeys/")
}

/// The token of an `Authorization: Bearer` header.
pub fn bearer(headers: &header::HeaderMap) -> Option<String> {
    let v = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok())?;
    v.strip_prefix("Bearer ").map(|t| t.trim().to_string())
}

pub fn extract_token(headers: &header::HeaderMap) -> Option<String> {
    if let Some(t) = bearer(headers) {
        return Some(t);
    }
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|kv| kv.trim().strip_prefix(&format!("{COOKIE}=")).map(str::to_string))
}

/// The user a session token belongs to, if the session is still valid: not past its absolute
/// expiry, used within the idle window, and the account not disabled. Also re-read
/// periodically by long-lived streams, so revoked sessions and access changes take effect.
pub async fn session_user(state: &AppState, token: &str) -> sqlx::Result<Option<User>> {
    // last_seen_at is only rewritten when a minute old, so polling pages don't cost a write
    // per request.
    sqlx::query_as::<_, User>(concat!(
            "WITH s AS (
                 SELECT ", user_columns!("$3", "s.id", "s.sso_provider_id IS NOT NULL"), "
                   FROM user_sessions s JOIN users u ON u.id = s.user_id
                  WHERE s.token_hash = $1 AND s.expires_at > now() AND NOT u.disabled
                    AND s.last_seen_at > now() - make_interval(hours => $2)
             ), touch AS (
                 UPDATE user_sessions SET last_seen_at = now()
                  WHERE id = (SELECT session_id FROM s) AND last_seen_at < now() - interval '1 minute'
             )
             SELECT * FROM s",
        ))
        .bind(token_hash(token))
        .bind(state.session_idle_hours())
        .bind(state.company().require_2fa_all)
        .fetch_optional(&state.db)
        .await
}

impl FromRequestParts<Arc<AppState>> for User {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<AppState>) -> Result<Self, ApiError> {
        // API keys only ever travel in the Authorization header, never in the cookie.
        if let Some(key) = bearer(&parts.headers).filter(|t| crate::apikeys::is_key(t)) {
            return crate::apikeys::authenticate(state, parts, &key).await;
        }
        let token = extract_token(&parts.headers).ok_or(ApiError::Unauthorized)?;
        let user = session_user(state, &token).await?.ok_or(ApiError::Unauthorized)?;
        if user.mfa_setup_required {
            // Nested routers see a stripped URI; OriginalUri has the full path.
            let path = parts
                .extensions
                .get::<axum::extract::OriginalUri>()
                .map(|u| u.path().to_string())
                .unwrap_or_else(|| parts.uri.path().to_string());
            if !allowed_before_mfa_setup(&path) {
                return Err(ApiError::MfaSetupRequired);
            }
        }
        Ok(user)
    }
}

/// `Option<User>` in a handler: `None` when not signed in, instead of rejecting the request.
impl axum::extract::OptionalFromRequestParts<Arc<AppState>> for User {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<AppState>) -> Result<Option<Self>, ApiError> {
        match <User as FromRequestParts<Arc<AppState>>>::from_request_parts(parts, state).await {
            Ok(u) => Ok(Some(u)),
            Err(ApiError::Unauthorized) => Ok(None),
            Err(e) => Err(e),
        }
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
    fn mfa_setup_paths() {
        for p in ["/api/auth/me", "/api/auth/totp", "/api/auth/totp/setup", "/auth/logout", "/api/auth/passkeys", "/api/auth/passkeys/register/start"] {
            assert!(allowed_before_mfa_setup(p), "{p}");
        }
        for p in ["/api/agents", "/api/auth/totpx", "/api/auth/passkeysx", "/api/auth/password", "/api/users/x/totp", "/api/auth/me/x"] {
            assert!(!allowed_before_mfa_setup(p), "{p}");
        }
    }

    #[test]
    fn role_order() {
        assert!(Role::Admin > Role::Technician && Role::Technician > Role::Readonly);
    }
}
