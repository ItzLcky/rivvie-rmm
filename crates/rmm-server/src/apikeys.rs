//! API keys: `Authorization: Bearer rmm_k_…` on the public API (docs/design/api.md).
//!
//! A key acts as its owner and never with more. Per request the owner's *current* rights are
//! intersected with what the key was given: its access level (read-only keys can only `GET`),
//! the named permissions it lists, and an optional subset of clients. Only routes in the public
//! API registry ([`crate::api::public`]) are reachable with a key, each in one resource group
//! the key must hold; the agent socket, the shell and desktop relays, the vault, sessions,
//! users and settings are not in it.

use std::sync::Arc;

use axum::extract::{FromRequestParts, MatchedPath, OriginalUri};
use axum::http::request::Parts;
use chrono::{DateTime, Utc};
use serde_json::json;
use uuid::Uuid;

use crate::auth::{self, Perm, Role, User};
use crate::error::ApiError;
use crate::ratelimit::ClientIp;
use crate::state::AppState;

/// Every key starts with this, so a leaked one is recognisable (and secret scanners can find it).
pub const PREFIX: &str = "rmm_k_";
/// How much of the key is shown in lists: the prefix and six characters of the secret.
pub const SHOWN: usize = PREFIX.len() + 6;
pub const DEFAULT_RATE: i32 = 600;

/// Resource groups a key can be limited to: (id, label). Each public route belongs to one.
pub const GROUPS: &[(&str, &str)] = &[
    ("clients", "Clients and sites"),
    ("agents", "Agents, inventory and metrics"),
    ("jobs", "Jobs and results"),
    ("scripts", "Script library"),
    ("alerts", "Alerts"),
    ("tickets", "Tickets"),
    ("security", "Endpoint protection (needs the security.read permission)"),
];

pub fn is_key(token: &str) -> bool {
    token.starts_with(PREFIX)
}

pub fn valid_group(g: &str) -> bool {
    GROUPS.iter().any(|(id, _)| *id == g)
}

/// A new key: (the secret, shown once; what is stored; the prefix shown in lists).
pub fn generate() -> (String, Vec<u8>, String) {
    let token = format!("{PREFIX}{}", auth::random_token());
    let hash = auth::token_hash(&token);
    let shown = token.chars().take(SHOWN).collect();
    (token, hash, shown)
}

#[derive(sqlx::FromRow)]
struct KeyRow {
    id: Uuid,
    owner_id: Uuid,
    prefix: String,
    access: String,
    scopes: Vec<String>,
    permissions: Vec<String>,
    client_ids: Option<Vec<Uuid>>,
    rate_limit_per_min: i32,
    expires_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
}

/// The route pattern the request matched, relative to the API root (`/agents/{id}`), whichever
/// of `/api` and `/api/v1` it came in on.
fn pattern(parts: &Parts) -> Option<String> {
    let matched = parts.extensions.get::<MatchedPath>()?.as_str();
    let rel = matched.strip_prefix("/api/v1").or_else(|| matched.strip_prefix("/api"))?;
    Some(if rel.is_empty() { "/".into() } else { rel.to_string() })
}

/// Authenticates a request carrying an API key and returns the user it acts as: the key's
/// owner, narrowed to what the key allows. Unknown, revoked and expired keys are 401; a key
/// that is valid but not allowed this route is 403 with the reason.
pub async fn authenticate(st: &Arc<AppState>, parts: &mut Parts, token: &str) -> Result<User, ApiError> {
    let key: KeyRow = sqlx::query_as(
        "SELECT k.id, k.owner_id, k.prefix, k.access, k.scopes, k.permissions, k.client_ids, k.rate_limit_per_min, k.expires_at, k.revoked_at
           FROM api_keys k WHERE k.token_hash = $1",
    )
    .bind(auth::token_hash(token))
    .fetch_optional(&st.db)
    .await?
    .ok_or(ApiError::Unauthorized)?;
    if key.revoked_at.is_some() || key.expires_at.is_some_and(|e| e <= Utc::now()) {
        return Err(ApiError::Unauthorized);
    }
    let owner: User = sqlx::query_as(concat!("SELECT ", auth::user_columns!("$2", "$3::uuid"), " FROM users u WHERE u.id = $1 AND NOT u.disabled"))
        .bind(key.owner_id)
        .bind(st.company().require_2fa_all)
        .bind(key.id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::Unauthorized)?;

    st.limits.api_keys.take(&key.id.to_string(), key.rate_limit_per_min.max(1) as u32).map_err(ApiError::Throttled)?;

    let method = parts.method.as_str();
    let method = if method == "HEAD" { "GET" } else { method };
    let op = pattern(parts)
        .and_then(|p| crate::api::public::find(method, &p))
        .ok_or_else(|| ApiError::Denied("this endpoint isn't available to API keys".into()))?;
    if !key.scopes.iter().any(|s| s == op.group) {
        return Err(ApiError::Denied(format!("this key has no access to {} ({})", op.group, key.prefix)));
    }
    if op.writes() && key.access != "write" {
        return Err(ApiError::Denied("this key is read-only".into()));
    }

    let user = narrow(owner, &key);
    if op.writes() {
        let path = parts.extensions.get::<OriginalUri>().map(|u| u.path().to_string()).unwrap_or_else(|| parts.uri.path().to_string());
        auth::audit(
            &st.db,
            Some(user.id),
            "api.request",
            Some(("api_key", key.id)),
            json!({ "key": key.prefix, "method": method, "path": path, "route": op.path }),
        )
        .await;
    }
    // Rewritten at most once a minute, like session `last_seen_at`.
    let ip = match ClientIp::from_request_parts(parts, st).await {
        Ok(ClientIp(ip)) => ip.to_string(),
        Err(never) => match never {},
    };
    sqlx::query(
        "UPDATE api_keys SET last_used_at = now(), last_used_ip = $2
          WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute')",
    )
    .bind(key.id)
    .bind(ip)
    .execute(&st.db)
    .await?;
    Ok(user)
}

/// What the owner may do through this key: never more than the owner may now.
fn narrow(owner: User, key: &KeyRow) -> User {
    let permissions: Vec<String> = key.permissions.iter().filter(|p| Perm::parse(p).is_some_and(|p| owner.has(p))).cloned().collect();
    let role = if key.access == "write" { owner.role().min(Role::Technician) } else { Role::Readonly };
    let client_ids = match (owner.client_ids, &key.client_ids) {
        (None, None) => None,
        (Some(o), None) => Some(o),
        (None, Some(k)) => Some(k.clone()),
        (Some(o), Some(k)) => Some(o.into_iter().filter(|c| k.contains(c)).collect()),
    };
    User {
        role: match role {
            Role::Admin => "admin",
            Role::Technician => "technician",
            Role::Readonly => "readonly",
        }
        .into(),
        // Keys never need the 2FA setup detour: they are not sessions.
        totp_enabled: false,
        mfa_setup_required: false,
        client_ids,
        permissions: Some(permissions),
        api_key: Some(key.id),
        ..owner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(role: &str, clients: Option<Vec<Uuid>>, perms: Option<Vec<&str>>) -> User {
        User {
            id: Uuid::new_v4(),
            email: "o@x".into(),
            name: "o".into(),
            role: role.into(),
            totp_enabled: true,
            mfa_setup_required: true,
            client_ids: clients,
            permissions: perms.map(|p| p.into_iter().map(String::from).collect()),
            session_id: Uuid::nil(),
            api_key: None,
        }
    }

    fn key(access: &str, perms: &[&str], clients: Option<Vec<Uuid>>) -> KeyRow {
        KeyRow {
            id: Uuid::new_v4(),
            owner_id: Uuid::nil(),
            prefix: "rmm_k_abcdef".into(),
            access: access.into(),
            scopes: vec!["tickets".into()],
            permissions: perms.iter().map(|s| s.to_string()).collect(),
            client_ids: clients,
            rate_limit_per_min: 10,
            expires_at: None,
            revoked_at: None,
        }
    }

    #[test]
    fn a_key_never_exceeds_its_owner() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        // A technician with an explicit permission set: the key can't claim billing.manage.
        let owner = user("technician", Some(vec![a]), Some(vec!["security.read"]));
        let u = narrow(owner, &key("write", &["security.read", "billing.manage", "nonsense"], Some(vec![a, b])));
        assert_eq!(u.effective_permissions(), ["security.read"]);
        assert_eq!(u.client_ids, Some(vec![a]));
        assert!(u.api_key.is_some() && !u.mfa_setup_required);
        // A key for every client still sees only the owner's.
        let u = narrow(user("technician", Some(vec![b]), None), &key("read", &[], None));
        assert_eq!(u.client_ids, Some(vec![b]));
    }

    #[test]
    fn admin_keys_are_not_admins() {
        let u = narrow(user("admin", None, None), &key("write", &["vault.read"], None));
        assert_eq!(u.role(), Role::Technician);
        // Admins hold every permission, but the key only the ones it lists.
        assert_eq!(u.effective_permissions(), ["vault.read"]);
        assert!(u.client_ids.is_none());
        let u = narrow(user("admin", None, None), &key("read", &[], Some(vec![Uuid::nil()])));
        assert_eq!(u.role(), Role::Readonly);
        assert_eq!(u.client_ids, Some(vec![Uuid::nil()]));
        assert!(u.effective_permissions().is_empty());
    }

    #[test]
    fn keys_are_recognisable_and_hashed() {
        let (token, hash, shown) = generate();
        assert!(is_key(&token) && token.len() == PREFIX.len() + 64);
        assert_eq!(shown.len(), SHOWN);
        assert!(token.starts_with(&shown));
        assert_eq!(hash, auth::token_hash(&token));
        assert!(!is_key("0123"));
    }
}
