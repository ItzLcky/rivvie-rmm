//! Single sign-on for technicians with OpenID Connect (authorization code flow with PKCE).
//!
//! * `GET /auth/sso/providers`, `/auth/sso/{id}/start` and `/auth/sso/callback` are the public
//!   half: the sign-in page's buttons, the redirect to the provider and the return from it.
//! * Everything under `/settings/sso` and the break-glass switch on users are admin only.
//!
//! A sign-in ends in an ordinary session, opened by the same code as a password sign-in (see
//! `auth::open_session`). The identity provider is trusted to have done the second factor, so an
//! SSO session never has to set up TOTP. Accounts are matched by the provider's stable subject;
//! a first sign-in links an existing account only by an email address the provider vouches for.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, header};
use axum::response::{AppendHeaders, IntoResponse, Redirect, Response};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::auth::{self, Perm, Role, User};
use crate::crypto;
use crate::error::{ApiError, ApiResult};
use crate::oidc::{self, AuthRequest, Expect};
use crate::ratelimit::ClientIp;
use crate::state::{AppState, Company};

const BINDING_COOKIE: &str = "rmm_sso";
const STATE_MINUTES: i64 = 10;
const DEFAULT_SCOPES: &str = "openid email profile";
const ENTRA_HOST: &str = "https://login.microsoftonline.com/";
const GOOGLE_ISSUER: &str = "https://accounts.google.com";

pub fn redirect_uri(st: &AppState) -> String {
    format!("{}/api/auth/sso/callback", st.cfg.public_url)
}

// ---------------------------------------------------------------------------------------
// Group mappings
// ---------------------------------------------------------------------------------------

/// One mapping row: members of `group` get `role`, the extra permissions and these clients.
#[derive(Debug, Clone)]
pub struct Mapping {
    pub group: String,
    pub role: Role,
    pub extra: Vec<Perm>,
    pub all_clients: bool,
    pub client_ids: Vec<Uuid>,
}

/// What a sign-in sets on the account.
#[derive(Debug, Clone, PartialEq)]
pub struct Grant {
    pub role: Role,
    /// `None`: the role's defaults.
    pub permissions: Option<Vec<String>>,
    pub all_clients: bool,
    pub client_ids: Vec<Uuid>,
}

fn role_name(r: Role) -> &'static str {
    match r {
        Role::Admin => "admin",
        Role::Technician => "technician",
        Role::Readonly => "readonly",
    }
}

/// The access a user's groups add up to: the highest role of the mappings that match, the
/// union of their clients and extra permissions. With no match, `fallback` (a role with no
/// clients), or `None` when the provider has none: that user may not sign in.
pub fn grant_for(maps: &[Mapping], groups: &[String], fallback: Option<Role>) -> Option<Grant> {
    let matched: Vec<&Mapping> = maps.iter().filter(|m| groups.iter().any(|g| g.eq_ignore_ascii_case(&m.group))).collect();
    let Some(role) = matched.iter().map(|m| m.role).max() else {
        return fallback.map(|role| Grant { role, permissions: None, all_clients: false, client_ids: Vec::new() });
    };
    let mut extra: Vec<Perm> = Vec::new();
    let mut client_ids: Vec<Uuid> = Vec::new();
    for m in &matched {
        for p in &m.extra {
            if !extra.contains(p) {
                extra.push(*p);
            }
        }
        for c in &m.client_ids {
            if !client_ids.contains(c) {
                client_ids.push(*c);
            }
        }
    }
    client_ids.sort();
    // Extra permissions are stored as an explicit set, so it has to include what the role gives.
    let permissions = (!extra.is_empty() && role != Role::Admin).then(|| {
        Perm::ALL
            .into_iter()
            .filter(|p| extra.contains(p) || Perm::role_defaults(role).contains(p))
            .map(|p| p.as_str().to_string())
            .collect()
    });
    Some(Grant { role, permissions, all_clients: matched.iter().any(|m| m.all_clients), client_ids })
}

/// Writes a grant to the account; returns whether anything changed.
async fn apply_grant(tx: &mut sqlx::PgConnection, user_id: Uuid, g: &Grant) -> ApiResult<bool> {
    type Row = (String, Option<Vec<String>>, bool, Vec<Uuid>);
    let (role, permissions, all_clients, mut clients): Row = sqlx::query_as(
        "SELECT role, permissions, all_clients, ARRAY(SELECT client_id FROM user_clients WHERE user_id = $1 ORDER BY client_id) FROM users WHERE id = $1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?;
    clients.sort();
    // Only clients that still exist.
    let wanted: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM clients WHERE id = ANY($1) ORDER BY id").bind(&g.client_ids).fetch_all(&mut *tx).await?;
    let (want_all, want_clients) = (g.all_clients && g.role != Role::Admin, if g.role == Role::Admin { Vec::new() } else { wanted });
    if role == role_name(g.role) && permissions == g.permissions && all_clients == want_all && clients == want_clients {
        return Ok(false);
    }
    sqlx::query("UPDATE users SET role = $2, permissions = $3, all_clients = $4 WHERE id = $1")
        .bind(user_id)
        .bind(role_name(g.role))
        .bind(&g.permissions)
        .bind(want_all)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM user_clients WHERE user_id = $1").bind(user_id).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO user_clients (user_id, client_id) SELECT $1, c FROM unnest($2::uuid[]) c").bind(user_id).bind(&want_clients).execute(&mut *tx).await?;
    Ok(true)
}

// ---------------------------------------------------------------------------------------
// Providers
// ---------------------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct Provider {
    id: Uuid,
    name: String,
    preset: String,
    issuer: String,
    client_id: String,
    client_secret: Vec<u8>,
    secret_sealed: bool,
    scopes: String,
    enabled: bool,
    groups_claim: String,
    jit: bool,
    group_sync: bool,
    default_role: Option<String>,
    allowed_domains: Vec<String>,
    allowed_tenants: Vec<String>,
    trust_email: bool,
}

const PROVIDER_COLUMNS: &str = "id, name, preset, issuer, client_id, client_secret, secret_sealed, scopes, enabled, groups_claim, jit,
    group_sync, default_role, allowed_domains, allowed_tenants, trust_email";

async fn load_provider(db: &sqlx::PgPool, id: Uuid) -> sqlx::Result<Option<Provider>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT {PROVIDER_COLUMNS} FROM sso_providers WHERE id = $1"))).bind(id).fetch_optional(db).await
}

fn open_secret(st: &AppState, p: &Provider) -> ApiResult<String> {
    let plain = crypto::load(st.cfg.data_key.as_ref(), &p.client_secret, p.secret_sealed)
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("can't decrypt the client secret of provider {}: RMM_DATA_KEY has changed", p.name)))?;
    String::from_utf8(plain).map_err(|_| ApiError::Internal(anyhow::anyhow!("client secret of provider {} is not text", p.name)))
}

/// Seals client secrets still stored in the clear (run at startup when `RMM_DATA_KEY` is set).
pub async fn seal_existing(db: &sqlx::PgPool, key: Option<&crypto::DataKey>) -> anyhow::Result<()> {
    let Some(key) = key else {
        let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM sso_providers WHERE secret_sealed").fetch_one(db).await?;
        anyhow::ensure!(n == 0, "{n} single sign-on provider(s) have client secrets encrypted with RMM_DATA_KEY, but it isn't set");
        return Ok(());
    };
    let rows: Vec<(Uuid, Vec<u8>)> = sqlx::query_as("SELECT id, client_secret FROM sso_providers WHERE NOT secret_sealed").fetch_all(db).await?;
    for (id, secret) in &rows {
        sqlx::query("UPDATE sso_providers SET client_secret = $2, secret_sealed = true WHERE id = $1 AND NOT secret_sealed")
            .bind(id)
            .bind(key.seal(secret))
            .execute(db)
            .await?;
    }
    Ok(())
}

#[derive(Serialize)]
struct MapView {
    group_value: String,
    role: String,
    extra_permissions: Vec<String>,
    all_clients: bool,
    client_ids: Vec<Uuid>,
}

#[derive(Serialize)]
struct ProviderView {
    id: Uuid,
    name: String,
    preset: String,
    issuer: String,
    client_id: String,
    has_secret: bool,
    scopes: String,
    enabled: bool,
    groups_claim: String,
    jit: bool,
    group_sync: bool,
    default_role: Option<String>,
    allowed_domains: Vec<String>,
    allowed_tenants: Vec<String>,
    trust_email: bool,
    identities: i64,
    maps: Vec<MapView>,
}

async fn view(db: &sqlx::PgPool, p: Provider) -> ApiResult<ProviderView> {
    type MapRow = (String, String, Vec<String>, bool, Vec<Uuid>);
    let maps: Vec<MapRow> = sqlx::query_as(
        "SELECT group_value, role, extra_permissions, all_clients, client_ids FROM sso_group_maps WHERE provider_id = $1 ORDER BY group_value",
    )
    .bind(p.id)
    .fetch_all(db)
    .await?;
    let (identities,): (i64,) = sqlx::query_as("SELECT count(*) FROM user_identities WHERE provider_id = $1").bind(p.id).fetch_one(db).await?;
    Ok(ProviderView {
        id: p.id,
        name: p.name,
        preset: p.preset,
        issuer: p.issuer,
        client_id: p.client_id,
        has_secret: !p.client_secret.is_empty(),
        scopes: p.scopes,
        enabled: p.enabled,
        groups_claim: p.groups_claim,
        jit: p.jit,
        group_sync: p.group_sync,
        default_role: p.default_role,
        allowed_domains: p.allowed_domains,
        allowed_tenants: p.allowed_tenants,
        trust_email: p.trust_email,
        identities,
        maps: maps
            .into_iter()
            .map(|(group_value, role, extra_permissions, all_clients, client_ids)| MapView { group_value, role, extra_permissions, all_clients, client_ids })
            .collect(),
    })
}

#[derive(Serialize, sqlx::FromRow)]
struct BreakGlass {
    id: Uuid,
    email: String,
    name: String,
}

/// Providers, group mappings and the break-glass accounts, for the settings page.
pub async fn settings(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<serde_json::Value>> {
    u.require(Role::Admin)?;
    let providers: Vec<Provider> =
        sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT {PROVIDER_COLUMNS} FROM sso_providers ORDER BY name"))).fetch_all(&st.db).await?;
    let mut views = Vec::new();
    for p in providers {
        views.push(view(&st.db, p).await?);
    }
    let exempt: Vec<BreakGlass> =
        sqlx::query_as("SELECT id, email, name FROM users WHERE sso_exempt ORDER BY email").fetch_all(&st.db).await?;
    Ok(Json(json!({
        "providers": views,
        "redirect_uri": redirect_uri(&st),
        "sso_required": st.company().sso_required,
        "break_glass": exempt,
    })))
}

#[derive(Deserialize)]
pub struct ProviderInput {
    name: String,
    #[serde(default)]
    preset: Option<String>,
    issuer: String,
    client_id: String,
    /// Omitted on update = unchanged.
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    scopes: Option<String>,
    #[serde(default = "yes")]
    enabled: bool,
    #[serde(default)]
    groups_claim: Option<String>,
    #[serde(default)]
    jit: bool,
    #[serde(default)]
    group_sync: bool,
    #[serde(default)]
    default_role: Option<String>,
    #[serde(default)]
    allowed_domains: Vec<String>,
    #[serde(default)]
    allowed_tenants: Vec<String>,
    #[serde(default)]
    trust_email: bool,
}

fn yes() -> bool {
    true
}

struct Clean {
    name: String,
    preset: String,
    issuer: String,
    client_id: String,
    scopes: String,
    groups_claim: String,
    default_role: Option<Role>,
    allowed_domains: Vec<String>,
    allowed_tenants: Vec<String>,
    trust_email: bool,
}

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError::BadRequest(msg.into())
}

/// Checks a provider form and applies what its preset implies.
fn clean(b: &ProviderInput) -> ApiResult<Clean> {
    let name = b.name.trim();
    if name.is_empty() || name.chars().count() > 60 {
        return Err(bad("the name must be 1 to 60 characters"));
    }
    let client_id = b.client_id.trim();
    if client_id.is_empty() || client_id.len() > 255 {
        return Err(bad("the client id is required"));
    }
    let issuer = b.issuer.trim().trim_end_matches('/').to_string();
    if !oidc::url_allowed(&issuer) {
        return Err(bad("the issuer must be an https URL"));
    }
    let preset = b.preset.as_deref().unwrap_or("custom").to_string();
    let mut allowed_tenants: Vec<String> = b.allowed_tenants.iter().map(|t| t.trim().to_lowercase()).filter(|t| !t.is_empty()).collect();
    allowed_tenants.sort();
    allowed_tenants.dedup();
    let mut trust_email = b.trust_email;
    match preset.as_str() {
        "entra" => {
            let tenant = issuer.strip_prefix(ENTRA_HOST).and_then(|r| r.strip_suffix("/v2.0")).unwrap_or("");
            let multi = matches!(tenant, "common" | "organizations");
            if !multi && !oidc::is_tenant_id(tenant) {
                return Err(bad("an Entra issuer looks like https://login.microsoftonline.com/<tenant id>/v2.0 (or /organizations/v2.0 for several tenants)"));
            }
            if allowed_tenants.iter().any(|t| !oidc::is_tenant_id(t)) {
                return Err(bad("allowed tenants are tenant ids (GUIDs)"));
            }
            if multi && allowed_tenants.is_empty() {
                return Err(bad("a multi-tenant Entra endpoint admits every Microsoft tenant: list the tenant ids that may sign in"));
            }
            // Within the tenants named, Entra's address for a work account can be believed
            // (it sends no `email_verified`).
            trust_email = true;
        }
        "google" => {
            if issuer != GOOGLE_ISSUER {
                return Err(bad("the Google issuer is https://accounts.google.com"));
            }
            // Anyone has a Google account: only the Workspace domains named may sign in.
            if b.allowed_domains.iter().all(|d| d.trim().is_empty()) {
                return Err(bad("name the Google Workspace domain(s) that may sign in (allowed email domains)"));
            }
            trust_email = false;
        }
        "custom" => {
            if !allowed_tenants.is_empty() {
                return Err(bad("allowed tenants are for Entra ID"));
            }
        }
        _ => return Err(bad("the preset must be custom, entra or google")),
    }
    let scopes = b.scopes.as_deref().unwrap_or(DEFAULT_SCOPES).split_whitespace().collect::<Vec<_>>().join(" ");
    let scopes = if scopes.is_empty() { DEFAULT_SCOPES.to_string() } else { scopes };
    if scopes.len() > 300 || !scopes.chars().all(|c| c.is_ascii_alphanumeric() || " _.:/-".contains(c)) {
        return Err(bad("the scopes are space separated names"));
    }
    let groups_claim = b.groups_claim.as_deref().map(str::trim).filter(|c| !c.is_empty()).unwrap_or("groups").to_string();
    if groups_claim.len() > 100 {
        return Err(bad("the groups claim is too long"));
    }
    let default_role = match b.default_role.as_deref().filter(|r| !r.is_empty()) {
        Some(r) => Some(Role::parse(r).ok_or_else(|| bad("the default role must be technician or readonly"))?),
        None => None,
    };
    if default_role == Some(Role::Admin) {
        return Err(bad("admin can't be the default role: it would make everyone the provider vouches for an admin. Map an admin group instead"));
    }
    if b.jit && default_role.is_none() && !b.group_sync {
        return Err(bad("creating accounts at first sign-in needs a default role or group mappings to decide the role"));
    }
    let mut allowed_domains: Vec<String> =
        b.allowed_domains.iter().map(|d| d.trim().trim_start_matches('@').to_lowercase()).filter(|d| !d.is_empty()).collect();
    allowed_domains.sort();
    allowed_domains.dedup();
    if allowed_domains.len() > 50 || allowed_domains.iter().any(|d| d.len() > 255 || d.contains('@') || d.contains(' ')) {
        return Err(bad("allowed domains are bare domain names like example.com"));
    }
    Ok(Clean { name: name.to_string(), preset, issuer, client_id: client_id.to_string(), scopes, groups_claim, default_role, allowed_domains, allowed_tenants, trust_email })
}

/// Refuses a configuration the provider doesn't answer for.
async fn check_provider(st: &AppState, issuer: &str) -> ApiResult<oidc::Discovery> {
    st.oidc.discovery(issuer, true).await.map_err(|e| bad(format!("can't use this provider: {e}")))
}

fn sealed(st: &AppState, secret: &str) -> ApiResult<(Vec<u8>, bool)> {
    if secret.is_empty() || secret.len() > 4096 {
        return Err(bad("the client secret is required"));
    }
    Ok(crypto::store(st.cfg.data_key.as_ref(), secret.as_bytes()))
}

pub async fn create_provider(State(st): State<Arc<AppState>>, u: User, Json(b): Json<ProviderInput>) -> ApiResult<Json<serde_json::Value>> {
    u.require(Role::Admin)?;
    let c = clean(&b)?;
    let (secret, is_sealed) = sealed(&st, b.client_secret.as_deref().unwrap_or(""))?;
    check_provider(&st, &c.issuer).await?;
    let (id,): (Uuid,) = sqlx::query_as(
        "INSERT INTO sso_providers (name, preset, issuer, client_id, client_secret, secret_sealed, scopes, enabled, groups_claim, jit, group_sync,
                                    default_role, allowed_domains, allowed_tenants, trust_email)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING id",
    )
    .bind(&c.name)
    .bind(&c.preset)
    .bind(&c.issuer)
    .bind(&c.client_id)
    .bind(secret)
    .bind(is_sealed)
    .bind(&c.scopes)
    .bind(b.enabled)
    .bind(&c.groups_claim)
    .bind(b.jit)
    .bind(b.group_sync)
    .bind(c.default_role.map(role_name))
    .bind(&c.allowed_domains)
    .bind(&c.allowed_tenants)
    .bind(c.trust_email)
    .fetch_one(&st.db)
    .await?;
    auth::audit(&st.db, Some(u.id), "sso.provider_create", Some(("sso_provider", id)), json!({ "name": c.name, "issuer": c.issuer, "preset": c.preset })).await;
    Ok(Json(json!({ "id": id })))
}

pub async fn update_provider(
    State(st): State<Arc<AppState>>,
    u: User,
    Path(id): Path<Uuid>,
    Json(b): Json<ProviderInput>,
) -> ApiResult<Json<serde_json::Value>> {
    u.require(Role::Admin)?;
    let current = load_provider(&st.db, id).await?.ok_or(ApiError::NotFound("provider"))?;
    let c = clean(&b)?;
    let secret = match b.client_secret.as_deref().filter(|s| !s.is_empty()) {
        Some(s) => Some(sealed(&st, s)?),
        None => None,
    };
    if c.issuer != current.issuer {
        // The old secret belongs to the old provider.
        if secret.is_none() {
            return Err(bad("enter the client secret again when the issuer changes"));
        }
        check_provider(&st, &c.issuer).await?;
    }
    let mut tx = st.db.begin().await?;
    sqlx::query(
        "UPDATE sso_providers SET name = $2, preset = $3, issuer = $4, client_id = $5,
                client_secret = COALESCE($6, client_secret), secret_sealed = CASE WHEN $6::bytea IS NULL THEN secret_sealed ELSE $7 END,
                scopes = $8, enabled = $9, groups_claim = $10, jit = $11, group_sync = $12, default_role = $13,
                allowed_domains = $14, allowed_tenants = $15, trust_email = $16, updated_at = now()
          WHERE id = $1",
    )
    .bind(id)
    .bind(&c.name)
    .bind(&c.preset)
    .bind(&c.issuer)
    .bind(&c.client_id)
    .bind(secret.as_ref().map(|s| s.0.clone()))
    .bind(secret.as_ref().is_some_and(|s| s.1))
    .bind(&c.scopes)
    .bind(b.enabled)
    .bind(&c.groups_claim)
    .bind(b.jit)
    .bind(b.group_sync)
    .bind(c.default_role.map(role_name))
    .bind(&c.allowed_domains)
    .bind(&c.allowed_tenants)
    .bind(c.trust_email)
    .execute(&mut *tx)
    .await?;
    // Subjects are only meaningful at the issuer and client that issued them (Entra's differ per
    // application), so linked identities don't survive a change of either; people link again by email.
    let identity_scope_changed = c.issuer != current.issuer || c.client_id != current.client_id;
    if identity_scope_changed {
        sqlx::query("DELETE FROM user_identities WHERE provider_id = $1").bind(id).execute(&mut *tx).await?;
    }
    // A provider that is switched off, or whose trust settings changed, no longer vouches for its sessions.
    let narrowed = identity_scope_changed
        || !b.enabled
        || c.allowed_tenants != current.allowed_tenants
        || c.allowed_domains != current.allowed_domains
        || c.trust_email != current.trust_email;
    if narrowed {
        sqlx::query("DELETE FROM user_sessions WHERE sso_provider_id = $1").bind(id).execute(&mut *tx).await?;
    }
    lockout_check(&mut tx).await?;
    tx.commit().await?;
    auth::audit(
        &st.db,
        Some(u.id),
        "sso.provider_update",
        Some(("sso_provider", id)),
        json!({ "name": c.name, "issuer": c.issuer, "enabled": b.enabled, "secret_changed": secret.is_some() }),
    )
    .await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn delete_provider(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<serde_json::Value>> {
    u.require(Role::Admin)?;
    let mut tx = st.db.begin().await?;
    // Its sessions and identities go with it (cascade).
    let name: Option<String> = sqlx::query_scalar("DELETE FROM sso_providers WHERE id = $1 RETURNING name").bind(id).fetch_optional(&mut *tx).await?;
    let Some(name) = name else { return Err(ApiError::NotFound("provider")) };
    lockout_check(&mut tx).await?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "sso.provider_delete", Some(("sso_provider", id)), json!({ "name": name })).await;
    Ok(Json(json!({ "ok": true })))
}

/// Fetches the provider's discovery document and says what it found; nothing is changed.
pub async fn test_provider(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<serde_json::Value>> {
    u.require(Role::Admin)?;
    let p = load_provider(&st.db, id).await?.ok_or(ApiError::NotFound("provider"))?;
    match st.oidc.discovery(&p.issuer, true).await {
        Ok(d) => {
            let keys = st.oidc.keys(&p.issuer, &d, true).await;
            Ok(Json(json!({
                "ok": keys.is_ok(),
                "error": keys.as_ref().err().map(|e| e.to_string()),
                "issuer": d.issuer,
                "authorization_endpoint": d.authorization_endpoint,
                "token_endpoint": d.token_endpoint,
                "keys": keys.map(|k| k.len()).unwrap_or(0),
            })))
        }
        Err(e) => Ok(Json(json!({ "ok": false, "error": e.to_string() }))),
    }
}

#[derive(Deserialize)]
pub struct MapInput {
    group_value: String,
    role: String,
    #[serde(default)]
    extra_permissions: Vec<String>,
    #[serde(default)]
    all_clients: bool,
    #[serde(default)]
    client_ids: Vec<Uuid>,
}

/// Replaces the provider's group mappings.
pub async fn update_maps(
    State(st): State<Arc<AppState>>,
    u: User,
    Path(id): Path<Uuid>,
    Json(maps): Json<Vec<MapInput>>,
) -> ApiResult<Json<serde_json::Value>> {
    u.require(Role::Admin)?;
    if maps.len() > 200 {
        return Err(bad("at most 200 mappings"));
    }
    let mut rows = Vec::new();
    for m in &maps {
        let group = m.group_value.trim().to_lowercase();
        if group.is_empty() || group.len() > 255 {
            return Err(bad("a group is 1 to 255 characters"));
        }
        if rows.iter().any(|r: &(String, &str, Vec<String>, bool, Vec<Uuid>)| r.0 == group) {
            return Err(bad(format!("the group {group} is mapped twice")));
        }
        let role = Role::parse(&m.role).ok_or_else(|| bad("the role must be admin, technician or readonly"))?;
        let mut perms = Vec::new();
        for p in &m.extra_permissions {
            let p = Perm::parse(p).ok_or_else(|| bad(format!("unknown permission {p}")))?;
            if !perms.contains(&p.as_str().to_string()) {
                perms.push(p.as_str().to_string());
            }
        }
        rows.push((group, role_name(role), perms, m.all_clients, m.client_ids.clone()));
    }
    let mut tx = st.db.begin().await?;
    if load_provider_tx(&mut tx, id).await?.is_none() {
        return Err(ApiError::NotFound("provider"));
    }
    sqlx::query("DELETE FROM sso_group_maps WHERE provider_id = $1").bind(id).execute(&mut *tx).await?;
    for (group, role, perms, all_clients, clients) in &rows {
        sqlx::query("INSERT INTO sso_group_maps (provider_id, group_value, role, extra_permissions, all_clients, client_ids) VALUES ($1,$2,$3,$4,$5,$6)")
            .bind(id)
            .bind(group)
            .bind(role)
            .bind(perms)
            .bind(all_clients)
            .bind(clients)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "sso.maps_update", Some(("sso_provider", id)), json!({ "mappings": rows.len() })).await;
    Ok(Json(json!({ "ok": true })))
}

async fn load_provider_tx(tx: &mut sqlx::PgConnection, id: Uuid) -> sqlx::Result<Option<Uuid>> {
    sqlx::query_scalar("SELECT id FROM sso_providers WHERE id = $1 FOR UPDATE").bind(id).fetch_optional(&mut *tx).await
}

// ---------------------------------------------------------------------------------------
// Requiring SSO, and the break-glass accounts
// ---------------------------------------------------------------------------------------

/// With SSO required, somebody has to still be able to sign in when it doesn't work: a
/// provider that is on, and an enabled admin who is exempt and has a password.
pub(super) async fn lockout_check(tx: &mut sqlx::PgConnection) -> ApiResult<()> {
    // Locked, so two requests that each remove "the other" break-glass admin can't both pass.
    let required: bool = sqlx::query_scalar("SELECT sso_required FROM company_settings FOR UPDATE").fetch_one(&mut *tx).await?;
    if !required {
        return Ok(());
    }
    let (providers,): (i64,) = sqlx::query_as("SELECT count(*) FROM sso_providers WHERE enabled").fetch_one(&mut *tx).await?;
    if providers == 0 {
        return Err(ApiError::Conflict("single sign-on is required, so at least one provider has to stay enabled; turn the requirement off first".into()));
    }
    exempt_admin_check(tx).await
}

async fn exempt_admin_check(tx: &mut sqlx::PgConnection) -> ApiResult<()> {
    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM users WHERE role = 'admin' AND sso_exempt AND NOT disabled AND NOT sso_only")
        .fetch_one(&mut *tx)
        .await?;
    if n == 0 {
        return Err(ApiError::Conflict("keep at least one admin with a password as a break-glass account (Users, “Allow password sign-in”)".into()));
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct Required {
    required: bool,
}

/// Turns the requirement on or off. Turning it on refuses to lock everyone out.
pub async fn set_required(State(st): State<Arc<AppState>>, u: User, Json(b): Json<Required>) -> ApiResult<Json<serde_json::Value>> {
    u.require(Role::Admin)?;
    let mut tx = st.db.begin().await?;
    let new: Company = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "UPDATE company_settings SET sso_required = $1, updated_at = now(), updated_by = $2 RETURNING {}",
        Company::COLUMNS
    )))
    .bind(b.required)
    .bind(u.id)
    .fetch_one(&mut *tx)
    .await?;
    lockout_check(&mut tx).await?;
    tx.commit().await?;
    *st.company.write().unwrap_or_else(|e| e.into_inner()) = new;
    auth::audit(&st.db, Some(u.id), "sso.required", None, json!({ "required": b.required })).await;
    Ok(Json(json!({ "ok": true, "sso_required": b.required })))
}

#[derive(Deserialize)]
pub struct Exempt {
    exempt: bool,
}

/// Marks an account as break-glass: it may sign in with a password when SSO is required, and
/// group mappings never change it.
pub async fn set_exempt(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<Exempt>) -> ApiResult<Json<serde_json::Value>> {
    u.require(Role::Admin)?;
    let mut tx = st.db.begin().await?;
    let n = sqlx::query("UPDATE users SET sso_exempt = $2 WHERE id = $1").bind(id).bind(b.exempt).execute(&mut *tx).await?.rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound("user"));
    }
    lockout_check(&mut tx).await?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "user.sso_exempt", Some(("user", id)), json!({ "exempt": b.exempt })).await;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------------------
// Sign-in
// ---------------------------------------------------------------------------------------

/// The buttons for the sign-in page.
pub async fn public_providers(State(st): State<Arc<AppState>>) -> ApiResult<Json<serde_json::Value>> {
    let rows: Vec<(Uuid, String, String)> = sqlx::query_as("SELECT id, name, preset FROM sso_providers WHERE enabled ORDER BY name").fetch_all(&st.db).await?;
    Ok(Json(json!({
        "providers": rows.into_iter().map(|(id, name, preset)| json!({ "id": id, "name": name, "preset": preset })).collect::<Vec<_>>(),
        "sso_required": st.company().sso_required,
    })))
}

/// Where to go after sign-in: a path on this site, nothing else.
pub fn safe_next(next: Option<&str>) -> String {
    match next {
        Some(n) if n.starts_with('/') && !n.starts_with("//") && !n.contains('\\') && n.len() <= 500 && !n.chars().any(char::is_control) => n.to_string(),
        _ => "/".to_string(),
    }
}

fn login_redirect(code: &str) -> Redirect {
    Redirect::to(&format!("/login?sso_error={code}"))
}

fn binding_cookie(value: &str, secure: bool) -> String {
    // Lax: the provider's redirect back is a cross-site navigation, which Strict would drop.
    format!("{BINDING_COOKIE}={value}; Path=/api/auth/sso; HttpOnly; SameSite=Lax; Max-Age={}{}", STATE_MINUTES * 60, if secure { "; Secure" } else { "" })
}

fn clear_binding_cookie() -> String {
    format!("{BINDING_COOKIE}=; Path=/api/auth/sso; HttpOnly; SameSite=Lax; Max-Age=0")
}

fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|kv| kv.trim().strip_prefix(name).and_then(|r| r.strip_prefix('=')))
}

#[derive(Deserialize)]
pub struct StartQuery {
    next: Option<String>,
}

/// Sends the browser to the provider. Saves the state, nonce and PKCE verifier (hashed state,
/// plus a cookie that binds the sign-in to this browser) for the callback.
pub async fn start(State(st): State<Arc<AppState>>, ClientIp(ip): ClientIp, Path(id): Path<Uuid>, Query(q): Query<StartQuery>) -> Response {
    match start_inner(&st, &ip.to_string(), id, q.next.as_deref()).await {
        Ok(r) => r,
        Err(code) => login_redirect(code).into_response(),
    }
}

async fn start_inner(st: &AppState, ip: &str, id: Uuid, next: Option<&str>) -> Result<Response, &'static str> {
    st.limits.sso_start.take(ip).map_err(|_| "too_many")?;
    let provider = match load_provider(&st.db, id).await {
        Ok(Some(p)) if p.enabled => p,
        _ => return Err("provider_error"),
    };
    let disc = st.oidc.discovery(&provider.issuer, false).await.map_err(|e| {
        tracing::warn!("sso: provider {} discovery failed: {e}", provider.name);
        "provider_error"
    })?;
    let (state, binding, nonce) = (auth::random_token(), auth::random_token(), auth::random_token());
    let (verifier, challenge) = oidc::pkce();
    sqlx::query("INSERT INTO sso_login_states (state_hash, binding_hash, provider_id, nonce, code_verifier, next, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7)")
        .bind(auth::token_hash(&state))
        .bind(auth::token_hash(&binding))
        .bind(id)
        .bind(&nonce)
        .bind(&verifier)
        .bind(safe_next(next))
        .bind(Utc::now() + Duration::minutes(STATE_MINUTES))
        .execute(&st.db)
        .await
        .map_err(|_| "failed")?;
    let redirect = redirect_uri(st);
    let url = oidc::authorization_url(
        &disc,
        &AuthRequest { client_id: &provider.client_id, redirect_uri: &redirect, scopes: &provider.scopes, state: &state, nonce: &nonce, challenge: &challenge },
    )
    .map_err(|_| "provider_error")?;
    Ok((AppendHeaders([(header::SET_COOKIE, binding_cookie(&binding, st.cfg.secure_cookies()))]), Redirect::to(&url)).into_response())
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// Why a sign-in was refused: `code` goes to the sign-in page, `reason` to the audit log.
struct Fail {
    code: &'static str,
    reason: String,
    user: Option<Uuid>,
    provider: Option<Uuid>,
    email: Option<String>,
    /// Audited and counted against the IP's limit. Failures before the state and the browser
    /// binding check out are neither: anyone can make a browser request the callback with junk.
    loud: bool,
}

impl Fail {
    fn new(code: &'static str, reason: impl Into<String>) -> Fail {
        Fail { code, reason: reason.into(), user: None, provider: None, email: None, loud: false }
    }

    fn loud(mut self, provider: Uuid) -> Fail {
        self.provider = Some(provider);
        self.loud = true;
        self
    }
}

impl From<ApiError> for Fail {
    fn from(e: ApiError) -> Fail {
        tracing::error!("sso: {e}");
        Fail { loud: true, ..Fail::new("failed", "server error") }
    }
}

impl From<sqlx::Error> for Fail {
    fn from(e: sqlx::Error) -> Fail {
        ApiError::from(e).into()
    }
}

impl From<oidc::OidcError> for Fail {
    fn from(e: oidc::OidcError) -> Fail {
        Fail { loud: true, ..Fail::new(if matches!(e, oidc::OidcError::Provider(_)) { "provider_error" } else { "failed" }, format!("{}: {e}", e.code())) }
    }
}

pub async fn callback(
    State(st): State<Arc<AppState>>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Query(q): Query<CallbackQuery>,
) -> Response {
    let ip_key = ip.to_string();
    if st.limits.sso_callback.check(&ip_key).is_err() {
        return (AppendHeaders([(header::SET_COOKIE, clear_binding_cookie())]), login_redirect("too_many")).into_response();
    }
    match callback_inner(&st, &headers, &ip_key, q).await {
        Ok((token, next)) => (
            AppendHeaders([
                (header::SET_COOKIE, auth::session_cookie(&token, st.cfg.secure_cookies())),
                (header::SET_COOKIE, clear_binding_cookie()),
            ]),
            Redirect::to(&next),
        )
            .into_response(),
        Err(f) => {
            if f.loud {
                // Its own limit: a page that makes browsers hit the callback with junk can't lock anyone out of passwords.
                st.limits.sso_callback.fail(&ip_key);
                auth::audit(
                    &st.db,
                    f.user,
                    "auth.sso_failed",
                    f.provider.map(|p| ("sso_provider", p)),
                    json!({ "reason": f.reason, "email": f.email, "ip": ip_key }),
                )
                .await;
            }
            (AppendHeaders([(header::SET_COOKIE, clear_binding_cookie())]), login_redirect(f.code)).into_response()
        }
    }
}

async fn callback_inner(st: &AppState, headers: &HeaderMap, ip: &str, q: CallbackQuery) -> Result<(String, String), Fail> {
    if let Some(e) = q.error.as_deref() {
        return Err(Fail::new("provider_denied", format!("the provider refused: {}", e.chars().take(60).collect::<String>())));
    }
    let (Some(code), Some(state)) = (q.code.as_deref(), q.state.as_deref()) else { return Err(Fail::new("failed", "no code or state")) };
    // The state is single use: gone once looked up, whatever happens next.
    type StateRow = (Vec<u8>, Uuid, String, String, String);
    let row: Option<StateRow> = sqlx::query_as(
        "DELETE FROM sso_login_states WHERE state_hash = $1 AND expires_at > now() RETURNING binding_hash, provider_id, nonce, code_verifier, next",
    )
    .bind(auth::token_hash(state))
    .fetch_optional(&st.db)
    .await?;
    let Some((binding_hash, provider_id, nonce, verifier, next)) = row else {
        return Err(Fail::new("expired", "unknown or expired state"));
    };
    let fail = |f: Fail| f.loud(provider_id);
    // A callback must come back to the browser that started it, or anyone could hand a victim a
    // link that signs them in as the attacker.
    let binding_ok = cookie(headers, BINDING_COOKIE).is_some_and(|c| bool::from(auth::token_hash(c).ct_eq(&binding_hash)));
    if !binding_ok {
        return Err(fail(Fail::new("failed", "the state cookie doesn't match")));
    }
    let provider = match load_provider(&st.db, provider_id).await? {
        Some(p) if p.enabled => p,
        _ => return Err(fail(Fail::new("provider_error", "provider removed or disabled"))),
    };
    let secret = open_secret(st, &provider)?;
    let redirect = redirect_uri(st);
    let disc = st.oidc.discovery(&provider.issuer, false).await.map_err(|e| fail(e.into()))?;
    let id_token = st.oidc.exchange_code(&disc, &provider.client_id, &secret, &redirect, code, &verifier).await.map_err(|e| fail(e.into()))?;
    let claims = st
        .oidc
        .validate(
            &provider.issuer,
            &disc,
            &id_token,
            &Expect { issuer: &disc.issuer, client_id: &provider.client_id, nonce: &nonce, now: Utc::now().timestamp(), allowed_tenants: &provider.allowed_tenants },
        )
        .await
        .map_err(|e| fail(e.into()))?;
    let identity = oidc::identity(&claims, &provider.groups_claim, provider.trust_email, provider.preset == "entra");
    let with_email = |mut f: Fail| {
        f.email = identity.email.clone();
        f.loud(provider_id)
    };

    // A Google Workspace account carries its domain in `hd`; a personal account on a company
    // address doesn't, and mustn't pass for one.
    if provider.preset == "google" && !claims["hd"].as_str().is_some_and(|hd| provider.allowed_domains.iter().any(|a| a.eq_ignore_ascii_case(hd))) {
        return Err(with_email(Fail::new("not_allowed", "not a Google Workspace account of an allowed domain")));
    }
    if let Some(email) = &identity.email
        && !provider.allowed_domains.is_empty()
        && !email.rsplit_once('@').is_some_and(|(_, d)| provider.allowed_domains.iter().any(|a| a == d))
    {
        return Err(with_email(Fail::new("not_allowed", "email domain not allowed")));
    }
    if !provider.allowed_domains.is_empty() && identity.email.is_none() {
        return Err(with_email(Fail::new("not_allowed", "no email to check the domain of")));
    }
    // A token that only points at the user's groups says nothing about them: with group sync it
    // refuses the sign-in and changes nothing.
    let overage = provider.group_sync && oidc::groups_overage(&claims);
    if overage {
        return Err(with_email(Fail::new("not_allowed", "too many groups to read from the token")));
    }
    let groups = identity.groups.clone();
    let maps = load_mappings(&st.db, provider_id).await?;
    let fallback = provider.default_role.as_deref().and_then(Role::parse);

    let mut tx = st.db.begin().await?;
    let linked: Option<Uuid> = sqlx::query_scalar("SELECT user_id FROM user_identities WHERE provider_id = $1 AND subject = $2")
        .bind(provider_id)
        .bind(&identity.subject)
        .fetch_optional(&mut *tx)
        .await?;
    let mut created = false;
    let mut linked_now = false;
    let user_id = match linked {
        Some(id) => id,
        None => {
            // A first sign-in: the address must be one the provider vouches for.
            let Some(email) = identity.email.as_deref().filter(|_| identity.email_verified) else {
                return Err(with_email(Fail::new("not_allowed", "the provider sent no verified email address")));
            };
            let existing: Option<(Uuid, bool)> =
                sqlx::query_as("SELECT id, sso_exempt FROM users WHERE lower(email) = $1").bind(email).fetch_optional(&mut *tx).await?;
            match existing {
                // Break-glass accounts are the ones that must keep working when the provider doesn't,
                // so a claim from the provider never reaches them.
                Some((_, true)) => return Err(with_email(Fail::new("not_allowed", "break-glass accounts aren't linked by email"))),
                Some((id, false)) => {
                    linked_now = true;
                    id
                }
                None if provider.jit => {
                    // Without a mapped group or a default role, nobody is created.
                    if provider.group_sync && grant_for(&maps, &groups, fallback).is_none() || !provider.group_sync && fallback.is_none() {
                        return Err(with_email(Fail::new("not_allowed", "no group mapping and no default role for a new account")));
                    }
                    created = true;
                    let name = identity.name.clone().unwrap_or_else(|| email.split('@').next().unwrap_or(email).to_string());
                    let hash = auth::hash_password_async(&auth::random_token()).await?;
                    let id = Uuid::new_v4();
                    // The role is set by the grant below.
                    sqlx::query("INSERT INTO users (id, email, name, password_hash, role, all_clients, sso_only) VALUES ($1,$2,$3,$4,'readonly',false,true)")
                        .bind(id)
                        .bind(email)
                        .bind(name.chars().take(100).collect::<String>())
                        .bind(hash)
                        .execute(&mut *tx)
                        .await?;
                    id
                }
                None => return Err(with_email(Fail::new("no_account", "no account has this email address"))),
            }
        }
    };
    if linked_now || created {
        sqlx::query("INSERT INTO user_identities (user_id, provider_id, subject, email) VALUES ($1,$2,$3,$4)")
            .bind(user_id)
            .bind(provider_id)
            .bind(&identity.subject)
            .bind(identity.email.clone().unwrap_or_default())
            .execute(&mut *tx)
            .await
            .map_err(|e| match e {
                // The account is already linked to another identity at this provider.
                sqlx::Error::Database(d) if d.is_unique_violation() => with_email(Fail::new("not_allowed", "the account is linked to a different identity at this provider")),
                e => Fail::from(e),
            })?;
    }
    let (disabled, exempt): (bool, bool) = sqlx::query_as("SELECT disabled, sso_exempt FROM users WHERE id = $1").bind(user_id).fetch_one(&mut *tx).await?;
    if disabled {
        let mut f = with_email(Fail::new("not_allowed", "the account is disabled"));
        f.user = Some(user_id);
        return Err(f);
    }
    // Access from groups: always for a new account, and at every sign-in when the provider
    // syncs. Break-glass accounts keep whatever an admin gave them.
    let mut access_changed = None;
    if created || (provider.group_sync && !exempt) {
        let grant = if provider.group_sync { grant_for(&maps, &groups, fallback) } else { fallback.map(|role| Grant { role, permissions: None, all_clients: false, client_ids: vec![] }) };
        match grant {
            Some(g) => {
                if apply_grant(&mut tx, user_id, &g).await? {
                    access_changed = Some(json!({ "role": role_name(g.role), "all_clients": g.all_clients, "clients": g.client_ids.len(), "permissions": g.permissions }));
                }
            }
            None => {
                let mut f = with_email(Fail::new("not_allowed", "no group mapping matches"));
                f.user = Some(user_id);
                // Someone who signed in through this provider before and is in none of the groups any more
                // loses their access (and the sessions it vouched for). A first sign-in that matches
                // nothing changes nothing: trying SSO once must not demote an existing account.
                if linked.is_some() {
                    let demoted = Grant { role: Role::Readonly, permissions: None, all_clients: false, client_ids: vec![] };
                    let changed = apply_grant(&mut tx, user_id, &demoted).await?;
                    sqlx::query("DELETE FROM user_sessions WHERE user_id = $1 AND sso_provider_id = $2").bind(user_id).bind(provider_id).execute(&mut *tx).await?;
                    tx.commit().await?;
                    if changed {
                        auth::audit(&st.db, Some(user_id), "auth.sso_access_sync", Some(("user", user_id)), json!({ "role": "readonly", "removed_from_all_groups": true })).await;
                    }
                }
                return Err(f);
            }
        }
    }
    sqlx::query("UPDATE user_identities SET last_login_at = now(), email = COALESCE($3, email) WHERE provider_id = $1 AND subject = $2")
        .bind(provider_id)
        .bind(&identity.subject)
        .bind(&identity.email)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    if created {
        auth::audit(&st.db, Some(user_id), "user.create", Some(("user", user_id)), json!({ "email": identity.email, "via": "sso", "provider": provider.name })).await;
    }
    if linked_now {
        auth::audit(&st.db, Some(user_id), "auth.sso_link", Some(("user", user_id)), json!({ "provider": provider.name, "email": identity.email })).await;
    }
    if let Some(details) = access_changed {
        auth::audit(&st.db, Some(user_id), "auth.sso_access_sync", Some(("user", user_id)), details).await;
    }
    let (token, _) = super::auth::open_session(st, headers, user_id, Some(provider_id)).await.map_err(Fail::from)?;
    auth::audit(&st.db, Some(user_id), "auth.login", None, json!({ "ip": ip, "via": "sso", "provider": provider.name })).await;
    Ok((token, next))
}

async fn load_mappings(db: &sqlx::PgPool, provider_id: Uuid) -> sqlx::Result<Vec<Mapping>> {
    type Row = (String, String, Vec<String>, bool, Vec<Uuid>);
    let rows: Vec<Row> = sqlx::query_as("SELECT group_value, role, extra_permissions, all_clients, client_ids FROM sso_group_maps WHERE provider_id = $1")
        .bind(provider_id)
        .fetch_all(db)
        .await?;
    Ok(rows
        .into_iter()
        .map(|(group, role, extra, all_clients, client_ids)| Mapping {
            group,
            role: Role::parse(&role).unwrap_or(Role::Readonly),
            extra: extra.iter().filter_map(|p| Perm::parse(p)).collect(),
            all_clients,
            client_ids,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(group: &str, role: Role, extra: &[Perm], all: bool, clients: &[Uuid]) -> Mapping {
        Mapping { group: group.into(), role, extra: extra.to_vec(), all_clients: all, client_ids: clients.to_vec() }
    }

    #[test]
    fn highest_role_and_union_of_clients() {
        let (a, b) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let maps = [
            map("techs", Role::Technician, &[], false, &[a]),
            map("leads", Role::Technician, &[Perm::BillingRead], false, &[b, a]),
            map("everyone", Role::Readonly, &[], false, &[]),
            map("admins", Role::Admin, &[], true, &[]),
        ];
        let g = |groups: &[&str], fb| grant_for(&maps, &groups.iter().map(|s| s.to_string()).collect::<Vec<_>>(), fb);
        let t = g(&["TECHS", "everyone"], None).unwrap();
        assert_eq!((t.role, t.permissions.clone(), t.all_clients, t.client_ids.clone()), (Role::Technician, None, false, vec![a]));
        let lead = g(&["techs", "leads"], None).unwrap();
        assert_eq!(lead.client_ids, vec![a, b]);
        // Extras are added to the role's defaults, which stay.
        let perms = lead.permissions.unwrap();
        assert!(perms.contains(&"billing.read".to_string()) && perms.contains(&"vault.read".to_string()) && !perms.contains(&"billing.manage".to_string()), "{perms:?}");
        assert_eq!(g(&["admins", "techs"], None).unwrap().role, Role::Admin);
        assert!(g(&["admins"], None).unwrap().all_clients);
        // Nothing matches: nobody without a fallback; the fallback role without any clients.
        assert_eq!(g(&["other"], None), None);
        assert_eq!(g(&[], Some(Role::Readonly)), Some(Grant { role: Role::Readonly, permissions: None, all_clients: false, client_ids: vec![] }));
    }

    #[test]
    fn next_paths_stay_on_the_site() {
        for ok in ["/", "/agents?x=1", "/tickets/abc#top"] {
            assert_eq!(safe_next(Some(ok)), ok);
        }
        for bad in ["//evil.example.com", "https://evil.example.com", "/\\evil.example.com", "evil", "/a\nb", ""] {
            assert_eq!(safe_next(Some(bad)), "/", "{bad:?}");
        }
        assert_eq!(safe_next(None), "/");
    }

    #[test]
    fn cookies_are_found_by_exact_name() {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, "other=1; rmm_sso_x=bad; rmm_sso=good".parse().unwrap());
        assert_eq!(cookie(&h, "rmm_sso"), Some("good"));
        assert_eq!(cookie(&h, "nope"), None);
    }

    fn input(preset: &str, issuer: &str, tenants: &[&str]) -> ProviderInput {
        ProviderInput {
            name: "IdP".into(),
            preset: Some(preset.into()),
            issuer: issuer.into(),
            client_id: "c".into(),
            client_secret: Some("s".into()),
            scopes: None,
            enabled: true,
            groups_claim: None,
            jit: false,
            group_sync: false,
            default_role: None,
            allowed_domains: vec![],
            allowed_tenants: tenants.iter().map(|t| t.to_string()).collect(),
            trust_email: false,
        }
    }

    #[test]
    fn preset_rules() {
        let tenant = "11111111-2222-3333-4444-555555555555";
        let entra = |tenant: &str| format!("https://login.microsoftonline.com/{tenant}/v2.0");
        let c = clean(&input("entra", &entra(tenant), &[])).unwrap();
        assert!(c.trust_email, "Entra work accounts are believed within the tenant");
        assert!(clean(&input("entra", &entra("organizations"), &[])).is_err(), "every tenant would be admitted");
        assert!(clean(&input("entra", &entra("organizations"), &[tenant])).is_ok());
        assert!(clean(&input("entra", &entra("consumers"), &[tenant])).is_err());
        assert!(clean(&input("entra", &entra("common"), &["not-a-guid"])).is_err());
        assert!(clean(&input("entra", "https://evil.example.com/x/v2.0", &[])).is_err());
        assert!(clean(&input("google", GOOGLE_ISSUER, &[])).is_err(), "Google needs a domain");
        let mut g = input("google", GOOGLE_ISSUER, &[]);
        g.allowed_domains = vec!["@Msp.Example".into()];
        assert_eq!(clean(&g).unwrap().allowed_domains, ["msp.example"]);
        let mut admin_default = input("custom", "https://idp.example.com", &[]);
        admin_default.default_role = Some("admin".into());
        assert!(clean(&admin_default).is_err(), "nobody is an admin by default");
        assert!(clean(&input("google", "https://accounts.google.com.evil.example", &[])).is_err());
        assert!(clean(&input("custom", "http://idp.example.com", &[])).is_err(), "plain http only on the machine itself");
        assert!(clean(&input("custom", "http://127.0.0.1:9000", &[])).is_ok());
        let mut jit = input("custom", "https://idp.example.com", &[]);
        jit.jit = true;
        assert!(clean(&jit).is_err(), "JIT needs a way to pick the role");
        jit.default_role = Some("readonly".into());
        assert!(clean(&jit).is_ok());
        let mut sc = input("custom", "https://idp.example.com", &[]);
        sc.scopes = Some("openid\" onmouseover=\"x".into());
        assert!(clean(&sc).is_err());
    }
}
