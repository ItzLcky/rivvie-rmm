use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::auth::{self, Role, User};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

#[derive(Serialize, sqlx::FromRow)]
pub struct SiteRow {
    id: Uuid,
    client_id: Uuid,
    name: String,
    agent_count: i64,
    online_count: i64,
}

#[derive(Serialize)]
pub struct ClientOut {
    id: Uuid,
    name: String,
    created_at: DateTime<Utc>,
    sites: Vec<SiteRow>,
}

pub async fn list(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Vec<ClientOut>>> {
    let clients: Vec<(Uuid, String, DateTime<Utc>)> =
        sqlx::query_as("SELECT id, name, created_at FROM clients WHERE ($1::uuid[] IS NULL OR id = ANY($1)) ORDER BY name")
            .bind(u.scope())
            .fetch_all(&st.db)
            .await?;
    let sites: Vec<SiteRow> = sqlx::query_as(
        "SELECT s.id, s.client_id, s.name,
                count(a.id) AS agent_count,
                count(a.id) FILTER (WHERE a.online) AS online_count
           FROM sites s LEFT JOIN agents a ON a.site_id = s.id
          WHERE ($1::uuid[] IS NULL OR s.client_id = ANY($1))
          GROUP BY s.id ORDER BY s.name",
    )
    .bind(u.scope())
    .fetch_all(&st.db)
    .await?;
    let mut out: Vec<ClientOut> =
        clients.into_iter().map(|(id, name, created_at)| ClientOut { id, name, created_at, sites: vec![] }).collect();
    for s in sites {
        if let Some(c) = out.iter_mut().find(|c| c.id == s.client_id) {
            c.sites.push(s);
        }
    }
    Ok(Json(out))
}

#[derive(Deserialize)]
pub struct NameBody {
    name: String,
}

fn clean_name(n: &str) -> ApiResult<String> {
    let n = n.trim();
    if n.is_empty() || n.len() > 200 {
        return Err(ApiError::BadRequest("name must be 1-200 characters".into()));
    }
    Ok(n.to_string())
}

pub async fn create(State(st): State<Arc<AppState>>, u: User, Json(b): Json<NameBody>) -> ApiResult<Json<serde_json::Value>> {
    u.require(Role::Admin)?;
    let name = clean_name(&b.name)?;
    let id = Uuid::new_v4();
    let mut tx = st.db.begin().await?;
    sqlx::query("INSERT INTO clients (id, name) VALUES ($1,$2)").bind(id).bind(&name).execute(&mut *tx).await?;
    // Every client starts with a default site so it can enroll agents immediately.
    let site_id = Uuid::new_v4();
    sqlx::query("INSERT INTO sites (id, client_id, name) VALUES ($1,$2,'Main')").bind(site_id).bind(id).execute(&mut *tx).await?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "client.create", Some(("client", id)), json!({ "name": name })).await;
    Ok(Json(json!({ "id": id, "default_site_id": site_id })))
}

pub async fn remove(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<serde_json::Value>> {
    u.require(Role::Admin)?;
    let n = sqlx::query("DELETE FROM clients WHERE id = $1").bind(id).execute(&st.db).await?.rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound("client"));
    }
    auth::audit(&st.db, Some(u.id), "client.delete", Some(("client", id)), json!({})).await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn create_site(
    State(st): State<Arc<AppState>>,
    u: User,
    Path(client_id): Path<Uuid>,
    Json(b): Json<NameBody>,
) -> ApiResult<Json<serde_json::Value>> {
    u.require(Role::Admin)?;
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO sites (id, client_id, name) VALUES ($1,$2,$3)")
        .bind(id)
        .bind(client_id)
        .bind(clean_name(&b.name)?)
        .execute(&st.db)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(d) if d.is_foreign_key_violation() => ApiError::NotFound("client"),
            e => e.into(),
        })?;
    auth::audit(&st.db, Some(u.id), "site.create", Some(("site", id)), json!({ "client_id": client_id })).await;
    Ok(Json(json!({ "id": id })))
}

pub async fn remove_site(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<serde_json::Value>> {
    u.require(Role::Admin)?;
    let n = sqlx::query("DELETE FROM sites WHERE id = $1").bind(id).execute(&st.db).await?.rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound("site"));
    }
    auth::audit(&st.db, Some(u.id), "site.delete", Some(("site", id)), json!({})).await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Serialize, sqlx::FromRow)]
pub struct TokenRow {
    id: Uuid,
    label: String,
    max_uses: Option<i32>,
    uses: i32,
    expires_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

pub async fn list_tokens(State(st): State<Arc<AppState>>, u: User, Path(site_id): Path<Uuid>) -> ApiResult<Json<Vec<TokenRow>>> {
    u.require(Role::Technician)?;
    super::access::site(&st, &u, site_id).await?;
    Ok(Json(
        sqlx::query_as(
            "SELECT id, label, max_uses, uses, expires_at, created_at FROM enrollment_tokens
              WHERE site_id = $1 ORDER BY created_at DESC",
        )
        .bind(site_id)
        .fetch_all(&st.db)
        .await?,
    ))
}

#[derive(Deserialize)]
pub struct NewToken {
    #[serde(default)]
    label: String,
    max_uses: Option<i32>,
    /// Defaults to 7 days (30 for packages). 0 = never expires (not allowed for packages).
    expires_in_hours: Option<i64>,
    /// `package`: for baking into .deb/.rpm files, which get copied around, so it must be
    /// bounded: defaults to 30 days and 50 uses, and refuses "never" or "unlimited".
    #[serde(default)]
    purpose: Option<String>,
}

pub const PACKAGE_TOKEN_HOURS: i64 = 24 * 30;
pub const PACKAGE_TOKEN_USES: i32 = 50;

pub async fn create_token(
    State(st): State<Arc<AppState>>,
    u: User,
    Path(site_id): Path<Uuid>,
    Json(b): Json<NewToken>,
) -> ApiResult<Json<serde_json::Value>> {
    u.require(Role::Technician)?;
    super::access::site(&st, &u, site_id).await?;
    let package = match b.purpose.as_deref() {
        None | Some("") => false,
        Some("package") => true,
        Some(other) => return Err(ApiError::BadRequest(format!("unknown token purpose {other}"))),
    };
    let (hours, max_uses) = if package {
        let hours = b.expires_in_hours.unwrap_or(PACKAGE_TOKEN_HOURS);
        let uses = b.max_uses.unwrap_or(PACKAGE_TOKEN_USES);
        if hours <= 0 || uses <= 0 {
            return Err(ApiError::BadRequest("package tokens need an expiry and a use limit".into()));
        }
        (hours, Some(uses))
    } else {
        (b.expires_in_hours.unwrap_or(24 * 7), b.max_uses.filter(|n| *n > 0))
    };
    let expires_at = (hours > 0).then(|| Utc::now() + Duration::hours(hours));
    let token = auth::random_token();
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO enrollment_tokens (id, site_id, token_hash, label, max_uses, expires_at, created_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(id)
    .bind(site_id)
    .bind(auth::token_hash(&token))
    .bind(b.label.trim())
    .bind(max_uses)
    .bind(expires_at)
    .bind(u.id)
    .execute(&st.db)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(d) if d.is_foreign_key_violation() => ApiError::NotFound("site"),
        e => e.into(),
    })?;
    auth::audit(&st.db, Some(u.id), "enrollment_token.create", Some(("site", site_id)), json!({ "token_id": id, "package": package }))
        .await;

    let url = &st.cfg.public_url;
    let mut linux = format!("sudo ./rmm-agent enroll --server {url} --token {token} --install");
    let mut windows = format!(".\\rmm-agent.exe enroll --server {url} --token {token} --install");
    // When the server has the binaries, make each command self-contained: fetch, then enroll.
    // The token authorizes the download without spending a use. It's hex, so no URL escaping.
    if super::agent_binary_exists(&st, "linux-x86_64") {
        linux = format!(
            "curl -fsSLo rmm-agent \"{url}/api/agent-downloads/linux-x86_64?token={token}\" && chmod +x rmm-agent && {linux}"
        );
    }
    if super::agent_binary_exists(&st, "windows-x86_64") {
        windows = format!(
            "$ProgressPreference = 'SilentlyContinue'; \
             Invoke-WebRequest -UseBasicParsing \"{url}/api/agent-downloads/windows-x86_64?token={token}\" -OutFile rmm-agent.exe; \
             {windows}"
        );
    }
    // Bounded tokens can also be baked into Linux packages.
    let packages = (expires_at.is_some() && max_uses.is_some() && super::agent_binary_exists(&st, "linux-x86_64")).then(|| {
        let base = format!("{url}/api/agent-packages/linux-x86_64");
        json!({
            "deb": format!("{base}/rmm-agent.deb?token={token}"),
            "rpm": format!("{base}/rmm-agent.rpm?token={token}"),
            "install_deb": format!("curl -fsSLo /tmp/rmm-agent.deb \"{base}/rmm-agent.deb?token={token}\" && sudo apt-get install -y /tmp/rmm-agent.deb"),
            "install_rpm": format!("curl -fsSLo /tmp/rmm-agent.rpm \"{base}/rmm-agent.rpm?token={token}\" && sudo dnf install -y /tmp/rmm-agent.rpm"),
        })
    });
    Ok(Json(json!({
        "id": id,
        "token": token,
        "expires_at": expires_at,
        "max_uses": max_uses,
        "install": { "linux": linux, "windows": windows },
        "packages": packages,
    })))
}

pub async fn revoke_token(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<serde_json::Value>> {
    u.require(Role::Technician)?;
    let n = sqlx::query(
        "DELETE FROM enrollment_tokens t USING sites s
          WHERE t.id = $1 AND s.id = t.site_id AND ($2::uuid[] IS NULL OR s.client_id = ANY($2))",
    )
    .bind(id)
    .bind(u.scope())
    .execute(&st.db)
    .await?
    .rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound("enrollment token"));
    }
    auth::audit(&st.db, Some(u.id), "enrollment_token.revoke", Some(("enrollment_token", id)), json!({})).await;
    Ok(Json(json!({ "ok": true })))
}
