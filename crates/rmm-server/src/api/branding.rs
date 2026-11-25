//! Branding settings: the instance's (`/settings/branding`) and a client's override
//! (`/clients/{id}/branding`), both admin-only, and the public image routes. The rules are in
//! [`crate::branding`].

use std::sync::Arc;

use axum::Json;
use axum::extract::{Multipart, Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::auth::{self, Role, User};
use crate::branding::{self, Row, Variant};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

fn variant(s: &str) -> ApiResult<Variant> {
    Variant::parse(s).ok_or(ApiError::NotFound("image"))
}

/// The stored row of a scope (instance or one client), as the settings page edits it.
fn view(st: &AppState, scope: Option<Uuid>) -> Value {
    let row = st.branding.row(scope).unwrap_or_default();
    let base = match scope {
        Some(c) => format!("/api/clients/{c}/branding"),
        None => "/api/settings/branding".into(),
    };
    let img = |k: &Option<String>, v: Variant| k.as_ref().map(|k| format!("{base}/{}?v={}", v.as_str(), branding::etag(k)));
    json!({
        "exists": st.branding.row(scope).is_some(),
        "product_name": row.product_name,
        "accent": row.accent,
        "support_email": row.support_email,
        "support_phone": row.support_phone,
        "support_url": row.support_url,
        "support_hours": row.support_hours,
        "email_from_name": row.email_from_name,
        "email_footer": row.email_footer,
        "logo_light": img(&row.logo_light, Variant::LogoLight),
        "logo_dark": img(&row.logo_dark, Variant::LogoDark),
        "icon": img(&row.icon, Variant::Icon),
        "updated_at": row.updated_at,
        // What it adds up to (for a client: its own values over the instance's).
        "resolved": branding::resolve(st, scope),
    })
}

#[derive(Deserialize, Default)]
pub struct Update {
    product_name: Option<String>,
    accent: Option<String>,
    support_email: Option<String>,
    support_phone: Option<String>,
    support_url: Option<String>,
    support_hours: Option<String>,
    email_from_name: Option<String>,
    email_footer: Option<String>,
}

/// Trimmed, `None` when blank, refused when longer than `max` characters or (unless
/// `multiline`) containing control characters.
fn text(label: &str, v: Option<String>, max: usize, multiline: bool) -> ApiResult<Option<String>> {
    let Some(v) = v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) else { return Ok(None) };
    if v.chars().count() > max {
        return Err(ApiError::BadRequest(format!("{label} must be at most {max} characters")));
    }
    if v.chars().any(|c| c.is_control() && !(multiline && (c == '\n' || c == '\r' || c == '\t'))) {
        return Err(ApiError::BadRequest(format!("{label} can't contain control characters")));
    }
    Ok(Some(v))
}

fn clean(b: Update) -> ApiResult<Update> {
    let accent = match text("the accent colour", b.accent, 7, false)? {
        Some(a) => Some(branding::validate_accent(&a).map_err(ApiError::BadRequest)?),
        None => None,
    };
    let support_email = text("the support email", b.support_email, 254, false)?;
    if let Some(e) = &support_email
        && e.parse::<lettre::Address>().is_err()
    {
        return Err(ApiError::BadRequest(format!("{e} is not an email address")));
    }
    let support_phone = text("the support phone number", b.support_phone, 40, false)?;
    if let Some(p) = &support_phone
        && !p.chars().all(|c| c.is_ascii_digit() || " +-().".contains(c))
    {
        return Err(ApiError::BadRequest("a phone number has digits, spaces and + - ( ) . only".into()));
    }
    let support_url = text("the support URL", b.support_url, 300, false)?;
    if let Some(u) = &support_url
        && !(u.starts_with("https://") || u.starts_with("http://"))
    {
        return Err(ApiError::BadRequest("the support URL must start with https://".into()));
    }
    let email_from_name = text("the sender name", b.email_from_name, 80, false)?;
    if email_from_name.as_deref().is_some_and(|n| n.contains(['<', '>', '"'])) {
        return Err(ApiError::BadRequest("the sender name can't contain < > or \"".into()));
    }
    Ok(Update {
        product_name: text("the product name", b.product_name, 60, false)?,
        accent,
        support_email,
        support_phone,
        support_url,
        support_hours: text("the support hours", b.support_hours, 100, false)?,
        email_from_name,
        email_footer: text("the email footer", b.email_footer, 1000, true)?,
    })
}

async fn client_exists(st: &AppState, id: Uuid) -> ApiResult<()> {
    let found: Option<Uuid> = sqlx::query_scalar("SELECT id FROM clients WHERE id = $1").bind(id).fetch_optional(&st.db).await?;
    found.map(|_| ()).ok_or(ApiError::NotFound("client"))
}

async fn save(st: &AppState, u: &User, scope: Option<Uuid>, b: Update) -> ApiResult<Value> {
    let b = clean(b)?;
    let before = st.branding.row(scope).unwrap_or_default();
    sqlx::query(
        "INSERT INTO branding (client_id, product_name, accent, support_email, support_phone, support_url, support_hours,
                               email_from_name, email_footer, updated_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         ON CONFLICT ON CONSTRAINT branding_client DO UPDATE
            SET product_name = $2, accent = $3, support_email = $4, support_phone = $5, support_url = $6, support_hours = $7,
                email_from_name = $8, email_footer = $9, updated_by = $10, updated_at = now()",
    )
    .bind(scope)
    .bind(&b.product_name)
    .bind(&b.accent)
    .bind(&b.support_email)
    .bind(&b.support_phone)
    .bind(&b.support_url)
    .bind(&b.support_hours)
    .bind(&b.email_from_name)
    .bind(&b.email_footer)
    .bind(u.id)
    .execute(&st.db)
    .await?;
    st.branding.reload(&st.db).await?;
    crate::helpdesk_agent::branding_changed(st, scope).await;
    let changed: Vec<&str> = [
        ("product_name", before.product_name == b.product_name),
        ("accent", before.accent == b.accent),
        ("support_email", before.support_email == b.support_email),
        ("support_phone", before.support_phone == b.support_phone),
        ("support_url", before.support_url == b.support_url),
        ("support_hours", before.support_hours == b.support_hours),
        ("email_from_name", before.email_from_name == b.email_from_name),
        ("email_footer", before.email_footer == b.email_footer),
    ]
    .into_iter()
    .filter(|(_, same)| !same)
    .map(|(k, _)| k)
    .collect();
    auth::audit(
        &st.db,
        Some(u.id),
        "branding.update",
        scope.map(|c| ("client", c)),
        json!({ "scope": if scope.is_some() { "client" } else { "instance" }, "changed": changed, "product_name": b.product_name }),
    )
    .await;
    Ok(view(st, scope))
}

async fn upload(st: &AppState, u: &User, scope: Option<Uuid>, v: Variant, mut form: Multipart) -> ApiResult<Value> {
    let mut bytes = None;
    while let Some(field) = form.next_field().await.map_err(|e| ApiError::BadRequest(format!("upload: {e}")))? {
        if field.name() == Some("file") {
            bytes = Some(field.bytes().await.map_err(|e| ApiError::BadRequest(format!("upload: {e}")))?);
        }
    }
    let bytes = bytes.ok_or_else(|| ApiError::BadRequest("no file in the upload (field `file`)".into()))?;
    let info = branding::check_image(v, &bytes).map_err(ApiError::BadRequest)?;
    let (ext, ct) = match info.format {
        branding::Format::Png => ("png", "image/png"),
        branding::Format::Jpeg => ("jpg", "image/jpeg"),
    };
    let owner = scope.map_or("instance".to_string(), |c| c.to_string());
    let key = format!("branding/{owner}/{}-{}.{ext}", v.as_str(), Uuid::new_v4().simple());
    st.storage.put(&key, bytes.to_vec(), ct).await?;
    let old = set_image(st, u, scope, v, Some(&key)).await;
    if let Err(e) = &old {
        let _ = st.storage.delete(&key).await;
        tracing::warn!("saving a branding image: {e}");
    }
    if let Some(old) = old? {
        let _ = st.storage.delete(&old).await;
    }
    auth::audit(
        &st.db,
        Some(u.id),
        "branding.update",
        scope.map(|c| ("client", c)),
        json!({ "scope": if scope.is_some() { "client" } else { "instance" }, "image": v.as_str(), "width": info.width, "height": info.height }),
    )
    .await;
    Ok(view(st, scope))
}

/// Points the scope's image column at `key` (or clears it); returns the key it replaced.
async fn set_image(st: &AppState, u: &User, scope: Option<Uuid>, v: Variant, key: Option<&str>) -> ApiResult<Option<String>> {
    let col = v.as_str(); // a fixed column name, never user input
    let mut tx = st.db.begin().await?;
    sqlx::query("INSERT INTO branding (client_id, updated_by) VALUES ($1, $2) ON CONFLICT ON CONSTRAINT branding_client DO NOTHING")
        .bind(scope)
        .bind(u.id)
        .execute(&mut *tx)
        .await?;
    let old: Option<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT {col} FROM branding WHERE client_id IS NOT DISTINCT FROM $1 FOR UPDATE"
    )))
    .bind(scope)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE branding SET {col} = $2, updated_by = $3, updated_at = now() WHERE client_id IS NOT DISTINCT FROM $1"
    )))
    .bind(scope)
    .bind(key)
    .bind(u.id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    st.branding.reload(&st.db).await?;
    crate::helpdesk_agent::branding_changed(st, scope).await;
    Ok(old)
}

async fn remove_image(st: &AppState, u: &User, scope: Option<Uuid>, v: Variant) -> ApiResult<Value> {
    if st.branding.row(scope).is_some()
        && let Some(old) = set_image(st, u, scope, v, None).await?
    {
        let _ = st.storage.delete(&old).await;
        auth::audit(
            &st.db,
            Some(u.id),
            "branding.update",
            scope.map(|c| ("client", c)),
            json!({ "scope": if scope.is_some() { "client" } else { "instance" }, "image": v.as_str(), "removed": true }),
        )
        .await;
    }
    Ok(view(st, scope))
}

/// An image response with an ETag, or 304 when the browser has it.
fn image_response(found: Option<(Vec<u8>, &'static str, String)>, headers: &HeaderMap, cache: &'static str) -> ApiResult<Response> {
    let (bytes, ct, tag) = found.ok_or(ApiError::NotFound("image"))?;
    let etag = format!("\"{tag}\"");
    let etag_value = HeaderValue::from_str(&etag).map_err(anyhow::Error::from)?;
    let cache = HeaderValue::from_static(cache);
    if headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()).is_some_and(|v| v.split(',').any(|t| t.trim() == etag)) {
        return Ok((StatusCode::NOT_MODIFIED, [(header::ETAG, etag_value), (header::CACHE_CONTROL, cache)]).into_response());
    }
    Ok(([(header::CONTENT_TYPE, HeaderValue::from_static(ct)), (header::ETAG, etag_value), (header::CACHE_CONTROL, cache)], bytes).into_response())
}

// --- the instance -------------------------------------------------------------------------

pub async fn get(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    Ok(Json(view(&st, None)))
}

pub async fn update(State(st): State<Arc<AppState>>, u: User, Json(b): Json<Update>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    Ok(Json(save(&st, &u, None, b).await?))
}

pub async fn upload_instance(State(st): State<Arc<AppState>>, u: User, Path(v): Path<String>, form: Multipart) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    let v = variant(&v)?;
    Ok(Json(upload(&st, &u, None, v, form).await?))
}

pub async fn remove_instance_image(State(st): State<Arc<AppState>>, u: User, Path(v): Path<String>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    let v = variant(&v)?;
    Ok(Json(remove_image(&st, &u, None, v).await?))
}

/// The instance's image; what the console, the sign-in pages and emails link to. Public.
pub async fn public_image(State(st): State<Arc<AppState>>, Path(v): Path<String>, headers: HeaderMap) -> ApiResult<Response> {
    let v = variant(&v)?;
    image_response(branding::image(&st, None, v).await?, &headers, "public, max-age=300")
}

/// The image a signed-in portal contact sees: their client's own, else the instance's. (The
/// portal session cookie is scoped to `/api/portal`, so this lives under it.)
pub async fn portal_image(State(st): State<Arc<AppState>>, c: super::portal::Contact, Path(v): Path<String>, headers: HeaderMap) -> ApiResult<Response> {
    let v = variant(&v)?;
    image_response(branding::image(&st, Some(c.client_id), v).await?, &headers, "private, max-age=300")
}

// --- a client's override -----------------------------------------------------------------------

pub async fn get_client(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    client_exists(&st, id).await?;
    Ok(Json(view(&st, Some(id))))
}

pub async fn update_client(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<Update>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    client_exists(&st, id).await?;
    Ok(Json(save(&st, &u, Some(id), b).await?))
}

/// Removes the override: the client's people see the instance's branding again.
pub async fn delete_client(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    client_exists(&st, id).await?;
    let gone: Option<Row> = sqlx::query_as(sqlx::AssertSqlSafe(format!("DELETE FROM branding WHERE client_id = $1 RETURNING {}", branding::COLUMNS)))
        .bind(id)
        .fetch_optional(&st.db)
        .await?;
    st.branding.reload(&st.db).await?;
    crate::helpdesk_agent::branding_changed(&st, Some(id)).await;
    if let Some(r) = gone {
        for k in [r.logo_light, r.logo_dark, r.icon].into_iter().flatten() {
            let _ = st.storage.delete(&k).await;
        }
        auth::audit(&st.db, Some(u.id), "branding.update", Some(("client", id)), json!({ "scope": "client", "removed": true })).await;
    }
    Ok(Json(view(&st, Some(id))))
}

pub async fn upload_client(State(st): State<Arc<AppState>>, u: User, Path((id, v)): Path<(Uuid, String)>, form: Multipart) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    let v = variant(&v)?;
    client_exists(&st, id).await?;
    Ok(Json(upload(&st, &u, Some(id), v, form).await?))
}

pub async fn remove_client_image(State(st): State<Arc<AppState>>, u: User, Path((id, v)): Path<(Uuid, String)>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    let v = variant(&v)?;
    client_exists(&st, id).await?;
    Ok(Json(remove_image(&st, &u, Some(id), v).await?))
}

/// A client's own image (not the instance's), for the settings preview.
pub async fn client_image(State(st): State<Arc<AppState>>, u: User, Path((id, v)): Path<(Uuid, String)>, headers: HeaderMap) -> ApiResult<Response> {
    u.require(Role::Admin)?;
    instance_or_client_image(&st, Some(id), variant(&v)?, &headers).await
}

/// The instance's own image, for the settings preview (same as the public route).
pub async fn instance_image(State(st): State<Arc<AppState>>, u: User, Path(v): Path<String>, headers: HeaderMap) -> ApiResult<Response> {
    u.require(Role::Admin)?;
    instance_or_client_image(&st, None, variant(&v)?, &headers).await
}

async fn instance_or_client_image(st: &AppState, scope: Option<Uuid>, v: Variant, headers: &HeaderMap) -> ApiResult<Response> {
    let row = st.branding.row(scope).unwrap_or_default();
    let key = match v {
        Variant::LogoLight => row.logo_light,
        Variant::LogoDark => row.logo_dark,
        Variant::Icon => row.icon,
    };
    let found = match key {
        Some(k) => {
            let bytes = st.storage.get(&k).await?;
            let ct = if branding::sniff(&bytes) == Some(branding::Format::Jpeg) { "image/jpeg" } else { "image/png" };
            Some((bytes, ct, branding::etag(&k)))
        }
        None => None,
    };
    image_response(found, headers, "private, max-age=60")
}
