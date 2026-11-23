//! The per-client password vault (docs/design/documentation.md#password-vault).
//!
//! Envelope encryption: each client has a random key, wrapped with `RMM_DATA_KEY`
//! ("vault-key:<client id>" as associated data), that seals an item's password, notes and TOTP
//! secret ("<item id>:<column>"), so a ciphertext moved to another row or column won't open.
//! There is no plaintext fallback: without `RMM_DATA_KEY` every endpoint answers 409.
//!
//! Secrets leave the server only through `reveal`, one field per call, rate-limited and
//! audited; TOTP secrets never do (the server computes the code). Nothing here logs a secret,
//! and errors never echo one.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};
use sqlx::AssertSqlSafe;
use uuid::Uuid;

use crate::auth::{self, Perm, User};
use crate::crypto::DataKey;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use crate::totp;

/// Earlier passwords kept per item.
const HISTORY_KEPT: i64 = 10;

/// Whether `u` may see vault items at all (metadata on documents included).
pub fn can_read(u: &User) -> bool {
    u.has(Perm::VaultRead) && u.second_factor()
}

/// The access checks every vault endpoint makes, in this order: the client is one `u` sees
/// (else 404), `u` holds `perm`, has two-factor authentication on, and the server has
/// `RMM_DATA_KEY`. Returns that key.
fn gate<'a>(st: &'a AppState, u: &User, client: Uuid, perm: Perm) -> ApiResult<&'a DataKey> {
    super::access::client(u, client)?;
    u.need(perm)?;
    if !u.second_factor() {
        return Err(ApiError::Denied("turn on two-factor authentication to use the vault".into()));
    }
    st.cfg.data_key.as_ref().ok_or_else(|| ApiError::Conflict("the vault needs RMM_DATA_KEY to be set on the server".into()))
}

/// [`gate`] for one item: an unknown item and another client's are both 404.
async fn item_gate<'a>(st: &'a AppState, u: &User, id: Uuid, perm: Perm) -> ApiResult<(Uuid, &'a DataKey)> {
    let client: Uuid = sqlx::query_scalar("SELECT client_id FROM vault_items WHERE id = $1")
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .filter(|c| u.can_see_client(*c))
        .ok_or(ApiError::NotFound("credential"))?;
    Ok((client, gate(st, u, client, perm)?))
}

/// The client's vault key, made on first use. Two first uses at once both end up with the
/// one that was stored.
async fn client_key(st: &AppState, master: &DataKey, client: Uuid) -> ApiResult<DataKey> {
    let aad = format!("vault-key:{client}");
    let load = || sqlx::query_scalar::<_, Vec<u8>>("SELECT wrapped_key FROM vault_keys WHERE client_id = $1").bind(client).fetch_optional(&st.db);
    let wrapped = match load().await? {
        Some(w) => w,
        None => {
            let mut raw = [0u8; 32];
            getrandom::fill(&mut raw).expect("OS RNG unavailable");
            sqlx::query("INSERT INTO vault_keys (client_id, wrapped_key) VALUES ($1, $2) ON CONFLICT (client_id) DO NOTHING")
                .bind(client)
                .bind(master.seal_aad(&raw, &aad))
                .execute(&st.db)
                .await
                .map_err(|e| match e {
                    sqlx::Error::Database(d) if d.is_foreign_key_violation() => ApiError::NotFound("client"),
                    e => e.into(),
                })?;
            load().await?.ok_or(ApiError::NotFound("client"))?
        }
    };
    let raw: [u8; 32] = master
        .open_aad(&wrapped, &aad)
        .and_then(|k| k.try_into().ok())
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("can't unwrap the vault key of client {client}: RMM_DATA_KEY has changed")))?;
    Ok(DataKey::from_bytes(raw))
}

fn seal(key: &DataKey, item: Uuid, field: &str, plain: &[u8]) -> Vec<u8> {
    key.seal_aad(plain, &format!("{item}:{field}"))
}

fn open(key: &DataKey, item: Uuid, field: &str, sealed: &[u8]) -> ApiResult<Vec<u8>> {
    key.open_aad(sealed, &format!("{item}:{field}"))
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("vault item {item}: {field} doesn't decrypt")))
}

#[derive(Serialize, sqlx::FromRow)]
pub struct ItemRow {
    id: Uuid,
    client_id: Uuid,
    name: String,
    username: String,
    url: String,
    has_password: bool,
    has_totp: bool,
    has_notes: bool,
    /// Pages linking to it.
    docs: i64,
    password_changed_at: Option<DateTime<Utc>>,
    updated_at: DateTime<Utc>,
    updated_by_name: Option<String>,
}

/// Metadata only: no sealed column is ever selected into a response.
pub const ITEM_COLS: &str = "i.id, i.client_id, i.name, i.username, i.url, i.password IS NOT NULL AS has_password,
     i.totp_secret IS NOT NULL AS has_totp, i.notes IS NOT NULL AS has_notes,
     (SELECT count(*) FROM client_doc_vault_links l WHERE l.item_id = i.id) AS docs,
     i.password_changed_at, i.updated_at, u.name AS updated_by_name
  FROM vault_items i LEFT JOIN users u ON u.id = i.updated_by";

pub async fn list(State(st): State<Arc<AppState>>, u: User, Path(client): Path<Uuid>) -> ApiResult<Json<Vec<ItemRow>>> {
    gate(&st, &u, client, Perm::VaultRead)?;
    Ok(Json(
        sqlx::query_as(AssertSqlSafe(format!("SELECT {ITEM_COLS} WHERE i.client_id = $1 ORDER BY lower(i.name), i.id")))
            .bind(client)
            .fetch_all(&st.db)
            .await?,
    ))
}

/// The metadata with the pages that link to it and the password history (dates only).
async fn detail(st: &AppState, id: Uuid) -> ApiResult<Value> {
    let item: ItemRow = sqlx::query_as(AssertSqlSafe(format!("SELECT {ITEM_COLS} WHERE i.id = $1")))
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("credential"))?;
    let docs: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT d.id, d.title FROM client_doc_vault_links l JOIN client_docs d ON d.id = l.doc_id WHERE l.item_id = $1 ORDER BY lower(d.title)",
    )
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    let history: Vec<(i64, DateTime<Utc>, Option<String>)> = sqlx::query_as(
        "SELECT h.id, h.replaced_at, u.name FROM vault_item_history h LEFT JOIN users u ON u.id = h.replaced_by WHERE h.item_id = $1 ORDER BY h.id DESC",
    )
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    let mut v = serde_json::to_value(&item).map_err(anyhow::Error::from)?;
    v["linked_docs"] = json!(docs.iter().map(|(id, t)| json!({ "id": id, "title": t })).collect::<Vec<_>>());
    v["history"] = json!(history.iter().map(|(id, at, by)| json!({ "id": id, "replaced_at": at, "replaced_by_name": by })).collect::<Vec<_>>());
    Ok(v)
}

pub async fn get(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    item_gate(&st, &u, id, Perm::VaultRead).await?;
    Ok(Json(detail(&st, id).await?))
}

fn clean_name(s: &str) -> ApiResult<String> {
    let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if s.is_empty() || s.chars().count() > 200 {
        return Err(ApiError::BadRequest("name must be 1-200 characters".into()));
    }
    Ok(s)
}

fn clean_username(s: &str) -> ApiResult<String> {
    let s = s.trim().to_string();
    if s.chars().count() > 200 {
        return Err(ApiError::BadRequest("the username is limited to 200 characters".into()));
    }
    Ok(s)
}

/// Shown as a link to open, so no script or data URLs.
fn clean_url(s: &str) -> ApiResult<String> {
    let s = s.trim().to_string();
    if s.chars().count() > 2000 {
        return Err(ApiError::BadRequest("the URL is limited to 2,000 characters".into()));
    }
    let lower = s.to_ascii_lowercase().replace(|c: char| c.is_ascii_whitespace() || c.is_ascii_control(), "");
    if ["javascript:", "data:", "vbscript:", "file:", "blob:"].iter().any(|p| lower.starts_with(p)) {
        return Err(ApiError::BadRequest("the URL must be a web address or host name".into()));
    }
    Ok(s)
}

/// A secret to store: an empty string is the same as none.
fn secret(s: Option<&str>, what: &str, max: usize) -> ApiResult<Option<String>> {
    match s {
        None | Some("") => Ok(None),
        Some(s) if s.chars().count() > max => Err(ApiError::BadRequest(format!("the {what} is limited to {max} characters"))),
        Some(s) => Ok(Some(s.to_string())),
    }
}

fn parse_totp(s: Option<&str>) -> ApiResult<Option<totp::Spec>> {
    match s.map(str::trim) {
        None | Some("") => Ok(None),
        Some(s) => totp::parse_spec(s).map(Some).map_err(|e| ApiError::BadRequest(e.into())),
    }
}

#[derive(Deserialize)]
pub struct NewItem {
    name: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    url: String,
    password: Option<String>,
    notes: Option<String>,
    /// A base32 secret or an `otpauth://totp/` URI.
    totp: Option<String>,
}

pub async fn create(State(st): State<Arc<AppState>>, u: User, Path(client): Path<Uuid>, Json(b): Json<NewItem>) -> ApiResult<Json<Value>> {
    let master = gate(&st, &u, client, Perm::VaultManage)?;
    let name = clean_name(&b.name)?;
    let username = clean_username(&b.username)?;
    let url = clean_url(&b.url)?;
    let password = secret(b.password.as_deref(), "password", 1000)?;
    let notes = secret(b.notes.as_deref(), "notes", 20_000)?;
    let spec = parse_totp(b.totp.as_deref())?;
    let key = client_key(&st, master, client).await?;
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO vault_items (id, client_id, name, username, url, password, notes, totp_secret, totp_algorithm, totp_digits, totp_period,
                                  password_changed_at, created_by, updated_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, CASE WHEN $6 IS NULL THEN NULL ELSE now() END, $12, $12)",
    )
    .bind(id)
    .bind(client)
    .bind(&name)
    .bind(&username)
    .bind(&url)
    .bind(password.as_ref().map(|p| seal(&key, id, "password", p.as_bytes())))
    .bind(notes.as_ref().map(|n| seal(&key, id, "notes", n.as_bytes())))
    .bind(spec.as_ref().map(|s| seal(&key, id, "totp_secret", &s.secret)))
    .bind(spec.as_ref().map_or("SHA1", |s| s.algorithm.as_str()))
    .bind(spec.as_ref().map_or(6, |s| s.digits as i16))
    .bind(spec.as_ref().map_or(30, |s| s.period as i16))
    .bind(u.id)
    .execute(&st.db)
    .await?;
    let fields: Vec<&str> = [("password", password.is_some()), ("notes", notes.is_some()), ("totp", spec.is_some())]
        .into_iter()
        .filter_map(|(f, set)| set.then_some(f))
        .collect();
    auth::audit(&st.db, Some(u.id), "vault.create", Some(("vault_item", id)), json!({ "client_id": client, "name": name, "secrets": fields })).await;
    Ok(Json(detail(&st, id).await?))
}

/// `null` in the body as `Some(None)`, an absent field as `None`.
fn present<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Option<String>>, D::Error> {
    Option::<String>::deserialize(d).map(Some)
}

#[derive(Deserialize)]
pub struct ItemUpdate {
    name: Option<String>,
    username: Option<String>,
    url: Option<String>,
    /// For the three secrets: absent = unchanged, `null` (or "") = cleared, a string = set.
    #[serde(default, deserialize_with = "present")]
    password: Option<Option<String>>,
    #[serde(default, deserialize_with = "present")]
    notes: Option<Option<String>>,
    #[serde(default, deserialize_with = "present")]
    totp: Option<Option<String>>,
}

/// Changing (or clearing) the password keeps the old one in the history.
pub async fn update(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<ItemUpdate>) -> ApiResult<Json<Value>> {
    let (client, master) = item_gate(&st, &u, id, Perm::VaultManage).await?;
    let name = b.name.as_deref().map(clean_name).transpose()?;
    let username = b.username.as_deref().map(clean_username).transpose()?;
    let url = b.url.as_deref().map(clean_url).transpose()?;
    let password = b.password.as_ref().map(|p| secret(p.as_deref(), "password", 1000)).transpose()?;
    let notes = b.notes.as_ref().map(|n| secret(n.as_deref(), "notes", 20_000)).transpose()?;
    let spec = b.totp.as_ref().map(|t| parse_totp(t.as_deref())).transpose()?;
    let key = client_key(&st, master, client).await?;

    let mut tx = st.db.begin().await?;
    type Cur = (String, String, String, Option<Vec<u8>>, bool, bool);
    let (cur_name, cur_user, cur_url, cur_pw, had_notes, had_totp): Cur = sqlx::query_as(
        "SELECT name, username, url, password, notes IS NOT NULL, totp_secret IS NOT NULL FROM vault_items WHERE id = $1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound("credential"))?;
    let old_pw = if password.is_some() { cur_pw.as_deref().map(|c| open(&key, id, "password", c)).transpose()? } else { None };
    // Saving the form with the same password isn't a change.
    let password = password.filter(|p| p.as_deref().map(str::as_bytes) != old_pw.as_deref());
    let mut fields = Vec::new();
    for (f, changed) in [
        ("name", name.as_ref().is_some_and(|n| *n != cur_name)),
        ("username", username.as_ref().is_some_and(|n| *n != cur_user)),
        ("url", url.as_ref().is_some_and(|n| *n != cur_url)),
        ("password", password.is_some()),
        ("notes", notes.as_ref().is_some_and(|n| n.is_some() || had_notes)),
        ("totp", spec.as_ref().is_some_and(|s| s.is_some() || had_totp)),
    ] {
        if changed {
            fields.push(f);
        }
    }
    if password.is_some()
        && let Some(old) = &cur_pw
    {
        // Copied as sealed: still bound to "<item id>:password".
        sqlx::query("INSERT INTO vault_item_history (item_id, password, replaced_by) VALUES ($1, $2, $3)")
            .bind(id)
            .bind(old)
            .bind(u.id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM vault_item_history WHERE item_id = $1 AND id NOT IN (SELECT id FROM vault_item_history WHERE item_id = $1 ORDER BY id DESC LIMIT $2)")
            .bind(id)
            .bind(HISTORY_KEPT)
            .execute(&mut *tx)
            .await?;
    }
    let new_spec = spec.as_ref().and_then(|s| s.as_ref());
    sqlx::query(
        "UPDATE vault_items SET name = coalesce($2, name), username = coalesce($3, username), url = coalesce($4, url),
                password = CASE WHEN $5 THEN $6 ELSE password END,
                password_changed_at = CASE WHEN $5 THEN now() ELSE password_changed_at END,
                notes = CASE WHEN $7 THEN $8 ELSE notes END,
                totp_secret = CASE WHEN $9 THEN $10 ELSE totp_secret END,
                totp_algorithm = CASE WHEN $9 THEN $11 ELSE totp_algorithm END,
                totp_digits = CASE WHEN $9 THEN $12 ELSE totp_digits END,
                totp_period = CASE WHEN $9 THEN $13 ELSE totp_period END,
                updated_by = $14, updated_at = now()
          WHERE id = $1",
    )
    .bind(id)
    .bind(&name)
    .bind(&username)
    .bind(&url)
    .bind(password.is_some())
    .bind(password.as_ref().and_then(|p| p.as_ref()).map(|p| seal(&key, id, "password", p.as_bytes())))
    .bind(notes.is_some())
    .bind(notes.as_ref().and_then(|n| n.as_ref()).map(|n| seal(&key, id, "notes", n.as_bytes())))
    .bind(spec.is_some())
    .bind(new_spec.map(|s| seal(&key, id, "totp_secret", &s.secret)))
    .bind(new_spec.map_or("SHA1", |s| s.algorithm.as_str()))
    .bind(new_spec.map_or(6, |s| s.digits as i16))
    .bind(new_spec.map_or(30, |s| s.period as i16))
    .bind(u.id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    if !fields.is_empty() {
        let shown = name.as_deref().unwrap_or(&cur_name);
        auth::audit(&st.db, Some(u.id), "vault.update", Some(("vault_item", id)), json!({ "client_id": client, "name": shown, "fields": fields })).await;
    }
    Ok(Json(detail(&st, id).await?))
}

/// Pages that reference it show "Credential not found" from then on.
pub async fn remove(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let (client, _) = item_gate(&st, &u, id, Perm::VaultManage).await?;
    let name: Option<String> = sqlx::query_scalar("DELETE FROM vault_items WHERE id = $1 RETURNING name").bind(id).fetch_optional(&st.db).await?;
    auth::audit(&st.db, Some(u.id), "vault.delete", Some(("vault_item", id)), json!({ "client_id": client, "name": name })).await;
    Ok(Json(json!({ "ok": true })))
}

/// Takes one of the user's reveal tokens (reveals and codes share them).
fn throttle(st: &AppState, u: &User) -> ApiResult<()> {
    st.limits.vault_reveal.take(&u.id.to_string()).map_err(ApiError::Throttled)
}

/// A response carrying a secret: never cached.
fn no_store(v: Value) -> Response {
    ([(header::CACHE_CONTROL, "no-store")], Json(v)).into_response()
}

#[derive(Deserialize)]
pub struct RevealIn {
    /// `password` or `notes`.
    field: Option<String>,
    /// Or an entry of the password history.
    history: Option<i64>,
}

pub async fn reveal(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<RevealIn>) -> ApiResult<Response> {
    let (client, master) = item_gate(&st, &u, id, Perm::VaultRead).await?;
    let (field, column, sealed): (&str, &str, Option<Vec<u8>>) = match (b.field.as_deref(), b.history) {
        (None, Some(h)) => {
            let p: Vec<u8> = sqlx::query_scalar("SELECT password FROM vault_item_history WHERE id = $2 AND item_id = $1")
                .bind(id)
                .bind(h)
                .fetch_optional(&st.db)
                .await?
                .ok_or(ApiError::NotFound("password history entry"))?;
            ("history", "password", Some(p))
        }
        (Some(f @ ("password" | "notes")), None) => {
            let sql = if f == "password" { "SELECT password FROM vault_items WHERE id = $1" } else { "SELECT notes FROM vault_items WHERE id = $1" };
            (f, f, sqlx::query_scalar(sql).bind(id).fetch_one(&st.db).await?)
        }
        _ => return Err(ApiError::BadRequest("reveal a field (password or notes) or a history entry".into())),
    };
    let sealed = sealed.ok_or_else(|| ApiError::BadRequest(format!("this credential has no {field}")))?;
    throttle(&st, &u)?;
    let key = client_key(&st, master, client).await?;
    let value = String::from_utf8_lossy(&open(&key, id, column, &sealed)?).into_owned();
    let name: String = sqlx::query_scalar("SELECT name FROM vault_items WHERE id = $1").bind(id).fetch_one(&st.db).await?;
    auth::audit(
        &st.db,
        Some(u.id),
        "vault.reveal",
        Some(("vault_item", id)),
        json!({ "client_id": client, "name": name, "field": field, "history_id": b.history }),
    )
    .await;
    Ok(no_store(json!({ "value": value })))
}

/// The current code, computed here: TOTP secrets never leave the server.
pub async fn totp(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Response> {
    let (client, master) = item_gate(&st, &u, id, Perm::VaultRead).await?;
    let (name, sealed, alg, digits, period): (String, Option<Vec<u8>>, String, i16, i16) =
        sqlx::query_as("SELECT name, totp_secret, totp_algorithm, totp_digits, totp_period FROM vault_items WHERE id = $1")
            .bind(id)
            .fetch_one(&st.db)
            .await?;
    let sealed = sealed.ok_or_else(|| ApiError::BadRequest("this credential has no TOTP secret".into()))?;
    throttle(&st, &u)?;
    let key = client_key(&st, master, client).await?;
    let secret = open(&key, id, "totp_secret", &sealed)?;
    let alg = totp::Algorithm::parse(&alg).unwrap_or(totp::Algorithm::Sha1);
    let (digits, period) = (digits as u32, period.max(1) as u32);
    let now = Utc::now().timestamp();
    let code = totp::code(&secret, alg, digits, period, now);
    let remaining = period as i64 - now.rem_euclid(period as i64);
    auth::audit(&st.db, Some(u.id), "vault.totp", Some(("vault_item", id)), json!({ "client_id": client, "name": name })).await;
    Ok(no_store(json!({ "code": code, "digits": digits, "period": period, "remaining": remaining })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        for ok in ["", "https://fw.acme.local:4443", "10.0.0.1", "rdp://server01", "ssh://root@host"] {
            assert!(clean_url(ok).is_ok(), "{ok}");
        }
        for bad in ["javascript:alert(1)", " JavaScript:alert(1)", "java\tscript:x", "data:text/html,x", "vbscript:x"] {
            assert!(clean_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn update_fields() {
        let b: ItemUpdate = serde_json::from_value(json!({ "password": null, "notes": "n" })).unwrap();
        assert_eq!((b.password, b.notes, b.totp), (Some(None), Some(Some("n".into())), None));
        assert_eq!(secret(Some(""), "password", 10).unwrap(), None, "empty clears");
        let e = secret(Some("hunter2hunter2"), "password", 10).unwrap_err().to_string();
        assert!(!e.contains("hunter2"));
    }
}
