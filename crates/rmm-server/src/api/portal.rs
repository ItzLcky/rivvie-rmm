//! The client portal (`/api/portal/...`): contacts sign in and see their tickets, reply, open
//! new ones, read public KB articles and (when the client allows it) their devices' status.
//!
//! Portal sessions are separate from technician sessions: their own table, and their own
//! cookie scoped to `/api/portal`, so a portal cookie never reaches the technician API and a
//! technician's session never authenticates here. Every query is scoped to the contact's
//! client; anything else is reported as not found.
//!
//! Also here: the public satisfaction-survey endpoints (`/api/feedback/{token}`).

use std::sync::Arc;

use axum::Json;
use axum::extract::{FromRequestParts, Multipart, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, header};
use axum::response::{AppendHeaders, IntoResponse, Response};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth;
use crate::error::{ApiError, ApiResult};
use crate::ratelimit::ClientIp;
use crate::state::AppState;
use crate::tickets::{self, Author, NewTicket};

pub const COOKIE: &str = "rmm_portal";
/// Sign-in links expire after this long.
pub const PORTAL_LINK_MINUTES: i64 = 30;
/// Absolute session lifetime; sessions unused for [`IDLE_DAYS`] end sooner.
const SESSION_DAYS: i64 = 30;
const IDLE_DAYS: i32 = 7;
const MAX_FILES: usize = 10;

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// The signed-in contact.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Contact {
    pub id: Uuid,
    pub client_id: Uuid,
    pub client_name: String,
    pub site_id: Option<Uuid>,
    pub name: String,
    pub email: String,
    pub is_primary: bool,
    pub portal_all_tickets: bool,
    pub is_billing: bool,
    #[serde(skip)]
    pub session_id: Uuid,
}

impl Contact {
    /// Primary contacts (and those allowed to) see every ticket of their client.
    fn sees_all(&self) -> bool {
        self.is_primary || self.portal_all_tickets
    }

    fn author(&self) -> Author {
        Author { contact_id: Some(self.id), name: self.name.clone(), ..Default::default() }
    }
}

fn portal_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|kv| kv.trim().strip_prefix(&format!("{COOKIE}=")).map(str::to_string))
}

impl FromRequestParts<Arc<AppState>> for Contact {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, st: &Arc<AppState>) -> Result<Self, ApiError> {
        let token = portal_token(&parts.headers).ok_or(ApiError::Unauthorized)?;
        // Turning portal access off (or removing the email) ends the contact's sessions at once.
        sqlx::query_as::<_, Contact>(
            "WITH s AS (
                 SELECT co.id, co.client_id, c.name AS client_name, co.site_id, co.name, co.email, co.is_primary,
                        co.portal_all_tickets, co.is_billing, s.id AS session_id
                   FROM contact_sessions s JOIN contacts co ON co.id = s.contact_id JOIN clients c ON c.id = co.client_id
                  WHERE s.token_hash = $1 AND s.expires_at > now() AND s.last_seen_at > now() - make_interval(days => $2)
                    AND co.portal_enabled AND co.email <> ''
             ), touch AS (
                 UPDATE contact_sessions SET last_seen_at = now()
                  WHERE id = (SELECT session_id FROM s) AND last_seen_at < now() - interval '1 minute'
             )
             SELECT * FROM s",
        )
        .bind(auth::token_hash(&token))
        .bind(IDLE_DAYS)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::Unauthorized)
    }
}

fn session_cookie(token: &str, secure: bool) -> String {
    format!(
        "{COOKIE}={token}; Path=/api/portal; HttpOnly; SameSite=Strict; Max-Age={}{}",
        SESSION_DAYS * 86400,
        if secure { "; Secure" } else { "" }
    )
}

fn clear_cookie() -> String {
    format!("{COOKIE}=; Path=/api/portal; HttpOnly; SameSite=Strict; Max-Age=0")
}

async fn start_session(st: &AppState, contact_id: Uuid, headers: &HeaderMap) -> ApiResult<String> {
    let token = auth::random_token();
    let ua = headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).map(|s| s.chars().take(200).collect::<String>());
    sqlx::query("INSERT INTO contact_sessions (token_hash, contact_id, expires_at, user_agent) VALUES ($1, $2, $3, $4)")
        .bind(auth::token_hash(&token))
        .bind(contact_id)
        .bind(Utc::now() + Duration::days(SESSION_DAYS))
        .bind(ua)
        .execute(&st.db)
        .await?;
    sqlx::query("UPDATE contacts SET portal_last_login_at = now() WHERE id = $1").bind(contact_id).execute(&st.db).await?;
    Ok(token)
}

/// Sends a sign-in link (or an invitation) to a contact with portal access.
pub async fn send_link(st: &AppState, contact_id: Uuid, invite: bool) -> ApiResult<()> {
    let (name, email): (String, String) =
        sqlx::query_as("SELECT name, email FROM contacts WHERE id = $1 AND portal_enabled AND email <> ''")
            .bind(contact_id)
            .fetch_optional(&st.db)
            .await?
            .ok_or_else(|| ApiError::BadRequest("turn on portal access (and give the contact an email) first".into()))?;
    let token = auth::random_token();
    sqlx::query("INSERT INTO contact_login_links (token_hash, contact_id, purpose, expires_at) VALUES ($1, $2, $3, $4)")
        .bind(auth::token_hash(&token))
        .bind(contact_id)
        .bind(if invite { "invite" } else { "login" })
        .bind(Utc::now() + Duration::minutes(if invite { 7 * 24 * 60 } else { PORTAL_LINK_MINUTES }))
        .execute(&st.db)
        .await?;
    let url = format!("{}/portal/login?token={token}", st.cfg.public_url);
    crate::email::queue_portal_link(st, &email, &name, &url, invite).await?;
    Ok(())
}

/// Counts every attempt (not just failures) against the IP and the address: sign-in links send
/// email, so they must not be a way to flood someone's inbox.
fn throttle(st: &AppState, ip: &str, account: &str) -> ApiResult<()> {
    let (ip_key, acct_key) = (format!("portal:{ip}"), format!("portal:{account}"));
    st.limits.login_ip.check(&ip_key).map_err(ApiError::TooManyRequests)?;
    st.limits.login_account.check(&acct_key).map_err(ApiError::TooManyRequests)?;
    Ok(())
}

fn count_attempt(st: &AppState, ip: &str, account: &str) {
    st.limits.login_ip.fail(&format!("portal:{ip}"));
    st.limits.login_account.fail(&format!("portal:{account}"));
}

#[derive(Deserialize)]
pub struct LinkIn {
    email: String,
}

/// `POST /portal/auth/link`: emails a sign-in link to every portal contact with the address.
/// Always answers the same, so it can't tell anyone which addresses have access.
pub async fn request_link(State(st): State<Arc<AppState>>, ClientIp(ip): ClientIp, Json(b): Json<LinkIn>) -> ApiResult<Json<Value>> {
    let email = b.email.trim().to_ascii_lowercase();
    let ip = ip.to_string();
    throttle(&st, &ip, &email)?;
    count_attempt(&st, &ip, &email);
    if email.parse::<lettre::Address>().is_err() {
        return Err(ApiError::BadRequest("enter your email address".into()));
    }
    let contacts: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM contacts WHERE lower(email) = $1 AND portal_enabled LIMIT 5")
        .bind(&email)
        .fetch_all(&st.db)
        .await?;
    for c in contacts {
        send_link(&st, c, false).await?;
    }
    Ok(Json(json!({ "ok": true })))
}

#[derive(sqlx::FromRow)]
struct Factor {
    totp_secret: Option<Vec<u8>>,
    totp_sealed: bool,
}

/// Checks a contact's TOTP code (each time step is accepted once). Passes when no TOTP is set up.
async fn check_totp(st: &AppState, contact_id: Uuid, f: &Factor, code: Option<&str>) -> ApiResult<()> {
    let Some(stored) = &f.totp_secret else { return Ok(()) };
    let secret = super::totp::open(st, stored, f.totp_sealed)?;
    let Some(code) = code.map(str::trim).filter(|c| !c.is_empty()) else {
        return Err(ApiError::MfaRequired("two-factor code required"));
    };
    let Some(step) = crate::totp::verify(&secret, code, Utc::now().timestamp()) else {
        return Err(ApiError::MfaRequired("invalid two-factor code"));
    };
    let n = sqlx::query(
        "UPDATE contact_credentials SET totp_last_step = $2 WHERE contact_id = $1 AND (totp_last_step IS NULL OR totp_last_step < $2)",
    )
    .bind(contact_id)
    .bind(step)
    .execute(&st.db)
    .await?
    .rows_affected();
    if n == 1 { Ok(()) } else { Err(ApiError::MfaRequired("invalid two-factor code")) }
}

#[derive(Deserialize)]
pub struct VerifyIn {
    token: String,
    code: Option<String>,
}

/// `POST /portal/auth/verify`: signs in with a link's token (plus a TOTP code if the contact
/// set one up). The link is used up only when the sign-in succeeds.
pub async fn verify(
    State(st): State<Arc<AppState>>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Json(b): Json<VerifyIn>,
) -> ApiResult<impl IntoResponse> {
    let ip = ip.to_string();
    throttle(&st, &ip, "links")?;
    let hash = auth::token_hash(b.token.trim());
    let row: Option<(Uuid, Option<Vec<u8>>, Option<bool>)> = sqlx::query_as(
        "SELECT l.contact_id, cc.totp_secret, cc.totp_sealed FROM contact_login_links l JOIN contacts co ON co.id = l.contact_id
           LEFT JOIN contact_credentials cc ON cc.contact_id = co.id
          WHERE l.token_hash = $1 AND l.used_at IS NULL AND l.expires_at > now() AND co.portal_enabled AND co.email <> ''",
    )
    .bind(&hash)
    .fetch_optional(&st.db)
    .await?;
    let Some((contact_id, totp_secret, sealed)) = row else {
        st.limits.login_ip.fail(&format!("portal:{ip}"));
        return Err(ApiError::BadRequest("this sign-in link has expired or was already used: ask for a new one".into()));
    };
    if let Err(e) = check_totp(&st, contact_id, &Factor { totp_secret, totp_sealed: sealed.unwrap_or(false) }, b.code.as_deref()).await {
        if matches!(e, ApiError::MfaRequired("invalid two-factor code")) {
            count_attempt(&st, &ip, &contact_id.to_string());
        }
        return Err(e);
    }
    let used = sqlx::query("UPDATE contact_login_links SET used_at = now() WHERE token_hash = $1 AND used_at IS NULL")
        .bind(&hash)
        .execute(&st.db)
        .await?
        .rows_affected();
    if used == 0 {
        return Err(ApiError::BadRequest("this sign-in link was already used".into()));
    }
    let token = start_session(&st, contact_id, &headers).await?;
    auth::audit(&st.db, None, "portal.login", Some(("contact", contact_id)), json!({ "ip": ip, "via": "link" })).await;
    Ok((AppendHeaders([(header::SET_COOKIE, session_cookie(&token, st.cfg.secure_cookies()))]), Json(json!({ "ok": true }))))
}

#[derive(Deserialize)]
pub struct LoginIn {
    email: String,
    password: String,
    code: Option<String>,
}

/// `POST /portal/auth/login`: email and the password the contact set (plus TOTP if set up).
pub async fn login(
    State(st): State<Arc<AppState>>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Json(b): Json<LoginIn>,
) -> ApiResult<impl IntoResponse> {
    let email = b.email.trim().to_ascii_lowercase();
    let ip = ip.to_string();
    throttle(&st, &ip, &email)?;
    let rows: Vec<(Uuid, String, Option<Vec<u8>>, bool)> = sqlx::query_as(
        "SELECT co.id, cc.password_hash, cc.totp_secret, cc.totp_sealed FROM contacts co JOIN contact_credentials cc ON cc.contact_id = co.id
          WHERE lower(co.email) = $1 AND co.portal_enabled AND cc.password_hash IS NOT NULL LIMIT 5",
    )
    .bind(&email)
    .fetch_all(&st.db)
    .await?;
    let mut found = None;
    for (id, hash, secret, sealed) in rows {
        if auth::verify_password_async(&b.password, hash).await {
            found = Some((id, Factor { totp_secret: secret, totp_sealed: sealed }));
            break;
        }
    }
    let Some((contact_id, factor)) = found else {
        // Same work either way, so timing doesn't reveal the address.
        let _ = auth::verify_password_async(&b.password, auth::hash_password("not-a-real-password").unwrap_or_default()).await;
        count_attempt(&st, &ip, &email);
        return Err(ApiError::Unauthorized);
    };
    if let Err(e) = check_totp(&st, contact_id, &factor, b.code.as_deref()).await {
        if matches!(e, ApiError::MfaRequired("invalid two-factor code")) {
            count_attempt(&st, &ip, &email);
        }
        return Err(e);
    }
    let token = start_session(&st, contact_id, &headers).await?;
    auth::audit(&st.db, None, "portal.login", Some(("contact", contact_id)), json!({ "ip": ip, "via": "password" })).await;
    Ok((AppendHeaders([(header::SET_COOKIE, session_cookie(&token, st.cfg.secure_cookies()))]), Json(json!({ "ok": true }))))
}

pub async fn logout(State(st): State<Arc<AppState>>, headers: HeaderMap) -> ApiResult<impl IntoResponse> {
    if let Some(t) = portal_token(&headers) {
        sqlx::query("DELETE FROM contact_sessions WHERE token_hash = $1").bind(auth::token_hash(&t)).execute(&st.db).await?;
    }
    Ok((AppendHeaders([(header::SET_COOKIE, clear_cookie())]), Json(json!({ "ok": true }))))
}

/// Company name and the portal's welcome text, for the sign-in page.
pub async fn public_info(State(st): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let welcome: String = sqlx::query_scalar("SELECT portal_welcome FROM company_settings").fetch_one(&st.db).await?;
    Ok(Json(json!({ "company_name": st.company().company_name, "welcome": welcome })))
}

pub async fn me(State(st): State<Arc<AppState>>, c: Contact) -> ApiResult<Json<Value>> {
    let (devices, has_password, totp): (bool, bool, bool) = sqlx::query_as(
        "SELECT cl.portal_devices, coalesce(cc.password_hash IS NOT NULL, false), coalesce(cc.totp_secret IS NOT NULL, false)
           FROM contacts co JOIN clients cl ON cl.id = co.client_id LEFT JOIN contact_credentials cc ON cc.contact_id = co.id
          WHERE co.id = $1",
    )
    .bind(c.id)
    .fetch_one(&st.db)
    .await?;
    let welcome: String = sqlx::query_scalar("SELECT portal_welcome FROM company_settings").fetch_one(&st.db).await?;
    Ok(Json(json!({
        "contact": c,
        "company_name": st.company().company_name,
        "welcome": welcome,
        "devices": devices,
        "sees_all_tickets": c.sees_all(),
        "invoices": c.is_billing,
        "has_password": has_password,
        "totp_enabled": totp,
    })))
}

// ---------------------------------------------------------------------------
// Account: password and TOTP
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct PasswordIn {
    current_password: Option<String>,
    password: String,
}

pub async fn set_password(State(st): State<Arc<AppState>>, c: Contact, Json(b): Json<PasswordIn>) -> ApiResult<Json<Value>> {
    let old: Option<Option<String>> =
        sqlx::query_scalar("SELECT password_hash FROM contact_credentials WHERE contact_id = $1").bind(c.id).fetch_optional(&st.db).await?;
    if let Some(Some(hash)) = old {
        let cur = b.current_password.unwrap_or_default();
        if !auth::verify_password_async(&cur, hash).await {
            return Err(ApiError::BadRequest("current password is incorrect".into()));
        }
    }
    let hash = auth::hash_password_async(&b.password).await?;
    sqlx::query(
        "INSERT INTO contact_credentials (contact_id, password_hash) VALUES ($1, $2)
         ON CONFLICT (contact_id) DO UPDATE SET password_hash = $2, updated_at = now()",
    )
    .bind(c.id)
    .bind(hash)
    .execute(&st.db)
    .await?;
    // Other sessions end: someone who knew the old password shouldn't stay signed in.
    sqlx::query("DELETE FROM contact_sessions WHERE contact_id = $1 AND id <> $2").bind(c.id).bind(c.session_id).execute(&st.db).await?;
    auth::audit(&st.db, None, "portal.password_set", Some(("contact", c.id)), json!({})).await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn totp_setup(State(st): State<Arc<AppState>>, c: Contact) -> ApiResult<Json<Value>> {
    let secret = crate::totp::new_secret();
    sqlx::query(
        "INSERT INTO contact_credentials (contact_id, totp_pending) VALUES ($1, $2)
         ON CONFLICT (contact_id) DO UPDATE SET totp_pending = $2, updated_at = now()",
    )
    .bind(c.id)
    .bind(&secret)
    .execute(&st.db)
    .await?;
    let brand = st.company().company_name;
    let issuer = if brand.trim().is_empty() { "Support portal".to_string() } else { format!("{brand} support") };
    let uri = crate::totp::otpauth_uri(&secret, &issuer, &c.email);
    Ok(Json(json!({ "secret": crate::totp::encode_secret(&secret), "otpauth_uri": uri, "qr_svg": crate::totp::qr_svg(&uri)? })))
}

#[derive(Deserialize)]
pub struct CodeIn {
    code: String,
}

pub async fn totp_enable(State(st): State<Arc<AppState>>, c: Contact, Json(b): Json<CodeIn>) -> ApiResult<Json<Value>> {
    let pending: Option<Option<Vec<u8>>> =
        sqlx::query_scalar("SELECT totp_pending FROM contact_credentials WHERE contact_id = $1").bind(c.id).fetch_optional(&st.db).await?;
    let secret = pending.flatten().ok_or_else(|| ApiError::BadRequest("start the setup first".into()))?;
    let step = crate::totp::verify(&secret, b.code.trim(), Utc::now().timestamp())
        .ok_or_else(|| ApiError::BadRequest("that code doesn't match: check the time on your phone and try again".into()))?;
    let (stored, sealed) = crate::crypto::store(st.cfg.data_key.as_ref(), &secret);
    sqlx::query(
        "UPDATE contact_credentials SET totp_secret = $2, totp_sealed = $3, totp_pending = NULL, totp_last_step = $4, updated_at = now()
          WHERE contact_id = $1",
    )
    .bind(c.id)
    .bind(stored)
    .bind(sealed)
    .bind(step)
    .execute(&st.db)
    .await?;
    auth::audit(&st.db, None, "portal.totp_enabled", Some(("contact", c.id)), json!({})).await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn totp_disable(State(st): State<Arc<AppState>>, c: Contact, Json(b): Json<CodeIn>) -> ApiResult<Json<Value>> {
    let f: Option<Factor> = sqlx::query_as("SELECT totp_secret, totp_sealed FROM contact_credentials WHERE contact_id = $1")
        .bind(c.id)
        .fetch_optional(&st.db)
        .await?;
    let f = f.filter(|f| f.totp_secret.is_some()).ok_or_else(|| ApiError::BadRequest("two-factor authentication is off".into()))?;
    check_totp(&st, c.id, &f, Some(&b.code)).await.map_err(|_| ApiError::BadRequest("invalid two-factor code".into()))?;
    sqlx::query("UPDATE contact_credentials SET totp_secret = NULL, totp_sealed = false, totp_last_step = NULL WHERE contact_id = $1")
        .bind(c.id)
        .execute(&st.db)
        .await?;
    auth::audit(&st.db, None, "portal.totp_disabled", Some(("contact", c.id)), json!({})).await;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Tickets
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct PortalTicket {
    id: Uuid,
    number: i64,
    subject: String,
    status_name: String,
    status_category: String,
    priority: i16,
    contact_name: Option<String>,
    created_at: DateTime<Utc>,
    /// The last public activity (internal work doesn't show here).
    last_activity_at: DateTime<Utc>,
    merged_into: Option<Uuid>,
}

const TICKET_COLS: &str = "t.id, t.number, t.subject, s.name AS status_name, s.category AS status_category, t.priority,
     co.name AS contact_name, t.created_at,
     coalesce((SELECT max(e.created_at) FROM ticket_events e WHERE e.ticket_id = t.id AND e.public), t.created_at) AS last_activity_at,
     t.merged_into
  FROM tickets t JOIN board_statuses s ON s.id = t.status_id LEFT JOIN contacts co ON co.id = t.contact_id";

#[derive(Deserialize)]
pub struct TicketQuery {
    /// open (default), closed, all
    state: Option<String>,
    q: Option<String>,
}

pub async fn tickets(State(st): State<Arc<AppState>>, c: Contact, Query(q): Query<TicketQuery>) -> ApiResult<Json<Vec<PortalTicket>>> {
    let state = match q.state.as_deref().unwrap_or("open") {
        "open" => "s.category NOT IN ('resolved', 'closed')",
        "closed" => "s.category IN ('resolved', 'closed')",
        "all" => "true",
        _ => return Err(ApiError::BadRequest("state must be open, closed or all".into())),
    };
    let search = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(|s| s.chars().take(200).collect::<String>());
    let number: Option<i64> = search.as_deref().and_then(|s| s.trim_start_matches(['T', 't']).trim_start_matches('-').parse().ok());
    let rows = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {TICKET_COLS}
          WHERE t.client_id = $1 AND t.merged_into IS NULL AND ($2 OR t.contact_id = $3) AND {state}
            AND ($4::text IS NULL OR t.number = $5 OR t.subject ILIKE '%' || $4 || '%')
          ORDER BY last_activity_at DESC LIMIT 200"
    )))
    .bind(c.client_id)
    .bind(c.sees_all())
    .bind(c.id)
    .bind(&search)
    .bind(number)
    .fetch_all(&st.db)
    .await?;
    Ok(Json(rows))
}

/// The ticket, if the contact may see it.
async fn visible(st: &AppState, c: &Contact, id: Uuid) -> ApiResult<PortalTicket> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT {TICKET_COLS} WHERE t.id = $1 AND t.client_id = $2 AND ($3 OR t.contact_id = $4)")))
        .bind(id)
        .bind(c.client_id)
        .bind(c.sees_all())
        .bind(c.id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("ticket"))
}

#[derive(Serialize, sqlx::FromRow)]
pub struct PortalEvent {
    id: i64,
    kind: String,
    /// staff / contact
    author_kind: String,
    author_name: String,
    body: String,
    created_at: DateTime<Utc>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct PortalAttachment {
    id: Uuid,
    event_id: Option<i64>,
    name: String,
    content_type: String,
    size: i64,
    created_at: DateTime<Utc>,
}

/// Attachments a contact can see: on public entries, or ones they uploaded.
const VISIBLE_ATTACHMENT: &str = "(a.event_id IN (SELECT id FROM ticket_events WHERE ticket_id = a.ticket_id AND public)
                                  OR a.uploaded_by_contact = $2)";

pub async fn ticket(State(st): State<Arc<AppState>>, c: Contact, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let t = visible(&st, &c, id).await?;
    let events: Vec<PortalEvent> = sqlx::query_as(
        "SELECT e.id, e.kind, CASE WHEN e.author_id IS NOT NULL OR (e.author_contact_id IS NULL AND e.kind = 'reply') THEN 'staff' ELSE 'contact' END AS author_kind,
                coalesce(u.name, co.name, nullif(e.author_name, ''), 'Support') AS author_name, e.body, e.created_at
           FROM ticket_events e LEFT JOIN users u ON u.id = e.author_id LEFT JOIN contacts co ON co.id = e.author_contact_id
          WHERE e.ticket_id = $1 AND e.public AND e.kind IN ('created', 'reply', 'message') ORDER BY e.id",
    )
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    let attachments: Vec<PortalAttachment> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT a.id, a.event_id, a.name, a.content_type, a.size, a.created_at FROM ticket_attachments a
          WHERE a.ticket_id = $1 AND {VISIBLE_ATTACHMENT} ORDER BY a.created_at, a.name"
    )))
    .bind(id)
    .bind(c.id)
    .fetch_all(&st.db)
    .await?;
    let merged_into_number: Option<i64> = match t.merged_into {
        Some(m) => sqlx::query_scalar("SELECT number FROM tickets WHERE id = $1").bind(m).fetch_optional(&st.db).await?,
        None => None,
    };
    let mut v = serde_json::to_value(&t).map_err(anyhow::Error::from)?;
    v["events"] = json!(events);
    v["attachments"] = json!(attachments);
    v["merged_into_number"] = json!(merged_into_number);
    Ok(Json(v))
}

struct Upload {
    name: String,
    content_type: String,
    bytes: Vec<u8>,
}

/// Text fields and files from a portal form.
async fn read_form(mut form: Multipart) -> ApiResult<(std::collections::HashMap<String, String>, Vec<Upload>)> {
    let bad = |e: axum::extract::multipart::MultipartError| ApiError::BadRequest(format!("upload: {e}"));
    let mut fields = std::collections::HashMap::new();
    let mut files = vec![];
    while let Some(f) = form.next_field().await.map_err(bad)? {
        let name = f.name().unwrap_or_default().to_string();
        if name == "file" {
            if files.len() >= MAX_FILES {
                return Err(ApiError::BadRequest(format!("at most {MAX_FILES} files")));
            }
            let fname = super::tickets::clean_filename(f.file_name().unwrap_or("attachment"));
            let ct = f
                .content_type()
                .filter(|c| c.len() < 100 && c.contains('/') && c.bytes().all(|b| b.is_ascii_graphic()))
                .unwrap_or("application/octet-stream")
                .to_ascii_lowercase();
            let bytes = f.bytes().await.map_err(bad)?.to_vec();
            if !bytes.is_empty() {
                files.push(Upload { name: fname, content_type: ct, bytes });
            }
        } else {
            let text = f.text().await.map_err(bad)?;
            fields.insert(name, text);
        }
    }
    Ok((fields, files))
}

async fn store_files(st: &AppState, ticket: Uuid, event: i64, contact: Uuid, files: Vec<Upload>) -> ApiResult<()> {
    for f in files {
        let aid = Uuid::new_v4();
        let key = format!("attachments/{aid}");
        let sha = Sha256::digest(&f.bytes).to_vec();
        let size = f.bytes.len() as i64;
        st.storage.put(&key, f.bytes, &f.content_type).await?;
        sqlx::query(
            "INSERT INTO ticket_attachments (id, ticket_id, event_id, name, content_type, size, sha256, storage_key, uploaded_by_contact)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(aid)
        .bind(ticket)
        .bind(event)
        .bind(&f.name)
        .bind(&f.content_type)
        .bind(size)
        .bind(sha)
        .bind(&key)
        .bind(contact)
        .execute(&st.db)
        .await?;
    }
    Ok(())
}

/// `POST /portal/tickets` (multipart: `subject`, `description`, `urgency` = low / normal / high,
/// and any number of `file`s up to the request limit).
pub async fn create_ticket(State(st): State<Arc<AppState>>, c: Contact, form: Multipart) -> ApiResult<Json<Value>> {
    let (fields, files) = read_form(form).await?;
    let subject = fields.get("subject").map(|s| s.split_whitespace().collect::<Vec<_>>().join(" ")).unwrap_or_default();
    if subject.is_empty() || subject.chars().count() > 300 {
        return Err(ApiError::BadRequest("give the request a subject (up to 300 characters)".into()));
    }
    let body = fields.get("description").map(|s| s.trim().to_string()).unwrap_or_default();
    if body.chars().count() > 100_000 {
        return Err(ApiError::BadRequest("the description is limited to 100,000 characters".into()));
    }
    // The client says how urgent it is; P1 is for the service desk to decide.
    let priority = match fields.get("urgency").map(String::as_str).unwrap_or("normal") {
        "high" => 2,
        "normal" => 3,
        "low" => 4,
        _ => return Err(ApiError::BadRequest("urgency must be low, normal or high".into())),
    };
    let mut tx = st.db.begin().await?;
    let board: Uuid = sqlx::query_scalar(
        "SELECT coalesce((SELECT portal_board_id FROM company_settings), (SELECT id FROM boards ORDER BY position, name LIMIT 1))",
    )
    .fetch_optional(&mut *tx)
    .await?
    .flatten()
    .ok_or_else(|| ApiError::Conflict("the service desk isn't set up yet".into()))?;
    let created = tickets::create(
        &mut tx,
        NewTicket {
            client_id: Some(c.client_id),
            site_id: c.site_id,
            contact_id: Some(c.id),
            board_id: board,
            priority,
            subject,
            body,
            body_public: true,
            source: "portal",
            author: c.author(),
            ..Default::default()
        },
    )
    .await?;
    tx.commit().await?;
    store_files(&st, created.id, created.event_id, c.id, files).await?;
    tickets::notify_created(&st, created.id).await;
    tickets::announce(&st, created.id).await;
    Ok(Json(json!({ "id": created.id, "number": created.number })))
}

/// `POST /portal/tickets/{id}/messages` (multipart: `body` and `file`s). Reopens a resolved
/// ticket, or one waiting on the client.
pub async fn add_message(State(st): State<Arc<AppState>>, c: Contact, Path(id): Path<Uuid>, form: Multipart) -> ApiResult<Json<Value>> {
    let t = visible(&st, &c, id).await?;
    if t.merged_into.is_some() || t.status_category == "closed" {
        return Err(ApiError::Conflict("this ticket is closed: open a new request instead".into()));
    }
    let (fields, files) = read_form(form).await?;
    let body = fields.get("body").map(|s| s.trim().to_string()).unwrap_or_default();
    if body.is_empty() && files.is_empty() {
        return Err(ApiError::BadRequest("write something first".into()));
    }
    if body.chars().count() > 100_000 {
        return Err(ApiError::BadRequest("messages are limited to 100,000 characters".into()));
    }
    let mut tx = st.db.begin().await?;
    sqlx::query("SELECT 1 FROM tickets WHERE id = $1 FOR UPDATE").bind(id).execute(&mut *tx).await?;
    let event = tickets::add_event(&mut tx, id, "message", true, &c.author(), &body, json!({ "via": "portal" })).await?;
    if matches!(t.status_category.as_str(), "resolved" | "waiting_client") {
        let board: Uuid = sqlx::query_scalar("SELECT board_id FROM tickets WHERE id = $1").bind(id).fetch_one(&mut *tx).await?;
        if let Some(s) = tickets::status_of(&mut tx, board, "open").await? {
            tickets::set_status(&mut tx, id, s, &Author::system("Portal")).await?;
        }
    }
    tx.commit().await?;
    store_files(&st, id, event, c.id, files).await?;
    if let Err(e) = crate::email::queue_client_message(&st, id, &c.name).await {
        tracing::warn!(ticket = %id, "telling the assignee about a portal reply: {e:#}");
    }
    tickets::announce(&st, id).await;
    Ok(Json(json!({ "id": event })))
}

/// The contact says it's sorted: resolve the ticket (a later message reopens it).
pub async fn resolve(State(st): State<Arc<AppState>>, c: Contact, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let t = visible(&st, &c, id).await?;
    if tickets::DONE.contains(&t.status_category.as_str()) {
        return Ok(Json(json!({ "ok": true })));
    }
    let mut tx = st.db.begin().await?;
    let board: Uuid = sqlx::query_scalar("SELECT board_id FROM tickets WHERE id = $1").bind(id).fetch_one(&mut *tx).await?;
    if let Some(s) = tickets::status_of(&mut tx, board, "resolved").await? {
        tickets::set_status(&mut tx, id, s, &c.author()).await?;
    }
    tickets::add_event(&mut tx, id, "message", true, &c.author(), "Marked as resolved in the portal.", json!({ "via": "portal" })).await?;
    tx.commit().await?;
    tickets::announce(&st, id).await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn download(State(st): State<Arc<AppState>>, c: Contact, Path((id, aid)): Path<(Uuid, Uuid)>) -> ApiResult<Response> {
    visible(&st, &c, id).await?;
    let (name, ct, key): (String, String, String) = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT a.name, a.content_type, a.storage_key FROM ticket_attachments a WHERE a.id = $3 AND a.ticket_id = $1 AND {VISIBLE_ATTACHMENT}"
    )))
    .bind(id)
    .bind(c.id)
    .bind(aid)
    .fetch_optional(&st.db)
    .await?
    .ok_or(ApiError::NotFound("attachment"))?;
    let bytes = st.storage.get(&key).await?;
    super::tickets::file_response(bytes, &name, &ct, false)
}

// ---------------------------------------------------------------------------
// Knowledge base and devices
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct KbQuery {
    q: Option<String>,
}

pub async fn kb(State(st): State<Arc<AppState>>, c: Contact, Query(q): Query<KbQuery>) -> ApiResult<Json<Value>> {
    let search = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(|s| s.chars().take(200).collect::<String>());
    let rows: Vec<(Uuid, String, String, String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, title, category, left(body, 240), updated_at FROM kb_articles
          WHERE public AND (client_id IS NULL OR client_id = $1)
            AND ($2::text IS NULL OR search @@ websearch_to_tsquery('simple', $2) OR title ILIKE '%' || $2 || '%')
          ORDER BY lower(category), lower(title) LIMIT 500",
    )
    .bind(c.client_id)
    .bind(&search)
    .fetch_all(&st.db)
    .await?;
    Ok(Json(json!(rows
        .into_iter()
        .map(|(id, title, category, excerpt, updated_at)| json!({ "id": id, "title": title, "category": category, "excerpt": excerpt, "updated_at": updated_at }))
        .collect::<Vec<_>>())))
}

pub async fn kb_article(State(st): State<Arc<AppState>>, c: Contact, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let (title, category, body, updated_at): (String, String, String, DateTime<Utc>) = sqlx::query_as(
        "SELECT title, category, body, updated_at FROM kb_articles WHERE id = $1 AND public AND (client_id IS NULL OR client_id = $2)",
    )
    .bind(id)
    .bind(c.client_id)
    .fetch_optional(&st.db)
    .await?
    .ok_or(ApiError::NotFound("article"))?;
    Ok(Json(json!({ "id": id, "title": title, "category": category, "body": body, "updated_at": updated_at })))
}

#[derive(Serialize, sqlx::FromRow)]
pub struct PortalDevice {
    id: Uuid,
    hostname: String,
    site_name: String,
    os_name: String,
    os_version: String,
    online: bool,
    last_seen_at: Option<DateTime<Utc>>,
    missing_patches: i64,
    reboot_pending: bool,
}

/// The client's devices, read-only: online, last seen, missing updates. Off unless the client
/// has it switched on.
pub async fn devices(State(st): State<Arc<AppState>>, c: Contact) -> ApiResult<Json<Vec<PortalDevice>>> {
    let allowed: bool = sqlx::query_scalar("SELECT portal_devices FROM clients WHERE id = $1").bind(c.client_id).fetch_one(&st.db).await?;
    if !allowed {
        return Err(ApiError::NotFound("devices"));
    }
    Ok(Json(
        sqlx::query_as(
            "SELECT a.id, a.hostname, s.name AS site_name, a.os_name, a.os_version, a.online, a.last_seen_at,
                    (SELECT count(*) FROM patches p WHERE p.agent_id = a.id AND p.state IN ('missing', 'failed') AND p.approval <> 'declined') AS missing_patches,
                    a.reboot_pending
               FROM agents a JOIN sites s ON s.id = a.site_id WHERE s.client_id = $1 ORDER BY lower(a.hostname) LIMIT 2000",
        )
        .bind(c.client_id)
        .fetch_all(&st.db)
        .await?,
    ))
}

// ---------------------------------------------------------------------------
// Invoices (billing contacts)
// ---------------------------------------------------------------------------

/// The client's finalised invoices and credit notes, for billing contacts.
pub async fn invoices(State(st): State<Arc<AppState>>, c: Contact) -> ApiResult<Json<Value>> {
    if !c.is_billing {
        return Err(ApiError::NotFound("invoices"));
    }
    #[allow(clippy::type_complexity)]
    let rows: Vec<(Uuid, Option<String>, String, String, String, chrono::NaiveDate, chrono::NaiveDate, i64)> = sqlx::query_as(
        "SELECT id, number, kind, status, currency, issue_date, due_date, total FROM invoices
          WHERE client_id = $1 AND status IN ('finalised', 'sent', 'paid', 'void') ORDER BY issue_date DESC, number DESC LIMIT 500",
    )
    .bind(c.client_id)
    .fetch_all(&st.db)
    .await?;
    Ok(Json(json!(rows
        .into_iter()
        .map(|(id, number, kind, status, currency, issue, due, total)| json!({
            "id": id, "number": number, "kind": kind, "status": status, "currency": currency, "issue_date": issue, "due_date": due,
            "total": total, "total_text": crate::billing::money(total, &currency),
            "overdue": kind == "invoice" && matches!(status.as_str(), "finalised" | "sent") && due < Utc::now().date_naive(),
        }))
        .collect::<Vec<_>>())))
}

pub async fn invoice_pdf(State(st): State<Arc<AppState>>, c: Contact, Path(id): Path<Uuid>) -> ApiResult<Response> {
    if !c.is_billing {
        return Err(ApiError::NotFound("invoice"));
    }
    let ok: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM invoices WHERE id = $1 AND client_id = $2 AND status IN ('finalised', 'sent', 'paid', 'void'))")
        .bind(id)
        .bind(c.client_id)
        .fetch_one(&st.db)
        .await?;
    if !ok {
        return Err(ApiError::NotFound("invoice"));
    }
    super::billing::stored_pdf(&st, id).await
}

// ---------------------------------------------------------------------------
// Satisfaction surveys (no session: the token is the key)
// ---------------------------------------------------------------------------

pub async fn feedback(State(st): State<Arc<AppState>>, Path(token): Path<String>) -> ApiResult<Json<Value>> {
    let (number, subject, rating, comment): (i64, String, Option<String>, String) = sqlx::query_as(
        "SELECT t.number, t.subject, c.rating, c.comment FROM csat_surveys c JOIN tickets t ON t.id = c.ticket_id WHERE c.token_hash = $1",
    )
    .bind(auth::token_hash(token.trim()))
    .fetch_optional(&st.db)
    .await?
    .ok_or(ApiError::NotFound("survey"))?;
    Ok(Json(json!({ "number": number, "subject": subject, "rating": rating, "comment": comment, "company_name": st.company().company_name })))
}

#[derive(Deserialize)]
pub struct FeedbackIn {
    rating: String,
    #[serde(default)]
    comment: String,
}

pub async fn answer_feedback(
    State(st): State<Arc<AppState>>,
    ClientIp(ip): ClientIp,
    Path(token): Path<String>,
    Json(b): Json<FeedbackIn>,
) -> ApiResult<Json<Value>> {
    if !matches!(b.rating.as_str(), "good" | "bad") {
        return Err(ApiError::BadRequest("rating must be good or bad".into()));
    }
    let comment: String = b.comment.trim().chars().take(5000).collect();
    let key = format!("feedback:{ip}");
    st.limits.login_ip.check(&key).map_err(ApiError::TooManyRequests)?;
    match crate::csat::answer(&st, token.trim(), &b.rating, &comment).await? {
        Some(_) => Ok(Json(json!({ "ok": true }))),
        None => {
            st.limits.login_ip.fail(&key);
            Err(ApiError::NotFound("survey"))
        }
    }
}

// ---------------------------------------------------------------------------
// Technician side: invitations and resets
// ---------------------------------------------------------------------------

/// `POST /contacts/{id}/portal-invite`: emails the contact an invitation link (valid a week).
pub async fn invite(State(st): State<Arc<AppState>>, u: auth::User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(auth::Role::Technician)?;
    let client: Uuid = sqlx::query_scalar("SELECT client_id FROM contacts WHERE id = $1")
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("contact"))?;
    super::access::client(&u, client).map_err(|_| ApiError::NotFound("contact"))?;
    send_link(&st, id, true).await?;
    auth::audit(&st.db, Some(u.id), "contact.portal_invite", Some(("contact", id)), json!({})).await;
    Ok(Json(json!({ "ok": true })))
}

/// `DELETE /contacts/{id}/portal-credentials`: removes the contact's portal password and 2FA and
/// signs them out everywhere (they can still sign in with an emailed link).
pub async fn reset_credentials(State(st): State<Arc<AppState>>, u: auth::User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(auth::Role::Technician)?;
    let client: Uuid = sqlx::query_scalar("SELECT client_id FROM contacts WHERE id = $1")
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("contact"))?;
    super::access::client(&u, client).map_err(|_| ApiError::NotFound("contact"))?;
    let mut tx = st.db.begin().await?;
    sqlx::query("DELETE FROM contact_credentials WHERE contact_id = $1").bind(id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM contact_sessions WHERE contact_id = $1").bind(id).execute(&mut *tx).await?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "contact.portal_reset", Some(("contact", id)), json!({})).await;
    Ok(Json(json!({ "ok": true })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portal_cookie_is_scoped() {
        let c = session_cookie("abc", true);
        assert!(c.contains("Path=/api/portal;") && c.contains("HttpOnly") && c.contains("SameSite=Strict") && c.ends_with("; Secure"));
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, "rmm_session=tech; rmm_portal=xyz".parse().unwrap());
        assert_eq!(portal_token(&h).as_deref(), Some("xyz"));
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, "rmm_session=tech".parse().unwrap());
        assert_eq!(portal_token(&h), None, "a technician cookie is not a portal session");
    }
}
