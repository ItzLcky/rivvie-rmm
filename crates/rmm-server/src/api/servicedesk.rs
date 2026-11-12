//! Service desk configuration and records around tickets: contacts, client email domains,
//! boards and their statuses, ticket types, support mailboxes, and the inbound email webhook.

use std::collections::HashMap;
use std::sync::Arc;

use axum::Json;
use axum::body::Bytes;
use axum::extract::{FromRequest, Multipart, Path, Query, Request, State};
use axum::http::header;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::AssertSqlSafe;
use uuid::Uuid;

use crate::auth::{self, Role, User};
use crate::email::{MAILBOX_COLS, Mailbox};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use crate::tickets::CATEGORIES;

// ---------------------------------------------------------------------------
// Contacts
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct ContactRow {
    id: Uuid,
    client_id: Uuid,
    client_name: String,
    site_id: Option<Uuid>,
    site_name: Option<String>,
    name: String,
    email: String,
    phone: String,
    job_title: String,
    notes: String,
    is_primary: bool,
    portal_enabled: bool,
    portal_all_tickets: bool,
    portal_last_login_at: Option<DateTime<Utc>>,
    is_billing: bool,
    open_tickets: i64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

const CONTACT_SELECT: &str = "SELECT co.id, co.client_id, c.name AS client_name, co.site_id, si.name AS site_name, co.name, co.email,
       co.phone, co.job_title, co.notes, co.is_primary, co.portal_enabled, co.portal_all_tickets, co.portal_last_login_at, co.is_billing,
       (SELECT count(*) FROM tickets t JOIN board_statuses bs ON bs.id = t.status_id
         WHERE t.contact_id = co.id AND bs.category NOT IN ('resolved', 'closed') AND t.merged_into IS NULL) AS open_tickets,
       co.created_at, co.updated_at
  FROM contacts co JOIN clients c ON c.id = co.client_id LEFT JOIN sites si ON si.id = co.site_id";

#[derive(Deserialize)]
pub struct ContactQuery {
    client_id: Option<Uuid>,
    q: Option<String>,
}

pub async fn list_contacts(State(st): State<Arc<AppState>>, u: User, Query(q): Query<ContactQuery>) -> ApiResult<Json<Vec<ContactRow>>> {
    let search = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty());
    Ok(Json(
        sqlx::query_as(AssertSqlSafe(format!(
            "{CONTACT_SELECT}
              WHERE ($1::uuid[] IS NULL OR co.client_id = ANY($1)) AND ($2::uuid IS NULL OR co.client_id = $2)
                AND ($3::text IS NULL OR co.name ILIKE '%' || $3 || '%' OR co.email ILIKE '%' || $3 || '%' OR co.phone ILIKE '%' || $3 || '%')
              ORDER BY co.is_primary DESC, lower(co.name) LIMIT 500"
        )))
        .bind(u.scope())
        .bind(q.client_id)
        .bind(search)
        .fetch_all(&st.db)
        .await?,
    ))
}

async fn fetch_contact(st: &AppState, u: &User, id: Uuid) -> ApiResult<ContactRow> {
    sqlx::query_as(AssertSqlSafe(format!("{CONTACT_SELECT} WHERE co.id = $1 AND ($2::uuid[] IS NULL OR co.client_id = ANY($2))")))
        .bind(id)
        .bind(u.scope())
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("contact"))
}

pub async fn get_contact(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<ContactRow>> {
    Ok(Json(fetch_contact(&st, &u, id).await?))
}

#[derive(Deserialize)]
pub struct ContactIn {
    client_id: Uuid,
    site_id: Option<Uuid>,
    name: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    phone: String,
    #[serde(default)]
    job_title: String,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    is_primary: bool,
    #[serde(default)]
    portal_enabled: bool,
    #[serde(default)]
    portal_all_tickets: bool,
    /// Invoices are emailed to billing contacts (and they see them in the portal).
    #[serde(default)]
    is_billing: bool,
}

impl ContactIn {
    async fn validate(&mut self, st: &AppState, u: &User) -> ApiResult<()> {
        super::access::client(u, self.client_id)?;
        let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM clients WHERE id = $1)").bind(self.client_id).fetch_one(&st.db).await?;
        if !exists {
            return Err(ApiError::NotFound("client"));
        }
        if let Some(s) = self.site_id
            && super::access::site(st, u, s).await? != self.client_id
        {
            return Err(ApiError::BadRequest("the site must belong to the contact's client".into()));
        }
        self.name = self.name.split_whitespace().collect::<Vec<_>>().join(" ");
        if self.name.is_empty() || self.name.chars().count() > 200 {
            return Err(ApiError::BadRequest("name must be 1-200 characters".into()));
        }
        self.email = self.email.trim().to_ascii_lowercase();
        if !self.email.is_empty() && self.email.parse::<lettre::Address>().is_err() {
            return Err(ApiError::BadRequest(format!("{} is not an email address", self.email)));
        }
        self.phone = self.phone.trim().chars().take(50).collect();
        self.job_title = self.job_title.trim().chars().take(200).collect();
        if self.notes.chars().count() > 10_000 {
            return Err(ApiError::BadRequest("notes are limited to 10,000 characters".into()));
        }
        if self.portal_enabled && self.email.is_empty() {
            return Err(ApiError::BadRequest("portal access needs an email address".into()));
        }
        Ok(())
    }
}

fn contact_conflict(e: sqlx::Error) -> ApiError {
    match e {
        sqlx::Error::Database(d) if d.is_unique_violation() => ApiError::Conflict("this client already has a contact with that email".into()),
        e => e.into(),
    }
}

pub async fn create_contact(State(st): State<Arc<AppState>>, u: User, Json(mut b): Json<ContactIn>) -> ApiResult<Json<ContactRow>> {
    u.require(Role::Technician)?;
    b.validate(&st, &u).await?;
    let id = Uuid::new_v4();
    let mut tx = st.db.begin().await?;
    if b.is_primary {
        sqlx::query("UPDATE contacts SET is_primary = false WHERE client_id = $1").bind(b.client_id).execute(&mut *tx).await?;
    }
    sqlx::query(
        "INSERT INTO contacts (id, client_id, site_id, name, email, phone, job_title, notes, is_primary, portal_enabled, portal_all_tickets, is_billing)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
    )
    .bind(id)
    .bind(b.client_id)
    .bind(b.site_id)
    .bind(&b.name)
    .bind(&b.email)
    .bind(&b.phone)
    .bind(&b.job_title)
    .bind(&b.notes)
    .bind(b.is_primary)
    .bind(b.portal_enabled)
    .bind(b.portal_all_tickets)
    .bind(b.is_billing)
    .execute(&mut *tx)
    .await
    .map_err(contact_conflict)?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "contact.create", Some(("contact", id)), json!({ "client_id": b.client_id })).await;
    Ok(Json(fetch_contact(&st, &u, id).await?))
}

pub async fn update_contact(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(mut b): Json<ContactIn>) -> ApiResult<Json<ContactRow>> {
    u.require(Role::Technician)?;
    let cur = fetch_contact(&st, &u, id).await?;
    if b.client_id != cur.client_id {
        return Err(ApiError::BadRequest("a contact can't move to another client".into()));
    }
    b.validate(&st, &u).await?;
    let mut tx = st.db.begin().await?;
    if b.is_primary {
        sqlx::query("UPDATE contacts SET is_primary = false WHERE client_id = $1 AND id <> $2").bind(b.client_id).bind(id).execute(&mut *tx).await?;
    }
    sqlx::query(
        "UPDATE contacts SET site_id = $2, name = $3, email = $4, phone = $5, job_title = $6, notes = $7, is_primary = $8,
                portal_enabled = $9, portal_all_tickets = $10, is_billing = $11, updated_at = now() WHERE id = $1",
    )
    .bind(id)
    .bind(b.site_id)
    .bind(&b.name)
    .bind(&b.email)
    .bind(&b.phone)
    .bind(&b.job_title)
    .bind(&b.notes)
    .bind(b.is_primary)
    .bind(b.portal_enabled)
    .bind(b.portal_all_tickets)
    .bind(b.is_billing)
    .execute(&mut *tx)
    .await
    .map_err(contact_conflict)?;
    if !b.portal_enabled || b.email != cur.email {
        // Access removed or moved to another address: end their portal sessions.
        sqlx::query("DELETE FROM contact_sessions WHERE contact_id = $1").bind(id).execute(&mut *tx).await?;
        sqlx::query("UPDATE contact_login_links SET used_at = now() WHERE contact_id = $1 AND used_at IS NULL").bind(id).execute(&mut *tx).await?;
    }
    // The name and email are part of their tickets' search text.
    sqlx::query("UPDATE tickets SET contact_id = contact_id WHERE contact_id = $1").bind(id).execute(&mut *tx).await?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "contact.update", Some(("contact", id)), json!({})).await;
    Ok(Json(fetch_contact(&st, &u, id).await?))
}

pub async fn remove_contact(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    fetch_contact(&st, &u, id).await?;
    sqlx::query("DELETE FROM contacts WHERE id = $1").bind(id).execute(&st.db).await?;
    auth::audit(&st.db, Some(u.id), "contact.delete", Some(("contact", id)), json!({})).await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct DomainsIn {
    domains: Vec<String>,
}

/// Mail from these domains is filed under the client when the sender isn't a contact.
pub async fn update_email_domains(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<DomainsIn>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    let mut domains: Vec<String> = vec![];
    for d in &b.domains {
        let d = d.trim().trim_start_matches('@').to_ascii_lowercase();
        if d.is_empty() {
            continue;
        }
        let valid = d.len() <= 253
            && d.contains('.')
            && d.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
        if !valid {
            return Err(ApiError::BadRequest(format!("{d} is not a domain name")));
        }
        if !domains.contains(&d) {
            domains.push(d);
        }
    }
    if domains.len() > 50 {
        return Err(ApiError::BadRequest("at most 50 domains".into()));
    }
    let taken: Option<String> = sqlx::query_scalar("SELECT name FROM clients WHERE id <> $1 AND email_domains && $2 LIMIT 1")
        .bind(id)
        .bind(&domains)
        .fetch_optional(&st.db)
        .await?;
    if let Some(other) = taken {
        return Err(ApiError::Conflict(format!("{other} already uses one of these domains")));
    }
    let n = sqlx::query("UPDATE clients SET email_domains = $2 WHERE id = $1").bind(id).bind(&domains).execute(&st.db).await?.rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound("client"));
    }
    auth::audit(&st.db, Some(u.id), "client.email_domains", Some(("client", id)), json!({ "domains": domains })).await;
    Ok(Json(json!({ "domains": domains })))
}

// ---------------------------------------------------------------------------
// Boards, statuses, ticket types
// ---------------------------------------------------------------------------

pub async fn list_boards(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Vec<super::tickets::BoardOut>>> {
    Ok(Json(super::tickets::boards(&st.db, u.scope()).await?))
}

#[derive(Deserialize)]
pub struct StatusIn {
    /// Existing status; omit for a new one.
    id: Option<Uuid>,
    name: String,
    category: String,
}

#[derive(Deserialize)]
pub struct BoardIn {
    name: String,
    #[serde(default)]
    description: String,
    /// In display order. Must include a New, a Resolved and a Closed status.
    statuses: Vec<StatusIn>,
    /// New tickets go to this team.
    #[serde(default)]
    default_team_id: Option<Uuid>,
    /// New tickets are announced on these notification channels.
    #[serde(default)]
    notify_channel_ids: Vec<Uuid>,
}

fn clean(s: &str, what: &str, max: usize) -> ApiResult<String> {
    let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if s.is_empty() || s.chars().count() > max {
        return Err(ApiError::BadRequest(format!("{what} must be 1-{max} characters")));
    }
    Ok(s)
}

impl BoardIn {
    fn validate(&self) -> ApiResult<()> {
        clean(&self.name, "name", 100)?;
        if self.statuses.is_empty() || self.statuses.len() > 30 {
            return Err(ApiError::BadRequest("a board needs 1-30 statuses".into()));
        }
        let mut names = vec![];
        for s in &self.statuses {
            let n = clean(&s.name, "status name", 60)?.to_lowercase();
            if names.contains(&n) {
                return Err(ApiError::BadRequest(format!("two statuses are called {}", s.name.trim())));
            }
            names.push(n);
            if !CATEGORIES.contains(&s.category.as_str()) {
                return Err(ApiError::BadRequest(format!("unknown status category {}", s.category)));
            }
        }
        for need in ["new", "resolved", "closed"] {
            if !self.statuses.iter().any(|s| s.category == need) {
                return Err(ApiError::BadRequest(format!("a board needs a status in the {need} category")));
            }
        }
        Ok(())
    }

    async fn check_refs(&self, db: &mut sqlx::PgConnection) -> ApiResult<()> {
        if let Some(t) = self.default_team_id {
            let ok: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM teams WHERE id = $1)").bind(t).fetch_one(&mut *db).await?;
            if !ok {
                return Err(ApiError::NotFound("team"));
            }
        }
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM notification_channels WHERE id = ANY($1)")
            .bind(&self.notify_channel_ids)
            .fetch_one(&mut *db)
            .await?;
        if n as usize != self.notify_channel_ids.len() {
            return Err(ApiError::BadRequest("unknown notification channel".into()));
        }
        Ok(())
    }
}

/// Replaces a board's statuses with `statuses`: updates the listed ones, adds new ones,
/// deletes the rest (refusing statuses still in use).
async fn save_statuses(tx: &mut sqlx::PgConnection, board: Uuid, statuses: &[StatusIn]) -> ApiResult<()> {
    let keep: Vec<Uuid> = statuses.iter().filter_map(|s| s.id).collect();
    let in_use: Option<String> = sqlx::query_scalar(
        "SELECT s.name FROM board_statuses s WHERE s.board_id = $1 AND NOT (s.id = ANY($2))
            AND EXISTS (SELECT 1 FROM tickets t WHERE t.status_id = s.id) LIMIT 1",
    )
    .bind(board)
    .bind(&keep)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(n) = in_use {
        return Err(ApiError::Conflict(format!("tickets are in status {n}; move them before removing it")));
    }
    sqlx::query("DELETE FROM board_statuses WHERE board_id = $1 AND NOT (id = ANY($2))").bind(board).bind(&keep).execute(&mut *tx).await?;
    // Park names first so renames that swap names don't trip the unique index.
    sqlx::query("UPDATE board_statuses SET name = id::text WHERE board_id = $1").bind(board).execute(&mut *tx).await?;
    for (pos, s) in statuses.iter().enumerate() {
        let name = clean(&s.name, "status name", 60)?;
        match s.id {
            Some(id) => {
                let n = sqlx::query("UPDATE board_statuses SET name = $3, category = $4, position = $5 WHERE id = $1 AND board_id = $2")
                    .bind(id)
                    .bind(board)
                    .bind(&name)
                    .bind(&s.category)
                    .bind(pos as i32)
                    .execute(&mut *tx)
                    .await?
                    .rows_affected();
                if n == 0 {
                    return Err(ApiError::BadRequest("a status belongs to another board".into()));
                }
            }
            None => {
                sqlx::query("INSERT INTO board_statuses (id, board_id, name, category, position) VALUES ($1, $2, $3, $4, $5)")
                    .bind(Uuid::new_v4())
                    .bind(board)
                    .bind(&name)
                    .bind(&s.category)
                    .bind(pos as i32)
                    .execute(&mut *tx)
                    .await?;
            }
        }
    }
    Ok(())
}

fn board_conflict(e: sqlx::Error) -> ApiError {
    match e {
        sqlx::Error::Database(d) if d.is_unique_violation() => ApiError::Conflict("a board with that name already exists".into()),
        e => e.into(),
    }
}

pub async fn create_board(State(st): State<Arc<AppState>>, u: User, Json(b): Json<BoardIn>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    b.validate()?;
    let id = Uuid::new_v4();
    let mut tx = st.db.begin().await?;
    b.check_refs(&mut tx).await?;
    sqlx::query(
        "INSERT INTO boards (id, name, description, position, default_team_id, notify_channel_ids)
         VALUES ($1, $2, $3, (SELECT coalesce(max(position), -1) + 1 FROM boards), $4, $5)",
    )
        .bind(id)
        .bind(clean(&b.name, "name", 100)?)
        .bind(b.description.trim())
        .bind(b.default_team_id)
        .bind(&b.notify_channel_ids)
        .execute(&mut *tx)
        .await
        .map_err(board_conflict)?;
    save_statuses(&mut tx, id, &b.statuses).await?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "board.create", Some(("board", id)), json!({ "name": b.name.trim() })).await;
    Ok(Json(json!({ "id": id })))
}

pub async fn update_board(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<BoardIn>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    b.validate()?;
    let mut tx = st.db.begin().await?;
    b.check_refs(&mut tx).await?;
    let n = sqlx::query("UPDATE boards SET name = $2, description = $3, default_team_id = $4, notify_channel_ids = $5 WHERE id = $1")
        .bind(id)
        .bind(clean(&b.name, "name", 100)?)
        .bind(b.description.trim())
        .bind(b.default_team_id)
        .bind(&b.notify_channel_ids)
        .execute(&mut *tx)
        .await
        .map_err(board_conflict)?
        .rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound("board"));
    }
    save_statuses(&mut tx, id, &b.statuses).await?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "board.update", Some(("board", id)), json!({ "name": b.name.trim() })).await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn remove_board(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    let used: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM tickets WHERE board_id = $1) OR EXISTS (SELECT 1 FROM mailboxes WHERE board_id = $1)",
    )
    .bind(id)
    .fetch_one(&st.db)
    .await?;
    if used {
        return Err(ApiError::Conflict("the board has tickets or a mailbox files into it; move them first".into()));
    }
    let n = sqlx::query("DELETE FROM boards WHERE id = $1").bind(id).execute(&st.db).await?.rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound("board"));
    }
    auth::audit(&st.db, Some(u.id), "board.delete", Some(("board", id)), json!({})).await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct TypesIn {
    /// The full list in order; omitted existing types are deleted (their tickets keep no type).
    types: Vec<TypeIn>,
}

#[derive(Deserialize)]
pub struct TypeIn {
    id: Option<Uuid>,
    name: String,
}

pub async fn save_types(State(st): State<Arc<AppState>>, u: User, Json(b): Json<TypesIn>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    if b.types.len() > 50 {
        return Err(ApiError::BadRequest("at most 50 ticket types".into()));
    }
    let mut names = vec![];
    for t in &b.types {
        let n = clean(&t.name, "type name", 60)?.to_lowercase();
        if names.contains(&n) {
            return Err(ApiError::BadRequest(format!("two types are called {}", t.name.trim())));
        }
        names.push(n);
    }
    let keep: Vec<Uuid> = b.types.iter().filter_map(|t| t.id).collect();
    let mut tx = st.db.begin().await?;
    sqlx::query("DELETE FROM ticket_types WHERE NOT (id = ANY($1))").bind(&keep).execute(&mut *tx).await?;
    sqlx::query("UPDATE ticket_types SET name = id::text").execute(&mut *tx).await?;
    for (pos, t) in b.types.iter().enumerate() {
        let name = clean(&t.name, "type name", 60)?;
        match t.id {
            Some(id) => {
                sqlx::query("UPDATE ticket_types SET name = $2, position = $3 WHERE id = $1").bind(id).bind(&name).bind(pos as i32).execute(&mut *tx).await?;
            }
            None => {
                sqlx::query("INSERT INTO ticket_types (id, name, position) VALUES ($1, $2, $3)")
                    .bind(Uuid::new_v4())
                    .bind(&name)
                    .bind(pos as i32)
                    .execute(&mut *tx)
                    .await?;
            }
        }
    }
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "ticket_types.update", None, json!({ "types": b.types.len() })).await;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Mailboxes
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct MailboxRow {
    id: Uuid,
    name: String,
    address: String,
    kind: String,
    imap_host: String,
    imap_port: i32,
    imap_security: String,
    imap_username: String,
    /// The password is never sent back.
    has_password: bool,
    imap_folder: String,
    board_id: Uuid,
    board_name: String,
    auto_reply: bool,
    enabled: bool,
    graph_tenant: String,
    graph_client_id: String,
    /// The Graph client secret is never sent back either.
    has_graph_secret: bool,
    graph_send: bool,
    last_polled_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
    received_24h: i64,
    created_at: DateTime<Utc>,
}

const MAILBOX_SELECT: &str = "SELECT m.id, m.name, m.address, m.kind, m.imap_host, m.imap_port, m.imap_security, m.imap_username,
       m.imap_password <> '' AS has_password, m.imap_folder, m.board_id, b.name AS board_name, m.auto_reply, m.enabled,
       m.graph_tenant, m.graph_client_id, m.graph_secret IS NOT NULL AS has_graph_secret, m.graph_send,
       m.last_polled_at, m.last_error,
       (SELECT count(*) FROM email_messages e WHERE e.mailbox_id = m.id AND e.created_at > now() - interval '24 hours') AS received_24h,
       m.created_at
  FROM mailboxes m JOIN boards b ON b.id = m.board_id";

pub async fn list_mailboxes(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Vec<MailboxRow>>> {
    u.require(Role::Admin)?;
    Ok(Json(sqlx::query_as(AssertSqlSafe(format!("{MAILBOX_SELECT} ORDER BY lower(m.name)"))).fetch_all(&st.db).await?))
}

async fn fetch_mailbox(st: &AppState, id: Uuid) -> ApiResult<MailboxRow> {
    sqlx::query_as(AssertSqlSafe(format!("{MAILBOX_SELECT} WHERE m.id = $1")))
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("mailbox"))
}

#[derive(Deserialize)]
pub struct MailboxIn {
    name: String,
    address: String,
    kind: String,
    #[serde(default)]
    imap_host: String,
    imap_port: Option<i32>,
    imap_security: Option<String>,
    #[serde(default)]
    imap_username: String,
    /// Omit (or null) to keep the stored password.
    imap_password: Option<String>,
    imap_folder: Option<String>,
    board_id: Uuid,
    #[serde(default)]
    auto_reply: bool,
    #[serde(default = "yes")]
    enabled: bool,
    #[serde(default)]
    graph_tenant: String,
    #[serde(default)]
    graph_client_id: String,
    /// Omit (or null) to keep the stored secret.
    graph_secret: Option<String>,
    #[serde(default = "yes")]
    graph_send: bool,
}

fn yes() -> bool {
    true
}

impl MailboxIn {
    async fn validate(&mut self, st: &AppState) -> ApiResult<()> {
        self.name = clean(&self.name, "name", 100)?;
        self.address = self.address.trim().to_ascii_lowercase();
        self.address.parse::<lettre::Address>().map_err(|_| ApiError::BadRequest(format!("{} is not an email address", self.address)))?;
        match self.kind.as_str() {
            "webhook" => {}
            "imap" => {
                self.imap_host = self.imap_host.trim().to_string();
                if self.imap_host.is_empty() || self.imap_username.trim().is_empty() {
                    return Err(ApiError::BadRequest("IMAP mailboxes need a host and a username".into()));
                }
                if !matches!(self.imap_security.as_deref().unwrap_or("tls"), "tls" | "none") {
                    return Err(ApiError::BadRequest("security must be tls or none".into()));
                }
                if self.imap_port.is_some_and(|p| !(1..=65535).contains(&p)) {
                    return Err(ApiError::BadRequest("port must be 1-65535".into()));
                }
            }
            "graph" => {
                self.graph_tenant = self.graph_tenant.trim().to_string();
                self.graph_client_id = self.graph_client_id.trim().to_string();
                let ok = |s: &str| !s.is_empty() && s.len() <= 100 && s.chars().all(|c| c.is_ascii_alphanumeric() || "-._".contains(c));
                if !ok(&self.graph_tenant) || !ok(&self.graph_client_id) {
                    return Err(ApiError::BadRequest("Microsoft 365 mailboxes need the tenant (directory) ID and the app's client ID".into()));
                }
            }
            other => return Err(ApiError::BadRequest(format!("unknown mailbox type {other}"))),
        }
        let board: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM boards WHERE id = $1)").bind(self.board_id).fetch_one(&st.db).await?;
        if !board {
            return Err(ApiError::NotFound("board"));
        }
        Ok(())
    }
}

fn mailbox_conflict(e: sqlx::Error) -> ApiError {
    match e {
        sqlx::Error::Database(d) if d.is_unique_violation() => ApiError::Conflict("a mailbox with that name or address already exists".into()),
        e => e.into(),
    }
}

/// Creates a mailbox. A webhook mailbox's URL (with its secret token) is returned only here
/// and when the token is rotated.
pub async fn create_mailbox(State(st): State<Arc<AppState>>, u: User, Json(mut b): Json<MailboxIn>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    b.validate(&st).await?;
    let id = Uuid::new_v4();
    let token = (b.kind == "webhook").then(auth::random_token);
    let secret = b.graph_secret.as_deref().map(str::trim).filter(|s| !s.is_empty());
    if b.kind == "graph" && secret.is_none() {
        return Err(ApiError::BadRequest("enter the app's client secret".into()));
    }
    let (secret, sealed) = match secret {
        Some(s) => {
            let (v, sealed) = crate::crypto::store(st.cfg.data_key.as_ref(), s.as_bytes());
            (Some(v), sealed)
        }
        None => (None, false),
    };
    sqlx::query(
        "INSERT INTO mailboxes (id, name, address, kind, imap_host, imap_port, imap_security, imap_username, imap_password, imap_folder,
                                webhook_token_hash, board_id, auto_reply, enabled, graph_tenant, graph_client_id, graph_secret,
                                graph_secret_sealed, graph_send)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)",
    )
    .bind(id)
    .bind(&b.name)
    .bind(&b.address)
    .bind(&b.kind)
    .bind(&b.imap_host)
    .bind(b.imap_port.unwrap_or(993))
    .bind(b.imap_security.as_deref().unwrap_or("tls"))
    .bind(b.imap_username.trim())
    .bind(b.imap_password.as_deref().unwrap_or(""))
    .bind(b.imap_folder.as_deref().map(str::trim).filter(|f| !f.is_empty()).unwrap_or("INBOX"))
    .bind(token.as_deref().map(auth::token_hash))
    .bind(b.board_id)
    .bind(b.auto_reply)
    .bind(b.enabled)
    .bind(&b.graph_tenant)
    .bind(&b.graph_client_id)
    .bind(secret)
    .bind(sealed)
    .bind(b.graph_send)
    .execute(&st.db)
    .await
    .map_err(mailbox_conflict)?;
    auth::audit(&st.db, Some(u.id), "mailbox.create", Some(("mailbox", id)), json!({ "name": b.name, "kind": b.kind })).await;
    let mut out = serde_json::to_value(fetch_mailbox(&st, id).await?).map_err(anyhow::Error::from)?;
    if let Some(t) = token {
        out["webhook_url"] = format!("{}/api/inbound/email/{t}", st.cfg.public_url).into();
    }
    Ok(Json(out))
}

pub async fn update_mailbox(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(mut b): Json<MailboxIn>) -> ApiResult<Json<MailboxRow>> {
    u.require(Role::Admin)?;
    let cur = fetch_mailbox(&st, id).await?;
    if cur.kind != b.kind {
        return Err(ApiError::BadRequest("a mailbox's type can't change; create a new one".into()));
    }
    b.validate(&st).await?;
    let secret = b.graph_secret.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(|s| crate::crypto::store(st.cfg.data_key.as_ref(), s.as_bytes()));
    sqlx::query(
        "UPDATE mailboxes SET name = $2, address = $3, imap_host = $4, imap_port = $5, imap_security = $6, imap_username = $7,
                imap_password = coalesce($8, imap_password), imap_folder = $9, board_id = $10, auto_reply = $11, enabled = $12,
                graph_tenant = $13, graph_client_id = $14, graph_secret = coalesce($15, graph_secret),
                graph_secret_sealed = CASE WHEN $15::bytea IS NULL THEN graph_secret_sealed ELSE $16 END, graph_send = $17,
                last_error = NULL
          WHERE id = $1",
    )
    .bind(id)
    .bind(&b.name)
    .bind(&b.address)
    .bind(&b.imap_host)
    .bind(b.imap_port.unwrap_or(993))
    .bind(b.imap_security.as_deref().unwrap_or("tls"))
    .bind(b.imap_username.trim())
    .bind(b.imap_password.as_deref())
    .bind(b.imap_folder.as_deref().map(str::trim).filter(|f| !f.is_empty()).unwrap_or("INBOX"))
    .bind(b.board_id)
    .bind(b.auto_reply)
    .bind(b.enabled)
    .bind(&b.graph_tenant)
    .bind(&b.graph_client_id)
    .bind(secret.as_ref().map(|s| s.0.clone()))
    .bind(secret.as_ref().is_some_and(|s| s.1))
    .bind(b.graph_send)
    .execute(&st.db)
    .await
    .map_err(mailbox_conflict)?;
    auth::audit(&st.db, Some(u.id), "mailbox.update", Some(("mailbox", id)), json!({ "name": b.name, "enabled": b.enabled })).await;
    Ok(Json(fetch_mailbox(&st, id).await?))
}

pub async fn remove_mailbox(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    let n = sqlx::query("DELETE FROM mailboxes WHERE id = $1").bind(id).execute(&st.db).await?.rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound("mailbox"));
    }
    auth::audit(&st.db, Some(u.id), "mailbox.delete", Some(("mailbox", id)), json!({})).await;
    Ok(Json(json!({ "ok": true })))
}

/// Polls an IMAP mailbox now (also the "test connection" button).
pub async fn poll_mailbox(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    let mb: Mailbox = sqlx::query_as(AssertSqlSafe(format!("SELECT {MAILBOX_COLS} FROM mailboxes WHERE id = $1")))
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("mailbox"))?;
    if mb.kind == "webhook" {
        return Err(ApiError::BadRequest("webhook mailboxes aren't polled".into()));
    }
    Ok(Json(match crate::email::poll_now(&st, &mb).await {
        Ok(n) => json!({ "ok": true, "filed": n }),
        Err(e) => json!({ "ok": false, "error": e }),
    }))
}

/// Issues a new webhook URL; the old one stops working.
pub async fn rotate_mailbox_token(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    let token = auth::random_token();
    let n = sqlx::query("UPDATE mailboxes SET webhook_token_hash = $2 WHERE id = $1 AND kind = 'webhook'")
        .bind(id)
        .bind(auth::token_hash(&token))
        .execute(&st.db)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound("webhook mailbox"));
    }
    auth::audit(&st.db, Some(u.id), "mailbox.rotate_token", Some(("mailbox", id)), json!({})).await;
    Ok(Json(json!({ "webhook_url": format!("{}/api/inbound/email/{token}", st.cfg.public_url) })))
}

#[derive(Serialize, sqlx::FromRow)]
pub struct InboundRow {
    id: Uuid,
    mailbox_name: Option<String>,
    from_addr: String,
    subject: String,
    status: String,
    ignored_reason: Option<String>,
    ticket_id: Option<Uuid>,
    ticket_number: Option<i64>,
    created_at: DateTime<Utc>,
}

/// The latest inbound mail and what happened to it (filed, ignored and why).
pub async fn inbound_log(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Vec<InboundRow>>> {
    u.require(Role::Admin)?;
    Ok(Json(
        sqlx::query_as(
            "SELECT e.id, m.name AS mailbox_name, e.from_addr, e.subject, e.status, e.ignored_reason, e.ticket_id, t.number AS ticket_number,
                    e.created_at
               FROM email_messages e LEFT JOIN mailboxes m ON m.id = e.mailbox_id LEFT JOIN tickets t ON t.id = e.ticket_id
              WHERE e.direction = 'in' ORDER BY e.created_at DESC LIMIT 100",
        )
        .fetch_all(&st.db)
        .await?,
    ))
}

// ---------------------------------------------------------------------------
// Inbound webhook
// ---------------------------------------------------------------------------

/// The raw message from a provider's inbound webhook: a `message/rfc822` (or text) body,
/// Postmark's JSON with `RawEmail`, or Mailgun's form post to a `mime` route (`body-mime`).
async fn raw_message(req: Request) -> ApiResult<Vec<u8>> {
    let ct = req.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("").to_ascii_lowercase();
    let bad = |m: &str| ApiError::BadRequest(m.to_string());
    if ct.starts_with("application/json") {
        let Json(v): Json<Value> = Json::from_request(req, &()).await.map_err(|e| bad(&e.to_string()))?;
        let raw = v.get("RawEmail").or_else(|| v.get("raw")).and_then(Value::as_str).ok_or_else(|| bad("JSON without RawEmail"))?;
        return Ok(raw.as_bytes().to_vec());
    }
    if ct.starts_with("multipart/form-data") {
        let mut form = Multipart::from_request(req, &()).await.map_err(|e| bad(&e.to_string()))?;
        while let Some(f) = form.next_field().await.map_err(|e| bad(&e.to_string()))? {
            if f.name() == Some("body-mime") {
                return Ok(f.bytes().await.map_err(|e| bad(&e.to_string()))?.to_vec());
            }
        }
        return Err(bad("form without body-mime"));
    }
    if ct.starts_with("application/x-www-form-urlencoded") {
        let axum::Form(f): axum::Form<HashMap<String, String>> = axum::Form::from_request(req, &()).await.map_err(|e| bad(&e.to_string()))?;
        return f.get("body-mime").map(|s| s.as_bytes().to_vec()).ok_or_else(|| bad("form without body-mime"));
    }
    let body = Bytes::from_request(req, &()).await.map_err(|e| bad(&e.to_string()))?;
    Ok(body.to_vec())
}

/// `POST /api/inbound/email/{token}`: no session; the token in the URL identifies the mailbox.
pub async fn inbound(State(st): State<Arc<AppState>>, Path(token): Path<String>, req: Request) -> ApiResult<Json<Value>> {
    let mb: Mailbox = sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {MAILBOX_COLS} FROM mailboxes WHERE webhook_token_hash = $1 AND kind = 'webhook'"
    )))
    .bind(auth::token_hash(&token))
    .fetch_optional(&st.db)
    .await?
    .ok_or(ApiError::NotFound("mailbox"))?;
    if !mb.enabled {
        return Err(ApiError::Conflict("this mailbox is disabled".into()));
    }
    let raw = raw_message(req).await?;
    if raw.is_empty() {
        return Err(ApiError::BadRequest("empty message".into()));
    }
    // Unparseable mail is the sender's problem (400); anything else is ours, and a 5xx makes
    // the provider retry.
    let outcome = crate::email::receive(&st, &mb, &raw).await.map_err(|e| {
        if e.to_string() == crate::email::NOT_EMAIL { ApiError::BadRequest(e.to_string()) } else { ApiError::Internal(e) }
    })?;
    Ok(Json(match outcome {
        crate::email::Outcome::Created(id) => json!({ "result": "created", "ticket_id": id }),
        crate::email::Outcome::Threaded(id) => json!({ "result": "threaded", "ticket_id": id }),
        crate::email::Outcome::Ignored(reason) => json!({ "result": "ignored", "reason": reason }),
        crate::email::Outcome::Duplicate => json!({ "result": "duplicate" }),
    }))
}
