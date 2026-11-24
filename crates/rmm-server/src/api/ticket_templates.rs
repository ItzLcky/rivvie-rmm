//! Ticket templates and ticket checklists (docs/design/identity.md#ticket-templates).
//!
//! A template opens a ticket with its subject, body, board, type, priority and a checklist.
//! A checklist item is a manual tick-off, optionally bound to an identity action on the
//! ticket's directory user (`tickets.identity_user_id`): running it goes through the same
//! checks as the Users tab ([`crate::identity::act`]). Every tick and every action writes an
//! internal note to the ticket's timeline.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::auth::{self, Role, User};
use crate::error::{ApiError, ApiResult};
use crate::identity::{Action, Delivery};
use crate::state::AppState;
use crate::tickets::{self, Author, NewTicket};

/// Actions a checklist item can be bound to.
pub const ACTIONS: &[&str] = &["identity.disable", "identity.reset_password", "identity.remove_groups", "identity.revoke_sessions"];
const MAX_ITEMS: usize = 100;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ItemSpec {
    pub text: String,
    #[serde(default)]
    pub action: Option<String>,
}

fn clean_items(items: &[ItemSpec]) -> ApiResult<Vec<ItemSpec>> {
    if items.len() > MAX_ITEMS {
        return Err(ApiError::BadRequest(format!("a checklist has at most {MAX_ITEMS} items")));
    }
    items
        .iter()
        .map(|i| {
            let text = i.text.split_whitespace().collect::<Vec<_>>().join(" ");
            if text.is_empty() || text.chars().count() > 500 {
                return Err(ApiError::BadRequest("each checklist item is 1-500 characters".into()));
            }
            let action = i.action.as_deref().map(str::trim).filter(|a| !a.is_empty());
            if let Some(a) = action
                && !ACTIONS.contains(&a)
            {
                return Err(ApiError::BadRequest(format!("unknown checklist action {a}: {}", ACTIONS.join(", "))));
            }
            Ok(ItemSpec { text, action: action.map(String::from) })
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct TemplateRow {
    id: Uuid,
    name: String,
    client_id: Option<Uuid>,
    client_name: Option<String>,
    board_id: Option<Uuid>,
    type_id: Option<Uuid>,
    priority: i16,
    subject: String,
    body: String,
    checklist: sqlx::types::Json<Vec<ItemSpec>>,
    updated_at: DateTime<Utc>,
}

const COLS: &str = "t.id, t.name, t.client_id, c.name AS client_name, t.board_id, t.type_id, t.priority, t.subject, t.body, t.checklist, t.updated_at
  FROM ticket_templates t LEFT JOIN clients c ON c.id = t.client_id";

#[derive(Deserialize)]
pub struct ListQuery {
    /// Templates for this client: its own and the shared ones.
    client_id: Option<Uuid>,
}

pub async fn list(State(st): State<Arc<AppState>>, u: User, Query(q): Query<ListQuery>) -> ApiResult<Json<Vec<TemplateRow>>> {
    u.require(Role::Technician)?;
    let rows: Vec<TemplateRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {COLS} WHERE ($1::uuid IS NULL OR t.client_id IS NULL OR t.client_id = $1) ORDER BY lower(t.name)"
    )))
    .bind(q.client_id)
    .fetch_all(&st.db)
    .await?;
    Ok(Json(rows.into_iter().filter(|r| r.client_id.is_none_or(|c| u.can_see_client(c))).collect()))
}

#[derive(Deserialize)]
pub struct TemplateIn {
    name: String,
    client_id: Option<Uuid>,
    board_id: Option<Uuid>,
    type_id: Option<Uuid>,
    priority: Option<i16>,
    #[serde(default)]
    subject: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    checklist: Vec<ItemSpec>,
}

fn clean_template(b: &TemplateIn) -> ApiResult<(String, i16, Vec<ItemSpec>)> {
    let name = b.name.split_whitespace().collect::<Vec<_>>().join(" ");
    if name.is_empty() || name.chars().count() > 100 {
        return Err(ApiError::BadRequest("name must be 1-100 characters".into()));
    }
    let p = b.priority.unwrap_or(3);
    if !(1..=4).contains(&p) {
        return Err(ApiError::BadRequest("priority is 1-4".into()));
    }
    if b.subject.chars().count() > 300 || b.body.chars().count() > 100_000 {
        return Err(ApiError::BadRequest("the subject is limited to 300 characters and the body to 100,000".into()));
    }
    Ok((name, p, clean_items(&b.checklist)?))
}

fn db_err(e: sqlx::Error) -> ApiError {
    match e {
        sqlx::Error::Database(d) if d.is_unique_violation() => ApiError::Conflict("a template with that name exists".into()),
        sqlx::Error::Database(d) if d.is_foreign_key_violation() => ApiError::BadRequest("unknown client, board or ticket type".into()),
        e => e.into(),
    }
}

async fn fetch(st: &AppState, id: Uuid) -> ApiResult<TemplateRow> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT {COLS} WHERE t.id = $1"))).bind(id).fetch_optional(&st.db).await?.ok_or(ApiError::NotFound("template"))
}

pub async fn create(State(st): State<Arc<AppState>>, u: User, Json(b): Json<TemplateIn>) -> ApiResult<Json<TemplateRow>> {
    u.require(Role::Admin)?;
    let (name, priority, items) = clean_template(&b)?;
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO ticket_templates (id, name, client_id, board_id, type_id, priority, subject, body, checklist) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(id)
    .bind(&name)
    .bind(b.client_id)
    .bind(b.board_id)
    .bind(b.type_id)
    .bind(priority)
    .bind(b.subject.trim())
    .bind(b.body.trim())
    .bind(sqlx::types::Json(&items))
    .execute(&st.db)
    .await
    .map_err(db_err)?;
    auth::audit(&st.db, Some(u.id), "ticket_template.create", Some(("ticket_template", id)), json!({ "name": name })).await;
    Ok(Json(fetch(&st, id).await?))
}

pub async fn update(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<TemplateIn>) -> ApiResult<Json<TemplateRow>> {
    u.require(Role::Admin)?;
    let (name, priority, items) = clean_template(&b)?;
    let n = sqlx::query(
        "UPDATE ticket_templates SET name = $2, client_id = $3, board_id = $4, type_id = $5, priority = $6, subject = $7, body = $8, checklist = $9,
                updated_at = now() WHERE id = $1",
    )
    .bind(id)
    .bind(&name)
    .bind(b.client_id)
    .bind(b.board_id)
    .bind(b.type_id)
    .bind(priority)
    .bind(b.subject.trim())
    .bind(b.body.trim())
    .bind(sqlx::types::Json(&items))
    .execute(&st.db)
    .await
    .map_err(db_err)?
    .rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound("template"));
    }
    auth::audit(&st.db, Some(u.id), "ticket_template.update", Some(("ticket_template", id)), json!({ "name": name })).await;
    Ok(Json(fetch(&st, id).await?))
}

pub async fn remove(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    let name: Option<String> = sqlx::query_scalar("DELETE FROM ticket_templates WHERE id = $1 RETURNING name").bind(id).fetch_optional(&st.db).await?;
    let name = name.ok_or(ApiError::NotFound("template"))?;
    auth::audit(&st.db, Some(u.id), "ticket_template.delete", Some(("ticket_template", id)), json!({ "name": name })).await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct FromTemplateIn {
    template_id: Uuid,
    client_id: Uuid,
    contact_id: Option<Uuid>,
    /// The directory user the ticket is about (a leaver, a starter).
    identity_user_id: Option<Uuid>,
    /// Overrides the template's subject.
    subject: Option<String>,
}

/// Checks the directory user belongs to the client; returns its display name.
async fn identity_user_of(st: &AppState, client: Uuid, id: Uuid) -> ApiResult<String> {
    let row: Option<(Uuid, String, String)> = sqlx::query_as(
        "SELECT s.client_id, u.display_name, u.username FROM identity_users u JOIN identity_sources s ON s.id = u.source_id WHERE u.id = $1",
    )
    .bind(id)
    .fetch_optional(&st.db)
    .await?;
    match row {
        Some((c, display, username)) if c == client => Ok(if display.is_empty() { username } else { display }),
        _ => Err(ApiError::BadRequest("the directory user must be one of the ticket client's".into())),
    }
}

pub async fn from_template(State(st): State<Arc<AppState>>, u: User, Json(b): Json<FromTemplateIn>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    super::access::client(&u, b.client_id)?;
    let t = fetch(&st, b.template_id).await?;
    if t.client_id.is_some_and(|c| c != b.client_id) {
        return Err(ApiError::BadRequest("that template is for another client".into()));
    }
    let mut name = String::new();
    if let Some(iu) = b.identity_user_id {
        u.need(auth::Perm::IdentityRead)?;
        name = identity_user_of(&st, b.client_id, iu).await?;
    }
    let mut tx = st.db.begin().await?;
    if let Some(c) = b.contact_id {
        let row: Option<(Uuid, String)> = sqlx::query_as("SELECT client_id, name FROM contacts WHERE id = $1").bind(c).fetch_optional(&mut *tx).await?;
        match row {
            Some((cl, n)) if cl == b.client_id => {
                if name.is_empty() {
                    name = n;
                }
            }
            _ => return Err(ApiError::BadRequest("the contact must be one of the client's".into())),
        }
    }
    let subject = b.subject.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(String::from).unwrap_or_else(|| t.subject.clone());
    let subject = subject.replace("{name}", &name).split_whitespace().collect::<Vec<_>>().join(" ");
    let subject = subject.trim_end_matches(|c: char| c == ':' || c.is_whitespace()).to_string();
    let subject = if subject.is_empty() { t.name.clone() } else { subject.chars().take(300).collect() };
    let board = match t.board_id {
        Some(b) => b,
        None => sqlx::query_scalar("SELECT id FROM boards ORDER BY position, name LIMIT 1")
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| ApiError::Conflict("there is no ticket board".into()))?,
    };
    let created = tickets::create(
        &mut tx,
        NewTicket {
            client_id: Some(b.client_id),
            contact_id: b.contact_id,
            board_id: board,
            type_id: t.type_id,
            priority: t.priority,
            subject,
            body: t.body.replace("{name}", &name),
            body_public: false,
            source: "dashboard",
            created_by: Some(u.id),
            author: Author::user(u.id),
            ..Default::default()
        },
    )
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => ApiError::BadRequest("the board has no status in the New category".into()),
        e => e.into(),
    })?;
    sqlx::query("UPDATE tickets SET identity_user_id = $2 WHERE id = $1").bind(created.id).bind(b.identity_user_id).execute(&mut *tx).await?;
    for (i, item) in t.checklist.0.iter().enumerate() {
        sqlx::query("INSERT INTO ticket_checklist_items (id, ticket_id, position, text, action) VALUES ($1, $2, $3, $4, $5)")
            .bind(Uuid::new_v4())
            .bind(created.id)
            .bind(i as i32)
            .bind(&item.text)
            .bind(&item.action)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    auth::audit(
        &st.db,
        Some(u.id),
        "ticket.create",
        Some(("ticket", created.id)),
        json!({ "number": created.number, "template": t.name, "identity_user_id": b.identity_user_id }),
    )
    .await;
    tickets::notify_created(&st, created.id).await;
    tickets::announce(&st, created.id).await;
    Ok(Json(json!({ "id": created.id, "number": created.number })))
}

// ---------------------------------------------------------------------------------------------
// Checklists
// ---------------------------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct ItemRow {
    id: Uuid,
    position: i32,
    text: String,
    action: Option<String>,
    action_state: Option<String>,
    done_by: Option<Uuid>,
    done_by_name: Option<String>,
    done_at: Option<DateTime<Utc>>,
}

async fn items(st: &AppState, ticket: Uuid) -> ApiResult<Vec<ItemRow>> {
    Ok(sqlx::query_as(
        "SELECT i.id, i.position, i.text, i.action, i.action_state, i.done_by, u.name AS done_by_name, i.done_at
           FROM ticket_checklist_items i LEFT JOIN users u ON u.id = i.done_by WHERE i.ticket_id = $1 ORDER BY i.position, i.id",
    )
    .bind(ticket)
    .fetch_all(&st.db)
    .await?)
}

async fn checklist_json(st: &AppState, u: &User, ticket: Uuid) -> ApiResult<Value> {
    let iu: Option<Uuid> = sqlx::query_scalar("SELECT identity_user_id FROM tickets WHERE id = $1").bind(ticket).fetch_one(&st.db).await?;
    let identity_user = match iu {
        Some(id) if u.has(auth::Perm::IdentityRead) => sqlx::query_as::<_, (Uuid, String, String, String, String, bool, bool, bool)>(
            "SELECT u.id, u.display_name, u.username, u.upn, s.kind, u.enabled, u.privileged, u.deleted_at IS NOT NULL
               FROM identity_users u JOIN identity_sources s ON s.id = u.source_id WHERE u.id = $1",
        )
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .map(|r| json!({ "id": r.0, "display_name": r.1, "username": r.2, "upn": r.3, "kind": r.4, "enabled": r.5, "privileged": r.6, "deleted": r.7 })),
        Some(id) => Some(json!({ "id": id })),
        None => None,
    };
    Ok(json!({ "identity_user": identity_user, "items": items(st, ticket).await? }))
}

pub async fn get_checklist(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    super::tickets::visible(&st, &u, id).await?;
    Ok(Json(checklist_json(&st, &u, id).await?))
}

#[derive(Deserialize)]
pub struct ChecklistItemIn {
    id: Option<Uuid>,
    text: String,
    #[serde(default)]
    action: Option<String>,
}

#[derive(Deserialize)]
pub struct ChecklistIn {
    items: Vec<ChecklistItemIn>,
    /// Absent keeps the ticket's directory user; `null` clears it.
    #[serde(default, deserialize_with = "some_or_null")]
    identity_user_id: Option<Option<Uuid>>,
}

fn some_or_null<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Option<Uuid>>, D::Error> {
    Ok(Some(Option::deserialize(d)?))
}

/// Replaces the checklist's items (keeping the state of the ones that stay) and, when given,
/// the ticket's directory user.
pub async fn put_checklist(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<ChecklistIn>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    let client = super::tickets::visible(&st, &u, id).await?;
    let specs = clean_items(&b.items.iter().map(|i| ItemSpec { text: i.text.clone(), action: i.action.clone() }).collect::<Vec<_>>())?;
    if let Some(Some(iu)) = b.identity_user_id {
        u.need(auth::Perm::IdentityRead)?;
        let client = client.ok_or_else(|| ApiError::BadRequest("give the ticket a client first".into()))?;
        identity_user_of(&st, client, iu).await?;
    }
    let mut tx = st.db.begin().await?;
    let keep: Vec<Uuid> = b.items.iter().filter_map(|i| i.id).collect();
    sqlx::query("DELETE FROM ticket_checklist_items WHERE ticket_id = $1 AND NOT (id = ANY($2))").bind(id).bind(&keep).execute(&mut *tx).await?;
    for (pos, (item, spec)) in b.items.iter().zip(&specs).enumerate() {
        match item.id {
            Some(iid) => {
                let n = sqlx::query("UPDATE ticket_checklist_items SET position = $3, text = $4, action = $5 WHERE id = $1 AND ticket_id = $2")
                    .bind(iid)
                    .bind(id)
                    .bind(pos as i32)
                    .bind(&spec.text)
                    .bind(&spec.action)
                    .execute(&mut *tx)
                    .await?
                    .rows_affected();
                if n == 0 {
                    return Err(ApiError::BadRequest("a checklist item isn't this ticket's".into()));
                }
            }
            None => {
                sqlx::query("INSERT INTO ticket_checklist_items (id, ticket_id, position, text, action) VALUES ($1, $2, $3, $4, $5)")
                    .bind(Uuid::new_v4())
                    .bind(id)
                    .bind(pos as i32)
                    .bind(&spec.text)
                    .bind(&spec.action)
                    .execute(&mut *tx)
                    .await?;
            }
        }
    }
    if let Some(iu) = b.identity_user_id {
        sqlx::query("UPDATE tickets SET identity_user_id = $2, updated_at = now() WHERE id = $1").bind(id).bind(iu).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    tickets::announce(&st, id).await;
    Ok(Json(checklist_json(&st, &u, id).await?))
}

async fn item_of(st: &AppState, ticket: Uuid, item: Uuid) -> ApiResult<(String, Option<String>, Option<DateTime<Utc>>)> {
    sqlx::query_as("SELECT text, action, done_at FROM ticket_checklist_items WHERE id = $1 AND ticket_id = $2")
        .bind(item)
        .bind(ticket)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("checklist item"))
}

#[derive(Deserialize)]
pub struct TickIn {
    done: bool,
}

/// Ticks an item off by hand (or un-ticks it).
pub async fn tick(State(st): State<Arc<AppState>>, u: User, Path((id, item)): Path<(Uuid, Uuid)>, Json(b): Json<TickIn>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    super::tickets::visible(&st, &u, id).await?;
    let (text, _, done_at) = item_of(&st, id, item).await?;
    if done_at.is_some() != b.done {
        let mut tx = st.db.begin().await?;
        sqlx::query(
            "UPDATE ticket_checklist_items SET done_at = CASE WHEN $2 THEN now() END, done_by = CASE WHEN $2 THEN $3::uuid END WHERE id = $1",
        )
        .bind(item)
        .bind(b.done)
        .bind(u.id)
        .execute(&mut *tx)
        .await?;
        let body = if b.done { format!("Checklist: done: {text}") } else { format!("Checklist: not done after all: {text}") };
        tickets::add_event(&mut tx, id, "note", false, &Author::user(u.id), &body, json!({ "checklist_item": item, "done": b.done })).await?;
        tx.commit().await?;
        tickets::announce(&st, id).await;
    }
    Ok(Json(checklist_json(&st, &u, id).await?))
}

#[derive(Deserialize, Default)]
pub struct RunIn {
    /// For `identity.reset_password`: where the generated password goes (default the vault).
    delivery: Option<Delivery>,
}

/// Runs an item's action on the ticket's directory user; on success the item is done.
pub async fn run(State(st): State<Arc<AppState>>, u: User, Path((id, item)): Path<(Uuid, Uuid)>, body: Option<Json<RunIn>>) -> ApiResult<Response> {
    u.require(Role::Technician)?;
    let client = super::tickets::visible(&st, &u, id).await?.ok_or_else(|| ApiError::BadRequest("the ticket has no client".into()))?;
    let (text, action, _) = item_of(&st, id, item).await?;
    let action_name = action.ok_or_else(|| ApiError::BadRequest("this item has no action: tick it off instead".into()))?;
    let iu: Option<Uuid> = sqlx::query_scalar("SELECT identity_user_id FROM tickets WHERE id = $1").bind(id).fetch_one(&st.db).await?;
    let iu = iu.ok_or_else(|| ApiError::Conflict("choose the ticket's directory user first".into()))?;
    let t = crate::identity::target(&st.db, iu).await?.filter(|t| t.client_id == client).ok_or(ApiError::NotFound("directory user"))?;
    super::identity::manage_gate(&st, &u, client)?;
    let delivery = body.and_then(|b| b.0.delivery).unwrap_or(Delivery::Vault);
    let action = match action_name.as_str() {
        "identity.disable" => Action::SetEnabled(false),
        "identity.reset_password" => Action::Reset { password: None, must_change: true, delivery },
        "identity.remove_groups" => Action::RemoveGroups(None),
        "identity.revoke_sessions" => Action::RevokeSessions,
        _ => return Err(ApiError::BadRequest("unknown action".into())),
    };
    let who = if t.display_name.is_empty() { t.username.clone() } else { t.display_name.clone() };
    let res = crate::identity::act(&st, &u, &t, action, "checklist").await;
    let state = match &res {
        Ok(_) => "done".to_string(),
        Err(e) => format!("failed: {}", e.to_string().chars().take(300).collect::<String>()),
    };
    let mut tx = st.db.begin().await?;
    sqlx::query(
        "UPDATE ticket_checklist_items SET action_state = $2,
                done_at = CASE WHEN $3 THEN now() ELSE done_at END, done_by = CASE WHEN $3 THEN $4::uuid ELSE done_by END
          WHERE id = $1",
    )
    .bind(item)
    .bind(&state)
    .bind(res.is_ok())
    .bind(u.id)
    .execute(&mut *tx)
    .await?;
    let body = match &res {
        Ok(_) => format!("Checklist: {text}: {action_name} on {who} ({}) done", t.source_name),
        Err(_) => format!("Checklist: {text}: {action_name} on {who} ({}) {state}", t.source_name),
    };
    // The event names the action, never a password.
    tickets::add_event(&mut tx, id, "note", false, &Author::user(u.id), &body, json!({ "checklist_item": item, "action": action_name, "ok": res.is_ok() }))
        .await?;
    tx.commit().await?;
    tickets::announce(&st, id).await;
    let out = res?;
    let mut v = checklist_json(&st, &u, id).await?;
    v["outcome"] = serde_json::to_value(out).map_err(anyhow::Error::from)?;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(v)).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn items_are_checked() {
        let ok = clean_items(&[ItemSpec { text: "  Disable   the account ".into(), action: Some("identity.disable".into()) }]).unwrap();
        assert_eq!(ok[0].text, "Disable the account");
        assert!(clean_items(&[ItemSpec { text: "x".into(), action: Some("identity.delete".into()) }]).is_err());
        assert!(clean_items(&[ItemSpec { text: " ".into(), action: None }]).is_err());
        assert!(clean_items(&vec![ItemSpec { text: "x".into(), action: None }; MAX_ITEMS + 1]).is_err());
    }

    #[test]
    fn seeded_templates_use_known_actions() {
        let sql = include_str!("../../migrations/0050_ticket_templates.sql");
        for a in ACTIONS {
            assert!(sql.contains(&format!("'{a}'")), "{a} missing from the CHECK");
        }
        for chunk in sql.split("\"action\": \"").skip(1) {
            let a = chunk.split('"').next().unwrap();
            assert!(ACTIONS.contains(&a), "seed uses {a}");
        }
    }
}
