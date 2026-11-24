//! More service desk configuration: teams, canned responses (and the macros built on them),
//! and the portal and survey settings.

use std::collections::HashMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::auth::{self, Role, User};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

fn clean(s: &str, what: &str, max: usize) -> ApiResult<String> {
    let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if s.is_empty() || s.chars().count() > max {
        return Err(ApiError::BadRequest(format!("{what} must be 1-{max} characters")));
    }
    Ok(s)
}

// ---------------------------------------------------------------------------
// Teams
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct TeamRow {
    id: Uuid,
    name: String,
    member_ids: Vec<Uuid>,
    open_tickets: i64,
}

pub async fn teams(db: &sqlx::PgPool) -> sqlx::Result<Vec<TeamRow>> {
    sqlx::query_as(
        "SELECT t.id, t.name, ARRAY(SELECT m.user_id FROM team_members m WHERE m.team_id = t.id) AS member_ids,
                (SELECT count(*) FROM tickets tk JOIN board_statuses s ON s.id = tk.status_id
                  WHERE tk.team_id = t.id AND s.category NOT IN ('resolved', 'closed') AND tk.merged_into IS NULL) AS open_tickets
           FROM teams t ORDER BY lower(t.name)",
    )
    .fetch_all(db)
    .await
}

pub async fn list_teams(State(st): State<Arc<AppState>>, _u: User) -> ApiResult<Json<Vec<TeamRow>>> {
    Ok(Json(teams(&st.db).await?))
}

#[derive(Deserialize)]
pub struct TeamIn {
    name: String,
    #[serde(default)]
    member_ids: Vec<Uuid>,
}

async fn save_team(tx: &mut sqlx::PgConnection, id: Uuid, b: &TeamIn) -> ApiResult<()> {
    let name = clean(&b.name, "name", 100)?;
    sqlx::query("INSERT INTO teams (id, name) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET name = $2")
        .bind(id)
        .bind(&name)
        .execute(&mut *tx)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(d) if d.is_unique_violation() => ApiError::Conflict("a team with that name already exists".into()),
            e => e.into(),
        })?;
    let techs: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE id = ANY($1) AND role IN ('technician', 'admin')")
        .bind(&b.member_ids)
        .fetch_one(&mut *tx)
        .await?;
    let mut unique = b.member_ids.clone();
    unique.sort_unstable();
    unique.dedup();
    if techs as usize != unique.len() {
        return Err(ApiError::BadRequest("team members must be technicians or admins".into()));
    }
    sqlx::query("DELETE FROM team_members WHERE team_id = $1").bind(id).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO team_members (team_id, user_id) SELECT $1, unnest($2::uuid[])").bind(id).bind(&unique).execute(&mut *tx).await?;
    Ok(())
}

pub async fn create_team(State(st): State<Arc<AppState>>, u: User, Json(b): Json<TeamIn>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    let id = Uuid::new_v4();
    let mut tx = st.db.begin().await?;
    save_team(&mut tx, id, &b).await?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "team.create", Some(("team", id)), json!({ "name": b.name.trim() })).await;
    Ok(Json(json!({ "id": id })))
}

pub async fn update_team(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<TeamIn>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM teams WHERE id = $1)").bind(id).fetch_one(&st.db).await?;
    if !exists {
        return Err(ApiError::NotFound("team"));
    }
    let mut tx = st.db.begin().await?;
    save_team(&mut tx, id, &b).await?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "team.update", Some(("team", id)), json!({ "members": b.member_ids.len() })).await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn remove_team(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    let n = sqlx::query("DELETE FROM teams WHERE id = $1").bind(id).execute(&st.db).await?.rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound("team"));
    }
    auth::audit(&st.db, Some(u.id), "team.delete", Some(("team", id)), json!({})).await;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Canned responses and macros
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct CannedRow {
    id: Uuid,
    name: String,
    body: String,
    kind: String,
    status_category: Option<String>,
    priority: Option<i16>,
    assign: Option<String>,
    /// null: shared with everyone.
    owner_id: Option<Uuid>,
    updated_at: DateTime<Utc>,
}

const CANNED_COLS: &str = "id, name, body, kind, status_category, priority, assign, owner_id, updated_at";

/// Shared responses and the user's own.
pub async fn list_canned(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Vec<CannedRow>>> {
    Ok(Json(
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {CANNED_COLS} FROM canned_responses WHERE owner_id IS NULL OR owner_id = $1 ORDER BY owner_id NULLS FIRST, lower(name)"
        )))
        .bind(u.id)
        .fetch_all(&st.db)
        .await?,
    ))
}

#[derive(Deserialize)]
pub struct CannedIn {
    name: String,
    #[serde(default)]
    body: String,
    #[serde(default = "reply")]
    kind: String,
    status_category: Option<String>,
    priority: Option<i16>,
    assign: Option<String>,
    /// Shared (admins only), or the creator's own.
    #[serde(default)]
    shared: bool,
}

fn reply() -> String {
    "reply".into()
}

impl CannedIn {
    fn validate(&mut self, u: &User) -> ApiResult<()> {
        self.name = clean(&self.name, "name", 100)?;
        if self.body.chars().count() > 20_000 {
            return Err(ApiError::BadRequest("responses are limited to 20,000 characters".into()));
        }
        if !matches!(self.kind.as_str(), "reply" | "note") {
            return Err(ApiError::BadRequest("kind must be reply or note".into()));
        }
        if let Some(c) = &self.status_category
            && !crate::tickets::CATEGORIES.contains(&c.as_str())
        {
            return Err(ApiError::BadRequest(format!("unknown status category {c}")));
        }
        if self.priority.is_some_and(|p| !(1..=4).contains(&p)) {
            return Err(ApiError::BadRequest("priority must be 1-4".into()));
        }
        if let Some(a) = &self.assign
            && !matches!(a.as_str(), "me" | "none")
        {
            return Err(ApiError::BadRequest("assign must be me or none".into()));
        }
        if self.shared {
            u.require(Role::Admin)?;
        }
        Ok(())
    }
}

pub async fn create_canned(State(st): State<Arc<AppState>>, u: User, Json(mut b): Json<CannedIn>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    b.validate(&u)?;
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO canned_responses (id, name, body, kind, status_category, priority, assign, owner_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(id)
    .bind(&b.name)
    .bind(&b.body)
    .bind(&b.kind)
    .bind(&b.status_category)
    .bind(b.priority)
    .bind(&b.assign)
    .bind((!b.shared).then_some(u.id))
    .execute(&st.db)
    .await?;
    Ok(Json(json!({ "id": id })))
}

/// Shared responses are admins' to change; personal ones their owner's.
async fn editable(st: &AppState, u: &User, id: Uuid) -> ApiResult<()> {
    let owner: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT owner_id FROM canned_responses WHERE id = $1").bind(id).fetch_optional(&st.db).await?;
    match owner {
        Some(Some(o)) if o == u.id => Ok(()),
        Some(None) if u.role() == Role::Admin => Ok(()),
        Some(None) => Err(ApiError::Forbidden),
        _ => Err(ApiError::NotFound("canned response")),
    }
}

pub async fn update_canned(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(mut b): Json<CannedIn>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    editable(&st, &u, id).await?;
    b.validate(&u)?;
    sqlx::query(
        "UPDATE canned_responses SET name = $2, body = $3, kind = $4, status_category = $5, priority = $6, assign = $7, owner_id = $8,
                updated_at = now() WHERE id = $1",
    )
    .bind(id)
    .bind(&b.name)
    .bind(&b.body)
    .bind(&b.kind)
    .bind(&b.status_category)
    .bind(b.priority)
    .bind(&b.assign)
    .bind((!b.shared).then_some(u.id))
    .execute(&st.db)
    .await?;
    Ok(Json(json!({ "ok": true })))
}

pub async fn remove_canned(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    editable(&st, &u, id).await?;
    sqlx::query("DELETE FROM canned_responses WHERE id = $1").bind(id).execute(&st.db).await?;
    Ok(Json(json!({ "ok": true })))
}

/// Fills `{{group.field}}` placeholders. Unknown ones stay as written, so a typo shows up in
/// the composer instead of vanishing.
pub fn render(template: &str, vars: &HashMap<&str, String>) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        match after.find("}}") {
            Some(end) => {
                let key = after[..end].trim();
                match vars.get(key) {
                    Some(v) => out.push_str(v),
                    None => out.push_str(&rest[start..start + 2 + end + 2]),
                }
                rest = &after[end + 2..];
            }
            None => {
                out.push_str(&rest[start..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

fn first_name(name: &str) -> String {
    name.split_whitespace().next().unwrap_or_default().to_string()
}

/// `GET /tickets/{id}/canned/{cid}`: the response with the ticket's details filled in, and the
/// macro's actions for the composer to apply.
pub async fn render_canned(State(st): State<Arc<AppState>>, u: User, Path((ticket, id)): Path<(Uuid, Uuid)>) -> ApiResult<Json<Value>> {
    super::tickets::visible(&st, &u, ticket).await?;
    let c: CannedRow = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {CANNED_COLS} FROM canned_responses WHERE id = $1 AND (owner_id IS NULL OR owner_id = $2)"
    )))
    .bind(id)
    .bind(u.id)
    .fetch_optional(&st.db)
    .await?
    .ok_or(ApiError::NotFound("canned response"))?;
    let (number, subject, contact, email, client): (i64, String, Option<String>, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT t.number, t.subject, coalesce(co.name, nullif(t.requester_name, '')), coalesce(nullif(co.email, ''), nullif(t.requester_email, '')),
                cl.name
           FROM tickets t LEFT JOIN contacts co ON co.id = t.contact_id LEFT JOIN clients cl ON cl.id = t.client_id WHERE t.id = $1",
    )
    .bind(ticket)
    .fetch_one(&st.db)
    .await?;
    let contact = contact.unwrap_or_default();
    let company = st.company().company_name;
    let vars: HashMap<&str, String> = HashMap::from([
        ("ticket.number", format!("T-{number}")),
        ("ticket.subject", subject),
        ("contact.name", contact.clone()),
        ("contact.first_name", first_name(&contact)),
        ("contact.email", email.unwrap_or_default()),
        ("client.name", client.unwrap_or_default()),
        ("technician.name", u.name.clone()),
        ("technician.first_name", first_name(&u.name)),
        ("company.name", company),
    ]);
    Ok(Json(json!({
        "body": render(&c.body, &vars),
        "kind": c.kind,
        "status_category": c.status_category,
        "priority": c.priority,
        "assign": c.assign,
    })))
}

// ---------------------------------------------------------------------------
// Portal and survey settings
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub struct DeskSettings {
    portal_board_id: Option<Uuid>,
    portal_welcome: String,
    csat_enabled: bool,
    /// Where requests from the devices' tray app go; none: the portal's board.
    #[serde(default)]
    tray_board_id: Option<Uuid>,
}

pub async fn get_settings(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<DeskSettings>> {
    u.require(Role::Admin)?;
    Ok(Json(sqlx::query_as("SELECT portal_board_id, portal_welcome, csat_enabled, tray_board_id FROM company_settings").fetch_one(&st.db).await?))
}

pub async fn update_settings(State(st): State<Arc<AppState>>, u: User, Json(b): Json<DeskSettings>) -> ApiResult<Json<DeskSettings>> {
    u.require(Role::Admin)?;
    if b.portal_welcome.chars().count() > 2000 {
        return Err(ApiError::BadRequest("the welcome text is limited to 2,000 characters".into()));
    }
    for bid in [b.portal_board_id, b.tray_board_id].into_iter().flatten() {
        let ok: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM boards WHERE id = $1)").bind(bid).fetch_one(&st.db).await?;
        if !ok {
            return Err(ApiError::NotFound("board"));
        }
    }
    let out: DeskSettings = sqlx::query_as(
        "UPDATE company_settings SET portal_board_id = $1, portal_welcome = $2, csat_enabled = $3, tray_board_id = $5, updated_at = now(), updated_by = $4
         RETURNING portal_board_id, portal_welcome, csat_enabled, tray_board_id",
    )
    .bind(b.portal_board_id)
    .bind(b.portal_welcome.trim())
    .bind(b.csat_enabled)
    .bind(u.id)
    .bind(b.tray_board_id)
    .fetch_one(&st.db)
    .await?;
    // The survey switch is read from the cached settings.
    let fresh = crate::state::Company::load(&st.db).await?;
    *st.company.write().unwrap_or_else(|e| e.into_inner()) = fresh;
    auth::audit(&st.db, Some(u.id), "settings.service_desk", None, json!({ "csat_enabled": out.csat_enabled, "tray_board_id": out.tray_board_id })).await;
    Ok(Json(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_variables() {
        let vars = HashMap::from([("contact.first_name", "Ann".to_string()), ("ticket.number", "T-10001".to_string())]);
        assert_eq!(render("Hi {{contact.first_name}}, re {{ ticket.number }}.", &vars), "Hi Ann, re T-10001.");
        assert_eq!(render("{{nope}} and {{contact.first_name}}", &vars), "{{nope}} and Ann");
        assert_eq!(render("unclosed {{ticket.number", &vars), "unclosed {{ticket.number");
        assert_eq!(first_name("  Ann  Example "), "Ann");
    }
}
