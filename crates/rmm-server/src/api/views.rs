//! Saved views (migration 0029, docs/design/fields.md): a name for the state of a list page, as
//! the query string the page keeps in its URL (filters, sort) plus the columns it hides.
//!
//! A view is personal, or shared with everyone who signs in (technicians may share). The query
//! is checked on the way in: only the keys the page understands, no paging cursors, and a
//! `client` that names a client the saver can see; the stored form is re-encoded from the parsed
//! pairs, so what the dashboard later puts in a link is always plain `key=value` pairs. A view
//! bound to a client is listed only to people who can see that client.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::auth::{self, Role, User};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// The query keys each page's views may carry.
fn allowed_keys(page: &str) -> &'static [&'static str] {
    match page {
        "agents" => &["client", "site", "view", "q", "os", "health", "category", "set", "tag", "cf", "cfv", "encryption", "sort", "dir"],
        _ => &[],
    }
}

const QUERY_MAX: usize = 2000;

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError::BadRequest(msg.into())
}

/// The canonical form of `query` for `page`, and the client it names (if any).
fn clean_query(page: &str, query: &str) -> ApiResult<(String, Option<Uuid>)> {
    let allowed = allowed_keys(page);
    if allowed.is_empty() {
        return Err(bad("views can be saved for: agents"));
    }
    let pairs: Vec<(String, String)> =
        serde_urlencoded::from_str(query.trim_start_matches('?')).map_err(|_| bad("the query isn't a valid query string"))?;
    let mut out: Vec<(String, String)> = Vec::new();
    let mut client = None;
    for (k, v) in pairs {
        if !allowed.contains(&k.as_str()) {
            return Err(bad(format!("{k} can't be part of a saved view")));
        }
        if v.is_empty() || out.iter().any(|(ok, _)| *ok == k) {
            continue;
        }
        if v.chars().any(char::is_control) || v.chars().count() > 200 {
            return Err(bad(format!("the value of {k} is not valid")));
        }
        if k == "client" {
            client = Some(v.parse::<Uuid>().map_err(|_| bad("client must be a client id"))?);
        }
        out.push((k, v));
    }
    let q = serde_urlencoded::to_string(&out).map_err(|_| bad("the query isn't a valid query string"))?;
    if q.len() > QUERY_MAX {
        return Err(bad("the query is too long"));
    }
    Ok((q, client))
}

fn clean_name(name: &str) -> ApiResult<String> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 60 || name.chars().any(char::is_control) {
        return Err(bad("a name is 1-60 characters"));
    }
    Ok(name.to_string())
}

fn clean_columns(cols: Option<Vec<String>>) -> ApiResult<Option<Vec<String>>> {
    let Some(cols) = cols else { return Ok(None) };
    if cols.len() > 40 || cols.iter().any(|c| c.is_empty() || c.len() > 40 || !c.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')) {
        return Err(bad("hidden_columns must be column ids"));
    }
    Ok(Some(cols))
}

#[derive(Serialize, sqlx::FromRow)]
pub struct View {
    id: Uuid,
    page: String,
    name: String,
    shared: bool,
    query: String,
    hidden_columns: Option<Vec<String>>,
    client_id: Option<Uuid>,
    owner_id: Uuid,
    owner_name: String,
    /// The signed-in user may change or delete it: its owner, or an admin for a shared one.
    #[sqlx(default)]
    can_edit: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

const SELECT: &str = "SELECT v.id, v.page, v.name, v.shared, v.query, v.hidden_columns, v.client_id, v.owner_id, o.name AS owner_name,
       (v.owner_id = $1 OR (v.shared AND $2)) AS can_edit, v.created_at, v.updated_at
  FROM saved_views v JOIN users o ON o.id = v.owner_id";

#[derive(Deserialize)]
pub struct ListQuery {
    page: Option<String>,
}

/// The user's own views and the shared ones they may see (a shared view for a client they can't
/// see is left out). Their own first.
pub async fn list(State(st): State<Arc<AppState>>, u: User, Query(q): Query<ListQuery>) -> ApiResult<Json<Vec<View>>> {
    Ok(Json(
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "{SELECT} WHERE ($3::text IS NULL OR v.page = $3)
               AND (v.owner_id = $1 OR (v.shared AND ($4::uuid[] IS NULL OR v.client_id IS NULL OR v.client_id = ANY($4))))
             ORDER BY (v.owner_id = $1) DESC, lower(v.name)"
        )))
        .bind(u.id)
        .bind(u.role() == Role::Admin)
        .bind(q.page.as_deref().filter(|p| !p.is_empty()))
        .bind(u.scope())
        .fetch_all(&st.db)
        .await?,
    ))
}

async fn get(st: &AppState, u: &User, id: Uuid) -> ApiResult<View> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "{SELECT} WHERE v.id = $3
           AND (v.owner_id = $1 OR (v.shared AND ($4::uuid[] IS NULL OR v.client_id IS NULL OR v.client_id = ANY($4))))"
    )))
    .bind(u.id)
    .bind(u.role() == Role::Admin)
    .bind(id)
    .bind(u.scope())
    .fetch_optional(&st.db)
    .await?
    .ok_or(ApiError::NotFound("view"))
}

fn taken(e: sqlx::Error) -> ApiError {
    match e {
        sqlx::Error::Database(d) if d.is_unique_violation() => ApiError::Conflict("you already have a view with that name".into()),
        e => e.into(),
    }
}

#[derive(Deserialize)]
pub struct NewView {
    page: String,
    name: String,
    query: String,
    hidden_columns: Option<Vec<String>>,
    #[serde(default)]
    shared: bool,
}

/// Views are cheap, but not unlimited.
const PER_USER_MAX: i64 = 100;

pub async fn create(State(st): State<Arc<AppState>>, u: User, Json(b): Json<NewView>) -> ApiResult<Json<View>> {
    if b.shared {
        u.require(Role::Technician)?;
    }
    let name = clean_name(&b.name)?;
    let (query, client) = clean_query(&b.page, &b.query)?;
    if let Some(c) = client {
        super::access::client(&u, c)?;
    }
    let columns = clean_columns(b.hidden_columns)?;
    let have: i64 = sqlx::query_scalar("SELECT count(*) FROM saved_views WHERE owner_id = $1").bind(u.id).fetch_one(&st.db).await?;
    if have >= PER_USER_MAX {
        return Err(bad(format!("at most {PER_USER_MAX} saved views each; delete some first")));
    }
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO saved_views (id, page, name, owner_id, shared, query, hidden_columns, client_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(id)
        .bind(&b.page)
        .bind(&name)
        .bind(u.id)
        .bind(b.shared)
        .bind(&query)
        .bind(&columns)
        .bind(client)
        .execute(&st.db)
        .await
        .map_err(taken)?;
    auth::audit(&st.db, Some(u.id), "saved_view.create", Some(("saved_view", id)), json!({ "page": b.page, "name": name, "shared": b.shared })).await;
    get(&st, &u, id).await.map(Json)
}

#[derive(Deserialize)]
pub struct EditView {
    name: Option<String>,
    query: Option<String>,
    /// Present (even `null`) replaces the hidden columns.
    #[serde(default, deserialize_with = "some")]
    hidden_columns: Option<Option<Vec<String>>>,
    shared: Option<bool>,
}

fn some<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Option<Vec<String>>>, D::Error> {
    Option::<Vec<String>>::deserialize(d).map(Some)
}

pub async fn update(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<EditView>) -> ApiResult<Json<View>> {
    let cur = get(&st, &u, id).await?;
    if !cur.can_edit {
        return Err(ApiError::Denied("only its owner can change a view".into()));
    }
    if b.shared == Some(true) {
        u.require(Role::Technician)?;
    }
    let name = b.name.as_deref().map(clean_name).transpose()?;
    let (query, client) = match b.query.as_deref() {
        Some(q) => {
            let (q, c) = clean_query(&cur.page, q)?;
            if let Some(c) = c {
                super::access::client(&u, c)?;
            }
            (Some(q), Some(c))
        }
        None => (None, None),
    };
    let set_columns = b.hidden_columns.is_some();
    let columns = clean_columns(b.hidden_columns.flatten())?;
    sqlx::query(
        "UPDATE saved_views SET name = coalesce($2, name), query = coalesce($3, query),
                client_id = CASE WHEN $4 THEN $5 ELSE client_id END,
                hidden_columns = CASE WHEN $6 THEN $7 ELSE hidden_columns END,
                shared = coalesce($8, shared), updated_at = now()
          WHERE id = $1",
    )
    .bind(id)
    .bind(&name)
    .bind(&query)
    .bind(query.is_some())
    .bind(client.flatten())
    .bind(set_columns)
    .bind(&columns)
    .bind(b.shared)
    .execute(&st.db)
    .await
    .map_err(taken)?;
    auth::audit(&st.db, Some(u.id), "saved_view.update", Some(("saved_view", id)), json!({ "name": name.as_deref().unwrap_or(&cur.name), "shared": b.shared })).await;
    get(&st, &u, id).await.map(Json)
}

pub async fn remove(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let cur = get(&st, &u, id).await?;
    if !cur.can_edit {
        return Err(ApiError::Denied("only its owner can delete a view".into()));
    }
    sqlx::query("DELETE FROM saved_views WHERE id = $1").bind(id).execute(&st.db).await?;
    auth::audit(&st.db, Some(u.id), "saved_view.delete", Some(("saved_view", id)), json!({ "name": cur.name })).await;
    Ok(Json(json!({ "ok": true })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queries_are_checked_and_reencoded() {
        let c = Uuid::new_v4();
        let (q, client) = clean_query("agents", &format!("?client={c}&os=windows&q=file+server&sort=hostname&dir=desc&health=")).unwrap();
        assert_eq!(client, Some(c));
        assert_eq!(q, format!("client={c}&os=windows&q=file+server&sort=hostname&dir=desc"));
        // Paging cursors, unknown keys and a bad client are refused.
        for bad in ["after=abc", "limit=1", "evil=1", "client=not-a-uuid", "q=a%00b"] {
            assert!(clean_query("agents", bad).is_err(), "{bad}");
        }
        assert!(clean_query("tickets", "q=x").is_err());
        // A repeated key keeps the first; an empty query is fine (the unfiltered list).
        assert_eq!(clean_query("agents", "os=linux&os=windows").unwrap().0, "os=linux");
        assert_eq!(clean_query("agents", "").unwrap(), (String::new(), None));
        // Special characters survive the round trip as data, not markup.
        let (q, _) = clean_query("agents", "q=%22%3E%3Cscript%3E%26x%3D1").unwrap();
        assert_eq!(q, "q=%22%3E%3Cscript%3E%26x%3D1");
        assert!(clean_query("agents", &format!("q={}", "x".repeat(201))).is_err());
    }

    #[test]
    fn names_and_columns() {
        assert_eq!(clean_name(" Servers ").unwrap(), "Servers");
        assert!(clean_name("").is_err());
        assert!(clean_name(&"x".repeat(61)).is_err());
        assert_eq!(clean_columns(None).unwrap(), None);
        assert_eq!(clean_columns(Some(vec!["os".into(), "last_seen".into()])).unwrap(), Some(vec!["os".into(), "last_seen".into()]));
        assert!(clean_columns(Some(vec!["a b".into()])).is_err());
        assert!(clean_columns(Some(vec!["".into()])).is_err());
    }
}
