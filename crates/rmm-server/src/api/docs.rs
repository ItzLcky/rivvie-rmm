//! Per-client documentation (docs/design/documentation.md): Markdown pages with their history,
//! the MSP-wide categories and templates they start from, and the links from pages to vault
//! credentials. Reading is for anyone who sees the client; pages are written by technicians,
//! categories and templates by admins.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::AssertSqlSafe;
use uuid::Uuid;

use super::vault;
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

fn check_body(body: &str) -> ApiResult<()> {
    if body.chars().count() > 200_000 {
        return Err(ApiError::BadRequest("pages are limited to 200,000 characters".into()));
    }
    Ok(())
}

async fn check_category(st: &AppState, id: Option<Uuid>) -> ApiResult<()> {
    if let Some(id) = id {
        let ok: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM doc_categories WHERE id = $1)").bind(id).fetch_one(&st.db).await?;
        if !ok {
            return Err(ApiError::BadRequest("unknown category".into()));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Documents
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct DocRow {
    id: Uuid,
    client_id: Uuid,
    title: String,
    category_id: Option<Uuid>,
    /// The category's name; empty when there is none.
    category: String,
    #[sqlx(default)]
    body: Option<String>,
    updated_by_name: Option<String>,
    updated_at: DateTime<Utc>,
    revisions: i64,
}

const DOC_COLS: &str = "d.id, d.client_id, d.title, d.category_id, coalesce(c.name, '') AS category, u.name AS updated_by_name, d.updated_at,
     (SELECT count(*) FROM client_doc_revisions r WHERE r.doc_id = d.id) AS revisions
  FROM client_docs d LEFT JOIN doc_categories c ON c.id = d.category_id LEFT JOIN users u ON u.id = d.updated_by";

/// A client's pages in category order, uncategorised last.
pub async fn list(State(st): State<Arc<AppState>>, u: User, Path(client): Path<Uuid>) -> ApiResult<Json<Vec<DocRow>>> {
    super::access::client(&u, client)?;
    Ok(Json(
        sqlx::query_as(AssertSqlSafe(format!(
            "SELECT {DOC_COLS} WHERE d.client_id = $1 ORDER BY c.position NULLS LAST, lower(c.name), lower(d.title)"
        )))
        .bind(client)
        .fetch_all(&st.db)
        .await?,
    ))
}

async fn fetch_doc(st: &AppState, u: &User, id: Uuid) -> ApiResult<DocRow> {
    let mut d: DocRow = sqlx::query_as(AssertSqlSafe(format!("SELECT {DOC_COLS} WHERE d.id = $1")))
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("document"))?;
    super::access::client(u, d.client_id).map_err(|_| ApiError::NotFound("document"))?;
    d.body = Some(sqlx::query_scalar("SELECT body FROM client_docs WHERE id = $1").bind(id).fetch_one(&st.db).await?);
    Ok(d)
}

/// The page with its history, the vault items it links to and the tickets that link it. The
/// items are metadata only (never a secret), and only for users who may use the vault; others
/// get `credentials_hidden`. Tickets are the newest 50 the user may see.
pub async fn get(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let d = fetch_doc(&st, &u, id).await?;
    let history: Vec<(i64, String, Option<String>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT r.id, r.title, u.name, r.edited_at FROM client_doc_revisions r LEFT JOIN users u ON u.id = r.edited_by
          WHERE r.doc_id = $1 ORDER BY r.id DESC LIMIT 100",
    )
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    let (credentials, hidden) = if vault::can_read(&u) {
        let items: Vec<vault::ItemRow> = sqlx::query_as(AssertSqlSafe(format!(
            "SELECT {} WHERE i.id IN (SELECT item_id FROM client_doc_vault_links WHERE doc_id = $1) ORDER BY lower(i.name)",
            vault::ITEM_COLS
        )))
        .bind(id)
        .fetch_all(&st.db)
        .await?;
        (items, false)
    } else {
        let any: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM client_doc_vault_links WHERE doc_id = $1)").bind(id).fetch_one(&st.db).await?;
        (Vec::new(), any)
    };
    let tickets: Vec<TicketLink> = sqlx::query_as(
        "SELECT t.id, t.number, t.subject, bs.name AS status, bs.category AS status_category, t.updated_at
           FROM ticket_docs td JOIN tickets t ON t.id = td.ticket_id JOIN board_statuses bs ON bs.id = t.status_id
          WHERE td.doc_id = $1 AND ($2::uuid[] IS NULL OR t.client_id = ANY($2))
          ORDER BY t.created_at DESC, t.number DESC LIMIT 50",
    )
    .bind(id)
    .bind(u.scope())
    .fetch_all(&st.db)
    .await?;
    let mut v = serde_json::to_value(&d).map_err(anyhow::Error::from)?;
    v["tickets"] = json!(tickets);
    v["history"] = json!(history.iter().map(|(id, t, n, at)| json!({ "id": id, "title": t, "edited_by": n, "edited_at": at })).collect::<Vec<_>>());
    v["credentials"] = json!(credentials);
    v["credentials_hidden"] = json!(hidden);
    Ok(Json(v))
}

/// A ticket that links a page.
#[derive(Serialize, sqlx::FromRow)]
pub struct TicketLink {
    id: Uuid,
    number: i64,
    subject: String,
    status: String,
    status_category: String,
    updated_at: DateTime<Utc>,
}

/// One earlier version's text.
pub async fn revision(State(st): State<Arc<AppState>>, u: User, Path((id, rev)): Path<(Uuid, i64)>) -> ApiResult<Json<Value>> {
    fetch_doc(&st, &u, id).await?;
    let (title, body, at): (String, String, DateTime<Utc>) =
        sqlx::query_as("SELECT title, body, edited_at FROM client_doc_revisions WHERE id = $2 AND doc_id = $1")
            .bind(id)
            .bind(rev)
            .fetch_optional(&st.db)
            .await?
            .ok_or(ApiError::NotFound("revision"))?;
    Ok(Json(json!({ "title": title, "body": body, "edited_at": at })))
}

/// A JSON string is a valid YAML double-quoted scalar, escapes and all.
fn yaml_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into())
}

/// The page as a `.md` file with YAML front matter (title, category, client, updated), which
/// the dashboard's import reads back.
pub async fn export(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Response> {
    let d = fetch_doc(&st, &u, id).await?;
    let client: String = sqlx::query_scalar("SELECT name FROM clients WHERE id = $1").bind(d.client_id).fetch_one(&st.db).await?;
    let text = format!(
        "---\ntitle: {}\ncategory: {}\nclient: {}\nupdated: {}\n---\n\n{}",
        yaml_str(&d.title),
        yaml_str(&d.category),
        yaml_str(&client),
        d.updated_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        d.body.unwrap_or_default()
    );
    let mut res = text.into_response();
    let h = res.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/markdown; charset=utf-8"));
    h.insert(header::CONTENT_DISPOSITION, HeaderValue::from_str(&super::tools::disposition(&format!("{}.md", d.title))).map_err(anyhow::Error::from)?);
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    Ok(res)
}

#[derive(Deserialize)]
pub struct DocIn {
    title: String,
    #[serde(default)]
    category_id: Option<Uuid>,
    #[serde(default)]
    body: String,
    /// The `updated_at` the editor opened; a page saved since then isn't overwritten.
    #[serde(default)]
    expected_updated_at: Option<DateTime<Utc>>,
}

impl DocIn {
    async fn validate(&mut self, st: &AppState) -> ApiResult<()> {
        self.title = clean(&self.title, "title", 300)?;
        check_body(&self.body)?;
        check_category(st, self.category_id).await
    }
}

/// The distinct `vault:<uuid>` references in a body, links and credential blocks alike.
fn vault_refs(body: &str) -> Vec<Uuid> {
    let mut out = Vec::new();
    for (i, _) in body.match_indices("vault:") {
        if let Some(id) = body.get(i + 6..i + 42).and_then(|s| Uuid::try_parse(s).ok())
            && !out.contains(&id)
        {
            out.push(id);
        }
    }
    out
}

/// Replaces the page's links with the references that resolve to the same client's items.
/// Anything else (deleted items, another client's, typos) is ignored, so a save never fails
/// over a reference: the page shows "Credential not found" there instead.
async fn relink(tx: &mut sqlx::PgConnection, doc: Uuid, client: Uuid, body: &str) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM client_doc_vault_links WHERE doc_id = $1").bind(doc).execute(&mut *tx).await?;
    let refs = vault_refs(body);
    if !refs.is_empty() {
        sqlx::query("INSERT INTO client_doc_vault_links (doc_id, item_id) SELECT $1, id FROM vault_items WHERE id = ANY($2) AND client_id = $3")
            .bind(doc)
            .bind(&refs)
            .bind(client)
            .execute(&mut *tx)
            .await?;
    }
    Ok(())
}

pub async fn create(State(st): State<Arc<AppState>>, u: User, Path(client): Path<Uuid>, Json(mut b): Json<DocIn>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    super::access::client(&u, client)?;
    b.validate(&st).await?;
    let id = Uuid::new_v4();
    let mut tx = st.db.begin().await?;
    let updated_at: DateTime<Utc> =
        sqlx::query_scalar("INSERT INTO client_docs (id, client_id, title, category_id, body, updated_by) VALUES ($1, $2, $3, $4, $5, $6) RETURNING updated_at")
            .bind(id)
            .bind(client)
            .bind(&b.title)
            .bind(b.category_id)
            .bind(&b.body)
            .bind(u.id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| match e {
                sqlx::Error::Database(d) if d.is_foreign_key_violation() => ApiError::NotFound("client"),
                e => e.into(),
            })?;
    relink(&mut tx, id, client, &b.body).await?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "client_doc.create", Some(("client_doc", id)), json!({ "client_id": client })).await;
    Ok(Json(json!({ "id": id, "updated_at": updated_at })))
}

/// Saves a new version; the previous one goes into the history.
pub async fn update(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(mut b): Json<DocIn>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    let cur = fetch_doc(&st, &u, id).await?;
    b.validate(&st).await?;
    let mut tx = st.db.begin().await?;
    let at: DateTime<Utc> = sqlx::query_scalar("SELECT updated_at FROM client_docs WHERE id = $1 FOR UPDATE")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ApiError::NotFound("document"))?;
    if b.expected_updated_at.is_some_and(|e| e != at) {
        return Err(ApiError::Conflict("someone else saved this page since you opened it".into()));
    }
    sqlx::query(
        "INSERT INTO client_doc_revisions (doc_id, title, body, edited_by, edited_at)
         SELECT id, title, body, updated_by, updated_at FROM client_docs WHERE id = $1",
    )
    .bind(id)
    .execute(&mut *tx)
    .await?;
    let updated_at: DateTime<Utc> =
        sqlx::query_scalar("UPDATE client_docs SET title = $2, category_id = $3, body = $4, updated_by = $5, updated_at = now() WHERE id = $1 RETURNING updated_at")
            .bind(id)
            .bind(&b.title)
            .bind(b.category_id)
            .bind(&b.body)
            .bind(u.id)
            .fetch_one(&mut *tx)
            .await?;
    relink(&mut tx, id, cur.client_id, &b.body).await?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "client_doc.update", Some(("client_doc", id)), json!({})).await;
    Ok(Json(json!({ "ok": true, "updated_at": updated_at })))
}

pub async fn remove(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    fetch_doc(&st, &u, id).await?;
    sqlx::query("DELETE FROM client_docs WHERE id = $1").bind(id).execute(&st.db).await?;
    auth::audit(&st.db, Some(u.id), "client_doc.delete", Some(("client_doc", id)), json!({})).await;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Categories
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct CategoryRow {
    id: Uuid,
    name: String,
    position: i32,
    /// Pages in it (of the clients the user can see).
    docs: i64,
    templates: i64,
}

const CATEGORY_SELECT: &str = "SELECT c.id, c.name, c.position,
       (SELECT count(*) FROM client_docs d WHERE d.category_id = c.id AND ($1::uuid[] IS NULL OR d.client_id = ANY($1))) AS docs,
       (SELECT count(*) FROM doc_templates t WHERE t.category_id = c.id) AS templates
  FROM doc_categories c";

async fn all_categories(st: &AppState, u: &User) -> ApiResult<Vec<CategoryRow>> {
    Ok(sqlx::query_as(AssertSqlSafe(format!("{CATEGORY_SELECT} ORDER BY c.position, lower(c.name)"))).bind(u.scope()).fetch_all(&st.db).await?)
}

async fn fetch_category(st: &AppState, u: &User, id: Uuid) -> ApiResult<CategoryRow> {
    sqlx::query_as(AssertSqlSafe(format!("{CATEGORY_SELECT} WHERE c.id = $2")))
        .bind(u.scope())
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("category"))
}

pub async fn categories(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Vec<CategoryRow>>> {
    Ok(Json(all_categories(&st, &u).await?))
}

fn category_taken(e: sqlx::Error) -> ApiError {
    match &e {
        sqlx::Error::Database(d) if d.is_unique_violation() => ApiError::Conflict("there is already a category with that name".into()),
        _ => e.into(),
    }
}

#[derive(Deserialize)]
pub struct CategoryIn {
    name: String,
}

/// A new category goes last.
pub async fn create_category(State(st): State<Arc<AppState>>, u: User, Json(b): Json<CategoryIn>) -> ApiResult<Json<CategoryRow>> {
    u.require(Role::Admin)?;
    let name = clean(&b.name, "name", 100)?;
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO doc_categories (id, name, position) VALUES ($1, $2, (SELECT coalesce(max(position), -1) + 1 FROM doc_categories))")
        .bind(id)
        .bind(&name)
        .execute(&st.db)
        .await
        .map_err(category_taken)?;
    auth::audit(&st.db, Some(u.id), "doc_category.create", Some(("doc_category", id)), json!({ "name": name })).await;
    Ok(Json(fetch_category(&st, &u, id).await?))
}

pub async fn update_category(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<CategoryIn>) -> ApiResult<Json<CategoryRow>> {
    u.require(Role::Admin)?;
    let cur = fetch_category(&st, &u, id).await?;
    let name = clean(&b.name, "name", 100)?;
    sqlx::query("UPDATE doc_categories SET name = $2, updated_at = now() WHERE id = $1").bind(id).bind(&name).execute(&st.db).await.map_err(category_taken)?;
    auth::audit(&st.db, Some(u.id), "doc_category.update", Some(("doc_category", id)), json!({ "from": cur.name, "name": name })).await;
    Ok(Json(fetch_category(&st, &u, id).await?))
}

/// Its pages and templates become uncategorised.
pub async fn delete_category(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    let cur = fetch_category(&st, &u, id).await?;
    sqlx::query("DELETE FROM doc_categories WHERE id = $1").bind(id).execute(&st.db).await?;
    auth::audit(&st.db, Some(u.id), "doc_category.delete", Some(("doc_category", id)), json!({ "name": cur.name })).await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct OrderIn {
    ids: Vec<Uuid>,
}

/// The listed categories first, in that order; any left out keep their order after them.
pub async fn reorder_categories(State(st): State<Arc<AppState>>, u: User, Json(b): Json<OrderIn>) -> ApiResult<Json<Vec<CategoryRow>>> {
    u.require(Role::Admin)?;
    sqlx::query(
        "UPDATE doc_categories c SET position = o.pos FROM (
             SELECT id, (row_number() OVER (ORDER BY array_position($1::uuid[], id) NULLS LAST, position, lower(name)) - 1)::int AS pos
               FROM doc_categories) o
          WHERE o.id = c.id AND c.position <> o.pos",
    )
    .bind(&b.ids)
    .execute(&st.db)
    .await?;
    auth::audit(&st.db, Some(u.id), "doc_category.reorder", None, json!({ "ids": b.ids })).await;
    Ok(Json(all_categories(&st, &u).await?))
}

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct TemplateRow {
    id: Uuid,
    name: String,
    category_id: Option<Uuid>,
    category: String,
    description: String,
    #[sqlx(default)]
    body: Option<String>,
    updated_by_name: Option<String>,
    updated_at: DateTime<Utc>,
}

const TEMPLATE_COLS: &str = "t.id, t.name, t.category_id, coalesce(c.name, '') AS category, t.description, u.name AS updated_by_name, t.updated_at
  FROM doc_templates t LEFT JOIN doc_categories c ON c.id = t.category_id LEFT JOIN users u ON u.id = t.updated_by";

/// Without bodies, in category order.
pub async fn templates(State(st): State<Arc<AppState>>, _u: User) -> ApiResult<Json<Vec<TemplateRow>>> {
    Ok(Json(
        sqlx::query_as(AssertSqlSafe(format!("SELECT {TEMPLATE_COLS} ORDER BY c.position NULLS LAST, lower(c.name), lower(t.name)")))
            .fetch_all(&st.db)
            .await?,
    ))
}

async fn fetch_template(st: &AppState, id: Uuid) -> ApiResult<TemplateRow> {
    let mut t: TemplateRow = sqlx::query_as(AssertSqlSafe(format!("SELECT {TEMPLATE_COLS} WHERE t.id = $1")))
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("template"))?;
    t.body = Some(sqlx::query_scalar("SELECT body FROM doc_templates WHERE id = $1").bind(id).fetch_one(&st.db).await?);
    Ok(t)
}

pub async fn template(State(st): State<Arc<AppState>>, _u: User, Path(id): Path<Uuid>) -> ApiResult<Json<TemplateRow>> {
    Ok(Json(fetch_template(&st, id).await?))
}

#[derive(Deserialize)]
pub struct TemplateIn {
    name: String,
    #[serde(default)]
    category_id: Option<Uuid>,
    #[serde(default)]
    description: String,
    #[serde(default)]
    body: String,
}

impl TemplateIn {
    async fn validate(&mut self, st: &AppState) -> ApiResult<()> {
        self.name = clean(&self.name, "name", 200)?;
        self.description = self.description.split_whitespace().collect::<Vec<_>>().join(" ");
        if self.description.chars().count() > 500 {
            return Err(ApiError::BadRequest("the description is limited to 500 characters".into()));
        }
        check_body(&self.body)?;
        check_category(st, self.category_id).await
    }
}

fn template_taken(e: sqlx::Error) -> ApiError {
    match &e {
        sqlx::Error::Database(d) if d.is_unique_violation() => ApiError::Conflict("there is already a template with that name".into()),
        _ => e.into(),
    }
}

pub async fn create_template(State(st): State<Arc<AppState>>, u: User, Json(mut b): Json<TemplateIn>) -> ApiResult<Json<TemplateRow>> {
    u.require(Role::Admin)?;
    b.validate(&st).await?;
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO doc_templates (id, name, category_id, description, body, created_by, updated_by) VALUES ($1, $2, $3, $4, $5, $6, $6)")
        .bind(id)
        .bind(&b.name)
        .bind(b.category_id)
        .bind(&b.description)
        .bind(&b.body)
        .bind(u.id)
        .execute(&st.db)
        .await
        .map_err(template_taken)?;
    auth::audit(&st.db, Some(u.id), "doc_template.create", Some(("doc_template", id)), json!({ "name": b.name })).await;
    Ok(Json(fetch_template(&st, id).await?))
}

pub async fn update_template(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(mut b): Json<TemplateIn>) -> ApiResult<Json<TemplateRow>> {
    u.require(Role::Admin)?;
    fetch_template(&st, id).await?;
    b.validate(&st).await?;
    sqlx::query("UPDATE doc_templates SET name = $2, category_id = $3, description = $4, body = $5, updated_by = $6, updated_at = now() WHERE id = $1")
        .bind(id)
        .bind(&b.name)
        .bind(b.category_id)
        .bind(&b.description)
        .bind(&b.body)
        .bind(u.id)
        .execute(&st.db)
        .await
        .map_err(template_taken)?;
    auth::audit(&st.db, Some(u.id), "doc_template.update", Some(("doc_template", id)), json!({ "name": b.name })).await;
    Ok(Json(fetch_template(&st, id).await?))
}

pub async fn delete_template(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    let cur = fetch_template(&st, id).await?;
    sqlx::query("DELETE FROM doc_templates WHERE id = $1").bind(id).execute(&st.db).await?;
    auth::audit(&st.db, Some(u.id), "doc_template.delete", Some(("doc_template", id)), json!({ "name": cur.name })).await;
    Ok(Json(json!({ "ok": true })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references() {
        let a = "6f1c0c1e-9a51-4c0e-b6c9-0a4de1f3a111";
        let b = "0b7e6d58-3c53-4b56-9d0b-2f2f7d1c9e10";
        let body = format!(
            "```credential\nitem: vault:{a}\n```\nSee [admin](vault:{b}) and [again](vault:{a}).\nvault:not-a-uuid vault:{} vault:",
            &b[..30]
        );
        assert_eq!(vault_refs(&body), vec![Uuid::parse_str(a).unwrap(), Uuid::parse_str(b).unwrap()]);
        assert!(vault_refs("no links, ünïcödé vault:ü").is_empty());
        assert_eq!(yaml_str("Say \"hi\"\n"), r#""Say \"hi\"\n""#);
    }
}
