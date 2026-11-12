//! Knowledge base articles. Internal ones are for technicians; public ones also show in the
//! client portal, to every client or to one.

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

#[derive(Serialize, sqlx::FromRow)]
pub struct Article {
    id: Uuid,
    title: String,
    category: String,
    public: bool,
    client_id: Option<Uuid>,
    client_name: Option<String>,
    #[sqlx(default)]
    body: Option<String>,
    excerpt: String,
    updated_by_name: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

const COLS: &str = "a.id, a.title, a.category, a.public, a.client_id, c.name AS client_name, left(a.body, 240) AS excerpt,
     u.name AS updated_by_name, a.created_at, a.updated_at
  FROM kb_articles a LEFT JOIN clients c ON c.id = a.client_id LEFT JOIN users u ON u.id = a.updated_by";

#[derive(Deserialize)]
pub struct ListQuery {
    q: Option<String>,
    category: Option<String>,
}

/// Articles for one client are visible to technicians who see that client.
pub async fn list(State(st): State<Arc<AppState>>, u: User, Query(q): Query<ListQuery>) -> ApiResult<Json<Vec<Article>>> {
    let search = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(|s| s.chars().take(200).collect::<String>());
    let category = q.category.as_deref().map(str::trim).filter(|s| !s.is_empty());
    Ok(Json(
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {COLS}
              WHERE (a.client_id IS NULL OR $1::uuid[] IS NULL OR a.client_id = ANY($1))
                AND ($2::text IS NULL OR a.search @@ websearch_to_tsquery('simple', $2) OR a.title ILIKE '%' || $2 || '%')
                AND ($3::text IS NULL OR lower(a.category) = lower($3))
              ORDER BY lower(a.category), lower(a.title) LIMIT 1000"
        )))
        .bind(u.scope())
        .bind(&search)
        .bind(category)
        .fetch_all(&st.db)
        .await?,
    ))
}

async fn fetch(st: &AppState, u: &User, id: Uuid) -> ApiResult<Article> {
    let mut a: Article = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {COLS} WHERE a.id = $1 AND (a.client_id IS NULL OR $2::uuid[] IS NULL OR a.client_id = ANY($2))"
    )))
    .bind(id)
    .bind(u.scope())
    .fetch_optional(&st.db)
    .await?
    .ok_or(ApiError::NotFound("article"))?;
    a.body = Some(sqlx::query_scalar("SELECT body FROM kb_articles WHERE id = $1").bind(id).fetch_one(&st.db).await?);
    Ok(a)
}

pub async fn get(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Article>> {
    Ok(Json(fetch(&st, &u, id).await?))
}

#[derive(Deserialize)]
pub struct ArticleIn {
    title: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    category: String,
    #[serde(default)]
    public: bool,
    client_id: Option<Uuid>,
}

impl ArticleIn {
    async fn validate(&mut self, st: &AppState, u: &User) -> ApiResult<()> {
        self.title = self.title.split_whitespace().collect::<Vec<_>>().join(" ");
        if self.title.is_empty() || self.title.chars().count() > 300 {
            return Err(ApiError::BadRequest("title must be 1-300 characters".into()));
        }
        if self.body.chars().count() > 200_000 {
            return Err(ApiError::BadRequest("articles are limited to 200,000 characters".into()));
        }
        self.category = self.category.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(100).collect();
        match self.client_id {
            Some(c) => {
                super::access::client(u, c)?;
                let ok: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM clients WHERE id = $1)").bind(c).fetch_one(&st.db).await?;
                if !ok {
                    return Err(ApiError::NotFound("client"));
                }
            }
            // An article for everyone: only for technicians who see everyone.
            None if u.scope().is_some() => return Err(ApiError::BadRequest("choose the client this article is for".into())),
            None => {}
        }
        Ok(())
    }
}

pub async fn create(State(st): State<Arc<AppState>>, u: User, Json(mut b): Json<ArticleIn>) -> ApiResult<Json<Article>> {
    u.require(Role::Technician)?;
    b.validate(&st, &u).await?;
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO kb_articles (id, title, body, category, public, client_id, created_by, updated_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $7)",
    )
    .bind(id)
    .bind(&b.title)
    .bind(&b.body)
    .bind(&b.category)
    .bind(b.public)
    .bind(b.client_id)
    .bind(u.id)
    .execute(&st.db)
    .await?;
    auth::audit(&st.db, Some(u.id), "kb.create", Some(("kb_article", id)), json!({ "title": b.title, "public": b.public })).await;
    Ok(Json(fetch(&st, &u, id).await?))
}

pub async fn update(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(mut b): Json<ArticleIn>) -> ApiResult<Json<Article>> {
    u.require(Role::Technician)?;
    fetch(&st, &u, id).await?;
    b.validate(&st, &u).await?;
    sqlx::query(
        "UPDATE kb_articles SET title = $2, body = $3, category = $4, public = $5, client_id = $6, updated_by = $7, updated_at = now() WHERE id = $1",
    )
    .bind(id)
    .bind(&b.title)
    .bind(&b.body)
    .bind(&b.category)
    .bind(b.public)
    .bind(b.client_id)
    .bind(u.id)
    .execute(&st.db)
    .await?;
    auth::audit(&st.db, Some(u.id), "kb.update", Some(("kb_article", id)), json!({ "public": b.public })).await;
    Ok(Json(fetch(&st, &u, id).await?))
}

pub async fn remove(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    fetch(&st, &u, id).await?;
    sqlx::query("DELETE FROM kb_articles WHERE id = $1").bind(id).execute(&st.db).await?;
    auth::audit(&st.db, Some(u.id), "kb.delete", Some(("kb_article", id)), json!({})).await;
    Ok(Json(json!({ "ok": true })))
}
