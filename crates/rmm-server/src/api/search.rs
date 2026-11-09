//! `/search?q=`: the command palette's lookup across agents, clients, sites, scripts and tickets.
//! Every result is limited to the clients the user can see.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};
use sqlx::AssertSqlSafe;
use uuid::Uuid;

use crate::auth::User;
use crate::error::ApiResult;
use crate::state::AppState;

const PER_KIND: i64 = 8;

#[derive(Deserialize)]
pub struct SearchQuery {
    q: String,
    /// Search one client only (the palette follows the client switcher unless told otherwise).
    client_id: Option<Uuid>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct AgentHit {
    id: Uuid,
    hostname: String,
    os_family: String,
    online: bool,
    client_name: String,
    site_name: String,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct ClientHit {
    id: Uuid,
    name: String,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct SiteHit {
    id: Uuid,
    name: String,
    client_id: Uuid,
    client_name: String,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct ScriptHit {
    id: Uuid,
    name: String,
    interpreter: String,
    client_name: Option<String>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct TicketHit {
    id: Uuid,
    number: i64,
    subject: String,
    client_name: Option<String>,
    status_name: String,
}

#[derive(Serialize, Default)]
pub struct Results {
    agents: Vec<AgentHit>,
    clients: Vec<ClientHit>,
    sites: Vec<SiteHit>,
    scripts: Vec<ScriptHit>,
    tickets: Vec<TicketHit>,
}

pub async fn search(State(st): State<Arc<AppState>>, u: User, Query(q): Query<SearchQuery>) -> ApiResult<Json<Results>> {
    let text = q.q.trim();
    if text.is_empty() {
        return Ok(Json(Results::default()));
    }
    let text: String = text.chars().take(100).collect();
    let scope = super::agents::narrow(&u, q.client_id)?;
    // Prefix matches rank first, then alphabetical.
    let agents = sqlx::query_as(AssertSqlSafe(format!(
        "SELECT a.id, a.hostname, a.os_family, a.online, c.name AS client_name, s.name AS site_name
           FROM agents a JOIN sites s ON s.id = a.site_id JOIN clients c ON c.id = s.client_id
          WHERE ($2::uuid[] IS NULL OR c.id = ANY($2)) AND {}
          ORDER BY a.hostname NOT ILIKE $1 || '%', lower(a.hostname) LIMIT {PER_KIND}",
        super::agents::agent_search(1)
    )))
    .bind(&text)
    .bind(&scope)
    .fetch_all(&st.db)
    .await?;
    let clients = sqlx::query_as(AssertSqlSafe(format!(
        "SELECT id, name FROM clients
          WHERE ($2::uuid[] IS NULL OR id = ANY($2)) AND name ILIKE '%' || $1 || '%'
          ORDER BY name NOT ILIKE $1 || '%', lower(name) LIMIT {PER_KIND}"
    )))
    .bind(&text)
    .bind(&scope)
    .fetch_all(&st.db)
    .await?;
    let sites = sqlx::query_as(AssertSqlSafe(format!(
        "SELECT s.id, s.name, s.client_id, c.name AS client_name FROM sites s JOIN clients c ON c.id = s.client_id
          WHERE ($2::uuid[] IS NULL OR c.id = ANY($2)) AND s.name ILIKE '%' || $1 || '%'
          ORDER BY s.name NOT ILIKE $1 || '%', lower(s.name) LIMIT {PER_KIND}"
    )))
    .bind(&text)
    .bind(&scope)
    .fetch_all(&st.db)
    .await?;
    // MSP-wide scripts are visible to everyone; client scripts only within scope.
    let scripts = sqlx::query_as(AssertSqlSafe(format!(
        "SELECT sc.id, sc.name, sc.interpreter, c.name AS client_name FROM scripts sc LEFT JOIN clients c ON c.id = sc.client_id
          WHERE (sc.client_id IS NULL OR $2::uuid[] IS NULL OR sc.client_id = ANY($2))
            AND (sc.name ILIKE '%' || $1 || '%' OR sc.description ILIKE '%' || $1 || '%')
          ORDER BY sc.name NOT ILIKE $1 || '%', lower(sc.name) LIMIT {PER_KIND}"
    )))
    .bind(&text)
    .bind(&scope)
    .fetch_all(&st.db)
    .await?;
    // Tickets by number (T-10423), else subject and timeline text; open ones first.
    let number: Option<i64> = text.trim_start_matches(['T', 't']).trim_start_matches('-').parse().ok();
    let tickets = sqlx::query_as(AssertSqlSafe(format!(
        "SELECT t.id, t.number, t.subject, c.name AS client_name, bs.name AS status_name
           FROM tickets t JOIN board_statuses bs ON bs.id = t.status_id LEFT JOIN clients c ON c.id = t.client_id
          WHERE ($2::uuid[] IS NULL OR t.client_id = ANY($2))
            AND (t.number = $3 OR t.subject ILIKE '%' || $1 || '%' OR t.search @@ websearch_to_tsquery('simple', $1))
          ORDER BY t.number = $3 DESC NULLS LAST, bs.category IN ('resolved', 'closed'), t.updated_at DESC LIMIT {PER_KIND}"
    )))
    .bind(&text)
    .bind(&scope)
    .bind(number)
    .fetch_all(&st.db)
    .await?;
    Ok(Json(Results { agents, clients, sites, scripts, tickets }))
}
