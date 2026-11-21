//! Tickets: list and search, detail with the timeline, the linked agents' live state and pages,
//! changes (each recorded on the timeline), replies and notes, attachments, merge, bulk edits.
//!
//! Visibility follows the ticket's client; tickets without one (triage) are visible only to
//! users who see every client. Anything else is reported as not found.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Multipart, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};
use sqlx::{AssertSqlSafe, PgConnection};
use uuid::Uuid;

use crate::auth::{self, Role, User};
use super::attachments;
use crate::error::{ApiError, ApiResult};
use crate::paging::{self, Page, PageQuery, Plan, SortKey};
use crate::state::AppState;
use crate::tickets::{self, Author, DONE, NewTicket};

#[derive(Serialize, sqlx::FromRow)]
pub struct TicketRow {
    id: Uuid,
    number: i64,
    subject: String,
    client_id: Option<Uuid>,
    client_name: Option<String>,
    site_id: Option<Uuid>,
    site_name: Option<String>,
    contact_id: Option<Uuid>,
    contact_name: Option<String>,
    contact_email: Option<String>,
    board_id: Uuid,
    board_name: String,
    status_id: Uuid,
    status_name: String,
    status_category: String,
    type_id: Option<Uuid>,
    type_name: Option<String>,
    priority: i16,
    impact: Option<i16>,
    urgency: Option<i16>,
    source: String,
    assignee_id: Option<Uuid>,
    assignee_name: Option<String>,
    requester_name: String,
    requester_email: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    first_response_at: Option<DateTime<Utc>>,
    resolved_at: Option<DateTime<Utc>>,
    closed_at: Option<DateTime<Utc>>,
    merged_into: Option<Uuid>,
    merged_into_number: Option<i64>,
    alert_policy_id: Option<Uuid>,
    alert_reopens: i32,
    agent_count: i64,
    team_id: Option<Uuid>,
    team_name: Option<String>,
    sla_policy_id: Option<Uuid>,
    sla_policy_name: Option<String>,
    respond_by: Option<DateTime<Utc>>,
    update_by: Option<DateTime<Utc>>,
    resolve_by: Option<DateTime<Utc>>,
    /// Waiting on the client (or resolved): the clock is stopped.
    sla_paused: bool,
    sla_warned: Vec<String>,
    sla_breached: Vec<String>,
    /// The next deadline still running, if any.
    sla_due: Option<DateTime<Utc>>,
    csat_rating: Option<String>,
    #[sqlx(default)]
    #[serde(skip)]
    sort_key: String,
}

const COLS: &str = "t.id, t.number, t.subject, t.client_id, c.name AS client_name, t.site_id, si.name AS site_name, t.contact_id,
     co.name AS contact_name, co.email AS contact_email, t.board_id, b.name AS board_name, t.status_id, bs.name AS status_name,
     bs.category AS status_category, t.type_id, ty.name AS type_name, t.priority, t.impact, t.urgency, t.source, t.assignee_id,
     ua.name AS assignee_name, t.requester_name, t.requester_email, t.created_at, t.updated_at, t.first_response_at,
     t.resolved_at, t.closed_at, t.merged_into, mt.number AS merged_into_number, t.alert_policy_id, t.alert_reopens,
     (SELECT count(*) FROM ticket_agents ta WHERE ta.ticket_id = t.id) AS agent_count, t.team_id, tm.name AS team_name,
     t.sla_policy_id, (SELECT name FROM sla_policies WHERE id = t.sla_policy_id) AS sla_policy_name, t.respond_by, t.update_by,
     t.resolve_by, t.sla_paused_at IS NOT NULL AS sla_paused, t.sla_warned, t.sla_breached,
     (CASE WHEN bs.category IN ('resolved', 'closed') OR t.sla_paused_at IS NOT NULL OR t.merged_into IS NOT NULL THEN NULL
           ELSE least(CASE WHEN t.first_response_at IS NULL THEN t.respond_by END,
                      CASE WHEN t.first_response_at IS NOT NULL THEN t.update_by END, t.resolve_by) END) AS sla_due,
     (SELECT rating FROM csat_surveys WHERE ticket_id = t.id) AS csat_rating";
const FROM: &str = "FROM tickets t JOIN boards b ON b.id = t.board_id JOIN board_statuses bs ON bs.id = t.status_id
     LEFT JOIN clients c ON c.id = t.client_id LEFT JOIN sites si ON si.id = t.site_id LEFT JOIN contacts co ON co.id = t.contact_id
     LEFT JOIN ticket_types ty ON ty.id = t.type_id LEFT JOIN users ua ON ua.id = t.assignee_id
     LEFT JOIN tickets mt ON mt.id = t.merged_into LEFT JOIN teams tm ON tm.id = t.team_id";
/// `$1` is the user's scope. Triage tickets (no client) only match an unscoped user.
const VISIBLE: &str = "($1::uuid[] IS NULL OR t.client_id = ANY($1))";
const CATEGORY_RANK: &str = "(array_position(ARRAY['new','open','waiting_client','waiting_vendor','resolved','closed'], bs.category))";

const SORT_KEYS: &[SortKey] = &[
    SortKey { name: "updated", expr: "t.updated_at", ty: "timestamptz" },
    SortKey { name: "created", expr: "t.created_at", ty: "timestamptz" },
    SortKey { name: "number", expr: "t.number", ty: "bigint" },
    SortKey { name: "priority", expr: "t.priority", ty: "smallint" },
    SortKey { name: "subject", expr: "lower(t.subject)", ty: "text" },
    SortKey { name: "status", expr: CATEGORY_RANK, ty: "int" },
    SortKey { name: "assignee", expr: "lower(coalesce(ua.name, '~'))", ty: "text" },
    SortKey { name: "client", expr: "lower(coalesce(c.name, ''))", ty: "text" },
    // Tickets without a running deadline sort last.
    SortKey {
        name: "due",
        expr: "coalesce(CASE WHEN bs.category IN ('resolved', 'closed') OR t.sla_paused_at IS NOT NULL THEN NULL
                   ELSE least(CASE WHEN t.first_response_at IS NULL THEN t.respond_by END,
                              CASE WHEN t.first_response_at IS NOT NULL THEN t.update_by END, t.resolve_by) END, 'infinity')",
        ty: "timestamptz",
    },
];

/// The ticket's client (None for triage), if `u` may see it.
pub async fn visible(st: &AppState, u: &User, id: Uuid) -> ApiResult<Option<Uuid>> {
    let client: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT client_id FROM tickets WHERE id = $1").bind(id).fetch_optional(&st.db).await?;
    match client {
        Some(Some(c)) if u.can_see_client(c) => Ok(Some(c)),
        Some(None) if u.scope().is_none() => Ok(None),
        _ => Err(ApiError::NotFound("ticket")),
    }
}

async fn fetch(st: &AppState, u: &User, id: Uuid) -> ApiResult<TicketRow> {
    sqlx::query_as(AssertSqlSafe(format!("SELECT {COLS} {FROM} WHERE t.id = $2 AND {VISIBLE}")))
        .bind(u.scope())
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("ticket"))
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ListQuery {
    /// open (default), mine, unassigned, waiting, triage, done, all
    view: Option<String>,
    board_id: Option<Uuid>,
    status_id: Option<Uuid>,
    /// Comma-separated 1-4.
    priority: Option<String>,
    /// A user id, or `none`.
    assignee: Option<String>,
    client_id: Option<Uuid>,
    contact_id: Option<Uuid>,
    agent_id: Option<Uuid>,
    /// Ticket number (`T-10423` or `10423`), or words from the subject, timeline and contact.
    q: Option<String>,
    /// A team id, or `none`.
    team: Option<String>,
}

pub async fn list(
    State(st): State<Arc<AppState>>,
    u: User,
    Query(q): Query<ListQuery>,
    Query(page): Query<PageQuery>,
) -> ApiResult<Json<Page<TicketRow>>> {
    let plan = Plan::new(SORT_KEYS, ("updated", true), &page, "t.id", "uuid", 15)?;
    let view = q.view.as_deref().unwrap_or("open");
    let view_sql = match view {
        "open" => "t.merged_into IS NULL AND bs.category NOT IN ('resolved', 'closed')",
        "mine" => "t.merged_into IS NULL AND bs.category NOT IN ('resolved', 'closed') AND t.assignee_id = $10",
        "unassigned" => "t.merged_into IS NULL AND bs.category NOT IN ('resolved', 'closed') AND t.assignee_id IS NULL",
        "waiting" => "bs.category IN ('waiting_client', 'waiting_vendor')",
        "triage" => "t.client_id IS NULL AND t.merged_into IS NULL AND bs.category NOT IN ('resolved', 'closed')",
        "team" => "t.merged_into IS NULL AND bs.category NOT IN ('resolved', 'closed')
                   AND t.team_id IN (SELECT team_id FROM team_members WHERE user_id = $10)",
        "breached" => "t.merged_into IS NULL AND bs.category NOT IN ('resolved', 'closed') AND cardinality(t.sla_breached) > 0",
        "due_soon" => "t.merged_into IS NULL AND bs.category NOT IN ('resolved', 'closed', 'waiting_client') AND t.sla_paused_at IS NULL
                       AND least(CASE WHEN t.first_response_at IS NULL THEN t.respond_by END,
                                 CASE WHEN t.first_response_at IS NOT NULL THEN t.update_by END, t.resolve_by) < now() + interval '4 hours'",
        "done" => "bs.category IN ('resolved', 'closed')",
        "all" => "true",
        other => return Err(ApiError::BadRequest(format!("unknown view {other}"))),
    };
    let priorities: Option<Vec<i16>> = q
        .priority
        .as_deref()
        .filter(|p| !p.is_empty())
        .map(|p| p.split(',').map(|x| x.trim().parse::<i16>().map_err(|_| ApiError::BadRequest("priority must be 1-4".into()))).collect())
        .transpose()?;
    let (assignee, unassigned) = match q.assignee.as_deref() {
        None | Some("") => (None, false),
        Some("none") => (None, true),
        Some("me") => (Some(u.id), false),
        Some(id) => (Some(id.parse::<Uuid>().map_err(|_| ApiError::BadRequest("assignee must be a user id, me or none".into()))?), false),
    };
    let search = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(|s| s.chars().take(200).collect::<String>());
    let number: Option<i64> = search.as_deref().and_then(|s| s.trim_start_matches(['T', 't']).trim_start_matches('-').parse().ok());
    let (team, no_team) = match q.team.as_deref() {
        None | Some("") => (None, false),
        Some("none") => (None, true),
        Some(id) => (Some(id.parse::<Uuid>().map_err(|_| ApiError::BadRequest("team must be a team id or none".into()))?), false),
    };
    let filters = format!(
        "{FROM}
          WHERE {VISIBLE} AND {view_sql}
            AND ($2::uuid IS NULL OR t.board_id = $2)
            AND ($3::uuid IS NULL OR t.status_id = $3)
            AND ($4::smallint[] IS NULL OR t.priority = ANY($4))
            AND ($5::uuid IS NULL OR t.assignee_id = $5) AND (NOT $6 OR t.assignee_id IS NULL)
            AND ($7::uuid IS NULL OR t.client_id = $7)
            AND ($8::uuid IS NULL OR t.contact_id = $8)
            AND ($9::uuid IS NULL OR EXISTS (SELECT 1 FROM ticket_agents ta WHERE ta.ticket_id = t.id AND ta.agent_id = $9))
            AND ($11::text IS NULL OR t.number = $12 OR t.search @@ websearch_to_tsquery('simple', $11)
                 OR t.subject ILIKE '%' || $11 || '%')
            AND ($13::uuid IS NULL OR t.team_id = $13) AND (NOT $14 OR t.team_id IS NULL)"
    );
    macro_rules! bind_filters {
        ($query:expr) => {
            $query
                .bind(u.scope())
                .bind(q.board_id)
                .bind(q.status_id)
                .bind(&priorities)
                .bind(assignee)
                .bind(unassigned)
                .bind(q.client_id)
                .bind(q.contact_id)
                .bind(q.agent_id)
                .bind(u.id)
                .bind(&search)
                .bind(number)
                .bind(team)
                .bind(no_team)
        };
    }
    let sql = format!("SELECT {COLS}, {} {filters} {} {} {}", plan.key_select, plan.keyset, plan.order, plan.limit_sql());
    let mut rows = bind_filters!(sqlx::query_as::<_, TicketRow>(AssertSqlSafe(sql)));
    if let Some((k, id)) = &plan.cursor {
        rows = rows.bind(k).bind(id);
    }
    let rows = rows.fetch_all(&st.db).await?;
    let total: i64 = bind_filters!(sqlx::query_scalar(AssertSqlSafe(paging::count_sql(&filters)))).fetch_one(&st.db).await?;
    Ok(Json(plan.finish(rows, |r| (r.sort_key.clone(), r.id.to_string()), total)))
}

#[derive(Deserialize)]
pub struct SummaryQuery {
    client_id: Option<Uuid>,
}

/// Open ticket counts for the sidebar and the views' tabs.
pub async fn summary(State(st): State<Arc<AppState>>, u: User, Query(q): Query<SummaryQuery>) -> ApiResult<Json<Value>> {
    let scope = super::agents::narrow(&u, q.client_id)?;
    let (open, mine, unassigned, triage, waiting, team, breached): (i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT count(*),
                count(*) FILTER (WHERE t.assignee_id = $2),
                count(*) FILTER (WHERE t.assignee_id IS NULL),
                count(*) FILTER (WHERE t.client_id IS NULL),
                count(*) FILTER (WHERE bs.category IN ('waiting_client', 'waiting_vendor')),
                count(*) FILTER (WHERE t.team_id IN (SELECT team_id FROM team_members WHERE user_id = $2)),
                count(*) FILTER (WHERE cardinality(t.sla_breached) > 0)
           FROM tickets t JOIN board_statuses bs ON bs.id = t.status_id
          WHERE ($1::uuid[] IS NULL OR t.client_id = ANY($1)) AND t.merged_into IS NULL
            AND bs.category NOT IN ('resolved', 'closed')
            AND ($3::uuid IS NULL OR t.client_id = $3)",
    )
    .bind(&scope)
    .bind(u.id)
    .bind(q.client_id)
    .fetch_one(&st.db)
    .await?;
    Ok(Json(json!({ "open": open, "mine": mine, "unassigned": unassigned, "triage": triage, "waiting": waiting, "team": team, "breached": breached })))
}

// ---------------------------------------------------------------------------
// Detail
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct EventRow {
    id: i64,
    kind: String,
    public: bool,
    author_id: Option<Uuid>,
    author_contact_id: Option<Uuid>,
    /// user / contact / system
    author_kind: String,
    author_name: String,
    body: String,
    data: Value,
    created_at: DateTime<Utc>,
    /// For replies: whether the email went out (pending / sent / failed), and why not.
    email_status: Option<String>,
    email_error: Option<String>,
    email_to: Option<Vec<String>>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct AttachmentRow {
    id: Uuid,
    event_id: Option<i64>,
    name: String,
    content_type: String,
    size: i64,
    uploaded_by_name: Option<String>,
    created_at: DateTime<Utc>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct TicketAgent {
    #[sqlx(flatten)]
    #[serde(flatten)]
    agent: super::agents::AgentSummary,
    capabilities: Vec<String>,
    reboot_pending: bool,
    missing_patches: i64,
    /// The worst few open alerts.
    alerts: Value,
}

/// A documentation page linked to the ticket.
#[derive(Serialize, sqlx::FromRow)]
pub struct TicketDoc {
    id: Uuid,
    title: String,
    /// The category's name; empty when there is none.
    category: String,
    updated_at: DateTime<Utc>,
    updated_by_name: Option<String>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct StatusRow {
    id: Uuid,
    name: String,
    category: String,
    position: i32,
}

#[derive(Serialize)]
pub struct TicketDetail {
    #[serde(flatten)]
    ticket: TicketRow,
    events: Vec<EventRow>,
    attachments: Vec<AttachmentRow>,
    agents: Vec<TicketAgent>,
    docs: Vec<TicketDoc>,
    /// The statuses of the ticket's board, for the status picker.
    statuses: Vec<StatusRow>,
    /// Where a public reply would be emailed, if anywhere.
    reply_to: Option<String>,
    /// The satisfaction survey, once sent.
    csat: Option<Value>,
}

pub async fn get(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<TicketDetail>> {
    let ticket = fetch(&st, &u, id).await?;
    let events = sqlx::query_as(
        "SELECT e.id, e.kind, e.public, e.author_id, e.author_contact_id,
                CASE WHEN e.author_id IS NOT NULL THEN 'user' WHEN e.author_contact_id IS NOT NULL THEN 'contact' ELSE 'system' END AS author_kind,
                coalesce(u.name, co.name, nullif(e.author_name, ''), 'System') AS author_name, e.body, e.data, e.created_at,
                m.status AS email_status, m.last_error AS email_error, m.to_addrs AS email_to
           FROM ticket_events e LEFT JOIN users u ON u.id = e.author_id LEFT JOIN contacts co ON co.id = e.author_contact_id
           LEFT JOIN LATERAL (SELECT status, last_error, to_addrs FROM email_messages
                               WHERE event_id = e.id AND direction = 'out' ORDER BY created_at DESC LIMIT 1) m ON true
          WHERE e.ticket_id = $1 ORDER BY e.id",
    )
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    let attachments = sqlx::query_as(
        "SELECT a.id, a.event_id, a.name, a.content_type, a.size, u.name AS uploaded_by_name, a.created_at
           FROM ticket_attachments a LEFT JOIN users u ON u.id = a.uploaded_by WHERE a.ticket_id = $1 ORDER BY a.created_at, a.name",
    )
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    let agents = sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {}, a.capabilities, a.reboot_pending,
                (SELECT count(*) FROM patches p WHERE p.agent_id = a.id AND p.state IN ('missing', 'failed') AND p.approval <> 'declined') AS missing_patches,
                coalesce((SELECT jsonb_agg(x) FROM (
                    SELECT al.id, al.title, al.severity, al.opened_at FROM alerts al WHERE al.agent_id = a.id AND al.resolved_at IS NULL
                     ORDER BY CASE al.severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END, al.opened_at DESC LIMIT 3) x), '[]') AS alerts
           FROM ticket_agents ta JOIN agents a ON a.id = ta.agent_id JOIN sites s ON s.id = a.site_id JOIN clients c ON c.id = s.client_id
          WHERE ta.ticket_id = $1 AND ($2::uuid[] IS NULL OR c.id = ANY($2)) ORDER BY lower(a.hostname)",
        super::agents::SUMMARY_COLS
    )))
    .bind(id)
    .bind(u.scope())
    .fetch_all(&st.db)
    .await?;
    let docs = sqlx::query_as(
        "SELECT d.id, d.title, coalesce(dc.name, '') AS category, d.updated_at, u.name AS updated_by_name
           FROM ticket_docs td JOIN client_docs d ON d.id = td.doc_id
           LEFT JOIN doc_categories dc ON dc.id = d.category_id LEFT JOIN users u ON u.id = d.updated_by
          WHERE td.ticket_id = $1 AND ($2::uuid[] IS NULL OR d.client_id = ANY($2)) ORDER BY lower(d.title), d.id",
    )
    .bind(id)
    .bind(u.scope())
    .fetch_all(&st.db)
    .await?;
    let statuses =
        sqlx::query_as("SELECT id, name, category, position FROM board_statuses WHERE board_id = $1 ORDER BY position, name")
            .bind(ticket.board_id)
            .fetch_all(&st.db)
            .await?;
    let reply_to = ticket
        .contact_email
        .clone()
        .filter(|e| !e.is_empty())
        .or_else(|| Some(ticket.requester_email.clone()).filter(|e| !e.is_empty()));
    let csat: Option<Value> = sqlx::query_scalar(
        "SELECT jsonb_build_object('email', email, 'sent_at', sent_at, 'rating', rating, 'comment', comment, 'answered_at', answered_at)
           FROM csat_surveys WHERE ticket_id = $1",
    )
    .bind(id)
    .fetch_optional(&st.db)
    .await?;
    Ok(Json(TicketDetail { ticket, events, attachments, agents, docs, statuses, reply_to, csat }))
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct NewTicketIn {
    subject: String,
    #[serde(default)]
    description: String,
    client_id: Option<Uuid>,
    site_id: Option<Uuid>,
    contact_id: Option<Uuid>,
    board_id: Option<Uuid>,
    type_id: Option<Uuid>,
    priority: Option<i16>,
    impact: Option<i16>,
    urgency: Option<i16>,
    assignee_id: Option<Uuid>,
    team_id: Option<Uuid>,
    #[serde(default)]
    agent_ids: Vec<Uuid>,
}

fn clean_subject(s: &str) -> ApiResult<String> {
    let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if s.is_empty() || s.chars().count() > 300 {
        return Err(ApiError::BadRequest("subject must be 1-300 characters".into()));
    }
    Ok(s)
}

fn check_text(body: &str, max: usize) -> ApiResult<()> {
    if body.chars().count() > max {
        return Err(ApiError::BadRequest(format!("text is limited to {max} characters")));
    }
    Ok(())
}

fn check_level(v: Option<i16>, what: &str, max: i16) -> ApiResult<()> {
    if v.is_some_and(|v| !(1..=max).contains(&v)) {
        return Err(ApiError::BadRequest(format!("{what} must be 1-{max}")));
    }
    Ok(())
}

/// The site and contact belong to the client.
async fn check_client_links(db: &mut PgConnection, client: Option<Uuid>, site: Option<Uuid>, contact: Option<Uuid>) -> ApiResult<()> {
    if let Some(s) = site {
        let c: Option<Uuid> = sqlx::query_scalar("SELECT client_id FROM sites WHERE id = $1").bind(s).fetch_optional(&mut *db).await?;
        if c.is_none() || c != client {
            return Err(ApiError::BadRequest("the site must belong to the ticket's client".into()));
        }
    }
    if let Some(p) = contact {
        let c: Option<Uuid> = sqlx::query_scalar("SELECT client_id FROM contacts WHERE id = $1").bind(p).fetch_optional(&mut *db).await?;
        if c.is_none() || c != client {
            return Err(ApiError::BadRequest("the contact must belong to the ticket's client".into()));
        }
    }
    Ok(())
}

/// The assignee is an active technician or admin who can see the client.
async fn check_assignee(db: &mut PgConnection, user: Uuid, client: Option<Uuid>) -> ApiResult<()> {
    let ok: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM users u WHERE u.id = $1 AND NOT u.disabled AND u.role IN ('technician', 'admin')
                           AND (u.role = 'admin' OR u.all_clients OR ($2::uuid IS NOT NULL AND EXISTS
                                (SELECT 1 FROM user_clients uc WHERE uc.user_id = u.id AND uc.client_id = $2))))",
    )
    .bind(user)
    .bind(client)
    .fetch_one(&mut *db)
    .await?;
    if !ok {
        return Err(ApiError::BadRequest("assign to an active technician who can see this client".into()));
    }
    Ok(())
}

async fn default_board(db: &mut PgConnection) -> ApiResult<Uuid> {
    sqlx::query_scalar("SELECT id FROM boards ORDER BY position, name LIMIT 1")
        .fetch_optional(&mut *db)
        .await?
        .ok_or_else(|| ApiError::BadRequest("create a board first (Company settings → Service desk)".into()))
}

pub async fn create(State(st): State<Arc<AppState>>, u: User, Json(b): Json<NewTicketIn>) -> ApiResult<Json<TicketRow>> {
    u.require(Role::Technician)?;
    let subject = clean_subject(&b.subject)?;
    check_text(&b.description, 100_000)?;
    check_level(b.priority, "priority", 4)?;
    check_level(b.impact, "impact", 3)?;
    check_level(b.urgency, "urgency", 3)?;
    match b.client_id {
        Some(c) => super::access::client(&u, c)?,
        // Triage tickets are for people who see every client.
        None if u.scope().is_some() => return Err(ApiError::BadRequest("choose a client".into())),
        None => {}
    }
    if b.agent_ids.len() > 50 {
        return Err(ApiError::BadRequest("link at most 50 agents".into()));
    }
    let mut tx = st.db.begin().await?;
    if let Some(c) = b.client_id {
        let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM clients WHERE id = $1)").bind(c).fetch_one(&mut *tx).await?;
        if !exists {
            return Err(ApiError::NotFound("client"));
        }
    }
    check_client_links(&mut tx, b.client_id, b.site_id, b.contact_id).await?;
    if let Some(a) = b.assignee_id {
        check_assignee(&mut tx, a, b.client_id).await?;
    }
    for agent in &b.agent_ids {
        let c = super::access::agent(&st, &u, *agent).await?;
        if Some(c) != b.client_id {
            return Err(ApiError::BadRequest("linked agents must belong to the ticket's client".into()));
        }
    }
    let board = match b.board_id {
        Some(id) => {
            let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM boards WHERE id = $1)").bind(id).fetch_one(&mut *tx).await?;
            if !exists {
                return Err(ApiError::NotFound("board"));
            }
            id
        }
        None => default_board(&mut tx).await?,
    };
    let priority = match (b.priority, b.impact, b.urgency) {
        (Some(p), _, _) => p,
        (None, Some(i), Some(ur)) => tickets::matrix_priority(i, ur),
        _ => 3,
    };
    let created = tickets::create(
        &mut tx,
        NewTicket {
            client_id: b.client_id,
            site_id: b.site_id,
            contact_id: b.contact_id,
            board_id: board,
            type_id: b.type_id,
            priority,
            impact: b.impact,
            urgency: b.urgency,
            subject,
            body: b.description.trim().to_string(),
            body_public: true,
            source: "dashboard",
            assignee_id: b.assignee_id,
            team_id: b.team_id,
            created_by: Some(u.id),
            author: Author::user(u.id),
            agent_ids: b.agent_ids.clone(),
            ..Default::default()
        },
    )
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(d) if d.is_foreign_key_violation() => ApiError::BadRequest("unknown ticket type or team".into()),
        sqlx::Error::RowNotFound => ApiError::BadRequest("the board has no status in the New category".into()),
        e => e.into(),
    })?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "ticket.create", Some(("ticket", created.id)), json!({ "number": created.number })).await;
    if let Some(a) = b.assignee_id.filter(|a| *a != u.id)
        && let Err(e) = crate::email::queue_assigned(&st, created.id, a, &u.name).await
    {
        tracing::warn!("queueing assignment email: {e:#}");
    }
    tickets::notify_created(&st, created.id).await;
    tickets::announce(&st, created.id).await;
    Ok(Json(fetch(&st, &u, created.id).await?))
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

/// Distinguishes "set to null" (`Some(None)`) from "not given" (`None`).
fn some<'de, T: Deserialize<'de>, D: Deserializer<'de>>(d: D) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

#[derive(Deserialize, Default)]
pub struct Patch {
    subject: Option<String>,
    board_id: Option<Uuid>,
    status_id: Option<Uuid>,
    priority: Option<i16>,
    #[serde(default, deserialize_with = "some")]
    impact: Option<Option<i16>>,
    #[serde(default, deserialize_with = "some")]
    urgency: Option<Option<i16>>,
    #[serde(default, deserialize_with = "some")]
    type_id: Option<Option<Uuid>>,
    #[serde(default, deserialize_with = "some")]
    assignee_id: Option<Option<Uuid>>,
    #[serde(default, deserialize_with = "some")]
    client_id: Option<Option<Uuid>>,
    #[serde(default, deserialize_with = "some")]
    site_id: Option<Option<Uuid>>,
    #[serde(default, deserialize_with = "some")]
    contact_id: Option<Option<Uuid>>,
    #[serde(default, deserialize_with = "some")]
    team_id: Option<Option<Uuid>>,
}

async fn name_of(db: &mut PgConnection, table: &str, id: Option<Uuid>) -> sqlx::Result<Value> {
    let Some(id) = id else { return Ok(Value::Null) };
    let name: Option<String> = sqlx::query_scalar(AssertSqlSafe(format!("SELECT name FROM {table} WHERE id = $1")))
        .bind(id)
        .fetch_optional(&mut *db)
        .await?;
    Ok(name.map(Value::String).unwrap_or(Value::Null))
}

async fn change(db: &mut PgConnection, id: Uuid, author: &Author, field: &str, from: Value, to: Value) -> sqlx::Result<()> {
    tickets::add_event(db, id, "change", false, author, "", json!({ "field": field, "from": from, "to": to })).await.map(drop)
}

/// Applies `p` to the ticket as `u`, recording each change. Returns the new assignee when it
/// changed to someone else (to notify them).
async fn apply(_st: &AppState, u: &User, db: &mut PgConnection, cur: &TicketRow, p: &Patch) -> ApiResult<Option<Uuid>> {
    let author = Author::user(u.id);
    let id = cur.id;
    if let Some(s) = &p.subject {
        let s = clean_subject(s)?;
        if s != cur.subject {
            sqlx::query("UPDATE tickets SET subject = $2 WHERE id = $1").bind(id).bind(&s).execute(&mut *db).await?;
            change(db, id, &author, "subject", json!(cur.subject), json!(s)).await?;
        }
    }
    // Client first: the site, contact, assignee, agents and pages are checked against the new one.
    let mut client = cur.client_id;
    if let Some(new) = p.client_id
        && new != cur.client_id
    {
        match new {
            Some(c) => {
                super::access::client(u, c)?;
                let exists: bool =
                    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM clients WHERE id = $1)").bind(c).fetch_one(&mut *db).await?;
                if !exists {
                    return Err(ApiError::NotFound("client"));
                }
            }
            None if u.scope().is_some() => return Err(ApiError::BadRequest("choose a client".into())),
            None => {}
        }
        client = new;
        // What belonged to the old client no longer applies.
        sqlx::query(
            "UPDATE tickets SET client_id = $2,
                    site_id = CASE WHEN site_id IN (SELECT id FROM sites WHERE client_id = $2) THEN site_id END,
                    contact_id = CASE WHEN contact_id IN (SELECT id FROM contacts WHERE client_id = $2) THEN contact_id END
              WHERE id = $1",
        )
        .bind(id)
        .bind(client)
        .execute(&mut *db)
        .await?;
        sqlx::query(
            "DELETE FROM ticket_agents ta USING agents a JOIN sites s ON s.id = a.site_id
              WHERE ta.ticket_id = $1 AND a.id = ta.agent_id AND s.client_id IS DISTINCT FROM $2",
        )
        .bind(id)
        .bind(client)
        .execute(&mut *db)
        .await?;
        sqlx::query(
            "DELETE FROM ticket_docs td USING client_docs d
              WHERE td.ticket_id = $1 AND d.id = td.doc_id AND d.client_id IS DISTINCT FROM $2",
        )
        .bind(id)
        .bind(client)
        .execute(&mut *db)
        .await?;
        let (from, to) = (name_of(db, "clients", cur.client_id).await?, name_of(db, "clients", client).await?);
        change(db, id, &author, "client", from, to).await?;
    }
    let (site_now, contact_now): (Option<Uuid>, Option<Uuid>) =
        sqlx::query_as("SELECT site_id, contact_id FROM tickets WHERE id = $1").bind(id).fetch_one(&mut *db).await?;
    if let Some(s) = p.site_id
        && s != site_now
    {
        check_client_links(db, client, s, None).await?;
        sqlx::query("UPDATE tickets SET site_id = $2 WHERE id = $1").bind(id).bind(s).execute(&mut *db).await?;
        let (from, to) = (name_of(db, "sites", site_now).await?, name_of(db, "sites", s).await?);
        change(db, id, &author, "site", from, to).await?;
    }
    if let Some(c) = p.contact_id
        && c != contact_now
    {
        check_client_links(db, client, None, c).await?;
        sqlx::query("UPDATE tickets SET contact_id = $2 WHERE id = $1").bind(id).bind(c).execute(&mut *db).await?;
        let (from, to) = (name_of(db, "contacts", contact_now).await?, name_of(db, "contacts", c).await?);
        change(db, id, &author, "contact", from, to).await?;
    }
    // Board: keep the status's category on the new board.
    if let Some(bid) = p.board_id
        && bid != cur.board_id
    {
        let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM boards WHERE id = $1)").bind(bid).fetch_one(&mut *db).await?;
        if !exists {
            return Err(ApiError::NotFound("board"));
        }
        let status = match p.status_id {
            Some(s) => s,
            None => tickets::status_of(db, bid, &cur.status_category)
                .await?
                .or(tickets::status_of(db, bid, "open").await?)
                .ok_or_else(|| ApiError::BadRequest("that board has no statuses".into()))?,
        };
        let on_board: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM board_statuses WHERE id = $1 AND board_id = $2)")
            .bind(status)
            .bind(bid)
            .fetch_one(&mut *db)
            .await?;
        if !on_board {
            return Err(ApiError::BadRequest("that status isn't on the board".into()));
        }
        sqlx::query("UPDATE tickets SET board_id = $2 WHERE id = $1").bind(id).bind(bid).execute(&mut *db).await?;
        let (from, to) = (name_of(db, "boards", Some(cur.board_id)).await?, name_of(db, "boards", Some(bid)).await?);
        change(db, id, &author, "board", from, to).await?;
        tickets::set_status(db, id, status, &author).await?;
    } else if let Some(s) = p.status_id {
        let on_board: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM board_statuses WHERE id = $1 AND board_id = $2)")
            .bind(s)
            .bind(cur.board_id)
            .fetch_one(&mut *db)
            .await?;
        if !on_board {
            return Err(ApiError::BadRequest("that status isn't on the ticket's board".into()));
        }
        tickets::set_status(db, id, s, &author).await?;
    }
    // Priority: explicit, else from impact × urgency when both are known.
    check_level(p.priority, "priority", 4)?;
    check_level(p.impact.flatten(), "impact", 3)?;
    check_level(p.urgency.flatten(), "urgency", 3)?;
    let impact = p.impact.unwrap_or(cur.impact);
    let urgency = p.urgency.unwrap_or(cur.urgency);
    if impact != cur.impact || urgency != cur.urgency {
        sqlx::query("UPDATE tickets SET impact = $2, urgency = $3 WHERE id = $1").bind(id).bind(impact).bind(urgency).execute(&mut *db).await?;
    }
    let priority = p.priority.or_else(|| match (impact, urgency) {
        (Some(i), Some(ur)) if impact != cur.impact || urgency != cur.urgency => Some(tickets::matrix_priority(i, ur)),
        _ => None,
    });
    if let Some(pr) = priority.filter(|pr| *pr != cur.priority) {
        sqlx::query("UPDATE tickets SET priority = $2 WHERE id = $1").bind(id).bind(pr).execute(&mut *db).await?;
        change(db, id, &author, "priority", json!(cur.priority), json!(pr)).await?;
    }
    if let Some(t) = p.type_id
        && t != cur.type_id
    {
        if let Some(tid) = t {
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM ticket_types WHERE id = $1)").bind(tid).fetch_one(&mut *db).await?;
            if !exists {
                return Err(ApiError::NotFound("ticket type"));
            }
        }
        sqlx::query("UPDATE tickets SET type_id = $2 WHERE id = $1").bind(id).bind(t).execute(&mut *db).await?;
        let (from, to) = (name_of(db, "ticket_types", cur.type_id).await?, name_of(db, "ticket_types", t).await?);
        change(db, id, &author, "type", from, to).await?;
    }
    let mut notify = None;
    let assignee_now: Option<Uuid> = sqlx::query_scalar("SELECT assignee_id FROM tickets WHERE id = $1").bind(id).fetch_one(&mut *db).await?;
    if let Some(a) = p.assignee_id
        && a != assignee_now
    {
        if let Some(uid) = a {
            check_assignee(db, uid, client).await?;
        }
        sqlx::query("UPDATE tickets SET assignee_id = $2 WHERE id = $1").bind(id).bind(a).execute(&mut *db).await?;
        let (from, to) = (name_of(db, "users", assignee_now).await?, name_of(db, "users", a).await?);
        change(db, id, &author, "assignee", from, to).await?;
        notify = a.filter(|x| *x != u.id);
    } else if client != cur.client_id
        && let Some(a) = assignee_now
        && check_assignee(db, a, client).await.is_err()
    {
        // The assignee can't see the new client.
        sqlx::query("UPDATE tickets SET assignee_id = NULL WHERE id = $1").bind(id).execute(&mut *db).await?;
        let from = name_of(db, "users", Some(a)).await?;
        change(db, id, &author, "assignee", from, Value::Null).await?;
    }
    if let Some(t) = p.team_id
        && t != cur.team_id
    {
        if let Some(tid) = t {
            let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM teams WHERE id = $1)").bind(tid).fetch_one(&mut *db).await?;
            if !exists {
                return Err(ApiError::NotFound("team"));
            }
        }
        sqlx::query("UPDATE tickets SET team_id = $2 WHERE id = $1").bind(id).bind(t).execute(&mut *db).await?;
        let (from, to) = (name_of(db, "teams", cur.team_id).await?, name_of(db, "teams", t).await?);
        change(db, id, &author, "team", from, to).await?;
    }
    // Priority or client may have changed the SLA.
    crate::sla::refresh(db, id).await?;
    Ok(notify)
}

pub async fn update(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(p): Json<Patch>) -> ApiResult<Json<TicketRow>> {
    u.require(Role::Technician)?;
    let cur = fetch(&st, &u, id).await?;
    let mut tx = st.db.begin().await?;
    sqlx::query("SELECT 1 FROM tickets WHERE id = $1 FOR UPDATE").bind(id).execute(&mut *tx).await?;
    let notify = apply(&st, &u, &mut tx, &cur, &p).await?;
    tx.commit().await?;
    after_change(&st, &u, id, notify).await;
    Ok(Json(fetch(&st, &u, id).await?))
}

async fn after_change(st: &AppState, u: &User, id: Uuid, notify: Option<Uuid>) {
    if let Some(a) = notify
        && let Err(e) = crate::email::queue_assigned(st, id, a, &u.name).await
    {
        tracing::warn!("queueing assignment email: {e:#}");
    }
    tickets::announce(st, id).await;
}

#[derive(Deserialize)]
pub struct Bulk {
    ids: Vec<Uuid>,
    /// Move each ticket to the first status of this category on its board.
    status_category: Option<String>,
    priority: Option<i16>,
    #[serde(default, deserialize_with = "some")]
    assignee_id: Option<Option<Uuid>>,
    #[serde(default, deserialize_with = "some")]
    team_id: Option<Option<Uuid>>,
}

pub async fn bulk(State(st): State<Arc<AppState>>, u: User, Json(b): Json<Bulk>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    if b.ids.is_empty() || b.ids.len() > 500 {
        return Err(ApiError::BadRequest("pick 1-500 tickets".into()));
    }
    if let Some(c) = &b.status_category
        && !tickets::CATEGORIES.contains(&c.as_str())
    {
        return Err(ApiError::BadRequest(format!("unknown status category {c}")));
    }
    let mut changed = 0;
    let mut notify = vec![];
    // All or nothing: one invalid assignee rejects the whole batch.
    let mut tx = st.db.begin().await?;
    for id in &b.ids {
        let cur = fetch(&st, &u, *id).await?;
        let status_id = match &b.status_category {
            Some(c) => tickets::status_of(&mut tx, cur.board_id, c).await?,
            None => None,
        };
        let p = Patch { status_id, priority: b.priority, assignee_id: b.assignee_id, team_id: b.team_id, ..Default::default() };
        if let Some(a) = apply(&st, &u, &mut tx, &cur, &p).await? {
            notify.push((*id, a));
        }
        changed += 1;
    }
    tx.commit().await?;
    for id in &b.ids {
        let n = notify.iter().find(|(t, _)| t == id).map(|(_, a)| *a);
        after_change(&st, &u, *id, n).await;
    }
    auth::audit(&st.db, Some(u.id), "ticket.bulk_update", None, json!({ "tickets": changed })).await;
    Ok(Json(json!({ "changed": changed })))
}

// ---------------------------------------------------------------------------
// Replies, notes, attachments
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct NewEvent {
    /// `reply` (public: emailed to the contact) or `note` (internal).
    kind: String,
    body: String,
    #[serde(default)]
    attachment_ids: Vec<Uuid>,
    /// Change the status in the same step ("reply and set to Waiting on client").
    status_id: Option<Uuid>,
}

pub async fn add_event(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<NewEvent>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    let cur = fetch(&st, &u, id).await?;
    let public = match b.kind.as_str() {
        "reply" => true,
        "note" => false,
        other => return Err(ApiError::BadRequest(format!("kind must be reply or note, not {other}"))),
    };
    let body = b.body.trim();
    if body.is_empty() && b.attachment_ids.is_empty() {
        return Err(ApiError::BadRequest("write something first".into()));
    }
    check_text(body, 100_000)?;
    if b.attachment_ids.len() > 20 {
        return Err(ApiError::BadRequest("at most 20 attachments".into()));
    }
    let mut tx = st.db.begin().await?;
    let event_id = tickets::add_event(&mut tx, id, &b.kind, public, &Author::user(u.id), body, json!({})).await?;
    if !b.attachment_ids.is_empty() {
        let n = sqlx::query("UPDATE ticket_attachments SET event_id = $3 WHERE ticket_id = $1 AND id = ANY($2) AND event_id IS NULL")
            .bind(id)
            .bind(&b.attachment_ids)
            .bind(event_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if n as usize != b.attachment_ids.len() {
            return Err(ApiError::BadRequest("unknown or already used attachment".into()));
        }
    }
    if public {
        // First response (and the update clock) count only a technician's public reply.
        crate::sla::replied(&mut tx, id).await?;
    }
    if let Some(s) = b.status_id {
        let p = Patch { status_id: Some(s), ..Default::default() };
        apply(&st, &u, &mut tx, &cur, &p).await?;
    }
    tx.commit().await?;
    let mut emailed = None;
    if public {
        match crate::email::queue_reply(&st, id, event_id, body, &u.name).await {
            Ok(m) => emailed = m,
            Err(e) => tracing::warn!(ticket = %id, "queueing reply email: {e:#}"),
        }
    }
    tickets::announce(&st, id).await;
    Ok(Json(json!({ "id": event_id, "emailed": emailed.is_some() })))
}

/// Files per upload request.
pub(crate) const MAX_UPLOAD_FILES: usize = 20;

/// Uploads files to the ticket (multipart, field `file`, one or more, each up to
/// RMM_ATTACHMENT_MAX_MB). Attach them to a reply or note by passing their ids to
/// `POST /tickets/{id}/events`.
pub async fn upload(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, mut form: Multipart) -> ApiResult<Json<Vec<AttachmentRow>>> {
    u.require(Role::Technician)?;
    visible(&st, &u, id).await?;
    let mut saved: Vec<attachments::Saved> = vec![];
    let res = async {
        while let Some(field) = form.next_field().await.map_err(|e| attachments::multipart_error(&st, e))? {
            if field.name() != Some("file") {
                continue;
            }
            if saved.len() >= MAX_UPLOAD_FILES {
                return Err(ApiError::BadRequest(format!("at most {MAX_UPLOAD_FILES} files at once")));
            }
            let name = super::tickets::clean_filename(field.file_name().unwrap_or("attachment"));
            match attachments::save(&st, field).await? {
                Some(f) => saved.push(f),
                None => return Err(ApiError::BadRequest(format!("{name} is empty"))),
            }
        }
        if saved.is_empty() {
            return Err(ApiError::BadRequest("no file in the upload".into()));
        }
        let mut tx = st.db.begin().await?;
        for f in &saved {
            sqlx::query(
                "INSERT INTO ticket_attachments (id, ticket_id, name, content_type, size, sha256, storage_key, uploaded_by)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            )
            .bind(f.id)
            .bind(id)
            .bind(&f.name)
            .bind(&f.content_type)
            .bind(f.size)
            .bind(&f.sha256)
            .bind(&f.key)
            .bind(u.id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }
    .await;
    if let Err(e) = res {
        attachments::discard(&st, &saved).await;
        return Err(e);
    }
    Ok(Json(
        saved
            .into_iter()
            .map(|f| AttachmentRow {
                id: f.id,
                event_id: None,
                name: f.name,
                content_type: f.content_type,
                size: f.size,
                uploaded_by_name: Some(u.name.clone()),
                created_at: Utc::now(),
            })
            .collect(),
    ))
}

pub(crate) fn clean_filename(name: &str) -> String {
    let n: String = name.chars().filter(|c| !c.is_control() && !matches!(c, '/' | '\\')).take(200).collect();
    let n = n.trim().trim_start_matches('.').to_string();
    if n.is_empty() { "attachment".into() } else { n }
}

#[derive(Deserialize)]
pub struct DownloadQuery {
    /// `1` or `true`: show images in the page instead of downloading.
    inline: Option<String>,
}

pub async fn download(
    State(st): State<Arc<AppState>>,
    u: User,
    Path((id, aid)): Path<(Uuid, Uuid)>,
    Query(q): Query<DownloadQuery>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    visible(&st, &u, id).await?;
    let (name, ct, key, size): (String, String, String, i64) =
        sqlx::query_as("SELECT name, content_type, storage_key, size FROM ticket_attachments WHERE id = $1 AND ticket_id = $2")
            .bind(aid)
            .bind(id)
            .fetch_optional(&st.db)
            .await?
            .ok_or(ApiError::NotFound("attachment"))?;
    attachments::serve(&st, &headers, &key, size, &name, &ct, matches!(q.inline.as_deref(), Some("1" | "true"))).await
}

// ---------------------------------------------------------------------------
// Agents, documentation pages, merge
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct AgentLink {
    agent_id: Uuid,
}

pub async fn link_agent(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<AgentLink>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    let client = visible(&st, &u, id).await?;
    let agent_client = super::access::agent(&st, &u, b.agent_id).await?;
    if client != Some(agent_client) {
        return Err(ApiError::BadRequest("the agent must belong to the ticket's client".into()));
    }
    let mut tx = st.db.begin().await?;
    let added = sqlx::query("INSERT INTO ticket_agents (ticket_id, agent_id, added_by) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
        .bind(id)
        .bind(b.agent_id)
        .bind(u.id)
        .execute(&mut *tx)
        .await?
        .rows_affected()
        > 0;
    if added {
        let host: String = sqlx::query_scalar("SELECT hostname FROM agents WHERE id = $1").bind(b.agent_id).fetch_one(&mut *tx).await?;
        tickets::add_event(&mut tx, id, "agent", false, &Author::user(u.id), "", json!({ "agent_id": b.agent_id, "hostname": host, "linked": true }))
            .await?;
    }
    tx.commit().await?;
    tickets::announce(&st, id).await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn unlink_agent(State(st): State<Arc<AppState>>, u: User, Path((id, agent_id)): Path<(Uuid, Uuid)>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    visible(&st, &u, id).await?;
    let mut tx = st.db.begin().await?;
    let removed = sqlx::query("DELETE FROM ticket_agents WHERE ticket_id = $1 AND agent_id = $2")
        .bind(id)
        .bind(agent_id)
        .execute(&mut *tx)
        .await?
        .rows_affected()
        > 0;
    if !removed {
        return Err(ApiError::NotFound("linked agent"));
    }
    let host: Option<String> = sqlx::query_scalar("SELECT hostname FROM agents WHERE id = $1").bind(agent_id).fetch_optional(&mut *tx).await?;
    tickets::add_event(&mut tx, id, "agent", false, &Author::user(u.id), "", json!({ "agent_id": agent_id, "hostname": host, "linked": false }))
        .await?;
    tx.commit().await?;
    tickets::announce(&st, id).await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct DocLink {
    doc_id: Uuid,
}

/// Links one of the client's documentation pages (a runbook, the network overview) to the ticket.
pub async fn link_doc(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<DocLink>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    let client = visible(&st, &u, id).await?;
    let doc_client = super::access::doc(&st, &u, b.doc_id).await?;
    if client != Some(doc_client) {
        return Err(ApiError::BadRequest("the page must belong to the ticket's client".into()));
    }
    let mut tx = st.db.begin().await?;
    let added = sqlx::query("INSERT INTO ticket_docs (ticket_id, doc_id, added_by) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
        .bind(id)
        .bind(b.doc_id)
        .bind(u.id)
        .execute(&mut *tx)
        .await?
        .rows_affected()
        > 0;
    if added {
        let title: String = sqlx::query_scalar("SELECT title FROM client_docs WHERE id = $1").bind(b.doc_id).fetch_one(&mut *tx).await?;
        tickets::add_event(&mut tx, id, "doc", false, &Author::user(u.id), "", json!({ "doc_id": b.doc_id, "title": title, "linked": true }))
            .await?;
    }
    tx.commit().await?;
    tickets::announce(&st, id).await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn unlink_doc(State(st): State<Arc<AppState>>, u: User, Path((id, doc_id)): Path<(Uuid, Uuid)>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    visible(&st, &u, id).await?;
    let mut tx = st.db.begin().await?;
    let removed = sqlx::query("DELETE FROM ticket_docs WHERE ticket_id = $1 AND doc_id = $2")
        .bind(id)
        .bind(doc_id)
        .execute(&mut *tx)
        .await?
        .rows_affected()
        > 0;
    if !removed {
        return Err(ApiError::NotFound("linked page"));
    }
    let title: Option<String> = sqlx::query_scalar("SELECT title FROM client_docs WHERE id = $1").bind(doc_id).fetch_optional(&mut *tx).await?;
    tickets::add_event(&mut tx, id, "doc", false, &Author::user(u.id), "", json!({ "doc_id": doc_id, "title": title, "linked": false }))
        .await?;
    tx.commit().await?;
    tickets::announce(&st, id).await;
    Ok(Json(json!({ "ok": true })))
}

/// A script started from the ticket (`POST /jobs` with `ticket_id`): note it and link the agent.
pub async fn job_started(st: &AppState, u: &User, ticket: Uuid, job: Uuid, agent: Uuid, script: Option<Uuid>) -> ApiResult<()> {
    let mut tx = st.db.begin().await?;
    sqlx::query("INSERT INTO ticket_agents (ticket_id, agent_id, added_by) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
        .bind(ticket)
        .bind(agent)
        .bind(u.id)
        .execute(&mut *tx)
        .await?;
    let (host, script_name): (String, Option<String>) =
        sqlx::query_as("SELECT a.hostname, (SELECT name FROM scripts WHERE id = $2) FROM agents a WHERE a.id = $1")
            .bind(agent)
            .bind(script)
            .fetch_one(&mut *tx)
            .await?;
    tickets::add_event(
        &mut tx,
        ticket,
        "job",
        false,
        &Author::user(u.id),
        "",
        json!({ "job_id": job, "agent_id": agent, "hostname": host, "script": script_name, "status": "started" }),
    )
    .await?;
    tx.commit().await?;
    tickets::announce(st, ticket).await;
    Ok(())
}

/// A terminal or remote desktop session started from a ticket: the ticket must be visible and
/// belong to the agent's client. Links the agent. Returns the ticket to record the session on.
pub async fn session_ticket(st: &AppState, u: &User, ticket: Option<Uuid>, agent: Uuid) -> ApiResult<Option<Uuid>> {
    let Some(t) = ticket else { return Ok(None) };
    let client = visible(st, u, t).await?;
    let agent_client = super::access::agent(st, u, agent).await?;
    if client != Some(agent_client) {
        return Err(ApiError::BadRequest("the agent must belong to the ticket's client".into()));
    }
    sqlx::query("INSERT INTO ticket_agents (ticket_id, agent_id, added_by) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
        .bind(t)
        .bind(agent)
        .bind(u.id)
        .execute(&st.db)
        .await?;
    Ok(Some(t))
}

#[derive(Deserialize)]
pub struct MergeIn {
    /// The ticket this one is merged into.
    into: Uuid,
}

/// Merges a duplicate into another ticket: its timeline, attachments, agents, pages and email thread
/// move over, and it's closed with a pointer to the other.
pub async fn merge(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<MergeIn>) -> ApiResult<Json<TicketRow>> {
    u.require(Role::Technician)?;
    if id == b.into {
        return Err(ApiError::BadRequest("a ticket can't be merged into itself".into()));
    }
    let src = fetch(&st, &u, id).await?;
    let dst = fetch(&st, &u, b.into).await?;
    if src.merged_into.is_some() || dst.merged_into.is_some() {
        return Err(ApiError::BadRequest("that ticket was already merged".into()));
    }
    if src.client_id.is_some() && dst.client_id.is_some() && src.client_id != dst.client_id {
        return Err(ApiError::BadRequest("both tickets must belong to the same client".into()));
    }
    let author = Author::user(u.id);
    let mut tx = st.db.begin().await?;
    sqlx::query("SELECT 1 FROM tickets WHERE id IN ($1, $2) ORDER BY id FOR UPDATE").bind(id).bind(b.into).execute(&mut *tx).await?;
    sqlx::query("UPDATE ticket_events SET ticket_id = $2 WHERE ticket_id = $1").bind(id).bind(b.into).execute(&mut *tx).await?;
    sqlx::query("UPDATE ticket_attachments SET ticket_id = $2 WHERE ticket_id = $1").bind(id).bind(b.into).execute(&mut *tx).await?;
    sqlx::query("UPDATE email_messages SET ticket_id = $2 WHERE ticket_id = $1").bind(id).bind(b.into).execute(&mut *tx).await?;
    sqlx::query("UPDATE jobs SET ticket_id = $2 WHERE ticket_id = $1").bind(id).bind(b.into).execute(&mut *tx).await?;
    sqlx::query(
        "INSERT INTO ticket_agents (ticket_id, agent_id, added_by, added_at)
         SELECT $2, agent_id, added_by, added_at FROM ticket_agents WHERE ticket_id = $1 ON CONFLICT DO NOTHING",
    )
    .bind(id)
    .bind(b.into)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM ticket_agents WHERE ticket_id = $1").bind(id).execute(&mut *tx).await?;
    sqlx::query(
        "INSERT INTO ticket_docs (ticket_id, doc_id, added_by, added_at)
         SELECT $2, doc_id, added_by, added_at FROM ticket_docs WHERE ticket_id = $1 ON CONFLICT DO NOTHING",
    )
    .bind(id)
    .bind(b.into)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM ticket_docs WHERE ticket_id = $1").bind(id).execute(&mut *tx).await?;
    // A triage duplicate takes the other's client; the other takes its contact if it had none.
    sqlx::query(
        "UPDATE tickets d SET contact_id = coalesce(d.contact_id, s.contact_id),
                first_response_at = least(d.first_response_at, s.first_response_at)
           FROM tickets s WHERE d.id = $2 AND s.id = $1",
    )
    .bind(id)
    .bind(b.into)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE tickets SET merged_into = $2, client_id = coalesce(client_id, $3) WHERE id = $1")
        .bind(id)
        .bind(b.into)
        .bind(dst.client_id)
        .execute(&mut *tx)
        .await?;
    if let Some(closed) = tickets::status_of(&mut tx, src.board_id, "closed").await? {
        tickets::set_status(&mut tx, id, closed, &author).await?;
    }
    tickets::add_event(&mut tx, id, "merge", false, &author, "", json!({ "into": b.into, "into_number": dst.number })).await?;
    tickets::add_event(&mut tx, b.into, "merge", false, &author, "", json!({ "from": id, "from_number": src.number, "subject": src.subject }))
        .await?;
    // Rebuild the search vector from the combined timeline.
    sqlx::query("UPDATE tickets SET subject = subject WHERE id = $1").bind(b.into).execute(&mut *tx).await?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "ticket.merge", Some(("ticket", id)), json!({ "into": b.into })).await;
    tickets::announce(&st, id).await;
    tickets::announce(&st, b.into).await;
    Ok(Json(fetch(&st, &u, b.into).await?))
}

#[derive(Deserialize)]
pub struct SplitIn {
    /// The timeline entry that becomes the new ticket's request.
    event_id: i64,
    subject: Option<String>,
}

/// Splits a timeline entry (usually a client's message about something else) into a new ticket
/// for the same client and contact. Its attachments move with it; both tickets note the split.
pub async fn split(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<SplitIn>) -> ApiResult<Json<TicketRow>> {
    u.require(Role::Technician)?;
    let src = fetch(&st, &u, id).await?;
    #[allow(clippy::type_complexity)]
    let ev: Option<(String, bool, String, Option<Uuid>, Option<Uuid>, String)> = sqlx::query_as(
        "SELECT kind, public, body, author_id, author_contact_id, author_name FROM ticket_events WHERE id = $1 AND ticket_id = $2",
    )
    .bind(b.event_id)
    .bind(id)
    .fetch_optional(&st.db)
    .await?;
    let Some((kind, public, body, author_id, author_contact, author_name)) = ev else { return Err(ApiError::NotFound("timeline entry")) };
    if !matches!(kind.as_str(), "created" | "message" | "reply" | "note") {
        return Err(ApiError::BadRequest("only messages, replies and notes can be split off".into()));
    }
    let subject = match b.subject.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => clean_subject(s)?,
        None => {
            let first = body.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("Split from another ticket");
            clean_subject(&first.chars().take(120).collect::<String>())?
        }
    };
    let mut tx = st.db.begin().await?;
    let contact = author_contact.or(src.contact_id);
    let created = tickets::create(
        &mut tx,
        NewTicket {
            client_id: src.client_id,
            site_id: src.site_id,
            contact_id: contact.filter(|_| src.client_id.is_some()),
            board_id: src.board_id,
            type_id: src.type_id,
            priority: src.priority,
            subject,
            body,
            body_public: public,
            source: "dashboard",
            requester_name: src.requester_name.clone(),
            requester_email: src.requester_email.clone(),
            created_by: Some(u.id),
            author: Author { user_id: author_id, contact_id: author_contact, name: author_name },
            team_id: src.team_id,
            ..Default::default()
        },
    )
    .await?;
    sqlx::query("UPDATE ticket_attachments SET ticket_id = $2, event_id = $3 WHERE event_id = $1")
        .bind(b.event_id)
        .bind(created.id)
        .bind(created.event_id)
        .execute(&mut *tx)
        .await?;
    // Replies to the split-off message's email thread keep landing on the old ticket; new mail
    // carries the new ticket's tag.
    let author = Author::user(u.id);
    tickets::add_event(&mut tx, id, "split", false, &author, "", json!({ "to": created.id, "to_number": created.number, "event_id": b.event_id }))
        .await?;
    tickets::add_event(&mut tx, created.id, "split", false, &author, "", json!({ "from": id, "from_number": src.number })).await?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "ticket.split", Some(("ticket", id)), json!({ "into": created.id })).await;
    tickets::notify_created(&st, created.id).await;
    tickets::announce(&st, id).await;
    tickets::announce(&st, created.id).await;
    Ok(Json(fetch(&st, &u, created.id).await?))
}

// ---------------------------------------------------------------------------
// Form data
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct BoardOut {
    id: Uuid,
    name: String,
    description: String,
    position: i32,
    statuses: Value,
    open_tickets: i64,
    default_team_id: Option<Uuid>,
    notify_channel_ids: Vec<Uuid>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct TypeOut {
    id: Uuid,
    name: String,
    position: i32,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct TechOut {
    id: Uuid,
    name: String,
    email: String,
    /// null = every client
    client_ids: Option<Vec<Uuid>>,
}

pub async fn boards(db: &sqlx::PgPool, scope: Option<&[Uuid]>) -> sqlx::Result<Vec<BoardOut>> {
    sqlx::query_as(
        "SELECT b.id, b.name, b.description, b.position,
                coalesce((SELECT jsonb_agg(jsonb_build_object('id', s.id, 'name', s.name, 'category', s.category, 'position', s.position)
                                          ORDER BY s.position, s.name) FROM board_statuses s WHERE s.board_id = b.id), '[]') AS statuses,
                (SELECT count(*) FROM tickets t JOIN board_statuses s ON s.id = t.status_id
                  WHERE t.board_id = b.id AND s.category NOT IN ('resolved', 'closed') AND t.merged_into IS NULL
                    AND ($1::uuid[] IS NULL OR t.client_id = ANY($1))) AS open_tickets,
                b.default_team_id, b.notify_channel_ids
           FROM boards b ORDER BY b.position, lower(b.name)",
    )
    .bind(scope)
    .fetch_all(db)
    .await
}

/// Boards with their statuses, ticket types and the technicians tickets can be assigned to.
pub async fn meta(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Value>> {
    let boards = boards(&st.db, u.scope()).await?;
    let types: Vec<TypeOut> = sqlx::query_as("SELECT id, name, position FROM ticket_types ORDER BY position, lower(name)").fetch_all(&st.db).await?;
    let techs: Vec<TechOut> = sqlx::query_as(
        "SELECT u.id, u.name, u.email,
                CASE WHEN u.role = 'admin' OR u.all_clients THEN NULL
                     ELSE ARRAY(SELECT uc.client_id FROM user_clients uc WHERE uc.user_id = u.id) END AS client_ids
           FROM users u WHERE NOT u.disabled AND u.role IN ('technician', 'admin') ORDER BY lower(u.name)",
    )
    .fetch_all(&st.db)
    .await?;
    let teams = super::desk::teams(&st.db).await?;
    Ok(Json(json!({ "boards": boards, "types": types, "technicians": techs, "teams": teams, "done_categories": DONE })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_tells_null_from_missing() {
        let p: Patch = serde_json::from_value(json!({ "assignee_id": null })).unwrap();
        assert_eq!(p.assignee_id, Some(None));
        assert!(p.contact_id.is_none());
        let p: Patch = serde_json::from_value(json!({ "contact_id": Uuid::nil() })).unwrap();
        assert_eq!(p.contact_id, Some(Some(Uuid::nil())));
    }

    #[test]
    fn filenames() {
        assert_eq!(clean_filename("../a/b.txt"), "ab.txt");
        assert_eq!(clean_filename("..."), "attachment");
    }
}
