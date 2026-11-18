//! Tickets: creation, the timeline, status changes, and the links to the RMM (alerts open
//! tickets, scripts run from a ticket report back to it).
//!
//! HTTP handlers live in `api::tickets`; email in [`crate::email`].

use serde_json::{Value, json};
use sqlx::{PgConnection, PgPool};
use tracing::{info, warn};
use uuid::Uuid;

use crate::hub::Event;
use crate::state::AppState;

/// Stop auto-resolving an alert ticket once its alert has come back this many times: a
/// flapping check should get a person's attention.
pub const FLAP_LIMIT: i32 = 3;

/// Status categories, in workflow order.
pub const CATEGORIES: &[&str] = &["new", "open", "waiting_client", "waiting_vendor", "resolved", "closed"];
/// Categories that count as finished: excluded from "open" views, and replies reopen them.
pub const DONE: &[&str] = &["resolved", "closed"];

/// Priority from impact and urgency (each 1 = high .. 3 = low): P1 only when both are high.
pub fn matrix_priority(impact: i16, urgency: i16) -> i16 {
    match impact.clamp(1, 3) + urgency.clamp(1, 3) {
        2 => 1,
        3 => 2,
        4 => 3,
        _ => 4,
    }
}

/// Who wrote an event.
#[derive(Clone, Debug, Default)]
pub struct Author {
    pub user_id: Option<Uuid>,
    pub contact_id: Option<Uuid>,
    /// Shown when neither id is set (an email sender, or automation such as "Alert").
    pub name: String,
}

impl Author {
    pub fn user(id: Uuid) -> Self {
        Author { user_id: Some(id), ..Default::default() }
    }
    pub fn system(name: &str) -> Self {
        Author { name: name.into(), ..Default::default() }
    }
}

/// Appends to the timeline and bumps `updated_at` (and `touched_at` for a person's action).
pub async fn add_event(
    db: &mut PgConnection,
    ticket_id: Uuid,
    kind: &str,
    public: bool,
    author: &Author,
    body: &str,
    data: Value,
) -> sqlx::Result<i64> {
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO ticket_events (ticket_id, kind, public, author_id, author_contact_id, author_name, body, data)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
    )
    .bind(ticket_id)
    .bind(kind)
    .bind(public)
    .bind(author.user_id)
    .bind(author.contact_id)
    .bind(&author.name)
    .bind(body)
    .bind(data)
    .fetch_one(&mut *db)
    .await?;
    sqlx::query(
        "UPDATE tickets SET updated_at = now(), touched_at = CASE WHEN $2 THEN now() ELSE touched_at END WHERE id = $1",
    )
    .bind(ticket_id)
    .bind(author.user_id.is_some())
    .execute(&mut *db)
    .await?;
    Ok(id)
}

/// The first status of `category` on the board (by position), falling back along the workflow
/// for `open` (to `new`) so boards without an `open` status still work.
pub async fn status_of(db: &mut PgConnection, board_id: Uuid, category: &str) -> sqlx::Result<Option<Uuid>> {
    let order: &[&str] = match category {
        "open" => &["open", "new"],
        "new" => &["new", "open"],
        c => std::slice::from_ref(match CATEGORIES.iter().find(|x| **x == c) {
            Some(x) => x,
            None => return Ok(None),
        }),
    };
    for c in order {
        let id: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM board_statuses WHERE board_id = $1 AND category = $2 ORDER BY position, name LIMIT 1")
                .bind(board_id)
                .bind(c)
                .fetch_optional(&mut *db)
                .await?;
        if id.is_some() {
            return Ok(id);
        }
    }
    Ok(None)
}

/// Moves a ticket to `status_id` (which must be on its board), keeping `resolved_at` and
/// `closed_at` in step with the category, and records the change. Returns false when it was
/// already there.
pub async fn set_status(db: &mut PgConnection, ticket_id: Uuid, status_id: Uuid, author: &Author) -> sqlx::Result<bool> {
    let old: Option<(Uuid, String, String)> = sqlx::query_as(
        "SELECT t.status_id, s.name, s.category FROM tickets t JOIN board_statuses s ON s.id = t.status_id WHERE t.id = $1 FOR UPDATE OF t",
    )
    .bind(ticket_id)
    .fetch_optional(&mut *db)
    .await?;
    let Some((old_id, old_name, old_category)) = old else { return Ok(false) };
    if old_id == status_id {
        return Ok(false);
    }
    let (new_name, category): (String, String) =
        sqlx::query_as("SELECT name, category FROM board_statuses WHERE id = $1").bind(status_id).fetch_one(&mut *db).await?;
    sqlx::query(
        "UPDATE tickets SET status_id = $2,
                resolved_at = CASE WHEN $3 IN ('resolved', 'closed') THEN coalesce(resolved_at, now()) END,
                closed_at = CASE WHEN $3 = 'closed' THEN coalesce(closed_at, now()) END
          WHERE id = $1",
    )
    .bind(ticket_id)
    .bind(status_id)
    .bind(&category)
    .execute(&mut *db)
    .await?;
    crate::sla::status_changed(db, ticket_id, &old_category, &category).await?;
    add_event(
        db,
        ticket_id,
        "change",
        false,
        author,
        "",
        json!({ "field": "status", "from": old_name, "to": new_name, "category": category }),
    )
    .await?;
    Ok(true)
}

/// A ticket to open. Everything but the subject and board is optional.
#[derive(Default)]
pub struct NewTicket {
    pub client_id: Option<Uuid>,
    pub site_id: Option<Uuid>,
    pub contact_id: Option<Uuid>,
    pub board_id: Uuid,
    pub type_id: Option<Uuid>,
    pub priority: i16,
    pub impact: Option<i16>,
    pub urgency: Option<i16>,
    pub subject: String,
    /// The request itself: the first timeline entry.
    pub body: String,
    /// Whether the client sees `body` (their own request does; an alert's facts don't).
    pub body_public: bool,
    pub source: &'static str,
    pub assignee_id: Option<Uuid>,
    /// None: the board's default team.
    pub team_id: Option<Uuid>,
    pub requester_name: String,
    pub requester_email: String,
    pub mailbox_id: Option<Uuid>,
    pub created_by: Option<Uuid>,
    pub author: Author,
    pub alert: Option<(Uuid, Uuid, String)>,
    pub agent_ids: Vec<Uuid>,
}

pub struct Created {
    pub id: Uuid,
    pub number: i64,
    /// The `created` event, which carries the request text.
    pub event_id: i64,
}

/// Inserts the ticket in its board's first `new` status, with its first event and agent links.
pub async fn create(db: &mut PgConnection, t: NewTicket) -> sqlx::Result<Created> {
    let status = status_of(db, t.board_id, "new").await?.ok_or(sqlx::Error::RowNotFound)?;
    let id = Uuid::new_v4();
    let (alert_policy, alert_agent, alert_key) = match &t.alert {
        Some((p, a, k)) => (Some(*p), Some(*a), Some(k.as_str())),
        None => (None, None, None),
    };
    let number: i64 = sqlx::query_scalar(
        "INSERT INTO tickets (id, client_id, site_id, contact_id, board_id, status_id, type_id, priority, impact, urgency, subject,
                              source, assignee_id, requester_name, requester_email, mailbox_id, created_by, touched_at,
                              alert_policy_id, alert_agent_id, alert_key, team_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
                 CASE WHEN $17::uuid IS NULL THEN NULL ELSE now() END, $18, $19, $20,
                 coalesce($21, (SELECT default_team_id FROM boards WHERE id = $5)))
         RETURNING number",
    )
    .bind(id)
    .bind(t.client_id)
    .bind(t.site_id)
    .bind(t.contact_id)
    .bind(t.board_id)
    .bind(status)
    .bind(t.type_id)
    .bind(t.priority.clamp(1, 4))
    .bind(t.impact)
    .bind(t.urgency)
    .bind(&t.subject)
    .bind(t.source)
    .bind(t.assignee_id)
    .bind(&t.requester_name)
    .bind(&t.requester_email)
    .bind(t.mailbox_id)
    .bind(t.created_by)
    .bind(alert_policy)
    .bind(alert_agent)
    .bind(alert_key)
    .bind(t.team_id)
    .fetch_one(&mut *db)
    .await?;
    let event_id = add_event(db, id, "created", t.body_public, &t.author, &t.body, json!({ "source": t.source })).await?;
    for agent in &t.agent_ids {
        sqlx::query("INSERT INTO ticket_agents (ticket_id, agent_id, added_by) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
            .bind(id)
            .bind(agent)
            .bind(t.created_by)
            .execute(&mut *db)
            .await?;
    }
    crate::sla::refresh(db, id).await?;
    Ok(Created { id, number, event_id })
}

/// A new ticket: tell its board's notification channels. Call after the creating transaction
/// commits.
pub async fn notify_created(st: &AppState, ticket_id: Uuid) {
    let res = sqlx::query(
        "INSERT INTO notifications (channel_id, ticket_id, event)
         SELECT c.id, t.id, 'ticket_created' FROM tickets t JOIN boards b ON b.id = t.board_id
           JOIN notification_channels c ON c.id = ANY(b.notify_channel_ids) AND c.enabled
          WHERE t.id = $1",
    )
    .bind(ticket_id)
    .execute(&st.db)
    .await;
    match res {
        Ok(r) if r.rows_affected() > 0 => st.notify_wake.notify_one(),
        Ok(_) => {}
        Err(e) => warn!(%ticket_id, "queueing new-ticket notifications: {e}"),
    }
}

/// Tells dashboards the ticket changed.
pub async fn announce(st: &AppState, ticket_id: Uuid) {
    let client: sqlx::Result<Option<Option<Uuid>>> =
        sqlx::query_scalar("SELECT client_id FROM tickets WHERE id = $1").bind(ticket_id).fetch_optional(&st.db).await;
    match client {
        Ok(Some(client_id)) => st.hub.publish(Event::Ticket { id: ticket_id, client_id }),
        Ok(None) => {}
        Err(e) => warn!(%ticket_id, "announcing ticket: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Alerts → tickets
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct AlertTicketCtx {
    policy_id: Uuid,
    agent_id: Uuid,
    key: String,
    title: String,
    severity: String,
    details: Value,
    hostname: String,
    client_id: Uuid,
    site_id: Uuid,
    board_id: Option<Uuid>,
    priority: i16,
    auto_resolve: bool,
    resolution: Option<String>,
}

async fn alert_ctx(db: &PgPool, alert_id: Uuid) -> sqlx::Result<Option<AlertTicketCtx>> {
    sqlx::query_as(
        "SELECT al.policy_id, al.agent_id, al.key, al.title, al.severity, al.details, a.hostname, s.client_id, a.site_id,
                (c ->> 'ticket_board_id')::uuid AS board_id, coalesce((c ->> 'ticket_priority')::smallint, 3::smallint) AS priority,
                coalesce((c ->> 'ticket_auto_resolve')::boolean, false) AS auto_resolve, al.resolution
           FROM alerts al JOIN agents a ON a.id = al.agent_id JOIN sites s ON s.id = a.site_id
           CROSS JOIN LATERAL policy_config(al.policy_id, al.agent_id) c
          WHERE al.id = $1 AND al.policy_id IS NOT NULL",
    )
    .bind(alert_id)
    .fetch_optional(db)
    .await
}

/// The newest not-closed ticket for an alert's (policy, agent, key), with its category.
async fn alert_ticket(db: &mut PgConnection, policy: Uuid, agent: Uuid, key: &str) -> sqlx::Result<Option<(Uuid, String, i32)>> {
    sqlx::query_as(
        "SELECT t.id, s.category, t.alert_reopens FROM tickets t JOIN board_statuses s ON s.id = t.status_id
          WHERE t.alert_policy_id = $1 AND t.alert_agent_id = $2 AND t.alert_key = $3 AND t.merged_into IS NULL
            AND s.category <> 'closed'
          ORDER BY t.created_at DESC LIMIT 1 FOR UPDATE OF t",
    )
    .bind(policy)
    .bind(agent)
    .bind(key)
    .fetch_optional(&mut *db)
    .await
}

fn alert_facts(c: &AlertTicketCtx) -> String {
    let mut lines = vec![format!("{} on {}", c.title, c.hostname), format!("Severity: {}", c.severity)];
    if let Some(obj) = c.details.as_object() {
        for (k, v) in obj {
            let v = match v {
                Value::String(s) if !s.is_empty() => s.clone(),
                Value::Number(_) | Value::Bool(_) => v.to_string(),
                _ => continue,
            };
            lines.push(format!("{}: {v}", k.replace('_', " ")));
        }
    }
    lines.join("\n")
}

/// An alert opened. If its policy files tickets: add to the open ticket for the same alert on
/// the same agent, reopen a resolved one, or open a new one.
pub async fn alert_opened(st: &AppState, alert_id: Uuid) {
    let res: sqlx::Result<Option<Uuid>> = async {
        let Some(c) = alert_ctx(&st.db, alert_id).await? else { return Ok(None) };
        let Some(board) = c.board_id else { return Ok(None) };
        let mut tx = st.db.begin().await?;
        let author = Author::system("Alert");
        let data = json!({ "alert_id": alert_id, "state": "opened", "agent_id": c.agent_id });
        let mut new_ticket = None;
        let ticket = match alert_ticket(&mut tx, c.policy_id, c.agent_id, &c.key).await? {
            Some((id, cat, reopens)) if cat == "resolved" => {
                let board = board_of(&mut tx, id).await?;
                let open = status_of(&mut tx, board, "open").await?;
                if let Some(s) = open {
                    set_status(&mut tx, id, s, &author).await?;
                }
                sqlx::query("UPDATE tickets SET alert_reopens = alert_reopens + 1 WHERE id = $1").bind(id).execute(&mut *tx).await?;
                add_event(&mut tx, id, "alert", false, &author, &format!("The alert came back: {}. Reopened ({} times so far).", c.title, reopens + 1), data)
                    .await?;
                id
            }
            Some((id, _, _)) => {
                add_event(&mut tx, id, "alert", false, &author, &format!("The alert fired again: {}", c.title), data).await?;
                id
            }
            None => {
                let type_id: Option<Uuid> =
                    sqlx::query_scalar("SELECT id FROM ticket_types WHERE name = 'Alert'").fetch_optional(&mut *tx).await?;
                let created = create(
                    &mut tx,
                    NewTicket {
                        client_id: Some(c.client_id),
                        site_id: Some(c.site_id),
                        board_id: board,
                        type_id,
                        priority: c.priority,
                        subject: format!("{} on {}", c.title, c.hostname).chars().take(300).collect(),
                        body: alert_facts(&c),
                        source: "alert",
                        author: author.clone(),
                        alert: Some((c.policy_id, c.agent_id, c.key.clone())),
                        agent_ids: vec![c.agent_id],
                        ..Default::default()
                    },
                )
                .await?;
                add_event(&mut tx, created.id, "alert", false, &author, "", data).await?;
                info!(ticket = created.number, %alert_id, "alert opened a ticket");
                new_ticket = Some(created.id);
                created.id
            }
        };
        tx.commit().await?;
        if let Some(t) = new_ticket {
            notify_created(st, t).await;
        }
        Ok(Some(ticket))
    }
    .await;
    match res {
        Ok(Some(t)) => announce(st, t).await,
        Ok(None) => {}
        Err(e) => warn!(%alert_id, "filing alert ticket: {e}"),
    }
}

async fn board_of(db: &mut PgConnection, ticket_id: Uuid) -> sqlx::Result<Uuid> {
    sqlx::query_scalar("SELECT board_id FROM tickets WHERE id = $1").bind(ticket_id).fetch_one(&mut *db).await
}

/// An alert resolved: note it on its ticket and, if the policy says so and nobody has worked
/// the ticket, resolve that too (unless the alert keeps coming back).
pub async fn alert_resolved(st: &AppState, alert_id: Uuid) {
    let res: sqlx::Result<Option<Uuid>> = async {
        let Some(c) = alert_ctx(&st.db, alert_id).await? else { return Ok(None) };
        let mut tx = st.db.begin().await?;
        let Some((id, cat, reopens)) = alert_ticket(&mut tx, c.policy_id, c.agent_id, &c.key).await? else { return Ok(None) };
        if DONE.contains(&cat.as_str()) {
            return Ok(None);
        }
        let author = Author::system("Alert");
        let how = match c.resolution.as_deref() {
            Some("manual") => "The alert was resolved by hand.",
            Some("policy") => "The alert was closed because its policy changed.",
            _ => "The alert cleared.",
        };
        add_event(&mut tx, id, "alert", false, &author, how, json!({ "alert_id": alert_id, "state": "resolved" })).await?;
        let untouched: bool =
            sqlx::query_scalar("SELECT touched_at IS NULL FROM tickets WHERE id = $1").bind(id).fetch_one(&mut *tx).await?;
        if c.auto_resolve && untouched && c.resolution.as_deref() == Some("cleared") {
            if reopens >= FLAP_LIMIT {
                add_event(
                    &mut tx,
                    id,
                    "note",
                    false,
                    &author,
                    &format!("Not resolving automatically: the alert has come back {reopens} times."),
                    json!({}),
                )
                .await?;
            } else {
                let board = board_of(&mut tx, id).await?;
                if let Some(s) = status_of(&mut tx, board, "resolved").await? {
                    set_status(&mut tx, id, s, &author).await?;
                }
            }
        }
        tx.commit().await?;
        Ok(Some(id))
    }
    .await;
    match res {
        Ok(Some(t)) => announce(st, t).await,
        Ok(None) => {}
        Err(e) => warn!(%alert_id, "updating alert ticket: {e}"),
    }
}

// ---------------------------------------------------------------------------
// RMM actions from a ticket
// ---------------------------------------------------------------------------

/// Keep timeline entries readable: this much of a job's output, from the end.
const JOB_OUTPUT_TAIL: usize = 4000;

fn tail(s: &str, max: usize) -> String {
    let n = s.chars().count();
    if n <= max { s.to_string() } else { format!("…{}", s.chars().skip(n - max).collect::<String>()) }
}

/// A job finished. If it was run from a ticket, its result goes on the timeline as an
/// internal note.
pub async fn job_finished(st: &AppState, job_id: Uuid) {
    let res: sqlx::Result<Option<Uuid>> = async {
        #[allow(clippy::type_complexity)]
        let row: Option<(Uuid, Uuid, String, Option<String>, String, Option<i32>, String, String, Option<Uuid>)> = sqlx::query_as(
            "SELECT j.ticket_id, j.agent_id, a.hostname, sc.name, j.status, j.exit_code, j.stdout, j.stderr, j.created_by
               FROM jobs j JOIN agents a ON a.id = j.agent_id LEFT JOIN scripts sc ON sc.id = j.script_id
              WHERE j.id = $1 AND j.ticket_id IS NOT NULL",
        )
        .bind(job_id)
        .fetch_optional(&st.db)
        .await?;
        let Some((ticket_id, agent_id, hostname, script, status, exit_code, stdout, stderr, by)) = row else { return Ok(None) };
        let mut body = String::new();
        if !stdout.trim().is_empty() {
            body.push_str(&tail(stdout.trim_end(), JOB_OUTPUT_TAIL));
        }
        if !stderr.trim().is_empty() {
            if !body.is_empty() {
                body.push_str("\n\n");
            }
            body.push_str("stderr:\n");
            body.push_str(&tail(stderr.trim_end(), JOB_OUTPUT_TAIL / 2));
        }
        let mut conn = st.db.acquire().await?;
        // Attributed to the system (with the technician in data) so it doesn't count as touching.
        let author = Author::system(&hostname);
        add_event(
            &mut conn,
            ticket_id,
            "job",
            false,
            &author,
            &body,
            json!({ "job_id": job_id, "agent_id": agent_id, "hostname": hostname, "script": script, "status": status,
                    "exit_code": exit_code, "run_by": by }),
        )
        .await?;
        Ok(Some(ticket_id))
    }
    .await;
    match res {
        Ok(Some(t)) => announce(st, t).await,
        Ok(None) => {}
        Err(e) => warn!(%job_id, "adding job result to its ticket: {e}"),
    }
}

/// A terminal or remote desktop session opened from a ticket started or ended. `secs` is the
/// duration, on end.
pub async fn session_event(st: &AppState, ticket_id: Uuid, user_id: Uuid, agent_id: Uuid, what: &str, secs: Option<u64>) {
    let res: sqlx::Result<()> = async {
        let hostname: String = sqlx::query_scalar("SELECT hostname FROM agents WHERE id = $1").bind(agent_id).fetch_one(&st.db).await?;
        let label = if what == "desktop" { "Remote desktop" } else { "Terminal" };
        let body = match secs {
            None => format!("{label} session on {hostname} started."),
            Some(s) => format!("{label} session on {hostname} ended after {}.", human_duration(s)),
        };
        let mut conn = st.db.acquire().await?;
        add_event(
            &mut conn,
            ticket_id,
            "session",
            false,
            &Author::user(user_id),
            &body,
            json!({ "kind": what, "agent_id": agent_id, "hostname": hostname, "ended": secs.is_some(), "duration_secs": secs }),
        )
        .await?;
        Ok(())
    }
    .await;
    match res {
        Ok(()) => announce(st, ticket_id).await,
        Err(e) => warn!(%ticket_id, "recording session: {e}"),
    }
}

pub fn human_duration(secs: u64) -> String {
    match secs {
        0..60 => format!("{secs} s"),
        60..3600 => format!("{} min", secs.div_ceil(60)),
        _ => format!("{} h {} min", secs / 3600, (secs % 3600) / 60),
    }
}

/// Moves resolved tickets to their board's closed status after `days`.
pub async fn auto_close(st: &AppState, days: u32) -> sqlx::Result<usize> {
    let due: Vec<Uuid> = sqlx::query_scalar(
        "SELECT t.id FROM tickets t JOIN board_statuses s ON s.id = t.status_id
          WHERE s.category = 'resolved' AND t.resolved_at < now() - make_interval(days => $1) LIMIT 500",
    )
    .bind(days as i32)
    .fetch_all(&st.db)
    .await?;
    let author = Author::system("Automation");
    for id in &due {
        let mut tx = st.db.begin().await?;
        let board = board_of(&mut tx, *id).await?;
        if let Some(s) = status_of(&mut tx, board, "closed").await? {
            set_status(&mut tx, *id, s, &author).await?;
        }
        tx.commit().await?;
        announce(st, *id).await;
    }
    Ok(due.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priority_matrix() {
        assert_eq!(matrix_priority(1, 1), 1);
        assert_eq!(matrix_priority(1, 2), 2);
        assert_eq!(matrix_priority(2, 1), 2);
        assert_eq!(matrix_priority(2, 2), 3);
        assert_eq!(matrix_priority(1, 3), 3);
        assert_eq!(matrix_priority(3, 3), 4);
        assert_eq!(matrix_priority(2, 3), 4);
    }

    #[test]
    fn output_tail_and_durations() {
        assert_eq!(tail("abcdef", 3), "…def");
        assert_eq!(tail("abc", 3), "abc");
        assert_eq!(human_duration(42), "42 s");
        assert_eq!(human_duration(61), "2 min");
        assert_eq!(human_duration(3720), "1 h 2 min");
    }
}
