//! Satisfaction surveys: one email per resolved ticket with a good / bad link, when Company
//! settings turn them on. Answers land on the ticket's timeline (internal) and in reporting.

use anyhow::Result;
use serde_json::json;
use tracing::info;
use uuid::Uuid;

use crate::auth;
use crate::state::AppState;
use crate::tickets::{self, Author};

/// Tickets resolved within this window get a survey (so turning surveys on doesn't email
/// everyone whose ticket was resolved last year).
const SEND_WITHIN_HOURS: i32 = 24;

/// Queues surveys for recently resolved tickets that have someone to ask. Returns how many.
pub async fn send_due(st: &AppState) -> Result<usize> {
    if !st.company().csat_enabled {
        return Ok(0);
    }
    let due: Vec<(Uuid, Option<Uuid>, String)> = sqlx::query_as(
        "SELECT t.id, t.contact_id, coalesce(nullif(co.email, ''), t.requester_email)
           FROM tickets t JOIN board_statuses s ON s.id = t.status_id LEFT JOIN contacts co ON co.id = t.contact_id
          WHERE s.category = 'resolved' AND t.resolved_at > now() - make_interval(hours => $1) AND t.merged_into IS NULL
            AND t.source <> 'alert' AND coalesce(nullif(co.email, ''), t.requester_email) <> ''
            AND NOT EXISTS (SELECT 1 FROM csat_surveys c WHERE c.ticket_id = t.id)
          LIMIT 50",
    )
    .bind(SEND_WITHIN_HOURS)
    .fetch_all(&st.db)
    .await?;
    let mut n = 0;
    for (ticket, contact, email) in due {
        let token = auth::random_token();
        let inserted = sqlx::query(
            "INSERT INTO csat_surveys (ticket_id, token_hash, contact_id, email) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
        )
        .bind(ticket)
        .bind(auth::token_hash(&token))
        .bind(contact)
        .bind(&email)
        .execute(&st.db)
        .await?
        .rows_affected();
        if inserted == 1 {
            crate::email::queue_survey(st, ticket, &email, &token).await?;
            n += 1;
        }
    }
    if n > 0 {
        info!(surveys = n, "sent satisfaction surveys");
    }
    Ok(n)
}

/// Records an answer (or a changed one). Returns the ticket.
pub async fn answer(st: &AppState, token: &str, rating: &str, comment: &str) -> sqlx::Result<Option<Uuid>> {
    let mut tx = st.db.begin().await?;
    #[allow(clippy::type_complexity)]
    let row: Option<(Uuid, Option<String>, String, Option<Uuid>, String)> = sqlx::query_as(
        "SELECT ticket_id, rating, comment, contact_id, email FROM csat_surveys WHERE token_hash = $1 FOR UPDATE",
    )
    .bind(auth::token_hash(token))
    .fetch_optional(&mut *tx)
    .await?;
    let Some((ticket, old_rating, old_comment, contact, email)) = row else { return Ok(None) };
    if old_rating.as_deref() == Some(rating) && old_comment == comment {
        return Ok(Some(ticket));
    }
    sqlx::query("UPDATE csat_surveys SET rating = $2, comment = $3, answered_at = now() WHERE ticket_id = $1")
        .bind(ticket)
        .bind(rating)
        .bind(comment)
        .execute(&mut *tx)
        .await?;
    let author = Author { contact_id: contact, name: email, ..Default::default() };
    let verdict = if rating == "good" { "Good" } else { "Bad" };
    let body = if comment.is_empty() { format!("Satisfaction: {verdict}") } else { format!("Satisfaction: {verdict}\n\n{comment}") };
    tickets::add_event(&mut tx, ticket, "csat", false, &author, &body, json!({ "rating": rating })).await?;
    tx.commit().await?;
    tickets::announce(st, ticket).await;
    Ok(Some(ticket))
}
