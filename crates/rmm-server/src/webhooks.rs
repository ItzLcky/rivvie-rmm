//! Outbound webhooks for ticket and alert events (docs/design/api.md).
//!
//! Subscriptions (admins, `api::webhooks`) name a URL, the events they want and optionally one
//! client. An event writes one `webhook_deliveries` row per matching subscription: for tickets
//! in the transaction that changed the ticket ([`ticket_event`], called by `tickets::add_event`,
//! so nothing is lost or announced for a change that rolled back), for alerts right after the
//! alert changed ([`alert_event`]). The notification worker drains the table ([`drain`]) with
//! the same lease, retries and backoff as the other notification channels, and the rows double
//! as the delivery log shown in the dashboard.
//!
//! Every delivery is `POST <url>` with the JSON envelope `{id, event, created_at, data}`,
//! signed like the webhook notification channel: `X-RMM-Signature: sha256=<hex HMAC-SHA256 of
//! the body>`, plus `X-RMM-Event` and `X-RMM-Delivery`. A retry sends identical bytes.

use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sqlx::PgConnection;
use tracing::{info, warn};
use uuid::Uuid;

use crate::state::AppState;
use crate::tickets::Author;

pub const EVENTS: &[&str] = &[
    "ticket.created",
    "ticket.updated",
    "ticket.status_changed",
    "ticket.resolved",
    "ticket.comment",
    "alert.created",
    "alert.acknowledged",
    "alert.resolved",
];
const BATCH: i64 = 20;

pub fn valid_event(e: &str) -> bool {
    EVENTS.contains(&e)
}

pub fn new_secret() -> String {
    format!("whsec_{}", crate::auth::random_token())
}

/// A subscription URL must be a full http(s) URL. (Admins choose it; internal addresses are
/// allowed on purpose, since the receiver is often a service on the same network.)
pub fn validate_url(url: &str) -> Result<String, String> {
    let url = url.trim();
    let parsed = reqwest::Url::parse(url).map_err(|_| "enter the full URL, starting with https://".to_string())?;
    if !matches!(parsed.scheme(), "https" | "http") || parsed.host_str().is_none() || !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("the URL must start with https:// (or http://) and carry no user name or password".into());
    }
    if url.len() > 2000 {
        return Err("the URL is too long".into());
    }
    Ok(url.to_string())
}

// ---------------------------------------------------------------------------
// Producing events
// ---------------------------------------------------------------------------

/// The webhook events a timeline entry stands for, each with the extra payload parts.
fn ticket_events(kind: &str, public: bool, event_id: i64, body: &str, data: &Value) -> Vec<(&'static str, Value)> {
    match kind {
        "created" => vec![("ticket.created", json!({}))],
        "reply" | "message" | "note" => {
            vec![("ticket.comment", json!({ "comment": { "id": event_id, "kind": kind, "public": public, "body": body } }))]
        }
        "change" if data["field"] == "status" => {
            let change = json!({ "field": "status", "from": data["from"], "to": data["to"], "category": data["category"] });
            let mut out = vec![("ticket.status_changed", json!({ "change": change }))];
            if data["category"] == "resolved" {
                out.push(("ticket.resolved", json!({ "change": change })));
            }
            out
        }
        "change" => vec![("ticket.updated", json!({ "change": { "field": data["field"], "from": data["from"], "to": data["to"] } }))],
        "agent" | "doc" | "merge" | "split" => vec![("ticket.updated", json!({ "change": { "field": kind, "detail": data } }))],
        _ => vec![],
    }
}

/// Queues the webhooks for one ticket timeline entry. Runs inside the caller's transaction.
#[allow(clippy::too_many_arguments)]
pub async fn ticket_event(
    db: &mut PgConnection,
    ticket_id: Uuid,
    kind: &str,
    public: bool,
    event_id: i64,
    author: &Author,
    body: &str,
    data: &Value,
) -> sqlx::Result<()> {
    let events = ticket_events(kind, public, event_id, body, data);
    if events.is_empty() {
        return Ok(());
    }
    let names: Vec<&str> = events.iter().map(|e| e.0).collect();
    let subs: Vec<(Uuid, Vec<String>, bool)> = sqlx::query_as(
        "SELECT s.id, s.events, s.internal_notes FROM webhook_subscriptions s
          WHERE s.enabled AND s.events && $1::text[]
            AND (s.client_id IS NULL OR s.client_id = (SELECT client_id FROM tickets WHERE id = $2))",
    )
    .bind(&names)
    .bind(ticket_id)
    .fetch_all(&mut *db)
    .await?;
    if subs.is_empty() {
        return Ok(());
    }
    let ticket: Option<Value> = sqlx::query_scalar(
        "SELECT jsonb_build_object(
                'id', t.id, 'number', t.number, 'subject', t.subject, 'priority', t.priority,
                'client', CASE WHEN t.client_id IS NULL THEN NULL ELSE jsonb_build_object('id', t.client_id, 'name', c.name) END,
                'board', b.name,
                'status', jsonb_build_object('id', s.id, 'name', s.name, 'category', s.category),
                'assignee', CASE WHEN t.assignee_id IS NULL THEN NULL ELSE jsonb_build_object('id', t.assignee_id, 'name', u.name) END,
                'source', t.source,
                'requester', jsonb_build_object('name', t.requester_name, 'email', t.requester_email),
                'created_at', t.created_at, 'updated_at', t.updated_at)
           FROM tickets t JOIN boards b ON b.id = t.board_id JOIN board_statuses s ON s.id = t.status_id
           LEFT JOIN clients c ON c.id = t.client_id LEFT JOIN users u ON u.id = t.assignee_id
          WHERE t.id = $1",
    )
    .bind(ticket_id)
    .fetch_optional(&mut *db)
    .await?;
    let Some(ticket) = ticket else { return Ok(()) };
    let actor = if let Some(id) = author.user_id {
        let name: Option<String> = sqlx::query_scalar("SELECT name FROM users WHERE id = $1").bind(id).fetch_optional(&mut *db).await?;
        json!({ "type": "user", "id": id, "name": name })
    } else if let Some(id) = author.contact_id {
        let name: Option<String> = sqlx::query_scalar("SELECT name FROM contacts WHERE id = $1").bind(id).fetch_optional(&mut *db).await?;
        json!({ "type": "contact", "id": id, "name": name })
    } else {
        json!({ "type": "system", "id": null, "name": author.name })
    };
    for (event, extra) in events {
        let mut payload = json!({ "ticket": ticket, "actor": actor });
        if let Some(extra) = extra.as_object() {
            for (k, v) in extra {
                payload[k] = v.clone();
            }
        }
        for (sub, wanted, internal) in &subs {
            // Internal notes go out only to subscriptions that asked for them.
            if !wanted.iter().any(|w| w == event) || (event == "ticket.comment" && !public && !internal) {
                continue;
            }
            sqlx::query("INSERT INTO webhook_deliveries (subscription_id, event, payload) VALUES ($1, $2, $3)")
                .bind(sub)
                .bind(event)
                .bind(&payload)
                .execute(&mut *db)
                .await?;
        }
    }
    Ok(())
}

/// Queues `alert.created`, `alert.acknowledged` or `alert.resolved` for an alert, and wakes the
/// worker. Failures are logged: an alert must never fail because a webhook couldn't be queued.
pub async fn alert_event(st: &AppState, alert_id: Uuid, event: &str) {
    if let Err(e) = queue_alert(st, alert_id, event).await {
        warn!(%alert_id, event, "queueing webhooks: {e}");
    }
}

async fn queue_alert(st: &AppState, alert_id: Uuid, event: &str) -> sqlx::Result<()> {
    let row: Option<(Uuid, Value)> = sqlx::query_as(
        "SELECT s.client_id, jsonb_build_object(
                'alert', jsonb_build_object(
                    'id', al.id, 'kind', al.kind, 'severity', al.severity, 'title', al.title, 'details', al.details,
                    'occurrences', al.occurrences, 'policy', p.name, 'opened_at', al.opened_at, 'acknowledged_at', al.acknowledged_at,
                    'resolved_at', al.resolved_at, 'resolution', al.resolution,
                    'state', CASE WHEN al.resolved_at IS NOT NULL THEN 'resolved' WHEN al.acknowledged_at IS NOT NULL THEN 'acknowledged' ELSE 'open' END),
                'agent', jsonb_build_object('id', a.id, 'hostname', a.hostname),
                'client', jsonb_build_object('id', c.id, 'name', c.name),
                'site', jsonb_build_object('id', s.id, 'name', s.name))
           FROM alerts al JOIN agents a ON a.id = al.agent_id JOIN sites s ON s.id = a.site_id JOIN clients c ON c.id = s.client_id
           LEFT JOIN policy_items p ON p.id = al.policy_id
          WHERE al.id = $1",
    )
    .bind(alert_id)
    .fetch_optional(&st.db)
    .await?;
    let Some((client_id, payload)) = row else { return Ok(()) };
    let n = sqlx::query(
        "INSERT INTO webhook_deliveries (subscription_id, event, payload)
         SELECT s.id, $1, $2 FROM webhook_subscriptions s
          WHERE s.enabled AND $1 = ANY(s.events) AND (s.client_id IS NULL OR s.client_id = $3)",
    )
    .bind(event)
    .bind(&payload)
    .bind(client_id)
    .execute(&st.db)
    .await?
    .rows_affected();
    if n > 0 {
        st.notify_wake.notify_one();
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Delivering
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct Due {
    id: i64,
    subscription_id: Uuid,
    delivery_id: Uuid,
    event: String,
    payload: Value,
    attempts: i32,
    created_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct Target {
    url: String,
    secret: Vec<u8>,
    secret_sealed: bool,
    enabled: bool,
}

/// The request body: stable across retries.
fn envelope(st: &AppState, d: &Due) -> Vec<u8> {
    let mut data = d.payload.clone();
    // Links are added here, not stored, so they follow RMM_PUBLIC_URL.
    if let Some(id) = data["ticket"]["id"].as_str().map(str::to_string) {
        data["ticket"]["url"] = format!("{}/tickets/{id}", st.cfg.public_url).into();
    }
    if let Some(id) = data["agent"]["id"].as_str().map(str::to_string) {
        data["url"] = format!("{}/agents/{id}?tab=alerts", st.cfg.public_url).into();
    }
    serde_json::to_vec(&json!({ "id": d.delivery_id, "event": d.event, "created_at": d.created_at, "data": data })).unwrap_or_default()
}

/// Sends the due deliveries. Returns how many it took.
pub async fn drain(st: &AppState) -> anyhow::Result<usize> {
    // Claim with a lease: a crash mid-send retries after it expires instead of losing the row.
    let due: Vec<Due> = sqlx::query_as(
        "UPDATE webhook_deliveries SET attempts = attempts + 1, next_attempt_at = now() + interval '10 minutes'
          WHERE id IN (SELECT id FROM webhook_deliveries WHERE status = 'pending' AND next_attempt_at <= now()
                        ORDER BY id LIMIT $1 FOR UPDATE SKIP LOCKED)
          RETURNING id, subscription_id, delivery_id, event, payload, attempts, created_at",
    )
    .bind(BATCH)
    .fetch_all(&st.db)
    .await?;
    let n = due.len();
    // Slow receivers must not hold up the others.
    for r in futures_util::future::join_all(due.into_iter().map(|d| send_one(st, d))).await {
        r?;
    }
    Ok(n)
}

async fn send_one(st: &AppState, d: Due) -> sqlx::Result<()> {
    let started = Instant::now();
    let (result, status) = attempt(st, &d).await;
    let ms = started.elapsed().as_millis().min(i32::MAX as u128) as i32;
    match result {
        Ok(()) => {
            info!(delivery = %d.delivery_id, event = %d.event, "webhook delivered");
            sqlx::query(
                "UPDATE webhook_deliveries SET status = 'sent', sent_at = now(), last_error = NULL, response_status = $2, duration_ms = $3 WHERE id = $1",
            )
            .bind(d.id)
            .bind(status)
            .bind(ms)
            .execute(&st.db)
            .await?;
        }
        Err(err) => {
            let give_up = d.attempts >= crate::notify::MAX_ATTEMPTS || err.permanent;
            warn!(delivery = %d.delivery_id, event = %d.event, attempts = d.attempts, give_up, "webhook failed: {}", err.message);
            sqlx::query(
                "UPDATE webhook_deliveries SET status = CASE WHEN $2 THEN 'failed' ELSE 'pending' END, last_error = $3,
                        next_attempt_at = now() + make_interval(secs => $4), response_status = $5, duration_ms = $6
                  WHERE id = $1",
            )
            .bind(d.id)
            .bind(give_up)
            .bind(err.message.chars().take(1000).collect::<String>())
            .bind(crate::notify::backoff(d.attempts).num_seconds() as f64)
            .bind(status)
            .bind(ms)
            .execute(&st.db)
            .await?;
        }
    }
    Ok(())
}

struct Failure {
    message: String,
    /// Not worth retrying (the subscription is gone or switched off).
    permanent: bool,
}

async fn attempt(st: &AppState, d: &Due) -> (Result<(), Failure>, Option<i32>) {
    let permanent = |m: &str| (Err(Failure { message: m.into(), permanent: true }), None);
    let target: Target = match sqlx::query_as("SELECT url, secret, secret_sealed, enabled FROM webhook_subscriptions WHERE id = $1")
        .bind(d.subscription_id)
        .fetch_optional(&st.db)
        .await
    {
        Ok(Some(t)) => t,
        Ok(None) => return permanent("the subscription was deleted"),
        Err(e) => return (Err(Failure { message: e.to_string(), permanent: false }), None),
    };
    if !target.enabled && d.event != "ping" {
        return permanent("the subscription is disabled");
    }
    let Some(secret) = crate::crypto::load(st.cfg.data_key.as_ref(), &target.secret, target.secret_sealed) else {
        return permanent("the signing secret can't be read: RMM_DATA_KEY is missing or changed");
    };
    let body = envelope(st, d);
    let signature = crate::notify::sign(&String::from_utf8_lossy(&secret), &body);
    let res = st
        .http
        .post(&target.url)
        .header("content-type", "application/json")
        .header("x-rmm-event", &d.event)
        .header("x-rmm-delivery", d.delivery_id.to_string())
        .header("x-rmm-signature", format!("sha256={signature}"))
        .timeout(Duration::from_secs(15))
        .body(body)
        .send()
        .await;
    match res {
        Err(e) => (Err(Failure { message: format!("request failed: {e}"), permanent: false }), None),
        Ok(r) => {
            let status = r.status();
            let code = Some(i32::from(status.as_u16()));
            if status.is_success() {
                return (Ok(()), code);
            }
            let text = r.text().await.unwrap_or_default();
            let message = format!("HTTP {status}: {}", text.chars().take(300).collect::<String>().trim());
            (Err(Failure { message, permanent: false }), code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeline_entries_become_events() {
        let status = json!({ "field": "status", "from": "Open", "to": "Resolved", "category": "resolved" });
        let names: Vec<_> = ticket_events("change", false, 1, "", &status).into_iter().map(|e| e.0).collect();
        assert_eq!(names, ["ticket.status_changed", "ticket.resolved"]);
        let waiting = json!({ "field": "status", "from": "Open", "to": "Waiting", "category": "waiting_client" });
        assert_eq!(ticket_events("change", false, 1, "", &waiting).len(), 1);
        let (name, extra) = &ticket_events("change", false, 1, "", &json!({ "field": "priority", "from": 3, "to": 1 }))[0];
        assert_eq!(*name, "ticket.updated");
        assert_eq!(extra["change"]["field"], "priority");
        let (name, extra) = &ticket_events("note", false, 9, "hello", &json!({}))[0];
        assert_eq!((*name, extra["comment"]["public"].as_bool(), extra["comment"]["id"].as_i64()), ("ticket.comment", Some(false), Some(9)));
        assert_eq!(ticket_events("created", true, 1, "x", &json!({}))[0].0, "ticket.created");
        // Machine entries (alerts, jobs, SLA clocks, time) aren't webhook events.
        for k in ["alert", "job", "session", "sla", "csat", "time"] {
            assert!(ticket_events(k, false, 1, "", &json!({})).is_empty(), "{k}");
        }
        assert!(EVENTS.iter().all(|e| valid_event(e)) && !valid_event("ticket.deleted"));
    }

    #[test]
    fn the_secret_survives_sealing() {
        let key = crate::crypto::DataKey::parse(&"ab".repeat(32)).unwrap();
        let secret = new_secret();
        let (stored, sealed) = crate::crypto::store(Some(&key), secret.as_bytes());
        assert!(sealed && stored != secret.as_bytes());
        let back = crate::crypto::load(Some(&key), &stored, sealed).unwrap();
        assert_eq!(crate::notify::sign(&String::from_utf8_lossy(&back), b"body"), crate::notify::sign(&secret, b"body"));
    }

    #[test]
    fn urls_are_checked() {
        assert!(validate_url(" https://hooks.example.com/x ").is_ok());
        assert!(validate_url("http://127.0.0.1:9000/x").is_ok());
        for bad in ["ftp://x.test/", "hooks.example.com", "https://user:pw@x.test/", "javascript:alert(1)", ""] {
            assert!(validate_url(bad).is_err(), "{bad}");
        }
    }
}
