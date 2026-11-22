//! Notification delivery: an outbox (`notifications`) drained by a background worker.
//!
//! Each alert event × channel is one row. The worker claims due rows, renders the alert,
//! sends it, and retries failures with backoff (1, 5, 30 minutes, then 2 hours) until
//! [`MAX_ATTEMPTS`]. Rows survive restarts, so a mail server outage delays notifications
//! rather than losing them.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::Sha256;
use tracing::{info, warn};
use uuid::Uuid;

use crate::state::AppState;

pub const MAX_ATTEMPTS: i32 = 5;
const BATCH: i64 = 20;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Channel {
    pub id: Uuid,
    pub name: String,
    pub kind: String,
    pub config: Value,
    pub enabled: bool,
}

#[derive(Debug, Default, Deserialize)]
struct ChannelConfig {
    #[serde(default)]
    to: Vec<String>,
    #[serde(default)]
    url: String,
    #[serde(default)]
    secret: Option<String>,
}

/// Checks a channel's config before it's saved. Returns the normalised config.
pub fn validate_config(kind: &str, config: &Value) -> Result<Value, String> {
    let c: ChannelConfig = serde_json::from_value(config.clone()).map_err(|e| format!("invalid config: {e}"))?;
    match kind {
        "email" => {
            let to: Vec<String> = c.to.iter().map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect();
            if to.is_empty() || to.len() > 50 {
                return Err("add 1-50 recipient addresses".into());
            }
            for t in &to {
                t.parse::<lettre::Address>().map_err(|_| format!("{t} is not an email address"))?;
            }
            Ok(json!({ "to": to }))
        }
        "webhook" | "slack" | "teams" => {
            let url = c.url.trim();
            let parsed = reqwest::Url::parse(url).map_err(|_| "enter the full webhook URL".to_string())?;
            if !matches!(parsed.scheme(), "https" | "http") || parsed.host_str().is_none() {
                return Err("the webhook URL must start with https://".into());
            }
            let mut out = json!({ "url": url });
            if kind == "webhook"
                && let Some(s) = c.secret.as_deref().map(str::trim).filter(|s| !s.is_empty())
            {
                out["secret"] = s.into();
            }
            Ok(out)
        }
        _ => Err(format!("unknown channel type {kind}")),
    }
}

/// Queues `event` for an alert on each enabled channel in `channels`. Call
/// `st.notify_wake.notify_one()` afterwards (done by the alert engine).
pub async fn enqueue(st: &AppState, alert_id: Uuid, event: &str, channels: &[Uuid]) {
    if channels.is_empty() {
        return;
    }
    let res = sqlx::query(
        "INSERT INTO notifications (channel_id, alert_id, event)
         SELECT id, $1, $2 FROM notification_channels WHERE id = ANY($3) AND enabled",
    )
    .bind(alert_id)
    .bind(event)
    .bind(channels)
    .execute(&st.db)
    .await;
    if let Err(e) = res {
        warn!(%alert_id, "queueing notifications: {e}");
    }
}

pub(crate) fn backoff(attempts: i32) -> chrono::Duration {
    chrono::Duration::minutes(match attempts {
        1 => 1,
        2 => 5,
        3 => 30,
        _ => 120,
    })
}

pub async fn worker(st: Arc<AppState>) {
    loop {
        let full = match drain(&st).await {
            // A full batch: there may be more due right away.
            Ok(n) => n as i64 == BATCH,
            Err(e) => {
                warn!("notification worker: {e}");
                false
            }
        };
        // Ticket email shares the worker (and the mail server).
        let full_mail = match crate::email::drain_outbox(&st).await {
            Ok(n) => n >= 20,
            Err(e) => {
                warn!("email outbox: {e:#}");
                false
            }
        };
        let full_hooks = match crate::webhooks::drain(&st).await {
            Ok(n) => n as i64 == BATCH,
            Err(e) => {
                warn!("webhook worker: {e:#}");
                false
            }
        };
        if full || full_mail || full_hooks {
            continue;
        }
        tokio::select! {
            _ = st.notify_wake.notified() => {}
            _ = tokio::time::sleep(Duration::from_secs(30)) => {}
        }
    }
}

async fn drain(st: &AppState) -> anyhow::Result<usize> {
    // Claim with a lease: a crash mid-send retries after it expires instead of losing the row.
    #[allow(clippy::type_complexity)]
    let due: Vec<(i64, Uuid, Option<Uuid>, String, i32, Option<Uuid>, Value)> = sqlx::query_as(
        "UPDATE notifications SET attempts = attempts + 1, next_attempt_at = now() + interval '10 minutes'
          WHERE id IN (SELECT id FROM notifications WHERE status = 'pending' AND next_attempt_at <= now()
                        ORDER BY id LIMIT $1 FOR UPDATE SKIP LOCKED)
          RETURNING id, channel_id, alert_id, event, attempts, ticket_id, data",
    )
    .bind(BATCH)
    .fetch_all(&st.db)
    .await?;
    let n = due.len();
    for (id, channel_id, alert_id, event, attempts, ticket_id, data) in due {
        let result = async {
            let channel = load_channel(st, channel_id).await?.ok_or_else(|| "channel was deleted".to_string())?;
            let msg = match (alert_id, ticket_id) {
                (Some(a), _) => render(st, a, &event).await?,
                (None, Some(t)) => render_ticket(st, t, &event, &data).await?,
                (None, None) => test_message(st),
            };
            deliver(st, &channel, &msg).await
        }
        .await;
        let res = match result {
            Ok(()) => {
                sqlx::query("UPDATE notifications SET status = 'sent', sent_at = now(), last_error = NULL WHERE id = $1")
                    .bind(id)
                    .execute(&st.db)
                    .await
            }
            Err(err) => {
                let give_up = attempts >= MAX_ATTEMPTS;
                warn!(notification = id, attempts, give_up, "notification failed: {err}");
                sqlx::query(
                    "UPDATE notifications SET status = CASE WHEN $3 THEN 'failed' ELSE 'pending' END,
                            last_error = $2, next_attempt_at = now() + make_interval(secs => $4)
                      WHERE id = $1",
                )
                .bind(id)
                .bind(err.chars().take(1000).collect::<String>())
                .bind(give_up)
                .bind(backoff(attempts).num_seconds() as f64)
                .execute(&st.db)
                .await
            }
        };
        res?;
    }
    Ok(n)
}

async fn load_channel(st: &AppState, id: Uuid) -> Result<Option<Channel>, String> {
    sqlx::query_as("SELECT id, name, kind, config, enabled FROM notification_channels WHERE id = $1")
        .bind(id)
        .fetch_optional(&st.db)
        .await
        .map_err(|e| e.to_string())
}

/// A rendered notification, shared by every channel type.
#[derive(Debug, Clone)]
pub struct Message {
    pub event: String,
    pub subject: String,
    /// Plain-text body (email, and the details of chat messages).
    pub text: String,
    pub headline: String,
    pub severity: String,
    pub facts: Vec<(String, String)>,
    pub url: String,
    /// The webhook body.
    pub payload: Value,
}

#[derive(sqlx::FromRow)]
struct AlertCtx {
    id: Uuid,
    agent_id: Uuid,
    hostname: String,
    client_name: String,
    site_name: String,
    policy_name: Option<String>,
    kind: String,
    severity: String,
    title: String,
    details: Value,
    occurrences: i32,
    opened_at: DateTime<Utc>,
    resolved_at: Option<DateTime<Utc>>,
    resolution: Option<String>,
}

fn brand(st: &AppState) -> String {
    let name = st.company().company_name;
    if name.trim().is_empty() { "RMM".into() } else { name }
}

fn detail_lines(details: &Value) -> Vec<(String, String)> {
    let Some(obj) = details.as_object() else { return vec![] };
    obj.iter()
        .filter_map(|(k, v)| {
            let v = match v {
                Value::Null => return None,
                Value::String(s) if s.is_empty() => return None,
                Value::String(s) => s.clone(),
                Value::Number(_) | Value::Bool(_) => v.to_string(),
                _ => return None,
            };
            let label = k.replace('_', " ");
            let mut chars = label.chars();
            let label = chars.next().map(|c| c.to_uppercase().collect::<String>() + chars.as_str()).unwrap_or_default();
            Some((label, v))
        })
        .collect()
}

async fn render(st: &AppState, alert_id: Uuid, event: &str) -> Result<Message, String> {
    let a: AlertCtx = sqlx::query_as(
        "SELECT al.id, al.agent_id, a.hostname, c.name AS client_name, s.name AS site_name, p.name AS policy_name, al.kind,
                al.severity, al.title, al.details, al.occurrences, al.opened_at, al.resolved_at, al.resolution
           FROM alerts al JOIN agents a ON a.id = al.agent_id JOIN sites s ON s.id = a.site_id JOIN clients c ON c.id = s.client_id
           LEFT JOIN policy_items p ON p.id = al.policy_id
          WHERE al.id = $1",
    )
    .bind(alert_id)
    .fetch_optional(&st.db)
    .await
    .map_err(|e| e.to_string())?
    .ok_or_else(|| "alert was deleted".to_string())?;

    let resolved = event == "resolved";
    let url = format!("{}/agents/{}?tab=alerts", st.cfg.public_url, a.agent_id);
    let reminder = event == "reminder";
    let status = if resolved {
        "Resolved".to_string()
    } else if reminder {
        format!("Still open, {}", a.severity.to_uppercase())
    } else {
        a.severity.to_uppercase()
    };
    let headline = format!("{}: {} on {}", status, a.title, a.hostname);
    let subject = format!("[{}] {headline}", brand(st));
    let mut facts = vec![
        ("Agent".to_string(), a.hostname.clone()),
        ("Client".to_string(), format!("{} › {}", a.client_name, a.site_name)),
        ("Severity".to_string(), a.severity.clone()),
        ("Opened".to_string(), a.opened_at.format("%Y-%m-%d %H:%M:%S UTC").to_string()),
    ];
    if let Some(p) = &a.policy_name {
        facts.insert(2, ("Policy".to_string(), p.clone()));
    }
    if let Some(r) = a.resolved_at {
        facts.push(("Resolved".to_string(), r.format("%Y-%m-%d %H:%M:%S UTC").to_string()));
    }
    if a.occurrences > 1 {
        facts.push(("Occurrences".to_string(), a.occurrences.to_string()));
    }
    facts.extend(detail_lines(&a.details));
    let width = facts.iter().map(|(k, _)| k.chars().count()).max().unwrap_or(0) + 2;
    let text = format!(
        "{}\n\n{}\n\n{url}\n",
        if resolved {
            format!("Resolved: {}", a.title)
        } else if reminder {
            format!("Still open (since {}): {}", a.opened_at.format("%Y-%m-%d %H:%M UTC"), a.title)
        } else {
            a.title.clone()
        },
        facts.iter().map(|(k, v)| format!("{:width$}{v}", format!("{k}:"))).collect::<Vec<_>>().join("\n"),
    );
    let payload = json!({
        "event": event,
        "alert": {
            "id": a.id, "kind": a.kind, "severity": a.severity, "title": a.title, "details": a.details,
            "occurrences": a.occurrences, "opened_at": a.opened_at, "resolved_at": a.resolved_at, "resolution": a.resolution,
            "policy": a.policy_name,
        },
        "agent": { "id": a.agent_id, "hostname": a.hostname, "client": a.client_name, "site": a.site_name },
        "url": url,
    });
    Ok(Message { event: event.into(), subject, text, headline, severity: a.severity, facts, url, payload })
}

#[derive(sqlx::FromRow)]
struct TicketCtx {
    number: i64,
    subject: String,
    priority: i16,
    client_name: Option<String>,
    board_name: String,
    status_name: String,
    assignee_name: Option<String>,
    requester: Option<String>,
    source: String,
    created_at: DateTime<Utc>,
}

/// SLA warnings and breaches, and new tickets on a board.
async fn render_ticket(st: &AppState, ticket_id: Uuid, event: &str, data: &Value) -> Result<Message, String> {
    let t: TicketCtx = sqlx::query_as(
        "SELECT t.number, t.subject, t.priority, c.name AS client_name, b.name AS board_name, s.name AS status_name,
                u.name AS assignee_name, coalesce(co.name, nullif(t.requester_name, ''), nullif(t.requester_email, '')) AS requester,
                t.source, t.created_at
           FROM tickets t JOIN boards b ON b.id = t.board_id JOIN board_statuses s ON s.id = t.status_id
           LEFT JOIN clients c ON c.id = t.client_id LEFT JOIN users u ON u.id = t.assignee_id LEFT JOIN contacts co ON co.id = t.contact_id
          WHERE t.id = $1",
    )
    .bind(ticket_id)
    .fetch_optional(&st.db)
    .await
    .map_err(|e| e.to_string())?
    .ok_or_else(|| "ticket was deleted".to_string())?;
    let url = format!("{}/tickets/{ticket_id}", st.cfg.public_url);
    let target = data["target"].as_str().unwrap_or("resolve");
    let due = data["due"].as_str().and_then(|d| DateTime::parse_from_rfc3339(d).ok()).map(|d| d.with_timezone(&Utc));
    let (status, severity) = match event {
        "sla_breach" => (format!("{} target missed", crate::sla::target_label(target)), "critical"),
        "sla_warning" => (format!("{} due soon", crate::sla::target_label(target)), "warning"),
        _ => ("New ticket".to_string(), if t.priority <= 2 { "warning" } else { "info" }),
    };
    let headline = format!("{status}: T-{} {}", t.number, t.subject);
    let mut facts = vec![
        ("Ticket".to_string(), format!("T-{}", t.number)),
        ("Client".to_string(), t.client_name.clone().unwrap_or_else(|| "Triage".into())),
        ("Priority".to_string(), format!("P{}", t.priority)),
        ("Board".to_string(), t.board_name.clone()),
        ("Status".to_string(), t.status_name.clone()),
        ("Assignee".to_string(), t.assignee_name.clone().unwrap_or_else(|| "Unassigned".into())),
    ];
    if let Some(r) = &t.requester {
        facts.push(("Requester".to_string(), r.clone()));
    }
    if let Some(d) = due {
        facts.push(("Due".to_string(), d.format("%Y-%m-%d %H:%M UTC").to_string()));
    }
    let width = facts.iter().map(|(k, _)| k.chars().count()).max().unwrap_or(0) + 2;
    let text = format!(
        "{headline}\n\n{}\n\n{url}\n",
        facts.iter().map(|(k, v)| format!("{:width$}{v}", format!("{k}:"))).collect::<Vec<_>>().join("\n")
    );
    let payload = json!({
        "event": event,
        "ticket": {
            "id": ticket_id, "number": t.number, "subject": t.subject, "priority": t.priority, "client": t.client_name,
            "board": t.board_name, "status": t.status_name, "assignee": t.assignee_name, "source": t.source, "created_at": t.created_at,
        },
        "sla": if event.starts_with("sla_") { json!({ "target": target, "due": due }) } else { Value::Null },
        "url": url,
    });
    Ok(Message {
        event: event.into(),
        subject: format!("[{}] {headline}", brand(st)),
        text,
        headline,
        severity: severity.into(),
        facts,
        url,
        payload,
    })
}

fn test_message(st: &AppState) -> Message {
    let headline = "Test notification".to_string();
    Message {
        event: "test".into(),
        subject: format!("[{}] {headline}", brand(st)),
        text: format!("This is a test from {}. If you can read it, the channel works.\n\n{}\n", brand(st), st.cfg.public_url),
        headline,
        severity: "info".into(),
        facts: vec![],
        url: st.cfg.public_url.clone(),
        payload: json!({ "event": "test", "url": st.cfg.public_url }),
    }
}

/// Sends a test message now and reports what happened.
pub async fn send_test(st: &AppState, channel: &Channel) -> Result<(), String> {
    deliver(st, channel, &test_message(st)).await
}

async fn deliver(st: &AppState, channel: &Channel, msg: &Message) -> Result<(), String> {
    if !channel.enabled && msg.event != "test" {
        return Err("channel is disabled".into());
    }
    let cfg: ChannelConfig = serde_json::from_value(channel.config.clone()).unwrap_or_default();
    let res = match channel.kind.as_str() {
        "email" => send_email(st, &cfg.to, msg).await,
        "webhook" => {
            let body = serde_json::to_vec(&msg.payload).map_err(|e| e.to_string())?;
            let mut req = st.http.post(&cfg.url).header("content-type", "application/json").header("x-rmm-event", &msg.event);
            if let Some(secret) = cfg.secret.as_deref().filter(|s| !s.is_empty()) {
                req = req.header("x-rmm-signature", format!("sha256={}", sign(secret, &body)));
            }
            post(req.body(body)).await
        }
        "slack" => post(st.http.post(&cfg.url).json(&slack_body(msg))).await,
        "teams" => post(st.http.post(&cfg.url).json(&teams_body(msg))).await,
        other => Err(format!("unknown channel type {other}")),
    };
    if res.is_ok() {
        info!(channel = %channel.name, channel_id = %channel.id, event = %msg.event, "notification sent");
    }
    res
}

/// HMAC-SHA256 of the body with the channel secret, hex: the `X-RMM-Signature` header.
pub fn sign(secret: &str, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

async fn post(req: reqwest::RequestBuilder) -> Result<(), String> {
    let res = req.send().await.map_err(|e| format!("request failed: {e}"))?;
    let status = res.status();
    if status.is_success() {
        return Ok(());
    }
    let body = res.text().await.unwrap_or_default();
    Err(format!("HTTP {status}: {}", body.chars().take(300).collect::<String>().trim()))
}

fn slack_body(m: &Message) -> Value {
    let facts = m.facts.iter().map(|(k, v)| format!("*{k}:* {v}")).collect::<Vec<_>>().join("\n");
    json!({
        "text": m.subject,
        "blocks": [
            { "type": "section", "text": { "type": "mrkdwn", "text": format!("*{}*\n{facts}", m.headline) } },
            { "type": "actions", "elements": [{ "type": "button", "text": { "type": "plain_text", "text": "Open in RMM" }, "url": m.url }] },
        ],
    })
}

/// An Adaptive Card for a Teams Workflows incoming webhook.
fn teams_body(m: &Message) -> Value {
    let color = match (m.event.as_str(), m.severity.as_str()) {
        ("resolved", _) => "Good",
        (_, "critical") => "Attention",
        (_, "warning") => "Warning",
        _ => "Default",
    };
    json!({
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [
                    { "type": "TextBlock", "size": "Medium", "weight": "Bolder", "wrap": true, "color": color, "text": m.headline },
                    { "type": "FactSet", "facts": m.facts.iter().map(|(k, v)| json!({ "title": k, "value": v })).collect::<Vec<_>>() },
                ],
                "actions": [{ "type": "Action.OpenUrl", "title": "Open in RMM", "url": m.url }],
            },
        }],
    })
}

/// An SMTP transport for the company mail server, and the configured sender.
pub(crate) fn mailer(
    st: &AppState,
) -> Result<(lettre::AsyncSmtpTransport<lettre::Tokio1Executor>, lettre::message::Mailbox), String> {
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{AsyncSmtpTransport, Tokio1Executor};

    let c = st.company();
    if c.smtp_host.trim().is_empty() || c.smtp_from.trim().is_empty() {
        return Err("no mail server: set one up under Company settings → Notifications".into());
    }
    let host = c.smtp_host.trim();
    let builder = match c.smtp_security.as_str() {
        "tls" => AsyncSmtpTransport::<Tokio1Executor>::relay(host).map_err(|e| e.to_string())?,
        "starttls" => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host).map_err(|e| e.to_string())?,
        _ => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host),
    };
    let mut builder = builder.port(c.smtp_port as u16).timeout(Some(Duration::from_secs(30)));
    if !c.smtp_username.is_empty() {
        builder = builder.credentials(Credentials::new(c.smtp_username.clone(), c.smtp_password.clone()));
    }
    let from = c.smtp_from.trim().parse().map_err(|_| format!("sender address {:?} is invalid", c.smtp_from))?;
    Ok((builder.build(), from))
}

async fn send_email(st: &AppState, to: &[String], m: &Message) -> Result<(), String> {
    use lettre::AsyncTransport;
    use lettre::message::header::ContentType;

    let (mailer, from) = mailer(st)?;
    let mut email = lettre::Message::builder().from(from).subject(&m.subject);
    for t in to {
        email = email.to(t.parse().map_err(|_| format!("{t} is not an email address"))?);
    }
    let email = email.header(ContentType::TEXT_PLAIN).body(m.text.clone()).map_err(|e| e.to_string())?;
    mailer.send(email).await.map(drop).map_err(|e| format!("SMTP: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configs_are_validated_and_normalised() {
        assert_eq!(validate_config("email", &json!({ "to": [" a@b.co ", ""] })).unwrap(), json!({ "to": ["a@b.co"] }));
        assert!(validate_config("email", &json!({ "to": ["nope"] })).is_err());
        assert!(validate_config("email", &json!({})).is_err());
        assert!(validate_config("slack", &json!({ "url": "ftp://x" })).is_err());
        let w = validate_config("webhook", &json!({ "url": "https://h.example/x", "secret": " s " })).unwrap();
        assert_eq!(w, json!({ "url": "https://h.example/x", "secret": "s" }));
        assert!(validate_config("pager", &json!({})).is_err());
    }

    #[test]
    fn signature_is_hmac_sha256() {
        // RFC 4231 test case 2.
        assert_eq!(sign("Jefe", b"what do ya want for nothing?"), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    }

    #[test]
    fn details_become_readable_facts() {
        let f = detail_lines(&json!({ "exit_code": 2, "script": "Backup", "nested": {}, "none": null, "empty": "" }));
        assert_eq!(f, [("Exit code".to_string(), "2".to_string()), ("Script".to_string(), "Backup".to_string())]);
    }
}
