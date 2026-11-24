//! Email ↔ tickets.
//!
//! Inbound: mail arrives from an IMAP mailbox ([`poll_loop`]) or a provider webhook
//! (`api::inbound`), and [`receive`] files it: threads it onto an existing ticket (the
//! `[T-10423]` subject tag, then `In-Reply-To`/`References` against the Message-IDs we've
//! seen), or opens a new one. Automated mail (auto-replies, bulk, bounces) and mail from our
//! own addresses is recorded and ignored, so two systems can't reply to each other forever.
//! The raw MIME is kept in object storage.
//!
//! Outbound: replies, acknowledgements and assignment notices are rows in `email_messages`
//! (`direction = 'out'`), drained by [`drain_outbox`] from the notification worker, with
//! the same retry schedule as notifications.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use futures_util::StreamExt;
use mail_parser::{MessageParser, MessageRef};
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::{info, warn};
use uuid::Uuid;

use crate::state::AppState;
use crate::tickets::{self, Author, NewTicket};

/// Our replies carry this line; anything the client quotes below it is dropped.
pub const REPLY_MARKER: &str = "##- Reply above this line to update the ticket -##";
/// Acknowledgements to one address per hour, at most.
const AUTO_REPLIES_PER_HOUR: i64 = 3;
const MAX_ATTACHMENTS: usize = 20;
const MAX_ATTACHMENT_BYTES: usize = 10 * 1024 * 1024;
/// Stored event text, at most (the raw message keeps everything).
const MAX_BODY_CHARS: usize = 100_000;
/// Attachments emailed with a reply, in total; larger files stay on the ticket only.
const MAX_OUTBOUND_ATTACHMENTS: usize = 15 * 1024 * 1024;
pub const NOT_EMAIL: &str = "not an email message";

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Mailbox {
    pub id: Uuid,
    pub name: String,
    pub address: String,
    pub kind: String,
    pub imap_host: String,
    pub imap_port: i32,
    pub imap_security: String,
    pub imap_username: String,
    /// Sealed with RMM_DATA_KEY when the server has one (`imap_password_sealed`); see [`Mailbox::imap_password`].
    pub imap_password_enc: Option<Vec<u8>>,
    pub imap_password_sealed: bool,
    pub imap_folder: String,
    pub board_id: Uuid,
    pub auto_reply: bool,
    pub enabled: bool,
    pub graph_tenant: String,
    pub graph_client_id: String,
    pub graph_secret: Option<Vec<u8>>,
    pub graph_secret_sealed: bool,
}

impl Mailbox {
    /// The IMAP password, opened.
    pub fn imap_password(&self, key: Option<&crate::crypto::DataKey>) -> Result<String> {
        let Some(stored) = self.imap_password_enc.as_deref() else { return Ok(String::new()) };
        let plain = crate::crypto::load(key, stored, self.imap_password_sealed).context("the IMAP password can't be read: RMM_DATA_KEY is missing or changed")?;
        Ok(String::from_utf8_lossy(&plain).into_owned())
    }
}

pub const MAILBOX_COLS: &str = "id, name, address, kind, imap_host, imap_port, imap_security, imap_username, imap_password_enc, imap_password_sealed, imap_folder,
     board_id, auto_reply, enabled, graph_tenant, graph_client_id, graph_secret, graph_secret_sealed";

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

/// `[T-10423]` anywhere in the subject.
pub fn subject_ticket_number(subject: &str) -> Option<i64> {
    let mut rest = subject;
    while let Some(i) = rest.find("[T-") {
        let after = &rest[i + 3..];
        let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
        if !digits.is_empty() && after[digits.len()..].starts_with(']') {
            return digits.parse().ok();
        }
        rest = after;
    }
    None
}

/// The subject without reply prefixes and our tag: "Re: Printer [T-10001]" → "Printer".
pub fn clean_subject(subject: &str) -> String {
    let mut s = subject.trim();
    loop {
        let lower = s.to_ascii_lowercase();
        let Some(p) = ["re:", "fw:", "fwd:", "aw:", "sv:", "wg:"].iter().find(|p| lower.starts_with(**p)) else { break };
        s = s[p.len()..].trim_start();
    }
    let mut out = s.to_string();
    if let Some(n) = subject_ticket_number(&out) {
        out = out.replace(&format!("[T-{n}]"), "");
    }
    let out = out.split_whitespace().collect::<Vec<_>>().join(" ");
    if out.is_empty() { "(no subject)".into() } else { out.chars().take(300).collect() }
}

/// Drops the quoted history from a reply: everything from our reply marker, an "On ... wrote:"
/// line, Outlook's "-----Original Message-----" / "From: ... Sent:" header block, or a run of
/// `>` lines at the end.
pub fn strip_quoted(text: &str) -> String {
    let text = text.replace("\r\n", "\n");
    let lines: Vec<&str> = text.lines().collect();
    let mut cut = lines.len();
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim();
        let lower = t.to_ascii_lowercase();
        let header_block = (lower.starts_with("from:") || lower.starts_with("von:"))
            && lines[i + 1..].iter().take(4).any(|l| {
                let l = l.trim().to_ascii_lowercase();
                l.starts_with("sent:") || l.starts_with("date:") || l.starts_with("gesendet:")
            });
        let wrote = (lower.starts_with("on ") && (lower.ends_with("wrote:") || lower.ends_with("writes:")))
            // Gmail wraps long "On ... wrote:" lines.
            || (lower.starts_with("on ") && lines.get(i + 1).is_some_and(|n| n.trim().to_ascii_lowercase().ends_with("wrote:")))
            || (lower.starts_with("am ") && lower.ends_with("schrieb:"))
            || (lower.starts_with("le ") && lower.ends_with("a écrit :"));
        if t.contains(REPLY_MARKER)
            || wrote
            || t.starts_with("-----Original Message-----")
            || t.starts_with("________________________________")
            || header_block
        {
            cut = i;
            break;
        }
    }
    let mut kept = &lines[..cut];
    // A trailing run of quoted lines (inline replies above it are kept).
    while let Some(last) = kept.last() {
        let t = last.trim();
        if t.starts_with('>') || t.is_empty() {
            kept = &kept[..kept.len() - 1];
        } else {
            break;
        }
    }
    let out = kept.join("\n").trim().to_string();
    // Quoted-only replies (or a stripper mistake): keep the original rather than nothing.
    if out.is_empty() { text.trim().to_string() } else { out }
}

fn header_text(m: &MessageRef<'_>, name: &str) -> Option<String> {
    m.headers().get(name).map(|h| String::from_utf8_lossy(h.raw_value()).trim().to_ascii_lowercase())
}

/// Why this message must not be answered or turned into a ticket, if it's automated.
pub fn automated_reason(m: &MessageRef<'_>, from: &str) -> Option<&'static str> {
    if header_text(m, "Auto-Submitted").is_some_and(|v| !v.is_empty() && !v.starts_with("no")) {
        return Some("auto-submitted");
    }
    if header_text(m, "Precedence").is_some_and(|v| matches!(v.as_str(), "bulk" | "junk" | "list" | "auto_reply")) {
        return Some("bulk or list mail");
    }
    if header_text(m, "X-Autoreply").is_some() || header_text(m, "X-Autorespond").is_some() {
        return Some("auto-reply");
    }
    if header_text(m, "X-Auto-Response-Suppress").is_some_and(|v| v.contains("all") || v.contains("oof")) {
        return Some("auto-reply");
    }
    if m.content_type().is_some_and(|ct| ct.ctype().eq_ignore_ascii_case("multipart") && ct.subtype().is_some_and(|s| s.eq_ignore_ascii_case("report")))
    {
        return Some("delivery report");
    }
    let local = from.split('@').next().unwrap_or_default();
    if local.eq_ignore_ascii_case("mailer-daemon") || local.eq_ignore_ascii_case("postmaster") || from.is_empty() {
        return Some("bounce");
    }
    if header_text(m, "List-Id").is_some() {
        return Some("mailing list");
    }
    None
}

fn sanitize_filename(name: &str) -> String {
    let n: String = name.chars().filter(|c| !c.is_control() && !matches!(c, '/' | '\\')).take(200).collect();
    let n = n.trim().trim_start_matches('.').to_string();
    if n.is_empty() { "attachment".into() } else { n }
}

/// Domain for our Message-IDs: the sender's, else the public URL's host.
fn id_domain(st: &AppState) -> String {
    let from = st.company().smtp_from;
    from.rsplit_once('@')
        .map(|(_, d)| d.trim_end_matches('>').trim().to_string())
        .filter(|d| !d.is_empty())
        .or_else(|| reqwest::Url::parse(&st.cfg.public_url).ok().and_then(|u| u.host_str().map(str::to_string)))
        .unwrap_or_else(|| "rmm.invalid".into())
}

// ---------------------------------------------------------------------------
// Inbound
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub enum Outcome {
    /// Added to an existing ticket.
    Threaded(Uuid),
    Created(Uuid),
    Ignored(&'static str),
    /// Seen before (the same Message-ID).
    Duplicate,
}

/// Files one raw message that arrived at `mb`.
pub async fn receive(st: &AppState, mb: &Mailbox, raw: &[u8]) -> Result<Outcome> {
    let Some(msg) = MessageParser::default().parse(raw) else {
        anyhow::bail!(NOT_EMAIL);
    };
    let m = msg.root();
    let message_id = m
        .message_id()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("sha256-{}@rmm.invalid", hex::encode(Sha256::digest(raw))));
    let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM email_messages WHERE direction = 'in' AND message_id = $1)")
        .bind(&message_id)
        .fetch_one(&st.db)
        .await?;
    if exists {
        return Ok(Outcome::Duplicate);
    }
    // Identity is From, not Reply-To: matching a contact on Reply-To would let anyone post as them.
    let sender = m.from().and_then(|l| l.first());
    let from = sender.and_then(|s| s.address()).unwrap_or_default().trim().to_ascii_lowercase();
    let from_name = sender.and_then(|s| s.name()).unwrap_or_default().trim().to_string();
    let subject = m.subject().unwrap_or_default().trim().to_string();
    let in_reply_to: Option<String> = m.in_reply_to().and_then(|l| l.first().map(str::to_string));
    let references: Vec<String> = m.references().map(|l| l.iter().map(str::to_string).collect()).unwrap_or_default();
    let to: Vec<String> = m.to().map(|l| l.mailboxes().filter_map(|x| x.address()).map(str::to_ascii_lowercase).collect()).unwrap_or_default();
    let cc: Vec<String> = m.cc().map(|l| l.mailboxes().filter_map(|x| x.address()).map(str::to_ascii_lowercase).collect()).unwrap_or_default();

    let email_id = Uuid::new_v4();
    let now = chrono::Utc::now();
    let raw_key = format!("email/{}/{email_id}.eml", now.format("%Y/%m"));
    st.storage.put(&raw_key, raw.to_vec(), "message/rfc822").await.context("storing the raw message")?;

    // Claims the Message-ID: a concurrent delivery of the same message then stops here.
    let claim = |status: &'static str, reason: Option<&'static str>| {
        sqlx::query(
            "INSERT INTO email_messages (id, direction, mailbox_id, message_id, in_reply_to, \"references\",
                                         from_addr, to_addrs, cc_addrs, subject, raw_key, status, ignored_reason)
             VALUES ($1, 'in', $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
             ON CONFLICT (message_id) WHERE direction = 'in' DO NOTHING",
        )
        .bind(email_id)
        .bind(mb.id)
        .bind(&message_id)
        .bind(&in_reply_to)
        .bind(&references)
        .bind(&from)
        .bind(&to)
        .bind(&cc)
        .bind(&subject)
        .bind(&raw_key)
        .bind(status)
        .bind(reason)
    };

    // Loop protection: never act on mail from our own addresses or from robots.
    let own: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM mailboxes WHERE lower(address) = $1)")
        .bind(&from)
        .fetch_one(&st.db)
        .await?;
    let smtp_from = st.company().smtp_from.parse::<lettre::message::Mailbox>().ok().map(|m| m.email.to_string().to_ascii_lowercase());
    let reason = if own || from == mb.address || smtp_from.as_deref() == Some(from.as_str()) {
        Some("from one of our own addresses")
    } else {
        automated_reason(&m, &from)
    };
    if let Some(reason) = reason {
        claim("ignored", Some(reason)).execute(&st.db).await?;
        info!(mailbox = %mb.name, %from, reason, "ignored inbound email");
        return Ok(Outcome::Ignored(reason));
    }

    let text = m.body_text(0).map(|t| t.into_owned()).unwrap_or_default();
    let body: String = strip_quoted(&text).chars().take(MAX_BODY_CHARS).collect();

    let mut tx = st.db.begin().await?;
    let mut client_message = false;
    if claim("received", None).execute(&mut *tx).await?.rows_affected() == 0 {
        return Ok(Outcome::Duplicate);
    }
    // Threading: our tag first, then the Message-IDs it answers.
    let mut ticket: Option<(Uuid, Option<Uuid>, String)> = None;
    if let Some(n) = subject_ticket_number(&subject) {
        ticket = sqlx::query_as(
            "SELECT t.id, t.client_id, s.category FROM tickets t JOIN board_statuses s ON s.id = t.status_id WHERE t.number = $1",
        )
        .bind(n)
        .fetch_optional(&mut *tx)
        .await?;
    }
    if ticket.is_none() {
        let ids: Vec<String> = in_reply_to.iter().cloned().chain(references.iter().rev().cloned()).take(50).collect();
        if !ids.is_empty() {
            ticket = sqlx::query_as(
                "SELECT t.id, t.client_id, s.category FROM email_messages e JOIN tickets t ON t.id = e.ticket_id
                   JOIN board_statuses s ON s.id = t.status_id
                  WHERE e.message_id = ANY($1) ORDER BY e.created_at DESC LIMIT 1",
            )
            .bind(&ids)
            .fetch_optional(&mut *tx)
            .await?;
        }
    }
    // A merged ticket forwards to the one it went into.
    if let Some((id, _, _)) = &ticket {
        let target: Option<Uuid> =
            sqlx::query_scalar("SELECT merged_into FROM tickets WHERE id = $1").bind(id).fetch_one(&mut *tx).await?;
        if let Some(t) = target {
            ticket = sqlx::query_as(
                "SELECT t.id, t.client_id, s.category FROM tickets t JOIN board_statuses s ON s.id = t.status_id WHERE t.id = $1",
            )
            .bind(t)
            .fetch_optional(&mut *tx)
            .await?;
        }
    }

    let (ticket_id, event_id, outcome, followup_of) = match ticket {
        Some((id, client_id, category)) if category != "closed" => {
            let contact: Option<Uuid> = match client_id {
                Some(c) => sqlx::query_scalar("SELECT id FROM contacts WHERE client_id = $1 AND lower(email) = $2")
                    .bind(c)
                    .bind(&from)
                    .fetch_optional(&mut *tx)
                    .await?,
                None => None,
            };
            let author = Author { contact_id: contact, name: display_name(&from_name, &from), ..Default::default() };
            let ev = tickets::add_event(&mut tx, id, "message", true, &author, &body, json!({ "email_id": email_id, "from": from })).await?;
            client_message = true;
            // The client answered: back to work.
            if matches!(category.as_str(), "resolved" | "waiting_client") {
                let board: Uuid = sqlx::query_scalar("SELECT board_id FROM tickets WHERE id = $1").bind(id).fetch_one(&mut *tx).await?;
                if let Some(s) = tickets::status_of(&mut tx, board, "open").await? {
                    tickets::set_status(&mut tx, id, s, &Author::system("Email")).await?;
                }
            }
            (id, ev, Outcome::Threaded(id), None)
        }
        other => {
            // A new request (or a reply to a closed ticket, which starts a new one).
            let followup = other.map(|(id, _, _)| id);
            let (client_id, contact_id) = resolve_sender(&mut tx, &from).await?;
            let site_id: Option<Uuid> = match contact_id {
                Some(c) => sqlx::query_scalar("SELECT site_id FROM contacts WHERE id = $1").bind(c).fetch_one(&mut *tx).await?,
                None => None,
            };
            let created = tickets::create(
                &mut tx,
                NewTicket {
                    client_id,
                    site_id,
                    contact_id,
                    board_id: mb.board_id,
                    priority: 3,
                    subject: clean_subject(&subject),
                    body: body.clone(),
                    body_public: true,
                    source: "email",
                    requester_name: if contact_id.is_none() { from_name.clone() } else { String::new() },
                    requester_email: if contact_id.is_none() { from.clone() } else { String::new() },
                    mailbox_id: Some(mb.id),
                    author: Author { contact_id, name: display_name(&from_name, &from), ..Default::default() },
                    ..Default::default()
                },
            )
            .await?;
            (created.id, created.event_id, Outcome::Created(created.id), followup)
        }
    };
    if let Some(prev) = followup_of {
        let n: i64 = sqlx::query_scalar("SELECT number FROM tickets WHERE id = $1").bind(prev).fetch_one(&mut *tx).await?;
        tickets::add_event(&mut tx, ticket_id, "note", false, &Author::system("Email"), &format!("Follow-up to closed ticket T-{n}."), json!({ "ticket_id": prev }))
            .await?;
    }
    sqlx::query("UPDATE email_messages SET ticket_id = $2, event_id = $3 WHERE id = $1")
        .bind(email_id)
        .bind(ticket_id)
        .bind(event_id)
        .execute(&mut *tx)
        .await?;

    // Attachments: stored after the event exists so they hang off it.
    let mut stored = 0;
    for part in m.attachments() {
        if stored >= MAX_ATTACHMENTS {
            break;
        }
        let bytes = part.decoded();
        if bytes.is_empty() || bytes.len() > MAX_ATTACHMENT_BYTES {
            continue;
        }
        let name = sanitize_filename(part.attachment_name().unwrap_or(if part.is_message() { "message.eml" } else { "attachment" }));
        let ct = part
            .content_type()
            .map(|c| match c.subtype() {
                Some(s) => format!("{}/{}", c.ctype(), s),
                None => c.ctype().to_string(),
            })
            .unwrap_or_else(|| "application/octet-stream".into())
            .to_ascii_lowercase();
        let id = Uuid::new_v4();
        let key = format!("attachments/{id}");
        let sha = Sha256::digest(&bytes).to_vec();
        let size = bytes.len() as i64;
        st.storage.put(&key, bytes.into_owned(), &ct).await.context("storing an attachment")?;
        sqlx::query(
            "INSERT INTO ticket_attachments (id, ticket_id, event_id, name, content_type, size, sha256, storage_key)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(id)
        .bind(ticket_id)
        .bind(event_id)
        .bind(&name)
        .bind(&ct)
        .bind(size)
        .bind(sha)
        .bind(&key)
        .execute(&mut *tx)
        .await?;
        stored += 1;
    }
    tx.commit().await?;
    info!(mailbox = %mb.name, %from, ?outcome, "inbound email filed");

    if let Outcome::Created(id) = &outcome {
        tickets::notify_created(st, *id).await;
        if mb.auto_reply
            && let Err(e) = queue_acknowledgement(st, *id, &from, &message_id).await
        {
            warn!(ticket = %id, "queueing acknowledgement: {e}");
        }
    }
    if client_message && let Err(e) = queue_client_message(st, ticket_id, &display_name(&from_name, &from)).await {
        warn!(ticket = %ticket_id, "telling the assignee about a reply: {e:#}");
    }
    tickets::announce(st, ticket_id).await;
    Ok(outcome)
}

fn display_name(name: &str, addr: &str) -> String {
    if name.is_empty() { addr.to_string() } else { name.to_string() }
}

/// Sender → contact → client: an exact contact address first, then the clients' email
/// domains. Anything ambiguous or unknown goes to triage (no client). Contacts are never
/// created automatically.
pub async fn resolve_sender(db: &mut sqlx::PgConnection, from: &str) -> sqlx::Result<(Option<Uuid>, Option<Uuid>)> {
    let contacts: Vec<(Uuid, Uuid)> = sqlx::query_as("SELECT id, client_id FROM contacts WHERE lower(email) = $1 LIMIT 2")
        .bind(from)
        .fetch_all(&mut *db)
        .await?;
    if let [(contact, client)] = contacts.as_slice() {
        return Ok((Some(*client), Some(*contact)));
    }
    if !contacts.is_empty() {
        return Ok((None, None));
    }
    let Some((_, domain)) = from.rsplit_once('@') else { return Ok((None, None)) };
    let clients: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM clients WHERE $1 = ANY(email_domains) LIMIT 2").bind(domain).fetch_all(&mut *db).await?;
    Ok(match clients.as_slice() {
        [c] => (Some(*c), None),
        _ => (None, None),
    })
}

// ---------------------------------------------------------------------------
// Outbound
// ---------------------------------------------------------------------------

/// Where replies go (and, for a Graph mailbox, what sends them): the ticket's mailbox, else
/// the first enabled one.
async fn reply_mailbox(db: &sqlx::PgPool, ticket_mailbox: Option<Uuid>) -> sqlx::Result<Option<(Uuid, String)>> {
    sqlx::query_as(
        "SELECT id, address FROM mailboxes WHERE enabled AND (id = $1 OR $1 IS NULL OR NOT EXISTS (SELECT 1 FROM mailboxes WHERE id = $1 AND enabled))
          ORDER BY (id = $1) DESC NULLS LAST, created_at LIMIT 1",
    )
    .bind(ticket_mailbox)
    .fetch_optional(db)
    .await
}

#[derive(Default)]
struct Outgoing<'a> {
    ticket_id: Option<Uuid>,
    event_id: Option<i64>,
    to: Vec<String>,
    subject: String,
    body: String,
    reply_to: Option<String>,
    in_reply_to: Option<String>,
    references: Vec<String>,
    purpose: &'a str,
    /// The support mailbox it goes out from: a Graph mailbox that sends sends it itself.
    mailbox_id: Option<Uuid>,
    /// Stored files to attach: (name, content type, storage key).
    files: Vec<(String, String, String)>,
    /// Whose people it goes to: their client's branding (sender name, footer) applies.
    client_id: Option<Uuid>,
}


/// Whether mail from this mailbox goes out through Microsoft Graph.
async fn sends_via_graph(db: &sqlx::PgPool, mailbox: Option<Uuid>) -> sqlx::Result<bool> {
    let Some(m) = mailbox else { return Ok(false) };
    Ok(sqlx::query_scalar("SELECT kind = 'graph' AND graph_send AND enabled FROM mailboxes WHERE id = $1")
        .bind(m)
        .fetch_optional(db)
        .await?
        .unwrap_or(false))
}

/// Whether there's any way to send mail: the SMTP server, or a Graph mailbox for replies.
pub fn smtp_configured(st: &AppState) -> bool {
    let c = st.company();
    !c.smtp_host.trim().is_empty() && !c.smtp_from.trim().is_empty()
}

/// Inserts into the outbox (or records a failure straight away when there's no mail server).
async fn enqueue(st: &AppState, o: Outgoing<'_>) -> Result<Uuid> {
    let id = Uuid::new_v4();
    let message_id = format!("{}@{}", Uuid::new_v4().simple(), id_domain(st));
    let c = st.company();
    let configured = smtp_configured(st) || sends_via_graph(&st.db, o.mailbox_id).await?;
    let brand = crate::branding::resolve(st, o.client_id);
    let body = with_footer(&o.body, brand.email_footer.as_deref());
    sqlx::query(
        "INSERT INTO email_messages (id, direction, ticket_id, event_id, message_id, in_reply_to, \"references\", from_addr, to_addrs,
                                     reply_to, subject, body, status, purpose, last_error, mailbox_id, files, from_name)
         VALUES ($1, 'out', $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)",
    )
    .bind(id)
    .bind(o.ticket_id)
    .bind(o.event_id)
    .bind(&message_id)
    .bind(&o.in_reply_to)
    .bind(&o.references)
    .bind(c.smtp_from.trim())
    .bind(&o.to)
    .bind(&o.reply_to)
    .bind(&o.subject)
    .bind(&body)
    .bind(if configured { "pending" } else { "failed" })
    .bind(o.purpose)
    .bind((!configured).then_some("no mail server: set one up under Company settings → Notifications"))
    .bind(o.mailbox_id)
    .bind(serde_json::Value::Array(o.files.iter().map(|(n, c, k)| json!({ "name": n, "content_type": c, "key": k })).collect()))
    .bind(&brand.email_from_name)
    .execute(&st.db)
    .await?;
    if configured {
        st.notify_wake.notify_one();
    }
    Ok(id)
}

/// The branding footer under a plain-text body, after the usual "-- " separator.
fn with_footer(body: &str, footer: Option<&str>) -> String {
    match footer.map(str::trim).filter(|f| !f.is_empty()) {
        Some(f) => format!("{}\n\n-- \n{f}\n", body.trim_end()),
        None => body.to_string(),
    }
}

/// The thread so far, for In-Reply-To and References: the last message, and up to 20 ids.
async fn thread_of(db: &sqlx::PgPool, ticket_id: Uuid) -> sqlx::Result<(Option<String>, Vec<String>)> {
    let mut ids: Vec<String> = sqlx::query_scalar(
        "SELECT message_id FROM (SELECT message_id, created_at FROM email_messages WHERE ticket_id = $1
                                   ORDER BY created_at DESC LIMIT 20) t ORDER BY created_at",
    )
    .bind(ticket_id)
    .fetch_all(db)
    .await?;
    ids.dedup();
    Ok((ids.last().cloned(), ids))
}

#[derive(sqlx::FromRow)]
struct ReplyCtx {
    number: i64,
    subject: String,
    mailbox_id: Option<Uuid>,
    client_id: Option<Uuid>,
    recipient: Option<String>,
}

/// Emails a public reply to the ticket's contact (or the unknown sender who opened it).
/// Returns `None` when there's nobody to send it to.
pub async fn queue_reply(st: &AppState, ticket_id: Uuid, event_id: i64, body: &str, author: &str) -> Result<Option<Uuid>> {
    let c: ReplyCtx = sqlx::query_as(
        "SELECT t.number, t.subject, t.mailbox_id, t.client_id,
                coalesce(nullif(co.email, ''), nullif(t.requester_email, '')) AS recipient
           FROM tickets t LEFT JOIN contacts co ON co.id = t.contact_id WHERE t.id = $1",
    )
    .bind(ticket_id)
    .fetch_one(&st.db)
    .await?;
    let Some(to) = c.recipient else { return Ok(None) };
    let (in_reply_to, references) = thread_of(&st.db, ticket_id).await?;
    let mailbox = reply_mailbox(&st.db, c.mailbox_id).await?;
    let prefix = if in_reply_to.is_some() { "Re: " } else { "" };
    let brand = brand(st);
    let text = format!(
        "{REPLY_MARKER}\n\n{body}\n\n{author}\n{brand}\n\n--\nTicket T-{n}: {subject}. Reply to this email to add to it.\n",
        n = c.number,
        subject = c.subject
    );
    let id = enqueue(
        st,
        Outgoing {
            ticket_id: Some(ticket_id),
            event_id: Some(event_id),
            to: vec![to],
            subject: format!("{prefix}{} [T-{}]", c.subject, c.number),
            body: text,
            reply_to: mailbox.as_ref().map(|m| m.1.clone()),
            in_reply_to,
            references,
            purpose: "reply",
            mailbox_id: mailbox.map(|m| m.0),
            files: vec![],
            client_id: c.client_id,
        },
    )
    .await?;
    Ok(Some(id))
}

/// "We got your request": once per new emailed ticket, rate-limited per address.
async fn queue_acknowledgement(st: &AppState, ticket_id: Uuid, to: &str, in_reply_to: &str) -> Result<()> {
    let recent: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM email_messages WHERE purpose = 'auto_reply' AND lower(to_addrs[1]) = $1 AND created_at > now() - interval '1 hour'",
    )
    .bind(to)
    .fetch_one(&st.db)
    .await?;
    if recent >= AUTO_REPLIES_PER_HOUR {
        info!(%to, "not acknowledging: rate limit");
        return Ok(());
    }
    let (number, subject, mailbox, client_id): (i64, String, Option<Uuid>, Option<Uuid>) =
        sqlx::query_as("SELECT number, subject, mailbox_id, client_id FROM tickets WHERE id = $1").bind(ticket_id).fetch_one(&st.db).await?;
    let brand = brand(st);
    let mailbox = reply_mailbox(&st.db, mailbox).await?;
    enqueue(
        st,
        Outgoing {
            ticket_id: Some(ticket_id),
            event_id: None,
            to: vec![to.to_string()],
            subject: format!("Re: {subject} [T-{number}]"),
            body: format!(
                "{REPLY_MARKER}\n\nThanks, we've received your request and opened ticket T-{number}. \
                 We'll be in touch soon. To add anything, reply to this email.\n\n{brand}\n"
            ),
            reply_to: mailbox.as_ref().map(|m| m.1.clone()),
            in_reply_to: Some(in_reply_to.to_string()),
            references: vec![in_reply_to.to_string()],
            purpose: "auto_reply",
            mailbox_id: mailbox.map(|m| m.0),
            files: vec![],
            client_id,
        },
    )
    .await?;
    Ok(())
}

/// Emails a technician about a ticket: `subject` and `lead` get the ticket's number and
/// subject appended, and the body links to it. A no-op without a mail server.
async fn queue_staff(st: &AppState, ticket_id: Uuid, user_id: Uuid, subject: &str, lead: &str, purpose: &str) -> Result<()> {
    // The person's devices, and whether they still want the email (Account → Notifications).
    let event = match purpose {
        "assigned" => "ticket_assigned",
        "client_message" => "ticket_reply",
        _ => "sla_warning",
    };
    if !crate::push::ticket_event(st, user_id, event, ticket_id, subject).await {
        return Ok(());
    }
    if !smtp_configured(st) {
        return Ok(()); // nothing to do without a mail server, and no point recording failures
    }
    let row: Option<(String, i64, String)> = sqlx::query_as(
        "SELECT u.email, t.number, t.subject FROM users u, tickets t WHERE u.id = $1 AND t.id = $2 AND NOT u.disabled",
    )
    .bind(user_id)
    .bind(ticket_id)
    .fetch_optional(&st.db)
    .await?;
    let Some((email, number, ticket_subject)) = row else { return Ok(()) };
    enqueue(
        st,
        Outgoing {
            to: vec![email],
            subject: format!("[{}] T-{number} {subject}: {ticket_subject}", brand(st)),
            body: format!("{lead}\n\nT-{number}: {ticket_subject}\n\n{}/tickets/{ticket_id}\n", st.cfg.public_url),
            purpose,
            ..Default::default()
        },
    )
    .await?;
    Ok(())
}

/// Tells a technician a ticket was assigned to them.
pub async fn queue_assigned(st: &AppState, ticket_id: Uuid, user_id: Uuid, by: &str) -> Result<()> {
    queue_staff(st, ticket_id, user_id, "assigned to you", &format!("{by} assigned this ticket to you."), "assigned").await
}

/// Tells the assignee the client wrote (by email or in the portal).
pub async fn queue_client_message(st: &AppState, ticket_id: Uuid, from: &str) -> Result<()> {
    let assignee: Option<Uuid> =
        sqlx::query_scalar("SELECT assignee_id FROM tickets WHERE id = $1").bind(ticket_id).fetch_optional(&st.db).await?.flatten();
    match assignee {
        Some(a) => queue_staff(st, ticket_id, a, "new reply", &format!("{from} replied."), "client_message").await,
        None => Ok(()),
    }
}

/// Tells the assignee about SLA warnings and breaches on their ticket.
pub async fn queue_sla(st: &AppState, ticket_id: Uuid, user_id: Uuid, events: &[(&str, bool)]) -> Result<()> {
    let breached = events.iter().any(|(_, b)| *b);
    let lines: Vec<String> = events
        .iter()
        .map(|(k, b)| format!("{}: {}", crate::sla::target_label(k), if *b { "missed" } else { "75% of the time used" }))
        .collect();
    let subject = if breached { "missed its SLA" } else { "SLA warning" };
    queue_staff(st, ticket_id, user_id, subject, &lines.join("\n"), "sla").await
}

/// A portal sign-in link or invitation.
pub async fn queue_portal_link(st: &AppState, client_id: Uuid, to: &str, name: &str, url: &str, invite: bool) -> Result<()> {
    let brand = brand(st);
    let (subject, lead) = if invite {
        (format!("You're invited to the {brand} support portal"), format!("Hello {name},\n\n{brand} invited you to its support portal, where you can open tickets, follow them and reply."))
    } else {
        (format!("Sign in to {brand} support"), format!("Hello {name},\n\nUse this link to sign in to the {brand} support portal."))
    };
    let mailbox = reply_mailbox(&st.db, None).await?;
    enqueue(
        st,
        Outgoing {
            to: vec![to.to_string()],
            subject,
            body: format!(
                "{lead}\n\n{url}\n\nThe link works once and expires in {} minutes. If you didn't ask for it, ignore this email.\n\n{brand}\n",
                crate::api::PORTAL_LINK_MINUTES
            ),
            purpose: "portal_link",
            mailbox_id: mailbox.map(|m| m.0),
            client_id: Some(client_id),
            ..Default::default()
        },
    )
    .await?;
    Ok(())
}

/// An invoice (or credit note) with its PDF, to the client's billing contacts.
pub async fn queue_invoice(st: &AppState, client_id: Uuid, to: Vec<String>, subject: String, body: String, pdf: (String, String)) -> Result<Uuid> {
    let mailbox = reply_mailbox(&st.db, None).await?;
    enqueue(
        st,
        Outgoing {
            to,
            subject,
            body,
            reply_to: mailbox.as_ref().map(|m| m.1.clone()),
            purpose: "invoice",
            mailbox_id: mailbox.map(|m| m.0),
            files: vec![(pdf.0, "application/pdf".into(), pdf.1)],
            client_id: Some(client_id),
            ..Default::default()
        },
    )
    .await
}

/// A scheduled report's PDF to one recipient (crate::reports). Returns the message id and
/// whether it can go out (`false`: no mail server, so the outbox recorded it as failed).
/// `client_id` is the report's client, whose branding (sender name, footer) the mail carries.
pub async fn queue_report(st: &AppState, to: String, subject: String, body: String, pdf: (String, String), client_id: Option<Uuid>) -> Result<(Uuid, bool)> {
    let mailbox = reply_mailbox(&st.db, None).await?;
    let id = enqueue(
        st,
        Outgoing {
            to: vec![to],
            subject,
            body,
            reply_to: mailbox.as_ref().map(|m| m.1.clone()),
            purpose: "report",
            mailbox_id: mailbox.map(|m| m.0),
            files: vec![(pdf.0, "application/pdf".into(), pdf.1)],
            client_id,
            ..Default::default()
        },
    )
    .await?;
    let ok: bool = sqlx::query_scalar("SELECT status <> 'failed' FROM email_messages WHERE id = $1").bind(id).fetch_one(&st.db).await?;
    Ok((id, ok))
}

/// Tells an account manager a block-hours contract is running low.
pub async fn queue_staff_note(st: &AppState, user_id: Uuid, subject: &str, body: &str) -> Result<()> {
    if !smtp_configured(st) {
        return Ok(());
    }
    let email: Option<String> =
        sqlx::query_scalar("SELECT email FROM users WHERE id = $1 AND NOT disabled").bind(user_id).fetch_optional(&st.db).await?;
    let Some(email) = email else { return Ok(()) };
    enqueue(st, Outgoing { to: vec![email], subject: format!("[{}] {subject}", brand(st)), body: body.into(), purpose: "low_balance", ..Default::default() })
        .await?;
    Ok(())
}

/// "How did we do?" after a ticket is resolved, with one-click links.
pub async fn queue_survey(st: &AppState, ticket_id: Uuid, to: &str, token: &str) -> Result<()> {
    let (number, subject, mailbox, client_id): (i64, String, Option<Uuid>, Option<Uuid>) =
        sqlx::query_as("SELECT number, subject, mailbox_id, client_id FROM tickets WHERE id = $1").bind(ticket_id).fetch_one(&st.db).await?;
    let brand = brand(st);
    let base = format!("{}/feedback/{token}", st.cfg.public_url);
    let mailbox = reply_mailbox(&st.db, mailbox).await?;
    enqueue(
        st,
        Outgoing {
            ticket_id: Some(ticket_id),
            to: vec![to.to_string()],
            subject: format!("How did we do? {subject} [T-{number}]"),
            body: format!(
                "We've resolved ticket T-{number}: {subject}\n\nHow did we do? One click is enough:\n\nGood: {base}?rating=good\nBad:  {base}?rating=bad\n\nThanks,\n{brand}\n"
            ),
            reply_to: mailbox.as_ref().map(|m| m.1.clone()),
            purpose: "survey",
            mailbox_id: mailbox.map(|m| m.0),
            client_id,
            ..Default::default()
        },
    )
    .await?;
    Ok(())
}

pub(crate) fn brand(st: &AppState) -> String {
    let n = st.company().company_name;
    if n.trim().is_empty() { "Support".into() } else { n }
}

#[derive(sqlx::FromRow)]
struct OutRow {
    id: Uuid,
    event_id: Option<i64>,
    message_id: String,
    in_reply_to: Option<String>,
    references: Vec<String>,
    to_addrs: Vec<String>,
    reply_to: Option<String>,
    subject: String,
    body: String,
    purpose: Option<String>,
    attempts: i32,
    mailbox_id: Option<Uuid>,
    files: serde_json::Value,
    from_name: Option<String>,
}

const OUTBOX_BATCH: i64 = 20;

/// Sends due outbound mail. Returns how many rows it claimed.
pub async fn drain_outbox(st: &AppState) -> Result<usize> {
    let due: Vec<OutRow> = sqlx::query_as(
        "UPDATE email_messages SET attempts = attempts + 1, next_attempt_at = now() + interval '10 minutes'
          WHERE id IN (SELECT id FROM email_messages WHERE direction = 'out' AND status = 'pending' AND next_attempt_at <= now()
                        ORDER BY created_at LIMIT $1 FOR UPDATE SKIP LOCKED)
          RETURNING id, event_id, message_id, in_reply_to, \"references\", to_addrs, reply_to, subject, body, purpose, attempts, mailbox_id, files, from_name",
    )
    .bind(OUTBOX_BATCH)
    .fetch_all(&st.db)
    .await?;
    let n = due.len();
    for row in due {
        match send(st, &row).await {
            Ok(()) => {
                sqlx::query("UPDATE email_messages SET status = 'sent', sent_at = now(), last_error = NULL WHERE id = $1")
                    .bind(row.id)
                    .execute(&st.db)
                    .await?;
            }
            Err(err) => {
                let give_up = row.attempts >= crate::notify::MAX_ATTEMPTS;
                warn!(email = %row.id, attempts = row.attempts, give_up, "sending email failed: {err}");
                sqlx::query(
                    "UPDATE email_messages SET status = CASE WHEN $3 THEN 'failed' ELSE 'pending' END, last_error = $2,
                            next_attempt_at = now() + make_interval(secs => $4)
                      WHERE id = $1",
                )
                .bind(row.id)
                .bind(err.chars().take(1000).collect::<String>())
                .bind(give_up)
                .bind(crate::notify::backoff(row.attempts).num_seconds() as f64)
                .execute(&st.db)
                .await?;
            }
        }
    }
    Ok(n)
}

async fn send(st: &AppState, r: &OutRow) -> Result<(), String> {
    use lettre::message::header::{ContentType, HeaderName, HeaderValue};
    use lettre::message::Mailbox as LMailbox;

    // A Graph mailbox sends its own mail, from its own address.
    let graph: Option<Mailbox> = match r.mailbox_id {
        Some(m) => sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {MAILBOX_COLS} FROM mailboxes WHERE id = $1 AND kind = 'graph' AND graph_send AND enabled"
        )))
        .bind(m)
        .fetch_optional(&st.db)
        .await
        .map_err(|e| e.to_string())?,
        None => None,
    };
    let (mailer, from) = match &graph {
        Some(mb) => (None, mb.address.parse::<LMailbox>().map_err(|_| format!("{} is not an email address", mb.address))?),
        None => {
            let (m, f) = crate::notify::mailer(st)?;
            (Some(m), f)
        }
    };
    // Queued before branding existed: the instance's sender name.
    let name = r.from_name.clone().filter(|n| !n.trim().is_empty()).unwrap_or_else(|| crate::branding::resolve(st, None).email_from_name);
    let from = LMailbox::new(Some(name), from.email);
    let mut b = lettre::Message::builder().from(from).subject(&r.subject).message_id(Some(format!("<{}>", r.message_id)));
    for t in &r.to_addrs {
        b = b.to(t.parse().map_err(|_| format!("{t} is not an email address"))?);
    }
    if let Some(rt) = r.reply_to.as_deref().and_then(|a| a.parse().ok()) {
        b = b.reply_to(rt);
    }
    if let Some(irt) = &r.in_reply_to {
        b = b.in_reply_to(format!("<{irt}>"));
    }
    if !r.references.is_empty() {
        b = b.references(r.references.iter().map(|x| format!("<{x}>")).collect::<Vec<_>>().join(" "));
    }
    if r.purpose.as_deref() == Some("auto_reply") {
        b = b.raw_header(HeaderValue::new(HeaderName::new_from_ascii_str("Auto-Submitted"), "auto-replied".into()));
    } else if matches!(r.purpose.as_deref(), Some("assigned" | "client_message" | "sla" | "portal_link" | "survey" | "invoice" | "low_balance")) {
        b = b.raw_header(HeaderValue::new(HeaderName::new_from_ascii_str("Auto-Submitted"), "auto-generated".into()));
    }
    // A reply's attachments go with it, up to a total that mail servers accept. The rest
    // become links (chosen by the recorded size, so a large file is never read to find out).
    let mut files: Vec<OutFile> = match r.event_id {
        Some(ev) => sqlx::query_as(
            "SELECT id, name, content_type, storage_key, size, ticket_id FROM ticket_attachments WHERE event_id = $1 ORDER BY created_at",
        )
        .bind(ev)
        .fetch_all(&st.db)
        .await
        .map_err(|e| e.to_string())?,
        None => vec![],
    };
    for f in r.files.as_array().into_iter().flatten() {
        if let (Some(n), Some(c), Some(k)) = (f["name"].as_str(), f["content_type"].as_str(), f["key"].as_str()) {
            // Generated files (invoice PDFs): small, but check the stored size anyway.
            let size = st.storage.size(k).await.map_err(|e| format!("{e:#}"))? as i64;
            files.push(OutFile { id: None, name: n.into(), content_type: c.into(), storage_key: k.into(), size, ticket_id: None });
        }
    }
    let email = if files.is_empty() {
        b.header(ContentType::TEXT_PLAIN).body(r.body.clone()).map_err(|e| e.to_string())?
    } else {
        use lettre::message::{Attachment, MultiPart, SinglePart};
        let mut attached = vec![];
        let mut links = vec![];
        let mut total = 0i64;
        for f in files {
            if total + f.size > MAX_OUTBOUND_ATTACHMENTS as i64 {
                links.push(f);
                continue;
            }
            total += f.size;
            attached.push(f);
        }
        let mut body = r.body.clone();
        if !links.is_empty() {
            let to = r.to_addrs.first().map(String::as_str).unwrap_or_default();
            body.push_str(&too_large_section(st, to, &links).await.map_err(|e| format!("{e:#}"))?);
            info!(email = %r.id, files = links.len(), "attachments too large to email; sent as links");
        }
        let mut parts = MultiPart::mixed().singlepart(SinglePart::plain(body));
        for f in attached {
            let bytes = st.storage.get(&f.storage_key).await.map_err(|e| format!("{e:#}"))?;
            let ct = ContentType::parse(&f.content_type).unwrap_or(ContentType::parse("application/octet-stream").expect("valid"));
            parts = parts.singlepart(Attachment::new(f.name).body(bytes, ct));
        }
        b.multipart(parts).map_err(|e| e.to_string())?
    };
    match (mailer, graph) {
        (Some(m), _) => {
            use lettre::AsyncTransport;
            m.send(email).await.map(drop).map_err(|e| format!("SMTP: {e}"))
        }
        (None, Some(mb)) => crate::graph::send(st, &mb, &email.formatted()).await,
        (None, None) => Err("no way to send mail".into()),
    }
}

#[derive(sqlx::FromRow)]
struct OutFile {
    /// The ticket attachment (none for generated files such as invoice PDFs).
    id: Option<Uuid>,
    name: String,
    content_type: String,
    storage_key: String,
    size: i64,
    ticket_id: Option<Uuid>,
}

/// Links in place of attachments over the email cap.
pub const ATTACHMENT_LINK_DAYS: i64 = 30;

/// The part of the message listing files that were too large to attach: a portal link for
/// a contact who can sign in there, otherwise a download link per file that works without an
/// account (a random token, like the satisfaction survey's, valid [`ATTACHMENT_LINK_DAYS`]).
async fn too_large_section(st: &AppState, to: &str, files: &[OutFile]) -> Result<String> {
    let base = &st.cfg.public_url;
    let ticket = files.iter().find_map(|f| f.ticket_id);
    let portal = match ticket {
        Some(t) => sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM tickets t JOIN contacts co ON co.client_id = t.client_id
                             WHERE t.id = $1 AND lower(co.email) = lower($2) AND co.portal_enabled)",
        )
        .bind(t)
        .bind(to)
        .fetch_one(&st.db)
        .await?,
        None => false,
    };
    let mut out = String::from("\n\nToo large to attach");
    if let (true, Some(t)) = (portal, ticket) {
        out.push_str(&format!(", in the portal at {base}/portal/tickets/{t}:\n"));
        for f in files {
            out.push_str(&format!("  {} ({})\n", f.name, human_size(f.size)));
        }
        return Ok(out);
    }
    out.push_str(&format!(" (links valid for {ATTACHMENT_LINK_DAYS} days):\n"));
    for f in files {
        match f.id {
            Some(id) => {
                let token = crate::auth::random_token();
                sqlx::query("INSERT INTO attachment_links (token_hash, attachment_id, expires_at) VALUES ($1, $2, now() + make_interval(days => $3))")
                    .bind(crate::auth::token_hash(&token))
                    .bind(id)
                    .bind(ATTACHMENT_LINK_DAYS as i32)
                    .execute(&st.db)
                    .await?;
                out.push_str(&format!("  {} ({}): {base}/api/files/{token}\n", f.name, human_size(f.size)));
            }
            None => out.push_str(&format!("  {} ({}): ask us for a copy\n", f.name, human_size(f.size))),
        }
    }
    Ok(out)
}

fn human_size(n: i64) -> String {
    let n = n.max(0) as f64;
    if n >= 1024.0 * 1024.0 { format!("{:.1} MB", n / 1048576.0) } else { format!("{:.0} KB", (n / 1024.0).ceil()) }
}

// ---------------------------------------------------------------------------
// IMAP
// ---------------------------------------------------------------------------

/// Polls every enabled IMAP mailbox every `secs`.
pub async fn poll_loop(st: Arc<AppState>, secs: u32) {
    let mut tick = tokio::time::interval(Duration::from_secs(secs.max(10) as u64));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let boxes: Vec<Mailbox> = match sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {MAILBOX_COLS} FROM mailboxes WHERE enabled AND kind IN ('imap', 'graph')"
        )))
        .fetch_all(&st.db)
        .await
        {
            Ok(b) => b,
            Err(e) => {
                warn!("loading mailboxes: {e}");
                continue;
            }
        };
        for mb in boxes {
            let _ = poll_now(&st, &mb).await;
        }
    }
}

/// Polls one mailbox and records the outcome on it. Returns how many messages were filed.
pub async fn poll_now(st: &AppState, mb: &Mailbox) -> Result<usize, String> {
    let work = async {
        if mb.kind == "graph" { crate::graph::poll(st, mb).await } else { poll(st, mb).await }
    };
    let res = tokio::time::timeout(Duration::from_secs(120), work).await.unwrap_or_else(|_| Err(anyhow::anyhow!("timed out")));
    let err = res.as_ref().err().map(|e| format!("{e:#}"));
    if let Some(e) = &err {
        warn!(mailbox = %mb.name, "polling mailbox: {e}");
    }
    let _ = sqlx::query("UPDATE mailboxes SET last_polled_at = now(), last_error = $2 WHERE id = $1")
        .bind(mb.id)
        .bind(&err)
        .execute(&st.db)
        .await;
    res.map_err(|e| format!("{e:#}"))
}

async fn poll(st: &AppState, mb: &Mailbox) -> Result<usize> {
    let tcp = tokio::net::TcpStream::connect((mb.imap_host.as_str(), mb.imap_port as u16))
        .await
        .with_context(|| format!("connecting to {}:{}", mb.imap_host, mb.imap_port))?;
    if mb.imap_security == "none" {
        return fetch_all(st, mb, async_imap::Client::new(tcp)).await;
    }
    let mut roots = tokio_rustls::rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    let config = tokio_rustls::rustls::ClientConfig::builder_with_provider(Arc::new(tokio_rustls::rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = tokio_rustls::rustls::pki_types::ServerName::try_from(mb.imap_host.clone()).context("IMAP host name")?;
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, tcp).await.context("TLS handshake")?;
    fetch_all(st, mb, async_imap::Client::new(tls)).await
}

/// Files unseen messages (at most 50 per poll), marking each seen once it's stored.
async fn fetch_all<T>(st: &AppState, mb: &Mailbox, mut client: async_imap::Client<T>) -> Result<usize>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + std::fmt::Debug + Send,
{
    client.read_response().await?.context("no IMAP greeting")?;
    let password = mb.imap_password(st.cfg.data_key.as_ref())?;
    let mut session = client.login(&mb.imap_username, &password).await.map_err(|(e, _)| anyhow::anyhow!("login: {e}"))?;
    session.select(&mb.imap_folder).await.with_context(|| format!("selecting {}", mb.imap_folder))?;
    let mut uids: Vec<u32> = session.uid_search("UNSEEN").await?.into_iter().collect();
    uids.sort_unstable();
    uids.truncate(50);
    let mut filed = 0;
    for uid in uids {
        let raw = {
            let mut stream = session.uid_fetch(uid.to_string(), "BODY.PEEK[]").await?;
            let mut raw = None;
            while let Some(f) = stream.next().await {
                let f = f?;
                if let Some(b) = f.body() {
                    raw = Some(b.to_vec());
                }
            }
            raw
        };
        let Some(raw) = raw else { continue };
        match receive(st, mb, &raw).await {
            Ok(_) => {
                filed += 1;
                let mut s = session.uid_store(uid.to_string(), "+FLAGS (\\Seen)").await?;
                while s.next().await.is_some() {}
            }
            // Left unseen, so the next poll retries it.
            Err(e) => warn!(mailbox = %mb.name, uid, "filing message: {e:#}"),
        }
    }
    let _ = session.logout().await;
    Ok(filed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subject_tags() {
        assert_eq!(subject_ticket_number("Re: Printer [T-10423]"), Some(10423));
        assert_eq!(subject_ticket_number("[T-] nope [T-12x] [T-7]"), Some(7));
        assert_eq!(subject_ticket_number("T-10423"), None);
        assert_eq!(clean_subject("RE: Fwd: Printer jammed [T-10001] "), "Printer jammed");
        assert_eq!(clean_subject("  "), "(no subject)");
    }

    #[test]
    fn strips_quoted_replies() {
        let gmail = "Thanks, that fixed it.\n\nOn Mon, 9 Nov 2026 at 10:00, Support <help@msp.example> wrote:\n> Try restarting.\n";
        assert_eq!(strip_quoted(gmail), "Thanks, that fixed it.");
        let ours = format!("Still broken.\r\n\r\n{REPLY_MARKER}\r\n\r\nTry restarting.\r\n");
        assert_eq!(strip_quoted(&ours), "Still broken.");
        let outlook = "Yes please.\n\nFrom: Support <help@msp.example>\nSent: Monday, 9 November 2026 10:00\nTo: Ann\nSubject: Re: x\n\nOld text";
        assert_eq!(strip_quoted(outlook), "Yes please.");
        let inline = "> Can you reboot tonight?\nYes, after 6pm.\n\n> Old\n> more\n";
        assert_eq!(strip_quoted(inline), "> Can you reboot tonight?\nYes, after 6pm.");
        // Only quotes: keep it all rather than store nothing.
        assert_eq!(strip_quoted("> just a quote"), "> just a quote");
        let wrapped = "Done.\n\nOn Mon, 9 Nov 2026 at 10:00, A Very Long Name <someone@example.com>\nwrote:\n> x";
        assert_eq!(strip_quoted(wrapped), "Done.");
    }

    fn parse(raw: &str) -> (mail_parser::Message<'_>, String) {
        let m = MessageParser::default().parse(raw.as_bytes()).unwrap();
        let from = m.root().from().and_then(|l| l.first()).and_then(|a| a.address()).unwrap_or_default().to_string();
        (m, from)
    }

    #[test]
    fn detects_automated_mail() {
        let cases = [
            ("From: a@x.co\r\nAuto-Submitted: auto-replied\r\nSubject: Out of office\r\n\r\nbye\r\n", Some("auto-submitted")),
            ("From: a@x.co\r\nAuto-Submitted: no\r\nSubject: hi\r\n\r\nhello\r\n", None),
            ("From: a@x.co\r\nPrecedence: bulk\r\nSubject: news\r\n\r\nx\r\n", Some("bulk or list mail")),
            ("From: MAILER-DAEMON@x.co\r\nSubject: Undelivered\r\n\r\nx\r\n", Some("bounce")),
            (
                "From: a@x.co\r\nContent-Type: multipart/report; report-type=delivery-status; boundary=b\r\n\r\n--b\r\n\r\nx\r\n--b--\r\n",
                Some("delivery report"),
            ),
            ("From: Ann <ann@client.example>\r\nSubject: Printer\r\n\r\nIt's jammed\r\n", None),
        ];
        for (raw, want) in cases {
            let (m, from) = parse(raw);
            assert_eq!(automated_reason(&m.root(), &from.to_ascii_lowercase()), want, "{raw}");
        }
    }

    #[test]
    fn filenames_are_sanitised() {
        assert_eq!(sanitize_filename("../../etc/passwd"), "etcpasswd");
        assert_eq!(sanitize_filename(".htaccess"), "htaccess");
        assert_eq!(sanitize_filename("  "), "attachment");
        assert_eq!(sanitize_filename("report q3.pdf"), "report q3.pdf");
    }
}
