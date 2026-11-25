//! The tray app on devices (docs/design/tray.md): what it shows ([`push_config`]) and the
//! tickets its help requests become ([`on_request`], [`on_attachment`]).
//!
//! A request arrives as `HelpRequest`, then its screenshot in `HelpAttachment` pieces, held in
//! memory until whole. The ticket is made the way a portal request is (client from the agent,
//! board `tray_board_id` else `portal_board_id`), with source `agent`, the device linked, the
//! screenshot attached, and a context note. Agents resend until answered, so a request id that
//! already has a ticket gets that ticket's number back.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use rmm_proto::ServerMsg;
use rmm_proto::tray::{self, CAPABILITY, Context};
use serde_json::json;
use sha2::Digest;
use tokio::sync::mpsc;
use tracing::{info, warn};
use uuid::Uuid;

use crate::state::AppState;
use crate::tickets::{self, Author, NewTicket};

/// Tickets one device may open through the tray in a day.
pub const DAILY_LIMIT: i64 = 20;
/// A screenshot not complete after this long is dropped (the agent resends).
const ASSEMBLY_TIMEOUT: Duration = Duration::from_secs(600);
/// Requests being assembled per agent.
const MAX_ASSEMBLING: usize = 3;

pub struct Request {
    pub request_id: Uuid,
    pub user: String,
    pub session: u32,
    pub subject: String,
    pub body: String,
    pub context: Context,
    pub screenshot_len: u32,
}

struct Assembling {
    req: Request,
    data: Vec<u8>,
    started: Instant,
}

static ASSEMBLING: LazyLock<Mutex<HashMap<(Uuid, Uuid), Assembling>>> = LazyLock::new(Default::default);

fn assembling() -> std::sync::MutexGuard<'static, HashMap<(Uuid, Uuid), Assembling>> {
    ASSEMBLING.lock().unwrap_or_else(|e| e.into_inner())
}

async fn reply(tx: &mpsc::WeakSender<ServerMsg>, request_id: Uuid, result: Result<i64, String>) {
    if let Some(tx) = tx.upgrade() {
        let (ticket_number, error) = match result {
            Ok(n) => (Some(n), None),
            Err(e) => (None, Some(e)),
        };
        let _ = tx.send(ServerMsg::HelpRequestResult { request_id, ticket_number, error }).await;
    }
}

pub async fn on_request(st: &AppState, agent_id: Uuid, client_id: Uuid, tx: &mpsc::WeakSender<ServerMsg>, req: Request) {
    let id = req.request_id;
    if req.screenshot_len as usize > tray::MAX_SCREENSHOT {
        return reply(tx, id, Err(format!("the screenshot is limited to {} MiB", tray::MAX_SCREENSHOT / (1024 * 1024)))).await;
    }
    if req.screenshot_len == 0 {
        let res = finish(st, agent_id, client_id, req, None).await;
        return reply(tx, id, res).await;
    }
    // Already a ticket (an answer that got lost): no need for the picture again.
    if let Ok(Some(n)) = existing(st, id).await {
        return reply(tx, id, Ok(n)).await;
    }
    let mut a = assembling();
    a.retain(|_, v| v.started.elapsed() < ASSEMBLY_TIMEOUT);
    if a.keys().filter(|(agent, _)| *agent == agent_id).count() >= MAX_ASSEMBLING && !a.contains_key(&(agent_id, id)) {
        warn!(%agent_id, "too many help requests being sent at once; dropped one");
        return;
    }
    let cap = req.screenshot_len as usize;
    a.insert((agent_id, id), Assembling { req, data: Vec::with_capacity(cap), started: Instant::now() });
}

/// One `HelpAttachment`.
pub struct Piece {
    pub request_id: Uuid,
    pub offset: u32,
    pub data: Vec<u8>,
    pub done: bool,
}

pub async fn on_attachment(st: &AppState, agent_id: Uuid, client_id: Uuid, tx: &mpsc::WeakSender<ServerMsg>, piece: Piece) {
    let Piece { request_id, offset, data, done } = piece;
    let whole = {
        let mut a = assembling();
        let key = (agent_id, request_id);
        let Some(p) = a.get_mut(&key) else { return };
        if p.data.len() != offset as usize || p.data.len() + data.len() > p.req.screenshot_len as usize {
            warn!(%agent_id, %request_id, "help request screenshot out of order or too long; dropped (the agent resends)");
            a.remove(&key);
            return;
        }
        p.data.extend_from_slice(&data);
        if !done {
            return;
        }
        let p = a.remove(&key).expect("present");
        if p.data.len() != p.req.screenshot_len as usize {
            warn!(%agent_id, %request_id, "help request screenshot shorter than announced; dropped");
            return;
        }
        p
    };
    let res = finish(st, agent_id, client_id, whole.req, Some(whole.data)).await;
    reply(tx, request_id, res).await;
}

async fn existing(st: &AppState, request_id: Uuid) -> sqlx::Result<Option<i64>> {
    sqlx::query_scalar("SELECT number FROM tickets WHERE source = 'agent' AND source_ref = $1").bind(request_id.to_string()).fetch_optional(&st.db).await
}

/// `jpg` or `png`, by content.
fn image_kind(data: &[u8]) -> Option<(&'static str, &'static str)> {
    if data.starts_with(&[0xff, 0xd8, 0xff]) {
        Some(("jpg", "image/jpeg"))
    } else if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some(("png", "image/png"))
    } else {
        None
    }
}

/// The account name without its domain: `ACME\jsmith` and `jsmith@acme.com` stay recognisable.
fn short_user(user: &str) -> &str {
    user.rsplit('\\').next().unwrap_or(user)
}

/// The context note: what a technician would ask first.
pub fn context_note(hostname: &str, os: &str, user: &str, ctx: &Context, alerts: &[(String, String)]) -> String {
    let mut out = String::from("Sent from the device's tray app.\n\n");
    out.push_str(&format!("Device: {hostname}\nOS: {os}\nSigned-in user: {user}\n"));
    let up = ctx.uptime_secs;
    out.push_str(&format!("Uptime: {}d {}h {}m\n", up / 86_400, (up % 86_400) / 3600, (up % 3600) / 60));
    if !ctx.ips.is_empty() {
        out.push_str(&format!("IP addresses: {}\n", ctx.ips.iter().take(16).cloned().collect::<Vec<_>>().join(", ")));
    }
    if ctx.queued_secs >= 60 {
        out.push_str(&format!("Waited on the device for {} minutes (the server couldn't be reached)\n", ctx.queued_secs / 60));
    }
    if alerts.is_empty() {
        out.push_str("Open alerts: none\n");
    } else {
        out.push_str("Open alerts:\n");
        for (sev, title) in alerts.iter().take(20) {
            out.push_str(&format!("- [{sev}] {title}\n"));
        }
    }
    out
}

async fn finish(st: &AppState, agent_id: Uuid, client_id: Uuid, req: Request, shot: Option<Vec<u8>>) -> Result<i64, String> {
    let db_err = |e: sqlx::Error| {
        warn!(%agent_id, "help request: {e}");
        "the server couldn't store the request; it will be sent again".to_string()
    };
    if let Some(n) = existing(st, req.request_id).await.map_err(db_err)? {
        return Ok(n);
    }
    let subject = req.subject.split_whitespace().collect::<Vec<_>>().join(" ");
    let body = req.body.trim().to_string();
    if subject.is_empty() || subject.chars().count() > tray::MAX_SUBJECT || body.chars().count() > tray::MAX_BODY {
        return Err("the subject or description is too long".into());
    }
    let shot = shot.filter(|s| !s.is_empty());
    if shot.as_deref().is_some_and(|s| image_kind(s).is_none()) {
        return Err("the screenshot must be a JPEG or PNG image".into());
    }
    let today: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM tickets t JOIN ticket_agents ta ON ta.ticket_id = t.id
          WHERE t.source = 'agent' AND ta.agent_id = $1 AND t.created_at > now() - interval '1 day'",
    )
    .bind(agent_id)
    .fetch_one(&st.db)
    .await
    .map_err(db_err)?;
    if today >= DAILY_LIMIT {
        return Err(format!("this computer has sent {DAILY_LIMIT} help requests today; please call or email the help desk"));
    }
    let (hostname, os, site_id): (String, String, Uuid) =
        sqlx::query_as("SELECT hostname, trim(os_name || ' ' || os_version), site_id FROM agents WHERE id = $1").bind(agent_id).fetch_one(&st.db).await.map_err(db_err)?;
    let alerts: Vec<(String, String)> = sqlx::query_as(
        "SELECT severity, title FROM alerts WHERE agent_id = $1 AND resolved_at IS NULL ORDER BY opened_at DESC LIMIT 20",
    )
    .bind(agent_id)
    .fetch_all(&st.db)
    .await
    .map_err(db_err)?;
    // A contact of this client whose email is the signed-in account (Entra / UPN-style names).
    let short = short_user(&req.user).to_string();
    let contact: Option<(Uuid, String, String)> = if short.contains('@') {
        sqlx::query_as("SELECT id, name, email FROM contacts WHERE client_id = $1 AND lower(email) = lower($2) ORDER BY created_at LIMIT 1")
            .bind(client_id)
            .bind(&short)
            .fetch_optional(&st.db)
            .await
            .map_err(db_err)?
    } else {
        None
    };
    let (requester_name, requester_email) = match &contact {
        Some((_, name, email)) => (name.clone(), email.clone()),
        None => (format!("{short} on {hostname}"), String::new()),
    };
    let note = context_note(&hostname, &os, &req.user, &req.context, &alerts);

    let mut tx = st.db.begin().await.map_err(db_err)?;
    let board: Option<Uuid> = sqlx::query_scalar(
        "SELECT coalesce((SELECT tray_board_id FROM company_settings), (SELECT portal_board_id FROM company_settings),
                         (SELECT id FROM boards ORDER BY position, name LIMIT 1))",
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err)?;
    let Some(board) = board else { return Err("the service desk isn't set up yet".into()) };
    let author = match &contact {
        Some((id, name, _)) => Author { contact_id: Some(*id), name: name.clone(), ..Default::default() },
        None => Author::system(&requester_name),
    };
    let created = tickets::create(
        &mut tx,
        NewTicket {
            client_id: Some(client_id),
            site_id: Some(site_id),
            contact_id: contact.as_ref().map(|c| c.0),
            board_id: board,
            priority: 3,
            subject,
            body,
            body_public: true,
            source: "agent",
            requester_name: requester_name.clone(),
            requester_email,
            author,
            agent_ids: vec![agent_id],
            ..Default::default()
        },
    )
    .await
    .map_err(db_err)?;
    let tagged = sqlx::query("UPDATE tickets SET source_ref = $2 WHERE id = $1").bind(created.id).bind(req.request_id.to_string()).execute(&mut *tx).await;
    match tagged {
        Ok(_) => {}
        // The same request, at the same moment, from a second connection: that one won.
        Err(sqlx::Error::Database(d)) if d.is_unique_violation() => {
            drop(tx);
            return existing(st, req.request_id).await.map_err(db_err)?.ok_or_else(|| "try again".to_string());
        }
        Err(e) => return Err(db_err(e)),
    }
    tickets::add_event(&mut tx, created.id, "note", false, &Author::system("Agent"), &note, json!({ "via": "tray", "context": true }))
        .await
        .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;

    if let Some(shot) = shot {
        let (ext, ct) = image_kind(&shot).expect("checked above");
        let id = Uuid::new_v4();
        let key = format!("attachments/{id}");
        let sha = sha2::Sha256::digest(&shot).to_vec();
        let size = shot.len() as i64;
        let stored = async {
            st.storage.put(&key, shot, ct).await?;
            sqlx::query(
                "INSERT INTO ticket_attachments (id, ticket_id, event_id, name, content_type, size, sha256, storage_key)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            )
            .bind(id)
            .bind(created.id)
            .bind(created.event_id)
            .bind(format!("screenshot.{ext}"))
            .bind(ct)
            .bind(size)
            .bind(&sha)
            .bind(&key)
            .execute(&st.db)
            .await?;
            anyhow::Ok(())
        }
        .await;
        if let Err(e) = stored {
            warn!(ticket = created.number, "storing the tray screenshot: {e:#}");
            let _ = st.storage.delete(&key).await;
        }
    }
    info!(%agent_id, ticket = created.number, user = %req.user, "help request from the tray became a ticket");
    crate::auth::audit(
        &st.db,
        None,
        "ticket.create",
        Some(("ticket", created.id)),
        json!({ "number": created.number, "source": "agent", "agent_id": agent_id, "user": req.user, "session": req.session }),
    )
    .await;
    tickets::notify_created(st, created.id).await;
    tickets::announce(st, created.id).await;
    Ok(created.number)
}

/// The tray's config for one agent: its policy and its client's branding.
pub async fn config_for(st: &AppState, agent_id: Uuid, client_id: Uuid) -> sqlx::Result<tray::Config> {
    let p = crate::policy::tray(st, agent_id).await?;
    let b = crate::branding::resolve(st, Some(client_id));
    let icon_png = match crate::branding::image(st, Some(client_id), crate::branding::Variant::Icon).await {
        Ok(Some((bytes, "image/png", _))) => bytes,
        Ok(_) => vec![],
        Err(e) => {
            warn!("reading the branding icon for the tray: {e:#}");
            vec![]
        }
    };
    let company = st.company().company_name.trim().to_string();
    let contact = if p.contact_card {
        tray::Contact {
            name: if company.is_empty() { b.name.clone() } else { company },
            phone: b.support.phone.clone().unwrap_or_default(),
            email: b.support.email.clone().unwrap_or_default(),
            url: b.support.url.clone().unwrap_or_default(),
            hours: b.support.hours.clone().unwrap_or_default(),
        }
    } else {
        tray::Contact::default()
    };
    Ok(tray::Config {
        enabled: p.enabled,
        product_name: b.name.clone(),
        icon_png,
        contact,
        links: p.links.into_iter().map(|l| tray::Link { label: l.label, url: l.url }).collect(),
        request_help: p.request_help,
        screenshot_default: p.screenshot_default,
    })
}

/// Sends the tray config to these online agents (`None`: all) that run a tray.
pub async fn push_config(st: &AppState, agents: Option<&[Uuid]>) {
    let rows: sqlx::Result<Vec<(Uuid, Uuid)>> = sqlx::query_as(
        "SELECT a.id, s.client_id FROM agents a JOIN sites s ON s.id = a.site_id
          WHERE a.online AND $2 = ANY(a.capabilities) AND ($1::uuid[] IS NULL OR a.id = ANY($1))",
    )
    .bind(agents)
    .bind(CAPABILITY)
    .fetch_all(&st.db)
    .await;
    match rows {
        Ok(rows) => {
            for (agent, client) in rows {
                match config_for(st, agent, client).await {
                    Ok(c) => {
                        st.hub.send(agent, ServerMsg::TrayConfig(c)).await;
                    }
                    Err(e) => warn!(%agent, "tray config: {e}"),
                }
            }
        }
        Err(e) => warn!("pushing tray configs: {e}"),
    }
}

/// Branding changed for one client (`Some`) or the instance (`None`, which reaches everyone
/// without their own row; pushing to all is simpler and cheap).
pub async fn branding_changed(st: &AppState, client: Option<Uuid>) {
    let agents: Option<Vec<Uuid>> = match client {
        None => None,
        Some(c) => sqlx::query_scalar("SELECT a.id FROM agents a JOIN sites s ON s.id = a.site_id WHERE s.client_id = $1")
            .bind(c)
            .fetch_all(&st.db)
            .await
            .ok(),
    };
    push_config(st, agents.as_deref()).await;
}

/// On connect, to an agent that runs a tray.
pub async fn on_connect(st: &AppState, agent_id: Uuid, client_id: Uuid, capabilities: &[String], tx: &mpsc::Sender<ServerMsg>) {
    if !capabilities.iter().any(|c| c == CAPABILITY) {
        return;
    }
    match config_for(st, agent_id, client_id).await {
        Ok(c) => {
            let _ = tx.send(ServerMsg::TrayConfig(c)).await;
        }
        Err(e) => warn!(%agent_id, "tray config: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn note_and_names() {
        let ctx = Context { uptime_secs: 90_061, ips: vec!["10.0.0.5".into()], queued_secs: 600 };
        let n = context_note("PC-1", "Windows 11", "ACME\\jsmith", &ctx, &[("critical".into(), "Disk C: 97% full".into())]);
        assert!(n.contains("Device: PC-1\nOS: Windows 11\nSigned-in user: ACME\\jsmith\nUptime: 1d 1h 1m\n"), "{n}");
        assert!(n.contains("IP addresses: 10.0.0.5") && n.contains("10 minutes") && n.contains("- [critical] Disk C: 97% full"), "{n}");
        assert!(context_note("h", "o", "u", &Context::default(), &[]).contains("Open alerts: none"));
        assert_eq!(short_user("ACME\\jsmith"), "jsmith");
        assert_eq!(short_user("AzureAD\\j@acme.com"), "j@acme.com");
        assert_eq!(short_user("jsmith"), "jsmith");
        assert_eq!(image_kind(&[0xff, 0xd8, 0xff, 0]), Some(("jpg", "image/jpeg")));
        assert_eq!(image_kind(b"GIF89a"), None);
    }
}
