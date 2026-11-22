//! The SIEM stream: audit events (and optionally security detections and alerts) sent to
//! syslog (UDP, TCP, TLS) and HTTPS collectors (docs/design/audit-siem.md).
//!
//! Admins configure destinations (`api::siem`). Triggers on `audit_log`, `security_detections`
//! and `alerts` (migration 0031) write one `siem_outbox` row per event per destination in the
//! transaction that wrote the event, so a restart or an outage loses nothing. [`run`] sends each
//! destination's rows in id order, a batch at a time, deleting them once sent; a failing
//! destination backs off (5 s doubling to 15 min) and the status it keeps (`last_error`,
//! `consecutive_failures`, `last_success_at`, the rows waiting) is what the settings page shows.
//! Delivery is at least once: a crash between sending and deleting repeats a batch, and every
//! event carries its `id` so a collector can drop repeats. Rows older than [`RETAIN_DAYS`] are
//! deleted unsent (counted in `dropped_total`) so a destination that is down for good can't fill
//! the database.
//!
//! Syslog messages are RFC 5424: `<PRI>1 TIMESTAMP HOST rmm-server - MSGID [rmm@32473 …] JSON`.
//! TCP uses RFC 6587 octet counting (or newlines), TLS RFC 5425 octet counting. HTTPS posts a
//! JSON body `{"events": [...]}`, or Splunk HEC events when asked.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Value, json};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tracing::{debug, warn};
use uuid::Uuid;

use crate::state::AppState;

/// Events not sent after this long are dropped.
pub const RETAIN_DAYS: i32 = 7;
/// Events per delivery (one HTTP request, or one TCP write).
const BATCH: i64 = 200;
/// Batches per destination per round, so one busy destination doesn't starve the loop.
const BATCHES_PER_ROUND: usize = 10;
/// A syslog message bigger than this is sent without its `details`: UDP datagrams must fit,
/// and collectors cap lines.
const MAX_MESSAGE: usize = 8000;
const TIMEOUT: Duration = Duration::from_secs(15);
/// RFC 5424 enterprise id for the structured data. 32473 is the one reserved for documentation
/// (RFC 5612): we have no IANA number.
const SD_ID: &str = "rmm@32473";

pub const KINDS: &[&str] = &["syslog_udp", "syslog_tcp", "syslog_tls", "https"];

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Destination {
    pub id: Uuid,
    pub name: String,
    pub kind: String,
    pub address: String,
    pub framing: String,
    pub https_format: String,
    pub token: Option<Vec<u8>>,
    pub token_sealed: bool,
    pub ca_pem: Option<String>,
    pub facility: i16,
    pub consecutive_failures: i32,
}

pub const DESTINATION_COLUMNS: &str = "id, name, kind, address, framing, https_format, token, token_sealed, ca_pem, facility, consecutive_failures";

impl Destination {
    fn token(&self, key: Option<&crate::crypto::DataKey>) -> Result<Option<String>> {
        let Some(stored) = self.token.as_deref() else { return Ok(None) };
        let plain = crate::crypto::load(key, stored, self.token_sealed).context("the token can't be read: RMM_DATA_KEY is missing or changed")?;
        Ok(Some(String::from_utf8_lossy(&plain).into_owned()))
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// `host:port` of a syslog destination (`[::1]:514` for IPv6). The port defaults by kind.
pub fn parse_syslog_address(kind: &str, address: &str) -> Result<(String, u16), String> {
    let address = address.trim();
    let default = if kind == "syslog_tls" { 6514 } else { 514 };
    if address.is_empty() || address.len() > 255 || address.contains(char::is_whitespace) || address.contains('/') {
        return Err("enter a host name or address, like logs.example.com:514".into());
    }
    let (host, port) = if let Some(rest) = address.strip_prefix('[') {
        let (h, tail) = rest.split_once(']').ok_or("an IPv6 address needs its closing ]")?;
        match tail {
            "" => (h, default),
            t => (h, t.strip_prefix(':').and_then(|p| p.parse().ok()).ok_or("the port must be a number")?),
        }
    } else if address.matches(':').count() == 1 {
        let (h, p) = address.split_once(':').expect("one colon");
        (h, p.parse().map_err(|_| "the port must be a number")?)
    } else if address.contains(':') {
        return Err("put an IPv6 address in brackets: [::1]:514".into());
    } else {
        (address, default)
    };
    if host.is_empty() || port == 0 {
        return Err("enter a host name or address, like logs.example.com:514".into());
    }
    Ok((host.to_string(), port))
}

/// Checks a destination before it is saved; returns the normalised address.
pub fn validate(kind: &str, address: &str, ca_pem: Option<&str>) -> Result<String, String> {
    if !KINDS.contains(&kind) {
        return Err("kind must be syslog_udp, syslog_tcp, syslog_tls or https".into());
    }
    let address = address.trim();
    if kind == "https" {
        let parsed = reqwest::Url::parse(address).map_err(|_| "enter the full URL, starting with https://".to_string())?;
        if !matches!(parsed.scheme(), "https" | "http") || parsed.host_str().is_none() || !parsed.username().is_empty() || parsed.password().is_some() {
            return Err("the URL must start with https:// (or http://) and carry no user name or password".into());
        }
        if address.len() > 2000 {
            return Err("the URL is too long".into());
        }
    } else {
        parse_syslog_address(kind, address)?;
    }
    if let Some(pem) = ca_pem {
        if !matches!(kind, "syslog_tls" | "https") {
            return Err("a CA certificate only applies to TLS and HTTPS destinations".into());
        }
        if pem.len() > 100_000 || certificates(pem).is_empty() {
            return Err("the CA certificate must be PEM (-----BEGIN CERTIFICATE-----)".into());
        }
    }
    Ok(address.to_string())
}

fn certificates(pem: &str) -> Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>> {
    use tokio_rustls::rustls::pki_types::{CertificateDer, pem::PemObject};
    CertificateDer::pem_slice_iter(pem.as_bytes()).filter_map(Result::ok).collect()
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

/// The syslog severity (RFC 5424 §6.2.1) of an event.
fn severity(ev: &Value) -> u8 {
    match ev["kind"].as_str() {
        Some("alert") => match ev["severity"].as_str() {
            Some("critical") => 2,
            Some("warning") => 4,
            _ => 6,
        },
        Some("detection") => match ev["severity"].as_str() {
            Some("severe") => 2,
            Some("high") => 3,
            Some("moderate") => 4,
            Some("low") => 5,
            _ => 6,
        },
        _ => 6,
    }
}

fn event_time(ev: &Value) -> DateTime<Utc> {
    ev["ts"].as_str().and_then(|t| DateTime::parse_from_rfc3339(t).ok()).map_or_else(Utc::now, |t| t.with_timezone(&Utc))
}

/// An RFC 5424 SD-PARAM value: `"`, `\` and `]` are escaped.
fn sd_escape(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        if matches!(c, '"' | '\\' | ']') {
            out.push('\\');
        }
        if !c.is_control() {
            out.push(c);
        }
    }
    out
}

/// MSGID: printable US-ASCII without spaces, at most 32 characters.
fn msg_id(ev: &Value) -> String {
    let id: String = ev["event"].as_str().unwrap_or("event").chars().filter(|c| c.is_ascii_graphic()).take(32).collect();
    if id.is_empty() { "-".into() } else { id }
}

fn compact(ev: &Value) -> String {
    serde_json::to_string(ev).unwrap_or_else(|_| "{}".into())
}

/// One RFC 5424 message (no framing).
pub fn syslog_message(facility: i16, host: &str, ev: &Value) -> String {
    let pri = i32::from(facility) * 8 + i32::from(severity(ev));
    let host: String = host.chars().filter(|c| c.is_ascii_graphic()).take(255).collect();
    let host = if host.is_empty() { "-".to_string() } else { host };
    let sd = format!(
        "[{SD_ID} kind=\"{}\" id=\"{}\" event=\"{}\"]",
        sd_escape(ev["kind"].as_str().unwrap_or("")),
        sd_escape(ev["id"].to_string().trim_matches('"')),
        sd_escape(ev["event"].as_str().unwrap_or(""))
    );
    let build = |body: &str| format!("<{pri}>1 {} {host} rmm-server - {} {sd} {body}", event_time(ev).to_rfc3339_opts(SecondsFormat::Millis, true), msg_id(ev));
    let full = build(&compact(ev));
    if full.len() <= MAX_MESSAGE {
        return full;
    }
    // Too big (a large `details`): keep the identifying fields.
    let mut small = ev.clone();
    if let Some(o) = small.as_object_mut() {
        o.retain(|k, _| !matches!(k.as_str(), "details" | "resources" | "mitre"));
        o.insert("truncated".into(), true.into());
    }
    let mut out = build(&compact(&small));
    if out.len() > MAX_MESSAGE {
        // Still too big (a huge action name or title): cut at a character boundary.
        let mut end = MAX_MESSAGE;
        while !out.is_char_boundary(end) {
            end -= 1;
        }
        out.truncate(end);
    }
    out
}

/// A message on a stream: RFC 6587 octet counting (`<length> <message>`, also RFC 5425), or a line.
pub fn frame(msg: &str, octet_counting: bool) -> Vec<u8> {
    if octet_counting { format!("{} {msg}", msg.len()).into_bytes() } else { format!("{}\n", msg.replace('\n', " ")).into_bytes() }
}

fn hec_event(host: &str, ev: &Value) -> Value {
    let t = event_time(ev);
    json!({
        "time": t.timestamp() as f64 + f64::from(t.timestamp_subsec_millis()) / 1000.0,
        "host": host,
        "source": "rmm-server",
        "sourcetype": format!("rmm:{}", ev["kind"].as_str().unwrap_or("event")),
        "event": ev,
    })
}

/// The host name events are stamped with: the one in RMM_PUBLIC_URL.
fn host_name(st: &AppState) -> String {
    reqwest::Url::parse(&st.cfg.public_url).ok().and_then(|u| u.host_str().map(str::to_string)).unwrap_or_else(|| "rmm".into())
}

// ---------------------------------------------------------------------------
// Transports
// ---------------------------------------------------------------------------

fn tls_connector(ca_pem: Option<&str>) -> Result<tokio_rustls::TlsConnector> {
    let mut roots = tokio_rustls::rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    if let Some(pem) = ca_pem.filter(|p| !p.trim().is_empty()) {
        for cert in certificates(pem) {
            roots.add(cert).context("the CA certificate")?;
        }
    }
    let config = tokio_rustls::rustls::ClientConfig::builder_with_provider(Arc::new(tokio_rustls::rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
}

async fn connect(host: &str, port: u16) -> Result<tokio::net::TcpStream> {
    let tcp = tokio::time::timeout(Duration::from_secs(10), tokio::net::TcpStream::connect((host, port)))
        .await
        .map_err(|_| anyhow::anyhow!("connecting to {host}:{port} timed out"))?
        .with_context(|| format!("connecting to {host}:{port}"))?;
    tcp.set_nodelay(true).ok();
    Ok(tcp)
}

async fn write_all<W: AsyncWrite + Unpin>(w: &mut W, bytes: &[u8]) -> Result<()> {
    tokio::time::timeout(TIMEOUT, async {
        w.write_all(bytes).await?;
        w.flush().await
    })
    .await
    .map_err(|_| anyhow::anyhow!("sending timed out"))?
    .context("sending")
}

/// Sends the events to a destination.
pub async fn send(st: &AppState, d: &Destination, events: &[Value]) -> Result<()> {
    if events.is_empty() {
        return Ok(());
    }
    let host = host_name(st);
    match d.kind.as_str() {
        "syslog_udp" => {
            let (h, port) = parse_syslog_address(&d.kind, &d.address).map_err(anyhow::Error::msg)?;
            let target: SocketAddr = tokio::net::lookup_host((h.as_str(), port)).await.with_context(|| format!("resolving {h}"))?.next().context("no address")?;
            let socket = tokio::net::UdpSocket::bind(if target.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await?;
            for ev in events {
                socket.send_to(syslog_message(d.facility, &host, ev).as_bytes(), target).await.context("sending")?;
            }
            Ok(())
        }
        "syslog_tcp" | "syslog_tls" => {
            let (h, port) = parse_syslog_address(&d.kind, &d.address).map_err(anyhow::Error::msg)?;
            let octets = d.kind == "syslog_tls" || d.framing == "octet";
            let mut bytes = Vec::new();
            for ev in events {
                bytes.extend(frame(&syslog_message(d.facility, &host, ev), octets));
            }
            let tcp = connect(&h, port).await?;
            if d.kind == "syslog_tcp" {
                let mut tcp = tcp;
                write_all(&mut tcp, &bytes).await?;
                let _ = tcp.shutdown().await;
            } else {
                let name = tokio_rustls::rustls::pki_types::ServerName::try_from(h.clone()).context("the syslog host name")?;
                let mut tls = tokio::time::timeout(TIMEOUT, tls_connector(d.ca_pem.as_deref())?.connect(name, tcp))
                    .await
                    .map_err(|_| anyhow::anyhow!("the TLS handshake timed out"))?
                    .context("TLS handshake")?;
                write_all(&mut tls, &bytes).await?;
                let _ = tls.shutdown().await;
            }
            Ok(())
        }
        "https" => {
            let token = d.token(st.cfg.data_key.as_ref())?;
            let (body, auth) = if d.https_format == "splunk_hec" {
                let body: String = events.iter().map(|e| compact(&hec_event(&host, e))).collect::<Vec<_>>().join("\n");
                (body, token.map(|t| format!("Splunk {t}")))
            } else {
                (compact(&json!({ "source": "rmm-server", "host": host, "events": events })), token.map(|t| format!("Bearer {t}")))
            };
            let client = match d.ca_pem.as_deref().filter(|p| !p.trim().is_empty()) {
                None => st.http.clone(),
                Some(pem) => {
                    let mut b = reqwest::Client::builder().user_agent(concat!("rmm-server/", env!("CARGO_PKG_VERSION"))).redirect(reqwest::redirect::Policy::none());
                    for cert in certificates(pem) {
                        b = b.add_root_certificate(reqwest::Certificate::from_der(&cert)?);
                    }
                    b.build()?
                }
            };
            let mut req = client.post(&d.address).header("content-type", "application/json").timeout(TIMEOUT).body(body);
            if let Some(a) = auth {
                req = req.header("authorization", a);
            }
            let res = req.send().await.map_err(|e| anyhow::anyhow!("request failed: {e}"))?;
            let status = res.status();
            if status.is_success() {
                return Ok(());
            }
            let text = res.text().await.unwrap_or_default();
            bail!("HTTP {status}: {}", text.chars().take(300).collect::<String>().trim())
        }
        other => bail!("unknown destination type {other}"),
    }
}

/// The event the test button sends (not queued, not counted).
pub fn test_event(d: &Destination) -> Value {
    json!({
        "kind": "audit", "event": "audit.siem.test", "id": 0, "ts": Utc::now(), "action": "siem.test",
        "user_id": null, "user_email": null, "target_type": "siem_destination", "target_id": d.id,
        "details": { "destination": d.name, "message": "This is a test event from RMM." },
    })
}

// ---------------------------------------------------------------------------
// The worker
// ---------------------------------------------------------------------------

/// Seconds to wait after `failures` consecutive failures: 5, 10, 20, … capped at 15 minutes.
pub fn backoff_secs(failures: i32) -> i64 {
    (5i64 << (failures.clamp(1, 12) - 1).min(10)).min(900)
}

/// Sends what is due, then sleeps. Also purges stale outbox rows once an hour.
pub async fn run(st: Arc<AppState>) {
    let mut purged = std::time::Instant::now() - Duration::from_secs(7200);
    loop {
        match deliver_due(&st).await {
            Ok(0) => tokio::time::sleep(Duration::from_secs(2)).await,
            // Busy: go round again right away.
            Ok(_) => tokio::task::yield_now().await,
            Err(e) => {
                warn!("SIEM delivery: {e:#}");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
        if purged.elapsed() >= Duration::from_secs(3600) {
            purged = std::time::Instant::now();
            if let Err(e) = purge(&st.db).await {
                warn!("SIEM outbox purge: {e}");
            }
        }
    }
}

/// Deletes events nobody could send for [`RETAIN_DAYS`], counting them per destination.
pub async fn purge(db: &sqlx::PgPool) -> sqlx::Result<()> {
    sqlx::query(
        "WITH gone AS (DELETE FROM siem_outbox WHERE created_at < now() - make_interval(days => $1) RETURNING destination_id)
         UPDATE siem_destinations d SET dropped_total = dropped_total + g.n
           FROM (SELECT destination_id, count(*) AS n FROM gone GROUP BY destination_id) g WHERE d.id = g.destination_id",
    )
    .bind(RETAIN_DAYS)
    .execute(db)
    .await?;
    Ok(())
}

/// One round: every destination that is due and has events gets its next batches. Returns how
/// many events were sent.
async fn deliver_due(st: &Arc<AppState>) -> Result<usize> {
    // Claimed with a lease: a crash mid-send retries after it, and two servers don't both send.
    let due: Vec<Destination> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "UPDATE siem_destinations SET next_attempt_at = now() + interval '2 minutes'
          WHERE id IN (SELECT d.id FROM siem_destinations d
                        WHERE d.enabled AND d.next_attempt_at <= now() AND EXISTS (SELECT 1 FROM siem_outbox o WHERE o.destination_id = d.id)
                        FOR UPDATE SKIP LOCKED)
          RETURNING {DESTINATION_COLUMNS}"
    )))
    .fetch_all(&st.db)
    .await?;
    let sent = futures_util::future::join_all(due.into_iter().map(|d| deliver_destination(st, d))).await;
    Ok(sent.into_iter().sum())
}

async fn deliver_destination(st: &Arc<AppState>, d: Destination) -> usize {
    let mut total = 0;
    for _ in 0..BATCHES_PER_ROUND {
        let rows: Vec<(i64, Value)> = match sqlx::query_as("SELECT id, event FROM siem_outbox WHERE destination_id = $1 ORDER BY id LIMIT $2")
            .bind(d.id)
            .bind(BATCH)
            .fetch_all(&st.db)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!(destination = %d.name, "reading the SIEM outbox: {e}");
                break;
            }
        };
        if rows.is_empty() {
            break;
        }
        let events: Vec<Value> = rows.iter().map(|r| r.1.clone()).collect();
        let ids: Vec<i64> = rows.iter().map(|r| r.0).collect();
        match send(st, &d, &events).await {
            Ok(()) => {
                debug!(destination = %d.name, events = events.len(), "SIEM batch sent");
                let done = sqlx::query("DELETE FROM siem_outbox WHERE id = ANY($1)").bind(&ids).execute(&st.db).await;
                // Not deleted = sent twice next time; say so rather than lose track.
                if let Err(e) = done {
                    warn!(destination = %d.name, "deleting sent SIEM events: {e}");
                }
                let _ = sqlx::query(
                    "UPDATE siem_destinations SET sent_total = sent_total + $2, consecutive_failures = 0, last_attempt_at = now(),
                            last_success_at = now(), last_error = NULL, next_attempt_at = now() WHERE id = $1",
                )
                .bind(d.id)
                .bind(ids.len() as i64)
                .execute(&st.db)
                .await;
                total += ids.len();
                if (ids.len() as i64) < BATCH {
                    break;
                }
            }
            Err(e) => {
                let failures = d.consecutive_failures.saturating_add(1);
                let wait = backoff_secs(failures);
                warn!(destination = %d.name, failures, "SIEM delivery failed, retrying in {wait}s: {e:#}");
                let _ = sqlx::query(
                    "UPDATE siem_destinations SET consecutive_failures = consecutive_failures + 1, last_attempt_at = now(), last_error = $2,
                            next_attempt_at = now() + make_interval(secs => $3) WHERE id = $1",
                )
                .bind(d.id)
                .bind(format!("{e:#}").chars().take(500).collect::<String>())
                .bind(wait as f64)
                .execute(&st.db)
                .await;
                return total;
            }
        }
    }
    // No failure: give the lease back, so the next round looks again straight away.
    let _ = sqlx::query("UPDATE siem_destinations SET next_attempt_at = now() WHERE id = $1").bind(d.id).execute(&st.db).await;
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    fn audit_event() -> Value {
        json!({ "kind": "audit", "event": "audit.user.login", "id": 42, "ts": "2026-11-22T10:00:00.123Z", "action": "user.login",
                "user_email": "a@b.test", "details": { "ip": "10.0.0.1" } })
    }

    #[test]
    fn syslog_is_rfc_5424() {
        let m = syslog_message(13, "rmm.example.com", &audit_event());
        // facility 13 * 8 + severity 6 (informational) = 110
        assert!(m.starts_with("<110>1 2026-11-22T10:00:00.123Z rmm.example.com rmm-server - audit.user.login [rmm@32473 kind=\"audit\" id=\"42\" event=\"audit.user.login\"] {"), "{m}");
        let json = &m[m.find("] {").unwrap() + 2..];
        assert_eq!(serde_json::from_str::<Value>(json).unwrap()["action"], "user.login");
    }

    #[test]
    fn severities_follow_the_event() {
        let a = |s: &str| syslog_message(1, "h", &json!({ "kind": "alert", "event": "alert.opened", "id": "x", "severity": s, "ts": "2026-01-01T00:00:00Z" }));
        assert!(a("critical").starts_with("<10>"));
        assert!(a("warning").starts_with("<12>"));
        assert!(a("info").starts_with("<14>"));
        let d = syslog_message(13, "h", &json!({ "kind": "detection", "event": "detection.created", "id": "x", "severity": "severe", "ts": "2026-01-01T00:00:00Z" }));
        assert!(d.starts_with("<106>"), "{d}");
    }

    #[test]
    fn structured_data_is_escaped_and_messages_stay_small() {
        let ev = json!({ "kind": "audit", "event": "audit.x\"]y", "id": 1, "ts": "2026-11-22T10:00:00Z", "details": { "blob": "x".repeat(20_000) } });
        let m = syslog_message(13, "h", &ev);
        assert!(m.contains("event=\"audit.x\\\"\\]y\""), "{m}");
        assert!(m.len() <= MAX_MESSAGE, "{}", m.len());
        assert!(m.contains("\"truncated\":true"));
        assert!(!m.contains("xxxx"));
    }

    #[test]
    fn framing() {
        assert_eq!(frame("héllo", true), "6 héllo".as_bytes());
        assert_eq!(frame("a\nb", false), b"a b\n");
    }

    #[test]
    fn hec_events_carry_the_time_and_type() {
        let h = hec_event("rmm.example.com", &audit_event());
        assert_eq!(h["sourcetype"], "rmm:audit");
        assert_eq!(h["host"], "rmm.example.com");
        assert!((h["time"].as_f64().unwrap() - 1_795_341_600.123).abs() < 1.0, "{}", h["time"]);
        assert_eq!(h["event"]["id"], 42);
    }

    #[test]
    fn addresses() {
        assert_eq!(parse_syslog_address("syslog_udp", "logs.example.com").unwrap(), ("logs.example.com".into(), 514));
        assert_eq!(parse_syslog_address("syslog_tls", "logs.example.com").unwrap().1, 6514);
        assert_eq!(parse_syslog_address("syslog_tcp", "10.0.0.5:1514").unwrap(), ("10.0.0.5".into(), 1514));
        assert_eq!(parse_syslog_address("syslog_tcp", "[::1]:601").unwrap(), ("::1".into(), 601));
        for bad in ["", "a b", "::1:514", "host:abc", "host:0", "[::1", "http://x/y"] {
            assert!(parse_syslog_address("syslog_tcp", bad).is_err(), "{bad}");
        }
        assert!(validate("https", "https://splunk.example.com:8088/services/collector/event", None).is_ok());
        assert!(validate("https", "ftp://x", None).is_err());
        assert!(validate("https", "https://u:p@x.test/", None).is_err());
        assert!(validate("syslog_udp", "x:514", Some("-----BEGIN CERTIFICATE-----")).is_err(), "a CA means nothing for UDP");
        assert!(validate("syslog_tls", "x", Some("not a certificate")).is_err());
        assert!(validate("carrier_pigeon", "x", None).is_err());
    }

    #[test]
    fn backoff_grows_and_is_capped() {
        assert_eq!(backoff_secs(1), 5);
        assert_eq!(backoff_secs(2), 10);
        assert_eq!(backoff_secs(5), 80);
        assert_eq!(backoff_secs(50), 900);
        assert_eq!(backoff_secs(0), 5);
    }
}
