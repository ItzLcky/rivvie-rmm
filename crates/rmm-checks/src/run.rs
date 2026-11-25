//! One run of one check from a [`CheckSpec`], as the agent and the server both run them.

use std::net::SocketAddr;
use std::time::Duration;

use chrono::Utc;
use rmm_proto::checks::{CertInfo, CheckData, CheckKind, CheckResult, CheckSpec, HttpMethod};

use crate::{Guard, dns, http, ping, tcp, tls};

fn cert_info(c: &crate::x509::Cert, untrusted: Option<String>) -> CertInfo {
    CertInfo { not_before: c.not_before, not_after: c.not_after, subject: c.subject.clone(), issuer: c.issuer.clone(), sans: c.sans.clone(), untrusted }
}

/// One run of one network check. Every address it connects to (after resolution, on every
/// redirect, and a named DNS server) goes past `guard`. A backup check isn't a network check:
/// it only says so (the agent runs those itself).
pub async fn run(spec: &CheckSpec, guard: Guard) -> CheckResult {
    let timeout = Duration::from_secs(u64::from(spec.timeout_secs.clamp(1, 300)));
    let mut r = CheckResult { check_id: spec.id, at: Utc::now(), ok: false, latency_ms: None, value: None, message: String::new(), data: None };
    match &spec.kind {
        CheckKind::Ping { host } => match ping::echo(host, guard, timeout, 3).await {
            Ok(ms) => (r.ok, r.latency_ms, r.message) = (true, Some(ms), format!("reply in {ms} ms")),
            Err(e) => r.message = e,
        },
        CheckKind::Tcp { host, port } => match tcp::connect(host, *port, guard, timeout).await {
            Ok((ms, peer)) => (r.ok, r.latency_ms, r.message) = (true, Some(ms), format!("{peer} accepted the connection")),
            Err(e) => r.message = e,
        },
        CheckKind::Http { url, method, statuses, keyword, keyword_absent, verify_tls } => {
            let req = http::Request { url: url.clone(), head: *method == HttpMethod::Head, timeout };
            match http::fetch(&req, guard).await {
                Ok(res) => {
                    r.latency_ms = Some(res.latency_ms);
                    r.value = Some(f64::from(res.status));
                    let status_ok = if statuses.is_empty() { (200..400).contains(&res.status) } else { statuses.contains(&res.status) };
                    let mut msg = format!("HTTP {}", res.status);
                    if res.redirects > 0 {
                        msg.push_str(&format!(" after {} redirect{}", res.redirects, if res.redirects == 1 { "" } else { "s" }));
                    }
                    let mut ok = status_ok;
                    if !status_ok {
                        msg.push_str(if statuses.is_empty() { " (expected 2xx or 3xx)" } else { " (not an expected status)" });
                    }
                    if let Some(k) = keyword.as_deref().filter(|k| !k.trim().is_empty()) {
                        let found = http::keyword_found(&res.body, k);
                        if found == *keyword_absent {
                            ok = false;
                            msg.push_str(if found { ", keyword found" } else { ", keyword not found" });
                        }
                    }
                    if let Some(seen) = res.tls {
                        if *verify_tls && let Some(why) = &seen.untrusted {
                            ok = false;
                            msg.push_str(&format!(", certificate not trusted: {why}"));
                        }
                        if let Some(c) = &seen.cert {
                            r.data = Some(CheckData::Cert(cert_info(c, seen.untrusted.clone())));
                        }
                    }
                    r.ok = ok;
                    r.message = msg;
                }
                Err(e) => r.message = e,
            }
        }
        CheckKind::Tls { host, port, server_name } => match tls::inspect(host, *port, server_name.as_deref(), guard, timeout).await {
            Ok((ms, seen)) => {
                r.latency_ms = Some(ms);
                match &seen.cert {
                    Some(c) => {
                        let days = c.days_left(Utc::now());
                        r.ok = true;
                        r.value = Some(days as f64);
                        r.message = if days >= 0 { format!("certificate valid for {days} more days") } else { format!("certificate expired {} days ago", -days) };
                        if let Some(p) = &seen.protocol {
                            r.message.push_str(&format!(" ({p})"));
                        }
                        r.data = Some(CheckData::Cert(cert_info(c, seen.untrusted.clone())));
                    }
                    None => r.message = "the certificate couldn't be read".into(),
                }
            }
            Err(e) => r.message = e,
        },
        CheckKind::Dns { name, record, server, expect } => {
            let server = match server.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                None => Ok(None),
                Some(s) => s
                    .parse::<SocketAddr>()
                    .or_else(|_| s.trim_matches(['[', ']']).parse::<std::net::IpAddr>().map(|ip| SocketAddr::new(ip, 53)))
                    .map_err(|_| format!("{s:?} isn't a DNS server address"))
                    .and_then(|a| guard(a.ip()).map(|()| Some(a))),
            };
            match (server, dns::record_type(record)) {
                (Err(e), _) => r.message = e,
                (_, None) => r.message = format!("{record:?} isn't a record type this agent asks for"),
                (Ok(server), Some(rtype)) => match dns::lookup(name, rtype, server, timeout).await {
                    Ok((answers, ms)) => {
                        r.latency_ms = Some(ms);
                        let norm = |s: &str| s.trim().trim_end_matches('.').to_ascii_lowercase();
                        let shown: String = answers.iter().take(5).cloned().collect::<Vec<_>>().join(", ");
                        if answers.is_empty() {
                            r.message = format!("no {} records", record.to_ascii_uppercase());
                        } else if !expect.is_empty() && !answers.iter().any(|a| expect.iter().any(|e| norm(e) == norm(a))) {
                            r.message = format!("{shown} (not what was expected)");
                        } else {
                            r.ok = true;
                            r.message = shown;
                        }
                    }
                    Err(e) => r.message = e,
                },
            }
        }
        CheckKind::Backup { .. } => r.message = "a backup check runs on the device".into(),
    }
    r.at = Utc::now();
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::public_only;
    use uuid::Uuid;

    fn spec(kind: CheckKind) -> CheckSpec {
        CheckSpec { id: Uuid::new_v4(), interval_secs: 30, timeout_secs: 5, kind }
    }

    #[tokio::test]
    async fn the_guard_applies_to_every_kind() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let refused = |r: &CheckResult| !r.ok && r.message.contains("loopback");
        for kind in [
            CheckKind::Tcp { host: "127.0.0.1".into(), port },
            CheckKind::Ping { host: "127.0.0.1".into() },
            CheckKind::Http { url: format!("http://127.0.0.1:{port}/"), method: HttpMethod::Get, statuses: vec![], keyword: None, keyword_absent: false, verify_tls: true },
            CheckKind::Tls { host: "localhost".into(), port, server_name: None },
            CheckKind::Dns { name: "example.com".into(), record: "A".into(), server: Some("127.0.0.1".into()), expect: vec![] },
        ] {
            let r = run(&spec(kind.clone()), public_only).await;
            assert!(refused(&r), "{kind:?}: {r:?}");
        }
        let r = run(&spec(CheckKind::Tcp { host: "127.0.0.1".into(), port }), crate::allow_all).await;
        assert!(r.ok, "{r:?}");
    }
}
