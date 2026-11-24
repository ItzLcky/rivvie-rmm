// Included by e2e.rs (`include!`): the uptime and backups sections. Kept in their own file so
// the parallel feature tracks don't all edit the same few thousand lines.

/// Local listeners for the uptime section: an HTTP server whose health can be switched, a TCP
/// port that can be closed and opened again, TLS servers with generated certificates, and a
/// one-answer DNS server.
mod uptime_fixtures {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpSocket, UdpSocket};
    use tokio::task::JoinHandle;

    pub fn bind(addr: SocketAddr) -> TcpListener {
        let s = TcpSocket::new_v4().unwrap();
        s.set_reuseaddr(true).unwrap();
        s.bind(addr).unwrap();
        s.listen(64).unwrap()
    }

    /// 200 with "e2e uptime ok" while `healthy`, else 503 "maintenance".
    pub async fn http(healthy: Arc<AtomicBool>) -> u16 {
        let l = bind("127.0.0.1:0".parse().unwrap());
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l.accept().await else { continue };
                let healthy = healthy.clone();
                tokio::spawn(async move {
                    let mut b = [0u8; 4096];
                    let _ = s.read(&mut b).await;
                    let (status, body) = if healthy.load(Ordering::SeqCst) { ("200 OK", "e2e uptime ok") } else { ("503 Service Unavailable", "maintenance") };
                    let _ = s.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await;
                });
            }
        });
        port
    }

    /// A port that accepts (and closes) connections until the task is aborted.
    pub fn tcp(addr: SocketAddr) -> JoinHandle<()> {
        let l = bind(addr);
        tokio::spawn(async move {
            loop {
                let _ = l.accept().await;
            }
        })
    }

    /// A TLS server for `localhost` whose certificate expires `days` from now (negative: expired).
    pub async fn tls(days: i64) -> u16 {
        use tokio_rustls::rustls;
        let end = chrono::Utc::now() + chrono::Duration::days(days);
        let start = chrono::Utc::now() - chrono::Duration::days(400);
        let ymd = |d: chrono::DateTime<chrono::Utc>| {
            use chrono::Datelike;
            rcgen::date_time_ymd(d.year(), d.month() as u8, d.day() as u8)
        };
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        params.not_before = ymd(start);
        params.not_after = ymd(end);
        params.distinguished_name.push(rcgen::DnType::CommonName, format!("e2e {days} days"));
        let cert = params.self_signed(&key).unwrap();
        let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()))
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let l = bind("127.0.0.1:0".parse().unwrap());
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = l.accept().await else { continue };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(mut t) = acceptor.accept(s).await {
                        let _ = t.shutdown().await;
                    }
                });
            }
        });
        port
    }

    /// Answers every A question with 10.0.0.7.
    pub async fn dns() -> u16 {
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = s.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((n, from)) = s.recv_from(&mut buf).await else { continue };
                let mut r = buf[..n].to_vec();
                r[2] = 0x81;
                r[3] = 0x80;
                r[7] = 1;
                r.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 0, 0, 7]);
                let _ = s.send_to(&r, from).await;
            }
        });
        port
    }
}

/// The monitor, once `pred` holds for it.
async fn monitor_where(admin: &Api, id: &str, what: &str, secs: u64, pred: impl Fn(&Value) -> bool) -> Value {
    eventually(secs, what, || async {
        let m = admin.get(&format!("/uptime/monitors/{id}")).await;
        pred(&m).then_some(m)
    })
    .await
}

/// Open alerts about a monitor.
async fn monitor_alerts(db: &sqlx::PgPool, id: &str) -> Vec<(String, String)> {
    sqlx::query_as("SELECT key, title FROM alerts WHERE monitor_id = $1::uuid AND resolved_at IS NULL ORDER BY key").bind(id).fetch_all(db).await.unwrap()
}

/// Asks for a check now and waits until a new result is in.
async fn check_now(admin: &Api, db: &sqlx::PgPool, id: &str) {
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM uptime_results WHERE monitor_id = $1::uuid").bind(id).fetch_one(db).await.unwrap();
    admin.post(&format!("/uptime/monitors/{id}/check"), json!({})).await;
    eventually(30, "a new check result", || async {
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM uptime_results WHERE monitor_id = $1::uuid").bind(id).fetch_one(db).await.unwrap();
        (n > before).then_some(())
    })
    .await;
}

#[allow(clippy::too_many_arguments)]
/// Uptime monitors (docs/design/uptime.md): every kind against local listeners from an agent,
/// the consecutive-failure rule, certificate alerts, a runner that goes away, scoping, health;
/// then monitors the server runs, refused private addresses, and their alerts without an agent
/// (the server restarts with RMM_UPTIME_ALLOW_PRIVATE=1 for that, and keeps it afterwards).
async fn uptime(server: &mut Server, url: &str, admin: &Api, db: &sqlx::PgPool, dir: &Path, id1: &str, a_id: &str, a_site: &str, b_id: &str) {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use reqwest::Method;

    // --- listeners ------------------------------------------------------------------------------------
    let healthy = Arc::new(AtomicBool::new(true));
    let http_port = uptime_fixtures::http(healthy.clone()).await;
    let tcp_addr: std::net::SocketAddr = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let mut tcp = uptime_fixtures::tcp(tcp_addr);
    let (tls_ok, tls_soon, tls_old) = (uptime_fixtures::tls(200).await, uptime_fixtures::tls(5).await, uptime_fixtures::tls(-3).await);
    let dns_port = uptime_fixtures::dns().await;

    // --- the agent can run checks; the alert item -----------------------------------------------------
    eventually(30, "the agent lists the checks capability", || async {
        let caps: Vec<String> = sqlx::query_scalar("SELECT unnest(capabilities) FROM agents WHERE id = $1::uuid").bind(id1).fetch_all(db).await.unwrap();
        caps.iter().any(|c| c == "checks").then_some(())
    })
    .await;
    let (s, _) = admin.alert_policy_call(json!({ "name": "bad uptime", "kind": "uptime", "params": { "failures": 0 }, "severity": "critical" })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let item = admin.alert_policy(json!({ "name": "E2E uptime", "kind": "uptime", "params": { "failures": 2, "cert_days": 14 }, "severity": "critical" })).await;
    let item_id = item["id"].as_str().unwrap().to_string();
    let alerts_before: i32 = sqlx::query_scalar("SELECT open_alerts FROM agents WHERE id = $1::uuid").bind(id1).fetch_one(db).await.unwrap();
    // The site's designated agent runs the monitors that don't name one.
    admin.put(&format!("/sites/{a_site}/network"), json!({ "agent_id": id1 })).await;

    // --- what a monitor may be ----------------------------------------------------------------------------
    let create = |body: Value| async move { admin.call(Method::POST, "/uptime/monitors", Some(body)).await };
    for (what, body) in [
        ("credentials in the URL", json!({ "site_id": a_site, "name": "x", "kind": "http", "config": { "url": "https://user:pw@example.com/" } })),
        ("not http", json!({ "site_id": a_site, "name": "x", "kind": "http", "config": { "url": "ftp://example.com/" } })),
        ("an unknown kind", json!({ "site_id": a_site, "name": "x", "kind": "smtp", "config": {} })),
        ("a runner that doesn't exist", json!({ "site_id": a_site, "name": "x", "kind": "ping", "runner": "elsewhere", "config": { "host": "10.0.0.1" } })),
        ("a private address, run by the server", json!({ "site_id": a_site, "name": "x", "kind": "ping", "runner": "server", "config": { "host": "10.0.0.1" } })),
        ("loopback, run by the server", json!({ "site_id": a_site, "name": "x", "kind": "http", "runner": "server", "config": { "url": format!("http://127.0.0.1:{http_port}/health") } })),
        ("a metadata address, run by the server", json!({ "site_id": a_site, "name": "x", "kind": "http", "runner": "server", "config": { "url": "http://169.254.169.254/latest/" } })),
        ("a private DNS server, run by the server", json!({ "site_id": a_site, "name": "x", "kind": "dns", "runner": "server", "config": { "name": "example.com", "server": "192.168.1.1" } })),
        ("an interval that's too short", json!({ "site_id": a_site, "name": "x", "kind": "ping", "interval_secs": 5, "config": { "host": "10.0.0.1" } })),
        ("another client's agent", json!({ "site_id": a_site, "name": "x", "kind": "ping", "agent_id": uuid::Uuid::new_v4(), "config": { "host": "10.0.0.1" } })),
        ("a bad DNS record", json!({ "site_id": a_site, "name": "x", "kind": "dns", "config": { "name": "example.com", "record": "SOA" } })),
    ] {
        let (s, v) = create(body).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{what}: {v}");
    }

    // --- one monitor of each kind ------------------------------------------------------------------------
    let mk = |name: &str, kind: &str, config: Value| json!({ "site_id": a_site, "name": name, "kind": kind, "config": config, "interval_secs": 30, "timeout_secs": 5 });
    let mut ids = std::collections::HashMap::new();
    for (name, kind, config) in [
        ("E2E web", "http", json!({ "url": format!("http://127.0.0.1:{http_port}/health"), "keyword": "uptime ok" })),
        ("E2E port", "tcp", json!({ "host": "127.0.0.1", "port": tcp_addr.port() })),
        ("E2E ping", "ping", json!({ "host": "127.0.0.1" })),
        ("E2E cert", "tls", json!({ "host": "127.0.0.1", "port": tls_ok, "server_name": "localhost" })),
        ("E2E cert soon", "tls", json!({ "host": "127.0.0.1", "port": tls_soon, "server_name": "localhost" })),
        ("E2E cert expired", "tls", json!({ "host": "127.0.0.1", "port": tls_old, "server_name": "localhost" })),
        ("E2E dns", "dns", json!({ "name": "svc.e2e.test", "record": "A", "server": format!("127.0.0.1:{dns_port}"), "expect": ["10.0.0.7"] })),
    ] {
        let v = admin.post("/uptime/monitors", mk(name, kind, config)).await;
        ids.insert(name, v["id"].as_str().unwrap().to_string());
    }
    let (s, _) = create(mk("E2E web", "ping", json!({ "host": "10.0.0.1" }))).await;
    assert_eq!(s, StatusCode::CONFLICT, "names are unique per client");
    for name in ["E2E web", "E2E port", "E2E cert", "E2E cert soon", "E2E cert expired", "E2E dns"] {
        let m = monitor_where(admin, &ids[name], &format!("{name} up"), 60, |m| m["state"] == "up").await;
        assert_eq!((m["runner_agent_id"].as_str(), m["agent_id"].as_str()), (Some(id1), None), "{name}: the designated agent runs it: {m}");
    }
    // ICMP needs the agent's group in net.ipv4.ping_group_range: up, or down saying why.
    let ping = monitor_where(admin, &ids["E2E ping"], "the ping monitor checked", 60, |m| m["last_at"].is_string()).await;
    assert!(ping["state"] == "up" || ping["last_message"].as_str().unwrap_or("").contains("ICMP"), "{ping}");
    let dns = admin.get(&format!("/uptime/monitors/{}", ids["E2E dns"])).await;
    assert_eq!(dns["last_message"], "10.0.0.7", "{dns}");
    let web = admin.get(&format!("/uptime/monitors/{}", ids["E2E web"])).await;
    assert!(web["last_message"] == "HTTP 200" && web["last_value"] == 200.0 && web["uptime_24h"] == 100.0, "{web}");
    assert!(!web.to_string().contains("e2e uptime ok\""), "the body is never stored: {web}");

    // --- certificates ---------------------------------------------------------------------------------------
    let cert = admin.get(&format!("/uptime/monitors/{}", ids["E2E cert"])).await;
    assert!(cert["cert"]["subject"].as_str().unwrap().contains("e2e 200 days") && cert["cert"]["sans"][0] == "localhost", "{cert}");
    assert!(cert["cert"]["untrusted"].is_string(), "self-signed: read, and said to be untrusted: {cert}");
    assert!(monitor_alerts(db, &ids["E2E cert"]).await.is_empty(), "200 days left is fine");
    let soon = eventually(30, "the certificate alert", || async {
        let a = monitor_alerts(db, &ids["E2E cert soon"]).await;
        (!a.is_empty()).then_some(a)
    })
    .await;
    assert_eq!(soon[0].0, format!("mon:{}:cert", ids["E2E cert soon"]));
    assert!(soon[0].1.starts_with("Certificate expires in") && soon[0].1.ends_with("E2E cert soon"), "{soon:?}");
    let old = eventually(30, "the expired certificate alert", || async {
        let a = monitor_alerts(db, &ids["E2E cert expired"]).await;
        (!a.is_empty()).then_some(a)
    })
    .await;
    assert_eq!(old[0].1, "Certificate expired: E2E cert expired");

    // --- down after two failures, up again ----------------------------------------------------------------
    healthy.store(false, Ordering::SeqCst);
    check_now(admin, db, &ids["E2E web"]).await;
    let m = monitor_where(admin, &ids["E2E web"], "one failure", 10, |m| m["fail_count"] == 1).await;
    assert_eq!(m["state"], "down");
    assert!(m["last_message"].as_str().unwrap().contains("HTTP 503"), "{m}");
    assert!(monitor_alerts(db, &ids["E2E web"]).await.is_empty(), "one failed check isn't an alert yet");
    check_now(admin, db, &ids["E2E web"]).await;
    let down = eventually(30, "the down alert", || async {
        let a = monitor_alerts(db, &ids["E2E web"]).await;
        (!a.is_empty()).then_some(a)
    })
    .await;
    assert_eq!((down[0].0.clone(), down[0].1.as_str()), (format!("mon:{}", ids["E2E web"]), "Monitor down: E2E web"));
    let listed = alerts_for(admin, "kind=uptime").await;
    let row = listed.iter().find(|a| a["monitor_id"] == ids["E2E web"].as_str()).expect("listed with its monitor");
    assert_eq!((row["monitor_name"].as_str(), row["agent_id"].as_str()), (Some("E2E web"), Some(id1)));
    // Not the runner's health.
    let open: i32 = sqlx::query_scalar("SELECT open_alerts FROM agents WHERE id = $1::uuid").bind(id1).fetch_one(db).await.unwrap();
    assert_eq!(open, alerts_before, "monitor alerts don't count against the agent that runs them");
    healthy.store(true, Ordering::SeqCst);
    check_now(admin, db, &ids["E2E web"]).await;
    monitor_where(admin, &ids["E2E web"], "up again", 10, |m| m["state"] == "up").await;
    eventually(10, "the down alert to clear", || async { monitor_alerts(db, &ids["E2E web"]).await.is_empty().then_some(()) }).await;

    // The TCP port goes away, then comes back on the same port.
    tcp.abort();
    let _ = tcp.await;
    check_now(admin, db, &ids["E2E port"]).await;
    check_now(admin, db, &ids["E2E port"]).await;
    let m = monitor_where(admin, &ids["E2E port"], "the port down", 10, |m| m["state"] == "down" && m["fail_count"].as_i64() >= Some(2)).await;
    assert!(m["last_message"].as_str().unwrap().contains("refused"), "{m}");
    eventually(20, "the port alert", || async { (!monitor_alerts(db, &ids["E2E port"]).await.is_empty()).then_some(()) }).await;
    tcp = uptime_fixtures::tcp(tcp_addr);
    check_now(admin, db, &ids["E2E port"]).await;
    eventually(20, "the port alert to clear", || async { monitor_alerts(db, &ids["E2E port"]).await.is_empty().then_some(()) }).await;

    // --- history, summary --------------------------------------------------------------------------------------
    let points = admin.get(&format!("/uptime/monitors/{}/results", ids["E2E web"])).await;
    let (checks, failures) = points.as_array().unwrap().iter().fold((0, 0), |(c, f), p| (c + p["checks"].as_i64().unwrap(), f + p["failures"].as_i64().unwrap()));
    assert!(checks >= 4 && failures >= 2, "{points}");
    let detail = admin.get(&format!("/uptime/monitors/{}", ids["E2E web"])).await;
    let today = &detail["days"].as_array().unwrap().last().unwrap().clone();
    assert!(today["failures"].as_i64() >= Some(2) && detail["recent"].as_array().unwrap().len() >= 4, "{detail}");
    let summary = admin.get(&format!("/uptime/summary?client_id={a_id}")).await;
    assert!(summary["monitors"].as_i64() >= Some(7) && summary["down"].as_i64().is_some(), "{summary}");
    assert_eq!(admin.get(&format!("/uptime/monitors?client_id={b_id}")).await.as_array().unwrap().len(), 0);
    let (s, _) = admin.call(Method::GET, &format!("/uptime/monitors/{}/results?from=2026-01-02T00:00:00Z&to=2026-01-01T00:00:00Z", ids["E2E web"]), None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // --- another client's technician sees none of it -----------------------------------------------------------
    let other = signed_in(url, admin, "uptime-tech-b@e2e.test", "technician", Some(b_id), false).await;
    let (s, _) = other.call(Method::GET, &format!("/uptime/monitors/{}", ids["E2E web"]), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = other.call(Method::POST, &format!("/uptime/monitors/{}/check", ids["E2E web"]), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert!(other.get("/uptime/monitors").await.as_array().unwrap().is_empty());
    let ro = signed_in(url, admin, "uptime-ro@e2e.test", "readonly", None, false).await;
    assert!(ro.get(&format!("/uptime/monitors/{}", ids["E2E web"])).await["name"] == "E2E web", "read-only users can look");
    let (s, _) = ro.call(Method::POST, "/uptime/monitors", Some(mk("ro", "ping", json!({ "host": "10.0.0.1" })))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // --- a runner that goes away: unknown, not down ----------------------------------------------------------------
    let token = admin.post(&format!("/sites/{a_site}/enrollment-tokens"), json!({ "label": "uptime runner" })).await;
    let mut runner = Agent::new(dir, "uprunner");
    let runner_id = runner.enroll(url, token["token"].as_str().unwrap()).unwrap();
    runner.run(dir);
    admin.wait_online(&runner_id, true).await;
    let own = admin.post("/uptime/monitors", json!({ "site_id": a_site, "name": "E2E own runner", "kind": "tcp", "agent_id": runner_id, "config": { "host": "127.0.0.1", "port": tcp_addr.port() }, "interval_secs": 30, "timeout_secs": 5 })).await;
    let own_id = own["id"].as_str().unwrap().to_string();
    let m = monitor_where(admin, &own_id, "checked by the named agent", 60, |m| m["state"] == "up").await;
    assert_eq!(m["runner_hostname"].as_str(), admin.get(&format!("/agents/{runner_id}")).await["hostname"].as_str());
    tcp.abort();
    runner.kill();
    admin.wait_online(&runner_id, false).await;
    monitor_where(admin, &own_id, "unknown once its agent is offline", 30, |m| m["state"] == "unknown").await;
    let (s, v) = admin.call(Method::POST, &format!("/uptime/monitors/{own_id}/check"), None).await;
    assert!(s == StatusCode::CONFLICT && v.to_string().contains("offline"), "{s} {v}");
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(monitor_alerts(db, &own_id).await.is_empty(), "no alert for a monitor nobody is checking");

    // --- run by the server --------------------------------------------------------------------------------------
    // A name that resolves to loopback is refused when the check runs (after resolution).
    let srv = admin
        .post("/uptime/monitors", json!({ "site_id": a_site, "name": "E2E server web", "kind": "http", "runner": "server", "agent_id": id1,
            "config": { "url": format!("http://localhost:{http_port}/health"), "keyword": "uptime ok" }, "interval_secs": 30, "timeout_secs": 5 }))
        .await;
    let srv_id = srv["id"].as_str().unwrap().to_string();
    let m = monitor_where(admin, &srv_id, "the server's first check", 30, |m| m["last_at"].is_string()).await;
    assert!(m["state"] == "down" && m["last_message"].as_str().unwrap().contains("loopback"), "refused without RMM_UPTIME_ALLOW_PRIVATE: {m}");
    assert!(m["runner"] == "server" && m["agent_id"].is_null() && m["runner_agent_id"].is_null() && m["runner_online"] == true, "no agent: {m}");
    // Allowed, after a restart with RMM_UPTIME_ALLOW_PRIVATE=1.
    // SAFETY: set before the restart below; nothing else in the test reads this variable.
    unsafe { std::env::set_var("RMM_UPTIME_ALLOW_PRIVATE", "1") };
    server.restart().await;
    admin.wait_online(id1, true).await;
    check_now(admin, db, &srv_id).await;
    let m = monitor_where(admin, &srv_id, "the server's monitor up", 30, |m| m["state"] == "up").await;
    assert_eq!(m["last_message"], "HTTP 200", "{m}");
    // Down twice: an alert of the All devices item, with no agent, for the monitor's client.
    healthy.store(false, Ordering::SeqCst);
    check_now(admin, db, &srv_id).await;
    check_now(admin, db, &srv_id).await;
    let down = eventually(30, "the server monitor's down alert", || async {
        let a = monitor_alerts(db, &srv_id).await;
        (!a.is_empty()).then_some(a)
    })
    .await;
    assert_eq!(down[0].1, "Monitor down: E2E server web");
    let (agent, client, policy): (Option<uuid::Uuid>, uuid::Uuid, Option<uuid::Uuid>) =
        sqlx::query_as("SELECT agent_id, client_id, policy_id FROM alerts WHERE monitor_id = $1::uuid AND resolved_at IS NULL").bind(&srv_id).fetch_one(db).await.unwrap();
    assert_eq!((agent, client.to_string(), policy.map(|p| p.to_string())), (None, a_id.to_string(), Some(item_id.clone())));
    let listed = alerts_for(admin, "kind=uptime").await;
    let row = listed.iter().find(|a| a["monitor_id"] == srv_id.as_str()).expect("an alert without an agent is listed");
    assert!(row["agent_id"].is_null() && row["hostname"].is_null() && row["client_id"] == a_id && row["site_name"].is_string(), "{row}");
    let alert_id = row["id"].as_str().unwrap().to_string();
    let found = alerts_for(admin, "q=E2E%20server").await;
    assert!(found.iter().any(|a| a["id"] == alert_id.as_str()), "found by its monitor's name");
    assert_eq!(admin.get(&format!("/alerts/{alert_id}")).await["monitor_name"], "E2E server web");
    let open: i32 = sqlx::query_scalar("SELECT open_alerts FROM agents WHERE id = $1::uuid").bind(id1).fetch_one(db).await.unwrap();
    assert_eq!(open, alerts_before, "nobody's health");
    let (s, _) = other.call(Method::GET, &format!("/alerts/{alert_id}"), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "another client's technician can't see it");
    let (s, v) = other.call(Method::POST, &format!("/alerts/{alert_id}/acknowledge"), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "nor acknowledge it: {v}");
    let acked = admin.post(&format!("/alerts/{alert_id}/acknowledge"), json!({})).await;
    assert_eq!(acked["state"], "acknowledged", "{acked}");
    healthy.store(true, Ordering::SeqCst);
    check_now(admin, db, &srv_id).await;
    eventually(20, "the server monitor's alert to clear", || async { monitor_alerts(db, &srv_id).await.is_empty().then_some(()) }).await;
    // Back to an agent: no agentless alert survives the move.
    admin.put(&format!("/uptime/monitors/{srv_id}"), json!({ "runner": "agent" })).await;
    let m = admin.get(&format!("/uptime/monitors/{srv_id}")).await;
    assert_eq!((m["runner"].as_str(), m["runner_agent_id"].as_str()), (Some("agent"), Some(id1)), "{m}");
    ids.insert("E2E server web", srv_id.clone());

    // --- switched off: its alerts close; deleted: gone ----------------------------------------------------------
    admin.put(&format!("/uptime/monitors/{}", ids["E2E cert soon"]), json!({ "enabled": false })).await;
    assert!(monitor_alerts(db, &ids["E2E cert soon"]).await.is_empty(), "switched off closes its alerts");
    assert_eq!(admin.get(&format!("/uptime/monitors/{}", ids["E2E cert soon"])).await["state"], "unknown");
    let audit: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action LIKE 'uptime.%'").fetch_one(db).await.unwrap();
    assert!(audit >= 10, "creates, checks and updates are audited ({audit})");
    for id in ids.values().chain([&own_id]) {
        let (s, _) = admin.call(Method::DELETE, &format!("/uptime/monitors/{id}"), None).await;
        assert!(s.is_success());
    }
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM alerts WHERE monitor_id IS NOT NULL AND resolved_at IS NULL").fetch_one(db).await.unwrap();
    assert_eq!(left, 0);
    assert!(admin.delete_policy(&item_id).await.is_success());
    let (s, _) = admin.call(Method::DELETE, &format!("/agents/{runner_id}"), None).await;
    assert!(s.is_success());
}

/// Writes the backup jobs the debug agent reports (`RMM_BACKUP_FAKE`).
fn write_backups(dir: &Path, agent: &str, jobs: Value) {
    std::fs::write(dir.join(format!("{agent}-backups.json")), json!({ "jobs": jobs }).to_string()).unwrap();
}

async fn backup_alerts(db: &sqlx::PgPool, agent: &str) -> Vec<(String, String)> {
    sqlx::query_as("SELECT key, title FROM alerts WHERE agent_id = $1::uuid AND kind = 'backup' AND resolved_at IS NULL ORDER BY key")
        .bind(agent)
        .fetch_all(db)
        .await
        .unwrap()
}

/// Asks the device to read its backups now and waits for the report.
async fn read_backups(admin: &Api, db: &sqlx::PgPool, agent: &str) {
    let before: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT max(updated_at) FROM backup_jobs WHERE agent_id = $1::uuid").bind(agent).fetch_one(db).await.unwrap();
    admin.post(&format!("/agents/{agent}/backups/check"), json!({})).await;
    eventually(30, "a new backup report", || async {
        let now: Option<chrono::DateTime<chrono::Utc>> =
            sqlx::query_scalar("SELECT max(updated_at) FROM backup_jobs WHERE agent_id = $1::uuid").bind(agent).fetch_one(db).await.unwrap();
        (now.is_some() && now != before).then_some(())
    })
    .await;
    // The alert is evaluated right after the rows are written.
    tokio::time::sleep(Duration::from_millis(500)).await;
}

/// Backup monitoring (docs/design/backups.md), with the agent's fake provider: a fresh success,
/// a failure, a stale job, recovery, a required backup that is missing. A real restic repository
/// too when `restic` is on PATH.
async fn backups(url: &str, admin: &Api, db: &sqlx::PgPool, dir: &Path, id1: &str, b_id: &str) {
    use reqwest::Method;
    let hours_ago = |h: i64| (chrono::Utc::now() - chrono::Duration::hours(h)).to_rfc3339();
    let job = |result: &str, success_hours: i64| json!({ "provider": "veeam", "job": "Nightly", "last_run_at": hours_ago(1), "last_success_at": hours_ago(success_hours), "last_result": result, "message": if result == "failed" { "There is not enough space on the disk." } else { "" } });
    write_backups(dir, "a1", json!([job("success", 1)]));

    for (what, params) in [
        ("a relative env file", json!({ "providers": [], "sources": [{ "provider": "restic", "env_file": "etc/restic/env" }] })),
        ("an unknown product", json!({ "providers": ["tape"] })),
        ("an age of zero", json!({ "max_age_hours": 0 })),
        ("a source for a product that finds its own jobs", json!({ "sources": [{ "provider": "veeam", "path": "/x" }] })),
    ] {
        let (s, v) = admin.alert_policy_call(json!({ "name": "bad backup", "kind": "backup", "params": params, "severity": "warning" })).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{what}: {v}");
    }
    let item = admin.alert_policy(json!({ "name": "E2E backups", "kind": "backup", "params": { "providers": ["auto"], "max_age_hours": 26 }, "severity": "warning" })).await;
    let item_id = item["id"].as_str().unwrap().to_string();
    // The new item's check runs as soon as the agent gets it.
    let jobs = eventually(30, "the first backup report", || async {
        let j = admin.get(&format!("/agents/{id1}/backups")).await;
        (j.as_array().unwrap().len() == 1).then_some(j)
    })
    .await;
    assert!(jobs[0]["job"] == "Nightly" && jobs[0]["last_result"] == "success" && jobs[0]["alerting"] == false, "{jobs}");
    assert!(backup_alerts(db, id1).await.is_empty(), "a fresh success is fine");
    let fleet = admin.get("/backups?result=success").await;
    assert!(fleet["items"].as_array().unwrap().iter().any(|j| j["agent_id"] == id1 && j["provider"] == "veeam"), "{fleet}");
    assert_eq!(admin.get("/backups?result=failed").await["total"], 0);
    let (s, _) = admin.call(Method::GET, "/backups?result=bogus", None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // --- failure -------------------------------------------------------------------------------------------
    write_backups(dir, "a1", json!([job("failed", 20)]));
    read_backups(admin, db, id1).await;
    let a = backup_alerts(db, id1).await;
    assert_eq!(a, [("backup:veeam:Nightly".to_string(), "Backup failed: Nightly (Veeam)".to_string())]);
    let fleet = admin.get("/backups?alerting=true").await;
    assert_eq!(fleet["items"][0]["last_result"], "failed", "{fleet}");
    let kinds = alerts_for(admin, &format!("agent_id={id1}&kind=backup")).await;
    assert_eq!(kinds.len(), 1);

    // --- stale (the same key: the alert stays open, saying why now) ------------------------------------------
    write_backups(dir, "a1", json!([job("success", 30)]));
    read_backups(admin, db, id1).await;
    let a = backup_alerts(db, id1).await;
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].1, "No successful backup for 26 hours: Nightly (Veeam)");

    // --- recovery -----------------------------------------------------------------------------------------------
    write_backups(dir, "a1", json!([job("success", 1)]));
    read_backups(admin, db, id1).await;
    assert!(backup_alerts(db, id1).await.is_empty(), "a fresh success clears it");

    // --- required, and nothing there -----------------------------------------------------------------------------
    let mut cfg = admin.item_in(ROOT_SET, &item_id).await["item_config"].clone();
    cfg["params"]["require"] = json!(true);
    cfg["params"]["jobs"] = json!(["Weekly*"]);
    let (s, v) = admin.call(Method::PUT, &format!("/policy-items/{item_id}"), Some(json!({ "config": cfg }))).await;
    assert!(s.is_success(), "{v}");
    eventually(30, "no matching job alert", || async {
        let a = backup_alerts(db, id1).await;
        (a.len() == 1 && a[0].0 == "backup:none").then_some(())
    })
    .await;

    // --- scoping --------------------------------------------------------------------------------------------------
    let other = signed_in(url, admin, "backup-tech-b@e2e.test", "technician", Some(b_id), false).await;
    let (s, _) = other.call(Method::GET, &format!("/agents/{id1}/backups"), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = other.call(Method::POST, &format!("/agents/{id1}/backups/check"), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(other.get("/backups").await["total"], 0);

    // --- a real restic repository, when restic is installed -----------------------------------------------------------
    let restic = Command::new("restic").arg("version").output().is_ok_and(|o| o.status.success());
    if restic {
        let repo = dir.join("restic-repo");
        let pw = dir.join("restic-pw");
        let data = dir.join("restic-data");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::write(data.join("file.txt"), "backed up").unwrap();
        std::fs::write(&pw, "e2e-restic-password").unwrap();
        let run = |args: &[&str]| {
            let o = Command::new("restic").args(args).env("RESTIC_REPOSITORY", &repo).env("RESTIC_PASSWORD_FILE", &pw).output().unwrap();
            assert!(o.status.success(), "restic {args:?}: {}", String::from_utf8_lossy(&o.stderr));
        };
        run(&["init"]);
        run(&["backup", data.to_str().unwrap()]);
        let env = dir.join("restic.env");
        std::fs::write(&env, format!("RESTIC_REPOSITORY={}\nRESTIC_PASSWORD_FILE={}\n", repo.display(), pw.display())).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&env, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        // The fake only answers while its file exists.
        std::fs::remove_file(dir.join("a1-backups.json")).unwrap();
        cfg["params"] = json!({ "providers": [], "sources": [{ "provider": "restic", "env_file": env.to_str().unwrap() }], "max_age_hours": 26, "require": true });
        let (s, v) = admin.call(Method::PUT, &format!("/policy-items/{item_id}"), Some(json!({ "config": cfg }))).await;
        assert!(s.is_success(), "{v}");
        let j = eventually(120, "the restic repository read", || async {
            let all = admin.get(&format!("/agents/{id1}/backups")).await;
            all.as_array().unwrap().iter().find(|j| j["provider"] == "restic").cloned()
        })
        .await;
        assert!(j["last_result"] == "success" && j["job"] == repo.to_str().unwrap() && j["last_success_at"].is_string(), "{j}");
        eventually(30, "no backup alert for a fresh restic snapshot", || async { backup_alerts(db, id1).await.is_empty().then_some(()) }).await;
    } else {
        println!("backups: restic isn't installed, skipping the real repository");
    }

    // --- the item goes: its alerts close quietly -------------------------------------------------------------------
    assert!(admin.delete_policy(&item_id).await.is_success());
    assert!(backup_alerts(db, id1).await.is_empty());
    let (s, v) = admin.call(Method::POST, &format!("/agents/{id1}/backups/check"), None).await;
    assert_eq!(s, StatusCode::CONFLICT, "nothing to read without an item: {v}");
    let _ = std::fs::remove_file(dir.join("a1-backups.json"));
}
