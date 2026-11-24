// Included by e2e.rs (`include!`): the end-user tray app section (docs/design/tray.md).

/// `rmm-agent tray` as the e2e's own user, against a1's socket (in its state directory).
fn tray_cli(dir: &Path, args: &[&str]) -> (bool, String, String) {
    let out = Command::new(agent_bin())
        .arg("tray")
        .args(args)
        .env("RMM_STATE_DIR", sensor_dir(dir, "a1", "state"))
        .output()
        .expect("running rmm-agent tray");
    (out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
}

fn tray_config(dir: &Path) -> Value {
    let (ok, out, err) = tray_cli(dir, &["--show-config"]);
    assert!(ok, "tray --show-config: {err}");
    serde_json::from_str(out.trim()).unwrap_or_else(|e| panic!("{e}: {out}"))
}

fn tray_ticket_number(out: &str) -> i64 {
    out.trim().strip_prefix("ticket #").and_then(|s| s.strip_suffix(" created")).and_then(|n| n.parse().ok()).unwrap_or_else(|| panic!("no ticket number in {out:?}"))
}

/// The headless CLI over the real Unix socket: a ticket with the screenshot, the device link and
/// the context note; a request made while the server is down arrives once; the sixth request in
/// an hour is refused; `TrayConfig` follows a client branding override.
async fn tray(server: &mut Server, admin: &Api, db: &sqlx::PgPool, dir: &Path, id1: &str, a_id: &str) {
    let sock = sensor_dir(dir, "a1", "state").join("tray.sock");
    eventually(30, "the agent's tray socket", || async { sock.exists().then_some(()) }).await;
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777, 0o666, "any local user may connect");

    // --- config: the policy's defaults and the branding, then a client override ---------------
    let c = eventually(30, "the tray config from the server", || async { Some(tray_config(dir)).filter(|c| !c.is_null()) }).await;
    assert_eq!((c["enabled"].as_bool(), c["request_help"].as_bool(), c["screenshot_default"].as_bool()), (Some(true), Some(true), Some(true)), "{c}");
    admin.put(&format!("/clients/{a_id}/branding"), json!({ "product_name": "Acme Desk", "support_phone": "+1 555 0100", "support_hours": "Mon-Fri 8-6" })).await;
    let c = eventually(30, "the client's branding on the tray", || async {
        Some(tray_config(dir)).filter(|c| c["product_name"] == "Acme Desk")
    })
    .await;
    assert_eq!((c["contact"]["phone"].as_str(), c["contact"]["hours"].as_str()), (Some("+1 555 0100"), Some("Mon-Fri 8-6")), "{c}");

    // --- a request with a screenshot ---------------------------------------------------------
    let shot = dir.join("tray-shot.jpg");
    let mut jpeg = vec![0xff, 0xd8, 0xff, 0xe0];
    jpeg.extend((0..300_000u32).map(|i| (i % 251) as u8)); // over one 256 KiB piece
    std::fs::write(&shot, &jpeg).unwrap();
    let (ok, out, err) = tray_cli(dir, &["--request", "--subject", "Printer jammed", "--body", "Paper stuck in tray 2.", "--screenshot", shot.to_str().unwrap()]);
    assert!(ok, "tray --request: {out} {err}");
    let number = tray_ticket_number(&out);
    let (tid, source, source_ref, client): (uuid::Uuid, String, Option<String>, Option<uuid::Uuid>) =
        sqlx::query_as("SELECT id, source, source_ref, client_id FROM tickets WHERE number = $1").bind(number).fetch_one(db).await.unwrap();
    assert_eq!((source.as_str(), client.map(|c| c.to_string())), ("agent", Some(a_id.to_string())));
    assert!(source_ref.is_some_and(|r| uuid::Uuid::parse_str(&r).is_ok()), "the agent's request id");
    let t = admin.get(&format!("/tickets/{tid}")).await;
    assert_eq!(t["source"], "agent", "{t}");
    assert_eq!(t["subject"], "Printer jammed");
    assert!(t["agents"].as_array().unwrap().iter().any(|a| a["id"] == id1), "linked to the device: {t}");
    let att = &t["attachments"].as_array().unwrap()[0];
    assert_eq!((att["name"].as_str(), att["size"].as_i64(), att["content_type"].as_str()), (Some("screenshot.jpg"), Some(jpeg.len() as i64), Some("image/jpeg")), "{att}");
    let events = t["events"].as_array().unwrap();
    let note = events.iter().find(|e| e["kind"] == "note").unwrap_or_else(|| panic!("a context note: {t}"));
    let user = {
        let out = Command::new("id").arg("-un").output().unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    let body = note["body"].as_str().unwrap();
    assert!(note["public"] == false && body.contains(&format!("Signed-in user: {user}")) && body.contains("Uptime:") && body.contains("Open alerts:"), "{note}");
    assert!(t["requester_name"].as_str().unwrap().starts_with(&format!("{user} on ")), "{t}");
    let audited: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action = 'ticket.create' AND target_id = $1 AND details ->> 'source' = 'agent'")
        .bind(tid)
        .fetch_one(db)
        .await
        .unwrap();
    assert_eq!(audited, 1);

    // --- the server is down: kept on the machine, sent once after reconnecting ----------------------
    server.stop();
    let (ok, out, err) = tray_cli(dir, &["--request", "--subject", "Cannot reach the internet", "--body", "Since lunch."]);
    assert!(ok && out.starts_with("queued"), "{out} {err}");
    let kept = std::fs::read_dir(sensor_dir(dir, "a1", "state").join("tray").join("requests")).unwrap().count();
    assert_eq!(kept, 1, "kept in the state directory");
    server.start_again().await;
    admin.wait_online(id1, true).await;
    eventually(90, "the queued request as a ticket", || async {
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM tickets WHERE subject = 'Cannot reach the internet' AND source = 'agent'").fetch_one(db).await.unwrap();
        (n >= 1).then_some(())
    })
    .await;
    eventually(30, "the agent to forget it", || async {
        (std::fs::read_dir(sensor_dir(dir, "a1", "state").join("tray").join("requests")).unwrap().count() == 0).then_some(())
    })
    .await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM tickets WHERE subject = 'Cannot reach the internet'").fetch_one(db).await.unwrap();
    assert_eq!(n, 1, "exactly once");

    // --- five an hour per user: three more go through, the sixth doesn't -----------------------------
    for i in 3..=5 {
        let (ok, out, err) = tray_cli(dir, &["--request", "--subject", &format!("Request {i}")]);
        assert!(ok, "request {i}: {out} {err}");
        tray_ticket_number(&out);
    }
    let (ok, out, err) = tray_cli(dir, &["--request", "--subject", "One too many"]);
    assert!(!ok && err.contains("last hour"), "{out} {err}");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM tickets WHERE subject = 'One too many'").fetch_one(db).await.unwrap();
    assert_eq!(n, 0);
    // Bad input never reaches the server.
    let (ok, _, err) = tray_cli(dir, &["--request", "--subject", "   "]);
    assert!(!ok, "{err}");

    // Put things back for the sections after this one.
    let (s, _) = admin.call(reqwest::Method::DELETE, &format!("/clients/{a_id}/branding"), None).await;
    assert!(s.is_success());
    eventually(30, "the instance branding on the tray again", || async { Some(tray_config(dir)).filter(|c| c["product_name"] != "Acme Desk") }).await;
    println!("tray: ok (tickets T-{number} and four more)");
}
