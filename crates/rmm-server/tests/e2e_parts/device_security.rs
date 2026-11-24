// Included by e2e.rs (`include!`): the disk encryption and local admin sections (parity plan
// B1, B2). Kept in their own file so the parallel feature tracks don't all edit e2e.rs.

const DISKENC_ITEM: &str = "00000000-0000-4000-8000-000000000005";
const LOCAL_ADMIN_ITEM: &str = "00000000-0000-4000-8000-000000000006";

/// Writes the disk encryption state the debug agent reports (`RMM_DISKENC_FAKE`).
fn write_diskenc(dir: &Path, agent: &str, state: &Value) {
    std::fs::write(dir.join(format!("{agent}-diskenc.json")), state.to_string()).unwrap();
}

fn read_diskenc(dir: &Path, agent: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(dir.join(format!("{agent}-diskenc.json"))).unwrap()).unwrap()
}

/// Asks the agent to report now and waits until the report is stored (and acted on).
async fn report_diskenc(admin: &Api, db: &sqlx::PgPool, agent: &str) {
    let before: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar("SELECT diskenc_at FROM agents WHERE id = $1::uuid").bind(agent).fetch_one(db).await.unwrap();
    admin.post(&format!("/agents/{agent}/disk-encryption/refresh"), json!({})).await;
    eventually(30, "a disk encryption report", || async {
        let now: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar("SELECT diskenc_at FROM agents WHERE id = $1::uuid").bind(agent).fetch_one(db).await.unwrap();
        (now.is_some() && now != before).then_some(())
    })
    .await;
    // Keys are requested and alerts checked right after the rows are written.
    tokio::time::sleep(Duration::from_millis(800)).await;
}

async fn diskenc_alerts(db: &sqlx::PgPool, agent: &str) -> Vec<(String, String)> {
    sqlx::query_as("SELECT key, details ->> 'finding' FROM alerts WHERE agent_id = $1::uuid AND kind = 'disk_encryption' AND resolved_at IS NULL ORDER BY key")
        .bind(agent)
        .fetch_all(db)
        .await
        .unwrap()
}

/// `(item id, protector id in the username, history rows)` of the recovery item of a volume.
async fn recovery_item(db: &sqlx::PgPool, agent: &str, volume: &str) -> Option<(String, String, i64)> {
    sqlx::query_as(
        "SELECT i.id::text, i.username, (SELECT count(*) FROM vault_item_history h WHERE h.item_id = i.id)
           FROM vault_items i WHERE i.managed_kind = 'disk_recovery' AND i.managed_ref = $1",
    )
    .bind(format!("{agent}:{volume}"))
    .fetch_optional(db)
    .await
    .unwrap()
}

/// The agent's own config: `(agent_id, secret)`.
fn agent_credentials(dir: &Path, name: &str) -> (String, String) {
    let raw = std::fs::read_to_string(dir.join(format!("{name}.toml"))).unwrap();
    let get = |k: &str| raw.lines().find_map(|l| l.strip_prefix(&format!("{k} = "))).unwrap().trim().trim_matches('"').to_string();
    (get("agent_id"), get("secret"))
}

/// Connects as `name` over the agent protocol and sends `msgs` (a stand-in for a hostile agent).
async fn send_as_agent(url: &str, dir: &Path, name: &str, msgs: Vec<rmm_proto::AgentMsg>) {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    let (id, secret) = agent_credentials(dir, name);
    let ws_url = format!("{}/api/agent/ws", url.replace("http://", "ws://"));
    let (mut ws, _) = tokio_tungstenite::connect_async(ws_url).await.unwrap();
    let auth = rmm_proto::AgentMsg::Auth {
        protocol: rmm_proto::PROTOCOL_VERSION,
        agent_id: id.parse().unwrap(),
        secret,
        agent_version: "0.0.0-e2e".into(),
        jobs: vec![],
        capabilities: vec![rmm_proto::diskenc::CAPABILITY.into()],
        patch_runs: vec![],
        security_actions: vec![],
        software_runs: vec![],
    };
    ws.send(Message::Binary(rmm_proto::encode(&auth).unwrap().into())).await.unwrap();
    let first = tokio::time::timeout(Duration::from_secs(10), ws.next()).await.unwrap().unwrap().unwrap();
    let Message::Binary(b) = first else { panic!("{first:?}") };
    assert!(matches!(rmm_proto::decode::<rmm_proto::ServerMsg>(&b).unwrap(), rmm_proto::ServerMsg::AuthOk { .. }));
    for m in msgs {
        ws.send(Message::Binary(rmm_proto::encode(&m).unwrap().into())).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(800)).await;
    let _ = ws.close(None).await;
}

/// Disk encryption with the agent's fake (docs/design/disk-encryption.md): an unencrypted volume
/// alerts and changes health; encrypting it with a recovery password escrows the key into the
/// vault, where reveal returns it; a rotation updates the item and keeps the old key in its
/// history; a key from another agent is ignored; with escrow off nothing is requested.
async fn disk_encryption(url: &str, admin: &Api, db: &sqlx::PgPool, dir: &Path, id1: &str, b_id: &str) {
    use reqwest::Method;
    let vol = |status: &str, kind: &str, protectors: Value, recovery: Option<&str>| {
        json!({ "volume_id": "C:", "mount": "C:\\", "device": "\\\\?\\Volume{e2e}\\", "kind": kind, "role": "os", "status": status,
                "percent": if status == "unencrypted" { 0.0 } else { 100.0 }, "method": "XTS-AES-128", "protectors": protectors,
                "protection_on": status == "encrypted", "locked": false, "recovery_protector_id": recovery })
    };
    let data = json!({ "volume_id": "D:", "mount": "D:\\", "kind": "none", "role": "data", "status": "unencrypted" });
    write_diskenc(dir, "a1", &json!({ "volumes": [vol("unencrypted", "none", json!([]), None), data], "tpm": { "present": true, "version": "2.0" } }));

    for (what, params) in [("a volume set that doesn't exist", json!({ "volumes": "usb" })), ("a negative grace period", json!({ "grace_hours": -1 }))] {
        let (s, v) = admin.alert_policy_call(json!({ "name": "bad disk", "kind": "disk_encryption", "params": params, "severity": "warning" })).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{what}: {v}");
    }
    let item = admin.alert_policy(json!({ "name": "E2E disk encryption", "kind": "disk_encryption", "params": { "volumes": "os" }, "severity": "critical" })).await;
    let item_id = item["id"].as_str().unwrap().to_string();

    // --- unencrypted --------------------------------------------------------------------------------------
    report_diskenc(admin, db, id1).await;
    let d = admin.get(&format!("/agents/{id1}/disk-encryption")).await;
    assert_eq!(d["volumes"].as_array().unwrap().len(), 2, "{d}");
    assert_eq!((d["volumes"][0]["volume_id"].as_str(), d["volumes"][0]["status"].as_str()), (Some("C:"), Some("unencrypted")), "the OS volume first: {d}");
    assert_eq!((d["summary"].as_str(), d["escrow_recovery_keys"].as_bool(), d["tpm"]["version"].as_str()), (Some("none"), Some(true), Some("2.0")));
    assert_eq!(diskenc_alerts(db, id1).await, [("vol:C:".to_string(), "unencrypted".to_string())], "only the OS volume with volumes=os");
    let a = admin.get(&format!("/agents/{id1}")).await;
    assert_eq!(a["encryption"], "none");
    assert_eq!(a["health"], "unhealthy", "a critical alert: {a}");
    let listed = admin.get("/agents?encryption=none").await;
    assert!(listed["items"].as_array().unwrap().iter().any(|x| x["id"] == id1), "{listed}");
    assert!(!admin.get("/agents?encryption=encrypted").await["items"].as_array().unwrap().iter().any(|x| x["id"] == id1));
    let (s, _) = admin.call(Method::GET, "/agents?encryption=sideways", None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let fleet = admin.get("/disk-encryption?status=unencrypted&os_only=true").await;
    assert!(fleet["items"].as_array().unwrap().iter().any(|v| v["agent_id"] == id1 && v["alerting"] == true), "{fleet}");

    // --- encrypted with a recovery password: escrowed ------------------------------------------------------
    let (p1, k1) = ("{11111111-AAAA-4BBB-8CCC-000000000001}", "111111-222222-333333-444444-555555-666666-777777-888888");
    write_diskenc(dir, "a1", &json!({ "volumes": [vol("encrypted", "bitlocker", json!(["tpm", "recovery_password"]), Some(p1)), data], "keys": { p1: k1 } }));
    report_diskenc(admin, db, id1).await;
    let (vault_id, user, history) = eventually(30, "the recovery key in the vault", || async { recovery_item(db, id1, "C:").await }).await;
    assert_eq!((user.as_str(), history), (p1, 0));
    assert_eq!(admin.post(&format!("/vault/{vault_id}/reveal"), json!({ "field": "password" })).await["value"], k1);
    let d = admin.get(&format!("/agents/{id1}/disk-encryption")).await;
    assert_eq!((d["volumes"][0]["escrowed"].as_bool(), d["volumes"][0]["vault_item_id"].as_str()), (Some(true), Some(vault_id.as_str())), "{d}");
    assert!(diskenc_alerts(db, id1).await.is_empty(), "encrypted and escrowed");
    let audit: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action = 'diskenc.escrow' AND target_id = $1::uuid").bind(id1).fetch_one(db).await.unwrap();
    assert_eq!(audit, 1);
    let leaked: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE details::text LIKE '%' || $1 || '%'").bind(k1).fetch_one(db).await.unwrap();
    assert_eq!(leaked, 0, "the key is never in the audit log");
    // The same report again asks for nothing new.
    report_diskenc(admin, db, id1).await;
    assert_eq!(recovery_item(db, id1, "C:").await.unwrap().2, 0);

    // --- rotate: a new protector id updates the item, the old key goes to its history -------------------------
    let tech_b = signed_in(url, admin, "diskenc-tech-b@e2e.test", "technician", Some(b_id), false).await;
    let (s, _) = tech_b.call(Method::POST, &format!("/agents/{id1}/disk-encryption/C:/rotate-key"), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "another client's technician");
    assert_eq!(tech_b.get("/disk-encryption").await["total"], 0);
    let r = admin.post(&format!("/agents/{id1}/disk-encryption/C:/rotate-key"), json!({})).await;
    assert!(r["message"].as_str().unwrap().contains("Replaced"), "{r}");
    let fake = read_diskenc(dir, "a1");
    let p2 = fake["volumes"][0]["recovery_protector_id"].as_str().unwrap().to_string();
    let k2 = fake["keys"][&p2].as_str().unwrap().to_string();
    assert_ne!(p2, p1);
    let (same_id, user, history) = eventually(30, "the new key escrowed", || async { recovery_item(db, id1, "C:").await.filter(|i| i.1 == p2) }).await;
    assert_eq!((same_id.as_str(), user.as_str(), history), (vault_id.as_str(), p2.as_str(), 1), "one item, one history row");
    assert_eq!(admin.post(&format!("/vault/{vault_id}/reveal"), json!({ "field": "password" })).await["value"], k2);
    let h: i64 = sqlx::query_scalar("SELECT id FROM vault_item_history WHERE item_id = $1::uuid").bind(&vault_id).fetch_one(db).await.unwrap();
    assert_eq!(admin.post(&format!("/vault/{vault_id}/reveal"), json!({ "history": h })).await["value"], k1);
    let rotated: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action = 'diskenc.rotate' AND target_id = $1::uuid").bind(id1).fetch_one(db).await.unwrap();
    assert_eq!(rotated, 1);

    // --- a key from another agent is ignored --------------------------------------------------------------------
    let (id3, _) = agent_credentials(dir, "a3");
    send_as_agent(
        url,
        dir,
        "a3",
        vec![
            rmm_proto::AgentMsg::DiskRecoveryKey {
                request_id: uuid::Uuid::new_v4(),
                volume_id: "C:".into(),
                protector_id: p2.clone(),
                key: Some(rmm_proto::localadmin::Secret("999999-999999-999999-999999-999999-999999-999999-999999".into())),
                error: None,
            },
        ],
    )
    .await;
    assert!(recovery_item(db, &id3, "C:").await.is_none(), "nothing stored for the sender");
    assert_eq!(admin.post(&format!("/vault/{vault_id}/reveal"), json!({ "field": "password" })).await["value"], k2, "a1's key unchanged");

    // --- escrow off: nothing is requested, and the item says the key isn't escrowed ----------------------------------
    let (s, v) = admin.set_root_item(DISKENC_ITEM, json!({ "escrow_recovery_keys": false })).await;
    assert!(s.is_success(), "{v}");
    let p3 = "{33333333-AAAA-4BBB-8CCC-000000000003}";
    let mut fake = read_diskenc(dir, "a1");
    fake["volumes"][0]["recovery_protector_id"] = json!(p3);
    fake["keys"][p3] = json!("333333-333333-333333-333333-333333-333333-333333-333333");
    write_diskenc(dir, "a1", &fake);
    report_diskenc(admin, db, id1).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(recovery_item(db, id1, "C:").await.unwrap().1, p2, "not fetched");
    assert_eq!(diskenc_alerts(db, id1).await, [("vol:C:".to_string(), "not_escrowed".to_string())]);
    assert_eq!(admin.get("/disk-encryption?escrowed=false").await["items"][0]["agent_id"], id1);
    // Back on: the policy change fetches it.
    admin.set_root_item(DISKENC_ITEM, json!({ "escrow_recovery_keys": true })).await;
    eventually(30, "escrow after the policy change", || async { recovery_item(db, id1, "C:").await.filter(|i| i.1 == p3).map(|_| ()) }).await;
    eventually(30, "the alert to clear", || async { diskenc_alerts(db, id1).await.is_empty().then_some(()) }).await;

    // --- suspended past the grace period ---------------------------------------------------------------------------------
    let mut cfg = admin.item_in(ROOT_SET, &item_id).await["item_config"].clone();
    cfg["params"]["grace_hours"] = json!(0);
    let (s, v) = admin.call(Method::PUT, &format!("/policy-items/{item_id}"), Some(json!({ "config": cfg }))).await;
    assert!(s.is_success(), "{v}");
    let mut fake = read_diskenc(dir, "a1");
    fake["volumes"][0]["status"] = json!("suspended");
    fake["volumes"][0]["protection_on"] = json!(false);
    write_diskenc(dir, "a1", &fake);
    report_diskenc(admin, db, id1).await;
    eventually(30, "a suspended alert", || async { (diskenc_alerts(db, id1).await == [("vol:C:".to_string(), "suspended".to_string())]).then_some(()) }).await;

    // Clean up: the item goes, the agent reports its real disks again.
    assert!(admin.delete_policy(&item_id).await.is_success());
    let _ = std::fs::remove_file(dir.join("a1-diskenc.json"));
    report_diskenc(admin, db, id1).await;
}

/// Local admin rotation with the agent's fake (docs/design/local-admin.md): turned on by an
/// override, the first rotation stores the password before the agent sets it; reveal returns
/// what the agent set and schedules the next rotation; a failure keeps the item pending with
/// the previous password in history and opens the alert; the retry sends the same password.
async fn local_admin(url: &str, admin: &Api, db: &sqlx::PgPool, dir: &Path, id1: &str, b_id: &str) {
    use reqwest::Method;
    let fake_path = dir.join("a1-localadmin.json");
    let _ = std::fs::remove_file(&fake_path);
    let fake = || -> Value { serde_json::from_str(&std::fs::read_to_string(&fake_path).unwrap_or_else(|_| "{}".into())).unwrap() };
    type Row = (String, Option<String>, Option<String>, Option<String>, i32);
    let state = || async {
        sqlx::query_as::<_, Row>(
            "SELECT status, vault_item_id::text, rotate_reason, last_error, attempts FROM local_admin_state WHERE agent_id = $1::uuid",
        )
        .bind(id1)
        .fetch_optional(db)
        .await
        .unwrap()
    };
    let managed = |item: String| async move {
        sqlx::query_as::<_, (Option<String>, i64)>(
            "SELECT managed_state, (SELECT count(*) FROM vault_item_history h WHERE h.item_id = i.id) FROM vault_items i WHERE id = $1::uuid",
        )
        .bind(item)
        .fetch_one(db)
        .await
        .unwrap()
    };
    let laps_alerts = || async {
        sqlx::query_scalar::<_, String>("SELECT title FROM alerts WHERE agent_id = $1::uuid AND kind = 'local_admin' AND resolved_at IS NULL")
            .bind(id1)
            .fetch_all(db)
            .await
            .unwrap()
    };

    // Off by default: nothing happens, and a manual rotation says so.
    let v = admin.get(&format!("/agents/{id1}/local-admin")).await;
    assert_eq!((v["policy"]["enabled"].as_bool(), v["state"].is_null()), (Some(false), true), "{v}");
    let (s, _) = admin.call(Method::POST, &format!("/agents/{id1}/local-admin/rotate"), None).await;
    assert_eq!(s, StatusCode::CONFLICT);
    for bad in [json!({ "account": "Administrator" }), json!({ "length": 6 })] {
        let (s, v) = admin.set_root_item(LOCAL_ADMIN_ITEM, bad.clone()).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}: {v}");
    }
    let item = admin.alert_policy(json!({ "name": "E2E local admin", "kind": "local_admin", "params": { "overdue_days": 7 }, "severity": "warning" })).await;
    let item_id = item["id"].as_str().unwrap().to_string();

    // --- turned on by an override in the device's set: the first rotation ------------------------------
    let set = admin.get(&format!("/agents/{id1}")).await["policy_set_id"].as_str().unwrap().to_string();
    assert_ne!(set, ROOT_SET, "the device sits in an OS set");
    let (s, v) = admin
        .call(Method::PUT, &format!("/policy-items/{LOCAL_ADMIN_ITEM}/overrides/{set}"), Some(json!({ "config": { "enabled": true, "account": "rmm-e2e-admin", "rotate_after_reveal_hours": 1 } })))
        .await;
    assert!(s.is_success(), "{v}");
    let (_, item1, reason, ..) = eventually(30, "the first rotation", || async { state().await.filter(|s| s.0 == "ok") }).await;
    let vault1 = item1.unwrap();
    assert_eq!(reason.as_deref(), Some("first"));
    let f = fake();
    let pw1 = f["accounts"]["rmm-e2e-admin"]["password"].as_str().unwrap().to_string();
    assert_eq!((pw1.len(), f["accounts"]["rmm-e2e-admin"]["created"].as_bool()), (20, Some(true)), "{f}");
    assert_eq!(managed(vault1.clone()).await, (Some("current".into()), 0));
    let listed = admin.get(&format!("/clients/{}/vault?kind=local_admin", admin.get(&format!("/agents/{id1}")).await["client_id"].as_str().unwrap())).await;
    assert_eq!(listed.as_array().unwrap().len(), 1, "{listed}");
    assert_eq!(listed[0]["username"], "rmm-e2e-admin");

    // --- reveal equals what the agent set, and schedules a rotation --------------------------------------
    assert_eq!(admin.post(&format!("/vault/{vault1}/reveal"), json!({ "field": "password" })).await["value"], pw1.as_str());
    let (next, why): (chrono::DateTime<chrono::Utc>, Option<String>) =
        sqlx::query_as("SELECT next_rotate_at, rotate_reason FROM local_admin_state WHERE agent_id = $1::uuid").bind(id1).fetch_one(db).await.unwrap();
    let in_secs = (next - chrono::Utc::now()).num_seconds();
    assert!((3000..=3600).contains(&in_secs) && why.as_deref() == Some("reveal"), "an hour after the reveal: {in_secs} s, {why:?}");
    // That hour passes.
    sqlx::query("UPDATE local_admin_state SET next_rotate_at = now() - interval '1 second' WHERE agent_id = $1::uuid").bind(id1).execute(db).await.unwrap();
    let pw2 = eventually(30, "the rotation after the reveal", || async {
        let p = fake()["accounts"]["rmm-e2e-admin"]["password"].as_str().map(String::from)?;
        (p != pw1 && state().await.is_some_and(|s| s.0 == "ok")).then_some(p)
    })
    .await;
    assert_eq!(managed(vault1.clone()).await, (Some("current".into()), 1), "one item, the old password in its history");
    assert_eq!(admin.post(&format!("/vault/{vault1}/reveal"), json!({ "field": "password" })).await["value"], pw2.as_str());
    let triggers: Vec<String> = sqlx::query_scalar("SELECT details ->> 'trigger' FROM audit_log WHERE action = 'local_admin.rotate' AND target_id = $1::uuid ORDER BY id")
        .bind(id1)
        .fetch_all(db)
        .await
        .unwrap();
    assert_eq!(triggers, ["first", "reveal"]);
    for pw in [&pw1, &pw2] {
        let leaked: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE details::text LIKE '%' || $1 || '%'").bind(pw).fetch_one(db).await.unwrap();
        assert_eq!(leaked, 0, "the password is never in the audit log");
    }

    // --- scoping and permissions --------------------------------------------------------------------------------
    let tech_b = signed_in(url, admin, "laps-tech-b@e2e.test", "technician", Some(b_id), false).await;
    let (s, _) = tech_b.call(Method::GET, &format!("/agents/{id1}/local-admin"), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = tech_b.call(Method::POST, &format!("/agents/{id1}/local-admin/rotate"), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // --- a failure keeps the previous password, the item stays pending, the alert opens ----------------------------
    let mut f = fake();
    f["fail"] = json!("The password does not meet the password policy requirements.");
    std::fs::write(&fake_path, f.to_string()).unwrap();
    admin.post(&format!("/agents/{id1}/local-admin/rotate"), json!({})).await;
    let (_, _, _, err, _) = eventually(30, "the failed rotation", || async { state().await.filter(|s| s.0 == "failed") }).await;
    assert!(err.unwrap().contains("password policy"));
    let (mstate, hist) = managed(vault1.clone()).await;
    assert_eq!((mstate.as_deref(), hist), (Some("pending"), 2), "the new password waits as pending; the one on the device is in the history");
    let h: i64 = sqlx::query_scalar("SELECT max(id) FROM vault_item_history WHERE item_id = $1::uuid").bind(&vault1).fetch_one(db).await.unwrap();
    assert_eq!(admin.post(&format!("/vault/{vault1}/reveal"), json!({ "history": h })).await["value"], pw2.as_str(), "nobody is locked out");
    let pending = admin.post(&format!("/vault/{vault1}/reveal"), json!({ "field": "password" })).await["value"].as_str().unwrap().to_string();
    assert_eq!(fake()["accounts"]["rmm-e2e-admin"]["password"], pw2.as_str(), "the device still has the previous one");
    eventually(30, "the local admin alert", || async { laps_alerts().await.into_iter().find(|t| t.contains("failed")) }).await;
    let v = admin.get(&format!("/agents/{id1}/local-admin")).await;
    assert_eq!((v["state"]["status"].as_str(), v["managed_state"].as_str()), (Some("failed"), Some("pending")), "{v}");

    // --- the retry sends the same pending password --------------------------------------------------------------------
    let mut f = fake();
    f["fail"] = Value::Null;
    std::fs::write(&fake_path, f.to_string()).unwrap();
    sqlx::query("UPDATE local_admin_state SET next_rotate_at = now() - interval '1 second' WHERE agent_id = $1::uuid").bind(id1).execute(db).await.unwrap();
    eventually(30, "the retry", || async { state().await.filter(|s| s.0 == "ok") }).await;
    assert_eq!(fake()["accounts"]["rmm-e2e-admin"]["password"], pending.as_str(), "the pending password, not a new one");
    assert_eq!(managed(vault1.clone()).await, (Some("current".into()), 2));
    eventually(30, "the alert to clear", || async { laps_alerts().await.is_empty().then_some(()) }).await;

    // --- turned off: rotation stops, the account and the item stay ------------------------------------------------------
    admin.call(Method::DELETE, &format!("/policy-items/{LOCAL_ADMIN_ITEM}/overrides/{set}"), None).await;
    let v = admin.get(&format!("/agents/{id1}/local-admin")).await;
    assert_eq!((v["policy"]["enabled"].as_bool(), v["state"]["status"].as_str()), (Some(false), Some("ok")), "{v}");
    sqlx::query("UPDATE local_admin_state SET next_rotate_at = now() - interval '1 second' WHERE agent_id = $1::uuid").bind(id1).execute(db).await.unwrap();
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert_eq!(fake()["accounts"]["rmm-e2e-admin"]["password"], pending.as_str(), "no rotation while it is off");
    assert!(admin.delete_policy(&item_id).await.is_success());
}
