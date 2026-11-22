//! The last step of the CI restore drill (`scripts/restore-drill.sh`, which has the whole
//! story): a server started on a database and storage directory *restored from a backup* must
//! give back what the e2e run wrote (`RMM_E2E_DRILL`, see tests/e2e.rs).
//!
//! `RMM_DRILL_DATABASE_URL` is the restored database, `RMM_DRILL_STORAGE` the restored storage
//! directory, `RMM_DRILL_EXPECT` the expectations file. Checked, in this order:
//! - the row counts of the tables the e2e run left;
//! - every ticket attachment's file in the restored directory (size and SHA-256 against the
//!   database row), and that every invoice PDF, triage package, signature database and raw
//!   email the database points to exists there;
//! - a real server on both, with the key of the backup: sign in as the admin with a 2FA code,
//!   download the drill attachment through the API and compare its hash, read the ticket, and
//!   reveal the vault item's password.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha1::Sha1;
use sha2::{Digest, Sha256};

fn totp(secret_b32: &str) -> String {
    let secret = data_encoding::BASE32_NOPAD.decode(secret_b32.as_bytes()).unwrap();
    let step = (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() / 30).to_be_bytes();
    let mut mac = Hmac::<Sha1>::new_from_slice(&secret).unwrap();
    mac.update(&step);
    let h = mac.finalize().into_bytes();
    let off = (h[h.len() - 1] & 0x0f) as usize;
    let bin = u32::from_be_bytes([h[off] & 0x7f, h[off + 1], h[off + 2], h[off + 3]]);
    format!("{:06}", bin % 1_000_000)
}

struct Running(Child);
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn var(k: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| panic!("set {k} (see the module docs)"))
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a restored backup: see scripts/restore-drill.sh"]
async fn restored_backup_serves_everything() {
    let db_url = var("RMM_DRILL_DATABASE_URL");
    let storage = PathBuf::from(var("RMM_DRILL_STORAGE"));
    let expect: Value = serde_json::from_slice(&std::fs::read(var("RMM_DRILL_EXPECT")).unwrap()).unwrap();
    let db = sqlx::PgPool::connect(&db_url).await.unwrap();

    // --- rows -----------------------------------------------------------------------------------
    for (table, want) in expect["counts"].as_object().unwrap() {
        let (n,): (i64,) = sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}"))).fetch_one(&db).await.unwrap();
        assert_eq!(Some(n), want.as_i64(), "{table}: rows in the restored database");
    }
    println!("drill: row counts match");

    // --- files ----------------------------------------------------------------------------------
    let rows: Vec<(String, i64, Vec<u8>)> = sqlx::query_as("SELECT storage_key, size, sha256 FROM ticket_attachments").fetch_all(&db).await.unwrap();
    assert!(rows.len() >= 2, "the e2e run leaves attachments ({} found)", rows.len());
    for (key, size, sha) in &rows {
        let bytes = std::fs::read(storage.join(key)).unwrap_or_else(|e| panic!("attachment {key} missing from the restored storage: {e}"));
        assert_eq!(bytes.len() as i64, *size, "{key}: size");
        assert_eq!(Sha256::digest(&bytes).as_slice(), sha.as_slice(), "{key}: SHA-256");
    }
    let mut pointed_at = 0;
    for q in [
        "SELECT pdf_key FROM invoices WHERE pdf_key IS NOT NULL",
        "SELECT storage_key FROM security_actions WHERE storage_key IS NOT NULL",
        "SELECT storage_key FROM signature_databases WHERE storage_key IS NOT NULL",
        "SELECT raw_key FROM email_messages WHERE raw_key IS NOT NULL",
    ] {
        let keys: Vec<(String,)> = sqlx::query_as(sqlx::AssertSqlSafe(q.to_string())).fetch_all(&db).await.unwrap();
        for (key,) in keys {
            assert!(storage.join(&key).is_file(), "{q}: {key} missing from the restored storage");
            pointed_at += 1;
        }
    }
    println!("drill: {} attachments verified by hash, {pointed_at} other stored files present", rows.len());

    // --- a server on it --------------------------------------------------------------------------
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let dir = std::env::temp_dir().join(format!("rmm-drill-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(dir.join("web")).unwrap();
    std::fs::write(dir.join("web/200.html"), "<!doctype html><title>drill</title>").unwrap();
    let log = std::fs::File::create(dir.join("server.log")).unwrap();
    let _server = Running(
        Command::new(env!("CARGO_BIN_EXE_rmm-server"))
            .env("DATABASE_URL", &db_url)
            .env("RMM_BIND", format!("127.0.0.1:{port}"))
            .env("RMM_PUBLIC_URL", format!("http://127.0.0.1:{port}"))
            .env("RMM_WEB_DIR", dir.join("web"))
            .env("RMM_AGENT_DIR", dir.join("agents"))
            .env("RMM_STORAGE_DIR", &storage)
            .env("RMM_DATA_KEY", expect["data_key"].as_str().unwrap())
            .env("RUST_LOG", "info")
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .stdin(Stdio::null())
            .spawn()
            .expect("starting rmm-server"),
    );
    let base = format!("http://127.0.0.1:{port}");
    let deadline = Instant::now() + Duration::from_secs(60);
    while !reqwest::get(format!("{base}/healthz")).await.is_ok_and(|r| r.status().is_success()) {
        assert!(Instant::now() < deadline, "the server on the restored backup didn't start; see {}", dir.join("server.log").display());
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let http = reqwest::Client::builder().cookie_store(true).build().unwrap();
    let api = |p: &str| format!("{base}/api{p}");
    let login = json!({ "email": expect["admin_email"], "password": expect["admin_password"], "code": totp(expect["admin_totp_secret"].as_str().unwrap()) });
    let res = http.post(api("/auth/login")).json(&login).send().await.unwrap();
    let me: Value = res.json().await.unwrap();
    assert_eq!(me["user"]["totp_enabled"], true, "signing in with a 2FA code works on the restored database: {me}");

    let ticket_id = expect["ticket_id"].as_str().unwrap();
    let t: Value = http.get(api(&format!("/tickets/{ticket_id}"))).send().await.unwrap().json().await.unwrap();
    assert_eq!(t["subject"], "Restore drill", "{t}");
    let res = http.get(api(&format!("/tickets/{ticket_id}/attachments/{}", expect["attachment_id"].as_str().unwrap()))).send().await.unwrap();
    assert!(res.status().is_success(), "{}", res.status());
    let bytes = res.bytes().await.unwrap();
    assert_eq!(bytes.len() as u64, expect["attachment_size"].as_u64().unwrap());
    assert_eq!(hex::encode(Sha256::digest(&bytes)), expect["attachment_sha256"].as_str().unwrap(), "the attachment's bytes through the API");

    let item = expect["vault_item_id"].as_str().unwrap();
    let res = http.post(api(&format!("/vault/{item}/reveal"))).json(&json!({ "field": "password" })).send().await.unwrap();
    let v: Value = res.json().await.unwrap();
    assert_eq!(v["value"], expect["vault_password"], "the vault opens with the backup's key: {v}");
    println!("drill: signed in with 2FA, attachment and vault secret read back through the API");
    let _ = std::fs::remove_dir_all(Path::new(&dir));
}
