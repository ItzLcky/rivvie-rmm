//! The first half of the CI `upgrade` job: puts real data into a database through the
//! *previous* release (its server image and its own agent binary), so the job can then start
//! the current server on that database and run the e2e suite against it.
//!
//! The previous release's server must already be running on `RMM_UPGRADE_URL`, bootstrapped
//! with the e2e admin (`admin@e2e.test` / `e2e-admin-password`); `RMM_UPGRADE_AGENT_BIN` is that
//! release's Linux agent. What was created is written to `RMM_UPGRADE_EXPECT` as JSON, which
//! the e2e suite reads back through the new server's API (`RMM_E2E_EXPECT`). See the `upgrade`
//! job in `.github/workflows/ci.yml`; locally:
//!
//! ```sh
//! RMM_UPGRADE_URL=http://127.0.0.1:18090 RMM_UPGRADE_AGENT_BIN=/tmp/prev/rmm-agent RMM_UPGRADE_EXPECT=/tmp/prev/expect.json \
//!     cargo test -p rmm-server --test upgrade -- --ignored --nocapture
//! ```
//!
//! Only the HTTP API and the agent protocol of the old release are used, so this file has to
//! keep working against it: don't call endpoints the previous release doesn't have.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha1::Sha1;

const ADMIN_EMAIL: &str = "admin@e2e.test";
const ADMIN_PASSWORD: &str = "e2e-admin-password";

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

async fn call(http: &reqwest::Client, method: reqwest::Method, url: String, body: Option<Value>) -> Value {
    let mut req = http.request(method.clone(), &url);
    if let Some(b) = body {
        req = req.json(&b);
    }
    let res = req.send().await.unwrap();
    let s = res.status();
    let v: Value = res.json().await.unwrap_or(Value::Null);
    assert!(s.is_success(), "{method} {url}: {s} {v}");
    v
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the previous release's server running; see the module docs"]
async fn seed_previous_release() {
    let url = std::env::var("RMM_UPGRADE_URL").expect("RMM_UPGRADE_URL");
    let agent_bin = std::env::var("RMM_UPGRADE_AGENT_BIN").expect("RMM_UPGRADE_AGENT_BIN");
    let out = std::env::var("RMM_UPGRADE_EXPECT").expect("RMM_UPGRADE_EXPECT");
    let api = format!("{url}/api");
    let http = reqwest::Client::builder().cookie_store(true).build().unwrap();
    let post = |p: &str, b: Value| call(&http, reqwest::Method::POST, format!("{api}{p}"), Some(b));
    let get = |p: &str| call(&http, reqwest::Method::GET, format!("{api}{p}"), None);

    post("/auth/login", json!({ "email": ADMIN_EMAIL, "password": ADMIN_PASSWORD })).await;
    let setup = post("/auth/totp/setup", json!({ "password": ADMIN_PASSWORD })).await;
    post("/auth/totp/enable", json!({ "code": totp(setup["secret"].as_str().unwrap()) })).await;

    let client = post("/clients", json!({ "name": "Upgraded Client Ltd" })).await;
    let client_id = client["id"].as_str().unwrap().to_string();
    let site_id = client["default_site_id"].as_str().unwrap().to_string();
    let token = post(&format!("/sites/{site_id}/enrollment-tokens"), json!({ "label": "upgrade" })).await;
    let token = token["token"].as_str().unwrap();

    // The old release's own agent enrolls and reports for a while.
    let dir = std::env::temp_dir().join(format!("rmm-upgrade-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("agent.toml");
    let st = Command::new(&agent_bin).arg("--config").arg(&config).args(["enroll", "--server", &url, "--token", token]).status().unwrap();
    assert!(st.success(), "the old agent enrolls");
    /// Stops the agent however the test ends.
    struct Running(std::process::Child);
    impl Drop for Running {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let log = std::fs::File::create(dir.join("agent.log")).unwrap();
    let agent = Command::new(&agent_bin)
        .arg("--config")
        .arg(&config)
        .arg("run")
        .env("RMM_STATE_DIR", dir.join("state"))
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    let agent = Running(agent);
    let deadline = Instant::now() + Duration::from_secs(120);
    let (agent_id, hostname, samples) = loop {
        let agents = get("/agents").await;
        let a = agents["items"].as_array().and_then(|a| a.first()).cloned();
        if let Some(a) = a.filter(|a| a["online"] == true) {
            let id = a["id"].as_str().unwrap().to_string();
            let m = get(&format!("/agents/{id}/metrics?hours=1")).await;
            let n = m.as_array().map(|p| p.len()).unwrap_or(0);
            // The list has no inventory; the agent page does.
            let detail = get(&format!("/agents/{id}")).await;
            if n >= 2 && detail["inventory_at"].is_string() {
                break (id, a["hostname"].as_str().unwrap().to_string(), n);
            }
        }
        assert!(Instant::now() < deadline, "the old agent came online and reported metrics and inventory");
        tokio::time::sleep(Duration::from_secs(2)).await;
    };
    drop(agent);

    let ticket = post(
        "/tickets",
        json!({ "subject": "Printer jammed before the upgrade", "description": "Filed on the previous release.", "client_id": client_id, "agent_ids": [agent_id] }),
    )
    .await;
    // Policies of the old model, for the new one's migration (docs/design/policies.md): a
    // client- and OS-limited alert policy, the client's own patch policy, a site's sensor policy,
    // a scheduled script, and remote desktop consent.
    let put = |p: &str, b: Value| call(&http, reqwest::Method::PUT, format!("{api}{p}"), Some(b));
    let alert = post(
        "/alert-policies",
        json!({ "name": "Upgraded offline", "kind": "offline", "params": { "minutes": 10 }, "severity": "warning", "client_id": client_id, "os_family": "linux" }),
    )
    .await;
    post("/patch-policies", json!({ "client_id": client_id, "auto_approve_categories": ["security", "driver"], "reboot_policy": "if_required" })).await;
    post(
        "/security/policies",
        json!({ "client_id": client_id, "site_id": site_id, "sensor_enabled": false, "quick_scan_hours": 6, "full_scan_days": 7,
                "auto_quarantine": true, "prevention": false, "canaries": true, "telemetry_mb": 64 }),
    )
    .await;
    let script = post("/scripts", json!({ "name": "Upgraded nightly", "interpreter": "bash", "body": "true" })).await;
    let schedule = post(
        "/schedules",
        json!({ "name": "Upgraded nightly", "script_id": script["id"], "client_id": client_id, "cron": "0 2 * * *", "timezone": "UTC" }),
    )
    .await;
    put(&format!("/clients/{client_id}/desktop"), json!({ "consent": true })).await;

    let expect = json!({
        "admin_email": ADMIN_EMAIL,
        "client_id": client_id, "client_name": "Upgraded Client Ltd", "site_id": site_id,
        "agent_id": agent_id, "hostname": hostname, "metric_samples": samples,
        "ticket_id": ticket["id"], "ticket_number": ticket["number"], "ticket_subject": "Printer jammed before the upgrade",
        "alert_policy_id": alert["id"], "schedule_id": schedule["id"], "schedule_next_run_at": schedule["next_run_at"],
    });
    std::fs::write(&out, serde_json::to_vec_pretty(&expect).unwrap()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    println!("seeded through the previous release: {expect}");
}
