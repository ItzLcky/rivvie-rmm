//! End-to-end: the real server against a scratch Postgres database, driven over HTTP, with
//! real agent processes.
//!
//! ```sh
//! docker compose -f docker-compose.dev.yml up -d
//! cargo build -p rmm-agent
//! RMM_E2E_DATABASE_URL=postgres://rmm:rmm@localhost:5432/postgres \
//!     cargo test -p rmm-server --test e2e -- --ignored --nocapture
//! ```
//!
//! `RMM_E2E_DATABASE_URL` must point at a database the user can `CREATE DATABASE` from; each
//! run creates and drops its own `rmm_e2e_<random>` database. A second test in this file,
//! `policy_migration`, needs only that database: it builds the schema up to 0021, writes rows of
//! the old policy model, applies 0022 and checks that the same policies apply to every agent. The agent binary defaults to
//! the one next to the server binary (`target/debug/rmm-agent`); set `RMM_E2E_AGENT_BIN`
//! to use another. Linux only: the agent runs bash jobs.
//!
//! `RMM_E2E_TEMPLATE=<database>` starts from a copy of an existing database instead of an
//! empty one (`CREATE DATABASE ... TEMPLATE`; nothing may be connected to it). The CI
//! `upgrade` job uses it for a database made by the previous release, with
//! `RMM_E2E_EXPECT=<file>` naming the rows that release wrote (see `tests/upgrade.rs`): they
//! must read back through the API before the suite runs. That database's admin must be the
//! e2e admin with two-factor auth cleared (`rmm-server reset2fa`).
//!
//! The single sign-on and passkey section starts a second server on the same database, because
//! WebAuthn needs a host name (`http://localhost:<port>`) where the main one is reached by
//! 127.0.0.1, and a stand-in OIDC provider (an axum issuer with a generated ES256 key).
//!
//! `RMM_E2E_PROMTOOL=<path to promtool>` also parses and lints the `/metrics` output with
//! Prometheus's own tool (CI sets it; without it that check is skipped).
//!
//! `RMM_E2E_ONLY=sso` runs only the sign-in and the single sign-on and passkey section.
//!
//! `RMM_E2E_ONLY=desk` runs only the core and service desk sections (faster while working on
//! tickets, the portal and billing).
//!
//! Optional: `RMM_E2E_IMAP=host:imap_port:smtp_port` of a GreenMail container (user
//! `imap@local.test`, password `secret`) also tests IMAP polling:
//! `docker run -d -p 33143:3143 -p 33025:3025 -e GREENMAIL_OPTS='-Dgreenmail.setup.test.all -Dgreenmail.hostname=0.0.0.0
//! -Dgreenmail.users=imap:secret@local.test -Dgreenmail.users.login=email' greenmail/standalone:2.1.3`

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use hmac::{Hmac, KeyInit, Mac};
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha1::Sha1;
use sqlx::Connection;

const ADMIN_EMAIL: &str = "admin@e2e.test";
const ADMIN_PASSWORD: &str = "e2e-admin-password";
/// RMM_ATTACHMENT_MAX_MB for the e2e server.
const ATTACHMENT_MAX_MB: usize = 20;
/// Seed of the key that signs the e2e detection content (agents and server get its public half).
const CONTENT_SEED: [u8; 32] = [9u8; 32];

/// The mock Microsoft Graph (and sign-in) endpoint the server is pointed at.
static GRAPH_URL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
static GRAPH: std::sync::OnceLock<GraphMock> = std::sync::OnceLock::new();
/// The QuickBooks Online and Xero stand-in.
static ACCT_URL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
static ACCT: std::sync::OnceLock<AcctMock> = std::sync::OnceLock::new();

fn content_pubkey() -> String {
    hex::encode(ed25519_dalek::SigningKey::from_bytes(&CONTENT_SEED).verifying_key().as_bytes())
}

struct Server {
    child: Child,
    port: u16,
    db_url: String,
    dir: PathBuf,
    /// RMM_METRICS_TOKEN and JSON logs: off for the first start (`/metrics` must 404), on
    /// from the first restart.
    observability: bool,
}

/// RMM_METRICS_TOKEN once `observability` is on.
const METRICS_TOKEN: &str = "e2e-metrics-token";

impl Server {
    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn start(db_url: &str, dir: &Path, port: u16, observability: bool) -> Child {
        let log = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("server.log")).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_rmm-server"));
        if observability {
            cmd.env("RMM_METRICS_TOKEN", METRICS_TOKEN).env("RMM_LOG_FORMAT", "json");
        }
        cmd
            .env("DATABASE_URL", db_url)
            .env("RMM_BIND", format!("127.0.0.1:{port}"))
            .env("RMM_PUBLIC_URL", format!("http://127.0.0.1:{port}"))
            .env("RMM_WEB_DIR", dir.join("web"))
            .env("RMM_AGENT_DIR", dir.join("agents"))
            .env("RMM_STORAGE_DIR", dir.join("storage"))
            .env("RMM_HEARTBEAT_SECS", "5")
            .env("RMM_ALERT_EVAL_SECS", "2")
            .env("RMM_TRUSTED_PROXIES", "127.0.0.1")
            .env("RMM_ADMIN_EMAIL", ADMIN_EMAIL)
            .env("RMM_ADMIN_PASSWORD", ADMIN_PASSWORD)
            .env("RMM_UPDATE_PUBKEY", content_pubkey())
            .env("RMM_CONTENT_SOAK_MINUTES", "0")
            .env("RMM_DATA_KEY", "ab".repeat(32))
            .env("RMM_SLA_SWEEP_SECS", "2")
            // Small enough to test the limit quickly, over the 8 MB that other requests get.
            .env("RMM_ATTACHMENT_MAX_MB", ATTACHMENT_MAX_MB.to_string())
            .env("RMM_XERO_AUTH_URL", format!("{}/xero/authorize", ACCT_URL.get().map(String::as_str).unwrap_or("http://127.0.0.1:9")))
            .env("RMM_XERO_TOKEN_URL", format!("{}/xero/token", ACCT_URL.get().map(String::as_str).unwrap_or("http://127.0.0.1:9")))
            .env("RMM_XERO_API_URL", format!("{}/xero/api", ACCT_URL.get().map(String::as_str).unwrap_or("http://127.0.0.1:9")))
            .env("RMM_QBO_AUTH_URL", format!("{}/qbo/authorize", ACCT_URL.get().map(String::as_str).unwrap_or("http://127.0.0.1:9")))
            .env("RMM_QBO_TOKEN_URL", format!("{}/qbo/token", ACCT_URL.get().map(String::as_str).unwrap_or("http://127.0.0.1:9")))
            .env("RMM_QBO_API_URL", format!("{}/qbo/api", ACCT_URL.get().map(String::as_str).unwrap_or("http://127.0.0.1:9")))
            .env("RMM_GRAPH_LOGIN_URL", GRAPH_URL.get().map(String::as_str).unwrap_or("http://127.0.0.1:9"))
            .env("RMM_GRAPH_URL", GRAPH_URL.get().map(String::as_str).unwrap_or("http://127.0.0.1:9"))
            .env("RUST_LOG", "info,rmm_server=debug")
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .expect("starting rmm-server")
    }

    async fn restart(&mut self) {
        self.stop();
        self.start_again().await;
    }

    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    async fn start_again(&mut self) {
        self.child = Self::start(&self.db_url, &self.dir, self.port, self.observability);
        wait_healthy(&self.url()).await;
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Agent {
    config: PathBuf,
    child: Option<Child>,
}

impl Agent {
    fn new(dir: &Path, name: &str) -> Self {
        Self { config: dir.join(format!("{name}.toml")), child: None }
    }

    fn enroll(&self, server: &str, token: &str) -> Result<String, String> {
        let out = Command::new(agent_bin())
            .arg("--config")
            .arg(&self.config)
            .args(["enroll", "--server", server, "--token", token])
            .output()
            .expect("running rmm-agent enroll");
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).into_owned());
        }
        let raw = std::fs::read_to_string(&self.config).unwrap();
        let id = raw.lines().find_map(|l| l.strip_prefix("agent_id = ")).unwrap().trim_matches('"').to_string();
        Ok(id)
    }

    fn run(&mut self, log_dir: &Path) {
        let name = self.config.file_stem().unwrap().to_string_lossy().to_string();
        let log = std::fs::OpenOptions::new().create(true).append(true).open(log_dir.join(format!("{name}.log"))).unwrap();
        self.child = Some(
            Command::new(agent_bin())
                .arg("--config")
                .arg(&self.config)
                .arg("run")
                .env("RUST_LOG", "info")
                // Debug agents read updates from this file instead of the real package manager.
                .env("RMM_PATCH_FAKE", log_dir.join(format!("{name}-patches.json")))
                // And capture a synthetic screen, logging input here.
                .env("RMM_DESKTOP_FAKE", log_dir.join(format!("{name}-desktop.jsonl")))
                // And report antivirus state from this file.
                .env("RMM_SECURITY_FAKE", log_dir.join(format!("{name}-security.json")))
                // The sensor runs unprivileged on scratch directories, with test-signed content.
                .env("RMM_STATE_DIR", sensor_dir(log_dir, &name, "state"))
                .env("RMM_CONTENT_PUBKEY", content_pubkey())
                .env("RMM_SENSOR_WATCH", sensor_dir(log_dir, &name, "watch"))
                .env("RMM_SENSOR_CANARY_DIRS", sensor_dir(log_dir, &name, "home"))
                .env("RMM_SENSOR_SCAN_ROOTS", sensor_dir(log_dir, &name, "scan"))
                .stdout(log.try_clone().unwrap())
                .stderr(log)
                .spawn()
                .expect("starting rmm-agent run"),
        );
    }

    fn kill(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        self.kill();
    }
}

fn sensor_dir(log_dir: &Path, agent: &str, what: &str) -> PathBuf {
    let d = log_dir.join(format!("{agent}-{what}"));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn agent_bin() -> PathBuf {
    if let Ok(p) = std::env::var("RMM_E2E_AGENT_BIN") {
        return p.into();
    }
    let p = Path::new(env!("CARGO_BIN_EXE_rmm-server")).with_file_name("rmm-agent");
    assert!(p.exists(), "{} not found: run `cargo build -p rmm-agent` first (or set RMM_E2E_AGENT_BIN)", p.display());
    p
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

async fn wait_healthy(url: &str) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if reqwest::get(format!("{url}/healthz")).await.is_ok_and(|r| r.status().is_success()) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("server at {url} didn't become healthy; see its server.log");
}

/// Polls `f` until it returns `Some`, or panics with `what` after `secs`.
async fn eventually<T, F, Fut>(secs: u64, what: &str, mut f: F) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(v) = f().await {
            return v;
        }
        assert!(Instant::now() < deadline, "timed out waiting for: {what}");
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

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

struct Api {
    http: reqwest::Client,
    base: String,
}

impl Api {
    fn new(base: &str) -> Self {
        Self { http: reqwest::Client::builder().cookie_store(true).build().unwrap(), base: format!("{base}/api") }
    }

    async fn call(&self, method: reqwest::Method, path: &str, body: Option<Value>) -> (StatusCode, Value) {
        let mut req = self.http.request(method, format!("{}{path}", self.base));
        if let Some(b) = body {
            req = req.json(&b);
        }
        let res = req.send().await.unwrap();
        let status = res.status();
        let v = res.json::<Value>().await.unwrap_or(Value::Null);
        (status, v)
    }

    async fn get(&self, path: &str) -> Value {
        let (s, v) = self.call(reqwest::Method::GET, path, None).await;
        assert!(s.is_success(), "GET {path}: {s} {v}");
        v
    }

    async fn post(&self, path: &str, body: Value) -> Value {
        let (s, v) = self.call(reqwest::Method::POST, path, Some(body)).await;
        assert!(s.is_success(), "POST {path}: {s} {v}");
        v
    }

    async fn job(&self, id: &str) -> Value {
        self.get(&format!("/jobs/{id}")).await
    }

    async fn run_script(&self, agent: &str, body: &str, timeout: i32) -> String {
        let v = self.post("/jobs", json!({ "agent_ids": [agent], "interpreter": "bash", "body": body, "timeout_secs": timeout })).await;
        v["jobs"][0]["job_id"].as_str().unwrap().to_string()
    }

    async fn wait_job(&self, id: &str, secs: u64) -> Value {
        let this = self;
        eventually(secs, &format!("job {id} to finish"), move || async move {
            let j = this.job(id).await;
            (!matches!(j["status"].as_str(), Some("queued" | "sent"))).then_some(j)
        })
        .await
    }

    async fn wait_online(&self, agent: &str, online: bool) {
        let this = self;
        eventually(30, &format!("agent {agent} online={online}"), move || async move {
            (this.get(&format!("/agents/{agent}")).await["online"] == online).then_some(())
        })
        .await;
    }

    async fn put(&self, path: &str, body: Value) -> Value {
        let (s, v) = self.call(reqwest::Method::PUT, path, Some(body)).await;
        assert!(s.is_success(), "PUT {path}: {s} {v}");
        v
    }

    /// An alert item in All devices from the fields an alert policy had (name, kind, params,
    /// severity, channels, ticket fields; client and site as the limit).
    async fn alert_policy_call(&self, b: Value) -> (StatusCode, Value) {
        self.call(reqwest::Method::POST, &format!("/policy-sets/{ROOT_SET}/items"), Some(alert_item(&b))).await
    }

    async fn alert_policy(&self, b: Value) -> Value {
        let (s, v) = self.alert_policy_call(b.clone()).await;
        assert!(s.is_success(), "creating alert policy {b}: {s} {v}");
        v
    }

    /// Replaces an alert item's config (and name, enabled, limit) at its origin.
    async fn update_alert_policy(&self, id: &str, b: Value) -> (StatusCode, Value) {
        let mut body = alert_item(&b);
        body.as_object_mut().unwrap().remove("module");
        self.call(reqwest::Method::PUT, &format!("/policy-items/{id}"), Some(body)).await
    }

    async fn delete_policy(&self, id: &str) -> StatusCode {
        self.call(reqwest::Method::DELETE, &format!("/policy-items/{id}"), None).await.0
    }

    /// An item as it applies in a set.
    async fn item_in(&self, set: &str, item: &str) -> Value {
        let s = self.get(&format!("/policy-sets/{set}")).await;
        s["policies"].as_array().unwrap().iter().find(|p| p["id"] == item).cloned().unwrap_or_else(|| panic!("{item} in {set}: {s}"))
    }

    /// Changes some fields of a single-instance item (patch, security, ...) in All devices.
    async fn set_root_item(&self, item: &str, fields: Value) -> (StatusCode, Value) {
        let mut config = self.item_in(ROOT_SET, item).await["item_config"].clone();
        config.as_object_mut().unwrap().extend(fields.as_object().unwrap().clone());
        self.call(reqwest::Method::PUT, &format!("/policy-items/{item}"), Some(json!({ "config": config }))).await
    }
}

const ROOT_SET: &str = "00000000-0000-4000-8001-000000000000";
const PATCH_ITEM: &str = "00000000-0000-4000-8000-000000000001";
const SECURITY_ITEM: &str = "00000000-0000-4000-8000-000000000002";
const REMOTE_ITEM: &str = "00000000-0000-4000-8000-000000000003";

/// The item body for [`Api::alert_policy`].
fn alert_item(b: &Value) -> Value {
    let mut config = serde_json::Map::new();
    for k in ["kind", "params", "severity", "channel_ids", "notify_resolved", "renotify_minutes", "ticket_board_id", "ticket_priority", "ticket_auto_resolve", "run_script_id"] {
        if let Some(v) = b.get(k) {
            config.insert(k.into(), v.clone());
        }
    }
    let mut out = json!({ "module": "alert", "name": b["name"], "config": config, "client_id": b.get("client_id"), "site_id": b.get("site_id") });
    if let Some(e) = b.get("enabled") {
        out["enabled"] = e.clone();
    }
    out
}

/// An open `/api/events` stream (Server-Sent Events).
struct Events {
    res: reqwest::Response,
    buf: String,
}

impl Events {
    async fn open(api: &Api) -> Self {
        let res = api.http.get(format!("{}/events", api.base)).send().await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert!(res.headers()["content-type"].to_str().unwrap().starts_with("text/event-stream"));
        let mut ev = Events { res, buf: String::new() };
        assert!(ev.next_matching(5, |v| v["type"] == "hello").await.is_some(), "hello on connect");
        ev
    }

    /// The next event matching `pred` within `secs`, skipping others.
    async fn next_matching(&mut self, secs: u64, pred: impl Fn(&Value) -> bool) -> Option<Value> {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            while let Some(end) = self.buf.find("\n\n") {
                let frame: String = self.buf.drain(..end + 2).collect();
                for line in frame.lines() {
                    if let Some(data) = line.strip_prefix("data: ")
                        && let Ok(v) = serde_json::from_str::<Value>(data)
                        && pred(&v)
                    {
                        return Some(v);
                    }
                }
            }
            let left = deadline.checked_duration_since(Instant::now())?;
            match tokio::time::timeout(left, self.res.chunk()).await {
                Ok(Ok(Some(b))) => self.buf.push_str(&String::from_utf8_lossy(&b)),
                _ => return None,
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Postgres and a built agent: see the module docs"]
async fn end_to_end() {
    let admin_url = std::env::var("RMM_E2E_DATABASE_URL").expect("set RMM_E2E_DATABASE_URL (see the test's module docs)");
    let db_name = format!("rmm_e2e_{}", uuid::Uuid::new_v4().simple());
    let mut admin_conn = sqlx::PgConnection::connect(&admin_url).await.expect("connecting to RMM_E2E_DATABASE_URL");
    let create = match std::env::var("RMM_E2E_TEMPLATE").ok().filter(|t| !t.is_empty()) {
        Some(t) => {
            assert!(t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'), "RMM_E2E_TEMPLATE must be a plain database name");
            format!("CREATE DATABASE {db_name} TEMPLATE {t}")
        }
        None => format!("CREATE DATABASE {db_name}"),
    };
    sqlx::query(sqlx::AssertSqlSafe(create)).execute(&mut admin_conn).await.unwrap();
    let db_url = {
        let (base, _) = admin_url.rsplit_once('/').expect("database URL with a /dbname");
        format!("{base}/{db_name}")
    };

    let dir = std::env::temp_dir().join(&db_name);
    std::fs::create_dir_all(dir.join("web")).unwrap();
    std::fs::create_dir_all(dir.join("agents")).unwrap();
    std::fs::write(dir.join("web/200.html"), "<!doctype html><title>e2e</title>").unwrap();
    std::fs::copy(agent_bin(), dir.join("agents/rmm-agent-linux-x86_64")).unwrap();
    // Only packaged into the MSI here, never run.
    std::fs::write(dir.join("agents/rmm-agent-windows-x86_64.exe"), b"MZ e2e stand-in").unwrap();
    println!("e2e scratch dir: {}", dir.display());

    let (graph_url, graph) = graph_mock().await;
    let _ = GRAPH_URL.set(graph_url);
    let _ = GRAPH.set(graph);
    let (acct_url, acct) = accounting_mock().await;
    let _ = ACCT_URL.set(acct_url);
    let _ = ACCT.set(acct);
    let result = {
        let port = free_port();
        let mut server =
            Server { child: Server::start(&db_url, &dir, port, false), port, db_url: db_url.clone(), dir: dir.clone(), observability: false };
        wait_healthy(&server.url()).await;
        let db = sqlx::PgPool::connect(&db_url).await.unwrap();
        run(&mut server, &db, &dir).await
    };

    sqlx::query(sqlx::AssertSqlSafe(format!("DROP DATABASE IF EXISTS {db_name} WITH (FORCE)")))
        .execute(&mut admin_conn)
        .await
        .unwrap();
    if result.is_ok() {
        let _ = std::fs::remove_dir_all(&dir);
    }
    result.unwrap();
}

async fn run(server: &mut Server, db: &sqlx::PgPool, dir: &Path) -> Result<(), String> {
    let url = server.url();
    let http = reqwest::Client::new();

    // --- security headers -------------------------------------------------------------
    for path in ["/", "/api/settings/public"] {
        let res = http.get(format!("{url}{path}")).send().await.unwrap();
        let h = res.headers();
        assert!(h["content-security-policy"].to_str().unwrap().contains("frame-ancestors 'none'"), "{path}: CSP");
        assert_eq!(h["x-frame-options"], "DENY", "{path}");
        assert_eq!(h["x-content-type-options"], "nosniff", "{path}");
        assert_eq!(h["referrer-policy"], "same-origin", "{path}");
    }

    // --- admin sign-in with mandatory 2FA ----------------------------------------------
    let admin = Api::new(&url);
    let me = admin.post("/auth/login", json!({ "email": ADMIN_EMAIL, "password": ADMIN_PASSWORD })).await;
    assert_eq!(me["user"]["mfa_setup_required"], true);
    let (s, _) = admin.call(reqwest::Method::GET, "/agents", None).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "nothing but 2FA setup before it's enabled");
    let setup = admin.post("/auth/totp/setup", json!({ "password": ADMIN_PASSWORD })).await;
    let secret = setup["secret"].as_str().unwrap().to_string();
    admin.post("/auth/totp/enable", json!({ "code": totp(&secret) })).await;
    let plain_secret = data_encoding::BASE32_NOPAD.decode(secret.as_bytes()).unwrap();
    let stored_totp = || async {
        sqlx::query_as::<_, (Vec<u8>, bool)>("SELECT totp_secret, totp_sealed FROM users WHERE email = $1")
            .bind(ADMIN_EMAIL)
            .fetch_one(db)
            .await
            .unwrap()
    };
    let (stored, sealed) = stored_totp().await;
    assert!(sealed && stored != plain_secret && stored.len() > plain_secret.len(), "TOTP secrets are encrypted at rest");
    if let Ok(path) = std::env::var("RMM_E2E_EXPECT") {
        previous_release_rows(&admin, &path).await;
    }

    // RMM_E2E_ONLY=sso runs just the single sign-on and passkey section (and the sign-in above).
    if std::env::var("RMM_E2E_ONLY").as_deref() == Ok("sso") {
        // The setup above used this step's code.
        LAST_TOTP_STEP.store(totp_step(), std::sync::atomic::Ordering::SeqCst);
        sso_and_passkeys(server, db, dir, &secret).await;
        return Ok(());
    }

    // --- tenancy -------------------------------------------------------------------------
    let client_a = admin.post("/clients", json!({ "name": "Client A" })).await;
    let client_b = admin.post("/clients", json!({ "name": "Client B" })).await;
    let (a_id, a_site) = (client_a["id"].as_str().unwrap(), client_a["default_site_id"].as_str().unwrap());
    let b_id = client_b["id"].as_str().unwrap();
    let token = admin.post(&format!("/sites/{a_site}/enrollment-tokens"), json!({ "label": "e2e" })).await;
    let token = token["token"].as_str().unwrap().to_string();

    // --- enrollment: reuse only with the old credential ----------------------------------
    let mut a1 = Agent::new(dir, "a1");
    let id1 = a1.enroll(&url, &token)?;
    assert_eq!(a1.enroll(&url, &token)?, id1, "re-enrolling with the old credential keeps the record");
    let a2 = Agent::new(dir, "a2");
    let id2 = a2.enroll(&url, &token)?;
    assert_ne!(id2, id1, "a bare token never takes over an existing agent");
    let a3 = Agent::new(dir, "a3"); // enrolled, never started: stays offline
    let id3 = a3.enroll(&url, &token)?;
    let (s, _) = admin.call(reqwest::Method::DELETE, &format!("/agents/{id2}"), None).await;
    assert!(s.is_success());

    a1.run(dir);
    admin.wait_online(&id1, true).await;

    // --- a job: output, exit code, status --------------------------------------------------
    let job = admin.run_script(&id1, "echo hello; echo oops >&2; exit 3", 30).await;
    let j = admin.wait_job(&job, 30).await;
    assert_eq!(j["status"], "failed", "{j}");
    assert_eq!(j["exit_code"], 3);
    assert_eq!(j["stdout"], "hello\n");
    assert_eq!(j["stderr"], "oops\n");
    assert_eq!(j["stdout_len"], 6);
    let tail = admin.get(&format!("/jobs/{job}?since_stdout=6&since_stderr=2")).await;
    assert_eq!((tail["stdout"].as_str(), tail["stderr"].as_str()), (Some(""), Some("ps\n")), "output from the given offsets");

    // --- live events: job status pushed over /api/events -----------------------------------
    let mut events = Events::open(&admin).await;
    let live = admin.run_script(&id1, "echo live", 30).await;
    let finished = events
        .next_matching(20, |v| v["type"] == "job" && v["id"] == live.as_str() && v["status"] == "succeeded")
        .await;
    assert!(finished.is_some(), "a job event reports the result");
    assert!(events.next_matching(15, |v| v["type"] == "agent" && v["id"] == id1.as_str()).await.is_some(), "heartbeats too");

    // --- paging, sorting, filters ----------------------------------------------------------
    let p1 = admin.get("/agents?limit=1&sort=hostname").await;
    assert_eq!((p1["items"].as_array().unwrap().len(), p1["total"].as_i64()), (1, Some(2)), "{p1}");
    assert!(p1["prev"].is_null());
    let p2 = admin.get(&format!("/agents?limit=1&sort=hostname&after={}", p1["next"].as_str().unwrap())).await;
    assert_eq!(p2["items"].as_array().unwrap().len(), 1);
    assert_ne!(p2["items"][0]["id"], p1["items"][0]["id"]);
    assert!(p2["next"].is_null(), "{p2}");
    let back = admin.get(&format!("/agents?limit=1&sort=hostname&before={}", p2["prev"].as_str().unwrap())).await;
    assert_eq!(back["items"][0]["id"], p1["items"][0]["id"], "before= returns to the first page");
    for sort in ["client", "os", "status", "health", "last_seen", "enrolled", "cpu", "mem", "disk", "version"] {
        for dir in ["asc", "desc"] {
            let p = admin.get(&format!("/agents?limit=1&sort={sort}&dir={dir}")).await;
            let next = p["next"].as_str().unwrap_or_else(|| panic!("{sort} {dir}: {p}"));
            let q = admin.get(&format!("/agents?limit=1&sort={sort}&dir={dir}&after={next}")).await;
            assert_ne!(q["items"][0]["id"], p["items"][0]["id"], "{sort} {dir}");
        }
    }
    let (s, _) = admin.call(reqwest::Method::GET, "/agents?sort=password", None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let unknown = admin.get("/agents?health=unknown").await;
    assert_eq!(unknown["items"][0]["id"], id3.as_str(), "an agent that never reported has unknown health");
    assert_eq!(admin.get("/agents?online=true").await["items"][0]["id"], id1.as_str());
    let failed = admin.get("/jobs?status=failed").await;
    assert_eq!(failed["items"][0]["id"], job.as_str());
    let mine = admin.get(&format!("/jobs?agent_id={id1}&limit=1")).await;
    assert!(mine["next"].is_string() && mine["total"].as_i64() >= Some(2), "{mine}");
    let a1_info = admin.get(&format!("/agents/{id1}")).await;
    // A failed job in the last day needs attention (or worse, if this machine's disk is full).
    assert!(matches!(a1_info["health"].as_str(), Some("attention" | "unhealthy")), "{a1_info}");
    let hostname = a1_info["hostname"].as_str().unwrap().to_string();

    // --- search, dashboard, client detail, preferences -------------------------------------
    let hits = admin.get(&format!("/search?q={}", &hostname[..hostname.len().min(3)])).await;
    assert!(hits["agents"].as_array().unwrap().iter().any(|a| a["id"] == id1.as_str()), "{hits}");
    let hits = admin.get("/search?q=client").await;
    assert_eq!(hits["clients"].as_array().unwrap().len(), 2);
    let hits = admin.get(&format!("/search?q=client&client_id={b_id}")).await;
    assert_eq!(hits["clients"].as_array().unwrap().len(), 1, "narrowed to one client");
    let dash = admin.get("/dashboard").await;
    assert_eq!(dash["offline"][0]["id"], id3.as_str());
    assert!(dash["failed_jobs"].as_array().unwrap().iter().any(|j| j["id"] == job.as_str()));
    assert_eq!(dash["client_health"][0]["id"], a_id, "the client with problems sorts first: {dash}");
    assert_eq!(admin.get(&format!("/dashboard?client_id={b_id}")).await["agents_total"], 0);
    let detail = admin.get(&format!("/clients/{a_id}")).await;
    assert_eq!((detail["name"].as_str(), detail["sites"][0]["agent_count"].as_i64()), (Some("Client A"), Some(2)));
    let (s, _) = admin.call(reqwest::Method::PUT, &format!("/clients/{b_id}"), Some(json!({ "name": "Client B2" }))).await;
    assert!(s.is_success());
    let (s, v) = admin.call(reqwest::Method::PUT, "/auth/preferences", Some(json!({ "theme": "dark", "density": "compact" }))).await;
    assert!(s.is_success() && v["theme"] == "dark", "{v}");
    admin.call(reqwest::Method::PUT, "/auth/preferences", Some(json!({ "theme": null }))).await;
    let prefs = &admin.get("/auth/me").await["preferences"];
    assert!(prefs.get("theme").is_none() && prefs["density"] == "compact", "{prefs}");
    let (s, _) = admin.call(reqwest::Method::PUT, "/auth/preferences", Some(json!({ "big": "x".repeat(40_000) }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(admin.get("/auth/me").await["preferences"]["density"], "compact", "a rejected patch keeps the old value");
    let audit = admin.get("/audit?limit=2").await;
    assert!(audit["items"].as_array().unwrap().len() == 2 && audit["next"].is_string(), "{audit}");
    let audit = admin.get("/audit?action=client.").await;
    assert!(audit["items"].as_array().unwrap().iter().all(|r| r["action"].as_str().unwrap().starts_with("client.")));

    // --- queued job for an offline agent expires --------------------------------------------
    let stale = admin.run_script(&id3, "echo never", 30).await;
    assert_eq!(admin.job(&stale).await["status"], "queued");
    sqlx::query("UPDATE jobs SET created_at = now() - interval '30 days' WHERE id = $1::uuid")
        .bind(&stale)
        .execute(db)
        .await
        .unwrap();

    // --- a job survives a server restart (agent buffers and resends) --------------------------
    let survivor = admin.run_script(&id1, "echo before; sleep 6; echo after", 60).await;
    let (api, id) = (&admin, survivor.as_str());
    eventually(10, "survivor job to start", move || async move { (api.job(id).await["stdout"] == "before\n").then_some(()) }).await;
    // A secret stored in the clear (before RMM_DATA_KEY was set) is encrypted at startup.
    sqlx::query("UPDATE users SET totp_secret = $2, totp_sealed = false, totp_last_step = NULL WHERE email = $1")
        .bind(ADMIN_EMAIL)
        .bind(&plain_secret)
        .execute(db)
        .await
        .unwrap();
    // Without RMM_METRICS_TOKEN there is no metrics endpoint at all.
    let res = http.get(format!("{url}/metrics")).bearer_auth(METRICS_TOKEN).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    // Housekeeping runs as soon as the server starts. Sessions live in Postgres, so the
    // admin's cookie still works afterwards. From here on: metrics on, JSON logs.
    server.observability = true;
    server.restart().await;
    let (stored, sealed) = stored_totp().await;
    assert!(sealed && stored != plain_secret, "plaintext TOTP secrets are encrypted on startup");
    let fresh = Api::new(&url);
    let me = fresh.post("/auth/login", json!({ "email": ADMIN_EMAIL, "password": ADMIN_PASSWORD, "code": totp(&secret) })).await;
    assert_eq!(me["user"]["totp_enabled"], true, "{me}");
    let j = admin.wait_job(&survivor, 90).await;
    assert_eq!(j["status"], "succeeded", "{j}");
    assert_eq!(j["stdout"], "before\nafter\n", "output from before and after the reconnect");
    assert_eq!(admin.job(&stale).await["status"], "expired");

    // --- a job interrupted by an agent restart reports what it had produced -----------------
    let doomed = admin.run_script(&id1, "echo started; sleep 30", 60).await;
    let (api, id) = (&admin, doomed.as_str());
    eventually(10, "doomed job to start", move || async move { (api.job(id).await["stdout"] == "started\n").then_some(()) }).await;
    a1.kill();
    a1.run(dir);
    let j = admin.wait_job(&doomed, 60).await;
    assert_eq!(j["status"], "error", "{j}");
    assert_eq!(j["stdout"], "started\n", "{j}");
    assert!(j["stderr"].as_str().unwrap().contains("agent stopped while this job was running"), "{j}");
    admin.wait_online(&id1, true).await;

    // --- a result produced while the server is down survives an agent restart too ----------
    let late = admin.run_script(&id1, "sleep 2; echo done late", 60).await;
    let (api, id) = (&admin, late.as_str());
    eventually(10, "late job to be sent", move || async move { (api.job(id).await["status"] == "sent").then_some(()) }).await;
    server.stop();
    tokio::time::sleep(Duration::from_secs(4)).await; // the job finishes with nobody to tell
    a1.kill();
    a1.run(dir);
    server.start_again().await;
    let j = admin.wait_job(&late, 60).await;
    assert_eq!(j["status"], "succeeded", "{j}");
    assert_eq!(j["stdout"], "done late\n", "{j}");
    admin.wait_online(&id1, true).await;

    // --- a job the agent has no record of is lost ----------------------------------------------
    let forgotten = admin.run_script(&id1, "sleep 30", 60).await;
    let (api, id) = (&admin, forgotten.as_str());
    eventually(10, "forgotten job to be sent", move || async move { (api.job(id).await["status"] == "sent").then_some(()) }).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    a1.kill();
    // As if the agent was reinstalled with its state wiped.
    std::fs::remove_dir_all(sensor_dir(dir, "a1", "state").join("job-results")).unwrap();
    a1.run(dir);
    let j = admin.wait_job(&forgotten, 60).await;
    assert_eq!(j["status"], "lost", "{j}");
    assert!(j["stderr"].as_str().unwrap().contains("no record of this job"), "{j}");
    admin.wait_online(&id1, true).await;

    // --- per-client access ---------------------------------------------------------------------
    admin
        .post(
            "/users",
            json!({ "email": "tech@e2e.test", "name": "Tech", "password": "tech-password-123", "role": "technician",
                    "all_clients": false, "client_ids": [b_id] }),
        )
        .await;
    let tech = Api::new(&url);
    tech.post("/auth/login", json!({ "email": "tech@e2e.test", "password": "tech-password-123" })).await;
    assert_eq!(tech.get("/agents").await["total"], 0, "client A's agents are hidden");
    let (s, _) = tech.call(reqwest::Method::GET, &format!("/clients/{a_id}"), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(tech.get(&format!("/search?q={hostname}")).await["agents"], json!([]));
    let (s, _) = tech.call(reqwest::Method::GET, &format!("/dashboard?client_id={a_id}"), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // Events about client A never reach them.
    let mut tech_events = Events::open(&tech).await;
    admin.run_script(&id1, "true", 30).await;
    assert!(
        tech_events.next_matching(4, |v| v["type"] == "job" || v["type"] == "agent").await.is_none(),
        "no events for another client's agents"
    );
    drop(tech_events);
    let clients = tech.get("/clients").await;
    assert_eq!(clients.as_array().unwrap().len(), 1);
    assert_eq!(clients[0]["id"], b_id);
    let (s, _) = tech.call(reqwest::Method::GET, &format!("/agents/{id1}"), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = tech.call(reqwest::Method::GET, &format!("/jobs/{job}"), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = tech
        .call(reqwest::Method::POST, "/jobs", Some(json!({ "agent_ids": [id1], "interpreter": "bash", "body": "id" })))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "can't run on another client's agent");
    let (s, _) = tech.call(reqwest::Method::GET, &format!("/sites/{a_site}/enrollment-tokens"), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let dash = tech.get("/dashboard").await;
    assert_eq!(dash["agents_total"], 0);

    // Scripts: MSP-wide ones are admin-only; client scripts only run on that client.
    let (s, _) = tech
        .call(reqwest::Method::POST, "/scripts", Some(json!({ "name": "global", "interpreter": "bash", "body": "true" })))
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = tech
        .call(
            reqwest::Method::POST,
            "/scripts",
            Some(json!({ "name": "a-only", "interpreter": "bash", "body": "true", "client_id": a_id })),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "can't create scripts for clients you can't see");
    // Scripts already there (an upgraded database brings its own) stay visible as they were.
    let script_names = || async {
        tech.get("/scripts").await.as_array().unwrap().iter().map(|s| s["name"].as_str().unwrap().to_string()).collect::<Vec<String>>()
    };
    let mut expected = script_names().await;
    let b_script = tech
        .post("/scripts", json!({ "name": "b-only", "interpreter": "bash", "body": "echo b", "client_id": b_id }))
        .await;
    let global = admin.post("/scripts", json!({ "name": "global", "interpreter": "bash", "body": "echo global" })).await;
    expected.extend(["b-only".to_string(), "global".to_string()]);
    expected.sort();
    let mut names = script_names().await;
    names.sort();
    assert_eq!(names, expected);
    let (s, _) = admin
        .call(reqwest::Method::POST, "/jobs", Some(json!({ "agent_ids": [id1], "script_id": b_script["id"] })))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "client B's script doesn't run on client A's agent");
    let j = admin.post("/jobs", json!({ "agent_ids": [id1], "script_id": global["id"] })).await;
    let j = admin.wait_job(j["jobs"][0]["job_id"].as_str().unwrap(), 30).await;
    assert_eq!(j["stdout"], "global\n");

    // --- patch management ---------------------------------------------------------------------
    let upd = |id: &str, category: &str, severity: Option<&str>, reboot: bool| {
        json!({ "id": id, "title": format!("Update {id}"), "kb": format!("KB{}", id.len()), "severity": severity,
                "category": category, "size": 1000, "requires_reboot": reboot })
    };
    std::fs::write(
        dir.join("a1-patches.json"),
        json!({ "updates": [upd("sec-1", "security", Some("critical"), true), upd("upd-1", "update", None, false),
                            upd("drv-1", "driver", None, false)], "fail": [] })
        .to_string(),
    )
    .unwrap();
    admin.post("/patches/scan", json!({ "agent_ids": [id1] })).await;
    let (api, id) = (&admin, id1.as_str());
    let p = eventually(30, "the patch scan", move || async move {
        let p = api.get(&format!("/agents/{id}/patches")).await;
        (p["patches"].as_array().unwrap().len() == 3).then_some(p)
    })
    .await;
    assert_eq!(p["status"]["supported"], true, "{p}");
    assert_eq!(p["status"]["provider"], "fake");
    let set_name = admin.get(&format!("/agents/{id1}")).await["policy_set_name"].clone();
    assert_eq!((p["policy"]["id"].as_str(), &p["policy"]["source"]), (Some(PATCH_ITEM), &set_name), "the patch policy of the agent's set");
    assert_eq!(p["window"]["open_now"], true, "no window: any time");
    let approval = |p: &Value, id: &str| {
        let row = p["patches"].as_array().unwrap().iter().find(|r| r["update_id"] == id).unwrap().clone();
        (row["approval"].as_str().unwrap().to_string(), row["state"].as_str().unwrap().to_string(), row["approval_manual"].as_bool().unwrap())
    };
    assert_eq!(p["patches"][0]["update_id"], "sec-1", "most severe first");
    assert_eq!(approval(&p, "sec-1"), ("approved".into(), "missing".into(), false), "the default policy approves security updates");
    assert_eq!(approval(&p, "upd-1").0, "pending");

    admin.post("/patches/approval", json!({ "decision": "approved", "update_ids": ["upd-1"], "agent_ids": [id1] })).await;
    admin.post("/patches/approval", json!({ "decision": "declined", "update_ids": ["drv-1"], "client_id": a_id })).await;
    let groups = admin.get("/patches").await;
    assert_eq!(groups["total"], 3, "{groups}");
    let declined = admin.get("/patches?approval=declined").await;
    assert_eq!(declined["items"][0]["update_id"], "drv-1");
    assert_eq!(declined["total"], 1);
    let on = admin.get("/patches/agents?update_id=sec-1").await;
    assert_eq!(on[0]["agent_id"], id1.as_str());
    let c = admin.get("/patches/compliance").await;
    let row_a = c["rows"].as_array().unwrap().iter().find(|r| r["id"] == a_id).unwrap().clone();
    assert_eq!((row_a["scanned"].as_i64(), row_a["compliant"].as_i64(), row_a["agents_missing_security"].as_i64()), (Some(1), Some(0), Some(1)), "{row_a}");

    // Scoped: client B's technician sees none of it.
    assert_eq!(tech.get("/patches").await["total"], 0);
    let (s, _) = tech.call(reqwest::Method::GET, &format!("/agents/{id1}/patches"), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = tech.call(reqwest::Method::POST, "/patches/approval", Some(json!({ "decision": "approved", "update_ids": ["drv-1"], "client_id": a_id }))).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let r = tech.post("/patches/approval", json!({ "decision": "approved", "update_ids": ["drv-1"] })).await;
    assert_eq!(r["changed"], 0, "no rows outside their clients");
    let (s, _) = tech.call(reqwest::Method::PUT, &format!("/policy-items/{PATCH_ITEM}"), Some(json!({ "config": { "reboot_policy": "always" } }))).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "the MSP-wide policy is admin-only");

    // Install everything approved: sec-1 and upd-1 (drv-1 is declined).
    let r = admin.post("/patches/install", json!({ "agent_ids": [id1], "reboot_policy": "never" })).await;
    let run_id = r["runs"][0]["run_id"].as_str().unwrap().to_string();
    assert_eq!(r["runs"][0]["updates"], 2, "{r}");
    let (api, rid) = (&admin, run_id.as_str());
    let run = eventually(30, "the install to finish", move || async move {
        let r = api.get(&format!("/patch-runs/{rid}")).await;
        (r["status"] != "sent" && r["status"] != "queued").then_some(r)
    })
    .await;
    assert_eq!(run["status"], "succeeded", "{run}");
    assert_eq!(run["succeeded"], 2);
    assert_eq!(run["reboot_required"], true, "sec-1 needs a reboot");
    assert!(run["output"].as_str().unwrap().contains("sec-1: installed"), "{run}");
    assert_eq!(run["items"].as_array().unwrap().len(), 2);
    let (api, id) = (&admin, id1.as_str());
    let p = eventually(30, "the post-install rescan", move || async move {
        let p = api.get(&format!("/agents/{id}/patches")).await;
        (p["patches"].as_array().unwrap().iter().filter(|r| r["state"] == "installed").count() == 2).then_some(p)
    })
    .await;
    assert_eq!(p["status"]["reboot_pending"], true);
    assert_eq!(approval(&p, "drv-1"), ("declined".into(), "missing".into(), true));
    let c = admin.get(&format!("/patches/compliance?client_id={a_id}")).await;
    assert_eq!(c["by"], "site");
    assert_eq!((c["totals"]["compliant"].as_i64(), c["totals"]["installed_30d"].as_i64()), (Some(1), Some(2)), "declined updates don't count: {c}");

    // Policies: client A's own set, assigned to its devices of a1's category, overrides the
    // MSP-wide patch policy to approve drivers; resetting the manual decline hands drv-1 to it.
    let a1_policy = admin.get(&format!("/agents/{id1}/policy")).await;
    let (leaf, cat) = (a1_policy["set"]["id"].as_str().unwrap().to_string(), a1_policy["category"]["id"].as_str().unwrap().to_string());
    let a_set = admin.post("/policy-sets", json!({ "name": "Client A patching", "parent_id": leaf, "client_id": a_id })).await;
    let a_set_id = a_set["id"].as_str().unwrap().to_string();
    let (s, v) = admin
        .call(reqwest::Method::PUT, &format!("/policy-items/{PATCH_ITEM}/overrides/{a_set_id}"), Some(json!({ "config": { "reboot_policy": "sometimes" } })))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    admin
        .put(
            &format!("/policy-items/{PATCH_ITEM}/overrides/{a_set_id}"),
            json!({ "config": { "auto_approve_categories": ["security", "driver"], "reboot_policy": "if_required" } }),
        )
        .await;
    let assignment = admin.put("/policy-assignments", json!({ "client_id": a_id, "category_id": cat, "policy_set_id": a_set_id })).await;
    // Resetting one agent goes back to the client-wide decline (a standing decision)...
    admin.post("/patches/approval", json!({ "decision": "pending", "update_ids": ["drv-1"], "agent_ids": [id1] })).await;
    assert_eq!(approval(&admin.get(&format!("/agents/{id1}/patches")).await, "drv-1"), ("declined".into(), "missing".into(), true));
    // ...resetting the client hands it to the policy.
    admin.post("/patches/approval", json!({ "decision": "pending", "update_ids": ["drv-1"], "client_id": a_id })).await;
    let p = admin.get(&format!("/agents/{id1}/patches")).await;
    assert_eq!((p["policy"]["source"].as_str(), p["policy"]["reboot_policy"].as_str()), (Some("Client A patching"), Some("if_required")), "{}", p["policy"]);
    assert_eq!(approval(&p, "drv-1"), ("approved".into(), "missing".into(), false));
    let (s, _) = admin.call(reqwest::Method::DELETE, &format!("/policy-assignments/{}", assignment["id"].as_str().unwrap()), None).await;
    assert!(s.is_success());
    assert_eq!(approval(&admin.get(&format!("/agents/{id1}/patches")).await, "drv-1").0, "pending", "back on the MSP-wide policy");
    let (s, _) = admin.call(reqwest::Method::DELETE, &format!("/policy-sets/{a_set_id}"), None).await;
    assert!(s.is_success());
    let (s, _) = admin.call(reqwest::Method::DELETE, &format!("/policy-items/{PATCH_ITEM}"), None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "the patch policy can't be deleted");

    // Maintenance windows.
    let (s, _) = admin.call(reqwest::Method::PUT, &format!("/sites/{a_site}/maintenance-window"), Some(json!({ "days": [1], "start": "02:00", "minutes": 120, "tz": "Mars/Olympus" }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    admin
        .call(reqwest::Method::PUT, &format!("/sites/{a_site}/maintenance-window"), Some(json!({ "days": [0, 1, 2, 3, 4, 5, 6], "start": "00:00", "minutes": 1440, "tz": "Europe/London" })))
        .await;
    let w = admin.get("/patch-windows").await;
    let w = w.as_array().unwrap().iter().find(|w| w["site_id"] == a_site).unwrap().clone();
    assert_eq!((w["open_now"].as_bool(), w["start"].as_str(), w["tz"].as_str()), (Some(true), Some("00:00"), Some("Europe/London")), "{w}");
    assert!(w["next_start"].is_string());
    let in_window: bool = sqlx::query_scalar(
        "SELECT in_maintenance_window('{6}', '23:00', 120, 'UTC', '2026-11-08 00:30+00')   -- Saturday's window, past midnight
            AND NOT in_maintenance_window('{6}', '23:00', 120, 'UTC', '2026-11-08 01:30+00')
            AND in_maintenance_window(NULL, NULL, NULL, 'UTC', now())
            AND next_maintenance_window('{1}', '02:00', 'America/New_York', '2026-11-08 12:00+00') = '2026-11-09 07:00+00'",
    )
    .fetch_one(db)
    .await
    .unwrap();
    assert!(in_window, "window arithmetic");

    // Patch alerts: failed installs, and (with reboot_hours) a restart left pending.
    let patch_policy = admin
        .alert_policy(json!({ "name": "Patching", "kind": "patch", "params": { "failed": true, "reboot_hours": 1 }, "severity": "warning", "client_id": a_id }))
        .await;
    let patch_policy_id = patch_policy["id"].as_str().unwrap().to_string();
    // The pending reboot from the first install is an hour "old".
    sqlx::query("UPDATE agents SET reboot_pending_since = now() - interval '2 hours' WHERE id = $1::uuid").bind(&id1).execute(db).await.unwrap();
    let (api, pp) = (&admin, patch_policy_id.as_str());
    let reboot = eventually(30, "the restart-pending alert", move || async move {
        alerts_for(api, &format!("policy_id={pp}")).await.into_iter().find(|a| a["title"] == "Restart pending to finish updates")
    })
    .await;
    assert_eq!(reboot["agent_id"], id1.as_str());

    // Automatic install: a new critical update, a policy that installs automatically, a
    // failure that is recorded (and retried later, up to three times).
    std::fs::write(
        dir.join("a1-patches.json"),
        json!({ "updates": [upd("upd-1b", "update", None, false), upd("drv-1", "driver", None, false), upd("sec-2", "security", Some("important"), false)],
                "fail": ["sec-2"] })
        .to_string(),
    )
    .unwrap();
    admin.set_root_item(PATCH_ITEM, json!({ "auto_approve_categories": ["security"], "auto_install": true, "reboot_policy": "never" })).await;
    admin.post("/patches/scan", json!({ "agent_ids": [id1] })).await;
    let (api, id) = (&admin, id1.as_str());
    let run = eventually(100, "an automatic install", move || async move {
        let runs = api.get(&format!("/patch-runs?agent_id={id}")).await;
        runs.as_array().unwrap().iter().find(|r| r["trigger"] == "policy" && r["status"] != "sent" && r["status"] != "queued").cloned()
    })
    .await;
    assert_eq!(run["status"], "failed", "{run}");
    assert_eq!(run["updates"], 1, "only the approved update: {run}");
    let (api, id) = (&admin, id1.as_str());
    let p = eventually(30, "the failure to be recorded", move || async move {
        let p = api.get(&format!("/agents/{id}/patches")).await;
        let row = p["patches"].as_array().unwrap().iter().find(|r| r["update_id"] == "sec-2")?.clone();
        (row["state"] == "failed").then_some(row)
    })
    .await;
    assert_eq!(p["fail_count"], 1);
    assert!(p["last_error"].as_str().unwrap().contains("simulated"), "{p}");
    let (api, pp) = (&admin, patch_policy_id.as_str());
    let failed = eventually(30, "the failed-install alert", move || async move {
        alerts_for(api, &format!("policy_id={pp}")).await.into_iter().find(|a| a["title"] == "Update failed to install: Update sec-2")
    })
    .await;
    assert_eq!(failed["details"]["count"], 1, "{failed}");
    let a = admin.get(&format!("/agents/{id1}")).await;
    assert_eq!(a["patches_failed"].as_i64(), Some(1), "{a}");
    // The rescan reported no pending restart any more (the fake's file was replaced), so that alert cleared.
    let (api, rid) = (&admin, reboot["id"].as_str().unwrap().to_string());
    eventually(30, "the restart-pending alert to clear", || async { (api.get(&format!("/alerts/{rid}")).await["state"] == "resolved").then_some(()) }).await;
    assert_ne!(a["health"], "healthy", "a failed install counts against health");
    // Declining the update clears it.
    admin.post("/patches/approval", json!({ "decision": "declined", "update_ids": ["sec-2"], "agent_ids": [id1] })).await;
    admin.post("/patches/scan", json!({ "agent_ids": [id1] })).await;
    let (api, fid) = (&admin, failed["id"].as_str().unwrap().to_string());
    eventually(30, "the failed-install alert to clear", || async { (api.get(&format!("/alerts/{fid}")).await["state"] == "resolved").then_some(()) }).await;
    let s = admin.delete_policy(&patch_policy_id).await;
    assert!(s.is_success());
    let agent = admin.get(&format!("/agents/{id1}/activity")).await;
    assert!(agent.as_array().unwrap().iter().any(|r| r["action"] == "agent.patch_result"), "results are in the agent's activity");
    // Back to the conservative default so the rest of the run isn't patched behind its back.
    let (s, v) = admin
        .set_root_item(PATCH_ITEM, json!({ "auto_approve_categories": ["security", "critical", "definition"], "auto_install": false, "reboot_policy": "never" }))
        .await;
    assert!(s.is_success(), "{v}");

    // An approval for a client stands: an agent that reports the update later gets it approved.
    let r = admin.post("/patches/approval", json!({ "decision": "approved", "update_ids": ["later-1"], "client_id": a_id })).await;
    assert_eq!(r["changed"], 0, "nobody has it yet");
    std::fs::write(dir.join("a1-patches.json"), json!({ "updates": [upd("later-1", "update", None, false)], "fail": [] }).to_string()).unwrap();
    admin.post("/patches/scan", json!({ "agent_ids": [id1] })).await;
    let (api, id) = (&admin, id1.as_str());
    let p = eventually(30, "the scan with a newly reported update", move || async move {
        let p = api.get(&format!("/agents/{id}/patches")).await;
        p["patches"].as_array().unwrap().iter().any(|r| r["update_id"] == "later-1").then_some(p)
    })
    .await;
    assert_eq!(approval(&p, "later-1"), ("approved".into(), "missing".into(), true), "the standing approval applies");
    admin.post("/patches/approval", json!({ "decision": "pending", "update_ids": ["later-1"], "client_id": a_id })).await;
    assert_eq!(approval(&admin.get(&format!("/agents/{id1}/patches")).await, "later-1").0, "pending", "and goes with a reset");

    // Granting client A takes effect on the next request.
    let tech_id = admin.get("/users").await.as_array().unwrap().iter().find(|u| u["email"] == "tech@e2e.test").unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (s, _) = admin
        .call(reqwest::Method::PUT, &format!("/users/{tech_id}/access"), Some(json!({ "all_clients": false, "client_ids": [a_id, b_id] })))
        .await;
    assert!(s.is_success());
    assert_eq!(tech.get(&format!("/agents/{id1}")).await["id"], id1.as_str());

    // --- Linux packages with the token baked in -------------------------------------------------
    let unbounded = admin.post(&format!("/sites/{a_site}/enrollment-tokens"), json!({ "expires_in_hours": 0 })).await;
    assert!(unbounded["packages"].is_null(), "no package links for a token without limits");
    let res = http
        .get(format!("{url}/api/agent-packages/linux-x86_64/rmm-agent.deb?token={}", unbounded["token"].as_str().unwrap()))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "unbounded tokens aren't baked into packages");
    let pkg_token = admin.post(&format!("/sites/{a_site}/enrollment-tokens"), json!({ "purpose": "package" })).await;
    assert_eq!(pkg_token["max_uses"], 50);
    assert!(pkg_token["expires_at"].is_string());
    for (key, magic) in [("deb", &b"!<arch>\n"[..]), ("rpm", &[0xed, 0xab, 0xee, 0xdb][..])] {
        let res = http.get(pkg_token["packages"][key].as_str().unwrap()).send().await.unwrap();
        assert_eq!(res.status(), StatusCode::OK, "{key}");
        let body = res.bytes().await.unwrap();
        assert!(body.starts_with(magic), "{key} magic");
        let path = dir.join(format!("rmm-agent.{key}"));
        std::fs::write(&path, &body).unwrap();
        // Inspect with the native tool when it's installed.
        let tool = if key == "deb" { ("dpkg-deb", vec!["-c"]) } else { ("rpm", vec!["-qlp"]) };
        if let Ok(out) = Command::new(tool.0).args(&tool.1).arg(&path).stderr(Stdio::null()).output() {
            let listing = String::from_utf8_lossy(&out.stdout);
            assert!(out.status.success(), "{} rejected the package", tool.0);
            assert!(listing.contains("usr/bin/rmm-agent") && listing.contains("etc/rmm-agent/enroll.toml"), "{listing}");
            println!("{} accepted the .{key}", tool.0);
        }
    }

    // --- Windows MSI with the token baked in ---------------------------------------------------
    let msi_url = pkg_token["windows_packages"]["msi"].as_str().unwrap();
    assert!(pkg_token["windows_packages"]["install_msi"].as_str().unwrap().contains("msiexec"));
    let res = http.get(msi_url).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()["content-type"], "application/x-msi");
    let body = res.bytes().await.unwrap();
    assert!(body.starts_with(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]), "compound file magic");
    let raw = String::from_utf8_lossy(&body);
    assert!(raw.contains(pkg_token["token"].as_str().unwrap()), "the token is in the Property table");
    let res = http
        .get(format!("{url}/api/agent-packages/windows-x86_64/rmm-agent.msi?token={}", unbounded["token"].as_str().unwrap()))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "unbounded tokens aren't baked into the MSI either");

    // --- what the MSI runs on upgrade/repair: keeps an existing enrollment ------------------------
    let install_log = dir.join("install.log");
    let out = Command::new(agent_bin())
        .arg("--config")
        .arg(&a1.config)
        .args(["enroll", "--server", &url, "--token", "", "--keep-existing", "--log-file"])
        .arg(&install_log)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let log = std::fs::read_to_string(&install_log).unwrap();
    assert!(log.contains(&format!("ok: already enrolled as {id1}")), "{log}");
    let out = Command::new(agent_bin())
        .arg("--config")
        .arg(dir.join("never-enrolled.toml"))
        .args(["enroll", "--server", &url, "--token", "not-a-token", "--keep-existing", "--log-file"])
        .arg(&install_log)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(std::fs::read_to_string(&install_log).unwrap().contains("failed: enrollment rejected"), "failures are logged too");

    // --- self-update offer reaches the agent, which refuses an unverifiable build ------------------
    let agent_file = dir.join("agents/rmm-agent-linux-x86_64");
    let sha = {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(std::fs::read(&agent_file).unwrap()))
    };
    std::fs::write(
        dir.join("agents/rmm-agent-linux-x86_64.update.json"),
        json!({ "platform": "linux-x86_64", "version": "99.0.0", "sha256": sha, "signature": "00".repeat(64) }).to_string(),
    )
    .unwrap();
    let releases = admin.get("/agent-updates").await;
    assert_eq!(releases["releases"][0]["version"], "99.0.0");
    assert_eq!(releases["releases"][0]["outdated"], 2);
    admin.post(&format!("/agents/{id1}/update"), json!({})).await;
    let (api, id) = (&admin, id1.as_str());
    let a = eventually(60, "the agent to report on the update", move || async move {
        let a = api.get(&format!("/agents/{id}")).await;
        (a["update_state"] == "failed").then_some(a)
    })
    .await;
    // Unsigned dev builds refuse outright; a build with a key fails the signature or the
    // not-under-systemd check instead. Either way nothing was installed.
    println!("update refused as expected: {}", a["update_detail"]);
    assert!(a["agent_version"] != "99.0.0");

    // RMM_E2E_ONLY=desk skips the slow device sections while working on the service desk.
    let all = std::env::var("RMM_E2E_ONLY").as_deref() != Ok("desk");
    if all {
        desktop(&url, &admin, dir, &id1).await;
    }
    tickets(&url, &admin, &id1, a_id, b_id).await;
    if all {
        security(&admin, dir, &id1, &id3).await;
        sensor(&url, &admin, db, dir, &id1, a_id, b_id).await;
        monitoring(server, &admin, db, dir, &id1, &id3, a_id).await;
        day_to_day(&admin, &tech, db, dir, &id1, &id3, a_id).await;
        policies(&url, &admin, db, dir, &id1, &id3, a_id, a_site, b_id).await;
    }
    portal_and_sla(&url, &admin, db, a_id, b_id).await;
    billing(&url, &admin, &tech, db, a_id, b_id).await;
    docs_and_vault(&url, &admin, db, a_id, b_id).await;
    ticket_docs(&url, &admin, a_id, b_id).await;
    sso_and_passkeys(server, db, dir, &secret).await;

    // --- rate limits ------------------------------------------------------------------------------
    // Failed sign-ins from one client IP (via the trusted proxy's X-Forwarded-For).
    let mut limited = None;
    for i in 0..15 {
        let res = http
            .post(format!("{url}/api/auth/login"))
            .header("x-forwarded-for", "203.0.113.7")
            .json(&json!({ "email": format!("nobody{i}@e2e.test"), "password": "wrong-password-x" }))
            .send()
            .await
            .unwrap();
        if res.status() == StatusCode::TOO_MANY_REQUESTS {
            assert!(res.headers().contains_key("retry-after"));
            limited = Some(i);
            break;
        }
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }
    assert_eq!(limited, Some(10), "the 11th failure from one IP is refused");
    // Other addresses are unaffected; a spoofed header from an untrusted peer isn't believed
    // (here every peer is 127.0.0.1, which is trusted, so a different header = a different IP).
    let res = http
        .post(format!("{url}/api/auth/login"))
        .header("x-forwarded-for", "203.0.113.8")
        .json(&json!({ "email": "nobody@e2e.test", "password": "wrong-password-x" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // Bad enrollment tokens (download endpoint and agent socket share the budget).
    let mut limited = None;
    for i in 0..25 {
        let res = http
            .get(format!("{url}/api/agent-downloads/linux-x86_64?token=bogus{i}"))
            .header("x-forwarded-for", "198.51.100.9")
            .send()
            .await
            .unwrap();
        if res.status() == StatusCode::TOO_MANY_REQUESTS {
            limited = Some(i);
            break;
        }
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }
    assert_eq!(limited, Some(20));

    observability(&url, dir).await;
    a1.kill();
    Ok(())
}

/// Policy management (docs/design/policies.md): the tree, inheritance with per-field overrides
/// and resets, validation against every descendant, assignments at client and site, pins and
/// "customize", category moves (and enrollment into a category), limits, alerts closing when a
/// policy stops applying, remote access turned off, run_script_id, and tenant scoping.
#[allow(clippy::too_many_arguments)]
async fn policies(url: &str, admin: &Api, db: &sqlx::PgPool, dir: &Path, id1: &str, id3: &str, a_id: &str, a_site: &str, b_id: &str) {
    const LINUX_SET: &str = "00000000-0000-4000-8001-000000000002";
    let item = |v: &Value| v["id"].as_str().unwrap().to_string();
    let find = |list: &Value, id: &str| list.as_array().unwrap().iter().find(|p| p["id"] == id).cloned();

    // --- the tree, the categories, and where a1 sits -------------------------------------------------
    let sets = admin.get("/policy-sets").await;
    let root = find(&sets, ROOT_SET).unwrap();
    assert_eq!((root["builtin"].as_bool(), root["depth"].as_i64(), root["parent_id"].as_str()), (Some(true), Some(0), None), "{root}");
    assert!(root["defines"].as_array().unwrap().iter().any(|m| m == "patch"), "{root}");
    assert_eq!(sets.as_array().unwrap().iter().filter(|s| s["builtin"] == true).count(), 10);
    let cats = admin.get("/device-categories").await;
    assert_eq!(cats.as_array().unwrap().iter().filter(|c| c["builtin"] == true).count(), 6, "{cats}");
    let mine = admin.get(&format!("/agents/{id1}/policy")).await;
    assert_eq!((mine["reason"].as_str(), mine["category"]["builtin"].as_bool(), mine["category"]["manual"].as_bool()), (Some("default"), Some(true), Some(false)), "{mine}");
    let platform = mine["platform"].as_str().unwrap().to_string();
    let reported = admin.get(&format!("/agents/{id1}")).await["inventory"]["system"]["platform"].clone();
    assert_eq!(reported.as_str(), Some(platform.as_str()), "the agent reports its platform and the server keeps it");
    let (leaf, cat) = (mine["set"]["id"].as_str().unwrap().to_string(), mine["category"]["id"].as_str().unwrap().to_string());
    assert_eq!(mine["chain"][1]["id"], LINUX_SET, "All devices, Linux, then the leaf: {mine}");
    assert_eq!(find(&cats, &cat).unwrap()["default_set_id"], leaf.as_str());
    let listed = admin.get(&format!("/agents?category_id={cat}")).await;
    assert!(listed["items"].as_array().unwrap().iter().any(|a| a["id"] == id1 && a["policy_set_id"] == leaf.as_str()), "{listed}");

    // --- a client's set, assigned to its devices of a1's category ------------------------------------
    let a_set = admin.post("/policy-sets", json!({ "name": "A Linux (e2e)", "parent_id": leaf, "client_id": a_id })).await;
    let a_set_id = item(&a_set);
    assert_eq!(a_set["depth"], 3);
    let (s, _) = admin.call(reqwest::Method::POST, "/policy-sets", Some(json!({ "name": "bad", "parent_id": a_set_id, "client_id": b_id }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "below a client's set, only that client's");
    let assignment = admin.put("/policy-assignments", json!({ "client_id": a_id, "category_id": cat, "policy_set_id": a_set_id })).await;
    let mine = admin.get(&format!("/agents/{id1}/policy")).await;
    assert_eq!((mine["reason"].as_str(), mine["set"]["id"].as_str(), mine["assignment_id"].as_str()), (Some("client"), Some(a_set_id.as_str()), assignment["id"].as_str()), "{mine}");
    assert_eq!(admin.get(&format!("/agents/{id3}/policy")).await["set"]["id"], a_set_id.as_str(), "a3 is in the same category");

    // --- inheritance and per-field overrides ------------------------------------------------------------
    let cpu = admin
        .post(
            &format!("/policy-sets/{LINUX_SET}/items"),
            json!({ "module": "alert", "name": "CPU (policies e2e)", "client_id": a_id,
                    "config": { "kind": "cpu", "params": { "threshold": 99, "minutes": 5 }, "severity": "warning" } }),
        )
        .await;
    let cpu_id = item(&cpu);
    assert_eq!((cpu["status"].as_str(), cpu["origin_set_id"].as_str()), (Some("defined"), Some(LINUX_SET)), "{cpu}");
    let here = admin.item_in(&a_set_id, &cpu_id).await;
    assert_eq!((here["status"].as_str(), here["config"]["params"]["threshold"].as_f64()), (Some("inherited"), Some(99.0)), "{here}");
    assert_eq!(here["sources"]["params.threshold"], LINUX_SET);
    // One item read by id (links from its alerts): as defined at its origin.
    let one = admin.get(&format!("/policy-items/{cpu_id}")).await;
    assert_eq!((one["status"].as_str(), one["origin_set_id"].as_str()), (Some("defined"), Some(LINUX_SET)), "{one}");
    let ov_path = format!("/policy-items/{cpu_id}/overrides/{a_set_id}");
    let ov = |config: Value| {
        let path = ov_path.clone();
        async move { admin.call(reqwest::Method::PUT, &path, Some(json!({ "config": config }))).await }
    };
    let (s, v) = ov(json!({ "params": { "threshold": 500 } })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert!(v["error"].as_str().unwrap().contains("A Linux (e2e)"), "the error names the set: {v}");
    let (s, v) = ov(json!({ "kind": "memory" })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "the alert type can't be overridden: {v}");
    let (s, v) = ov(json!({ "params": { "threshold": 95 }, "severity": "critical" })).await;
    assert!(s.is_success(), "{v}");
    assert_eq!((v["status"].as_str(), v["config"]["params"]["threshold"].as_f64(), v["config"]["params"]["minutes"].as_i64()), (Some("overridden"), Some(95.0), Some(5)), "{v}");
    assert_eq!((v["sources"]["params.threshold"].as_str(), v["sources"]["params.minutes"].as_str()), (Some(a_set_id.as_str()), Some(LINUX_SET)), "{v}");
    assert_eq!(v["override"]["config"], json!({ "params": { "threshold": 95 }, "severity": "critical" }));
    // Reset one field: the override without it.
    let (_, v) = ov(json!({ "params": { "threshold": 95 } })).await;
    assert_eq!((v["config"]["severity"].as_str(), v["sources"]["severity"].as_str()), (Some("warning"), Some(LINUX_SET)), "{v}");
    // The origin's own edits still flow down to fields not overridden.
    let (s, v) = admin
        .call(reqwest::Method::PUT, &format!("/policy-items/{cpu_id}"), Some(json!({ "config": { "kind": "cpu", "params": { "threshold": 98, "minutes": 7 }, "severity": "info" } })))
        .await;
    assert!(s.is_success(), "{v}");
    let here = admin.item_in(&a_set_id, &cpu_id).await;
    assert_eq!((here["config"]["params"]["threshold"].as_f64(), here["config"]["params"]["minutes"].as_i64(), here["config"]["severity"].as_str()), (Some(95.0), Some(7), Some("info")), "{here}");
    let (s, _) = admin.call(reqwest::Method::PUT, &format!("/policy-items/{cpu_id}"), Some(json!({ "config": { "kind": "memory", "params": { "threshold": 98, "minutes": 7 }, "severity": "info" } }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "an item's type can't change");
    // Reset all.
    let (s, v) = admin.call(reqwest::Method::DELETE, &format!("/policy-items/{cpu_id}/overrides/{a_set_id}"), None).await;
    assert!(s.is_success(), "{v}");
    assert_eq!((v["status"].as_str(), v["config"]["params"]["threshold"].as_f64()), (Some("inherited"), Some(98.0)), "{v}");
    // Overrides only below the item's own set.
    let (s, _) = admin.call(reqwest::Method::PUT, &format!("/policy-items/{cpu_id}/overrides/{ROOT_SET}"), Some(json!({ "config": { "severity": "info" } }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(admin.delete_policy(&cpu_id).await, StatusCode::OK);

    // Validation runs against every descendant: All devices' patch window can't go away while a
    // set below only changes its length.
    let (s, v) = admin.set_root_item(PATCH_ITEM, json!({ "window": { "days": [6], "start": "22:00", "minutes": 120, "tz": "site" } })).await;
    assert!(s.is_success(), "{v}");
    admin.put(&format!("/policy-items/{PATCH_ITEM}/overrides/{a_set_id}"), json!({ "config": { "window": { "minutes": 60 } } })).await;
    let p = admin.get(&format!("/agents/{id1}/patches")).await;
    assert_eq!((p["policy"]["own_window"].as_bool(), p["policy"]["window"]["minutes"].as_i64()), (Some(true), Some(60)), "{}", p["policy"]);
    let (s, v) = admin.set_root_item(PATCH_ITEM, json!({ "window": null })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert!(v["error"].as_str().unwrap().contains("A Linux (e2e)"), "{v}");
    admin.call(reqwest::Method::DELETE, &format!("/policy-items/{PATCH_ITEM}/overrides/{a_set_id}"), None).await;
    let (s, v) = admin.set_root_item(PATCH_ITEM, json!({ "window": null })).await;
    assert!(s.is_success(), "{v}");
    assert_eq!(admin.get(&format!("/agents/{id1}/patches")).await["policy"]["own_window"], false, "back on the site's window");

    // --- an alert that stops applying closes ---------------------------------------------------------------
    let off = admin
        .post(
            &format!("/policy-sets/{a_set_id}/items"),
            json!({ "module": "alert", "name": "Offline (policies e2e)", "config": { "kind": "offline", "params": { "minutes": 1 }, "severity": "warning" } }),
        )
        .await;
    let off_id = item(&off);
    assert_eq!(off["limit"]["client_id"], a_id, "a client's set limits its items to the client");
    let open_on_a3 = |what: &'static str| {
        let off_id = off_id.clone();
        async move {
            eventually(60, what, || async { alerts_for(admin, &format!("policy_id={off_id}&agent_id={id3}")).await.into_iter().next() }).await
        }
    };
    let closed = |alert: Value, what: &'static str| async move {
        let aid = alert["id"].as_str().unwrap().to_string();
        let a = eventually(30, what, || async {
            let a = admin.get(&format!("/alerts/{aid}")).await;
            (a["state"] == "resolved").then_some(a)
        })
        .await;
        assert_eq!(a["resolution"], "policy", "{what}: {a}");
    };
    let a = open_on_a3("the offline alert from the client's set").await;
    // Moving a3 to a custom category (whose default is the Linux set) takes it out of the set.
    let (s, _) = admin.call(reqwest::Method::POST, "/device-categories", Some(json!({ "name": "Kiosks (e2e)", "default_set_id": a_set_id }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "a category's default is an MSP-wide set");
    let kiosks = admin.post("/device-categories", json!({ "name": "Kiosks (e2e)", "description": "e2e", "default_set_id": LINUX_SET })).await;
    let kiosks_id = item(&kiosks);
    let (s, _) = admin.call(reqwest::Method::POST, "/device-categories", Some(json!({ "name": "kiosks (E2E)", "default_set_id": LINUX_SET }))).await;
    assert_eq!(s, StatusCode::CONFLICT);
    let moved = admin.post("/agents/category", json!({ "agent_ids": [id3], "category_id": kiosks_id })).await;
    assert_eq!((moved["changed"].as_i64(), moved["moved"].as_i64()), (Some(1), Some(1)), "{moved}");
    let a3 = admin.get(&format!("/agents/{id3}/policy")).await;
    assert_eq!((a3["category"]["id"].as_str(), a3["category"]["manual"].as_bool(), a3["set"]["id"].as_str()), (Some(kiosks_id.as_str()), Some(true), Some(LINUX_SET)), "{a3}");
    closed(a, "the alert to close when a3 left the set").await;
    // Back to automatic: the client's set again, and the alert with it.
    admin.post("/agents/category", json!({ "agent_ids": [id3], "category_id": null })).await;
    assert_eq!(admin.get(&format!("/agents/{id3}/policy")).await["category"]["id"], cat.as_str());
    let a = open_on_a3("the offline alert again").await;
    // A pin beats the assignment.
    let pinned = admin.put(&format!("/agents/{id3}/policy-pin"), json!({ "policy_set_id": LINUX_SET })).await;
    assert_eq!((pinned["reason"].as_str(), pinned["set"]["id"].as_str()), (Some("pin"), Some(LINUX_SET)), "{pinned}");
    closed(a, "the alert to close when a3 was pinned elsewhere").await;
    let custom = admin.post(&format!("/agents/{id3}/policy-pin/customize"), json!({})).await;
    let custom_set = custom["set"]["id"].as_str().unwrap().to_string();
    assert_eq!((custom["reason"].as_str(), custom["chain"][1]["id"].as_str(), custom["pin"]["id"].as_str()), (Some("pin"), Some(LINUX_SET), Some(custom_set.as_str())), "a child of its set: {custom}");
    assert_eq!(custom["chain"].as_array().unwrap().len(), 3, "{custom}");
    let (s, v) = admin.call(reqwest::Method::DELETE, &format!("/policy-sets/{custom_set}"), None).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert!(v["error"].as_str().unwrap().contains("1 pinned device"), "{v}");
    admin.put(&format!("/agents/{id3}/policy-pin"), json!({ "policy_set_id": null })).await;
    let (s, _) = admin.call(reqwest::Method::DELETE, &format!("/policy-sets/{custom_set}"), None).await;
    assert!(s.is_success());
    let a = open_on_a3("the offline alert once unpinned").await;
    // A site assignment beats the client's; the site's set switches the alert off there.
    let site_set = admin.post("/policy-sets", json!({ "name": "A site (e2e)", "parent_id": a_set_id })).await;
    let site_set_id = item(&site_set);
    assert_eq!(site_set["client_id"], a_id, "children of a client's set are the client's");
    let site_assignment = admin.put("/policy-assignments", json!({ "client_id": a_id, "site_id": a_site, "category_id": cat, "policy_set_id": site_set_id })).await;
    assert_eq!(admin.get(&format!("/agents/{id3}/policy")).await["reason"], "site");
    let v = admin.put(&format!("/policy-items/{off_id}/overrides/{site_set_id}"), json!({ "enabled": false, "config": {} })).await;
    assert_eq!((v["enabled"].as_bool(), v["sources"]["enabled"].as_str()), (Some(false), Some(site_set_id.as_str())), "{v}");
    closed(a, "the alert to close when the site's set disabled the policy").await;
    let listed = admin.get(&format!("/policy-assignments?client_id={a_id}")).await;
    assert_eq!(listed.as_array().unwrap().len(), 2, "{listed}");
    let (s, v) = admin.call(reqwest::Method::DELETE, &format!("/policy-sets/{site_set_id}"), None).await;
    assert_eq!(s, StatusCode::CONFLICT, "assigned: {v}");
    admin.call(reqwest::Method::DELETE, &format!("/policy-assignments/{}", site_assignment["id"].as_str().unwrap()), None).await;
    assert_eq!(admin.get(&format!("/agents/{id3}/policy")).await["reason"], "client");
    let a = open_on_a3("the offline alert back on the client's set").await;
    let devices = admin.get(&format!("/policy-sets/{a_set_id}/agents")).await;
    assert_eq!(devices["total"], 2, "{devices}");
    assert!(devices["items"].as_array().unwrap().iter().all(|d| d["reason"] == "client"), "{devices}");

    // --- run_script_id: a script runs when an alert opens --------------------------------------------------
    let heal = admin.post("/scripts", json!({ "name": "heal (policies e2e)", "interpreter": "bash", "body": "echo healed" })).await;
    let jf = admin
        .post(
            &format!("/policy-sets/{a_set_id}/items"),
            json!({ "module": "alert", "name": "Jobs fail (policies e2e)",
                    "config": { "kind": "job_failed", "params": {}, "severity": "info", "run_script_id": heal["id"] } }),
        )
        .await;
    let failing = admin.run_script(id1, "exit 7", 30).await;
    admin.wait_job(&failing, 30).await;
    let jf_id = item(&jf);
    let opened = eventually(30, "the job alert with its script", || async {
        alerts_for(admin, &format!("policy_id={jf_id}&agent_id={id1}")).await.into_iter().find(|a| a["script_job_id"].is_string())
    })
    .await;
    let healed = admin.wait_job(opened["script_job_id"].as_str().unwrap(), 30).await;
    assert_eq!((healed["status"].as_str(), healed["stdout"].as_str(), healed["script_id"].as_str()), (Some("succeeded"), Some("healed\n"), heal["id"].as_str()), "{healed}");
    assert_eq!(admin.delete_policy(&jf_id).await, StatusCode::OK);

    // --- limits ----------------------------------------------------------------------------------------------
    let b_only = admin
        .alert_policy(json!({ "name": "B only (policies e2e)", "kind": "offline", "params": { "minutes": 60 }, "severity": "info", "client_id": b_id }))
        .await;
    let site_only = admin
        .alert_policy(json!({ "name": "Site only (policies e2e)", "kind": "offline", "params": { "minutes": 60 }, "severity": "info", "client_id": a_id, "site_id": a_site }))
        .await;
    let view = admin.get(&format!("/agents/{id1}/policy")).await;
    assert_eq!(find(&view["policies"], &item(&b_only)).unwrap()["applies"], false);
    assert_eq!(find(&view["policies"], &item(&site_only)).unwrap()["applies"], true);
    let (s, _) = admin
        .call(reqwest::Method::PUT, &format!("/policy-items/{}", item(&site_only)), Some(json!({ "client_id": b_id, "site_id": a_site })))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "the site must be the client's");

    // --- remote access turned off by a set ---------------------------------------------------------------------
    admin.put(&format!("/policy-items/{REMOTE_ITEM}/overrides/{a_set_id}"), json!({ "config": { "files_enabled": false, "shell_enabled": false } })).await;
    let (s, v) = admin.call(reqwest::Method::GET, &format!("/agents/{id1}/files"), None).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert!(v["error"].as_str().unwrap().contains("A Linux (e2e)"), "the message names the set: {v}");
    let (s, v) = admin.call(reqwest::Method::PUT, &format!("/policy-items/{REMOTE_ITEM}/overrides/{a_set_id}"), Some(json!({ "enabled": false, "config": {} }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "single-instance policies can't be switched off: {v}");
    admin.call(reqwest::Method::DELETE, &format!("/policy-items/{REMOTE_ITEM}/overrides/{a_set_id}"), None).await;
    let (s, _) = admin.call(reqwest::Method::GET, &format!("/agents/{id1}/files"), None).await;
    assert!(s.is_success(), "back on");

    // --- tenant scoping: a technician limited to client B ---------------------------------------------------------
    admin
        .post("/users", json!({ "email": "policytech@e2e.test", "name": "Policy tech", "password": "tech-password-123", "role": "technician",
                                "all_clients": false, "client_ids": [b_id] }))
        .await;
    let tech = Api::new(url);
    tech.post("/auth/login", json!({ "email": "policytech@e2e.test", "password": "tech-password-123" })).await;
    let theirs = tech.get("/policy-sets").await;
    assert!(find(&theirs, ROOT_SET).is_some() && find(&theirs, &a_set_id).is_none(), "MSP-wide sets only, not client A's");
    let root_items = tech.get(&format!("/policy-sets/{ROOT_SET}")).await["policies"].clone();
    assert!(find(&root_items, &item(&site_only)).is_none() && find(&root_items, &item(&b_only)).is_some(), "client A's items are hidden");
    for (m, path, body) in [
        (reqwest::Method::GET, format!("/policy-sets/{a_set_id}"), None),
        (reqwest::Method::GET, format!("/policy-sets/{a_set_id}/agents"), None),
        (reqwest::Method::PUT, format!("/policy-sets/{a_set_id}"), Some(json!({ "name": "mine" }))),
        (reqwest::Method::DELETE, format!("/policy-sets/{a_set_id}"), None),
        (reqwest::Method::POST, format!("/policy-sets/{a_set_id}/items"), Some(json!({ "module": "alert", "name": "x", "config": {} }))),
        (reqwest::Method::PUT, format!("/policy-items/{off_id}"), Some(json!({ "name": "mine" }))),
        (reqwest::Method::DELETE, format!("/policy-items/{off_id}"), None),
        (reqwest::Method::PUT, format!("/policy-items/{PATCH_ITEM}/overrides/{a_set_id}"), Some(json!({ "config": { "auto_install": true } }))),
        (reqwest::Method::GET, format!("/policy-assignments?client_id={a_id}"), None),
        (reqwest::Method::PUT, "/policy-assignments".into(), Some(json!({ "client_id": a_id, "category_id": cat, "policy_set_id": LINUX_SET }))),
        (reqwest::Method::DELETE, format!("/policy-assignments/{}", assignment["id"].as_str().unwrap()), None),
        (reqwest::Method::GET, format!("/agents/{id1}/policy"), None),
        (reqwest::Method::PUT, format!("/agents/{id1}/policy-pin"), Some(json!({ "policy_set_id": null }))),
        (reqwest::Method::POST, format!("/agents/{id1}/policy-pin/customize"), None),
        (reqwest::Method::POST, "/agents/category".into(), Some(json!({ "agent_ids": [id1], "category_id": null }))),
        (reqwest::Method::PUT, format!("/policy-items/{off_id}/exclusions/{id1}"), None),
    ] {
        let (s, v) = tech.call(m.clone(), &path, body).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{m} {path}: {v}");
    }
    assert!(tech.get("/policy-assignments").await.as_array().unwrap().is_empty());
    for (m, path, body) in [
        (reqwest::Method::POST, "/policy-sets".to_string(), json!({ "name": "MSP", "parent_id": ROOT_SET })),
        (reqwest::Method::POST, format!("/policy-sets/{ROOT_SET}/items"), json!({ "module": "alert", "name": "x", "config": { "kind": "offline", "params": { "minutes": 5 }, "severity": "info" } })),
        (reqwest::Method::PUT, format!("/policy-items/{REMOTE_ITEM}"), json!({ "config": { "desktop_enabled": false, "desktop_consent": false, "shell_enabled": true, "files_enabled": true } })),
        (reqwest::Method::POST, "/device-categories".to_string(), json!({ "name": "x", "default_set_id": ROOT_SET })),
        (reqwest::Method::PUT, format!("/policy-items/{SECURITY_ITEM}/overrides/{LINUX_SET}"), json!({ "config": { "prevention": true } })),
    ] {
        let (s, v) = tech.call(m.clone(), &path, Some(body)).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{m} {path}: {v}");
    }
    // Their own client: a set, an override and an item of their own.
    let b_set = tech.post("/policy-sets", json!({ "name": "B (e2e)", "parent_id": LINUX_SET, "client_id": b_id })).await;
    let b_set_id = item(&b_set);
    tech.put(&format!("/policy-items/{PATCH_ITEM}/overrides/{b_set_id}"), json!({ "config": { "deferral_days": 3 } })).await;
    let (s, _) = tech.call(reqwest::Method::PUT, &format!("/policy-items/{SECURITY_ITEM}/overrides/{b_set_id}"), Some(json!({ "config": { "prevention": true } }))).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "the security module also needs security.manage");
    let b_item = tech
        .post(&format!("/policy-sets/{ROOT_SET}/items"), json!({ "module": "alert", "name": "B tech's", "client_id": b_id,
                                                              "config": { "kind": "offline", "params": { "minutes": 30 }, "severity": "info" } }))
        .await;
    assert_eq!(b_item["editable"], true);
    let dup = tech.post(&format!("/policy-sets/{b_set_id}/duplicate"), json!({})).await;
    assert_eq!((dup["name"].as_str(), dup["overrides"].as_i64(), dup["client_id"].as_str()), (Some("Copy of B (e2e)"), Some(1), Some(b_id)), "{dup}");
    for id in [item(&dup), b_set_id] {
        let (s, v) = tech.call(reqwest::Method::DELETE, &format!("/policy-sets/{id}"), None).await;
        assert!(s.is_success(), "{v}");
    }
    assert_eq!(tech.delete_policy(&item(&b_item)).await, StatusCode::OK);

    // --- enrollment into a category, and agents that don't report a platform ----------------------------------------
    let token = admin.post(&format!("/sites/{a_site}/enrollment-tokens"), json!({ "label": "kiosks", "category_id": kiosks_id })).await;
    let a4 = Agent::new(dir, "a4").enroll(url, token["token"].as_str().unwrap()).unwrap();
    let v = admin.get(&format!("/agents/{a4}/policy")).await;
    assert_eq!((v["category"]["id"].as_str(), v["category"]["manual"].as_bool()), (Some(kiosks_id.as_str()), Some(true)), "{v}");
    let plain = admin.post(&format!("/sites/{a_site}/enrollment-tokens"), json!({ "label": "plain" })).await;
    let a5 = Agent::new(dir, "a5").enroll(url, plain["token"].as_str().unwrap()).unwrap();
    // As an older Windows build would be: no platform, so the OS name decides; once it reports
    // one, it moves; a manual category stays.
    let category_of = |agent: String| async move {
        sqlx::query_scalar::<_, String>("SELECT dc.name FROM agents a JOIN device_categories dc ON dc.id = a.category_id WHERE a.id = $1::uuid")
            .bind(agent)
            .fetch_one(db)
            .await
            .unwrap()
    };
    for (sql, want) in [
        ("UPDATE agents SET os_family = 'windows', os_name = 'Windows Server 2022 Standard', platform = NULL WHERE id = $1::uuid", "Windows servers"),
        ("UPDATE agents SET platform = 'workstation' WHERE id = $1::uuid", "Windows workstations"),
        ("UPDATE agents SET os_name = 'Windows 11 Pro', platform = NULL WHERE id = $1::uuid", "Windows workstations"),
    ] {
        sqlx::query(sql).bind(&a5).execute(db).await.unwrap();
        assert_eq!(category_of(a5.clone()).await, want, "{sql}");
    }
    admin.post("/agents/category", json!({ "agent_ids": [a5], "category_id": kiosks_id })).await;
    sqlx::query("UPDATE agents SET os_name = 'Windows Server 2025', platform = 'server' WHERE id = $1::uuid").bind(&a5).execute(db).await.unwrap();
    assert_eq!(category_of(a5.clone()).await, "Kiosks (e2e)", "moved by hand: stays");
    let windows_ws = admin.get(&format!("/agents/{a5}/policy")).await;
    assert_eq!(windows_ws["set"]["id"], LINUX_SET, "Kiosks' default set");
    // Deleting the category puts its devices back on automatic.
    let (s, _) = admin.call(reqwest::Method::DELETE, &format!("/device-categories/{kiosks_id}"), None).await;
    assert!(s.is_success());
    assert_eq!(category_of(a5.clone()).await, "Windows servers");
    assert_eq!(category_of(a4.clone()).await, cats.as_array().unwrap().iter().find(|c| c["id"] == cat.as_str()).unwrap()["name"].as_str().unwrap());
    let (s, _) = admin.call(reqwest::Method::DELETE, &format!("/device-categories/{cat}"), None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "built-in categories stay");
    for agent in [&a4, &a5] {
        admin.call(reqwest::Method::DELETE, &format!("/agents/{agent}"), None).await;
    }

    // --- clean up: back to the built-in sets ---------------------------------------------------------------------
    for id in [item(&b_only), item(&site_only), off_id.clone()] {
        assert_eq!(admin.delete_policy(&id).await, StatusCode::OK);
    }
    let a = admin.get(&format!("/alerts/{}", a["id"].as_str().unwrap())).await;
    assert_eq!(a["resolution"], "policy", "deleting a policy closes its alerts quietly: {a}");
    admin.call(reqwest::Method::DELETE, &format!("/policy-assignments/{}", assignment["id"].as_str().unwrap()), None).await;
    assert_eq!(admin.get(&format!("/agents/{id1}/policy")).await["reason"], "default");
    for id in [&site_set_id, &a_set_id] {
        let (s, v) = admin.call(reqwest::Method::DELETE, &format!("/policy-sets/{id}"), None).await;
        assert!(s.is_success(), "{v}");
    }
    let audit = admin.get("/audit?action=policy.override").await;
    assert!(!audit["items"].as_array().unwrap().is_empty(), "{audit}");
    println!("policies: ok");
}

/// Rows written by the previous release (`RMM_E2E_EXPECT`, from `tests/upgrade.rs`) read back
/// through this release's API after the migrations ran on them.
async fn previous_release_rows(admin: &Api, path: &str) {
    let e: Value = serde_json::from_slice(&std::fs::read(path).expect("RMM_E2E_EXPECT")).unwrap();
    let s = |k: &str| e[k].as_str().unwrap_or_else(|| panic!("{k} in {e}")).to_string();
    let client = admin.get(&format!("/clients/{}", s("client_id"))).await;
    assert_eq!(client["name"], e["client_name"], "{client}");
    let agent = admin.get(&format!("/agents/{}", s("agent_id"))).await;
    assert_eq!((agent["hostname"].as_str(), agent["site_id"].as_str()), (e["hostname"].as_str(), e["site_id"].as_str()), "{agent}");
    assert!(agent["inventory"].is_object() || agent["inventory_at"].is_string(), "the old agent's inventory: {agent}");
    // The range tests/upgrade.rs counted with: points are bucketed by range (and ranges over
    // 48 hours come from the hourly rollups), so another range can merge or miss samples.
    let points = admin.get(&format!("/agents/{}/metrics?hours=1", s("agent_id"))).await;
    assert!(points.as_array().unwrap().len() as i64 >= e["metric_samples"].as_i64().unwrap(), "metrics from before the upgrade: {points}");
    let t = admin.get(&format!("/tickets/{}", s("ticket_id"))).await;
    assert_eq!((t["subject"].as_str(), t["number"].as_i64()), (e["ticket_subject"].as_str(), e["ticket_number"].as_i64()), "{t}");
    assert!(t["agents"].as_array().unwrap().iter().any(|a| a["id"] == e["agent_id"]), "the ticket's linked agent: {t}");
    let found = admin.get(&format!("/search?q={}", url_escape(&s("hostname")))).await;
    assert!(found.to_string().contains(&s("agent_id")), "search finds the old agent: {found}");
    println!("previous release's rows: ok (client, agent with {} metric samples, ticket T-{})", points.as_array().unwrap().len(), e["ticket_number"]);
    // Its policies, migrated (written by releases that had the old model; see tests/upgrade.rs).
    if let Some(alert) = e["alert_policy_id"].as_str() {
        let linux = admin.item_in("00000000-0000-4000-8001-000000000002", alert).await;
        assert_eq!((linux["status"].as_str(), linux["limit"]["client_id"].as_str()), (Some("defined"), e["client_id"].as_str()), "the OS-limited alert policy: {linux}");
        let p = admin.get(&format!("/agents/{}/policy", s("agent_id"))).await;
        assert_eq!(p["reason"], "site", "the site's sensor policy became a site set: {p}");
        let name = format!("{} · ", e["client_name"].as_str().unwrap());
        assert!(p["set"]["name"].as_str().unwrap().starts_with(&name) && p["chain"][3]["name"].as_str().unwrap().starts_with(&name), "{p}");
        let policies = p["policies"].as_array().unwrap();
        let module = |m: &str| policies.iter().find(|x| x["module"] == m).unwrap().clone();
        assert_eq!(module("remote_access")["config"]["desktop_consent"], true, "the client's consent");
        assert!(policies.iter().any(|x| x["id"] == alert && x["applies"] == true), "{p}");
        let patch = admin.get(&format!("/agents/{}/patches", s("agent_id"))).await["policy"].clone();
        assert_eq!((patch["reboot_policy"].as_str(), patch["auto_approve_categories"].clone()), (Some("if_required"), json!(["security", "driver"])), "{patch}");
        let sec = admin.get(&format!("/agents/{}/security", s("agent_id"))).await["policy"].clone();
        assert_eq!((sec["quick_scan_hours"].as_i64(), sec["telemetry_mb"].as_i64()), (Some(6), Some(64)), "the site's sensor policy: {sec}");
        let sched = admin.get(&format!("/schedules/{}", s("schedule_id"))).await;
        assert_eq!((sched["next_run_at"].as_str(), sched["agents"].as_i64()), (e["schedule_next_run_at"].as_str(), Some(1)), "{sched}");
        println!("previous release's policies: ok");
    }
    // Its documentation pages: free-text categories became category rows (see tests/upgrade.rs).
    // Only when the previous release had documentation to seed (`docs_seeded`, see tests/upgrade.rs).
    if e["docs_seeded"] == true {
        let (doc, seeded) = (e["doc_id"].as_str().expect("doc_id"), e["doc_seeded_id"].as_str().expect("doc_seeded_id"));
        let d = admin.get(&format!("/docs/{doc}")).await;
        assert_eq!((d["title"].as_str(), d["category"].as_str(), d["body"].as_str()), (Some("Alarm panel"), Some("Alarm codes"), Some("Code changes monthly.")), "{d}");
        let cats = admin.get("/doc-categories").await;
        assert!(cats.as_array().unwrap().iter().any(|c| c["id"] == d["category_id"] && c["name"] == "Alarm codes"), "{cats}");
        let d = admin.get(&format!("/docs/{seeded}")).await;
        assert_eq!(d["category_id"], "00000000-0000-4000-8003-000000000002", "matched the seeded Infrastructure: {d}");
        println!("previous release's documentation: ok");
    }
    // The suite counts what it creates (agents, tickets, alerts), so the old client goes once
    // it has been read back: deleting it is a check of its own on the migrated rows' keys.
    admin.call(reqwest::Method::DELETE, &format!("/agents/{}", s("agent_id")), None).await;
    let (st, v) = admin.call(reqwest::Method::DELETE, &format!("/clients/{}", s("client_id")), None).await;
    assert!(st.is_success(), "deleting the old client: {st} {v}");
    let (st, _) = admin.call(reqwest::Method::GET, &format!("/tickets/{}", s("ticket_id")), None).await;
    assert_eq!(st, StatusCode::NOT_FOUND, "its ticket went with it");
}

/// `/metrics` (auth, content, bounded labels, a real Prometheus parser) and the JSON logs
/// written since the first restart.
async fn observability(url: &str, dir: &Path) {
    let http = reqwest::Client::new();
    let res = http.get(format!("{url}/metrics")).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let res = http.get(format!("{url}/metrics")).bearer_auth("e2e-metrics-tokem").send().await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let res = http.get(format!("{url}/metrics")).bearer_auth(METRICS_TOKEN).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert!(res.headers()["content-type"].to_str().unwrap().starts_with("text/plain; version=0.0.4"));
    let text = res.text().await.unwrap();
    let value = |series: &str| -> f64 {
        text.lines().find_map(|l| l.strip_prefix(series).and_then(|v| v.strip_prefix(' '))).unwrap_or_else(|| panic!("{series} in:\n{text}")).parse().unwrap()
    };
    assert!(value("rmm_agents_connected") >= 1.0);
    assert!(value("rmm_agent_messages_total{type=\"heartbeat\"}") > 0.0);
    assert!(value("rmm_agent_connects_total") >= 1.0);
    assert!(value("rmm_db_pool_max") >= 1.0 && value("rmm_db_pool_connections") >= 1.0);
    assert!(value("rmm_alert_eval_duration_seconds_count") > 0.0);
    assert!(value("rmm_db_pool_acquire_seconds_count") > 0.0);
    assert!(value("process_resident_memory_bytes") > 1e6 && value("process_cpu_seconds_total") > 0.0);
    assert!(value("rmm_http_requests_total{method=\"GET\",route=\"/api/tickets/{id}\",status=\"2xx\"}") > 0.0);
    assert!(value("rmm_http_requests_total{method=\"GET\",route=\"/api/agent-downloads/{id}\",status=\"4xx\"}") > 0.0);
    assert!(text.contains("rmm_outbox_pending{outbox=\"notifications\"}") && text.contains("rmm_outbox_oldest_seconds{outbox=\"email\"}"));
    assert!(text.contains(&format!("rmm_build_info{{version=\"{}\"}} 1", env!("CARGO_PKG_VERSION"))));
    // Bounded labels: no ids (a UUID or a 64-hex token) and no query strings anywhere.
    let id = regex_lite::Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-|[0-9a-f]{32}").unwrap();
    assert!(!id.is_match(&text) && !text.contains('?'), "ids or query strings in the metrics:\n{text}");
    // Parsed and linted by Prometheus's own tool when it's available (CI installs it).
    match std::env::var("RMM_E2E_PROMTOOL") {
        Ok(tool) if !tool.is_empty() => {
            let mut child = Command::new(&tool).args(["check", "metrics"]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
            use std::io::Write;
            child.stdin.take().unwrap().write_all(text.as_bytes()).unwrap();
            let out = child.wait_with_output().unwrap();
            assert!(out.status.success(), "promtool check metrics: {}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
            println!("promtool: the metrics parse and pass its lint");
        }
        _ => println!("RMM_E2E_PROMTOOL not set: metrics not checked with promtool"),
    }

    // JSON logs: every line since the restart is one object; request lines carry the request
    // id, method, route template, status and duration, and never a query string or token.
    let log = std::fs::read_to_string(dir.join("server.log")).unwrap();
    let json: Vec<Value> = log.lines().filter(|l| l.starts_with('{')).map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{e}: {l}"))).collect();
    assert!(json.len() > 100, "JSON log lines after the restart: {}", json.len());
    let requests: Vec<&Value> = json.iter().filter(|v| v["target"] == "rmm_server::http").collect();
    let r = requests.iter().find(|v| v["span"]["route"] == "/api/tickets/{id}").expect("a request log line");
    assert!(r["span"]["id"].as_str().is_some_and(|i| i.len() == 16) && r["span"]["method"] == "GET" && r["fields"]["status"].is_number());
    assert!(r["fields"]["duration_ms"].is_number());
    for l in log.lines().filter(|l| l.starts_with('{')) {
        assert!(!l.contains("token=bogus") && !l.contains("?from=") && !l.contains("e2e-metrics-token"), "{l}");
    }
    println!("observability: ok ({} request log lines)", requests.len());
}

/// Collects webhook deliveries: (X-RMM-Event, X-RMM-Signature, body).
type Hooks = std::sync::Arc<std::sync::Mutex<Vec<(String, String, Value)>>>;

async fn webhook_receiver() -> (String, Hooks) {
    use axum::http::HeaderMap;
    let hooks: Hooks = Default::default();
    let store = hooks.clone();
    let app = axum::Router::new().route(
        "/hook",
        axum::routing::post(move |headers: HeaderMap, body: axum::body::Bytes| {
            let store = store.clone();
            async move {
                let h = |k: &str| headers.get(k).and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
                let sig = h("x-rmm-signature");
                // Check the signature here, against the raw body.
                let mut mac = Hmac::<sha2::Sha256>::new_from_slice(b"hook-secret").unwrap();
                mac.update(&body);
                let ok = sig == format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
                store.lock().unwrap().push((h("x-rmm-event"), if ok { "valid".into() } else { sig }, serde_json::from_slice(&body).unwrap()));
                "ok"
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/hook", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, hooks)
}

async fn wait_hook(hooks: &Hooks, what: &str, pred: impl Fn(&str, &Value) -> bool) -> Value {
    eventually(30, what, || async {
        let h = hooks.lock().unwrap();
        h.iter().find(|(ev, sig, body)| {
            assert_eq!(sig, "valid", "webhook signature");
            pred(ev, body)
        })
        .map(|(_, _, b)| b.clone())
    })
    .await
}

/// Signs a content bundle the way `rmm-sign sign-content` does.
fn signed(bundle: &Value) -> Value {
    use ed25519_dalek::Signer;
    use sha2::Digest;
    let text = serde_json::to_string_pretty(bundle).unwrap();
    let sha = hex::encode(sha2::Sha256::digest(text.as_bytes()));
    let version = bundle["version"].as_str().unwrap();
    let sig = ed25519_dalek::SigningKey::from_bytes(&CONTENT_SEED).sign(&rmm_proto::security::content_signed_message(version, &sha));
    json!({ "bundle": text, "signature": { "version": version, "sha256": sha, "signature": hex::encode(sig.to_bytes()) } })
}

fn e2e_bundle(version: &str) -> Value {
    let proc_ev = |cmd: &str| json!({ "ts": "2026-11-10T00:00:00Z", "kind": "process", "action": "start", "process": { "pid": 9, "name": "sh", "command_line": cmd } });
    let file_ev = |path: &str| json!({ "ts": "2026-11-10T00:00:00Z", "kind": "file", "action": "create", "file": { "path": path } });
    json!({
        "version": version, "created_at": chrono::Utc::now(), "description": "e2e content",
        "hashes": [],
        "file_rules": [{
            "id": "E2E-F-1", "name": "E2E test malware", "severity": "high", "confidence": "high", "mode": "alert", "mitre": ["T1204"],
            "strings": [{ "text": "RMM-E2E-MALWARE" }],
            "tests": [{ "text": "x RMM-E2E-MALWARE x", "expect": true }, { "text": "clean", "expect": false }]
        }],
        "behaviour_rules": [
            { "id": "E2E-B-1", "name": "E2E marker process", "severity": "high", "confidence": "high", "mode": "alert", "mitre": ["T1059"],
              "event": "process", "actions": ["start"], "when": { "field": "process.command_line", "op": "contains", "value": "rmm-e2e-marker" },
              "tests": [{ "event": proc_ev("sh -c sleep 4 rmm-e2e-marker"), "expect": true }, { "event": proc_ev("sh -c sleep 4"), "expect": false }] },
            { "id": "E2E-B-2", "name": "E2E audit-only rule", "severity": "medium", "confidence": "medium", "mode": "audit",
              "event": "process", "actions": ["start"], "when": { "field": "process.command_line", "op": "contains", "value": "rmm-e2e-audit" },
              "tests": [{ "event": proc_ev("sh -c sleep 4 rmm-e2e-audit"), "expect": true }, { "event": proc_ev("sh"), "expect": false }] },
            { "id": "E2E-B-3", "name": "E2E unit file dropped", "severity": "medium", "confidence": "high", "mode": "alert", "mitre": ["T1543.002"],
              "event": "file", "actions": ["create"], "when": { "field": "file.name", "op": "equals", "value": "evil.service" },
              "tests": [{ "event": file_ev("/x/evil.service"), "expect": true }, { "event": file_ev("/x/good.service"), "expect": false }] }
        ]
    })
}

async fn detections_for(api: &Api, agent: &str, rule: &str) -> Vec<Value> {
    api.get(&format!("/security/detections?view=all&audit=true&agent_id={agent}&rule_id={rule}")).await["items"].as_array().unwrap().clone()
}

async fn wait_action(api: &Api, agent: &str, action_id: &str) -> Value {
    eventually(60, &format!("action {action_id} to finish"), || async {
        let s = api.get(&format!("/agents/{agent}/security")).await;
        let a = s["actions"].as_array().unwrap().iter().find(|a| a["id"] == action_id)?.clone();
        (!matches!(a["status"].as_str(), Some("sent" | "running"))).then_some(a)
    })
    .await
}

async fn sensor(url: &str, admin: &Api, db: &sqlx::PgPool, dir: &Path, id1: &str, a_id: &str, b_id: &str) {
    let respond = |action: Value| async move {
        let v = admin.post(&format!("/agents/{id1}/security/respond"), json!({ "action": action })).await;
        v["id"].as_str().unwrap().to_string()
    };

    // --- the sensor follows the policy --------------------------------------------------------
    let s = admin.get(&format!("/agents/{id1}/security")).await;
    assert_eq!((s["sensor_supported"].as_bool(), s["policy"]["enabled"].as_bool()), (Some(true), Some(false)), "{}", s["policy"]);
    let gid = SECURITY_ITEM.to_string();
    let policy = |enabled: bool| json!({ "sensor_enabled": enabled, "quick_scan_hours": 0, "full_scan_days": 0, "auto_quarantine": true,
                                        "prevention": false, "canaries": true, "telemetry_mb": 16 });
    let (s, _) = admin.set_root_item(&gid, json!({ "sensor_enabled": true, "telemetry_mb": 1 })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "telemetry below 16 MB");
    let (s, v) = admin.set_root_item(&gid, policy(true)).await;
    assert!(s.is_success(), "{v}");
    eventually(30, "the sensor to start", || async {
        let s = admin.get(&format!("/agents/{id1}/security")).await;
        (s["sensor"]["running"] == true).then_some(())
    })
    .await;
    let canary = dir.join("a1-home/.rmm-canary-do-not-touch.docx");
    eventually(20, "decoy planted", || async { canary.exists().then_some(()) }).await;

    // --- signed content: checked on upload, canary first, then promoted ------------------------
    let mut tampered = signed(&e2e_bundle("e2e.0"));
    tampered["bundle"] = json!(tampered["bundle"].as_str().unwrap().replace("E2E marker process", "Changed after signing"));
    let (s, v) = admin.call(reqwest::Method::POST, "/security/content", Some(tampered)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let mut failing = e2e_bundle("e2e.0");
    failing["file_rules"][0]["tests"][0]["text"] = json!("no marker in here");
    let (s, v) = admin.call(reqwest::Method::POST, "/security/content", Some(signed(&failing))).await;
    assert!(s == StatusCode::BAD_REQUEST && v["error"].as_str().unwrap().contains("tests fail"), "{v}");
    admin.call(reqwest::Method::PUT, &format!("/clients/{a_id}/security"), Some(json!({ "canary": true }))).await;
    let up = admin.post("/security/content", signed(&e2e_bundle("e2e.1"))).await;
    assert_eq!(up["stage"], "canary");
    eventually(30, "content on the agent", || async {
        (admin.get(&format!("/agents/{id1}/security")).await["content_version"] == "e2e.1").then_some(())
    })
    .await;
    eventually(30, "automatic promotion after the (zero) soak", || async {
        let c = admin.get("/security/content").await;
        (c["versions"][0]["stage"] == "general").then_some(())
    })
    .await;
    let rules = admin.get("/security/rules").await;
    assert_eq!(rules.as_array().unwrap().len(), 4, "{rules}");

    // A policy that alerts on every new detection and on the sensor going down.
    let pol = admin
        .alert_policy(json!({ "name": "Sensor", "kind": "security", "severity": "critical",
                                          "params": { "threats": "any", "sensor_down": true } }))
        .await;
    let pol_id = pol["id"].as_str().unwrap().to_string();
    let sec_alerts = || async { alerts_for(admin, &format!("agent_id={id1}&kind=security&state=all")).await };

    // --- file scan, auto-quarantine, restore with an exclusion ---------------------------------
    let bad = dir.join("a1-scan/sub/payload.bin");
    std::fs::create_dir_all(bad.parent().unwrap()).unwrap();
    std::fs::write(&bad, b"header RMM-E2E-MALWARE trailer").unwrap();
    let scan = respond(json!({ "type": "scan_path", "path": dir.join("a1-scan").to_string_lossy() })).await;
    let a = wait_action(admin, id1, &scan).await;
    assert_eq!(a["status"], "succeeded", "{a}");
    assert!(a["message"].as_str().unwrap().starts_with("Found 1 threat"), "{a}");
    let d = eventually(20, "file detection", || async { detections_for(admin, id1, "E2E-F-1").await.into_iter().next() }).await;
    assert_eq!((d["source"].as_str(), d["status"].as_str(), d["action_taken"].as_str()), (Some("file"), Some("quarantined"), Some("quarantined")), "{d}");
    assert!(!bad.exists(), "moved into quarantine");
    let q = eventually(20, "quarantine list", || async {
        admin.get(&format!("/security/quarantine?agent_id={id1}")).await.as_array().unwrap().first().cloned()
    })
    .await;
    assert_eq!(q["sha256"], d["sha256"]);
    let restore = admin
        .post(&format!("/agents/{id1}/security/respond"), json!({ "action": { "type": "restore_file", "id": q["id"] }, "exclude_hash": true }))
        .await;
    let a = wait_action(admin, id1, restore["id"].as_str().unwrap()).await;
    assert_eq!(a["status"], "succeeded", "{a}");
    assert_eq!(std::fs::read(&bad).unwrap(), b"header RMM-E2E-MALWARE trailer", "restored byte for byte");
    let ex = admin.get("/security/exclusions").await;
    assert!(ex.as_array().unwrap().iter().any(|e| e["kind"] == "sha256" && e["value"] == d["sha256"]), "{ex}");
    eventually(20, "quarantine row marked restored", || async {
        admin.get(&format!("/security/quarantine?agent_id={id1}&state=all")).await.as_array().unwrap().iter().any(|i| i["state"] == "restored").then_some(())
    })
    .await;
    tokio::time::sleep(Duration::from_secs(2)).await; // the agent applies the new exclusion
    let rescan = respond(json!({ "type": "scan_path", "path": dir.join("a1-scan").to_string_lossy() })).await;
    let a = wait_action(admin, id1, &rescan).await;
    assert!(a["message"].as_str().unwrap().starts_with("No threats found"), "the excluded hash is skipped: {a}");
    let quick = admin.post(&format!("/agents/{id1}/security/actions"), json!({ "action": "quick_scan", "product": "rmm" })).await;
    let a = wait_action(admin, id1, quick["id"].as_str().unwrap()).await;
    assert_eq!(a["status"], "succeeded", "{a}");

    signature_database(url, admin, dir, id1).await;
    realtime_and_reputation(url, admin, dir, id1, &gid, b_id).await;

    // --- behaviour rules, telemetry, hunting ---------------------------------------------------
    admin.run_script(id1, "sh -c 'sleep 4; true' rmm-e2e-marker", 30).await;
    admin.run_script(id1, "sh -c 'sleep 4; true' rmm-e2e-audit", 30).await;
    let hit = eventually(30, "behaviour detection", || async { detections_for(admin, id1, "E2E-B-1").await.into_iter().next() }).await;
    assert_eq!((hit["source"].as_str(), hit["audit"].as_bool(), hit["mitre"][0].as_str()), (Some("behaviour"), Some(false), Some("T1059")), "{hit}");
    let audit = eventually(30, "audit-mode detection", || async { detections_for(admin, id1, "E2E-B-2").await.into_iter().next() }).await;
    assert_eq!(audit["audit"], true);
    assert!(
        !admin.get(&format!("/security/detections?view=all&agent_id={id1}")).await["items"].as_array().unwrap().iter().any(|d| d["rule_id"] == "E2E-B-2"),
        "audit hits stay out of the default list"
    );
    eventually(20, "an alert for the behaviour detection", || async {
        sec_alerts().await.into_iter().find(|a| a["title"] == "Threat detected: E2E marker process")
    })
    .await;
    assert!(!sec_alerts().await.iter().any(|a| a["title"].as_str().unwrap().contains("audit")), "audit hits don't alert");
    let detail = admin.get(&format!("/security/detections/{}", hit["id"].as_str().unwrap())).await;
    let ctx = detail["context"].as_array().unwrap();
    assert!(ctx[0]["process"]["command_line"].as_str().unwrap().contains("rmm-e2e-marker"), "{detail}");
    assert!(ctx.len() > 1, "ancestors come with it: {detail}");
    assert_eq!(detail["rule"]["mitre"][0], "T1059");
    let enc: bool = sqlx::query_scalar("SELECT context_encrypted FROM security_detections WHERE id = $1::uuid").bind(hit["id"].as_str().unwrap()).fetch_one(db).await.unwrap();
    assert!(enc, "context is encrypted at rest with RMM_DATA_KEY");
    eventually(20, "the marker in the agent's telemetry", || async {
        let t = admin.get(&format!("/agents/{id1}/telemetry?text=rmm-e2e-marker&kinds=process")).await;
        (!t["events"].as_array().unwrap().is_empty()).then_some(())
    })
    .await;
    let h = admin.post("/security/hunt", json!({ "text": "rmm-e2e-marker", "kinds": "process" })).await;
    assert_eq!((h["hits"][0]["agent_id"].as_str(), h["searched"].as_i64()), (Some(id1), Some(1)), "{h}");
    let (s, _) = admin.call(reqwest::Method::POST, "/security/hunt", Some(json!({}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "a hunt needs a search term");

    // Files appearing in watched places, and the ransomware decoy.
    std::fs::write(dir.join("a1-watch/evil.service"), b"[Service]
ExecStart=/tmp/x
").unwrap();
    eventually(40, "file-watch detection", || async { detections_for(admin, id1, "E2E-B-3").await.into_iter().next() }).await;
    std::fs::write(&canary, b"encrypted!").unwrap();
    let c = eventually(30, "decoy detection", || async { detections_for(admin, id1, "RMM-CANARY").await.into_iter().next() }).await;
    assert_eq!((c["name"].as_str(), c["severity"].as_str()), (Some("Ransomware decoy file modified"), Some("severe")));

    // --- verdicts feed rule stats; blocking needs history; the kill switch ---------------------
    admin.post(&format!("/security/detections/{}/verdict", hit["id"].as_str().unwrap()), json!({ "verdict": "false_positive", "notes": "e2e" })).await;
    let r = admin.get("/security/rules").await.as_array().unwrap().iter().find(|r| r["id"] == "E2E-B-1").unwrap().clone();
    assert_eq!((r["false_positives"].as_i64(), r["can_block"].as_bool()), (Some(1), Some(false)), "{r}");
    let (s, v) = admin.call(reqwest::Method::PUT, "/security/rules/E2E-B-1", Some(json!({ "mode": "block" }))).await;
    assert!(s == StatusCode::BAD_REQUEST && v["error"].as_str().unwrap().contains("can't block yet"), "{v}");
    admin.call(reqwest::Method::PUT, "/security/rules/E2E-B-1", Some(json!({ "mode": "disabled", "reason": "e2e kill switch" }))).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    admin.run_script(id1, "sh -c 'sleep 4; true' rmm-e2e-marker-again", 30).await;
    tokio::time::sleep(Duration::from_secs(8)).await;
    assert_eq!(detections_for(admin, id1, "E2E-B-1").await.len(), 1, "a disabled rule doesn't fire");
    admin.call(reqwest::Method::PUT, "/security/rules/E2E-B-1", Some(json!({ "mode": null }))).await;

    // --- response: kill a process tree, triage, isolation ----------------------------------------
    let job = admin.run_script(id1, "sleep 300 # rmm-e2e-victim", 400).await;
    let pid = eventually(20, "the victim in telemetry", || async {
        let t = admin.get(&format!("/agents/{id1}/telemetry?text=sleep%20300&kinds=process")).await;
        t["events"].as_array().unwrap().iter().find(|e| e["action"] == "start" && e["process"]["name"] == "sleep").map(|e| e["process"]["pid"].as_u64().unwrap())
    })
    .await;
    let kill = respond(json!({ "type": "kill_process", "pid": pid, "tree": true })).await;
    let a = wait_action(admin, id1, &kill).await;
    assert_eq!(a["status"], "succeeded", "{a}");
    let j = admin.wait_job(&job, 30).await;
    assert_ne!(j["status"], "succeeded", "the job's process was killed: {j}");
    // Only a sensor started from the binary under test: a dev machine may run an installed agent too.
    let bin = std::fs::canonicalize(agent_bin()).unwrap();
    let agent_pid = std::fs::read_dir("/proc").unwrap().flatten().filter_map(|e| e.file_name().to_string_lossy().parse::<u32>().ok()).find(|p| {
        std::fs::read_link(format!("/proc/{p}/exe")).is_ok_and(|exe| exe == bin)
            && std::fs::read(format!("/proc/{p}/cmdline"))
                .is_ok_and(|c| String::from_utf8_lossy(&c).split('\0').collect::<Vec<_>>().ends_with(&["sensor", ""]))
    });
    if let Some(sensor_pid) = agent_pid {
        let refused = respond(json!({ "type": "kill_process", "pid": sensor_pid })).await;
        let a = wait_action(admin, id1, &refused).await;
        assert!(a["status"] == "failed" && a["message"].as_str().unwrap().contains("protected"), "our own sensor is protected: {a}");
    }
    let triage = respond(json!({ "type": "collect_triage" })).await;
    let a = wait_action(admin, id1, &triage).await;
    assert_eq!(a["status"], "succeeded", "{a}");
    // The action is marked done before the package is in storage (a big one takes a moment).
    eventually(20, "the triage package stored", || async {
        let s = admin.get(&format!("/agents/{id1}/security")).await;
        s["actions"].as_array().unwrap().iter().find(|x| x["id"] == triage.as_str() && x["has_download"] == true).map(|_| ())
    })
    .await;
    let res = admin.http.get(format!("{}/security/actions/{triage}/download", admin.base)).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert!(res.headers()["content-disposition"].to_str().unwrap().contains("triage-"));
    let body = res.bytes().await.unwrap();
    assert!(body.len() > 100 && body[..2] == [0x1f, 0x8b], "a gzip file");
    // Unprivileged, isolation can't touch the firewall: it must fail cleanly, not half-apply.
    let iso = respond(json!({ "type": "isolate", "allow": [] })).await;
    let a = wait_action(admin, id1, &iso).await;
    assert_eq!(a["status"], "failed", "{a}");
    assert_eq!(admin.get(&format!("/agents/{id1}/security")).await["isolated"], false);

    // --- the sensor crashing is noticed and it comes back ------------------------------------------
    if let Some(sensor_pid) = agent_pid {
        let _ = Command::new("kill").args(["-9", &sensor_pid.to_string()]).status();
        eventually(30, "a sensor-down alert", || async { sec_alerts().await.into_iter().find(|a| a["title"] == "Sensor not running") }).await;
        eventually(60, "the sensor restarted", || async {
            let s = admin.get(&format!("/agents/{id1}/security")).await;
            (s["sensor"]["running"] == true && s["sensor"]["restarts"].as_u64() >= Some(1)).then_some(())
        })
        .await;
    }

    // --- permission sets ----------------------------------------------------------------------------
    admin.post("/users", json!({ "email": "viewer@e2e.test", "name": "Viewer", "password": "viewer-password-1", "role": "technician" })).await;
    let vid = admin.get("/users").await.as_array().unwrap().iter().find(|u| u["email"] == "viewer@e2e.test").unwrap()["id"].as_str().unwrap().to_string();
    admin.call(reqwest::Method::PUT, &format!("/users/{vid}/permissions"), Some(json!({ "permissions": ["security.read"] }))).await;
    let viewer = Api::new(url);
    let me = viewer.post("/auth/login", json!({ "email": "viewer@e2e.test", "password": "viewer-password-1" })).await;
    assert_eq!(me["user"]["permissions"], json!(["security.read"]));
    viewer.get("/security/detections").await;
    let (s, _) = viewer.call(reqwest::Method::POST, &format!("/agents/{id1}/security/respond"), Some(json!({ "action": { "type": "collect_triage" } }))).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "read-only security permissions can't respond");
    let (s, _) = viewer.call(reqwest::Method::POST, "/security/exclusions", Some(json!({ "kind": "path", "value": "/x" }))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // --- switching the sensor off takes the decoys away --------------------------------------------
    admin.delete_policy(&pol_id).await;
    admin.set_root_item(&gid, policy(false)).await;
    eventually(30, "the sensor to stop", || async {
        (admin.get(&format!("/agents/{id1}/security")).await["sensor"]["running"] == false).then_some(())
    })
    .await;
    eventually(20, "decoys removed", || async { (!dir.join("a1-home/.rmm-canary-do-not-touch.docx").exists()).then_some(()) }).await;
    println!("sensor: ok");
}

/// A signature database signed the way `rmm-sign build-db` does: a hash signature and a YARA
/// rule, both alerting.
fn e2e_database(version: &str, marker: &str, hashed: &[u8]) -> Vec<u8> {
    e2e_database_built(version, marker, hashed, 0)
}

/// The same, built `age_hours` ago.
fn e2e_database_built(version: &str, marker: &str, hashed: &[u8], age_hours: i64) -> Vec<u8> {
    use ed25519_dalek::Signer;
    use sha2::Digest;
    let mut b = rmm_scan::db::Builder::new(version, "e2e signatures");
    b.meta.created_at = chrono::Utc::now() - chrono::Duration::hours(age_hours);
    b.add_hash(rmm_scan::db::HashSig {
        algo: rmm_scan::db::Algo::Sha256,
        digest: sha2::Sha256::digest(hashed).to_vec(),
        size: None,
        name: "E2E hashed sample".into(),
        severity: rmm_proto::security::ThreatSeverity::High,
    });
    b.add_yara(&format!(
        "{}e2e\nrule E2E_Marker {{ meta: id = \"E2E-Y-1\" name = \"E2E YARA marker\" severity = \"high\" confidence = \"high\" mode = \"alert\" mitre = \"T1027\"\n strings: $m = \"{marker}\" condition: $m }}\n",
        rmm_scan::rules::NAMESPACE_MARKER
    ));
    b.meta.rules = vec![rmm_scan::db::RuleInfo {
        id: "E2E-Y-1".into(),
        name: "E2E YARA marker".into(),
        kind: "yara".into(),
        severity: rmm_proto::security::ThreatSeverity::High,
        confidence: rmm_content::Confidence::High,
        mode: rmm_proto::security::RuleMode::Alert,
        mitre: vec!["T1027".into()],
        description: String::new(),
        digest: format!("{version}-{marker}"),
        source: Some("e2e".into()),
        licence: None,
        author: None,
        reference: None,
    }];
    b.meta.yara_rules = 1;
    let key = ed25519_dalek::SigningKey::from_bytes(&CONTENT_SEED);
    rmm_scan::db::seal(b.build().unwrap(), version, |m| key.sign(m).to_bytes())
}

/// One stored member: enough of a zip for the engine.
fn stored_zip(name: &str, data: &[u8]) -> Vec<u8> {
    let mut z = b"PK\x03\x04\x14\0\0\0\0\0\0\0\0\0\0\0\0\0".to_vec();
    z.extend_from_slice(&(data.len() as u32).to_le_bytes());
    z.extend_from_slice(&(data.len() as u32).to_le_bytes());
    z.extend_from_slice(&(name.len() as u16).to_le_bytes());
    z.extend_from_slice(&[0, 0]);
    z.extend_from_slice(name.as_bytes());
    z.extend_from_slice(data);
    let cd_off = z.len() as u32;
    let mut cd = b"PK\x01\x02\x14\0\x14\0\0\0\0\0\0\0\0\0\0\0\0\0".to_vec();
    cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
    cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
    cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
    cd.extend_from_slice(&[0; 12]);
    cd.extend_from_slice(&0u32.to_le_bytes());
    cd.extend_from_slice(name.as_bytes());
    z.extend_from_slice(&cd);
    z.extend_from_slice(b"PK\x05\x06\0\0\0\0\x01\0\x01\0");
    z.extend_from_slice(&(cd.len() as u32).to_le_bytes());
    z.extend_from_slice(&cd_off.to_le_bytes());
    z.extend_from_slice(&[0, 0]);
    z
}

/// Antivirus milestone 2 end to end: a signed database uploaded (a tampered one refused),
/// rolled out to the canary agent, downloaded over HTTP with its credentials, used by scans
/// (a hash, and a YARA rule inside an archive), the verdict cache, then a rollback that sends
/// the agent back to the previous file without downloading it again.
async fn signature_database(url: &str, admin: &Api, dir: &Path, id1: &str) {
    let upload = |body: Vec<u8>| async move {
        let res = admin.http.post(format!("{}/security/databases", admin.base)).body(body).send().await.unwrap();
        (res.status(), res.json::<Value>().await.unwrap_or(Value::Null))
    };
    let hashed = b"rmm e2e: this exact file is in the signature database".to_vec();
    let db1 = e2e_database("e2e-db.1", "RMM-E2E-YARA-MARKER", &hashed);
    let mut tampered = db1.clone();
    let n = tampered.len() / 2;
    tampered[n] ^= 1;
    let (s, v) = upload(tampered).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert!(v["error"].as_str().unwrap().contains("signature") || v["error"].as_str().unwrap().contains("database"), "{v}");
    let (s, v) = upload(db1.clone()).await;
    assert!(s.is_success(), "{v}");
    assert_eq!(v["stage"], "canary");
    let (s, _) = upload(db1.clone()).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "the same version twice");
    eventually(60, "the database on the agent", || async {
        let s = admin.get(&format!("/agents/{id1}/security")).await;
        (s["sensor"]["database_version"] == "e2e-db.1").then_some(())
    })
    .await;
    eventually(30, "automatic promotion of the database", || async {
        (admin.get("/security/databases").await["versions"][0]["stage"] == "general").then_some(())
    })
    .await;
    let list = admin.get("/security/databases").await;
    assert_eq!((list["versions"][0]["hashes"].as_i64(), list["versions"][0]["yara_rules"].as_i64()), (Some(1), Some(1)), "{list}");
    let rules = admin.get("/security/rules").await;
    assert!(rules.as_array().unwrap().iter().any(|r| r["id"] == "E2E-Y-1"), "database rules are listed with the others: {rules}");

    // The download endpoint wants the agent's own credentials, and resumes.
    let cfg = std::fs::read_to_string(dir.join("a1.toml")).unwrap();
    let secret = cfg.lines().find_map(|l| l.strip_prefix("secret = ")).unwrap().trim_matches('"').to_string();
    let link = format!("{url}/api/agent/databases/e2e-db.1");
    let http = reqwest::Client::new();
    assert_eq!(http.get(&link).send().await.unwrap().status(), StatusCode::UNAUTHORIZED);
    let res = http.get(&link).header("X-Rmm-Agent", id1).header("Authorization", "Bearer wrong").send().await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let res = http.get(&link).header("X-Rmm-Agent", id1).header("Authorization", format!("Bearer {secret}")).header("Range", "bytes=8-").send().await.unwrap();
    assert_eq!(res.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(res.bytes().await.unwrap(), db1[8..]);

    // A scan finds the listed file by hash and the marker inside an archive by YARA.
    let d = dir.join("a1-scan/db");
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("hashed.bin"), &hashed).unwrap();
    std::fs::write(d.join("bundle.zip"), stored_zip("inner/marker.txt", b"x RMM-E2E-YARA-MARKER x")).unwrap();
    for i in 0..20 {
        std::fs::write(d.join(format!("clean-{i}.txt")), format!("an ordinary file {i}")).unwrap();
    }
    let scan = |path: PathBuf| async move {
        let v = admin.post(&format!("/agents/{id1}/security/respond"), json!({ "action": { "type": "scan_path", "path": path.to_string_lossy() } })).await;
        wait_action(admin, id1, v["id"].as_str().unwrap()).await
    };
    let a = scan(d.clone()).await;
    assert!(a["status"] == "succeeded" && a["message"].as_str().unwrap().starts_with("Found 2 threats"), "{a}");
    let h = eventually(20, "the hash detection", || async { detections_for(admin, id1, "RMM-HASH").await.into_iter().find(|d| d["name"] == "E2E hashed sample") }).await;
    let y = eventually(20, "the YARA detection", || async { detections_for(admin, id1, "E2E-Y-1").await.into_iter().next() }).await;
    assert_eq!((y["status"].as_str(), y["mitre"][0].as_str()), (Some("quarantined"), Some("T1027")), "{y}");
    assert_eq!(h["status"], "quarantined", "{h}");
    assert_eq!((h["found_by"].as_str(), h["denied"].as_bool()), (Some("scan"), Some(false)), "how it was found: {h}");
    let detail = admin.get(&format!("/security/detections/{}", y["id"].as_str().unwrap())).await;
    assert_eq!((detail["database_version"].as_str(), detail["part"].as_str()), (Some("e2e-db.1"), Some("inner/marker.txt")), "{detail}");
    assert_eq!(detail["rule"]["id"], "E2E-Y-1", "the rule comes from the database's summary");
    assert!(!d.join("bundle.zip").exists() && !d.join("hashed.bin").exists(), "both quarantined");
    // Unchanged clean files aren't read again.
    let a = scan(d.clone()).await;
    assert!(a["message"].as_str().unwrap().contains("20 unchanged since a clean scan"), "{a}");
    let health = &admin.get(&format!("/agents/{id1}/security")).await["sensor"]["health"];
    assert!(health.is_null() || health["database_version"] == "e2e-db.1", "{health}");

    // A second version, then rolled back: the agent returns to the first without fetching it.
    let (s, v) = upload(e2e_database("e2e-db.2", "RMM-E2E-YARA-MARKER-2", b"another")).await;
    assert!(s.is_success(), "{v}");
    let db2 = v["id"].as_str().unwrap().to_string();
    eventually(60, "the second database on the agent", || async {
        (admin.get(&format!("/agents/{id1}/security")).await["sensor"]["database_version"] == "e2e-db.2").then_some(())
    })
    .await;
    let files = || std::fs::read_dir(sensor_dir(dir, "a1", "state").join("security/db")).unwrap().flatten().filter(|e| e.path().extension().is_some_and(|x| x == "rmmdb")).count();
    assert_eq!(files(), 2, "the previous file is kept to fall back on");
    let r = admin.post(&format!("/security/databases/{db2}/rollback"), json!({ "reason": "e2e" })).await;
    assert_eq!(r["ok"], true);
    eventually(30, "back on the first database", || async {
        (admin.get(&format!("/agents/{id1}/security")).await["sensor"]["database_version"] == "e2e-db.1").then_some(())
    })
    .await;
    let list = admin.get("/security/databases").await;
    let stages: Vec<(&str, &str)> = list["versions"].as_array().unwrap().iter().map(|v| (v["version"].as_str().unwrap(), v["stage"].as_str().unwrap())).collect();
    assert_eq!(stages, [("e2e-db.2", "rolled_back"), ("e2e-db.1", "general")]);
    let log = std::fs::read_to_string(dir.join("a1.log")).unwrap_or_default();
    assert!(log.contains("back to the previous version"), "switched without a download");
    std::fs::remove_dir_all(&d).unwrap();
    println!("signature database: ok");
}

/// Antivirus milestones 3 and 5 end to end, as far as an unprivileged agent goes: the real-time
/// policy reaches the sensor, which says on-access protection is unavailable (no fanotify
/// without root; `crates/rmm-agent/tests/onaccess.rs` covers it as root) and falls back. Then
/// the reputation lookup: a program the agent's database doesn't know but a server-only hash
/// list does is reported (and left alone), its sightings answer "which machines, first when",
/// within the user's clients only, and database hashes follow the newest database.
async fn realtime_and_reputation(url: &str, admin: &Api, dir: &Path, id1: &str, gid: &str, b_id: &str) {
    let policy = |extra: Value| {
        let mut p = json!({ "sensor_enabled": true, "quick_scan_hours": 0, "full_scan_days": 0, "auto_quarantine": true,
                            "prevention": false, "canaries": true, "telemetry_mb": 16 });
        p.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        p
    };
    let put = |p: Value| async move {
        let (s, v) = admin.set_root_item(gid, p).await;
        (s, v["config"].clone())
    };
    let (s, _) = put(policy(json!({ "realtime": "sometimes" }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = put(policy(json!({ "archive_depth": 50 }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, v) = put(policy(json!({ "realtime": "audit", "scan_on_write": false, "archive_depth": 4 }))).await;
    assert!(s.is_success(), "{v}");
    assert_eq!((v["realtime"].as_str(), v["scan_on_write"].as_bool(), v["archive_depth"].as_i64()), (Some("audit"), Some(false), Some(4)), "{v}");
    let (_, v) = put(policy(json!({}))).await;
    assert_eq!(v["realtime"], "audit", "fields left out stay as they were: {v}");
    let sec = eventually(30, "the real-time state from the sensor", || async {
        let s = admin.get(&format!("/agents/{id1}/security")).await;
        (s["sensor"]["health"]["realtime"]["mode"] == "audit").then_some(s)
    })
    .await;
    let rt = &sec["sensor"]["health"]["realtime"];
    assert_eq!((rt["state"].as_str(), rt["mechanism"].as_str()), (Some("unavailable"), Some("scan-after-start")), "unprivileged: {rt}");
    assert!(rt["error"].as_str().unwrap().contains("fanotify"), "{rt}");
    assert_eq!(sec["policy"]["realtime"], "audit", "{}", sec["policy"]);
    let collectors = sec["sensor"]["health"]["collectors"].as_array().unwrap();
    assert!(collectors.iter().any(|c| c[0] == "realtime" && c[1] == "scan-after-start"), "{collectors:?}");
    let rmm = eventually(30, "the sensor's product with real-time off", || async {
        let s = admin.get(&format!("/agents/{id1}/security")).await;
        s["products"].as_array().unwrap().iter().find(|p| p["kind"] == "rmm" && p["realtime"] == false).cloned()
    })
    .await;
    assert_eq!(rmm["enabled"], true);

    // On Linux, real-time protection the policy wants and the machine doesn't have counts against
    // it (elsewhere `unavailable` is the platform: see the unit tests), and can alert.
    let s = eventually(30, "at risk for its real-time protection", || async {
        let s = admin.get(&format!("/agents/{id1}/security")).await;
        s["risks"].as_array().unwrap().iter().any(|r| r == "sensor_realtime").then_some(s)
    })
    .await;
    assert!(s["state"] == "at_risk" || s["state"] == "threats", "{s}");
    assert_eq!((s["database"]["version"].as_str(), s["database_max_age_hours"].as_i64()), (Some("e2e-db.1"), Some(72)), "{s}");
    let fleet = admin.get("/security/agents?limit=200").await;
    let row = fleet["items"].as_array().unwrap().iter().find(|a| a["id"] == id1).unwrap().clone();
    assert!(row["risks"].as_array().unwrap().iter().any(|r| r == "sensor_realtime"), "{row}");
    assert_eq!((row["prevention"].as_bool(), row["database_version"].as_str(), row["database_max_age_hours"].as_i64()), (Some(false), Some("e2e-db.1"), Some(72)), "{row}");
    assert!(row["database_built_at"].is_string(), "{row}");
    let engine_pol = admin
        .alert_policy(json!({ "name": "Our engine", "kind": "security", "severity": "warning",
                                         "params": { "sensor_realtime": true, "database_stale": true, "threats": "off" } }))
        .await;
    let engine_pol = engine_pol["id"].as_str().unwrap().to_string();
    let engine_alert = |title: &'static str| async move {
        alerts_for(admin, &format!("agent_id={id1}&kind=security")).await.into_iter().find(|a| a["title"] == title)
    };
    let a = eventually(30, "the real-time alert", || engine_alert("Real-time protection not on")).await;
    assert_eq!((a["details"]["mode"].as_str(), a["details"]["state"].as_str()), (Some("audit"), Some("unavailable")), "{a}");

    let (s, _) = put(policy(json!({ "realtime": "off", "scan_on_write": true, "archive_depth": 5 }))).await;
    assert!(s.is_success());
    eventually(30, "the real-time alert to clear with the policy off", || async { engine_alert("Real-time protection not on").await.is_none().then_some(()) }).await;
    let s = admin.get(&format!("/agents/{id1}/security")).await;
    assert!(!s["risks"].as_array().unwrap().iter().any(|r| r == "sensor_realtime"), "off by policy isn't a fault: {s}");

    // --- reputation: a server-only hash list, an agent that ran the program ------------------------
    let d = dir.join("a1-scan/rep");
    std::fs::create_dir_all(&d).unwrap();
    // Copies of bash, which runs under any name (a multi-call coreutils `sleep` doesn't: it
    // looks at its own name and refuses one it doesn't know).
    let make = |name: &str, marker: &str| {
        let mut b = std::fs::read("/bin/bash").unwrap();
        b.extend_from_slice(marker.as_bytes());
        let p = d.join(name);
        std::fs::write(&p, &b).unwrap();
        std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        (p, sha256(&b))
    };
    let (known, known_h) = make("rep-known", "rmm e2e: known to the server only");
    let (rare, rare_h) = make("rep-rare", "rmm e2e: known to nobody");
    let list = format!("# e2e\n{known_h} E2E.Reputation.Sample\n{}\n", "ab".repeat(32));
    let res = admin.http.put(format!("{}/security/reputation/lists/e2e-list?severity=high", admin.base)).body(list).send().await.unwrap();
    assert!(res.status().is_success(), "{:?}", res.text().await);
    let res = admin.http.put(format!("{}/security/reputation/lists/bad?severity=high", admin.base)).body("not a hash\n").send().await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    // A whole feed is far bigger than an ordinary request body.
    let big: String = (0..60_000u32).map(|i| format!("{}\n", sha256(&i.to_le_bytes()))).collect();
    assert!(big.len() > 3 << 20);
    let res = admin.http.put(format!("{}/security/reputation/lists/e2e-big?severity=low", admin.base)).body(big).send().await.unwrap();
    assert!(res.status().is_success(), "{:?}", res.status());
    assert_eq!(res.json::<Value>().await.unwrap()["hashes"], 60_000);
    let (s, v) = admin.call(reqwest::Method::DELETE, "/security/reputation/lists/e2e-big", None).await;
    assert!(s.is_success() && v["hashes"] == 60_000, "{v}");
    // `; :` keeps each copy running its own `sleep` as a child rather than exec'ing into it.
    let job = admin.run_script(id1, &format!("{0} -c 'sleep 6; :'; {1} -c 'sleep 6; :'", known.display(), rare.display()), 60).await;
    let job = admin.wait_job(&job, 60).await;
    assert_eq!((job["status"].as_str(), job["exit_code"].as_i64()), (Some("succeeded"), Some(0)), "{job}");
    let det = eventually(90, "the reputation detection", || async { detections_for(admin, id1, "RMM-REPUTATION").await.into_iter().next() }).await;
    assert_eq!((det["found_by"].as_str(), det["sha256"].as_str(), det["status"].as_str()), (Some("reputation"), Some(known_h.as_str()), Some("active")), "{det}");
    assert!(det["action_taken"].as_str().unwrap().contains("reported only"), "{det}");
    assert!(known.exists(), "a reputation answer never quarantines");
    let p = admin.get(&format!("/security/prevalence?sha256={known_h}")).await;
    assert_eq!((p["seen_on"].as_i64(), p["agents"][0]["agent_id"].as_str()), (Some(1), Some(id1)), "{p}");
    assert!(p["agents"][0]["how"].as_str().unwrap().contains("ran") && p["first_seen"].is_string(), "{p}");
    assert_eq!((p["known"][0]["source"].as_str(), p["known"][0]["name"].as_str()), (Some("list:e2e-list"), Some("E2E.Reputation.Sample")), "{p}");
    let detail = admin.get(&format!("/security/detections/{}", det["id"].as_str().unwrap())).await;
    assert_eq!((detail["seen_on"].as_i64(), detail["reputation"][0]["source"].as_str()), (Some(1), Some("list:e2e-list")), "{detail}");
    let r = eventually(30, "the rare program as a hunting lead", || async {
        admin.get("/security/reputation/rare?max_agents=1&days=1").await["items"].as_array().unwrap().iter().find(|i| i["sha256"] == rare_h.as_str()).cloned()
    })
    .await;
    assert_eq!(r["agents"][0]["path"], rare.to_string_lossy().as_ref(), "{r}");
    assert!(
        !admin.get("/security/reputation/rare?max_agents=5&days=1").await["items"].as_array().unwrap().iter().any(|i| i["sha256"] == known_h.as_str()),
        "known hashes aren't leads"
    );

    // Another client's technician learns nothing about these machines.
    admin
        .post("/users", json!({ "email": "rep-scoped@e2e.test", "name": "Rep", "password": "rep-password-123", "role": "technician",
                                "all_clients": false, "client_ids": [b_id] }))
        .await;
    let scoped = Api::new(url);
    scoped.post("/auth/login", json!({ "email": "rep-scoped@e2e.test", "password": "rep-password-123" })).await;
    let p = scoped.get(&format!("/security/prevalence?sha256={known_h}")).await;
    assert_eq!((p["seen_on"].as_i64(), p["agents"].as_array().map(Vec::len)), (Some(0), Some(0)), "{p}");
    assert!(p["first_seen"].is_null(), "{p}");
    assert!(scoped.get("/security/reputation/rare?max_agents=5&days=1").await["items"].as_array().unwrap().is_empty());
    let (s, _) = scoped.call(reqwest::Method::GET, &format!("/security/detections/{}", det["id"].as_str().unwrap()), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let res = scoped.http.put(format!("{}/security/reputation/lists/x", scoped.base)).body(format!("{known_h}\n")).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "only unrestricted admins upload lists");

    // The server's set: the list, and the newest database still standing (e2e-db.2 was rolled
    // back, so its hash is gone again).
    eventually(60, "database hashes in the reputation set", || async {
        let r = admin.get("/security/reputation").await;
        let src: Vec<(String, i64)> = r["sources"].as_array().unwrap().iter().map(|s| (s["source"].as_str().unwrap().to_string(), s["hashes"].as_i64().unwrap())).collect();
        (src == [("db:e2e-db.1".to_string(), 1), ("list:e2e-list".into(), 2)]).then_some(())
    })
    .await;

    // A database older than the policy allows: the agent is at risk and alerts; no limit, neither.
    let (s, _) = put(policy(json!({ "database_max_age_hours": 9000 }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, v) = put(policy(json!({ "database_max_age_hours": 72 }))).await;
    assert!(s.is_success() && v["database_max_age_hours"] == 72, "{v}");
    let (s, v) = admin.call(reqwest::Method::POST, "/security/databases", None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "an empty upload: {v}");
    let res = admin.http.post(format!("{}/security/databases", admin.base)).body(e2e_database_built("e2e-db.3", "RMM-E2E-YARA-MARKER-3", b"old", 100)).send().await.unwrap();
    assert!(res.status().is_success(), "{:?}", res.text().await);
    let db3 = res.json::<Value>().await.unwrap()["id"].as_str().unwrap().to_string();
    eventually(60, "the old database on the agent", || async {
        (admin.get(&format!("/agents/{id1}/security")).await["sensor"]["database_version"] == "e2e-db.3").then_some(())
    })
    .await;
    eventually(60, "at risk for the database's age", || async {
        let s = admin.get(&format!("/agents/{id1}/security")).await;
        s["risks"].as_array().unwrap().iter().any(|r| r == "database").then_some(())
    })
    .await;
    let a = eventually(60, "the database alert", || engine_alert("Signature database out of date")).await;
    assert_eq!(a["details"]["max_age_hours"], 72, "{a}");
    let (s, _) = put(policy(json!({ "database_max_age_hours": 0 }))).await;
    assert!(s.is_success());
    let s = admin.get(&format!("/agents/{id1}/security")).await;
    assert!(!s["risks"].as_array().unwrap().iter().any(|r| r == "database"), "0: no limit: {s}");
    eventually(90, "the database alert to clear", || async { engine_alert("Signature database out of date").await.is_none().then_some(()) }).await;
    let (s, _) = put(policy(json!({ "database_max_age_hours": 72 }))).await;
    assert!(s.is_success());
    admin.post(&format!("/security/databases/{db3}/rollback"), json!({ "reason": "e2e: too old" })).await;
    eventually(30, "back on the first database", || async {
        (admin.get(&format!("/agents/{id1}/security")).await["sensor"]["database_version"] == "e2e-db.1").then_some(())
    })
    .await;
    let s = admin.delete_policy(&engine_pol).await;
    assert!(s.is_success());
    std::fs::remove_dir_all(&d).unwrap();
    println!("real-time policy and reputation: ok");
}

/// The fake antivirus state the agent reads (`RMM_SECURITY_FAKE`).
fn write_security(dir: &Path, state: &Value) {
    std::fs::write(dir.join("a1-security.json"), serde_json::to_vec_pretty(state).unwrap()).unwrap();
}

async fn security(admin: &Api, dir: &Path, id1: &str, id3: &str) {
    let hours_ago = |h: i64| (chrono::Utc::now() - chrono::Duration::hours(h)).to_rfc3339();
    let defender = |enabled: bool, sig_hours: i64| {
        json!({
            "kind": "defender", "name": "Microsoft Defender Antivirus", "version": "4.18.24090.11", "enabled": enabled, "realtime": enabled,
            "signature_version": "1.421.0.0", "signatures_updated_at": hours_ago(sig_hours), "tamper_protection": true,
            "actions": ["quick_scan", "full_scan", "update_signatures"]
        })
    };
    let detection = |id: &str, status: &str, hours: i64| {
        json!({ "id": id, "product": "defender", "name": format!("Virus:DOS/EICAR {id}"), "severity": "severe", "status": status,
                "resources": [format!("file:_C:\\Users\\bob\\{id}.com")], "detected_at": hours_ago(hours) })
    };
    let fetch = || async { admin.get(&format!("/agents/{id1}/security")).await };
    let refresh = || async { admin.post(&format!("/agents/{id1}/security/refresh"), json!({})).await };
    let wait_state = |want: &'static str| async move {
        eventually(20, &format!("protection state {want}"), || async {
            let s = admin.get(&format!("/agents/{id1}/security")).await;
            (s["state"] == want).then_some(s)
        })
        .await
    };
    let security_alerts = || async { alerts_for(admin, &format!("agent_id={id1}&kind=security")).await };

    // --- status: reported on connect, refreshed on request ------------------------------------
    let s = fetch().await;
    assert_eq!(s["supported"], true, "{s}");
    write_security(dir, &json!({ "products": [defender(true, 1)], "detections": [detection("old", "quarantined", 48)] }));
    refresh().await;
    let s = wait_state("protected").await;
    assert_eq!(s["products"][0]["kind"], "defender");
    assert_eq!(s["products"][0]["tamper_protection"], true);
    assert_eq!(s["detections"].as_array().unwrap().len(), 1);
    assert!(!s["detections"][0]["resolved_at"].is_null(), "a quarantined detection isn't open");
    let fleet = admin.get("/security/agents?state=protected").await;
    assert!(fleet["items"].as_array().unwrap().iter().any(|a| a["id"] == id1), "{fleet}");
    let never = admin.get("/security/agents?state=unknown").await;
    assert!(never["items"].as_array().unwrap().iter().any(|a| a["id"] == id3), "an agent that never reported is unknown");
    for sort in ["state", "hostname", "client", "signatures", "last_scan", "threats"] {
        admin.get(&format!("/security/agents?sort={sort}&dir=desc&limit=1")).await;
    }

    // --- a policy on every condition, alerting on every new detection ---------------------------
    let pol = admin
        .alert_policy(json!({ "name": "Protection", "kind": "security", "severity": "critical",
                    "params": { "unprotected": true, "realtime_off": true, "signature_max_age_hours": 24, "threats": "any" } }),
        )
        .await;
    let pol_id = pol["id"].as_str().unwrap().to_string();
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(security_alerts().await.is_empty(), "old history doesn't alert");

    // An active threat appears.
    write_security(dir, &json!({ "products": [defender(true, 1)], "detections": [detection("old", "quarantined", 48), detection("live", "active", 0)] }));
    refresh().await;
    wait_state("threats").await;
    let a = eventually(20, "threat alert", || async { security_alerts().await.into_iter().find(|a| a["title"] == "Threat detected: Virus:DOS/EICAR live") }).await;
    assert_eq!((a["severity"].as_str(), a["details"]["status"].as_str()), (Some("critical"), Some("active")), "{a}");
    let sum = admin.get("/security/summary").await;
    assert_eq!(sum["active_threats"], 1, "{sum}");
    assert_eq!(sum["agents"]["threats"], 1);
    let active = admin.get("/security/detections").await;
    assert_eq!(active["total"], 1, "{active}");
    assert_eq!(admin.get("/security/detections?view=all&q=old").await["total"], 1, "search by name");
    assert_eq!(admin.get(&format!("/agents/{id1}")).await["health"], "unhealthy", "a critical alert makes the agent unhealthy");

    // --- a quick scan finds (and quarantines) something --------------------------------------------
    let mut state = json!({ "products": [defender(true, 1)], "detections": [detection("old", "quarantined", 48), detection("live", "active", 0)],
                            "scan_finds": [detection("scanned", "quarantined", 0)] });
    write_security(dir, &state);
    let (s, v) = admin.call(reqwest::Method::POST, &format!("/agents/{id1}/security/actions"), Some(json!({ "action": "reboot" }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let started = admin.post(&format!("/agents/{id1}/security/actions"), json!({ "action": "quick_scan" })).await;
    assert_eq!(started["product"], "defender");
    let action_id = started["id"].as_str().unwrap().to_string();
    let done = eventually(20, "quick scan to finish", || async {
        let s = admin.get(&format!("/agents/{id1}/security")).await;
        let a = s["actions"].as_array().unwrap().iter().find(|a| a["id"] == action_id.as_str()).cloned()?;
        (a["status"] == "succeeded").then_some((s, a))
    })
    .await;
    assert_eq!(done.1["message"], "Found 1 threats", "{}", done.1);
    eventually(20, "scan time reported", || async { (!fetch().await["products"][0]["last_quick_scan_at"].is_null()).then_some(()) }).await;
    eventually(20, "quarantined-on-scan alert (threats: any)", || async {
        security_alerts().await.into_iter().find(|a| a["title"] == "Threat quarantined: Virus:DOS/EICAR scanned")
    })
    .await;

    // One action at a time per agent.
    state["scan_ms"] = json!(3000);
    write_security(dir, &state);
    admin.post(&format!("/agents/{id1}/security/actions"), json!({ "action": "full_scan" })).await;
    let (s, v) = admin.call(reqwest::Method::POST, &format!("/agents/{id1}/security/actions"), Some(json!({ "action": "quick_scan" }))).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    let bulk = admin.post("/security/actions", json!({ "agent_ids": [id1, id3], "action": "update_signatures" })).await;
    assert_eq!(bulk["started"], 0, "{bulk}");
    assert_eq!(bulk["skipped"].as_array().unwrap().len(), 2, "busy and offline: {bulk}");
    eventually(20, "full scan to finish", || async {
        let s = fetch().await;
        s["actions"].as_array().unwrap().iter().all(|a| a["status"] != "sent" && a["status"] != "running").then_some(())
    })
    .await;

    // --- the threat is dealt with; switching to "active" clears what isn't active ---------------
    state["scan_ms"] = json!(0);
    state["detections"] = json!([detection("live", "quarantined", 0), detection("scanned", "quarantined", 0)]);
    write_security(dir, &state);
    refresh().await;
    wait_state("protected").await;
    assert_eq!(security_alerts().await.len(), 2, "under \"any\", threat alerts wait for a person");
    let all = admin.get(&format!("/security/detections?view=all&agent_id={id1}")).await;
    let old = all["items"].as_array().unwrap().iter().find(|d| d["name"] == "Virus:DOS/EICAR old").unwrap().clone();
    assert!(!old["resolved_at"].is_null(), "a detection the product stopped listing is resolved");
    let mut body = pol["item_config"].clone();
    body["name"] = pol["name"].clone();
    body["params"]["threats"] = json!("active");
    let (s, v) = admin.update_alert_policy(&pol_id, body.clone()).await;
    assert!(s.is_success(), "{v}");
    eventually(20, "threat alerts to clear", || async { security_alerts().await.is_empty().then_some(()) }).await;

    // --- stale signatures, fixed by a signature update ---------------------------------------------
    state["products"] = json!([defender(true, 100)]);
    write_security(dir, &state);
    refresh().await;
    let a = eventually(20, "stale signature alert", || async {
        security_alerts().await.into_iter().find(|a| a["title"] == "Antivirus signatures out of date")
    })
    .await;
    assert_eq!(a["details"]["max_age_hours"], 24, "{a}");
    wait_state("at_risk").await;
    admin.post(&format!("/agents/{id1}/security/actions"), json!({ "action": "update_signatures", "product": "defender" })).await;
    eventually(20, "signature alert to clear after the update", || async { security_alerts().await.is_empty().then_some(()) }).await;
    wait_state("protected").await;

    // --- protection switched off, then on -----------------------------------------------------------
    state["products"] = json!([defender(false, 1)]);
    write_security(dir, &state);
    refresh().await;
    eventually(20, "unprotected alert", || async { security_alerts().await.into_iter().find(|a| a["title"] == "No active antivirus") }).await;
    wait_state("unprotected").await;
    let (s, _) = admin.call(reqwest::Method::POST, &format!("/agents/{id1}/security/actions"), Some(json!({ "action": "quick_scan", "product": "clamav" }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "no such product here");
    state["products"] = json!([defender(true, 1)]);
    write_security(dir, &state);
    refresh().await;
    eventually(20, "unprotected alert to clear", || async { security_alerts().await.is_empty().then_some(()) }).await;

    // --- a failed read keeps the last known state ------------------------------------------------------
    std::fs::write(dir.join("a1-security.json"), b"{ not json").unwrap();
    refresh().await;
    let s = eventually(20, "the read error to show", || async {
        let s = fetch().await;
        s["error"].as_str().is_some_and(|e| e.contains("parsing")).then_some(s)
    })
    .await;
    assert_eq!((s["state"].as_str(), s["products"].as_array().unwrap().len()), (Some("protected"), 1), "{s}");
    assert!(security_alerts().await.is_empty(), "no \"no antivirus\" alert from a failed read");
    write_security(dir, &state);
    refresh().await;
    eventually(20, "the error to clear", || async { fetch().await["error"].is_null().then_some(()) }).await;

    // --- audit: actions and their results --------------------------------------------------------------
    let activity = admin.get(&format!("/agents/{id1}/activity")).await;
    let actions: Vec<&str> = activity.as_array().unwrap().iter().filter_map(|r| r["action"].as_str()).collect();
    assert!(actions.contains(&"security.quick_scan") && actions.contains(&"security.succeeded"), "{actions:?}");

    let s = admin.delete_policy(&pol_id).await;
    assert!(s.is_success());
    println!("security: ok");
}

async fn alerts_for(api: &Api, query: &str) -> Vec<Value> {
    api.get(&format!("/alerts?{query}")).await["items"].as_array().unwrap().clone()
}

type DesktopWs = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// A decoded `/desktop` binary frame: (seq, screen w/h, picture w/h, rects as (x, y, w, h, jpeg)).
type DesktopFrame = (u32, (u16, u16), (u16, u16), Vec<(u16, u16, u16, u16, Vec<u8>)>);

fn parse_desktop_frame(b: &[u8]) -> DesktopFrame {
    let u16_at = |i: usize| u16::from_be_bytes([b[i], b[i + 1]]);
    let u32_at = |i: usize| u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
    assert_eq!(b[0], 1, "frame kind");
    let n = u16_at(21) as usize;
    let mut rects = Vec::new();
    let mut p = 23;
    for _ in 0..n {
        assert_eq!(b[p + 8], 1, "JPEG codec");
        let len = u32_at(p + 9) as usize;
        rects.push((u16_at(p), u16_at(p + 2), u16_at(p + 4), u16_at(p + 6), b[p + 13..p + 13 + len].to_vec()));
        p += 13 + len;
    }
    assert_eq!(p, b.len(), "frame length");
    (u32_at(1), (u16_at(5), u16_at(7)), (u16_at(9), u16_at(11)), rects)
}

enum DesktopMsg {
    Text(Value),
    Frame(DesktopFrame),
}

/// Next message within `secs`, or `None` (timeout or socket closed).
async fn desktop_next(ws: &mut DesktopWs, secs: u64) -> Option<DesktopMsg> {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::Message;
    loop {
        match tokio::time::timeout(Duration::from_secs(secs), ws.next()).await.ok()?? {
            Ok(Message::Text(t)) => return Some(DesktopMsg::Text(serde_json::from_str(&t).unwrap())),
            Ok(Message::Binary(b)) => return Some(DesktopMsg::Frame(parse_desktop_frame(&b))),
            Ok(Message::Close(_)) | Err(_) => return None,
            Ok(_) => continue,
        }
    }
}

async fn desktop_send(ws: &mut DesktopWs, v: Value) {
    use futures_util::SinkExt;
    ws.send(tokio_tungstenite::tungstenite::Message::Text(v.to_string().into())).await.unwrap();
}

async fn desktop_frame(ws: &mut DesktopWs) -> DesktopFrame {
    match desktop_next(ws, 15).await {
        Some(DesktopMsg::Frame(f)) => f,
        Some(DesktopMsg::Text(v)) => panic!("expected a frame, got {v}"),
        None => panic!("expected a frame, got nothing"),
    }
}

async fn desktop_text(ws: &mut DesktopWs) -> Value {
    loop {
        match desktop_next(ws, 15).await {
            Some(DesktopMsg::Text(v)) => return v,
            // Frames still in flight from before a settings change.
            Some(DesktopMsg::Frame(_)) => continue,
            None => panic!("expected a control message, got nothing"),
        }
    }
}

/// Phase 6: remote desktop through the server, with the agent's synthetic screen.
async fn desktop(url: &str, admin: &Api, dir: &Path, id1: &str) {
    let a = admin.get(&format!("/agents/{id1}")).await;
    assert!(a["capabilities"].as_array().unwrap().iter().any(|c| c == "desktop"), "{a}");

    admin
        .post(
            "/users",
            json!({ "email": "desk@e2e.test", "name": "Desk Tech", "password": "desk-password-123", "role": "technician", "all_clients": true }),
        )
        .await;
    let res = reqwest::Client::new()
        .post(format!("{url}/api/auth/login"))
        .json(&json!({ "email": "desk@e2e.test", "password": "desk-password-123" }))
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success());
    let cookie = res.headers()["set-cookie"].to_str().unwrap().split(';').next().unwrap().to_string();
    let ws_url = format!("{}/api/agents/{id1}/desktop?quality=high", url.replacen("http", "ws", 1));
    let connect = |q: &str| {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let mut req = ws_url.replace("quality=high", q).into_client_request().unwrap();
        req.headers_mut().insert("cookie", cookie.parse().unwrap());
        tokio_tungstenite::connect_async(req)
    };

    // Unauthenticated sockets are refused.
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    assert!(tokio_tungstenite::connect_async(ws_url.clone().into_client_request().unwrap()).await.is_err());

    let (mut ws, _) = connect("quality=high").await.expect("desktop socket");
    let info = desktop_text(&mut ws).await;
    assert_eq!(info["type"], "info", "{info}");
    assert_eq!(info["monitors"].as_array().unwrap().len(), 2);
    assert_eq!(info["monitor"], 0);

    // The first frame covers the whole 640x360 screen in 64-row bands.
    let (seq, screen, size, rects) = desktop_frame(&mut ws).await;
    assert_eq!((seq, screen, size), (1, (640, 360), (640, 360)));
    assert_eq!(rects.iter().map(|r| r.1).collect::<Vec<_>>(), [0, 64, 128, 192, 256, 320]);
    assert!(rects.iter().all(|r| r.4.starts_with(&[0xff, 0xd8]) && r.2 == 640));
    // Then only what changed (the moving block in the top band).
    let (seq, _, _, rects) = desktop_frame(&mut ws).await;
    assert_eq!(seq, 2);
    assert!(!rects.is_empty() && rects.iter().all(|r| r.1 == 0), "{:?}", rects.iter().map(|r| (r.0, r.1, r.2, r.3)).collect::<Vec<_>>());
    // Two unacknowledged frames: the agent waits.
    assert!(desktop_next(&mut ws, 2).await.is_none(), "no third frame before an ack");
    desktop_send(&mut ws, json!({ "type": "ack", "seq": 2 })).await;
    assert_eq!(desktop_frame(&mut ws).await.0, 3);

    // Input reaches the machine; invalid events are dropped by the server.
    desktop_send(
        &mut ws,
        json!({ "type": "input", "events": [
            { "t": "move", "x": 10, "y": 20 },
            { "t": "button", "button": "left", "down": true, "x": 10, "y": 20 },
            { "t": "key", "code": "Key A", "down": true },
            { "t": "key", "code": "KeyA", "down": true },
            { "t": "text", "text": "héllo" },
            { "t": "ctrl_alt_del" }
        ] }),
    )
    .await;
    let log = dir.join(format!("{}-desktop.jsonl", "a1"));
    let lines = eventually(10, "desktop input logged", || async {
        let raw = std::fs::read_to_string(&log).unwrap_or_default();
        (raw.lines().count() >= 5).then_some(raw)
    })
    .await;
    let events: Vec<Value> = lines.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(events[0], json!({ "t": "move", "x": 10, "y": 20 }));
    assert_eq!(events[2], json!({ "t": "key", "code": "KeyA", "down": true }));
    assert_eq!(events[3], json!({ "t": "text", "text": "héllo" }));
    assert_eq!(events.len(), 5, "{events:?}");

    // Switching monitor and quality: fresh info, then a full half-size frame of monitor 2.
    desktop_send(&mut ws, json!({ "type": "settings", "monitor": 1, "quality": "low" })).await;
    desktop_send(&mut ws, json!({ "type": "ack", "seq": 3 })).await;
    let info = desktop_text(&mut ws).await;
    assert_eq!((info["type"].as_str(), info["monitor"].as_u64()), (Some("info"), Some(1)), "{info}");
    let (seq, screen, size, rects) = loop {
        let f = desktop_frame(&mut ws).await;
        desktop_send(&mut ws, json!({ "type": "ack", "seq": f.0 })).await;
        if f.1 == (320, 240) {
            break f;
        }
    };
    assert!(seq > 3);
    assert_eq!((screen, size), ((320, 240), (160, 120)));
    assert_eq!(rects.iter().map(|r| (r.0, r.1, r.2, r.3)).collect::<Vec<_>>(), [(0, 0, 160, 64), (0, 64, 160, 56)]);
    drop(ws);

    let audit = eventually(10, "desktop audit entries", || async {
        let a = admin.get("/audit?action=desktop.").await;
        let actions: Vec<String> = a["items"].as_array().unwrap().iter().map(|r| r["action"].as_str().unwrap().to_string()).collect();
        actions.contains(&"desktop.close".to_string()).then_some(actions)
    })
    .await;
    assert!(audit.contains(&"desktop.open".to_string()), "{audit:?}");

    // Consent: the user declines, then allows.
    // Consent is the remote access policy's (here All devices').
    let (s, v) = admin.set_root_item(REMOTE_ITEM, json!({ "desktop_consent": true })).await;
    assert!(s.is_success(), "{v}");
    let mine = admin.get(&format!("/agents/{id1}/policy")).await;
    let remote = mine["policies"].as_array().unwrap().iter().find(|p| p["module"] == "remote_access").unwrap().clone();
    assert_eq!(remote["config"]["desktop_consent"], true, "{remote}");
    let mut answer = log.clone().into_os_string();
    answer.push(".consent");
    std::fs::write(&answer, "deny").unwrap();
    let (mut ws, _) = connect("quality=balanced").await.unwrap();
    assert_eq!(desktop_text(&mut ws).await["type"], "waiting");
    let closed = desktop_text(&mut ws).await;
    assert_eq!((closed["type"].as_str(), closed["reason"].as_str()), (Some("closed"), Some("the user declined the session")), "{closed}");
    std::fs::remove_file(&answer).unwrap();
    let (mut ws, _) = connect("quality=balanced").await.unwrap();
    assert_eq!(desktop_text(&mut ws).await["type"], "waiting");
    assert_eq!(desktop_text(&mut ws).await["type"], "info");
    assert_eq!(desktop_frame(&mut ws).await.0, 1);
    drop(ws);
    admin.set_root_item(REMOTE_ITEM, json!({ "desktop_consent": false })).await;
}

/// Phase 4: notification channels, alert policies, services, log watchers, schedules,
/// retention and metric rollups.
async fn monitoring(server: &mut Server, admin: &Api, db: &sqlx::PgPool, dir: &Path, id1: &str, id3: &str, a_id: &str) {
    let (hook_url, hooks) = webhook_receiver().await;

    // --- channels: a signed webhook, with a test send ---------------------------------------
    let ch = admin
        .post("/notification-channels", json!({ "name": "e2e hook", "kind": "webhook", "config": { "url": hook_url, "secret": "hook-secret" } }))
        .await;
    assert_eq!((ch["has_secret"].as_bool(), ch["config"].get("secret")), (Some(true), None), "the secret is never sent back: {ch}");
    let ch_id = ch["id"].as_str().unwrap().to_string();
    let t = admin.post(&format!("/notification-channels/{ch_id}/test"), json!({})).await;
    assert_eq!(t["ok"], true, "{t}");
    wait_hook(&hooks, "test webhook", |ev, _| ev == "test").await;
    let (s, _) = admin
        .call(reqwest::Method::POST, "/notification-channels", Some(json!({ "name": "bad", "kind": "email", "config": { "to": ["nope"] } })))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // --- failed job: opens on failure, clears on the next success ----------------------------
    let policy = |name: &str, kind: &str, params: Value| {
        json!({ "name": name, "kind": kind, "params": params, "severity": "warning", "client_id": a_id, "channel_ids": [ch_id] })
    };
    let (s, v) = admin.alert_policy_call(policy("bad", "cpu", json!({ "threshold": 500, "minutes": 5 }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let jf = admin.alert_policy(policy("Jobs fail", "job_failed", json!({}))).await;
    let failing = admin.run_script(id1, "exit 4", 30).await;
    admin.wait_job(&failing, 30).await;
    let opened = wait_hook(&hooks, "job alert opened", |ev, b| ev == "opened" && b["alert"]["kind"] == "job_failed").await;
    assert_eq!(opened["agent"]["id"], id1);
    assert_eq!(opened["alert"]["details"]["exit_code"], 4, "{opened}");
    let alert_id = opened["alert"]["id"].as_str().unwrap().to_string();
    let again = admin.run_script(id1, "exit 5", 30).await;
    admin.wait_job(&again, 30).await;
    let (api, aid) = (admin, alert_id.as_str());
    eventually(10, "a second failure counts on the open alert", move || async move {
        (api.get(&format!("/alerts/{aid}")).await["occurrences"] == 2).then_some(())
    })
    .await;
    assert!(matches!(admin.get(&format!("/agents/{id1}")).await["health"].as_str(), Some("attention" | "unhealthy")));
    let ok = admin.run_script(id1, "true", 30).await;
    admin.wait_job(&ok, 30).await;
    wait_hook(&hooks, "job alert resolved", |ev, b| ev == "resolved" && b["alert"]["id"] == alert_id.as_str()).await;
    let detail = admin.get(&format!("/alerts/{alert_id}")).await;
    assert_eq!((detail["state"].as_str(), detail["resolution"].as_str()), (Some("resolved"), Some("cleared")), "{detail}");
    assert!(detail["notifications"].as_array().unwrap().iter().all(|n| n["status"] == "sent"), "{detail}");

    // --- memory held over a threshold, and an offline agent ------------------------------------
    let mem = admin.alert_policy(policy("Memory", "memory", json!({ "threshold": 1, "minutes": 1 }))).await;
    let off = admin.alert_policy(json!({ "name": "Offline", "kind": "offline", "params": { "minutes": 1 }, "severity": "critical", "client_id": a_id })).await;
    let mem_id = mem["id"].as_str().unwrap().to_string();
    let (api, m) = (admin, mem_id.as_str());
    let mem_alert = eventually(120, "memory alert", move || async move {
        alerts_for(api, &format!("policy_id={m}")).await.into_iter().next()
    })
    .await;
    assert_eq!(mem_alert["agent_id"], id1);
    assert!(mem_alert["title"].as_str().unwrap().starts_with("Memory at or above 1"), "{mem_alert}");
    let off_id = off["id"].as_str().unwrap().to_string();
    let (api, o) = (admin, off_id.as_str());
    let off_alert = eventually(120, "offline alert", move || async move {
        alerts_for(api, &format!("policy_id={o}")).await.into_iter().next()
    })
    .await;
    assert_eq!(off_alert["agent_id"], id3);
    assert_eq!(admin.get(&format!("/agents/{id3}")).await["health"], "unhealthy", "an open critical alert");
    let dash = admin.get("/dashboard").await;
    assert!(dash["alerts"]["critical"].as_i64() >= Some(1) && dash["open_alerts"][0]["severity"] == "critical", "{dash}");
    // Raising the threshold out of reach clears the memory alert at the next check.
    let mut edit = policy("Memory", "memory", json!({ "threshold": 100, "minutes": 1 }));
    edit["notify_resolved"] = json!(false);
    let (s, v) = admin.update_alert_policy(&mem_id, edit).await;
    assert!(s.is_success(), "{v}");
    let (api, aid) = (admin, mem_alert["id"].as_str().unwrap().to_string());
    eventually(30, "memory alert to clear", || async { (api.get(&format!("/alerts/{aid}")).await["state"] == "resolved").then_some(()) }).await;
    // Acknowledge, then resolve by hand.
    let off_alert_id = off_alert["id"].as_str().unwrap();
    let a = admin.post(&format!("/alerts/{off_alert_id}/acknowledge"), json!({})).await;
    assert_eq!(a["state"], "acknowledged");
    assert_eq!(alerts_for(admin, "state=acknowledged").await.len(), 1);
    admin.post("/alerts/bulk", json!({ "ids": [off_alert_id], "action": "resolve" })).await;
    assert_eq!(admin.get(&format!("/alerts/{off_alert_id}")).await["resolution"], "manual");
    let s = admin.delete_policy(&off_id).await;
    assert!(s.is_success());

    // --- services (systemd hosts only) ---------------------------------------------------------
    let (api, id) = (admin, id1);
    let services = eventually(30, "the agent's service list", move || async move {
        let v = api.get(&format!("/agents/{id}/services")).await;
        (!v["services"].is_null()).then_some(v)
    })
    .await;
    let list = services["services"].as_array().unwrap();
    if list.is_empty() {
        println!("no systemd here; skipping service alerts");
    } else {
        println!("agent reported {} services", list.len());
        let r = admin
            .post(&format!("/agents/{id1}/services/control"), json!({ "name": "no-such-unit-e2e.service", "action": "restart" }))
            .await;
        assert_eq!(r["ok"], false, "{r}");
        assert!(r["message"].as_str().unwrap().contains("no service named"), "{r}");
        if let Some(stopped) = list.iter().find(|s| s["state"] == "stopped") {
            let name = stopped["name"].as_str().unwrap();
            let sp = admin.alert_policy(policy("Service down", "service", json!({ "services": [name] }))).await;
            let sp_id = sp["id"].as_str().unwrap().to_string();
            let (api, p) = (admin, sp_id.as_str());
            let a = eventually(20, "service alert", move || async move {
                alerts_for(api, &format!("policy_id={p}")).await.into_iter().next()
            })
            .await;
            assert_eq!(a["details"]["service"], name);
            let alerting = admin.get(&format!("/agents/{id1}/services")).await["alerting"].clone();
            assert_eq!(alerting, json!([name]));
            admin.delete_policy(&sp_id).await;
            let a = admin.get(&format!("/alerts/{}", a["id"].as_str().unwrap())).await;
            assert_eq!(a["resolution"], "policy", "deleting a policy closes its alerts quietly");
        }
    }

    // --- log watcher (needs a journal this user can read) ------------------------------------------
    let marker = format!("rmm-e2e-{}", uuid::Uuid::new_v4().simple());
    let lp = admin.alert_policy(policy("Marker", "log", json!({ "min_level": "error", "pattern": marker }))).await;
    tokio::time::sleep(Duration::from_secs(2)).await; // the watcher set reaches the agent
    let lj = admin.run_script(id1, &format!("logger -p user.err '{marker}' || true"), 30).await;
    admin.wait_job(&lj, 30).await;
    let lp_id = lp["id"].as_str().unwrap().to_string();
    let mut found = None;
    for _ in 0..40 {
        if let Some(a) = alerts_for(admin, &format!("policy_id={lp_id}")).await.into_iter().next() {
            found = Some(a);
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    match found {
        Some(a) => {
            assert!(a["details"]["message"].as_str().unwrap().contains(&marker), "{a}");
            // The entries are stored just after the alert opens, so give them a moment.
            let mut logs = json!([]);
            for _ in 0..20 {
                logs = admin.get(&format!("/agents/{id1}/log-events")).await;
                if logs[0]["message"].is_string() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            assert!(logs[0]["message"].as_str().is_some_and(|m| m.contains(&marker)), "{logs}");
            println!("log watcher matched");
        }
        None => println!("no log match (journal not readable by this user?); skipping the log watcher check"),
    }
    admin.delete_policy(&lp_id).await;
    admin.delete_policy(jf["id"].as_str().unwrap()).await;

    // --- schedules -------------------------------------------------------------------------------
    let script = admin.post("/scripts", json!({ "name": "scheduled", "interpreter": "bash", "body": "echo scheduled \"$1\"" })).await;
    let preview = admin.get("/schedules/preview?cron=0%203%20*%20*%201&timezone=Europe/Berlin").await;
    assert_eq!(preview["runs"].as_array().unwrap().len(), 5, "{preview}");
    // A scheduled script is a `schedule` item, here in All devices limited to client A.
    let (s, v) = admin
        .call(
            reqwest::Method::POST,
            &format!("/policy-sets/{ROOT_SET}/items"),
            Some(json!({ "module": "schedule", "name": "bad", "client_id": a_id, "config": { "script_id": script["id"], "cron": "every day" } })),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let sched = admin
        .post(
            &format!("/policy-sets/{ROOT_SET}/items"),
            json!({ "module": "schedule", "name": "Nightly", "client_id": a_id,
                    "config": { "script_id": script["id"], "cron": "0 3 * * *", "timezone": "America/Chicago", "args": ["x1"], "retain_days": 1 } }),
        )
        .await;
    assert!(sched["schedule"]["next_run_at"].is_string(), "{sched}");
    let sid = sched["id"].as_str().unwrap().to_string();
    let r = admin.post(&format!("/schedules/{sid}/run"), json!({})).await;
    assert_eq!((r["sent"].as_i64(), r["queued"].as_i64()), (Some(1), Some(1)), "online agent gets it, offline one queues: {r}");
    let runs = admin.get(&format!("/jobs?schedule_id={sid}")).await;
    let run_id = runs["items"].as_array().unwrap().iter().find(|j| j["agent_id"] == id1).unwrap()["id"].as_str().unwrap().to_string();
    let j = admin.wait_job(&run_id, 30).await;
    assert_eq!((j["stdout"].as_str(), j["schedule_name"].as_str()), (Some("scheduled x1\n"), Some("Nightly")), "{j}");
    let r = admin.post(&format!("/schedules/{sid}/run"), json!({})).await;
    assert_eq!((r["sent"].as_i64(), r["skipped"].as_i64()), (Some(1), Some(1)), "the offline agent's run is still queued: {r}");
    let listed = admin.get("/schedules").await;
    assert_eq!(listed[0]["name"], "Nightly");
    // A due schedule runs on its own and moves to its next time.
    sqlx::query("UPDATE policy_schedule_state SET next_run_at = now() - interval '1 minute' WHERE item_id = $1::uuid").bind(&sid).execute(db).await.unwrap();
    let (api, s) = (admin, sid.as_str());
    eventually(40, "the scheduler to run a due schedule", move || async move {
        let v = api.get(&format!("/schedules/{s}")).await;
        (v["next_run_at"].as_str().is_some_and(|t| t > v["last_run_at"].as_str().unwrap_or(""))
            && api.get(&format!("/jobs?schedule_id={s}&agent_id={}", id1)).await["total"].as_i64() >= Some(3))
        .then_some(())
    })
    .await;

    // --- retention and rollups run at startup -------------------------------------------------------
    sqlx::query("UPDATE jobs SET finished_at = now() - interval '2 days' WHERE id = $1::uuid").bind(&run_id).execute(db).await.unwrap();
    // Checked by its hour: the agent's real samples are rolled up too, and on a busy CI runner
    // another hour can also peak above 42%.
    let hour: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
        "INSERT INTO agent_metrics (agent_id, ts, cpu_percent, mem_used, mem_total, disk_max_pct, net_rx_bytes, net_tx_bytes)
         VALUES ($1::uuid, date_trunc('hour', now()) - interval '90 minutes', 42, 1, 2, 3, 4, 5)
         RETURNING date_trunc('hour', ts)",
    )
    .bind(id1)
    .fetch_one(db)
    .await
    .unwrap();
    server.restart().await;
    admin.wait_online(id1, true).await;
    let (s, _) = admin.call(reqwest::Method::GET, &format!("/jobs/{run_id}"), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "scheduled output past its retention is deleted");
    let hourly: i64 =
        sqlx::query_scalar("SELECT count(*) FROM agent_metrics_hourly WHERE agent_id = $1::uuid AND hour = $2 AND cpu_max >= 42")
            .bind(id1)
            .bind(hour)
            .fetch_one(db)
            .await
            .unwrap();
    assert_eq!(hourly, 1, "the sample was rolled up");
    let week = admin.get(&format!("/agents/{id1}/metrics?hours=168")).await;
    assert!(!week.as_array().unwrap().is_empty(), "long ranges read the rollups");
    let _ = (dir, id3);
}

/// Messages received by [`smtp_sink`]: (envelope recipients, raw DATA).
type Mail = std::sync::Arc<std::sync::Mutex<Vec<(Vec<String>, String)>>>;

/// A minimal SMTP server that accepts everything (no TLS, no auth).
async fn smtp_sink() -> (u16, Mail) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let mail: Mail = Default::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let store = mail.clone();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else { return };
            let store = store.clone();
            tokio::spawn(async move {
                let (r, mut w) = sock.into_split();
                let mut lines = BufReader::new(r).lines();
                let _ = w.write_all(b"220 sink ESMTP\r\n").await;
                let mut rcpt = vec![];
                while let Ok(Some(line)) = lines.next_line().await {
                    let upper = line.to_ascii_uppercase();
                    let reply: &[u8] = if upper.starts_with("EHLO") || upper.starts_with("HELO") {
                        b"250 sink\r\n"
                    } else if upper.starts_with("RCPT TO:") {
                        rcpt.push(line[8..].trim().trim_matches(['<', '>']).to_string());
                        b"250 ok\r\n"
                    } else if upper.starts_with("DATA") {
                        let _ = w.write_all(b"354 go\r\n").await;
                        let mut data = String::new();
                        while let Ok(Some(l)) = lines.next_line().await {
                            if l == "." {
                                break;
                            }
                            data.push_str(l.strip_prefix('.').filter(|_| l.starts_with("..")).unwrap_or(&l));
                            data.push_str("\r\n");
                        }
                        store.lock().unwrap().push((std::mem::take(&mut rcpt), data));
                        b"250 queued\r\n"
                    } else if upper.starts_with("QUIT") {
                        let _ = w.write_all(b"221 bye\r\n").await;
                        break;
                    } else {
                        b"250 ok\r\n"
                    };
                    if w.write_all(reply).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (port, mail)
}

async fn wait_mail(mail: &Mail, what: &str, pred: impl Fn(&[String], &str) -> bool) -> String {
    eventually(30, what, || async { mail.lock().unwrap().iter().find(|(to, data)| pred(to, data)).map(|(_, d)| d.clone()) }).await
}

fn header<'a>(raw: &'a str, name: &str) -> Option<&'a str> {
    let prefix = format!("{}:", name.to_ascii_lowercase());
    raw.lines().take_while(|l| !l.is_empty()).find(|l| l.to_ascii_lowercase().starts_with(&prefix)).map(|l| l[prefix.len()..].trim())
}

async fn inbound(http: &reqwest::Client, url: &str, raw: String) -> Value {
    let res = http.post(url).header("content-type", "message/rfc822").body(raw).send().await.unwrap();
    let status = res.status();
    let v: Value = res.json().await.unwrap_or(Value::Null);
    assert!(status.is_success(), "inbound: {status} {v}");
    v
}

fn events_of(t: &Value, kind: &str) -> Vec<Value> {
    t["events"].as_array().unwrap().iter().filter(|e| e["kind"] == kind).cloned().collect()
}

async fn tickets(url: &str, admin: &Api, id1: &str, a_id: &str, b_id: &str) {
    let http = reqwest::Client::new();
    let (smtp_port, mail) = smtp_sink().await;
    admin
        .call(
            reqwest::Method::PUT,
            "/settings/smtp",
            Some(json!({ "host": "127.0.0.1", "port": smtp_port, "security": "none", "from": "Help Desk <help@msp.example>" })),
        )
        .await;

    // --- setup: boards, a contact, the client's domain, a webhook mailbox ----------------------
    let meta = admin.get("/tickets/meta").await;
    let boards = meta["boards"].as_array().unwrap();
    let desk = boards.iter().find(|b| b["name"] == "Service Desk").unwrap().clone();
    let alerts_board = boards.iter().find(|b| b["name"] == "Alerts").unwrap()["id"].as_str().unwrap().to_string();
    let status = |cat: &str| desk["statuses"].as_array().unwrap().iter().find(|s| s["category"] == cat).unwrap()["id"].as_str().unwrap().to_string();
    let (s, v) = admin
        .call(reqwest::Method::PUT, &format!("/boards/{}", desk["id"].as_str().unwrap()), Some(json!({ "name": "Service Desk", "statuses": [{ "name": "New", "category": "new" }] })))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "a board needs resolved and closed statuses: {v}");
    let ann = admin
        .post("/contacts", json!({ "client_id": a_id, "name": "Ann Example", "email": "Ann@Client-A.example", "is_primary": true }))
        .await;
    assert_eq!(ann["email"], "ann@client-a.example");
    let (s, _) = admin.call(reqwest::Method::POST, "/contacts", Some(json!({ "client_id": a_id, "name": "Dup", "email": "ann@client-a.example" }))).await;
    assert_eq!(s, StatusCode::CONFLICT);
    admin.call(reqwest::Method::PUT, &format!("/clients/{a_id}/email-domains"), Some(json!({ "domains": ["@Client-A.example"] }))).await;
    let (s, _) = admin.call(reqwest::Method::PUT, &format!("/clients/{b_id}/email-domains"), Some(json!({ "domains": ["client-a.example"] }))).await;
    assert_eq!(s, StatusCode::CONFLICT, "a domain belongs to one client");
    let mb = admin
        .post("/mailboxes", json!({ "name": "Support", "address": "support@msp.example", "kind": "webhook", "board_id": desk["id"], "auto_reply": true }))
        .await;
    let hook = mb["webhook_url"].as_str().unwrap().to_string();
    assert!(admin.get("/mailboxes").await[0].get("webhook_url").is_none(), "the URL is shown once");

    // --- a ticket from the dashboard, linked to an agent ---------------------------------------------
    let t = admin
        .post(
            "/tickets",
            json!({ "subject": "  Printer   offline ", "description": "The office printer stopped working.", "client_id": a_id,
                    "contact_id": ann["id"], "impact": 1, "urgency": 2, "agent_ids": [id1] }),
        )
        .await;
    assert_eq!((t["subject"].as_str(), t["priority"].as_i64(), t["status_category"].as_str()), (Some("Printer offline"), Some(2), Some("new")), "{t}");
    assert!(t["number"].as_i64() >= Some(10001));
    let (tid, number) = (t["id"].as_str().unwrap().to_string(), t["number"].as_i64().unwrap());
    let (s, _) = admin.call(reqwest::Method::POST, "/tickets", Some(json!({ "subject": "x", "client_id": b_id, "agent_ids": [id1] }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "agents must belong to the ticket's client");

    // Detail: the agent's live state rides along.
    let d = admin.get(&format!("/tickets/{tid}")).await;
    assert_eq!(d["agents"][0]["id"], id1);
    assert!(d["agents"][0]["online"].is_boolean() && d["agents"][0]["alerts"].is_array(), "{}", d["agents"]);
    assert_eq!(d["reply_to"], "ann@client-a.example");

    // --- a public reply is emailed with the ticket tag; notes aren't -------------------------------
    admin.post(&format!("/tickets/{tid}/events"), json!({ "kind": "note", "body": "Checked the spooler." })).await;
    let r = admin
        .post(&format!("/tickets/{tid}/events"), json!({ "kind": "reply", "body": "Could you power-cycle it?", "status_id": status("waiting_client") }))
        .await;
    assert_eq!(r["emailed"], true);
    let sent = wait_mail(&mail, "the reply email", |to, _| to == ["ann@client-a.example"]).await;
    assert!(header(&sent, "Subject").unwrap().contains(&format!("[T-{number}]")), "{sent}");
    assert!(header(&sent, "Reply-To").unwrap().contains("support@msp.example"), "{sent}");
    let our_id = header(&sent, "Message-ID").unwrap().trim_matches(['<', '>']).to_string();
    assert!(sent.contains("power-cycle"));
    assert_eq!(mail.lock().unwrap().len(), 1, "internal notes are never emailed");
    let d = admin.get(&format!("/tickets/{tid}")).await;
    assert_eq!(d["status_category"], "waiting_client");
    assert!(d["first_response_at"].is_string());
    let (api, t2) = (admin, tid.as_str());
    eventually(20, "the reply to show as sent", move || async move {
        let d = api.get(&format!("/tickets/{t2}")).await;
        (events_of(&d, "reply")[0]["email_status"] == "sent").then_some(())
    })
    .await;

    // --- the client answers without the tag: threaded by In-Reply-To, back to work ---------------------
    let answer = format!(
        "From: Ann Example <ann@client-a.example>\r\nTo: support@msp.example\r\nSubject: Re: Printer offline\r\n\
         Message-ID: <answer-1@client-a.example>\r\nIn-Reply-To: <{our_id}>\r\nReferences: <{our_id}>\r\n\
         Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nDid that, it prints now.\r\n\r\n\
         On Mon, 9 Nov 2026, Help Desk <help@msp.example> wrote:\r\n> Could you power-cycle it?\r\n\r\n--b\r\n\
         Content-Type: text/plain; name=\"log.txt\"\r\nContent-Disposition: attachment; filename=\"log.txt\"\r\n\r\nprinter log\r\n--b--\r\n"
    );
    let v = inbound(&http, &hook, answer.clone()).await;
    assert_eq!((v["result"].as_str(), v["ticket_id"].as_str()), (Some("threaded"), Some(tid.as_str())), "{v}");
    assert_eq!(inbound(&http, &hook, answer).await["result"], "duplicate");
    let d = admin.get(&format!("/tickets/{tid}")).await;
    let msg = events_of(&d, "message");
    assert_eq!(msg[0]["body"], "Did that, it prints now.", "quoted text is stripped");
    assert_eq!((msg[0]["author_kind"].as_str(), msg[0]["author_name"].as_str()), (Some("contact"), Some("Ann Example")));
    assert_eq!(d["status_category"], "open", "a reply while waiting on the client reopens the work");
    let att = d["attachments"].as_array().unwrap().iter().find(|a| a["name"] == "log.txt").unwrap().clone();
    let res = admin.http.get(format!("{}/tickets/{tid}/attachments/{}", admin.base, att["id"].as_str().unwrap())).send().await.unwrap();
    assert_eq!(res.headers()["content-type"], "application/octet-stream", "non-images always download");
    assert!(res.headers()["content-disposition"].to_str().unwrap().starts_with("attachment"));
    assert!(res.text().await.unwrap().contains("printer log"));

    // --- new mail: a domain match, a stranger (triage), robots ------------------------------------------
    let new_mail = |from: &str, id: &str, extra: &str, body: &str| {
        format!("From: {from}\r\nTo: support@msp.example\r\nSubject: Need help with VPN\r\nMessage-ID: <{id}>\r\n{extra}\r\n{body}\r\n")
    };
    let v = inbound(&http, &hook, new_mail("Bob <bob@client-a.example>", "n1@x", "", "zebrafish VPN drops every hour")).await;
    assert_eq!(v["result"], "created");
    let bob_ticket = admin.get(&format!("/tickets/{}", v["ticket_id"].as_str().unwrap())).await;
    assert_eq!((bob_ticket["client_id"].as_str(), bob_ticket["contact_id"].as_str()), (Some(a_id), None), "filed by domain, no contact created");
    assert_eq!(bob_ticket["requester_email"], "bob@client-a.example");
    wait_mail(&mail, "the acknowledgement", |to, data| to == ["bob@client-a.example"] && header(data, "Auto-Submitted") == Some("auto-replied")).await;
    let v = inbound(&http, &hook, new_mail("stranger@nowhere.example", "n2@x", "", "who are you")).await;
    let triage_id = v["ticket_id"].as_str().unwrap().to_string();
    assert!(admin.get(&format!("/tickets/{triage_id}")).await["client_id"].is_null());
    for (extra, why) in [("Auto-Submitted: auto-replied\r\n", "auto-submitted"), ("Precedence: bulk\r\n", "bulk or list mail")] {
        let v = inbound(&http, &hook, new_mail("ooo@client-a.example", &format!("{why}@x"), extra, "I'm away")).await;
        assert_eq!((v["result"].as_str(), v["reason"].as_str()), (Some("ignored"), Some(why)));
    }
    let v = inbound(&http, &hook, new_mail("support@msp.example", "loop@x", "", "echo")).await;
    assert_eq!(v["result"], "ignored", "mail from our own mailbox is never filed");
    let (s, _) = admin.call(reqwest::Method::GET, "/mailboxes/inbound", None).await;
    assert!(s.is_success());
    let res = http.post(format!("{url}/api/inbound/email/not-a-token")).body("x").send().await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    // --- search, views, scoping ---------------------------------------------------------------------------
    let hits = admin.get("/tickets?q=zebrafish").await;
    assert_eq!(hits["items"][0]["id"], bob_ticket["id"], "event text is searchable: {hits}");
    assert_eq!(admin.get(&format!("/tickets?q=T-{number}")).await["items"][0]["id"], tid.as_str());
    assert_eq!(admin.get(&format!("/tickets?view=all&agent_id={id1}")).await["total"], 1);
    assert_eq!(admin.get("/tickets?view=triage").await["items"][0]["id"], triage_id.as_str());
    let desk_user = admin
        .post("/users", json!({ "email": "scoped-desk@e2e.test", "name": "Scoped Desk", "password": "desk-password-123", "role": "technician", "all_clients": false, "client_ids": [b_id] }))
        .await;
    let desk_api = Api::new(url);
    desk_api.post("/auth/login", json!({ "email": "scoped-desk@e2e.test", "password": "desk-password-123" })).await;
    assert_eq!(desk_api.get("/tickets?view=all").await["total"], 0, "other clients' and triage tickets are hidden");
    for path in [format!("/tickets/{tid}"), format!("/tickets/{triage_id}")] {
        let (s, _) = desk_api.call(reqwest::Method::GET, &path, None).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{path}");
    }
    let (s, _) = desk_api.call(reqwest::Method::POST, "/tickets", Some(json!({ "subject": "x" }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "scoped users can't open triage tickets");
    let (s, v) = admin.call(reqwest::Method::PATCH, &format!("/tickets/{tid}"), Some(json!({ "assignee_id": desk_user["id"] }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "the assignee must see the client: {v}");

    // --- changes are recorded; bulk; merge ---------------------------------------------------------------
    let me = admin.get("/auth/me").await["id"].as_str().unwrap().to_string();
    let p = admin.call(reqwest::Method::PATCH, &format!("/tickets/{tid}"), Some(json!({ "priority": 1, "assignee_id": me, "subject": "Printer offline (2nd floor)" }))).await;
    assert!(p.0.is_success(), "{}", p.1);
    assert_eq!(p.1["assignee_id"], me.as_str());
    let d = admin.get(&format!("/tickets/{tid}")).await;
    let fields: Vec<String> = events_of(&d, "change").iter().map(|e| e["data"]["field"].as_str().unwrap().to_string()).collect();
    for f in ["status", "subject", "priority", "assignee"] {
        assert!(events_of(&d, "change").iter().any(|e| e["data"]["field"] == f), "{f} change recorded: {fields:?}");
    }
    assert_eq!(admin.get("/tickets?view=mine").await["items"][0]["id"], tid.as_str());
    let b = admin.post("/tickets/bulk", json!({ "ids": [bob_ticket["id"]], "status_category": "open", "priority": 4 })).await;
    assert_eq!(b["changed"], 1);
    let m = admin.post(&format!("/tickets/{triage_id}/merge"), json!({ "into": bob_ticket["id"] })).await;
    assert!(m["id"] == bob_ticket["id"]);
    let merged = admin.get(&format!("/tickets/{triage_id}")).await;
    assert_eq!((merged["status_category"].as_str(), merged["merged_into"].as_str()), (Some("closed"), bob_ticket["id"].as_str()));
    let target = admin.get(&format!("/tickets/{}", bob_ticket["id"].as_str().unwrap())).await;
    assert!(events_of(&target, "message").is_empty() && events_of(&target, "created").len() == 2, "the duplicate's timeline moved over");

    // --- uploads and a reply with an attachment ------------------------------------------------------------
    let form = reqwest::multipart::Form::new().part("file", reqwest::multipart::Part::bytes(b"\x89PNG fake".to_vec()).file_name("shot.png").mime_str("image/png").unwrap());
    let up: Value = admin.http.post(format!("{}/tickets/{tid}/attachments", admin.base)).multipart(form).send().await.unwrap().json().await.unwrap();
    let up_id = up[0]["id"].as_str().unwrap().to_string();
    admin.post(&format!("/tickets/{tid}/events"), json!({ "kind": "reply", "body": "Screenshot attached.", "attachment_ids": [up_id] })).await;
    let sent = wait_mail(&mail, "the reply with an attachment", |_, d| d.contains("Screenshot attached")).await;
    assert!(sent.contains("shot.png"), "the attachment is emailed too");
    assert!(header(&sent, "In-Reply-To").unwrap().contains("answer-1@client-a.example"), "threads onto the client's last message");
    let res = admin.http.get(format!("{}/tickets/{tid}/attachments/{up_id}?inline=1", admin.base)).send().await.unwrap();
    assert_eq!(res.headers()["content-type"], "image/png");
    let (s, _) = admin.call(reqwest::Method::POST, &format!("/tickets/{tid}/events"), Some(json!({ "kind": "note", "body": "x", "attachment_ids": [up_id] }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "an attachment belongs to one event");

    // --- attachments over 8 MB: streamed in and out, a link in the email instead of the file -----------
    // 16 MiB: over the old 8 MB request limit and over the 15 MB that a reply email carries.
    let big = pattern(16 << 20, 7);
    let form = reqwest::multipart::Form::new().part("file", reqwest::multipart::Part::bytes(big.clone()).file_name("disk image.bin"));
    let res = admin.http.post(format!("{}/tickets/{tid}/attachments", admin.base)).multipart(form).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let up: Value = res.json().await.unwrap();
    let big_id = up[0]["id"].as_str().unwrap().to_string();
    assert_eq!(up[0]["size"], big.len());
    let res = admin.http.get(format!("{}/tickets/{tid}/attachments/{big_id}", admin.base)).send().await.unwrap();
    assert_eq!((res.status(), res.headers()["accept-ranges"].to_str().unwrap()), (StatusCode::OK, "bytes"));
    assert_eq!(sha256(&res.bytes().await.unwrap()), sha256(&big), "read back by hash");
    let res = admin.http.get(format!("{}/tickets/{tid}/attachments/{big_id}", admin.base)).header("range", "bytes=1000-1999").send().await.unwrap();
    assert_eq!(res.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(res.headers()["content-range"], format!("bytes 1000-1999/{}", big.len()).as_str());
    assert_eq!(res.bytes().await.unwrap().as_ref(), &big[1000..2000]);
    let res = admin.http.get(format!("{}/tickets/{tid}/attachments/{big_id}", admin.base)).header("range", "bytes=99999999-").send().await.unwrap();
    assert_eq!(res.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    let before = admin.get(&format!("/tickets/{tid}")).await["attachments"].as_array().unwrap().len();
    let over = pattern((ATTACHMENT_MAX_MB << 20) + 1, 1);
    let form = reqwest::multipart::Form::new()
        .part("file", reqwest::multipart::Part::bytes(b"small".to_vec()).file_name("first.txt"))
        .part("file", reqwest::multipart::Part::bytes(over).file_name("huge.iso"));
    let res = admin.http.post(format!("{}/tickets/{tid}/attachments", admin.base)).multipart(form).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let err: Value = res.json().await.unwrap();
    assert_eq!(err["error"], format!("huge.iso is larger than the {ATTACHMENT_MAX_MB} MB limit for attachments"));
    assert_eq!(admin.get(&format!("/tickets/{tid}")).await["attachments"].as_array().unwrap().len(), before, "a failed upload keeps none of its files");
    admin.post(&format!("/tickets/{tid}/events"), json!({ "kind": "reply", "body": "The disk image you asked for.", "attachment_ids": [big_id] })).await;
    let sent = wait_mail(&mail, "the reply with a large attachment", |_, d| d.contains("The disk image you asked for")).await;
    let text = mail_text(&sent);
    assert!(sent.len() < 1 << 20 && text.contains("disk image.bin (16.0 MB)"), "a link, not the file: {text}");
    let token = token_after(&text, "/api/files/");
    let res = reqwest::get(format!("{}/files/{token}", admin.base)).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK, "the link works without signing in");
    assert_eq!(sha256(&res.bytes().await.unwrap()), sha256(&big));
    let (s, _) = admin.call(reqwest::Method::GET, &format!("/files/{}", "0".repeat(64)), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // --- a script run from the ticket reports back ----------------------------------------------------------
    let j = admin.post("/jobs", json!({ "agent_ids": [id1], "interpreter": "bash", "body": "echo spooler restarted", "timeout_secs": 30, "ticket_id": tid })).await;
    admin.wait_job(j["jobs"][0]["job_id"].as_str().unwrap(), 30).await;
    let (api, t2) = (admin, tid.as_str());
    let job_ev = eventually(20, "the job result on the timeline", move || async move {
        let d = api.get(&format!("/tickets/{t2}")).await;
        events_of(&d, "job").into_iter().find(|e| e["data"]["status"] == "succeeded")
    })
    .await;
    assert!(job_ev["body"].as_str().unwrap().contains("spooler restarted"), "{job_ev}");
    let b_ticket = admin.post("/tickets", json!({ "subject": "Client B issue", "client_id": b_id })).await;
    let (s, _) = admin
        .call(reqwest::Method::POST, "/jobs", Some(json!({ "agent_ids": [id1], "interpreter": "bash", "body": "true", "ticket_id": b_ticket["id"] })))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "the agent must belong to the ticket's client");

    // --- an alert policy files a ticket, resolves it, reopens it ---------------------------------------------
    let pol = admin
        .alert_policy(json!({ "name": "Ticket on failure", "kind": "job_failed", "params": {}, "severity": "warning", "client_id": a_id,
                    "ticket_board_id": alerts_board, "ticket_priority": 2, "ticket_auto_resolve": true }),
        )
        .await;
    assert_eq!(pol["config"]["ticket_board_id"], alerts_board.as_str());
    let fail = admin.run_script(id1, "exit 3", 30).await;
    admin.wait_job(&fail, 30).await;
    let pid = pol["id"].as_str().unwrap().to_string();
    let (api, p) = (admin, pid.as_str());
    let at = eventually(20, "the alert ticket", move || async move {
        let l = api.get("/tickets?view=all&sort=created&dir=desc").await;
        l["items"].as_array().unwrap().iter().find(|t| t["alert_policy_id"] == p).cloned()
    })
    .await;
    assert_eq!((at["board_id"].as_str(), at["priority"].as_i64(), at["source"].as_str()), (Some(alerts_board.as_str()), Some(2), Some("alert")));
    assert_eq!(at["agent_count"], 1);
    let at_id = at["id"].as_str().unwrap().to_string();
    let ok = admin.run_script(id1, "true", 30).await;
    admin.wait_job(&ok, 30).await;
    let (api, a2) = (admin, at_id.as_str());
    eventually(20, "the alert ticket to resolve itself", move || async move {
        (api.get(&format!("/tickets/{a2}")).await["status_category"] == "resolved").then_some(())
    })
    .await;
    let fail = admin.run_script(id1, "exit 3", 30).await;
    admin.wait_job(&fail, 30).await;
    let (api, a2) = (admin, at_id.as_str());
    let back = eventually(20, "the same ticket to reopen", move || async move {
        let t = api.get(&format!("/tickets/{a2}")).await;
        (t["status_category"] == "open").then_some(t)
    })
    .await;
    assert_eq!(back["alert_reopens"], 1, "{back}");
    let n_alert_tickets = admin.get("/tickets?view=all").await["items"].as_array().unwrap().iter().filter(|t| t["alert_policy_id"] == pid.as_str()).count();
    assert_eq!(n_alert_tickets, 1, "deduplicated onto one ticket");
    // A person working it stops automation from resolving it.
    admin.post(&format!("/tickets/{at_id}/events"), json!({ "kind": "note", "body": "Looking into it." })).await;
    let ok = admin.run_script(id1, "true", 30).await;
    admin.wait_job(&ok, 30).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let t = admin.get(&format!("/tickets/{at_id}")).await;
    assert_eq!(t["status_category"], "open", "touched tickets aren't auto-resolved");
    assert!(events_of(&t, "alert").iter().any(|e| e["data"]["state"] == "resolved"), "the clear is still noted");
    admin.delete_policy(&pid).await;
    // --- IMAP (optional): RMM_E2E_IMAP=host:imap_port:smtp_port of a GreenMail container -----------
    if let Ok(spec) = std::env::var("RMM_E2E_IMAP") {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let parts: Vec<&str> = spec.split(':').collect();
        let (host, imap_port, smtp) = (parts[0], parts[1].parse::<u16>().unwrap(), parts[2]);
        // Deliver one message over SMTP.
        let sock = tokio::net::TcpStream::connect(format!("{host}:{smtp}")).await.unwrap();
        let (r, mut w) = sock.into_split();
        let mut lines = BufReader::new(r).lines();
        lines.next_line().await.unwrap();
        for cmd in ["EHLO e2e", "MAIL FROM:<ann@client-a.example>", "RCPT TO:<imap@local.test>", "DATA"] {
            w.write_all(format!("{cmd}\r\n").as_bytes()).await.unwrap();
            loop {
                let l = lines.next_line().await.unwrap().unwrap();
                if l.as_bytes().get(3) != Some(&b'-') {
                    break;
                }
            }
        }
        let msg = format!("From: Ann Example <ann@client-a.example>\r\nTo: imap@local.test\r\nSubject: Re: Printer [T-{number}]\r\nMessage-ID: <imap-1@client-a.example>\r\n\r\nSent over IMAP.\r\n.\r\nQUIT\r\n");
        w.write_all(msg.as_bytes()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        let mb = admin
            .post(
                "/mailboxes",
                json!({ "name": "IMAP", "address": "imap@local.test", "kind": "imap", "imap_host": host, "imap_port": imap_port,
                        "imap_security": "none", "imap_username": "imap@local.test", "imap_password": "secret", "board_id": desk["id"] }),
            )
            .await;
        let r = admin.post(&format!("/mailboxes/{}/poll", mb["id"].as_str().unwrap()), json!({})).await;
        assert_eq!((r["ok"].as_bool(), r["filed"].as_i64()), (Some(true), Some(1)), "{r}");
        let d = admin.get(&format!("/tickets/{tid}")).await;
        assert!(events_of(&d, "message").iter().any(|e| e["body"] == "Sent over IMAP."), "IMAP mail threaded onto the ticket");
        let r = admin.post(&format!("/mailboxes/{}/poll", mb["id"].as_str().unwrap()), json!({})).await;
        assert_eq!(r["filed"], 0, "marked seen, not filed twice");
        println!("IMAP polling filed the message");
    }
    let summary = admin.get("/tickets/summary").await;
    assert!(summary["open"].as_i64() >= Some(2) && summary["mine"].as_i64() >= Some(1), "{summary}");
}

/// Maintenance windows and snoozes, reminders, per-agent exclusions, the stale protection
/// report, the process list and the file browser.
async fn day_to_day(admin: &Api, tech: &Api, db: &sqlx::PgPool, dir: &Path, id1: &str, id3: &str, a_id: &str) {
    let (hook_url, hooks) = webhook_receiver().await;
    let ch = admin.post("/notification-channels", json!({ "name": "e2e day-to-day", "kind": "webhook", "config": { "url": hook_url, "secret": "hook-secret" } })).await;
    let ch_id = ch["id"].as_str().unwrap().to_string();

    // --- a snooze holds an alert back; ending it announces the alert ---------------------------
    for bad in [json!({ "for_minutes": 60 }), json!({ "agent_id": id3, "client_id": a_id, "for_minutes": 60 }), json!({ "agent_id": id3 }),
                json!({ "client_id": a_id, "days": [1], "start": "02:00", "minutes": 60, "tz": "Mars/Olympus" })] {
        let (s, v) = admin.call(reqwest::Method::POST, "/alert-mutes", Some(bad.clone())).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad} -> {v}");
    }
    let snooze = admin.post("/alert-mutes", json!({ "agent_id": id3, "for_minutes": 120, "reason": "e2e: planned work" })).await;
    assert_eq!((snooze["active"].as_bool(), snooze["target_name"].is_string()), (Some(true), true), "{snooze}");
    assert_eq!(admin.get(&format!("/agents/{id3}")).await["alerts_muted"], true);
    let off = admin
        .alert_policy(json!({ "name": "Offline (e2e)", "kind": "offline", "params": { "minutes": 1 }, "severity": "critical",
                                         "client_id": a_id, "channel_ids": [ch_id], "renotify_minutes": 15 }))
        .await;
    assert_eq!(off["config"]["renotify_minutes"], 15);
    let off_id = off["id"].as_str().unwrap().to_string();
    let (api, o) = (admin, off_id.as_str());
    let held = eventually(120, "the offline alert, held back", move || async move {
        alerts_for(api, &format!("policy_id={o}")).await.into_iter().find(|a| a["agent_id"] == id3)
    })
    .await;
    assert_eq!(held["suppressed"], true, "{held}");
    let a3 = admin.get(&format!("/agents/{id3}")).await;
    assert_ne!(a3["health"], "unhealthy", "held-back alerts don't count against health: {a3}");
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(!hooks.lock().unwrap().iter().any(|(_, _, b)| b["alert"]["id"] == held["id"]), "nobody is told during a snooze");
    let (s, _) = tech.call(reqwest::Method::DELETE, &format!("/alert-mutes/{}", snooze["id"].as_str().unwrap()), None).await;
    assert!(s.is_success(), "technicians can end snoozes on their clients");
    let held_id = held["id"].as_str().unwrap().to_string();
    wait_hook(&hooks, "the alert announced when the snooze ends", |ev, b| ev == "opened" && b["alert"]["id"] == held_id.as_str()).await;
    assert_eq!(admin.get(&format!("/alerts/{held_id}")).await["suppressed"], false);
    let activity = admin.get(&format!("/agents/{id3}/activity")).await;
    assert!(activity.as_array().unwrap().iter().any(|r| r["action"] == "alert.mute"), "{activity}");

    // --- reminders while it stays open and unacknowledged ----------------------------------------
    sqlx::query("UPDATE alerts SET last_notified_at = now() - interval '1 hour' WHERE id = $1::uuid").bind(&held_id).execute(db).await.unwrap();
    wait_hook(&hooks, "a reminder", |ev, b| ev == "reminder" && b["alert"]["id"] == held_id.as_str()).await;
    admin.post(&format!("/alerts/{held_id}/acknowledge"), json!({})).await;
    sqlx::query("UPDATE alerts SET last_notified_at = now() - interval '1 hour' WHERE id = $1::uuid").bind(&held_id).execute(db).await.unwrap();
    tokio::time::sleep(Duration::from_secs(5)).await;
    let reminders = hooks.lock().unwrap().iter().filter(|(ev, _, b)| ev == "reminder" && b["alert"]["id"] == held_id.as_str()).count();
    assert_eq!(reminders, 1, "acknowledged alerts aren't repeated");

    // --- leave one agent out of a policy --------------------------------------------------------
    let p = admin.call(reqwest::Method::PUT, &format!("/policy-items/{off_id}/exclusions/{id3}"), Some(json!({}))).await;
    assert!(p.0.is_success(), "{p:?}");
    assert_eq!(p.1["limit"]["excluded"][0]["id"], id3, "{}", p.1);
    let al = admin.get(&format!("/alerts/{held_id}")).await;
    assert_eq!((al["state"].as_str(), al["resolution"].as_str()), (Some("resolved"), Some("policy")), "{al}");
    let covering = admin.get(&format!("/agents/{id3}/policy")).await;
    let row = covering["policies"].as_array().unwrap().iter().find(|r| r["id"] == off_id.as_str()).unwrap().clone();
    assert_eq!((row["excluded"].as_bool(), row["applies"].as_bool(), row["limit"]["client_id"].as_str()), (Some(true), Some(false), Some(a_id)), "{row}");
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(alerts_for(admin, &format!("policy_id={off_id}")).await.iter().all(|a| a["agent_id"] != id3), "excluded agents don't alert");
    let (s, _) = admin.call(reqwest::Method::DELETE, &format!("/policy-items/{off_id}/exclusions/{id3}"), None).await;
    assert!(s.is_success());
    let (api, o) = (admin, off_id.as_str());
    eventually(30, "the offline alert to return once included again", move || async move {
        alerts_for(api, &format!("policy_id={o}")).await.into_iter().find(|a| a["agent_id"] == id3)
    })
    .await;
    let s = admin.delete_policy(&off_id).await;
    assert!(s.is_success());

    // --- weekly windows -------------------------------------------------------------------------
    let w = admin.post("/alert-mutes", json!({ "client_id": a_id, "days": [0, 1, 2, 3, 4, 5, 6], "start": "00:00", "minutes": 1440, "tz": "Europe/London", "reason": "always" })).await;
    assert_eq!(w["active"], true, "{w}");
    assert_eq!(admin.get(&format!("/agents/{id1}")).await["alerts_muted"], true, "a client window covers its agents");
    let listed = admin.get(&format!("/alert-mutes?agent_id={id1}")).await;
    assert!(listed.as_array().unwrap().iter().any(|m| m["id"] == w["id"]), "{listed}");
    let (s, _) = admin.call(reqwest::Method::DELETE, &format!("/alert-mutes/{}", w["id"].as_str().unwrap()), None).await;
    assert!(s.is_success());
    assert_eq!(admin.get(&format!("/agents/{id1}")).await["alerts_muted"], false);

    // --- an agent that stops reporting its protection state ---------------------------------------
    let stale = admin
        .alert_policy(json!({ "name": "Silent AV (e2e)", "kind": "security", "params": { "threats": "off", "stale_hours": 2 }, "severity": "warning", "client_id": a_id }))
        .await;
    let stale_id = stale["id"].as_str().unwrap().to_string();
    sqlx::query("UPDATE agents SET security_at = now() - interval '3 hours', connected_at = now() - interval '3 hours' WHERE id = $1::uuid")
        .bind(id1)
        .execute(db)
        .await
        .unwrap();
    let (api, sp) = (admin, stale_id.as_str());
    let silent = eventually(30, "the stale-report alert", move || async move {
        alerts_for(api, &format!("policy_id={sp}")).await.into_iter().find(|a| a["agent_id"] == id1)
    })
    .await;
    assert_eq!(silent["title"], "Protection state not reported");
    admin.post(&format!("/agents/{id1}/security/refresh"), json!({})).await;
    let (api, sid) = (admin, silent["id"].as_str().unwrap().to_string());
    eventually(30, "a fresh report to clear it", || async { (api.get(&format!("/alerts/{sid}")).await["state"] == "resolved").then_some(()) }).await;
    let s = admin.delete_policy(&stale_id).await;
    assert!(s.is_success());

    // --- processes --------------------------------------------------------------------------------
    let mut victim = Command::new("sleep").arg("300").spawn().unwrap();
    let pid = victim.id();
    let (api, id) = (admin, id1);
    let procs = eventually(15, "the process list", move || async move {
        let v = api.get(&format!("/agents/{id}/processes")).await;
        v["processes"].as_array().unwrap().iter().any(|p| p["pid"] == pid).then_some(v)
    })
    .await;
    let list = procs["processes"].as_array().unwrap();
    assert!(list.iter().any(|p| p["name"].as_str().unwrap_or("").starts_with("rmm-agent") && p["protected"] == true), "the agent protects itself");
    let k = admin.post(&format!("/agents/{id1}/processes/{pid}/kill"), json!({ "tree": false, "name": "sleep" })).await;
    assert!(k["message"].as_str().unwrap().contains("Killed"), "{k}");
    let status = tokio::task::spawn_blocking(move || victim.wait().unwrap()).await.unwrap();
    assert!(!status.success(), "killed");
    let agent_pid = list.iter().find(|p| p["name"].as_str().unwrap_or("").starts_with("rmm-agent")).unwrap()["pid"].as_u64().unwrap();
    let (s, v) = admin.call(reqwest::Method::POST, &format!("/agents/{id1}/processes/{agent_pid}/kill"), Some(json!({ "tree": true }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let (s, _) = admin.call(reqwest::Method::GET, &format!("/agents/{id3}/processes"), None).await;
    assert_eq!(s, StatusCode::CONFLICT, "offline");

    // --- files: browse, download, upload past the 8 MB request limit -----------------------------
    let here = dir.canonicalize().unwrap();
    let listing = admin.get(&format!("/agents/{id1}/files?path={}", url_escape(&here.to_string_lossy()))).await;
    assert!(listing["entries"].as_array().unwrap().iter().any(|e| e["name"] == "a1.toml" && e["dir"] == false), "{listing}");
    assert_eq!(listing["parent"], here.parent().unwrap().to_string_lossy().as_ref());
    let roots = admin.get(&format!("/agents/{id1}/files")).await;
    assert_eq!(roots["entries"][0]["path"], "/");
    let (s, _) = admin.call(reqwest::Method::GET, &format!("/agents/{id1}/files?path=relative/dir"), None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    let base = admin.base.clone();
    let data: Vec<u8> = (0..20 * 1024 * 1024 + 123).map(|i: u32| (i.wrapping_mul(2654435761) >> 24) as u8).collect();
    let target = here.join("uploaded.bin");
    let up = |overwrite: bool, body: Vec<u8>| {
        let url = format!("{base}/agents/{id1}/files/upload?path={}&overwrite={overwrite}", url_escape(&target.to_string_lossy()));
        admin.http.put(url).body(body).send()
    };
    let res = up(false, data.clone()).await.unwrap();
    assert!(res.status().is_success(), "{}", res.text().await.unwrap());
    assert_eq!(std::fs::read(&target).unwrap(), data, "uploaded intact");
    let res = up(false, b"again".to_vec()).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "no silent overwrite");
    assert_eq!(std::fs::metadata(&target).unwrap().len(), data.len() as u64, "the refused upload changed nothing");
    let res = up(true, b"small".to_vec()).await.unwrap();
    assert!(res.status().is_success());
    assert_eq!(std::fs::read(&target).unwrap(), b"small");
    std::fs::write(&target, &data).unwrap();
    let res = admin.http.get(format!("{base}/agents/{id1}/files/download?path={}", url_escape(&target.to_string_lossy()))).send().await.unwrap();
    assert!(res.status().is_success());
    assert_eq!(res.headers()["x-file-size"], data.len().to_string().as_str());
    assert!(res.headers()["content-disposition"].to_str().unwrap().contains("uploaded.bin"));
    assert_eq!(res.bytes().await.unwrap().as_ref(), data.as_slice(), "downloaded intact");
    let (s, _) = admin.call(reqwest::Method::GET, &format!("/agents/{id1}/files/download?path={}", url_escape(&here.join("missing").to_string_lossy())), None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let activity = admin.get(&format!("/agents/{id1}/activity")).await;
    let acts: Vec<&str> = activity.as_array().unwrap().iter().filter_map(|r| r["action"].as_str()).collect();
    assert!(acts.contains(&"agent.file_upload") && acts.contains(&"agent.file_download") && acts.contains(&"agent.process_kill"), "{acts:?}");
    let _ = std::fs::remove_file(&target);
}

fn url_escape(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

// ---------------------------------------------------------------------------------------------
// Microsoft Graph stand-in
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Default)]
struct GraphMock {
    /// (id, raw MIME, read)
    inbox: std::sync::Arc<std::sync::Mutex<Vec<(String, String, bool)>>>,
    /// MIME messages sent through sendMail.
    sent: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    /// Form fields of token requests.
    logins: std::sync::Arc<std::sync::Mutex<Vec<std::collections::HashMap<String, String>>>>,
}

/// The token endpoint and the few mail endpoints the server uses.
async fn graph_mock() -> (String, GraphMock) {
    use axum::extract::{Path as P, State as S};
    use axum::http::{HeaderMap, StatusCode as Code};
    use axum::routing::{get, patch, post};
    let mock = GraphMock::default();
    fn authed(h: &HeaderMap) -> bool {
        h.get("authorization").and_then(|v| v.to_str().ok()) == Some("Bearer graph-token")
    }
    let app = axum::Router::new()
        .route(
            "/{tenant}/oauth2/v2.0/token",
            post(|S(m): S<GraphMock>, P(tenant): P<String>, axum::Form(f): axum::Form<std::collections::HashMap<String, String>>| async move {
                let ok = tenant == "e2e-tenant" && f.get("client_secret").map(String::as_str) == Some("graph-s3cret");
                m.logins.lock().unwrap().push(f);
                if ok {
                    (Code::OK, axum::Json(json!({ "access_token": "graph-token", "token_type": "Bearer", "expires_in": 3600 })))
                } else {
                    (Code::UNAUTHORIZED, axum::Json(json!({ "error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret." })))
                }
            }),
        )
        .route(
            "/v1.0/users/{user}/mailFolders/{folder}/messages",
            get(|S(m): S<GraphMock>, h: HeaderMap, P((user, folder)): P<(String, String)>| async move {
                assert_eq!((user.as_str(), folder.as_str()), ("m365@msp.example", "inbox"));
                if !authed(&h) {
                    return (Code::UNAUTHORIZED, axum::Json(json!({ "error": { "message": "no token" } })));
                }
                let ids: Vec<Value> = m.inbox.lock().unwrap().iter().filter(|x| !x.2).map(|x| json!({ "id": x.0 })).collect();
                (Code::OK, axum::Json(json!({ "value": ids })))
            }),
        )
        .route(
            "/v1.0/users/{user}/messages/{id}/$value",
            get(|S(m): S<GraphMock>, h: HeaderMap, P((_, id)): P<(String, String)>| async move {
                assert!(authed(&h));
                m.inbox.lock().unwrap().iter().find(|x| x.0 == id).map(|x| x.1.clone()).unwrap_or_default()
            }),
        )
        .route(
            "/v1.0/users/{user}/messages/{id}",
            patch(|S(m): S<GraphMock>, h: HeaderMap, P((_, id)): P<(String, String)>, axum::Json(b): axum::Json<Value>| async move {
                assert!(authed(&h));
                assert_eq!(b, json!({ "isRead": true }));
                for x in m.inbox.lock().unwrap().iter_mut().filter(|x| x.0 == id) {
                    x.2 = true;
                }
                axum::Json(json!({}))
            }),
        )
        .route(
            "/v1.0/users/{user}/sendMail",
            post(|S(m): S<GraphMock>, h: HeaderMap, body: String| async move {
                assert!(authed(&h));
                assert_eq!(h.get("content-type").unwrap(), "text/plain");
                let mime = data_encoding::BASE64.decode(body.trim().as_bytes()).expect("base64 MIME");
                m.sent.lock().unwrap().push(String::from_utf8(mime).unwrap());
                Code::ACCEPTED
            }),
        )
        .with_state(mock.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, mock)
}

/// The decoded text of a raw message from the SMTP sink.
/// `n` bytes that don't compress to nothing and differ by `seed`.
fn pattern(n: usize, seed: u8) -> Vec<u8> {
    let mut x = 0x9e37_79b9u32 ^ seed as u32;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

fn sha256(b: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(b))
}

fn mail_text(raw: &str) -> String {
    let m = mail_parser::MessageParser::default().parse(raw.as_bytes()).expect("a MIME message");
    m.body_text(0).map(|t| t.into_owned()).unwrap_or_default()
}

/// The 64-hex-digit token after `marker` in `text`.
fn token_after(text: &str, marker: &str) -> String {
    let i = text.find(marker).unwrap_or_else(|| panic!("{marker} in {text}")) + marker.len();
    text[i..].chars().take_while(|c| c.is_ascii_hexdigit()).collect()
}

async fn portal_form(api: &Api, path: &str, form: reqwest::multipart::Form) -> (StatusCode, Value) {
    let res = api.http.post(format!("{}{path}", api.base)).multipart(form).send().await.unwrap();
    let s = res.status();
    (s, res.json().await.unwrap_or(Value::Null))
}

/// Roadmap block 4: SLAs, the client portal, the knowledge base, satisfaction surveys, teams,
/// canned responses, splitting, new-ticket notifications and Microsoft 365 mailboxes.
async fn portal_and_sla(url: &str, admin: &Api, db: &sqlx::PgPool, a_id: &str, b_id: &str) {
    let (smtp_port, mail) = smtp_sink().await;
    admin
        .call(
            reqwest::Method::PUT,
            "/settings/smtp",
            Some(json!({ "host": "127.0.0.1", "port": smtp_port, "security": "none", "from": "Help Desk <help@msp.example>" })),
        )
        .await;
    let (hook_url, hooks) = webhook_receiver().await;
    let ch = admin.post("/notification-channels", json!({ "name": "e2e service desk", "kind": "webhook", "config": { "url": hook_url, "secret": "hook-secret" } })).await;
    let ch_id = ch["id"].as_str().unwrap().to_string();
    let me = admin.get("/auth/me").await;
    let admin_id = me["id"].as_str().unwrap().to_string();
    let meta = admin.get("/tickets/meta").await;
    let desk = meta["boards"].as_array().unwrap().iter().find(|b| b["name"] == "Service Desk").unwrap().clone();
    let desk_id = desk["id"].as_str().unwrap().to_string();
    let status = |cat: &str| desk["statuses"].as_array().unwrap().iter().find(|s| s["category"] == cat).unwrap()["id"].as_str().unwrap().to_string();
    let secs = |v: &Value| chrono::DateTime::parse_from_rfc3339(v.as_str().unwrap_or_else(|| panic!("a timestamp, got {v}"))).unwrap().timestamp();

    // --- SLA: deadlines from the default policy, moved by priority, paused while waiting -----
    let (s, v) = admin
        .call(reqwest::Method::POST, "/sla/calendars", Some(json!({ "name": "Bad", "timezone": "Mars/Olympus", "hours": [[[540, 1020]], [], [], [], [], [], []] })))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let cal = admin
        .post(
            "/sla/calendars",
            json!({ "name": "Office", "timezone": "Europe/London", "hours": [[[540, 1020]], [[540, 1020]], [[540, 1020]], [[540, 1020]], [[540, 1020]], [], []],
                    "holidays": [{ "day": "2026-12-25", "name": "Christmas" }] }),
        )
        .await;
    let cals = admin.get("/sla/calendars").await;
    assert_eq!(cals[0]["holidays"][0]["name"], "Christmas");
    // Around the clock, so the test doesn't depend on the time of day.
    let policy = admin
        .post(
            "/sla/policies",
            json!({ "name": "E2E SLA", "is_default": true, "channel_ids": [ch_id], "targets": [
                { "priority": 2, "respond_mins": 30, "update_mins": 60, "resolve_mins": 240 },
                { "priority": 3, "respond_mins": 60, "update_mins": 120, "resolve_mins": 480 } ] }),
        )
        .await;
    let policy_id = policy["id"].as_str().unwrap().to_string();
    let (s, _) = admin
        .call(reqwest::Method::POST, "/sla/policies", Some(json!({ "name": "Odd", "targets": [{ "priority": 3, "respond_mins": 600, "resolve_mins": 60 }] })))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "respond longer than resolve");
    let t = admin.post("/tickets", json!({ "subject": "SLA clock", "client_id": a_id, "priority": 3, "assignee_id": admin_id })).await;
    let tid = t["id"].as_str().unwrap().to_string();
    assert_eq!(t["sla_policy_name"], "E2E SLA");
    let created = secs(&t["created_at"]);
    assert!((secs(&t["respond_by"]) - (created + 3600)).abs() <= 2, "{t}");
    assert!((secs(&t["resolve_by"]) - (created + 8 * 3600)).abs() <= 2);
    assert!(t["update_by"].is_null(), "the update clock starts with the first response");
    assert_eq!(t["sla_due"], t["respond_by"]);
    let (_, t) = admin.call(reqwest::Method::PATCH, &format!("/tickets/{tid}"), Some(json!({ "priority": 2 }))).await;
    assert!((secs(&t["respond_by"]) - (created + 1800)).abs() <= 2, "a higher priority tightens it: {t}");
    let (_, t) = admin.call(reqwest::Method::PATCH, &format!("/tickets/{tid}"), Some(json!({ "status_id": status("waiting_client") }))).await;
    assert_eq!(t["sla_paused"], true);
    assert!(t["sla_due"].is_null(), "no running deadline while paused");
    tokio::time::sleep(Duration::from_millis(2100)).await;
    let (_, t) = admin.call(reqwest::Method::PATCH, &format!("/tickets/{tid}"), Some(json!({ "status_id": status("open") }))).await;
    assert_eq!(t["sla_paused"], false);
    let paused: i64 = sqlx::query_scalar("SELECT sla_paused_secs FROM tickets WHERE id = $1::uuid").bind(&tid).fetch_one(db).await.unwrap();
    assert!(paused >= 2, "paused {paused}s");
    assert!(secs(&t["respond_by"]) >= created + 1800 + 2, "the pause pushes the deadline back: {t}");
    // Another client's policy can differ; clients without one use the default.
    let strict = admin.post("/sla/policies", json!({ "name": "Strict", "calendar_id": cal["id"], "targets": [{ "priority": 2, "respond_mins": 5 }] })).await;
    admin.call(reqwest::Method::PUT, &format!("/clients/{b_id}/service"), Some(json!({ "sla_policy_id": strict["id"] }))).await;
    let tb = admin.post("/tickets", json!({ "subject": "Strict client", "client_id": b_id, "priority": 2 })).await;
    assert_eq!(tb["sla_policy_name"], "Strict");
    let tb4 = admin.post("/tickets", json!({ "subject": "No target", "client_id": b_id, "priority": 4 })).await;
    assert!(tb4["respond_by"].is_null() && tb4["sla_due"].is_null(), "no target for P4 in that policy");

    // --- SLA: a warning, then a breach, on the channel, the timeline and to the assignee ---------
    // (Policy changes recompute open tickets in the background; let that finish first.)
    tokio::time::sleep(Duration::from_secs(1)).await;
    sqlx::query("UPDATE tickets SET respond_warn_at = now() - interval '1 minute' WHERE id = $1::uuid").bind(&tid).execute(db).await.unwrap();
    let hook = wait_hook(&hooks, "an SLA warning", |ev, b| ev == "sla_warning" && b["ticket"]["id"] == tid.as_str()).await;
    assert_eq!(hook["sla"]["target"], "respond");
    sqlx::query("UPDATE tickets SET respond_by = now() - interval '1 second' WHERE id = $1::uuid").bind(&tid).execute(db).await.unwrap();
    wait_hook(&hooks, "an SLA breach", |ev, b| ev == "sla_breach" && b["ticket"]["id"] == tid.as_str()).await;
    let d = admin.get(&format!("/tickets/{tid}")).await;
    let sla_events = events_of(&d, "sla");
    assert_eq!(sla_events.len(), 2, "{sla_events:?}");
    assert_eq!(d["sla_breached"], json!(["respond"]));
    wait_mail(&mail, "the SLA email to the assignee", |to, data| to.iter().any(|t| t == ADMIN_EMAIL) && data.contains("missed its SLA")).await;
    let breached = admin.get("/tickets?view=breached").await;
    assert!(breached["items"].as_array().unwrap().iter().any(|x| x["id"] == tid.as_str()));
    assert!(admin.get("/tickets/summary").await["breached"].as_i64() >= Some(1));
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(events_of(&admin.get(&format!("/tickets/{tid}")).await, "sla").len(), 2, "each warning and breach once");
    // The first public reply starts the update clock.
    admin.post(&format!("/tickets/{tid}/events"), json!({ "kind": "reply", "body": "On it." })).await;
    let t = admin.get(&format!("/tickets/{tid}")).await;
    let replied = secs(&t["first_response_at"]);
    assert!((secs(&t["update_by"]) - (replied + 3600)).abs() <= 2, "{t}");
    assert_eq!(t["sla_due"], t["update_by"]);
    let due = admin.get("/tickets?view=open&sort=due&dir=asc&limit=200").await;
    let dues: Vec<Option<i64>> = due["items"].as_array().unwrap().iter().map(|x| x["sla_due"].as_str().map(|_| secs(&x["sla_due"]))).collect();
    let running: Vec<i64> = dues.iter().map_while(|d| *d).collect();
    assert!(running.windows(2).all(|w| w[0] <= w[1]) && dues[running.len()..].iter().all(Option::is_none), "soonest first, none last: {dues:?}");
    assert!(due["items"].as_array().unwrap().iter().any(|x| x["id"] == tid.as_str()));

    // --- teams, board defaults and new-ticket notifications ---------------------------------------
    let team = admin.post("/teams", json!({ "name": "Tier 1", "member_ids": [admin_id] })).await;
    let team_id = team["id"].as_str().unwrap().to_string();
    let statuses: Vec<Value> = desk["statuses"].as_array().unwrap().iter().map(|s| json!({ "id": s["id"], "name": s["name"], "category": s["category"] })).collect();
    admin
        .call(
            reqwest::Method::PUT,
            &format!("/boards/{desk_id}"),
            Some(json!({ "name": "Service Desk", "statuses": statuses, "default_team_id": team_id, "notify_channel_ids": [ch_id] })),
        )
        .await;
    let nt = admin.post("/tickets", json!({ "subject": "Goes to Tier 1", "client_id": a_id })).await;
    assert_eq!(nt["team_name"], "Tier 1");
    wait_hook(&hooks, "the new-ticket notification", |ev, b| ev == "ticket_created" && b["ticket"]["id"] == nt["id"]).await;
    let mine = admin.get("/tickets?view=team").await;
    assert!(mine["items"].as_array().unwrap().iter().any(|x| x["id"] == nt["id"]));
    let (_, moved) = admin.call(reqwest::Method::PATCH, &format!("/tickets/{}", nt["id"].as_str().unwrap()), Some(json!({ "team_id": null }))).await;
    assert!(moved["team_id"].is_null());
    let unteamed = admin.get("/tickets?team=none").await;
    assert!(unteamed["items"].as_array().unwrap().iter().any(|x| x["id"] == nt["id"]));

    // --- the portal: invitation, sign-in link, tickets, replies, attachments ----------------------
    let pat = admin.post("/contacts", json!({ "client_id": a_id, "name": "Pat Portal", "email": "pat@client-a.example", "portal_enabled": true })).await;
    let pat_id = pat["id"].as_str().unwrap().to_string();
    let bob = admin.post("/contacts", json!({ "client_id": b_id, "name": "Bob Other", "email": "bob@client-b.example", "portal_enabled": true })).await;
    admin.post(&format!("/contacts/{pat_id}/portal-invite"), json!({})).await;
    let invite = wait_mail(&mail, "the portal invitation", |to, data| to.iter().any(|t| t == "pat@client-a.example") && data.contains("invited")).await;
    let invite_token = token_after(&mail_text(&invite), "/portal/login?token=");
    assert_eq!(invite_token.len(), 64);
    let portal = Api::new(url);
    let (s, _) = portal.call(reqwest::Method::GET, "/portal/me", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    portal.post("/portal/auth/verify", json!({ "token": invite_token })).await;
    let pme = portal.get("/portal/me").await;
    assert_eq!((pme["contact"]["name"].as_str(), pme["contact"]["client_name"].as_str()), (Some("Pat Portal"), Some("Client A")));
    let (s, _) = portal.call(reqwest::Method::POST, "/portal/auth/verify", Some(json!({ "token": invite_token }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "a link works once");
    // Sessions don't cross over: the portal cookie isn't a technician session, and back.
    let (s, _) = portal.call(reqwest::Method::GET, "/tickets", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "portal cookie on the technician API");
    let (s, _) = admin.call(reqwest::Method::GET, "/portal/me", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "technician cookie on the portal");
    // Asking for a link answers the same whether or not the address has access.
    portal.post("/portal/auth/link", json!({ "email": "nobody@nowhere.example" })).await;
    portal.post("/portal/auth/link", json!({ "email": "PAT@client-a.example" })).await;
    let link = wait_mail(&mail, "the sign-in link", |to, data| to.iter().any(|t| t == "pat@client-a.example") && data.contains("Sign in to")).await;
    assert_ne!(token_after(&mail_text(&link), "/portal/login?token="), invite_token);

    let form = reqwest::multipart::Form::new()
        .text("subject", "Laptop won't charge")
        .text("description", "Since this morning.\nAlso: the projector in room 2 is broken.")
        .text("urgency", "high")
        .part("file", reqwest::multipart::Part::bytes(b"charger photo".to_vec()).file_name("charger.jpg").mime_str("image/jpeg").unwrap());
    let (s, created) = portal_form(&portal, "/portal/tickets", form).await;
    assert!(s.is_success(), "{s} {created}");
    let ptid = created["id"].as_str().unwrap().to_string();
    let pt = admin.get(&format!("/tickets/{ptid}")).await;
    assert_eq!((pt["source"].as_str(), pt["priority"].as_i64(), pt["contact_id"].as_str()), (Some("portal"), Some(2), Some(pat_id.as_str())));
    assert_eq!(pt["attachments"].as_array().unwrap().len(), 1);
    wait_hook(&hooks, "portal tickets announce themselves too", |ev, b| ev == "ticket_created" && b["ticket"]["id"] == ptid.as_str()).await;
    admin.post(&format!("/tickets/{ptid}/events"), json!({ "kind": "note", "body": "Internal: order a charger." })).await;
    admin.post(&format!("/tickets/{ptid}/events"), json!({ "kind": "reply", "body": "Which model is it?", "status_id": status("waiting_client") })).await;
    let view = portal.get(&format!("/portal/tickets/{ptid}")).await;
    let bodies: Vec<&str> = view["events"].as_array().unwrap().iter().map(|e| e["body"].as_str().unwrap()).collect();
    assert!(bodies.contains(&"Which model is it?") && !bodies.iter().any(|b| b.contains("Internal")), "{bodies:?}");
    assert_eq!(view["events"].as_array().unwrap().iter().find(|e| e["body"] == "Which model is it?").unwrap()["author_kind"], "staff");
    // A linked documentation page is internal: no `doc` event in the portal, none emailed.
    let runbook = admin.post(&format!("/clients/{a_id}/docs"), json!({ "title": "Charger runbook", "body": "Internal steps." })).await;
    let runbook_id = runbook["id"].as_str().unwrap().to_string();
    admin.post(&format!("/tickets/{ptid}/docs"), json!({ "doc_id": runbook_id })).await;
    let (s, _) = admin.call(reqwest::Method::DELETE, &format!("/tickets/{ptid}/docs/{runbook_id}"), None).await;
    assert!(s.is_success());
    admin.post(&format!("/tickets/{ptid}/docs"), json!({ "doc_id": runbook_id })).await;
    let doc_events: Vec<i64> = events_of(&admin.get(&format!("/tickets/{ptid}")).await, "doc").iter().map(|e| e["id"].as_i64().unwrap()).collect();
    assert_eq!(doc_events.len(), 3);
    let view = portal.get(&format!("/portal/tickets/{ptid}")).await;
    assert!(view["events"].as_array().unwrap().iter().all(|e| e["kind"] != "doc"), "{view}");
    assert!(!view.to_string().contains("Charger runbook"), "{view}");
    assert!(!portal.get("/portal/tickets?state=all").await.to_string().contains("Charger runbook"));
    tokio::time::sleep(Duration::from_secs(1)).await;
    let (mailed,): (i64,) = sqlx::query_as("SELECT count(*) FROM email_messages WHERE event_id = ANY($1) OR body LIKE '%Charger runbook%'")
        .bind(&doc_events)
        .fetch_one(db)
        .await
        .unwrap();
    assert_eq!(mailed, 0, "nothing emailed for a linked page");
    let aid = view["attachments"][0]["id"].as_str().unwrap();
    let res = portal.http.get(format!("{}/portal/tickets/{ptid}/attachments/{aid}", portal.base)).send().await.unwrap();
    assert_eq!(res.headers()["content-type"], "application/octet-stream");
    assert_eq!(res.bytes().await.unwrap().as_ref(), b"charger photo");
    // Over 8 MB through the portal (a new request), read back by hash; over the limit is a 413.
    let big = pattern(9 << 20, 3);
    let form = reqwest::multipart::Form::new()
        .text("subject", "Event log export")
        .part("file", reqwest::multipart::Part::bytes(big.clone()).file_name("events.evtx"))
        .text("description", "Attached (fields after the file are read too).");
    let (s, created) = portal_form(&portal, "/portal/tickets", form).await;
    assert!(s.is_success(), "{s} {created}");
    let big_ticket = created["id"].as_str().unwrap().to_string();
    let v = portal.get(&format!("/portal/tickets/{big_ticket}")).await;
    assert!(v["events"][0]["body"].as_str().unwrap().contains("fields after the file"), "{v}");
    let res = portal.http.get(format!("{}/portal/tickets/{big_ticket}/attachments/{}", portal.base, v["attachments"][0]["id"].as_str().unwrap())).send().await.unwrap();
    assert_eq!(sha256(&res.bytes().await.unwrap()), sha256(&big));
    let form = reqwest::multipart::Form::new()
        .text("body", "And the full dump")
        .part("file", reqwest::multipart::Part::bytes(pattern((ATTACHMENT_MAX_MB << 20) + 1, 4)).file_name("full.dmp"));
    let (s, err) = portal_form(&portal, &format!("/portal/tickets/{big_ticket}/messages"), form).await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(err["error"], format!("full.dmp is larger than the {ATTACHMENT_MAX_MB} MB limit for attachments"));
    let v = portal.get(&format!("/portal/tickets/{big_ticket}")).await;
    assert_eq!((v["attachments"].as_array().unwrap().len(), v["events"].as_array().unwrap().len()), (1, 1), "nothing of the failed reply is kept");
    let list = portal.get("/portal/tickets").await;
    assert!(list.as_array().unwrap().iter().any(|x| x["id"] == ptid.as_str()));
    assert!(!list.as_array().unwrap().iter().any(|x| x["id"] == tid.as_str()), "not Pat's ticket, and Pat isn't primary");
    let (s, _) = portal.call(reqwest::Method::GET, &format!("/portal/tickets/{tid}"), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // Pat answers: the ticket is back to work and the assignee hears about it.
    admin.call(reqwest::Method::PATCH, &format!("/tickets/{ptid}"), Some(json!({ "assignee_id": admin_id }))).await;
    let form = reqwest::multipart::Form::new()
        .text("body", "A ThinkPad T14.\n\nAnd separately: the room 2 projector shows no picture.")
        .part("file", reqwest::multipart::Part::bytes(b"projector".to_vec()).file_name("projector.png").mime_str("image/png").unwrap());
    let (s, _) = portal_form(&portal, &format!("/portal/tickets/{ptid}/messages"), form).await;
    assert!(s.is_success());
    let pt = admin.get(&format!("/tickets/{ptid}")).await;
    assert_eq!(pt["status_category"], "open");
    let msg = events_of(&pt, "message").into_iter().last().unwrap();
    assert_eq!(msg["author_contact_id"], pat_id.as_str());
    wait_mail(&mail, "the assignee hears about the portal reply", |to, data| to.iter().any(|t| t == ADMIN_EMAIL) && data.contains("new reply")).await;
    // Another client's contact sees none of it.
    admin.post(&format!("/contacts/{}/portal-invite", bob["id"].as_str().unwrap()), json!({})).await;
    let bmail = wait_mail(&mail, "Bob's invitation", |to, _| to.iter().any(|t| t == "bob@client-b.example")).await;
    let other = Api::new(url);
    other.post("/portal/auth/verify", json!({ "token": token_after(&mail_text(&bmail), "/portal/login?token=") })).await;
    let (s, _) = other.call(reqwest::Method::GET, &format!("/portal/tickets/{ptid}"), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = other.call(reqwest::Method::GET, &format!("/portal/tickets/{ptid}/attachments/{aid}"), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert!(other.get("/portal/tickets?state=all").await.as_array().unwrap().iter().all(|x| x["id"] != ptid.as_str()));

    // --- split the unrelated part off; canned responses -----------------------------------------------
    let split = admin.post(&format!("/tickets/{ptid}/split"), json!({ "event_id": msg["id"], "subject": "Room 2 projector" })).await;
    assert_eq!((split["subject"].as_str(), split["contact_id"].as_str()), (Some("Room 2 projector"), Some(pat_id.as_str())));
    let sd = admin.get(&format!("/tickets/{}", split["id"].as_str().unwrap())).await;
    assert_eq!(sd["attachments"][0]["name"], "projector.png", "the message's attachment moves with it");
    assert_eq!(events_of(&sd, "split")[0]["data"]["from_number"], pt["number"]);
    assert_eq!(admin.get(&format!("/tickets/{ptid}")).await["attachments"].as_array().unwrap().len(), 1);
    let canned = admin
        .post("/canned-responses", json!({ "name": "Need info", "body": "Hi {{contact.first_name}}, could you send a photo for {{ticket.number}}? {{oops}}", "status_category": "waiting_client" }))
        .await;
    let r = admin.get(&format!("/tickets/{ptid}/canned/{}", canned["id"].as_str().unwrap())).await;
    assert_eq!(r["body"], format!("Hi Pat, could you send a photo for T-{}? {{{{oops}}}}", pt["number"]));
    assert_eq!(r["status_category"], "waiting_client");

    // --- password and TOTP sign-in for contacts -----------------------------------------------------
    let (s, _) = portal.call(reqwest::Method::POST, "/portal/account/password", Some(json!({ "password": "short" }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    portal.post("/portal/account/password", json!({ "password": "portal-password-1" })).await;
    let setup = portal.post("/portal/account/totp/setup", json!({})).await;
    let psecret = setup["secret"].as_str().unwrap().to_string();
    portal.post("/portal/account/totp/enable", json!({ "code": totp(&psecret) })).await;
    let (sealed,): (bool,) = sqlx::query_as("SELECT totp_sealed FROM contact_credentials WHERE contact_id = $1::uuid").bind(&pat_id).fetch_one(db).await.unwrap();
    assert!(sealed, "contact TOTP secrets are encrypted at rest too");
    sqlx::query("UPDATE contact_credentials SET totp_last_step = NULL WHERE contact_id = $1::uuid").bind(&pat_id).execute(db).await.unwrap();
    portal.post("/portal/auth/logout", json!({})).await;
    let (s, _) = portal.call(reqwest::Method::GET, "/portal/me", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, v) = portal.call(reqwest::Method::POST, "/portal/auth/login", Some(json!({ "email": "pat@client-a.example", "password": "portal-password-1" }))).await;
    assert_eq!((s, v["mfa_required"].as_bool()), (StatusCode::UNAUTHORIZED, Some(true)));
    let (s, _) = portal.call(reqwest::Method::POST, "/portal/auth/login", Some(json!({ "email": "pat@client-a.example", "password": "wrong-password-1" }))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let code = totp(&psecret);
    portal.post("/portal/auth/login", json!({ "email": "pat@client-a.example", "password": "portal-password-1", "code": code })).await;
    assert_eq!(portal.get("/portal/me").await["totp_enabled"], true);
    let again = Api::new(url);
    let (s, _) = again.call(reqwest::Method::POST, "/portal/auth/login", Some(json!({ "email": "pat@client-a.example", "password": "portal-password-1", "code": code }))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "a TOTP code works once");

    // --- knowledge base and devices -------------------------------------------------------------------
    let public = admin.post("/kb", json!({ "title": "Reset your password", "body": "Press Ctrl+Alt+Del, then Change a password.", "category": "Accounts", "public": true })).await;
    let internal = admin.post("/kb", json!({ "title": "Domain controller rebuild", "body": "Internal runbook.", "category": "Runbooks" })).await;
    let only_b = admin.post("/kb", json!({ "title": "Client B VPN", "body": "For B only.", "public": true, "client_id": b_id })).await;
    let kb = portal.get("/portal/kb").await;
    let titles: Vec<&str> = kb.as_array().unwrap().iter().map(|a| a["title"].as_str().unwrap()).collect();
    assert_eq!(titles, vec!["Reset your password"]);
    assert!(portal.get("/portal/kb?q=password").await.as_array().unwrap().len() == 1);
    for hidden in [&internal, &only_b] {
        let (s, _) = portal.call(reqwest::Method::GET, &format!("/portal/kb/{}", hidden["id"].as_str().unwrap()), None).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
    }
    assert_eq!(portal.get(&format!("/portal/kb/{}", public["id"].as_str().unwrap())).await["body"], "Press Ctrl+Alt+Del, then Change a password.");
    assert_eq!(admin.get("/kb?q=runbook").await.as_array().unwrap().len(), 1);
    let (s, _) = portal.call(reqwest::Method::GET, "/portal/devices", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "off until the client allows it");
    admin.call(reqwest::Method::PUT, &format!("/clients/{a_id}/service"), Some(json!({ "sla_policy_id": null, "portal_devices": true }))).await;
    let devices = portal.get("/portal/devices").await;
    assert!(!devices.as_array().unwrap().is_empty() && devices[0]["hostname"].is_string(), "{devices}");

    // --- satisfaction survey on resolve -----------------------------------------------------------------
    admin.call(reqwest::Method::PUT, "/settings/service-desk", Some(json!({ "portal_board_id": desk_id, "portal_welcome": "Welcome!", "csat_enabled": true }))).await;
    assert_eq!(portal.get("/portal/me").await["welcome"], "Welcome!");
    admin.call(reqwest::Method::PATCH, &format!("/tickets/{ptid}"), Some(json!({ "status_id": status("resolved") }))).await;
    let survey = wait_mail(&mail, "the survey", |to, data| to.iter().any(|t| t == "pat@client-a.example") && data.contains("How did we do")).await;
    let stoken = token_after(&mail_text(&survey), "/feedback/");
    let http = reqwest::Client::new();
    let fb: Value = http.get(format!("{url}/api/feedback/{stoken}")).send().await.unwrap().json().await.unwrap();
    assert_eq!(fb["number"], pt["number"]);
    let res = http.post(format!("{url}/api/feedback/{stoken}")).json(&json!({ "rating": "good", "comment": "Quick fix" })).send().await.unwrap();
    assert!(res.status().is_success());
    let res = http.post(format!("{url}/api/feedback/{}", "0".repeat(64))).json(&json!({ "rating": "good" })).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let pt = admin.get(&format!("/tickets/{ptid}")).await;
    assert_eq!((pt["csat"]["rating"].as_str(), pt["csat_rating"].as_str()), (Some("good"), Some("good")));
    assert_eq!(events_of(&pt, "csat")[0]["body"], "Satisfaction: Good\n\nQuick fix");
    tokio::time::sleep(Duration::from_secs(3)).await;
    let surveys = mail.lock().unwrap().iter().filter(|(to, d)| to.iter().any(|t| t == "pat@client-a.example") && d.contains("How did we do")).count();
    assert_eq!(surveys, 1, "one survey per ticket");
    // Pat can resolve their own ticket from the portal, and a later message reopens it.
    portal.post(&format!("/portal/tickets/{}/resolve", split["id"].as_str().unwrap()), json!({})).await;
    assert_eq!(admin.get(&format!("/tickets/{}", split["id"].as_str().unwrap())).await["status_category"], "resolved");

    // --- turning portal access off ends the session ------------------------------------------------------
    let mut pat_in = pat.clone();
    pat_in["portal_enabled"] = false.into();
    let (s, _) = admin.call(reqwest::Method::PUT, &format!("/contacts/{pat_id}"), Some(pat_in)).await;
    assert!(s.is_success());
    let (s, _) = portal.call(reqwest::Method::GET, "/portal/me", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // --- Microsoft 365 mailbox over Graph: poll, file, reply through sendMail ----------------------------
    let graph = GRAPH.get().unwrap();
    let (s, v) = admin
        .call(reqwest::Method::POST, "/mailboxes", Some(json!({ "name": "M365", "address": "m365@msp.example", "kind": "graph", "board_id": desk_id })))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "needs the tenant and app: {v}");
    let mb = admin
        .post(
            "/mailboxes",
            json!({ "name": "M365", "address": "m365@msp.example", "kind": "graph", "board_id": desk_id, "graph_tenant": "e2e-tenant",
                    "graph_client_id": "e2e-client", "graph_secret": "graph-s3cret" }),
        )
        .await;
    let mb_id = mb["id"].as_str().unwrap().to_string();
    assert_eq!((mb["has_graph_secret"].as_bool(), mb.get("graph_secret")), (Some(true), None));
    let (stored, sealed): (Vec<u8>, bool) =
        sqlx::query_as("SELECT graph_secret, graph_secret_sealed FROM mailboxes WHERE id = $1::uuid").bind(&mb_id).fetch_one(db).await.unwrap();
    assert!(sealed && stored != b"graph-s3cret", "the client secret is encrypted at rest");
    graph.inbox.lock().unwrap().push((
        "AAMk-1".into(),
        "From: Gail <gail@client-a.example>\r\nTo: m365@msp.example\r\nSubject: VPN drops\r\nMessage-ID: <graph-1@client-a.example>\r\n\r\nEvery hour.\r\n".into(),
        false,
    ));
    let r = admin.post(&format!("/mailboxes/{mb_id}/poll"), json!({})).await;
    assert_eq!((r["ok"].as_bool(), r["filed"].as_i64()), (Some(true), Some(1)), "{r}");
    assert!(graph.inbox.lock().unwrap()[0].2, "marked read");
    assert_eq!(graph.logins.lock().unwrap()[0].get("scope").map(String::as_str), Some("https://graph.microsoft.com/.default"));
    let r = admin.post(&format!("/mailboxes/{mb_id}/poll"), json!({})).await;
    assert_eq!(r["filed"], 0);
    let gt = admin.get("/tickets?view=all&q=VPN%20drops").await["items"][0].clone();
    assert_eq!(gt["client_id"], a_id, "filed by the sender's domain");
    let gid = gt["id"].as_str().unwrap();
    admin.post(&format!("/tickets/{gid}/events"), json!({ "kind": "reply", "body": "Try the new client." })).await;
    let sent = eventually(30, "the reply sent through Graph", || async { graph.sent.lock().unwrap().first().cloned() }).await;
    assert!(sent.contains("m365@msp.example") && sent.contains(&format!("[T-{}]", gt["number"])), "{sent}");
    assert!(header(&sent, "In-Reply-To").is_some_and(|h| h.contains("graph-1@client-a.example")), "{sent}");
    // A bad secret is reported on the mailbox.
    admin
        .call(
            reqwest::Method::PUT,
            &format!("/mailboxes/{mb_id}"),
            Some(json!({ "name": "M365", "address": "m365@msp.example", "kind": "graph", "board_id": desk_id, "graph_tenant": "e2e-tenant",
                         "graph_client_id": "e2e-client", "graph_secret": "wrong" })),
        )
        .await;
    let r = admin.post(&format!("/mailboxes/{mb_id}/poll"), json!({})).await;
    assert!(r["error"].as_str().unwrap_or_default().contains("Invalid client secret"), "{r}");
    admin.call(reqwest::Method::DELETE, &format!("/mailboxes/{mb_id}"), None).await;
    admin.call(reqwest::Method::DELETE, &format!("/sla/policies/{policy_id}"), None).await;
    println!("portal, SLA, CSAT, teams, canned responses, split, Graph: ok");
}

// ---------------------------------------------------------------------------------------------
// QuickBooks Online and Xero stand-ins
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Default)]
struct AcctMock {
    /// Documents created, as (provider/kind, body).
    docs: std::sync::Arc<std::sync::Mutex<Vec<(String, Value)>>>,
    /// External ids marked paid.
    paid: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

async fn accounting_mock() -> (String, AcctMock) {
    use axum::extract::{Path as P, Query as Q, State as S};
    use axum::http::{HeaderMap, StatusCode as Code};
    use axum::routing::{get, post};
    use std::collections::HashMap;
    let mock = AcctMock::default();
    fn basic(h: &HeaderMap, user: &str, pass: &str) -> bool {
        let want = format!("Basic {}", data_encoding::BASE64.encode(format!("{user}:{pass}").as_bytes()));
        h.get("authorization").and_then(|v| v.to_str().ok()) == Some(want.as_str())
    }
    fn bearer(h: &HeaderMap, tok: &str) -> bool {
        h.get("authorization").and_then(|v| v.to_str().ok()) == Some(format!("Bearer {tok}").as_str())
    }
    let token = |user: &'static str, pass: &'static str, code: &'static str, access: &'static str| {
        move |h: HeaderMap, axum::Form(f): axum::Form<HashMap<String, String>>| async move {
            let ok = basic(&h, user, pass)
                && match f.get("grant_type").map(String::as_str) {
                    Some("authorization_code") => f.get("code").map(String::as_str) == Some(code) && f.contains_key("redirect_uri"),
                    Some("refresh_token") => f.contains_key("refresh_token"),
                    _ => false,
                };
            if ok {
                (Code::OK, axum::Json(json!({ "access_token": access, "refresh_token": "refresh", "expires_in": 3600, "token_type": "Bearer" })))
            } else {
                (Code::BAD_REQUEST, axum::Json(json!({ "error": "invalid_grant" })))
            }
        }
    };
    let app = axum::Router::new()
        .route("/xero/token", post(token("xero-id", "xero-secret", "xero-code", "xero-token")))
        .route("/qbo/token", post(token("qbo-id", "qbo-secret", "qbo-code", "qbo-token")))
        .route(
            "/xero/api/connections",
            get(|h: HeaderMap| async move {
                assert!(bearer(&h, "xero-token"));
                axum::Json(json!([{ "tenantId": "tenant-1", "tenantName": "Demo MSP Ltd" }]))
            }),
        )
        .route(
            "/xero/api/api.xro/2.0/Contacts",
            get(|h: HeaderMap| async move {
                assert_eq!(h.get("xero-tenant-id").unwrap(), "tenant-1");
                axum::Json(json!({ "Contacts": [] }))
            })
            .post(|S(m): S<AcctMock>, h: HeaderMap, axum::Json(b): axum::Json<Value>| async move {
                assert!(bearer(&h, "xero-token"));
                m.docs.lock().unwrap().push(("xero/contact".into(), b.clone()));
                axum::Json(json!({ "Contacts": [{ "ContactID": format!("contact-{}", b["Contacts"][0]["Name"].as_str().unwrap()) }] }))
            }),
        )
        .route(
            "/xero/api/api.xro/2.0/Invoices",
            post(|S(m): S<AcctMock>, h: HeaderMap, axum::Json(b): axum::Json<Value>| async move {
                assert!(bearer(&h, "xero-token"));
                let id = format!("xinv-{}", b["Invoices"][0]["InvoiceNumber"].as_str().unwrap());
                m.docs.lock().unwrap().push(("xero/invoice".into(), b));
                axum::Json(json!({ "Invoices": [{ "InvoiceID": id }] }))
            }),
        )
        .route(
            "/xero/api/api.xro/2.0/Invoices/{id}",
            get(|S(m): S<AcctMock>, P(id): P<String>| async move {
                let paid = m.paid.lock().unwrap().contains(&id);
                axum::Json(json!({ "Invoices": [{ "InvoiceID": id, "Status": if paid { "PAID" } else { "AUTHORISED" } }] }))
            }),
        )
        .route(
            "/qbo/api/v3/company/{realm}/query",
            get(|h: HeaderMap, P(realm): P<String>, Q(q): Q<HashMap<String, String>>| async move {
                assert!(bearer(&h, "qbo-token") && realm == "realm-9");
                assert!(q["query"].starts_with("select Id from Customer where DisplayName = "), "{q:?}");
                axum::Json(json!({ "QueryResponse": {} }))
            }),
        )
        .route(
            "/qbo/api/v3/company/{realm}/{kind}",
            post(|S(m): S<AcctMock>, P((_, kind)): P<(String, String)>, axum::Json(b): axum::Json<Value>| async move {
                m.docs.lock().unwrap().push((format!("qbo/{kind}"), b));
                let key = match kind.as_str() {
                    "customer" => "Customer",
                    "creditmemo" => "CreditMemo",
                    _ => "Invoice",
                };
                axum::Json(json!({ key: { "Id": format!("q{}", m.docs.lock().unwrap().len()) } }))
            }),
        )
        .with_state(mock.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, mock)
}

/// The `state` an authorize URL carries.
fn state_of(url: &str) -> String {
    reqwest::Url::parse(url).unwrap().query_pairs().find(|(k, _)| k == "state").unwrap().1.to_string()
}

/// Roadmap block 6: time, timesheets, contracts and coverage, the invoice run, finalising,
/// PDFs, sending, accounting sync, the portal's invoices, projects, scheduling, client
/// documentation and reports.
async fn billing(url: &str, admin: &Api, tech: &Api, db: &sqlx::PgPool, a_id: &str, b_id: &str) {
    use chrono::Datelike;
    let (smtp_port, mail) = smtp_sink().await;
    admin
        .call(
            reqwest::Method::PUT,
            "/settings/smtp",
            Some(json!({ "host": "127.0.0.1", "port": smtp_port, "security": "none", "from": "Help Desk <help@msp.example>" })),
        )
        .await;
    let today = chrono::Utc::now().date_naive();
    let month_start = today.with_day(1).unwrap();
    let month_end = (month_start + chrono::Months::new(1)) - chrono::Days::new(1);
    let admin_id = admin.get("/auth/me").await["id"].as_str().unwrap().to_string();

    // --- settings, rates, and what technicians can't see ---------------------------------------
    admin
        .call(
            reqwest::Method::PUT,
            "/settings/billing",
            Some(json!({ "currency": "usd", "company_address": "1 Main Street\nSpringfield", "invoice_prefix": "INV-", "invoice_terms_days": 14,
                         "invoice_footer": "Bank transfer to 12-34-56", "default_rate": 10000 })),
        )
        .await;
    assert_eq!(admin.get("/settings/billing").await["next_number"], "INV-1001");
    let types = admin.get("/work-types").await;
    let wt = |n: &str| types.as_array().unwrap().iter().find(|t| t["name"] == n).unwrap()["id"].as_str().unwrap().to_string();
    let (remote, onsite, internal) = (wt("Remote support"), wt("Onsite"), wt("Internal"));
    let mut list: Vec<Value> = types.as_array().unwrap().iter().map(|t| json!({ "id": t["id"], "name": t["name"], "rate": t["rate"], "billable": t["billable"] })).collect();
    for t in &mut list {
        if t["name"] == "Remote support" {
            t["rate"] = 12000.into();
        }
    }
    admin.call(reqwest::Method::PUT, "/work-types", Some(json!({ "types": list }))).await;
    assert!(tech.get("/work-types").await.as_array().unwrap().iter().all(|t| t["rate"].is_null()), "technicians don't see rates");
    for path in ["/invoices", "/contracts", "/billing/rates"] {
        let (s, _) = tech.call(reqwest::Method::GET, path, None).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{path}");
    }
    let (s, _) = tech.call(reqwest::Method::PUT, "/work-types", Some(json!({ "types": [] }))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // --- contracts ------------------------------------------------------------------------------
    let devices_a = admin.get(&format!("/agents?client_id={a_id}&limit=1")).await["total"].as_i64().unwrap();
    let managed = admin
        .post(
            "/contracts",
            json!({ "client_id": a_id, "name": "Managed workstations", "kind": "per_device", "start_date": month_start, "unit_price": 2500,
                    "covered_work_type_ids": [remote], "rate_overrides": [{ "work_type_id": onsite, "rate": 20000 }] }),
        )
        .await;
    assert_eq!(managed["devices"], devices_a);
    let mid = month_start + chrono::Days::new(15);
    admin
        .post("/contracts", json!({ "client_id": a_id, "name": "Backup service", "kind": "recurring", "start_date": mid, "unit_price": 3000,
                                    "items": [{ "description": "Cloud storage (TB)", "quantity_milli": 2000, "unit_price": 1000 }] }))
        .await;
    let block = admin
        .post(
            "/contracts",
            json!({ "client_id": b_id, "name": "10 hours a month", "kind": "block_hours", "start_date": month_start, "unit_price": 90000,
                    "block_minutes": 600, "overage_rate": 15000, "low_balance_minutes": 120, "manager_id": admin_id }),
        )
        .await;
    let block_id = block["id"].as_str().unwrap().to_string();
    let (s, _) = admin.call(reqwest::Method::POST, "/contracts", Some(json!({ "client_id": b_id, "name": "x", "kind": "block_hours", "start_date": month_start }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "block hours need hours");

    // The block is bought on the first run, before any time is approved against it.
    let run_b = admin.post("/invoices/run", json!({ "from": month_start, "to": month_end, "client_ids": [b_id] })).await;
    assert_eq!(run_b["created"].as_array().unwrap().len(), 1);
    let first_b = run_b["created"][0].as_str().unwrap().to_string();
    let inv = admin.get(&format!("/invoices/{first_b}")).await;
    assert_eq!((inv["total"].as_i64(), inv["lines"][0]["kind"].as_str()), (Some(90000), Some("block")));
    assert_eq!(admin.get(&format!("/contracts/{block_id}")).await["balance_minutes"], 600);

    // --- time: by hand, the timer, a ticket note; technicians don't see money -----------------
    let ta = admin.post("/tickets", json!({ "subject": "Billing: printer", "client_id": a_id })).await;
    let ta_id = ta["id"].as_str().unwrap().to_string();
    let tb = admin.post("/tickets", json!({ "subject": "Billing: server move", "client_id": b_id })).await;
    let tb_id = tb["id"].as_str().unwrap().to_string();
    admin.post("/time", json!({ "ticket_id": ta_id, "minutes": 90, "work_type_id": remote, "note": "Reinstalled the driver.", "public": true })).await;
    admin.post("/time", json!({ "ticket_id": ta_id, "minutes": 60, "work_type_id": onsite, "note": "Site visit" })).await;
    admin.post("/time", json!({ "minutes": 30, "work_type_id": internal, "note": "Team meeting" })).await;
    let td = admin.get(&format!("/tickets/{ta_id}")).await;
    assert_eq!(events_of(&td, "time").len(), 2);
    assert!(events_of(&td, "reply").iter().any(|e| e["body"] == "Reinstalled the driver."), "the note went out as a reply too");
    assert!(td["first_response_at"].is_string());
    let started = tech.post("/time/timer/start", json!({ "ticket_id": tb_id, "work_type_id": remote })).await;
    assert!(started["ended_at"].is_null());
    assert_eq!(tech.get("/time/timer").await["id"], started["id"]);
    let stopped = tech.post("/time/timer/stop", json!({ "note": "Quick look" })).await;
    assert_eq!(stopped["minutes"], 1, "at least a minute");
    tech.post("/time", json!({ "ticket_id": tb_id, "minutes": 540, "work_type_id": remote, "note": "Moved the server" })).await;
    tech.post("/time", json!({ "ticket_id": tb_id, "minutes": 119, "work_type_id": remote, "note": "Cabling" })).await;
    let mine = tech.get("/time").await;
    assert_eq!(mine.as_array().unwrap().len(), 3);
    assert!(mine.as_array().unwrap().iter().all(|e| e["rate"].is_null() && e["amount"].is_null()));
    let (s, _) = tech.call(reqwest::Method::GET, &format!("/time?user_id={admin_id}"), None).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "others' time needs time.approve");

    // --- timesheets: submit locks the week; reject reopens it; approve resolves coverage --------
    let week = tech.post("/timesheets/submit", json!({ "week": today })).await;
    assert_eq!(week["status"], "submitted");
    assert_eq!(week["minutes"], 660);
    let entry = mine[0]["id"].as_str().unwrap().to_string();
    let (s, _) = tech.call(reqwest::Method::PUT, &format!("/time/{entry}"), Some(json!({ "note": "late edit" }))).await;
    assert_eq!(s, StatusCode::CONFLICT, "a submitted week is locked");
    let pending = admin.get("/timesheets/pending").await;
    let sheet = pending.as_array().unwrap().iter().find(|t| t["user_name"] == "Tech").unwrap()["id"].as_str().unwrap().to_string();
    admin.post(&format!("/timesheets/{sheet}/reject"), json!({ "note": "Split the cabling" })).await;
    let (s, _) = tech.call(reqwest::Method::PUT, &format!("/time/{entry}"), Some(json!({ "note": "Cabling and patching" }))).await;
    assert!(s.is_success(), "editable again after a rejection");
    tech.post("/timesheets/submit", json!({ "week": today })).await;
    admin.post(&format!("/timesheets/{sheet}/approve"), json!({})).await;
    admin.post("/timesheets/submit", json!({ "week": today })).await;
    let mine_sheet = admin.get("/timesheets").await["timesheet"]["id"].as_str().unwrap().to_string();
    admin.post(&format!("/timesheets/{mine_sheet}/approve"), json!({})).await;
    let entries = admin.get(&format!("/time?ticket_id={tb_id}")).await;
    let cov: Vec<(String, i64)> = entries.as_array().unwrap().iter().map(|e| (e["coverage"].as_str().unwrap().to_string(), e["amount"].as_i64().unwrap())).collect();
    // 1 + 540 + 119 = 660 minutes against a 600-minute bank: 60 minutes over at 150.00/h.
    assert_eq!(cov.iter().map(|c| c.1).sum::<i64>(), 15000, "{cov:?}");
    assert!(cov.iter().all(|c| c.0 == "block"));
    assert_eq!(admin.get(&format!("/contracts/{block_id}")).await["balance_minutes"], 0);
    wait_mail(&mail, "the low-balance warning", |to, data| to.iter().any(|t| t == ADMIN_EMAIL) && data.contains("running low")).await;
    let a_entries = admin.get(&format!("/time?ticket_id={ta_id}")).await;
    let by_type = |n: &str| a_entries.as_array().unwrap().iter().find(|e| e["work_type_name"] == n).unwrap().clone();
    assert_eq!((by_type("Remote support")["coverage"].as_str(), by_type("Remote support")["amount"].as_i64()), (Some("covered"), Some(0)));
    assert_eq!((by_type("Onsite")["coverage"].as_str(), by_type("Onsite")["rate"].as_i64()), (Some("billable"), Some(20000)), "the contract's rate");

    // --- products sold on a ticket ------------------------------------------------------------
    let charger = admin.post("/products", json!({ "sku": "CHG-65", "name": "65W charger", "cost": 2000, "price": 4500 })).await;
    let (s, _) = tech.call(reqwest::Method::POST, "/charges", Some(json!({ "ticket_id": ta_id, "product_id": charger["id"], "unit_price": 1 }))).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "technicians sell at the catalog price");
    tech.post("/charges", json!({ "ticket_id": ta_id, "product_id": charger["id"] })).await;
    assert!(tech.get(&format!("/charges?ticket_id={ta_id}")).await[0]["unit_price"].is_null());

    // --- the invoice run ------------------------------------------------------------------------
    let run = admin.post("/invoices/run", json!({ "from": month_start, "to": month_end })).await;
    let created: Vec<String> = run["created"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    let invoices = admin.get("/invoices?status=draft").await;
    let draft_of = |client: &str| invoices.as_array().unwrap().iter().find(|i| i["client_id"] == client && created.contains(&i["id"].as_str().unwrap().to_string())).unwrap()["id"].as_str().unwrap().to_string();
    let inv_a = draft_of(a_id);
    let inv_b = draft_of(b_id);
    let a = admin.get(&format!("/invoices/{inv_a}")).await;
    let lines = a["lines"].as_array().unwrap();
    let line = |k: &str| lines.iter().filter(|l| l["kind"] == k).cloned().collect::<Vec<_>>();
    assert_eq!(line("devices")[0]["details"]["devices"], devices_a, "{a}");
    assert_eq!(line("devices")[0]["amount"], devices_a * 2500);
    let backup = line("recurring");
    assert_eq!(backup.len(), 2, "fee and item");
    assert!(backup.iter().all(|l| l["description"].as_str().unwrap().contains("prorated")), "{backup:?}");
    assert_eq!(line("time").len(), 1, "covered time isn't billed");
    assert_eq!(line("time")[0]["amount"], 20000);
    assert_eq!(line("product")[0]["amount"], 4500);
    let b = admin.get(&format!("/invoices/{inv_b}")).await;
    assert_eq!(b["lines"].as_array().unwrap().iter().map(|l| l["kind"].as_str().unwrap()).collect::<Vec<_>>(), vec!["overage"], "the block was billed already");
    assert_eq!(b["total"], 15000);
    let again = admin.post("/invoices/run", json!({ "from": month_start, "to": month_end })).await;
    assert!(again["created"].as_array().unwrap().is_empty(), "nothing is billed twice");
    admin.call(reqwest::Method::DELETE, &format!("/invoices/{first_b}"), None).await;
    assert_eq!(admin.get(&format!("/contracts/{block_id}")).await["balance_minutes"], -600, "deleting the draft takes its purchase back");
    let rerun = admin.post("/invoices/run", json!({ "from": month_start, "to": month_end, "client_ids": [b_id] })).await;
    assert_eq!(rerun["created"].as_array().unwrap().len(), 1, "and its cycle can be billed again");
    let rerun_b = rerun["created"][0].as_str().unwrap().to_string();
    admin.call(reqwest::Method::DELETE, &format!("/invoices/{rerun_b}"), None).await;
    // Editing a draft: a manual discount, and taking the product off (it goes back to unbilled).
    let r = admin.post(&format!("/invoices/{inv_a}/lines"), json!({ "description": "Loyalty discount", "quantity_milli": -1000, "unit_price": 1000 })).await;
    let product_line = line("product")[0]["id"].as_str().unwrap().to_string();
    let r2 = admin.call(reqwest::Method::DELETE, &format!("/invoices/{inv_a}/lines/{product_line}"), None).await.1;
    assert_eq!(r2["total"].as_i64().unwrap(), r["total"].as_i64().unwrap() - 4500);
    assert_eq!(admin.get(&format!("/charges?client_id={a_id}&unbilled=true")).await.as_array().unwrap().len(), 1);
    let total_a = r2["total"].as_i64().unwrap();

    // --- finalise: gapless numbers, a frozen PDF ----------------------------------------------------
    let f = admin.post(&format!("/invoices/{inv_a}/finalise"), json!({})).await;
    assert_eq!(f["number"], "INV-1001");
    let (s, _) = admin.call(reqwest::Method::PATCH, &format!("/invoices/{inv_a}"), Some(json!({ "notes": "x" }))).await;
    assert_eq!(s, StatusCode::CONFLICT, "finalised invoices don't change");
    assert_eq!(admin.post(&format!("/invoices/{inv_b}/finalise"), json!({})).await["number"], "INV-1002");
    let res = admin.http.get(format!("{}/invoices/{inv_a}/pdf", admin.base)).send().await.unwrap();
    assert_eq!(res.headers()["content-type"], "application/pdf");
    let pdf = res.bytes().await.unwrap();
    assert!(pdf.starts_with(b"%PDF-1.4"));
    let text = String::from_utf8_lossy(&pdf);
    assert!(text.contains("(INV-1001)") && text.contains("(Client A)") && text.contains("Loyalty discount"), "PDF content");

    // --- send to the billing contact, with the PDF ----------------------------------------------
    let payer = admin
        .post("/contacts", json!({ "client_id": a_id, "name": "Paula Payer", "email": "paula@client-a.example", "is_billing": true, "portal_enabled": true }))
        .await;
    let sent = admin.post(&format!("/invoices/{inv_a}/send"), json!({})).await;
    assert_eq!(sent["to"], json!(["paula@client-a.example"]));
    let raw = wait_mail(&mail, "the invoice email", |to, _| to.iter().any(|t| t == "paula@client-a.example")).await;
    let m = mail_parser::MessageParser::default().parse(raw.as_bytes()).unwrap();
    let att = m.attachments().next().expect("the PDF is attached");
    assert_eq!(att.attachment_name(), Some("INV-1001.pdf"));
    assert!(att.decoded().starts_with(b"%PDF"));
    assert_eq!(admin.get(&format!("/invoices/{inv_a}")).await["status"], "sent");

    // --- the portal: billing contacts see invoices ------------------------------------------------
    admin.post(&format!("/contacts/{}/portal-invite", payer["id"].as_str().unwrap()), json!({})).await;
    let invite = wait_mail(&mail, "Paula's invitation", |to, data| to.iter().any(|t| t == "paula@client-a.example") && data.contains("invited")).await;
    let portal = Api::new(url);
    portal.post("/portal/auth/verify", json!({ "token": token_after(&mail_text(&invite), "/portal/login?token=") })).await;
    assert_eq!(portal.get("/portal/me").await["invoices"], true);
    let pinv = portal.get("/portal/invoices").await;
    assert_eq!(pinv[0]["number"], "INV-1001");
    assert_eq!(pinv[0]["total"], total_a);
    let res = portal.http.get(format!("{}/portal/invoices/{inv_a}/pdf", portal.base)).send().await.unwrap();
    assert!(res.status().is_success() && res.bytes().await.unwrap().starts_with(b"%PDF"));
    let (s, _) = portal.call(reqwest::Method::GET, &format!("/portal/invoices/{inv_b}/pdf"), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "another client's invoice");

    // --- Xero: connect over OAuth, push, pull payment -------------------------------------------
    let acct = ACCT.get().unwrap();
    admin.call(reqwest::Method::PUT, "/billing/accounting/xero", Some(json!({ "client_id": "xero-id", "client_secret": "xero-secret", "settings": { "account_code": "200" } }))).await;
    let c = admin.post("/billing/accounting/xero/connect", json!({})).await;
    let auth = c["url"].as_str().unwrap();
    assert!(auth.contains("/xero/authorize?") && auth.contains("client_id=xero-id") && auth.contains("offline_access"), "{auth}");
    let noredirect = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
    let bad = noredirect.get(format!("{url}/api/billing/accounting/xero/callback?code=xero-code&state=forged")).send().await.unwrap();
    assert!(bad.headers()["location"].to_str().unwrap().contains("accounting_error"));
    let ok = noredirect.get(format!("{url}/api/billing/accounting/xero/callback?code=xero-code&state={}", state_of(auth))).send().await.unwrap();
    assert_eq!(ok.headers()["location"], "/settings/billing?connected=xero");
    let conns = admin.get("/billing/accounting").await;
    let xero = conns.as_array().unwrap().iter().find(|c| c["provider"] == "xero").unwrap();
    assert_eq!((xero["connected"].as_bool(), xero["tenant_name"].as_str()), (Some(true), Some("Demo MSP Ltd")));
    let (sealed,): (bool,) = sqlx::query_as("SELECT sealed FROM accounting_connections WHERE provider = 'xero'").fetch_one(db).await.unwrap();
    assert!(sealed, "tokens and the secret are encrypted at rest");
    let sync = admin.post("/billing/accounting/sync", json!({})).await;
    assert_eq!(sync["pushed"], 2, "{sync}");
    let pushed = acct.docs.lock().unwrap().iter().find(|(k, b)| k == "xero/invoice" && b["Invoices"][0]["InvoiceNumber"] == "INV-1001").cloned().unwrap().1;
    let x = &pushed["Invoices"][0];
    assert_eq!((x["Type"].as_str(), x["Contact"]["ContactID"].as_str(), x["CurrencyCode"].as_str()), (Some("ACCREC"), Some("contact-Client A"), Some("USD")));
    let sum: f64 = x["LineItems"].as_array().unwrap().iter().map(|l| l["LineAmount"].as_f64().unwrap()).sum();
    assert!((sum * 100.0 - total_a as f64).abs() < 0.5, "line amounts add up to the total");
    assert_eq!(admin.get(&format!("/invoices/{inv_a}")).await["external"]["id"], "xinv-INV-1001");
    acct.paid.lock().unwrap().push("xinv-INV-1001".into());
    let sync = admin.post("/billing/accounting/sync", json!({})).await;
    assert_eq!((sync["pushed"].as_i64(), sync["paid"].as_i64()), (Some(0), Some(1)), "{sync}");
    assert_eq!(admin.get(&format!("/invoices/{inv_a}")).await["status"], "paid");

    // --- a credit note, through QuickBooks (connecting it disconnects Xero) -----------------------------
    let cn = admin.post(&format!("/invoices/{inv_b}/credit"), json!({})).await;
    let cn_id = cn["id"].as_str().unwrap().to_string();
    let cnd = admin.get(&format!("/invoices/{cn_id}")).await;
    assert_eq!((cnd["kind"].as_str(), cnd["total"].as_i64(), cnd["credit_of_number"].as_str()), (Some("credit_note"), Some(-15000), Some("INV-1002")));
    assert_eq!(admin.post(&format!("/invoices/{cn_id}/finalise"), json!({})).await["number"], "INV-1003");
    admin.call(reqwest::Method::PUT, "/billing/accounting/qbo", Some(json!({ "client_id": "qbo-id", "client_secret": "qbo-secret", "settings": { "item_id": "7" } }))).await;
    let c = admin.post("/billing/accounting/qbo/connect", json!({})).await;
    let ok = noredirect
        .get(format!("{url}/api/billing/accounting/qbo/callback?code=qbo-code&state={}&realmId=realm-9", state_of(c["url"].as_str().unwrap())))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.headers()["location"], "/settings/billing?connected=qbo");
    let conns = admin.get("/billing/accounting").await;
    assert!(conns.as_array().unwrap().iter().all(|c| c["connected"] == (c["provider"] == "qbo")), "one provider at a time: {conns}");
    let sync = admin.post("/billing/accounting/sync", json!({})).await;
    assert_eq!(sync["pushed"], 1, "{sync}");
    let memo = acct.docs.lock().unwrap().iter().find(|(k, _)| k == "qbo/creditmemo").cloned().expect("a credit memo").1;
    assert_eq!(memo["DocNumber"], "INV-1003");
    assert_eq!(memo["Line"][0]["Amount"].as_f64(), Some(150.0), "credit memos are positive there");
    assert_eq!(memo["Line"][0]["SalesItemLineDetail"]["ItemRef"]["value"], "7");
    let void = admin.call(reqwest::Method::POST, &format!("/invoices/{inv_a}/void"), None).await.0;
    assert_eq!(void, StatusCode::CONFLICT, "a paid invoice can't be voided");

    // --- projects and scheduling -----------------------------------------------------------------
    let p = admin.post("/projects", json!({ "client_id": a_id, "name": "Office move", "budget_minutes": 600, "status": "active" })).await;
    let pid = p["id"].as_str().unwrap().to_string();
    let task = admin.post(&format!("/projects/{pid}/tasks"), json!({ "phase": "Prep", "title": "Label the cables", "estimate_minutes": 120 })).await;
    let tt = admin.post(&format!("/projects/{pid}/tasks/{}/ticket", task["id"].as_str().unwrap()), json!({})).await;
    let tt_id = tt["ticket_id"].as_str().unwrap().to_string();
    // (This week's timesheet is approved; last week's is still open.)
    let last_week = chrono::Utc::now() - chrono::Duration::days(8);
    admin.post("/time", json!({ "ticket_id": tt_id, "minutes": 45, "work_type_id": onsite, "started_at": last_week })).await;
    admin.post("/time", json!({ "project_id": pid, "minutes": 15, "work_type_id": onsite, "started_at": last_week })).await;
    let (s, _) = admin.call(reqwest::Method::POST, "/time", Some(json!({ "project_id": pid, "minutes": 15, "work_type_id": onsite }))).await;
    assert_eq!(s, StatusCode::CONFLICT, "this week is approved");
    let pd = admin.get(&format!("/projects/{pid}")).await;
    assert_eq!((pd["logged_minutes"].as_i64(), pd["estimate_minutes"].as_i64()), (Some(60), Some(120)));
    assert_eq!(pd["task_list"][0]["status"], "doing");
    assert_eq!(pd["burn"][0]["minutes"], 60);
    let tomorrow = chrono::Utc::now() + chrono::Duration::days(1);
    let sch = admin
        .post("/schedule", json!({ "user_id": admin_id, "starts_at": tomorrow, "ends_at": tomorrow + chrono::Duration::hours(2), "ticket_id": tt_id }))
        .await;
    assert_eq!(sch["overlaps"], 0);
    let cal = admin.get(&format!("/schedule?from={}&to={}", url_escape(&chrono::Utc::now().to_rfc3339()), url_escape(&(tomorrow + chrono::Duration::days(1)).to_rfc3339()))).await;
    assert!(cal.as_array().unwrap().iter().any(|e| e["ticket_id"] == tt_id.as_str() && e["project_name"].is_null()));

    // --- reports ----------------------------------------------------------------------------------
    let desk = admin.get(&format!("/reports/service-desk?from={month_start}&to={month_end}")).await;
    assert!(desk["opened"].as_i64() >= Some(3) && desk["sla"]["respond"]["total"].is_number(), "{desk}");
    let util = admin.get(&format!("/reports/utilisation?from={month_start}&to={month_end}")).await;
    let t = util["technicians"].as_array().unwrap().iter().find(|t| t["name"] == "Tech").unwrap().clone();
    assert_eq!(t["logged_minutes"], 660);
    let prof = admin.get(&format!("/reports/profitability?from={month_start}&to={month_end}")).await;
    let pa = prof["clients"].as_array().unwrap().iter().find(|c| c["client_id"] == a_id).unwrap().clone();
    assert_eq!(pa["revenue"], total_a);
    let (s, _) = tech.call(reqwest::Method::GET, "/reports/profitability", None).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // In a full run client A has an offline alert in the period (the monitoring section),
    // which is what made the QBR's offline-hours query fail once.
    let res = admin.http.get(format!("{}/reports/qbr/{a_id}?from={month_start}&to={month_end}", admin.base)).send().await.unwrap();
    let ct = res.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
    if ct != "application/pdf" {
        panic!("QBR: {} {ct}: {}", res.status(), res.text().await.unwrap_or_default());
    }
    let qbr = res.bytes().await.unwrap();
    assert!(String::from_utf8_lossy(&qbr).contains("(Quarterly business review)"));
    let ov = admin.get("/billing/overview").await;
    assert!(ov["currencies"].as_array().unwrap().iter().any(|c| c["currency"] == "USD"), "{ov}");
    println!("time, contracts, invoices, accounting, projects, schedule, reports: ok");
}

/// A user signed in through their own session, with two-factor authentication turned on when
/// `mfa` is set. `client` limits them to one client.
async fn signed_in(url: &str, admin: &Api, email: &str, role: &str, client: Option<&str>, mfa: bool) -> Api {
    let access = match client {
        Some(c) => json!({ "all_clients": false, "client_ids": [c] }),
        None => json!({ "all_clients": true }),
    };
    let mut body = json!({ "email": email, "name": email, "password": "user-password-123", "role": role });
    body.as_object_mut().unwrap().extend(access.as_object().unwrap().clone());
    admin.post("/users", body).await;
    let api = Api::new(url);
    api.post("/auth/login", json!({ "email": email, "password": "user-password-123" })).await;
    if mfa {
        let setup = api.post("/auth/totp/setup", json!({ "password": "user-password-123" })).await;
        api.post("/auth/totp/enable", json!({ "code": totp(setup["secret"].as_str().unwrap()) })).await;
    }
    api
}

/// Client documentation (categories, templates, pages, links, export) and the password vault
/// (encryption at rest, reveal, history, TOTP, who is refused, and that no secret ever shows
/// up outside a reveal).
async fn docs_and_vault(url: &str, admin: &Api, db: &sqlx::PgPool, a_id: &str, b_id: &str) {
    use reqwest::Method;
    let tech = signed_in(url, admin, "docs-tech@e2e.test", "technician", None, true).await;

    // --- categories and templates -----------------------------------------------------------------
    let cats = admin.get("/doc-categories").await;
    let names: Vec<&str> = cats.as_array().unwrap().iter().map(|c| c["name"].as_str().unwrap()).collect();
    assert_eq!(&names[..3], ["Network", "Infrastructure", "Accounts & access"], "seeded, in order: {cats}");
    let cat_id = |cats: &Value, name: &str| cats.as_array().unwrap().iter().find(|c| c["name"] == name).unwrap()["id"].as_str().unwrap().to_string();
    let infra = cat_id(&cats, "Infrastructure");
    let (s, _) = tech.call(Method::POST, "/doc-categories", Some(json!({ "name": "Printers" }))).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "categories are for admins");
    let printers = admin.post("/doc-categories", json!({ "name": "Printers" })).await;
    let printers_id = printers["id"].as_str().unwrap().to_string();
    assert_eq!(printers["position"].as_i64(), Some(names.len() as i64), "new categories go last: {printers}");
    let (s, v) = admin.call(Method::POST, "/doc-categories", Some(json!({ "name": "printers" }))).await;
    assert_eq!((s, v["error"].as_str()), (StatusCode::CONFLICT, Some("there is already a category with that name")));
    let renamed = admin.put(&format!("/doc-categories/{printers_id}"), json!({ "name": "Printers & copiers" })).await;
    assert_eq!(renamed["name"], "Printers & copiers");
    let ordered = admin.put("/doc-categories/order", json!({ "ids": [printers_id] })).await;
    assert_eq!((ordered[0]["id"].as_str(), ordered[0]["position"].as_i64()), (Some(printers_id.as_str()), Some(0)), "{ordered}");
    assert_eq!((ordered[1]["name"].as_str(), ordered[1]["position"].as_i64()), (Some("Network"), Some(1)), "the rest keep their order");

    let templates = tech.get("/doc-templates").await;
    let net = templates.as_array().unwrap().iter().find(|t| t["name"] == "Network overview").cloned().unwrap();
    assert_eq!((net["category"].as_str(), net["body"].is_null()), (Some("Network"), true), "lists carry no bodies: {net}");
    assert_eq!(templates.as_array().unwrap().len(), 9, "the starter set");
    let net = tech.get(&format!("/doc-templates/{}", net["id"].as_str().unwrap())).await;
    let body = net["body"].as_str().unwrap();
    assert!(body.contains("```credential\nlabel: Firewall admin\n```") && body.contains("{{client.name}}") && body.contains("```fields"), "{body}");
    let (s, _) = tech.call(Method::POST, "/doc-templates", Some(json!({ "name": "Printer" }))).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "templates are for admins");
    let t = admin.post("/doc-templates", json!({ "name": "Printer", "category_id": printers_id, "description": "One printer", "body": "# Printer at {{client.name}}" })).await;
    let t_id = t["id"].as_str().unwrap().to_string();
    assert_eq!((t["category"].as_str(), t["body"].as_str()), (Some("Printers & copiers"), Some("# Printer at {{client.name}}")), "{t}");
    let (s, v) = admin.call(Method::POST, "/doc-templates", Some(json!({ "name": "printer" }))).await;
    assert_eq!((s, v["error"].as_str()), (StatusCode::CONFLICT, Some("there is already a template with that name")));
    let (s, v) = admin.call(Method::POST, "/doc-templates", Some(json!({ "name": "Ghost", "category_id": uuid::Uuid::new_v4() }))).await;
    assert_eq!((s, v["error"].as_str()), (StatusCode::BAD_REQUEST, Some("unknown category")));
    let t = admin.put(&format!("/doc-templates/{t_id}"), json!({ "name": "Printer or copier", "category_id": printers_id, "body": "# {{client.name}}" })).await;
    assert_eq!((t["name"].as_str(), t["description"].as_str()), (Some("Printer or copier"), Some("")));
    admin.call(Method::DELETE, &format!("/doc-categories/{printers_id}"), None).await;
    let t = admin.get(&format!("/doc-templates/{t_id}")).await;
    assert_eq!((t["category_id"].is_null(), t["category"].as_str()), (true, Some("")), "deleting a category uncategorises its templates");
    let (s, _) = admin.call(Method::DELETE, &format!("/doc-templates/{t_id}"), None).await;
    assert!(s.is_success());
    assert_eq!(admin.call(Method::GET, &format!("/doc-templates/{t_id}"), None).await.0, StatusCode::NOT_FOUND);

    // --- pages: versions, stale saves, export ------------------------------------------------------
    let doc = admin.post(&format!("/clients/{a_id}/docs"), json!({ "title": "Network", "category_id": infra, "body": "VLAN 10: staff" })).await;
    let doc_id = doc["id"].as_str().unwrap().to_string();
    let opened = doc["updated_at"].clone();
    let saved = admin.put(&format!("/docs/{doc_id}"), json!({ "title": "Network", "category_id": infra, "body": "VLAN 10: staff\nVLAN 20: guests", "expected_updated_at": opened })).await;
    assert_ne!(saved["updated_at"], opened);
    let d = admin.get(&format!("/docs/{doc_id}")).await;
    assert_eq!((d["revisions"].as_i64(), d["body"].as_str()), (Some(1), Some("VLAN 10: staff\nVLAN 20: guests")));
    assert_eq!((d["category"].as_str(), d["category_id"].as_str(), d["updated_at"].clone()), (Some("Infrastructure"), Some(infra.as_str()), saved["updated_at"].clone()));
    let old = admin.get(&format!("/docs/{doc_id}/revisions/{}", d["history"][0]["id"])).await;
    assert_eq!(old["body"], "VLAN 10: staff");
    let (s, v) = tech
        .call(Method::PUT, &format!("/docs/{doc_id}"), Some(json!({ "title": "Network", "body": "overwrite", "expected_updated_at": opened })))
        .await;
    assert_eq!((s, v["error"].as_str()), (StatusCode::CONFLICT, Some("someone else saved this page since you opened it")));
    assert_eq!(admin.get(&format!("/docs/{doc_id}")).await["revisions"], 1, "a refused save keeps nothing");
    let (s, v) = admin.call(Method::POST, &format!("/clients/{a_id}/docs"), Some(json!({ "title": "X", "category_id": uuid::Uuid::new_v4() }))).await;
    assert_eq!((s, v["error"].as_str()), (StatusCode::BAD_REQUEST, Some("unknown category")));
    let res = admin.http.get(format!("{}/docs/{doc_id}/export", admin.base)).send().await.unwrap();
    assert_eq!(res.headers()["content-type"], "text/markdown; charset=utf-8");
    assert!(res.headers()["content-disposition"].to_str().unwrap().starts_with("attachment; filename=\"Network.md\""), "{:?}", res.headers());
    let md = res.text().await.unwrap();
    let updated = chrono::DateTime::parse_from_rfc3339(saved["updated_at"].as_str().unwrap()).unwrap().with_timezone(&chrono::Utc);
    assert_eq!(
        md,
        format!(
            "---\ntitle: \"Network\"\ncategory: \"Infrastructure\"\nclient: \"Client A\"\nupdated: {}\n---\n\nVLAN 10: staff\nVLAN 20: guests",
            updated.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        )
    );

    // --- the vault ---------------------------------------------------------------------------------
    const PW1: &str = "Fw-first-p4ss!";
    const PW2: &str = "Fw-second-p4ss!";
    const NOTE: &str = "Console cable is in the comms cabinet";
    const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    let mut seen = String::new();
    let item = admin
        .post(
            &format!("/clients/{a_id}/vault"),
            json!({ "name": "Firewall admin", "username": "admin", "url": "https://fw.client-a.example", "password": PW1, "notes": NOTE,
                    "totp": format!("otpauth://totp/Client%20A:admin?secret={SECRET}&issuer=Client%20A&algorithm=SHA1&digits=6&period=30") }),
        )
        .await;
    seen += &item.to_string();
    let item_id = item["id"].as_str().unwrap().to_string();
    assert_eq!((item["has_password"].as_bool(), item["has_notes"].as_bool(), item["has_totp"].as_bool()), (Some(true), Some(true), Some(true)), "{item}");
    assert!(item["password_changed_at"].is_string());
    let (s, v) = admin.call(Method::POST, &format!("/clients/{a_id}/vault"), Some(json!({ "name": "Bad", "totp": "not a secret!" }))).await;
    assert_eq!((s, v["error"].as_str()), (StatusCode::BAD_REQUEST, Some("the TOTP secret must be base32 or an otpauth://totp/ URI")));
    let (s, _) = admin.call(Method::POST, &format!("/clients/{a_id}/vault"), Some(json!({ "name": "Bad", "url": "javascript:alert(1)" }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let b_item = admin.post(&format!("/clients/{b_id}/vault"), json!({ "name": "Client B router", "password": "b-router-pass" })).await;
    let b_item_id = b_item["id"].as_str().unwrap().to_string();
    // At rest: sealed, bound to the row and column, under a wrapped per-client key.
    let (pw, notes, secret): (Vec<u8>, Vec<u8>, Vec<u8>) =
        sqlx::query_as("SELECT password, notes, totp_secret FROM vault_items WHERE id = $1::uuid").bind(&item_id).fetch_one(db).await.unwrap();
    for (sealed, plain) in [(&pw, PW1.as_bytes()), (&notes, NOTE.as_bytes())] {
        assert!(!sealed.windows(plain.len()).any(|w| w == plain), "sealed at rest");
    }
    assert_ne!(secret, data_encoding::BASE32_NOPAD.decode(SECRET.as_bytes()).unwrap());
    let (keys,): (i64,) = sqlx::query_as("SELECT count(*) FROM vault_keys WHERE client_id IN ($1::uuid, $2::uuid)").bind(a_id).bind(b_id).fetch_one(db).await.unwrap();
    assert_eq!(keys, 2, "one key per client");
    // A ciphertext moved to another column doesn't open.
    sqlx::query("UPDATE vault_items SET notes = password WHERE id = $1::uuid").bind(&b_item_id).execute(db).await.unwrap();
    let (s, _) = admin.call(Method::POST, &format!("/vault/{b_item_id}/reveal"), Some(json!({ "field": "notes" }))).await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR);
    sqlx::query("UPDATE vault_items SET notes = NULL WHERE id = $1::uuid").bind(&b_item_id).execute(db).await.unwrap();

    let list = admin.get(&format!("/clients/{a_id}/vault")).await;
    seen += &list.to_string();
    assert_eq!(list.as_array().unwrap().len(), 1, "only client A's items: {list}");
    assert_eq!((list[0]["username"].as_str(), list[0]["url"].as_str()), (Some("admin"), Some("https://fw.client-a.example")));

    let res = admin.http.post(format!("{}/vault/{item_id}/reveal", admin.base)).json(&json!({ "field": "password" })).send().await.unwrap();
    assert_eq!(res.headers()["cache-control"], "no-store");
    assert_eq!(res.json::<Value>().await.unwrap()["value"], PW1);
    assert_eq!(admin.post(&format!("/vault/{item_id}/reveal"), json!({ "field": "notes" })).await["value"], NOTE);
    let (n, details): (i64, Option<Value>) = sqlx::query_as(
        "SELECT count(*) OVER (), details FROM audit_log WHERE action = 'vault.reveal' AND target_id = $1::uuid ORDER BY id DESC LIMIT 1",
    )
    .bind(&item_id)
    .fetch_one(db)
    .await
    .unwrap();
    let details = details.unwrap();
    assert_eq!((n, details["field"].as_str(), details["name"].as_str()), (2, Some("notes"), Some("Firewall admin")), "{details}");
    let before = totp(SECRET);
    let code = admin.post(&format!("/vault/{item_id}/totp"), json!({})).await;
    let after = totp(SECRET);
    assert!(code["code"] == before.as_str() || code["code"] == after.as_str(), "{code} vs {before}/{after}");
    assert_eq!((code["digits"].as_i64(), code["period"].as_i64()), (Some(6), Some(30)));
    assert!((1..=30).contains(&code["remaining"].as_i64().unwrap()));
    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM audit_log WHERE action = 'vault.totp' AND target_id = $1::uuid").bind(&item_id).fetch_one(db).await.unwrap();
    assert_eq!(n, 1);

    // Update: absent fields stay, null clears, a new password keeps the old one.
    let upd = admin.put(&format!("/vault/{item_id}"), json!({ "password": PW2, "notes": null })).await;
    seen += &upd.to_string();
    assert_eq!((upd["has_password"].as_bool(), upd["has_notes"].as_bool(), upd["has_totp"].as_bool()), (Some(true), Some(false), Some(true)), "{upd}");
    assert_eq!((upd["name"].as_str(), upd["history"].as_array().unwrap().len()), (Some("Firewall admin"), 1));
    let same = admin.put(&format!("/vault/{item_id}"), json!({ "password": PW2, "username": "root" })).await;
    assert_eq!((same["username"].as_str(), same["history"].as_array().unwrap().len()), (Some("root"), 1), "the same password isn't a change");
    assert_eq!(admin.post(&format!("/vault/{item_id}/reveal"), json!({ "field": "password" })).await["value"], PW2);
    let h = upd["history"][0]["id"].clone();
    assert_eq!(admin.post(&format!("/vault/{item_id}/reveal"), json!({ "history": h })).await["value"], PW1);
    let (s, _) = admin.call(Method::POST, &format!("/vault/{item_id}/reveal"), Some(json!({ "field": "notes" }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "notes were cleared");
    let (s, _) = admin.call(Method::POST, &format!("/vault/{item_id}/reveal"), Some(json!({ "field": "totp_secret" }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "TOTP secrets are never revealed");
    let (details,): (Value,) =
        sqlx::query_as("SELECT details FROM audit_log WHERE action = 'vault.update' AND target_id = $1::uuid ORDER BY id LIMIT 1").bind(&item_id).fetch_one(db).await.unwrap();
    assert_eq!(details["fields"], json!(["password", "notes"]), "{details}");
    let (audit,): (String,) = sqlx::query_as("SELECT coalesce(string_agg(details::text, ' '), '') FROM audit_log WHERE action LIKE 'vault.%'").fetch_one(db).await.unwrap();
    assert!(![PW1, PW2, NOTE, SECRET].iter().any(|x| audit.contains(x)), "no secret in the audit log: {audit}");

    // --- links from pages ---------------------------------------------------------------------------
    let ghost = uuid::Uuid::new_v4();
    let linked = admin
        .post(
            &format!("/clients/{a_id}/docs"),
            json!({ "title": "Firewall", "category_id": cat_id(&cats, "Network"),
                    "body": format!("```credential\nitem: vault:{item_id}\n```\n\nAlso [B's router](vault:{b_item_id}) and [gone](vault:{ghost}).\n\n```credential\nlabel: Switch admin\n```") }),
        )
        .await;
    let linked_id = linked["id"].as_str().unwrap().to_string();
    let d = admin.get(&format!("/docs/{linked_id}")).await;
    seen += &d.to_string();
    let creds: Vec<&str> = d["credentials"].as_array().unwrap().iter().map(|c| c["id"].as_str().unwrap()).collect();
    assert_eq!((creds, d["credentials_hidden"].as_bool()), (vec![item_id.as_str()], Some(false)), "only the same client's item resolves: {d}");
    assert_eq!(d["credentials"][0]["username"], "root");
    let detail = admin.get(&format!("/vault/{item_id}")).await;
    seen += &detail.to_string();
    assert_eq!((detail["docs"].as_i64(), detail["linked_docs"][0]["title"].as_str()), (Some(1), Some("Firewall")), "{detail}");
    assert_eq!(admin.get(&format!("/vault/{b_item_id}")).await["docs"], 0, "another client's item isn't linked");
    seen += &admin.get(&format!("/clients/{a_id}/docs")).await.to_string();
    seen += &tech.get(&format!("/clients/{a_id}/vault")).await.to_string();
    // Saving without the reference drops the link.
    admin.put(&format!("/docs/{linked_id}"), json!({ "title": "Firewall", "body": "No credentials here." })).await;
    assert_eq!(admin.get(&format!("/vault/{item_id}")).await["docs"], 0);
    admin.put(&format!("/docs/{linked_id}"), json!({ "title": "Firewall", "body": format!("[admin](vault:{item_id})") })).await;

    // --- who is refused ------------------------------------------------------------------------------
    let no_mfa = signed_in(url, admin, "vault-nomfa@e2e.test", "technician", None, false).await;
    let readonly = signed_in(url, admin, "vault-readonly@e2e.test", "readonly", None, true).await;
    let scoped = signed_in(url, admin, "vault-scoped@e2e.test", "technician", Some(b_id), true).await;
    for (who, api, status, error) in [
        ("without 2FA", &no_mfa, StatusCode::FORBIDDEN, Some("turn on two-factor authentication to use the vault")),
        ("read-only", &readonly, StatusCode::FORBIDDEN, Some("insufficient permissions")),
        ("scoped to client B", &scoped, StatusCode::NOT_FOUND, None),
    ] {
        for (method, path, body) in [
            (Method::GET, format!("/clients/{a_id}/vault"), None),
            (Method::GET, format!("/vault/{item_id}"), None),
            (Method::POST, format!("/vault/{item_id}/reveal"), Some(json!({ "field": "password" }))),
            (Method::POST, format!("/vault/{item_id}/totp"), Some(json!({}))),
            (Method::PUT, format!("/vault/{item_id}"), Some(json!({ "password": "stolen" }))),
            (Method::DELETE, format!("/vault/{item_id}"), None),
            (Method::POST, format!("/clients/{a_id}/vault"), Some(json!({ "name": "Planted" }))),
        ] {
            let (s, v) = api.call(method.clone(), &path, body).await;
            assert_eq!(s, status, "{who}: {method} {path}: {v}");
            if let Some(e) = error {
                assert_eq!(v["error"], e, "{who}: {method} {path}");
            }
        }
    }
    assert_eq!(scoped.get(&format!("/clients/{b_id}/vault")).await.as_array().unwrap().len(), 1, "their own client's vault works");
    let (s, _) = readonly.call(Method::POST, &format!("/clients/{b_id}/vault"), Some(json!({ "name": "x" }))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    for api in [&no_mfa, &readonly] {
        let d = api.get(&format!("/docs/{linked_id}")).await;
        seen += &d.to_string();
        assert_eq!((d["credentials"].clone(), d["credentials_hidden"].as_bool()), (json!([]), Some(true)), "{d}");
    }
    let still = admin.post(&format!("/vault/{item_id}/reveal"), json!({ "field": "password" })).await;
    assert_eq!(still["value"], PW2, "nothing the refused users sent changed it");

    for s in [PW1, PW2, NOTE, SECRET, "b-router-pass"] {
        assert!(!seen.contains(s), "a secret appeared outside a reveal");
    }

    // Deleting an item leaves the page; the reference no longer resolves.
    admin.call(Method::DELETE, &format!("/vault/{item_id}"), None).await;
    assert_eq!(admin.call(Method::GET, &format!("/vault/{item_id}"), None).await.0, StatusCode::NOT_FOUND);
    let d = admin.get(&format!("/docs/{linked_id}")).await;
    assert_eq!((d["credentials"].clone(), d["body"].as_str()), (json!([]), Some(format!("[admin](vault:{item_id})").as_str())));
    println!("documentation and the vault: ok");
}

/// Documentation pages linked to tickets: link, duplicate, the client rule, unlink, the timeline,
/// both sides' responses, client changes and merges, and who is refused. (That the portal never
/// shows the `doc` events is checked in `portal_and_sla`, which has a portal session.)
async fn ticket_docs(url: &str, admin: &Api, a_id: &str, b_id: &str) {
    use reqwest::Method;
    let tech = signed_in(url, admin, "tdocs-tech@e2e.test", "technician", None, true).await;
    let readonly = signed_in(url, admin, "tdocs-readonly@e2e.test", "readonly", None, true).await;
    let scoped = signed_in(url, admin, "tdocs-scoped@e2e.test", "technician", Some(b_id), true).await;
    let network = admin.get("/doc-categories").await.as_array().unwrap().iter().find(|c| c["name"] == "Network").unwrap()["id"].clone();
    let page = |client: &str, title: &str, category: Value| {
        let (client, title) = (client.to_string(), title.to_string());
        async move { admin.post(&format!("/clients/{client}/docs"), json!({ "title": title, "category_id": category, "body": "Steps." })).await["id"].as_str().unwrap().to_string() }
    };
    let admin_name = admin.get("/auth/me").await["name"].clone();
    let net = page(a_id, "Network overview", network.clone()).await;
    let backup = page(a_id, "Backup runbook", Value::Null).await;
    let b_page = page(b_id, "Client B wiki", Value::Null).await;
    let ticket = |client: &str, subject: &str| {
        let (client, subject) = (client.to_string(), subject.to_string());
        async move { admin.post("/tickets", json!({ "subject": subject, "client_id": client })).await }
    };
    let t1 = ticket(a_id, "VPN down").await;
    let t1_id = t1["id"].as_str().unwrap().to_string();
    let tb_id = ticket(b_id, "Client B printer").await["id"].as_str().unwrap().to_string();

    // Link, twice, and the rules.
    for doc in [&backup, &net, &net] {
        tech.post(&format!("/tickets/{t1_id}/docs"), json!({ "doc_id": doc })).await;
    }
    let (s, v) = tech.call(Method::POST, &format!("/tickets/{t1_id}/docs"), Some(json!({ "doc_id": b_page }))).await;
    assert_eq!((s, v["error"].as_str()), (StatusCode::BAD_REQUEST, Some("the page must belong to the ticket's client")));
    let (s, _) = tech.call(Method::POST, &format!("/tickets/{t1_id}/docs"), Some(json!({ "doc_id": uuid::Uuid::new_v4() }))).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "no such page");
    let (s, v) = scoped.call(Method::POST, &format!("/tickets/{tb_id}/docs"), Some(json!({ "doc_id": net }))).await;
    assert_eq!((s, v["error"].as_str()), (StatusCode::NOT_FOUND, Some("document not found")), "a page of a client they can't see");
    let (s, _) = scoped.call(Method::POST, &format!("/tickets/{t1_id}/docs"), Some(json!({ "doc_id": net }))).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "a ticket they can't see");
    for (method, path, body) in [
        (Method::POST, format!("/tickets/{t1_id}/docs"), Some(json!({ "doc_id": backup }))),
        (Method::DELETE, format!("/tickets/{t1_id}/docs/{net}"), None),
    ] {
        let (s, v) = readonly.call(method.clone(), &path, body).await;
        assert_eq!((s, v["error"].as_str()), (StatusCode::FORBIDDEN, Some("insufficient permissions")), "read-only: {method} {path}");
    }

    // The ticket: pages by title, with category and who saved them; one event per change.
    let d = readonly.get(&format!("/tickets/{t1_id}")).await;
    let titles: Vec<&str> = d["docs"].as_array().unwrap().iter().map(|x| x["title"].as_str().unwrap()).collect();
    assert_eq!(titles, ["Backup runbook", "Network overview"], "{d}");
    let n = &d["docs"][1];
    assert_eq!((n["id"].as_str(), n["category"].as_str(), n["updated_by_name"].as_str()), (Some(net.as_str()), Some("Network"), admin_name.as_str()), "{n}");
    assert!(n["updated_at"].is_string());
    assert_eq!(d["docs"][0]["category"], "", "uncategorised");
    let ev = events_of(&d, "doc");
    assert_eq!(ev.len(), 2, "linking twice is a no-op: {ev:?}");
    assert_eq!(ev[0]["data"], json!({ "doc_id": backup, "title": "Backup runbook", "linked": true }));
    assert_eq!((ev[1]["data"]["title"].as_str(), ev[1]["public"].as_bool(), ev[1]["author_name"].as_str()), (Some("Network overview"), Some(false), Some("tdocs-tech@e2e.test")));

    // The page: the tickets that link it.
    let p = readonly.get(&format!("/docs/{net}")).await;
    assert_eq!(p["tickets"].as_array().unwrap().len(), 1, "{p}");
    let t = &p["tickets"][0];
    assert_eq!((t["id"].as_str(), t["number"].as_i64(), t["subject"].as_str()), (Some(t1_id.as_str()), t1["number"].as_i64(), Some("VPN down")));
    assert_eq!((t["status"].as_str(), t["status_category"].as_str()), (Some("New"), Some("new")), "{t}");
    assert!(t["updated_at"].is_string());
    assert_eq!(admin.get(&format!("/docs/{b_page}")).await["tickets"], json!([]));

    // Unlink.
    let (s, _) = tech.call(Method::DELETE, &format!("/tickets/{t1_id}/docs/{backup}"), None).await;
    assert!(s.is_success());
    let (s, v) = tech.call(Method::DELETE, &format!("/tickets/{t1_id}/docs/{backup}"), None).await;
    assert_eq!((s, v["error"].as_str()), (StatusCode::NOT_FOUND, Some("linked page not found")));
    let d = admin.get(&format!("/tickets/{t1_id}")).await;
    assert_eq!(d["docs"].as_array().unwrap().len(), 1);
    let ev = events_of(&d, "doc");
    assert_eq!(ev.len(), 3);
    assert_eq!(ev[2]["data"], json!({ "doc_id": backup, "title": "Backup runbook", "linked": false }));
    assert_eq!(admin.get(&format!("/docs/{backup}")).await["tickets"], json!([]));

    // Merging moves the links to the surviving ticket.
    let t2_id = ticket(a_id, "VPN down again").await["id"].as_str().unwrap().to_string();
    for doc in [&backup, &net] {
        tech.post(&format!("/tickets/{t2_id}/docs"), json!({ "doc_id": doc })).await;
    }
    let p = admin.get(&format!("/docs/{net}")).await;
    let ids: Vec<&str> = p["tickets"].as_array().unwrap().iter().map(|x| x["id"].as_str().unwrap()).collect();
    assert_eq!(ids, [t2_id.as_str(), t1_id.as_str()], "newest first");
    tech.post(&format!("/tickets/{t2_id}/merge"), json!({ "into": t1_id })).await;
    let d = admin.get(&format!("/tickets/{t1_id}")).await;
    let titles: Vec<&str> = d["docs"].as_array().unwrap().iter().map(|x| x["title"].as_str().unwrap()).collect();
    assert_eq!(titles, ["Backup runbook", "Network overview"], "{d}");
    assert_eq!(admin.get(&format!("/tickets/{t2_id}")).await["docs"], json!([]));
    let p = admin.get(&format!("/docs/{backup}")).await;
    assert_eq!((p["tickets"].as_array().unwrap().len(), p["tickets"][0]["id"].as_str()), (1, Some(t1_id.as_str())), "{p}");

    // Changing the client drops the old client's pages.
    let (s, v) = tech.call(Method::PATCH, &format!("/tickets/{t1_id}"), Some(json!({ "client_id": b_id }))).await;
    assert!(s.is_success(), "{v}");
    assert_eq!(admin.get(&format!("/tickets/{t1_id}")).await["docs"], json!([]));
    assert_eq!(admin.get(&format!("/docs/{net}")).await["tickets"], json!([]));
    tech.post(&format!("/tickets/{t1_id}/docs"), json!({ "doc_id": b_page })).await;
    assert_eq!(scoped.get(&format!("/docs/{b_page}")).await["tickets"][0]["id"], t1_id.as_str(), "client B's page now");

    // Deleting a page drops its links.
    admin.call(Method::DELETE, &format!("/docs/{b_page}"), None).await;
    assert_eq!(admin.get(&format!("/tickets/{t1_id}")).await["docs"], json!([]));
    println!("documentation on tickets: ok");
}

/// The policy migration (0022) on a database with old-model rows in every shape: MSP-wide,
/// client and site policies, OS limits, excluded agents, desktop consent, schedules with run
/// state, open alerts. What applied to each agent before must apply after.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Postgres: see the module docs"]
async fn policy_migration() {
    use std::collections::{BTreeMap, BTreeSet};

    let admin_url = std::env::var("RMM_E2E_DATABASE_URL").expect("set RMM_E2E_DATABASE_URL (see the test's module docs)");
    let db_name = format!("rmm_e2e_mig_{}", uuid::Uuid::new_v4().simple());
    let mut admin_conn = sqlx::PgConnection::connect(&admin_url).await.unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {db_name}"))).execute(&mut admin_conn).await.unwrap();
    let db_url = format!("{}/{db_name}", admin_url.rsplit_once('/').unwrap().0);
    let db = sqlx::PgPool::connect(&db_url).await.unwrap();

    let all = sqlx::migrate!("./migrations");
    let mut before = sqlx::migrate!("./migrations");
    before.migrations = std::borrow::Cow::Owned(all.migrations.iter().filter(|m| m.version < 22).cloned().collect());
    before.run(&db).await.unwrap();

    // --- the old model, in every shape ---------------------------------------------------------------
    let seed = r#"
        UPDATE company_settings SET auto_update_agents = true;
        INSERT INTO clients (id, name, desktop_consent) VALUES
            ('c1000000-0000-4000-8000-000000000000', 'Consent Co', true),
            ('c2000000-0000-4000-8000-000000000000', 'Site Policies Ltd', false),
            ('c3000000-0000-4000-8000-000000000000', 'Plain Inc', false);
        INSERT INTO sites (id, client_id, name) VALUES
            ('51000000-0000-4000-8000-000000000000', 'c1000000-0000-4000-8000-000000000000', 'HQ'),
            ('52000000-0000-4000-8000-00000000000a', 'c2000000-0000-4000-8000-000000000000', 'North'),
            ('52000000-0000-4000-8000-00000000000b', 'c2000000-0000-4000-8000-000000000000', 'South'),
            ('53000000-0000-4000-8000-000000000000', 'c3000000-0000-4000-8000-000000000000', 'Main');
        INSERT INTO agents (id, site_id, secret_hash, hostname, os_family, os_name) VALUES
            ('a1000000-0000-4000-8000-000000000001', '51000000-0000-4000-8000-000000000000', '\x00', 'c1-winsrv', 'windows', 'Windows Server 2022 Standard'),
            ('a1000000-0000-4000-8000-000000000002', '51000000-0000-4000-8000-000000000000', '\x00', 'c1-win11', 'windows', 'Windows 11 Pro'),
            ('a1000000-0000-4000-8000-000000000003', '51000000-0000-4000-8000-000000000000', '\x00', 'c1-mac', 'macos', 'macOS 15'),
            ('a2000000-0000-4000-8000-000000000001', '52000000-0000-4000-8000-00000000000a', '\x00', 'c2n-linux', 'linux', 'Ubuntu 24.04'),
            ('a2000000-0000-4000-8000-000000000002', '52000000-0000-4000-8000-00000000000a', '\x00', 'c2n-win', 'windows', 'Windows 10 Pro'),
            ('a2000000-0000-4000-8000-000000000003', '52000000-0000-4000-8000-00000000000b', '\x00', 'c2s-linux', 'linux', 'Debian 12'),
            ('a2000000-0000-4000-8000-000000000004', '52000000-0000-4000-8000-00000000000b', '\x00', 'c2s-other', 'other', 'FreeBSD 14'),
            ('a3000000-0000-4000-8000-000000000001', '53000000-0000-4000-8000-000000000000', '\x00', 'c3-linux', 'linux', 'Rocky 9'),
            ('a3000000-0000-4000-8000-000000000002', '53000000-0000-4000-8000-000000000000', '\x00', 'c3-win', 'windows', 'Windows Server 2019');
        UPDATE patch_policies SET auto_install = true, deferral_days = 2, auto_approve_severities = '{critical}' WHERE client_id IS NULL;
        INSERT INTO patch_policies (id, client_id, site_id, auto_approve_categories, reboot_policy, deferral_days, auto_install) VALUES
            ('99000000-0000-4000-8000-000000000001', 'c1000000-0000-4000-8000-000000000000', NULL, '{security,driver}', 'if_required', 0, false),
            ('99000000-0000-4000-8000-000000000002', 'c2000000-0000-4000-8000-000000000000', '52000000-0000-4000-8000-00000000000a', '{}', 'always', 7, true);
        UPDATE security_policies SET quick_scan_hours = 12, realtime = 'audit' WHERE client_id IS NULL;
        INSERT INTO security_policies (id, client_id, site_id, sensor_enabled, telemetry_mb, database_max_age_hours) VALUES
            ('98000000-0000-4000-8000-000000000001', 'c1000000-0000-4000-8000-000000000000', NULL, true, 256, 24);
        INSERT INTO security_policies (id, client_id, site_id, prevention, realtime, archive_depth) VALUES
            ('98000000-0000-4000-8000-000000000002', 'c2000000-0000-4000-8000-000000000000', '52000000-0000-4000-8000-00000000000b', true, 'block', 9);
        INSERT INTO notification_channels (id, name, kind, config) VALUES ('cc000000-0000-4000-8000-000000000000', 'ops', 'webhook', '{"url": "http://127.0.0.1:9"}');
        INSERT INTO alert_policies (id, name, kind, params, severity, client_id, site_id, os_family, excluded_agents, channel_ids, enabled, renotify_minutes) VALUES
            ('a0000000-0000-4000-8000-000000000001', 'Offline everywhere', 'offline', '{"minutes": 10}', 'critical', NULL, NULL, NULL, '{}', '{cc000000-0000-4000-8000-000000000000}', true, 60),
            ('a0000000-0000-4000-8000-000000000002', 'Windows CPU', 'cpu', '{"threshold": 90, "minutes": 5}', 'warning', NULL, NULL, 'windows', '{a2000000-0000-4000-8000-000000000002}', '{}', true, NULL),
            ('a0000000-0000-4000-8000-000000000003', 'Consent Co disk', 'disk', '{"threshold": 80, "minutes": 5}', 'warning', 'c1000000-0000-4000-8000-000000000000', NULL, NULL, '{}', '{}', true, NULL),
            ('a0000000-0000-4000-8000-000000000004', 'North services', 'service', '{"services": ["nginx"]}', 'warning', 'c2000000-0000-4000-8000-000000000000', '52000000-0000-4000-8000-00000000000a', NULL, '{}', '{}', true, NULL),
            ('a0000000-0000-4000-8000-000000000005', 'Linux memory (off)', 'memory', '{"threshold": 95, "minutes": 10}', 'info', NULL, NULL, 'linux', '{}', '{}', false, NULL),
            ('a0000000-0000-4000-8000-000000000006', 'Linux disk', 'disk', '{"threshold": 95, "minutes": 10}', 'info', NULL, NULL, 'linux', '{}', '{}', true, NULL),
            ('a0000000-0000-4000-8000-000000000007', 'Mac offline', 'offline', '{"minutes": 30}', 'info', 'c1000000-0000-4000-8000-000000000000', NULL, 'macos', '{}', '{}', true, NULL);
        INSERT INTO alerts (id, policy_id, agent_id, kind, severity, title) VALUES
            ('ae000000-0000-4000-8000-000000000001', 'a0000000-0000-4000-8000-000000000001', 'a3000000-0000-4000-8000-000000000002', 'offline', 'critical', 'Offline for more than 10 minutes'),
            ('ae000000-0000-4000-8000-000000000002', 'a0000000-0000-4000-8000-000000000002', 'a1000000-0000-4000-8000-000000000001', 'cpu', 'warning', 'CPU at or above 90% for 5 minutes');
        INSERT INTO scripts (id, name, interpreter, body) VALUES ('5c000000-0000-4000-8000-000000000000', 'nightly', 'bash', 'true');
        INSERT INTO schedules (id, name, script_id, client_id, site_id, os_family, cron, timezone, args, enabled, next_run_at, last_run_at) VALUES
            ('5d000000-0000-4000-8000-000000000001', 'Linux nightly', '5c000000-0000-4000-8000-000000000000', NULL, NULL, 'linux', '0 3 * * *', 'UTC', '["x"]', true,
             '2030-01-01 03:00+00', '2029-12-31 03:00+00'),
            ('5d000000-0000-4000-8000-000000000002', 'South weekly', '5c000000-0000-4000-8000-000000000000', 'c2000000-0000-4000-8000-000000000000',
             '52000000-0000-4000-8000-00000000000b', NULL, '0 4 * * 1', 'Europe/Berlin', '[]', false, NULL, NULL);
        INSERT INTO jobs (id, agent_id, script_id, interpreter, body, timeout_secs, schedule_id) VALUES
            ('70000000-0000-4000-8000-000000000001', 'a3000000-0000-4000-8000-000000000001', '5c000000-0000-4000-8000-000000000000', 'bash', 'true', 60,
             '5d000000-0000-4000-8000-000000000001');
    "#;
    sqlx::raw_sql(seed).execute(&db).await.unwrap();

    type Snapshot = BTreeMap<String, Value>;
    let patch_sql = "SELECT agent_id::text, jsonb_build_object('sev', auto_approve_severities, 'cat', auto_approve_categories, 'defer', deferral_days,
                            'install', auto_install, 'reboot', reboot_policy) FROM agent_patch_policy";
    let snapshot = |sql: String| {
        let db = db.clone();
        async move { sqlx::query_as::<_, (String, Value)>(sqlx::AssertSqlSafe(sql)).fetch_all(&db).await.unwrap().into_iter().collect::<Snapshot>() }
    };
    let sec_cols = "jsonb_build_object('sensor', p.sensor_enabled, 'quick', p.quick_scan_hours, 'full', p.full_scan_days, 'quarantine', p.auto_quarantine,
                    'prevention', p.prevention, 'canaries', p.canaries, 'mb', p.telemetry_mb, 'realtime', p.realtime, 'write', p.scan_on_write,
                    'depth', p.archive_depth, 'db_age', p.database_max_age_hours)";
    let old_patch = snapshot(patch_sql.into()).await;
    let old_sec = snapshot(format!(
        "SELECT a.id::text, (SELECT {sec_cols} FROM security_policies p
                              WHERE p.site_id = a.site_id OR (p.site_id IS NULL AND p.client_id = s.client_id) OR p.client_id IS NULL
                              ORDER BY (p.site_id IS NOT NULL) DESC, (p.client_id IS NOT NULL) DESC LIMIT 1)
           FROM agents a JOIN sites s ON s.id = a.site_id"
    ))
    .await;
    let old_alerts = snapshot(
        "SELECT a.id::text, coalesce((SELECT jsonb_agg(p.id::text ORDER BY p.id) FROM alert_policies p
                                       WHERE p.enabled AND (p.client_id IS NULL OR p.client_id = s.client_id) AND (p.site_id IS NULL OR p.site_id = a.site_id)
                                         AND (p.os_family IS NULL OR p.os_family = a.os_family) AND NOT (a.id = ANY(p.excluded_agents))), '[]')
           FROM agents a JOIN sites s ON s.id = a.site_id"
            .into(),
    )
    .await;
    let old_schedules = snapshot(
        "SELECT sc.id::text, jsonb_build_object('enabled', sc.enabled, 'next', sc.next_run_at, 'last', sc.last_run_at, 'agents',
                coalesce((SELECT jsonb_agg(a.id::text ORDER BY a.id) FROM agents a JOIN sites s ON s.id = a.site_id
                           WHERE (sc.client_id IS NULL OR s.client_id = sc.client_id) AND (sc.site_id IS NULL OR a.site_id = sc.site_id)
                             AND (sc.os_family IS NULL OR a.os_family = sc.os_family)), '[]'))
           FROM schedules sc"
            .into(),
    )
    .await;
    let old_consent = snapshot("SELECT a.id::text, to_jsonb(c.desktop_consent) FROM agents a JOIN sites s ON s.id = a.site_id JOIN clients c ON c.id = s.client_id".into()).await;
    assert_eq!(old_patch.len(), 9);

    // --- 0022 ----------------------------------------------------------------------------------------------------
    all.run(&db).await.unwrap();

    assert_eq!(snapshot(patch_sql.into()).await, old_patch, "the same patch policy applies to every agent");
    let new_sec = snapshot(format!("SELECT p.agent_id::text, {sec_cols} FROM agent_security_policy p")).await;
    assert_eq!(new_sec, old_sec, "the same sensor policy applies to every agent");
    let new_alerts = snapshot(
        "SELECT a.id::text, coalesce((SELECT jsonb_agg(ap.item_id::text ORDER BY ap.item_id) FROM agent_policy ap
                                       WHERE ap.agent_id = a.id AND ap.module = 'alert' AND ap.enabled), '[]')
           FROM agents a"
            .into(),
    )
    .await;
    assert_eq!(new_alerts, old_alerts, "the same alert policies (same ids) cover every agent");
    let new_schedules = snapshot(
        "SELECT i.id::text, jsonb_build_object('enabled', i.enabled, 'next', ss.next_run_at, 'last', ss.last_run_at, 'agents',
                coalesce((SELECT jsonb_agg(ap.agent_id::text ORDER BY ap.agent_id) FROM agent_policy ap WHERE ap.item_id = i.id), '[]'))
           FROM policy_items i JOIN policy_schedule_state ss ON ss.item_id = i.id WHERE i.module = 'schedule'"
            .into(),
    )
    .await;
    assert_eq!(new_schedules, old_schedules, "schedules keep their targets and run state");
    let new_consent = snapshot(
        "SELECT a.id::text, e.config -> 'desktop_consent' FROM agents a
           JOIN policy_effective e ON e.set_id = a.policy_set_id AND e.item_id = '00000000-0000-4000-8000-000000000003'"
            .into(),
    )
    .await;
    assert_eq!(new_consent, old_consent, "desktop consent per agent");
    let auto: Vec<bool> = sqlx::query_scalar(
        "SELECT (e.config ->> 'auto_update')::boolean FROM agents a JOIN policy_effective e ON e.set_id = a.policy_set_id
          WHERE e.item_id = '00000000-0000-4000-8000-000000000004'",
    )
    .fetch_all(&db)
    .await
    .unwrap();
    assert!(auto.len() == 9 && auto.iter().all(|a| *a), "auto-update carried over");

    // Same alerts open under the same policy ids; foreign keys re-pointed.
    let open: BTreeSet<(String, String)> = sqlx::query_as("SELECT id::text, policy_id::text FROM alerts WHERE resolved_at IS NULL")
        .fetch_all(&db)
        .await
        .unwrap()
        .into_iter()
        .collect();
    assert_eq!(
        open,
        [("ae000000-0000-4000-8000-000000000001", "a0000000-0000-4000-8000-000000000001"), ("ae000000-0000-4000-8000-000000000002", "a0000000-0000-4000-8000-000000000002")]
            .into_iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect()
    );
    let job_schedule: Option<String> = sqlx::query_scalar("SELECT schedule_id::text FROM jobs WHERE id = '70000000-0000-4000-8000-000000000001'").fetch_one(&db).await.unwrap();
    assert_eq!(job_schedule.as_deref(), Some("5d000000-0000-4000-8000-000000000001"));
    let channels: Value = sqlx::query_scalar("SELECT policy_config('a0000000-0000-4000-8000-000000000001', 'a3000000-0000-4000-8000-000000000002') -> 'channel_ids'")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(channels, json!(["cc000000-0000-4000-8000-000000000000"]));

    // Categories by OS and the old server rule; client and site sets assigned where needed.
    let cats: Snapshot = snapshot(
        "SELECT a.hostname, jsonb_build_object('category', dc.name, 'platform', a.platform, 'set', ps.name)
           FROM agents a JOIN device_categories dc ON dc.id = a.category_id JOIN policy_sets ps ON ps.id = a.policy_set_id"
            .into(),
    )
    .await;
    let want = |cat: &str, platform: &str, set: &str| json!({ "category": cat, "platform": platform, "set": set });
    assert_eq!(cats["c1-winsrv"], want("Windows servers", "server", "Consent Co · Windows servers"));
    assert_eq!(cats["c1-win11"], want("Windows workstations", "workstation", "Consent Co · Windows workstations"));
    assert_eq!(cats["c1-mac"], want("macOS workstations", "workstation", "Consent Co · macOS workstations"));
    assert_eq!(cats["c2n-linux"], want("Linux servers", "server", "Site Policies Ltd · North · Linux servers"));
    assert_eq!(cats["c2s-linux"], want("Linux servers", "server", "Site Policies Ltd · South · Linux servers"));
    // 'other' goes to Linux servers; its platform is billing's old guess (not a server).
    assert_eq!(cats["c2s-other"], want("Linux servers", "workstation", "Site Policies Ltd · South · Linux servers"));
    assert_eq!(cats["c3-linux"], want("Linux servers", "server", "Linux servers"));
    assert_eq!(cats["c3-win"], want("Windows servers", "server", "Windows servers"));
    // Only what differs went into the overrides.
    let c1_patch: Value = sqlx::query_scalar(
        "SELECT o.config FROM policy_overrides o JOIN policy_sets ps ON ps.id = o.set_id
          WHERE ps.name = 'Consent Co · Windows servers' AND o.item_id = '00000000-0000-4000-8000-000000000001'",
    )
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(c1_patch, json!({ "auto_approve_severities": [], "auto_approve_categories": ["security", "driver"], "deferral_days": 0,
                                 "auto_install": false, "reboot_policy": "if_required" }));
    // A new agent goes through the trigger: category, platform guess, set.
    sqlx::query(
        "INSERT INTO agents (id, site_id, secret_hash, hostname, os_family, os_name) VALUES
            (gen_random_uuid(), '51000000-0000-4000-8000-000000000000', '\\x00', 'c1-new', 'windows', 'Windows Server 2025')",
    )
    .execute(&db)
    .await
    .unwrap();
    let new_one = snapshot(
        "SELECT a.hostname, jsonb_build_object('category', dc.name, 'platform', a.platform, 'set', ps.name)
           FROM agents a JOIN device_categories dc ON dc.id = a.category_id JOIN policy_sets ps ON ps.id = a.policy_set_id WHERE a.hostname = 'c1-new'"
            .into(),
    )
    .await;
    assert_eq!(new_one["c1-new"], want("Windows servers", "server", "Consent Co · Windows servers"));

    db.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP DATABASE IF EXISTS {db_name} WITH (FORCE)"))).execute(&mut admin_conn).await.unwrap();
    println!("policy migration: ok");
}


// ---------------------------------------------------------------------------------------------
// Single sign-on (OIDC) and passkeys
// ---------------------------------------------------------------------------------------------

/// What the stand-in identity provider puts in the next ID token it issues.
#[derive(Clone)]
struct Scenario {
    sub: String,
    email: Option<String>,
    email_verified: bool,
    name: String,
    groups: Vec<String>,
    aud: Option<String>,
    nonce: Option<String>,
    iss: Option<String>,
    /// Sign with a key that isn't in the JWKS.
    wrong_key: bool,
    expired: bool,
}

impl Scenario {
    fn user(sub: &str, email: &str, groups: &[&str]) -> Scenario {
        Scenario {
            sub: sub.into(),
            email: Some(email.into()),
            email_verified: true,
            name: "Sso Person".into(),
            groups: groups.iter().map(|g| g.to_string()).collect(),
            aud: None,
            nonce: None,
            iss: None,
            wrong_key: false,
            expired: false,
        }
    }
}

struct Issued {
    scenario: Scenario,
    nonce: String,
    challenge: String,
}

struct IdpInner {
    base: String,
    key: ring::signature::EcdsaKeyPair,
    other: ring::signature::EcdsaKeyPair,
    jwks: Value,
    scenario: std::sync::Mutex<Scenario>,
    codes: std::sync::Mutex<std::collections::HashMap<String, Issued>>,
}

type Idp = std::sync::Arc<IdpInner>;

const IDP_CLIENT: &str = "rmm-e2e";
const IDP_SECRET: &str = "s3cret-e2e-client-secret";

fn b64url(b: &[u8]) -> String {
    data_encoding::BASE64URL_NOPAD.encode(b)
}

fn ec_key() -> ring::signature::EcdsaKeyPair {
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
    let rng = ring::rand::SystemRandom::new();
    let pk8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pk8.as_ref(), &rng).unwrap()
}

impl IdpInner {
    fn sign(&self, claims: &Value, wrong_key: bool) -> String {
        use ring::signature::KeyPair;
        let _ = KeyPair::public_key(&self.key);
        let input = format!("{}.{}", b64url(json!({ "alg": "ES256", "kid": "e2e-1", "typ": "JWT" }).to_string().as_bytes()), b64url(claims.to_string().as_bytes()));
        let key = if wrong_key { &self.other } else { &self.key };
        let sig = key.sign(&ring::rand::SystemRandom::new(), input.as_bytes()).unwrap();
        format!("{input}.{}", b64url(sig.as_ref()))
    }
}

/// An OIDC provider on a free port: discovery, JWKS, authorize (which approves at once) and token.
async fn idp_mock() -> Idp {
    use axum::extract::{Query as Q, State as S};
    use axum::http::{HeaderMap, StatusCode as Code};
    use axum::routing::{get, post};
    use ring::signature::KeyPair;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let key = ec_key();
    let point = key.public_key().as_ref().to_vec();
    let jwks = json!({ "keys": [{ "kty": "EC", "crv": "P-256", "kid": "e2e-1", "use": "sig", "alg": "ES256", "x": b64url(&point[1..33]), "y": b64url(&point[33..]) }] });
    let idp: Idp = std::sync::Arc::new(IdpInner {
        base: base.clone(),
        key,
        other: ec_key(),
        jwks,
        scenario: std::sync::Mutex::new(Scenario::user("sub-0", "nobody@e2e.test", &[])),
        codes: Default::default(),
    });
    let app = axum::Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(|S(i): S<Idp>| async move {
                axum::Json(json!({
                    "issuer": i.base, "authorization_endpoint": format!("{}/authorize", i.base), "token_endpoint": format!("{}/token", i.base),
                    "jwks_uri": format!("{}/jwks", i.base), "token_endpoint_auth_methods_supported": ["client_secret_basic"],
                    "id_token_signing_alg_values_supported": ["ES256"], "response_types_supported": ["code"], "subject_types_supported": ["public"],
                }))
            }),
        )
        .route("/jwks", get(|S(i): S<Idp>| async move { axum::Json(i.jwks.clone()) }))
        .route(
            "/authorize",
            get(|S(i): S<Idp>, Q(q): Q<std::collections::HashMap<String, String>>| async move {
                assert_eq!(q["response_type"], "code");
                assert_eq!(q["client_id"], IDP_CLIENT);
                assert_eq!(q["code_challenge_method"], "S256", "PKCE is mandatory");
                assert!(q["scope"].split(' ').any(|s| s == "openid"));
                assert!(!q["nonce"].is_empty() && !q["state"].is_empty());
                let code = hex::encode(rand_bytes());
                i.codes.lock().unwrap().insert(
                    code.clone(),
                    Issued { scenario: i.scenario.lock().unwrap().clone(), nonce: q["nonce"].clone(), challenge: q["code_challenge"].clone() },
                );
                axum::response::Redirect::to(&format!("{}?code={code}&state={}", q["redirect_uri"], q["state"]))
            }),
        )
        .route(
            "/token",
            post(|S(i): S<Idp>, h: HeaderMap, axum::Form(f): axum::Form<std::collections::HashMap<String, String>>| async move {
                let basic = h.get("authorization").and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Basic ")).and_then(|v| data_encoding::BASE64.decode(v.as_bytes()).ok());
                if basic.as_deref() != Some(format!("{IDP_CLIENT}:{IDP_SECRET}").as_bytes()) {
                    return (Code::UNAUTHORIZED, axum::Json(json!({ "error": "invalid_client" })));
                }
                let Some(issued) = i.codes.lock().unwrap().remove(f.get("code").map(String::as_str).unwrap_or("")) else {
                    return (Code::BAD_REQUEST, axum::Json(json!({ "error": "invalid_grant" })));
                };
                if b64url(&sha256_raw(f.get("code_verifier").map(String::as_str).unwrap_or("").as_bytes())) != issued.challenge {
                    return (Code::BAD_REQUEST, axum::Json(json!({ "error": "invalid_grant", "error_description": "PKCE verification failed" })));
                }
                let sc = issued.scenario;
                let now = chrono::Utc::now().timestamp();
                let mut claims = json!({
                    "iss": sc.iss.clone().unwrap_or_else(|| i.base.clone()),
                    "aud": sc.aud.clone().unwrap_or_else(|| IDP_CLIENT.to_string()),
                    "sub": sc.sub, "iat": now, "exp": if sc.expired { now - 3600 } else { now + 300 },
                    "nonce": sc.nonce.clone().unwrap_or(issued.nonce), "name": sc.name, "groups": sc.groups,
                });
                if let Some(e) = &sc.email {
                    claims["email"] = json!(e);
                    claims["email_verified"] = json!(sc.email_verified);
                }
                (Code::OK, axum::Json(json!({ "access_token": "unused", "token_type": "Bearer", "id_token": i.sign(&claims, sc.wrong_key) })))
            }),
        )
        .with_state(idp.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    idp
}

fn rand_bytes() -> [u8; 16] {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).unwrap();
    b
}

fn sha256_raw(b: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    sha2::Sha256::digest(b).to_vec()
}

/// A browser: keeps cookies, follows no redirects by itself.
fn browser() -> reqwest::Client {
    reqwest::Client::builder().cookie_store(true).redirect(reqwest::redirect::Policy::none()).build().unwrap()
}

fn location(r: &reqwest::Response) -> String {
    assert!(r.status().is_redirection(), "expected a redirect, got {} from {}", r.status(), r.url());
    r.headers()["location"].to_str().unwrap().to_string()
}

/// The redirects of one SSO sign-in. Returns (the callback URL the provider sent the browser back
/// to, where the server then sent it).
async fn sso_walk(b: &reqwest::Client, public: &str, provider: &str) -> (String, String) {
    let to_idp = location(&b.get(format!("{public}/api/auth/sso/{provider}/start?next=/agents")).send().await.unwrap());
    let back = location(&b.get(&to_idp).send().await.unwrap());
    let end = location(&b.get(&back).send().await.unwrap());
    (back, end)
}

/// The server, started a second time on the e2e database with a public URL of `localhost`.
struct SsoServer(Child);

impl Drop for SsoServer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn audit_detail(db: &sqlx::PgPool, action: &str) -> Value {
    sqlx::query_scalar("SELECT details FROM audit_log WHERE action = $1 ORDER BY id DESC LIMIT 1").bind(action).fetch_one(db).await.unwrap_or(Value::Null)
}

async fn audit_count(db: &sqlx::PgPool, action: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action = $1").bind(action).fetch_one(db).await.unwrap()
}

async fn sso_and_passkeys(server: &Server, db: &sqlx::PgPool, dir: &Path, admin_totp_secret: &str) {
    use reqwest::Method;
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;
    use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse, Url};

    let port = free_port();
    let public = format!("http://localhost:{port}");
    let log = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("server-sso.log")).unwrap();
    let _guard = SsoServer(
        Command::new(env!("CARGO_BIN_EXE_rmm-server"))
            .env("DATABASE_URL", &server.db_url)
            .env("RMM_BIND", format!("127.0.0.1:{port}"))
            .env("RMM_PUBLIC_URL", &public)
            .env("RMM_WEB_DIR", dir.join("web"))
            .env("RMM_AGENT_DIR", dir.join("agents"))
            .env("RMM_STORAGE_DIR", dir.join("storage"))
            .env("RMM_DATA_KEY", "ab".repeat(32))
            .env("RMM_UPDATE_PUBKEY", content_pubkey())
            .env("RUST_LOG", "info,rmm_server=debug")
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .expect("starting the second rmm-server"),
    );
    wait_healthy(&format!("http://127.0.0.1:{port}")).await;
    let api = |b: reqwest::Client| Api { http: b, base: format!("{public}/api") };

    // The built-in admin signs in here with its authenticator app.
    let admin = api(browser());
    sign_in_with_totp(&admin, admin_totp_secret).await;
    let client_x = admin.post("/clients", json!({ "name": "SSO Client X" })).await["id"].as_str().unwrap().to_string();
    let client_y = admin.post("/clients", json!({ "name": "SSO Client Y" })).await["id"].as_str().unwrap().to_string();

    // --- a provider: validated against the stand-in, secret sealed, never read back -------------------
    let idp = idp_mock().await;
    let provider = |name: &str| {
        json!({ "name": name, "preset": "custom", "issuer": idp.base, "client_id": IDP_CLIENT, "client_secret": IDP_SECRET,
                "jit": true, "group_sync": true, "groups_claim": "groups", "allowed_domains": ["e2e.test"] })
    };
    let (s, v) = admin.call(Method::POST, "/settings/sso/providers", Some(json!({ "name": "Dead", "issuer": "http://127.0.0.1:9", "client_id": "c", "client_secret": "s" }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "an issuer that doesn't answer is refused: {v}");
    let (s, _) = admin.call(Method::POST, "/settings/sso/providers", Some(json!({ "name": "Plain", "issuer": "http://idp.example.com", "client_id": "c", "client_secret": "s" }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "plain http only for localhost");
    let created = admin.post("/settings/sso/providers", provider("Mock IdP")).await;
    let pid = created["id"].as_str().unwrap().to_string();
    let (blob, sealed): (Vec<u8>, bool) = sqlx::query_as("SELECT client_secret, secret_sealed FROM sso_providers WHERE id = $1::uuid").bind(&pid).fetch_one(db).await.unwrap();
    assert!(sealed && !blob.windows(IDP_SECRET.len()).any(|w| w == IDP_SECRET.as_bytes()), "client secrets are encrypted at rest");
    let listing = admin.get("/settings/sso").await;
    assert!(!listing.to_string().contains(IDP_SECRET), "the secret is never returned");
    assert_eq!(listing["providers"][0]["has_secret"], true);
    assert_eq!(listing["redirect_uri"], format!("{public}/api/auth/sso/callback"));
    let test = admin.post(&format!("/settings/sso/providers/{pid}/test"), json!({})).await;
    assert_eq!((test["ok"].clone(), test["keys"].clone()), (json!(true), json!(1)), "{test}");
    admin
        .put(
            &format!("/settings/sso/providers/{pid}/maps"),
            json!([
                { "group_value": "RMM-Admins", "role": "admin" },
                { "group_value": "rmm-techs", "role": "technician", "client_ids": [client_x] },
                { "group_value": "rmm-lead", "role": "technician", "extra_permissions": ["billing.read"], "client_ids": [client_y] },
            ]),
        )
        .await;
    let (s, _) = admin.call(Method::PUT, &format!("/settings/sso/providers/{pid}/maps"), Some(json!([{ "group_value": "x", "role": "technician", "extra_permissions": ["nope"] }]))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let buttons = reqwest::get(format!("{public}/api/auth/sso/providers")).await.unwrap().json::<Value>().await.unwrap();
    assert_eq!(buttons["providers"][0]["name"], "Mock IdP", "the sign-in page lists providers without a session: {buttons}");
    assert!(!buttons.to_string().contains("issuer"), "and only what a button needs");

    // --- JIT sign-in: the account, role and clients come from the groups ---------------------------------
    *idp.scenario.lock().unwrap() = Scenario::user("sub-new", "Newhire@e2e.test", &["rmm-techs", "unrelated"]);
    let b = browser();
    let (_, end) = sso_walk(&b, &public, &pid).await;
    assert_eq!(end, "/agents", "back to where the sign-in began");
    let tech = api(b);
    let me = tech.get("/auth/me").await;
    assert_eq!((me["email"].as_str(), me["role"].as_str(), me["sso_session"].clone(), me["mfa_setup_required"].clone()), (Some("newhire@e2e.test"), Some("technician"), json!(true), json!(false)), "{me}");
    assert_eq!(me["client_ids"], json!([client_x]));
    assert!(tech.get("/agents").await.is_array() || tech.get("/agents").await.is_object());
    let (s, v) = tech.call(Method::GET, &format!("/clients/{client_x}/vault"), None).await;
    assert!(s.is_success(), "the vault wants a second factor, which the identity provider did: {s} {v}");
    let user_id = me["id"].as_str().unwrap().to_string();
    let (only, hash): (bool, String) = sqlx::query_as("SELECT sso_only, password_hash FROM users WHERE id = $1::uuid").bind(&user_id).fetch_one(db).await.unwrap();
    assert!(only && hash.starts_with("$argon2"), "an unusable random password");
    let pw = api(browser());
    let (s, _) = pw.call(Method::POST, "/auth/login", Some(json!({ "email": "newhire@e2e.test", "password": "" }))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(audit_detail(db, "auth.login").await["via"], "sso");
    assert_eq!(audit_count(db, "auth.sso_access_sync").await, 1);

    // --- the next sign-in follows the groups: more clients, a permission, then none at all ------------------
    *idp.scenario.lock().unwrap() = Scenario::user("sub-new", "newhire@e2e.test", &["rmm-techs", "RMM-LEAD"]);
    let b = browser();
    sso_walk(&b, &public, &pid).await;
    let tech = api(b);
    let me = tech.get("/auth/me").await;
    let mut clients: Vec<String> = me["client_ids"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_string()).collect();
    clients.sort();
    let mut want = vec![client_x.clone(), client_y.clone()];
    want.sort();
    assert_eq!(clients, want);
    assert!(me["permissions"].as_array().unwrap().iter().any(|p| p == "billing.read"), "{me}");
    assert!(!me["permissions"].as_array().unwrap().iter().any(|p| p == "billing.manage"));
    *idp.scenario.lock().unwrap() = Scenario::user("sub-new", "newhire@e2e.test", &["rmm-admins"]);
    let b = browser();
    sso_walk(&b, &public, &pid).await;
    let me = api(b).get("/auth/me").await;
    assert_eq!((me["role"].as_str(), me["mfa_setup_required"].clone()), (Some("admin"), json!(false)), "an admin from an SSO session doesn't have to set up TOTP here: {me}");
    *idp.scenario.lock().unwrap() = Scenario::user("sub-new", "newhire@e2e.test", &["somebody-else"]);
    let b = browser();
    let (_, end) = sso_walk(&b, &public, &pid).await;
    assert_eq!(end, "/login?sso_error=not_allowed", "no mapping, no default role");
    let (s, _) = api(b).call(Method::GET, "/auth/me", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "and no session");
    assert_eq!(audit_detail(db, "auth.sso_failed").await["reason"], "no group mapping matches");
    // Someone who used SSO before and is in none of the groups now loses their access.
    let (role, all, n): (String, bool, i64) =
        sqlx::query_as("SELECT role, all_clients, (SELECT count(*) FROM user_clients WHERE user_id = $1::uuid) FROM users WHERE id = $1::uuid").bind(&user_id).fetch_one(db).await.unwrap();
    assert_eq!((role.as_str(), all, n), ("readonly", false, 0), "removed from every group");
    // A first sign-in that matches nothing changes nothing: trying SSO once doesn't demote an account.
    let keep = admin.post("/users", json!({ "email": "keepme@e2e.test", "name": "Keep", "password": "user-password-123", "role": "admin" })).await;
    *idp.scenario.lock().unwrap() = Scenario::user("sub-keep", "keepme@e2e.test", &[]);
    assert_eq!(sso_walk(&browser(), &public, &pid).await.1, "/login?sso_error=not_allowed");
    let (role, links): (String, i64) =
        sqlx::query_as("SELECT role, (SELECT count(*) FROM user_identities WHERE user_id = $1::uuid) FROM users WHERE id = $1::uuid").bind(keep["id"].as_str().unwrap()).fetch_one(db).await.unwrap();
    assert_eq!((role.as_str(), links), ("admin", 0), "still an admin, and not linked");

    // --- linking: only by a verified address, and never over another identity ---------------------------------
    let linked = admin.post("/users", json!({ "email": "linked@e2e.test", "name": "Linked", "password": "user-password-123", "role": "readonly", "all_clients": false, "client_ids": [] })).await;
    let linked_id = linked["id"].as_str().unwrap().to_string();
    let mut sc = Scenario::user("sub-linked", "linked@e2e.test", &["rmm-techs"]);
    sc.email_verified = false;
    *idp.scenario.lock().unwrap() = sc.clone();
    let (_, end) = sso_walk(&browser(), &public, &pid).await;
    assert_eq!(end, "/login?sso_error=not_allowed", "an unverified address links nothing");
    sc.email = None;
    *idp.scenario.lock().unwrap() = sc.clone();
    assert_eq!(sso_walk(&browser(), &public, &pid).await.1, "/login?sso_error=not_allowed", "no address at all");
    sc.email = Some("linked@e2e.test".into());
    sc.email_verified = true;
    *idp.scenario.lock().unwrap() = sc.clone();
    let b = browser();
    assert_eq!(sso_walk(&b, &public, &pid).await.1, "/agents");
    let me = api(b).get("/auth/me").await;
    assert_eq!(me["id"], linked_id.as_str(), "the existing account, not a new one");
    assert_eq!(me["role"], "technician", "group sync applies to linked accounts");
    assert_eq!(audit_count(db, "auth.sso_link").await, 1);
    // The same person again, now by subject alone: a changed address doesn't matter.
    sc.email = Some("renamed@e2e.test".into());
    *idp.scenario.lock().unwrap() = sc.clone();
    let b = browser();
    assert_eq!(sso_walk(&b, &public, &pid).await.1, "/agents");
    assert_eq!(api(b).get("/auth/me").await["id"], linked_id.as_str());
    // A different identity claiming that address can't take the account over.
    let other = Scenario::user("sub-impostor", "linked@e2e.test", &["rmm-admins"]);
    *idp.scenario.lock().unwrap() = other;
    assert_eq!(sso_walk(&browser(), &public, &pid).await.1, "/login?sso_error=not_allowed");
    assert_eq!(audit_detail(db, "auth.sso_failed").await["reason"], "the account is linked to a different identity at this provider");
    // Domains are restricted per provider.
    *idp.scenario.lock().unwrap() = Scenario::user("sub-outsider", "visitor@other.example", &["rmm-admins"]);
    assert_eq!(sso_walk(&browser(), &public, &pid).await.1, "/login?sso_error=not_allowed");
    assert_eq!(audit_detail(db, "auth.sso_failed").await["reason"], "email domain not allowed");
    // A disabled account stays out.
    admin.call(Method::DELETE, &format!("/users/{linked_id}"), None).await;
    *idp.scenario.lock().unwrap() = Scenario::user("sub-linked", "linked@e2e.test", &["rmm-techs"]);
    assert_eq!(sso_walk(&browser(), &public, &pid).await.1, "/login?sso_error=not_allowed");
    assert_eq!(audit_detail(db, "auth.sso_failed").await["reason"], "the account is disabled");

    // --- tokens that must not be accepted ------------------------------------------------------------------
    let base_sc = Scenario::user("sub-new", "newhire@e2e.test", &["rmm-techs"]);
    type Tweak = Box<dyn Fn(&mut Scenario)>;
    let attempts: Vec<(&str, Tweak, &str)> = vec![
        ("bad_nonce", Box::new(|s| s.nonce = Some("replayed-nonce".into())), "bad_nonce"),
        ("bad_audience", Box::new(|s| s.aud = Some("someone-elses-client".into())), "bad_audience"),
        ("bad_issuer", Box::new(|s| s.iss = Some("https://evil.example.com".into())), "bad_issuer"),
        ("expired", Box::new(|s| s.expired = true), "expired"),
        ("bad_signature", Box::new(|s| s.wrong_key = true), "bad_signature"),
    ];
    for (name, tweak, code) in attempts {
        let mut sc = base_sc.clone();
        tweak(&mut sc);
        *idp.scenario.lock().unwrap() = sc;
        let b = browser();
        let (_, end) = sso_walk(&b, &public, &pid).await;
        assert_eq!(end, "/login?sso_error=failed", "{name}");
        let (s, _) = api(b).call(Method::GET, "/auth/me", None).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{name}: no session");
        let reason = audit_detail(db, "auth.sso_failed").await["reason"].as_str().unwrap().to_string();
        assert!(reason.starts_with(code), "{name}: {reason}");
    }
    // A callback is single use, and only for the browser that began it.
    *idp.scenario.lock().unwrap() = base_sc.clone();
    let b = browser();
    let (back, end) = sso_walk(&b, &public, &pid).await;
    assert_eq!(end, "/agents");
    assert_eq!(location(&b.get(&back).send().await.unwrap()), "/login?sso_error=expired", "replayed callback");
    let to_idp = location(&browser().get(format!("{public}/api/auth/sso/{pid}/start")).send().await.unwrap());
    let back = location(&browser().get(&to_idp).send().await.unwrap());
    assert_eq!(location(&browser().get(&back).send().await.unwrap()), "/login?sso_error=failed", "another browser has no binding cookie");
    assert_eq!(audit_detail(db, "auth.sso_failed").await["reason"], "the state cookie doesn't match");
    assert_eq!(location(&browser().get(format!("{public}/api/auth/sso/callback?code=x&state=forged")).send().await.unwrap()), "/login?sso_error=expired");
    // Redirect targets stay on the site.
    let to_idp = location(&b.get(format!("{public}/api/auth/sso/{pid}/start?next=//evil.example.com")).send().await.unwrap());
    let back = location(&b.get(&to_idp).send().await.unwrap());
    assert_eq!(location(&b.get(&back).send().await.unwrap()), "/");

    // --- requiring SSO, with a break-glass admin ------------------------------------------------------------------
    let (s, v) = admin.call(Method::PUT, "/settings/sso", Some(json!({ "required": true }))).await;
    assert_eq!(s, StatusCode::CONFLICT, "nobody could sign in with a password afterwards: {v}");
    let me = admin.get("/auth/me").await;
    admin.post("/users", json!({ "email": "plain@e2e.test", "name": "Plain", "password": "user-password-123", "role": "technician" })).await;
    let bg2 = admin.post("/users", json!({ "email": "bg2@e2e.test", "name": "Second break-glass", "password": "user-password-123", "role": "admin" })).await["id"].as_str().unwrap().to_string();
    admin.put(&format!("/users/{}/sso-exempt", me["id"].as_str().unwrap()), json!({ "exempt": true })).await;
    // A claim from the provider never reaches a break-glass account.
    *idp.scenario.lock().unwrap() = Scenario::user("sub-bg", ADMIN_EMAIL, &["rmm-admins"]);
    assert_eq!(sso_walk(&browser(), &public, &pid).await.1, "/login?sso_error=not_allowed");
    assert_eq!(audit_detail(db, "auth.sso_failed").await["reason"], "break-glass accounts aren't linked by email");
    admin.put("/settings/sso", json!({ "required": true })).await;
    let plain = api(browser());
    let (s, v) = plain.call(Method::POST, "/auth/login", Some(json!({ "email": "plain@e2e.test", "password": "user-password-123" }))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "refused, and in the same words as a wrong password: {v}");
    assert_eq!(v["error"], "not authenticated");
    assert_eq!(audit_detail(db, "auth.login_denied_sso_required").await["ip"], "127.0.0.1");
    let breakglass = api(browser());
    let (s, v) = breakglass.call(Method::POST, "/auth/login", Some(json!({ "email": ADMIN_EMAIL, "password": ADMIN_PASSWORD }))).await;
    assert_eq!((s, v["mfa_required"].clone()), (StatusCode::UNAUTHORIZED, json!(true)), "the password is accepted for a break-glass account, which then asks for its second factor: {v}");
    let me2 = sign_in_with_totp(&breakglass, admin_totp_secret).await;
    assert_eq!(me2["user"]["email"], ADMIN_EMAIL, "the break-glass admin still signs in with a password");
    let (s, _) = admin.call(Method::PUT, &format!("/users/{}/sso-exempt", me["id"].as_str().unwrap()), Some(json!({ "exempt": false }))).await;
    assert_eq!(s, StatusCode::CONFLICT, "the last break-glass admin stays");
    let (s, _) = admin.call(Method::DELETE, &format!("/settings/sso/providers/{pid}"), None).await;
    assert_eq!(s, StatusCode::CONFLICT, "and the last provider");
    // Disabling the last break-glass admin is refused too (the first one may stand down while a second holds).
    admin.put(&format!("/users/{bg2}/sso-exempt"), json!({ "exempt": true })).await;
    admin.put(&format!("/users/{}/sso-exempt", me["id"].as_str().unwrap()), json!({ "exempt": false })).await;
    let (s, v) = admin.call(Method::DELETE, &format!("/users/{bg2}"), None).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    admin.put(&format!("/users/{}/sso-exempt", me["id"].as_str().unwrap()), json!({ "exempt": true })).await;
    admin.put("/settings/sso", json!({ "required": false })).await;
    // Switching the provider off ends the sessions it vouched for.
    *idp.scenario.lock().unwrap() = base_sc.clone();
    let b = browser();
    sso_walk(&b, &public, &pid).await;
    let held = api(b);
    held.get("/auth/me").await;
    let mut off = provider("Mock IdP");
    off["enabled"] = json!(false);
    admin.put(&format!("/settings/sso/providers/{pid}"), off).await;
    let (s, _) = held.call(Method::GET, "/auth/me", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(sso_walk_start_only(&public, &pid).await, "/login?sso_error=provider_error");
    admin.put(&format!("/settings/sso/providers/{pid}"), provider("Mock IdP")).await;
    // A new client id means the subjects it issued mean nothing: links and sessions go.
    let (links,): (i64,) = sqlx::query_as("SELECT count(*) FROM user_identities WHERE provider_id = $1::uuid").bind(&pid).fetch_one(db).await.unwrap();
    assert!(links > 0);
    let mut moved = provider("Mock IdP");
    moved["client_id"] = json!("another-client");
    admin.put(&format!("/settings/sso/providers/{pid}"), moved).await;
    let (links,): (i64,) = sqlx::query_as("SELECT count(*) FROM user_identities WHERE provider_id = $1::uuid").bind(&pid).fetch_one(db).await.unwrap();
    assert_eq!(links, 0);
    let mut moved = provider("Mock IdP");
    moved["issuer"] = json!(format!("{}/another", idp.base));
    moved.as_object_mut().unwrap().remove("client_secret");
    let (s, v) = admin.call(Method::PUT, &format!("/settings/sso/providers/{pid}"), Some(moved)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "a new issuer needs the secret entered again: {v}");
    assert!(v["error"].as_str().unwrap().contains("secret"), "{v}");
    admin.put(&format!("/settings/sso/providers/{pid}"), provider("Mock IdP")).await;

    // --- passkeys ----------------------------------------------------------------------------------------------------
    let origin = Url::parse(&public).unwrap();
    let pk_pw = "user-password-123";
    let mut device = SoftPasskey::new(true);
    let pk = signed_in_at(&public, &admin, "pk@e2e.test", "technician").await;
    // 2FA isn't required for a technician, so nothing changes at sign-in yet.
    let start = pk.post("/auth/passkeys/register/start", json!({ "password": pk_pw })).await;
    let (s, _) = pk.call(Method::POST, "/auth/passkeys/register/start", Some(json!({ "password": "wrong-password-1" }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "registering asks for the password");
    let ccr: CreationChallengeResponse = serde_json::from_value(start["options"].clone()).unwrap();
    let cred = device.do_registration(origin.clone(), ccr).unwrap();
    let vault = format!("/clients/{client_x}/vault");
    assert_eq!(pk.call(Method::GET, &vault, None).await.0, StatusCode::FORBIDDEN, "no second factor yet, no vault");
    let fin = pk.post("/auth/passkeys/register/finish", json!({ "ceremony_id": start["ceremony_id"], "name": "Laptop key", "credential": cred })).await;
    let recovery: Vec<String> = fin["recovery_codes"].as_array().expect("a first factor with no TOTP creates recovery codes").iter().map(|c| c.as_str().unwrap().to_string()).collect();
    assert_eq!(recovery.len(), 10);
    let (s, _) = pk.call(Method::POST, "/auth/passkeys/register/finish", Some(json!({ "ceremony_id": start["ceremony_id"], "name": "again", "credential": cred }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "a ceremony finishes once");
    assert!(pk.call(Method::GET, &vault, None).await.0.is_success(), "a passkey is a second factor for the vault");
    let list = pk.get("/auth/passkeys").await;
    assert_eq!(list["passkeys"][0]["name"], "Laptop key");
    assert_eq!(list["recovery_codes_left"], 10);
    let (stored, ): (Value,) = sqlx::query_as("SELECT passkey FROM user_passkeys WHERE user_id = (SELECT id FROM users WHERE email = 'pk@e2e.test')").fetch_one(db).await.unwrap();
    assert!(!stored.to_string().to_lowercase().contains("private"), "only the public credential is stored");
    let passkey_id = list["passkeys"][0]["id"].as_str().unwrap().to_string();
    pk.call(Method::PATCH, &format!("/auth/passkeys/{passkey_id}"), Some(json!({ "name": "Work laptop" }))).await;
    assert_eq!(pk.get("/auth/passkeys").await["passkeys"][0]["name"], "Work laptop");

    // Signing in now asks for a second factor, and offers the passkey.
    let login = |body: Value| async {
        let b = api(browser());
        let (s, v) = b.call(Method::POST, "/auth/login", Some(body)).await;
        (b, s, v)
    };
    let creds = json!({ "email": "pk@e2e.test", "password": pk_pw });
    let (_, s, v) = login(creds.clone()).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!((v["mfa_required"].clone(), v["methods"].clone()), (json!(true), json!({ "totp": false, "passkey": true })), "{v}");
    let challenge = |email: &str, password: &str| {
        let api = api(browser());
        let (email, password) = (email.to_string(), password.to_string());
        async move { api.call(Method::POST, "/auth/login/passkey", Some(json!({ "email": email, "password": password }))).await }
    };
    assert_eq!(challenge("pk@e2e.test", "wrong").await.0, StatusCode::UNAUTHORIZED, "the challenge is for someone who knows the password");
    let (s, ch) = challenge("pk@e2e.test", pk_pw).await;
    assert!(s.is_success(), "{ch}");
    let rcr: RequestChallengeResponse = serde_json::from_value(ch["options"].clone()).unwrap();
    let assertion = device.do_authentication(origin.clone(), rcr).unwrap();
    let body = json!({ "email": "pk@e2e.test", "password": pk_pw, "passkey": { "ceremony_id": ch["ceremony_id"], "credential": assertion } });
    let (b, s, v) = login(body.clone()).await;
    assert!(s.is_success(), "{v}");
    assert_eq!(b.get("/auth/me").await["email"], "pk@e2e.test");
    let (_, s, _) = login(body).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "an answer can't be replayed");
    let used: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar("SELECT last_used_at FROM user_passkeys WHERE id = $1::uuid").bind(&passkey_id).fetch_one(db).await.unwrap();
    assert!(used.is_some());
    // A challenge answered for another account's ceremony, a wrong password at the last step and a TOTP-shaped code all fail.
    let (_, ch2) = challenge("pk@e2e.test", pk_pw).await;
    let rcr: RequestChallengeResponse = serde_json::from_value(ch2["options"].clone()).unwrap();
    let assertion = device.do_authentication(origin.clone(), rcr).unwrap();
    let (_, s, _) = login(json!({ "email": "pk@e2e.test", "password": "wrong-password", "passkey": { "ceremony_id": ch2["ceremony_id"], "credential": assertion } })).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (_, s, _) = login(json!({ "email": "pk@e2e.test", "password": pk_pw, "code": "123456" })).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "there is no authenticator app to check a code against");
    // Recovery codes still work, once.
    let (b, s, v) = login(json!({ "email": "pk@e2e.test", "password": pk_pw, "code": recovery[0] })).await;
    assert!(s.is_success(), "{v}");
    assert_eq!(b.get("/auth/me").await["email"], "pk@e2e.test");
    let (_, s, _) = login(json!({ "email": "pk@e2e.test", "password": pk_pw, "code": recovery[0] })).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "recovery codes are single use");
    // TOTP beside the passkey; removing TOTP keeps the passkey (and the codes).
    let setup = pk.post("/auth/totp/setup", json!({ "password": pk_pw })).await;
    let secret = setup["secret"].as_str().unwrap().to_string();
    pk.post("/auth/totp/enable", json!({ "code": totp(&secret) })).await;
    let (_, s, v) = login(json!({ "email": "pk@e2e.test", "password": pk_pw })).await;
    assert_eq!((s, v["methods"].clone()), (StatusCode::UNAUTHORIZED, json!({ "totp": true, "passkey": true })));
    // Remove the passkey (password needed): TOTP remains.
    let (s, _) = pk.call(Method::POST, &format!("/auth/passkeys/{passkey_id}/remove"), Some(json!({ "password": "wrong-password-1" }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    pk.post(&format!("/auth/passkeys/{passkey_id}/remove"), json!({ "password": pk_pw })).await;
    assert_eq!(pk.get("/auth/passkeys").await["passkeys"], json!([]));
    let (_, s, v) = login(json!({ "email": "pk@e2e.test", "password": pk_pw })).await;
    assert_eq!((s, v["methods"].clone()), (StatusCode::UNAUTHORIZED, json!({ "totp": true, "passkey": false })));
    let (b, s, _) = login(json!({ "email": "pk@e2e.test", "password": pk_pw, "code": "000000" })).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    drop(b);

    // A required second factor can be a passkey: an admin has nothing but the setup endpoints until one is registered.
    let boss = signed_in_at(&public, &admin, "pk-admin@e2e.test", "admin").await;
    assert_eq!(boss.get("/auth/me").await["mfa_setup_required"], true);
    let (s, _) = boss.call(Method::GET, "/agents", None).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let mut boss_device = SoftPasskey::new(true);
    let start = boss.post("/auth/passkeys/register/start", json!({ "password": pk_pw })).await;
    let ccr: CreationChallengeResponse = serde_json::from_value(start["options"].clone()).unwrap();
    let cred = boss_device.do_registration(origin.clone(), ccr).unwrap();
    boss.post("/auth/passkeys/register/finish", json!({ "ceremony_id": start["ceremony_id"], "name": "Key", "credential": cred })).await;
    assert_eq!(boss.get("/auth/me").await["mfa_setup_required"], false, "a passkey satisfies the requirement");
    boss.get("/agents").await;
    // The admin's reset (lost key) removes passkeys and codes.
    let boss_id = boss.get("/auth/me").await["id"].as_str().unwrap().to_string();
    let (s, _) = admin.call(Method::DELETE, &format!("/users/{boss_id}/totp"), None).await;
    assert!(s.is_success());
    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM user_passkeys WHERE user_id = $1::uuid").bind(&boss_id).fetch_one(db).await.unwrap();
    assert_eq!(n, 0);
    // SSO-only accounts have no password to confirm with, so no passkeys.
    let (s, v) = tech.call(Method::POST, "/auth/passkeys/register/start", Some(json!({ "password": "anything-at-all-1" }))).await;
    assert!(s == StatusCode::UNAUTHORIZED || s == StatusCode::BAD_REQUEST, "{s} {v}");
}

/// The 30-second step of the current time, which a TOTP code is good for once.
fn totp_step() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() / 30
}

static LAST_TOTP_STEP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The built-in admin's password and authenticator code. A code is accepted once per step, so
/// this waits for a step it hasn't used (a wrong code would also count against the sign-in limit).
async fn sign_in_with_totp(api: &Api, secret: &str) -> Value {
    while totp_step() <= LAST_TOTP_STEP.load(std::sync::atomic::Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    LAST_TOTP_STEP.store(totp_step(), std::sync::atomic::Ordering::SeqCst);
    let (s, v) = api.call(reqwest::Method::POST, "/auth/login", Some(json!({ "email": ADMIN_EMAIL, "password": ADMIN_PASSWORD, "code": totp(secret) }))).await;
    assert!(s.is_success(), "the admin's sign-in with a TOTP code: {s} {v}");
    v
}

/// A user the admin creates, signed in on the second server.
async fn signed_in_at(public: &str, admin: &Api, email: &str, role: &str) -> Api {
    admin.post("/users", json!({ "email": email, "name": email, "password": "user-password-123", "role": role, "all_clients": true })).await;
    let api = Api { http: browser(), base: format!("{public}/api") };
    api.post("/auth/login", json!({ "email": email, "password": "user-password-123" })).await;
    api
}

/// `/start` for a provider that is switched off.
async fn sso_walk_start_only(public: &str, provider: &str) -> String {
    location(&browser().get(format!("{public}/api/auth/sso/{provider}/start")).send().await.unwrap())
}
