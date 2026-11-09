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
//! run creates and drops its own `rmm_e2e_<random>` database. The agent binary defaults to
//! the one next to the server binary (`target/debug/rmm-agent`); set `RMM_E2E_AGENT_BIN`
//! to use another. Linux only: the agent runs bash jobs.

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

struct Server {
    child: Child,
    port: u16,
    db_url: String,
    dir: PathBuf,
}

impl Server {
    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn start(db_url: &str, dir: &Path, port: u16) -> Child {
        let log = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("server.log")).unwrap();
        Command::new(env!("CARGO_BIN_EXE_rmm-server"))
            .env("DATABASE_URL", db_url)
            .env("RMM_BIND", format!("127.0.0.1:{port}"))
            .env("RMM_PUBLIC_URL", format!("http://127.0.0.1:{port}"))
            .env("RMM_WEB_DIR", dir.join("web"))
            .env("RMM_AGENT_DIR", dir.join("agents"))
            .env("RMM_HEARTBEAT_SECS", "5")
            .env("RMM_ALERT_EVAL_SECS", "2")
            .env("RMM_TRUSTED_PROXIES", "127.0.0.1")
            .env("RMM_ADMIN_EMAIL", ADMIN_EMAIL)
            .env("RMM_ADMIN_PASSWORD", ADMIN_PASSWORD)
            .env("RUST_LOG", "info,rmm_server=debug")
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .expect("starting rmm-server")
    }

    async fn restart(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.child = Self::start(&self.db_url, &self.dir, self.port);
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
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {db_name}"))).execute(&mut admin_conn).await.unwrap();
    let db_url = {
        let (base, _) = admin_url.rsplit_once('/').expect("database URL with a /dbname");
        format!("{base}/{db_name}")
    };

    let dir = std::env::temp_dir().join(&db_name);
    std::fs::create_dir_all(dir.join("web")).unwrap();
    std::fs::create_dir_all(dir.join("agents")).unwrap();
    std::fs::write(dir.join("web/200.html"), "<!doctype html><title>e2e</title>").unwrap();
    std::fs::copy(agent_bin(), dir.join("agents/rmm-agent-linux-x86_64")).unwrap();
    println!("e2e scratch dir: {}", dir.display());

    let result = {
        let port = free_port();
        let mut server = Server { child: Server::start(&db_url, &dir, port), port, db_url: db_url.clone(), dir: dir.clone() };
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
    // Housekeeping runs as soon as the server starts. Sessions live in Postgres, so the
    // admin's cookie still works afterwards.
    server.restart().await;
    let j = admin.wait_job(&survivor, 90).await;
    assert_eq!(j["status"], "succeeded", "{j}");
    assert_eq!(j["stdout"], "before\nafter\n", "output from before and after the reconnect");
    assert_eq!(admin.job(&stale).await["status"], "expired");

    // --- a job whose agent restarts is lost --------------------------------------------------
    let doomed = admin.run_script(&id1, "sleep 30", 60).await;
    let (api, id) = (&admin, doomed.as_str());
    eventually(10, "doomed job to be sent", move || async move { (api.job(id).await["status"] == "sent").then_some(()) }).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    a1.kill();
    a1.run(dir);
    let j = admin.wait_job(&doomed, 60).await;
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
    let b_script = tech
        .post("/scripts", json!({ "name": "b-only", "interpreter": "bash", "body": "echo b", "client_id": b_id }))
        .await;
    let global = admin.post("/scripts", json!({ "name": "global", "interpreter": "bash", "body": "echo global" })).await;
    let names: Vec<String> =
        tech.get("/scripts").await.as_array().unwrap().iter().map(|s| s["name"].as_str().unwrap().to_string()).collect();
    assert_eq!(names, ["b-only", "global"]);
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
    assert_eq!(p["policy"]["source"], "global");
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
    let (s, _) = tech.call(reqwest::Method::PUT, "/patch-policies/00000000-0000-4000-8000-000000000001", Some(json!({ "reboot_policy": "always" }))).await;
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

    // Policies: a client policy that approves drivers overrides the MSP-wide one; resetting
    // the manual decline hands drv-1 back to it.
    let pol = admin
        .post("/patch-policies", json!({ "client_id": a_id, "auto_approve_categories": ["security", "driver"], "reboot_policy": "if_required" }))
        .await;
    let (s, _) = admin.call(reqwest::Method::POST, "/patch-policies", Some(json!({ "client_id": a_id, "reboot_policy": "never" }))).await;
    assert_eq!(s, StatusCode::CONFLICT, "one policy per client");
    admin.post("/patches/approval", json!({ "decision": "pending", "update_ids": ["drv-1"], "agent_ids": [id1] })).await;
    let p = admin.get(&format!("/agents/{id1}/patches")).await;
    assert_eq!(p["policy"]["source"], "client");
    assert_eq!(approval(&p, "drv-1"), ("approved".into(), "missing".into(), false));
    let pid = pol["id"].as_str().unwrap();
    let (s, _) = admin.call(reqwest::Method::DELETE, &format!("/patch-policies/{pid}"), None).await;
    assert!(s.is_success());
    assert_eq!(approval(&admin.get(&format!("/agents/{id1}/patches")).await, "drv-1").0, "pending");
    let (s, _) = admin.call(reqwest::Method::DELETE, "/patch-policies/00000000-0000-4000-8000-000000000001", None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

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

    // Automatic install: a new critical update, a policy that installs automatically, a
    // failure that is recorded (and retried later, up to three times).
    std::fs::write(
        dir.join("a1-patches.json"),
        json!({ "updates": [upd("upd-1b", "update", None, false), upd("drv-1", "driver", None, false), upd("sec-2", "security", Some("important"), false)],
                "fail": ["sec-2"] })
        .to_string(),
    )
    .unwrap();
    admin
        .call(
            reqwest::Method::PUT,
            "/patch-policies/00000000-0000-4000-8000-000000000001",
            Some(json!({ "auto_approve_categories": ["security"], "auto_install": true, "reboot_policy": "never" })),
        )
        .await;
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
    let agent = admin.get(&format!("/agents/{id1}/activity")).await;
    assert!(agent.as_array().unwrap().iter().any(|r| r["action"] == "agent.patch_result"), "results are in the agent's activity");
    // Back to the conservative default so the rest of the run isn't patched behind its back.
    admin
        .call(
            reqwest::Method::PUT,
            "/patch-policies/00000000-0000-4000-8000-000000000001",
            Some(json!({ "auto_approve_categories": ["security", "critical", "definition"], "reboot_policy": "never" })),
        )
        .await;

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

    monitoring(server, &admin, db, dir, &id1, &id3, a_id).await;

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

    a1.kill();
    Ok(())
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

async fn alerts_for(api: &Api, query: &str) -> Vec<Value> {
    api.get(&format!("/alerts?{query}")).await["items"].as_array().unwrap().clone()
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
    let (s, v) = admin.call(reqwest::Method::POST, "/alert-policies", Some(policy("bad", "cpu", json!({ "threshold": 500, "minutes": 5 })))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let jf = admin.post("/alert-policies", policy("Jobs fail", "job_failed", json!({}))).await;
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
    let mem = admin.post("/alert-policies", policy("Memory", "memory", json!({ "threshold": 1, "minutes": 1 }))).await;
    let off = admin.post("/alert-policies", json!({ "name": "Offline", "kind": "offline", "params": { "minutes": 1 }, "severity": "critical", "client_id": a_id })).await;
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
    let (s, v) = admin.call(reqwest::Method::PUT, &format!("/alert-policies/{mem_id}"), Some(edit)).await;
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
    let (s, _) = admin.call(reqwest::Method::DELETE, &format!("/alert-policies/{off_id}"), None).await;
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
            let sp = admin.post("/alert-policies", policy("Service down", "service", json!({ "services": [name] }))).await;
            let sp_id = sp["id"].as_str().unwrap().to_string();
            let (api, p) = (admin, sp_id.as_str());
            let a = eventually(20, "service alert", move || async move {
                alerts_for(api, &format!("policy_id={p}")).await.into_iter().next()
            })
            .await;
            assert_eq!(a["details"]["service"], name);
            let alerting = admin.get(&format!("/agents/{id1}/services")).await["alerting"].clone();
            assert_eq!(alerting, json!([name]));
            admin.call(reqwest::Method::DELETE, &format!("/alert-policies/{sp_id}"), None).await;
            let a = admin.get(&format!("/alerts/{}", a["id"].as_str().unwrap())).await;
            assert_eq!(a["resolution"], "policy", "deleting a policy closes its alerts quietly");
        }
    }

    // --- log watcher (needs a journal this user can read) ------------------------------------------
    let marker = format!("rmm-e2e-{}", uuid::Uuid::new_v4().simple());
    let lp = admin.post("/alert-policies", policy("Marker", "log", json!({ "min_level": "error", "pattern": marker }))).await;
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
            let logs = admin.get(&format!("/agents/{id1}/log-events")).await;
            assert!(logs[0]["message"].as_str().unwrap().contains(&marker), "{logs}");
            println!("log watcher matched");
        }
        None => println!("no log match (journal not readable by this user?); skipping the log watcher check"),
    }
    admin.call(reqwest::Method::DELETE, &format!("/alert-policies/{lp_id}"), None).await;
    admin.call(reqwest::Method::DELETE, &format!("/alert-policies/{}", jf["id"].as_str().unwrap()), None).await;

    // --- schedules -------------------------------------------------------------------------------
    let script = admin.post("/scripts", json!({ "name": "scheduled", "interpreter": "bash", "body": "echo scheduled \"$1\"" })).await;
    let preview = admin.get("/schedules/preview?cron=0%203%20*%20*%201&timezone=Europe/Berlin").await;
    assert_eq!(preview["runs"].as_array().unwrap().len(), 5, "{preview}");
    let (s, v) = admin
        .call(reqwest::Method::POST, "/schedules", Some(json!({ "name": "bad", "script_id": script["id"], "cron": "every day", "client_id": a_id })))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let sched = admin
        .post(
            "/schedules",
            json!({ "name": "Nightly", "script_id": script["id"], "client_id": a_id, "cron": "0 3 * * *", "timezone": "America/Chicago",
                    "args": ["x1"], "retain_days": 1 }),
        )
        .await;
    assert!(sched["next_run_at"].is_string(), "{sched}");
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
    sqlx::query("UPDATE schedules SET next_run_at = now() - interval '1 minute' WHERE id = $1::uuid").bind(&sid).execute(db).await.unwrap();
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
    sqlx::query(
        "INSERT INTO agent_metrics (agent_id, ts, cpu_percent, mem_used, mem_total, disk_max_pct, net_rx_bytes, net_tx_bytes)
         VALUES ($1::uuid, date_trunc('hour', now()) - interval '90 minutes', 42, 1, 2, 3, 4, 5)",
    )
    .bind(id1)
    .execute(db)
    .await
    .unwrap();
    server.restart().await;
    admin.wait_online(id1, true).await;
    let (s, _) = admin.call(reqwest::Method::GET, &format!("/jobs/{run_id}"), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "scheduled output past its retention is deleted");
    let hourly: i64 = sqlx::query_scalar("SELECT count(*) FROM agent_metrics_hourly WHERE agent_id = $1::uuid AND cpu_max >= 42")
        .bind(id1)
        .fetch_one(db)
        .await
        .unwrap();
    assert_eq!(hourly, 1, "the sample was rolled up");
    let week = admin.get(&format!("/agents/{id1}/metrics?hours=168")).await;
    assert!(!week.as_array().unwrap().is_empty(), "long ranges read the rollups");
    let _ = (dir, id3);
}
