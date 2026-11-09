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
