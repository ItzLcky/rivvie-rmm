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
    assert_eq!(tech.get("/agents").await.as_array().unwrap().len(), 0, "client A's agents are hidden");
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
