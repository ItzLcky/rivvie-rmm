//! End-to-end on Windows: the real server, and the agent installed from the generated MSI as a
//! real Windows service. Runs in CI on `windows-latest` (elevated, with PostgreSQL installed);
//! on a workstation it changes the machine (installs and removes the RmmAgent service), so
//! only run it on a throwaway VM:
//!
//! ```powershell
//! cargo build -p rmm-agent
//! $env:RMM_E2E_DATABASE_URL = "postgres://postgres:root@localhost:5432/postgres"
//! cargo test -p rmm-server --test e2e_windows -- --ignored --nocapture
//! ```
//!
//! It covers what the Linux suite can't: the MSI (install, upgrade over itself, uninstall),
//! the service and its recovery settings, the `C:\ProgramData\RMM` ACL, PowerShell and cmd
//! jobs, Job Objects killing a timed-out script's whole tree, job results surviving a
//! service restart, and the service list.
#![cfg(windows)]

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

fn agent_bin() -> PathBuf {
    if let Some(p) = std::env::var_os("RMM_E2E_AGENT_BIN") {
        return p.into();
    }
    let mut p = PathBuf::from(env!("CARGO_BIN_EXE_rmm-server"));
    p.set_file_name("rmm-agent.exe");
    assert!(p.exists(), "build the agent first (cargo build -p rmm-agent), or set RMM_E2E_AGENT_BIN");
    p
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

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
        tokio::time::sleep(Duration::from_millis(500)).await;
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
        (status, res.json::<Value>().await.unwrap_or(Value::Null))
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

    async fn run(&self, interpreter: &str, agent: &str, body: &str, timeout: i32) -> String {
        let v = self.post("/jobs", json!({ "agent_ids": [agent], "interpreter": interpreter, "body": body, "timeout_secs": timeout })).await;
        v["jobs"][0]["job_id"].as_str().unwrap().to_string()
    }

    async fn job(&self, id: &str) -> Value {
        self.get(&format!("/jobs/{id}")).await
    }

    async fn wait_job(&self, id: &str, secs: u64) -> Value {
        eventually(secs, &format!("job {id} to finish"), || async {
            let j = self.job(id).await;
            (!matches!(j["status"].as_str(), Some("queued" | "sent"))).then_some(j)
        })
        .await
    }

    async fn agents(&self) -> Vec<Value> {
        self.get("/agents").await["items"].as_array().cloned().unwrap_or_default()
    }
}

/// Runs a command, returning (success, stdout + stderr).
fn sh(program: &str, args: &[&str]) -> (bool, String) {
    let out = Command::new(program).args(args).output().unwrap_or_else(|e| panic!("running {program}: {e}"));
    (out.status.success(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

fn powershell(script: &str) -> (bool, String) {
    sh("powershell.exe", &["-NoProfile", "-NonInteractive", "-Command", script])
}

/// msiexec, waiting for it, with a verbose log in `dir`. 3010 = success, reboot required.
fn msiexec(dir: &Path, args: &[&str], log: &str) {
    let log = dir.join(log);
    let status = Command::new("msiexec.exe").args(args).arg("/qn").arg("/l*v").arg(&log).status().unwrap();
    let code = status.code().unwrap_or(-1);
    if code != 0 && code != 3010 {
        let text = std::fs::read(&log).map(|b| decode_log(&b)).unwrap_or_default();
        let tail: String = text.lines().rev().take(80).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("\n");
        panic!("msiexec {args:?} exited with {code}; end of its log:\n{tail}");
    }
}

/// msiexec writes UTF-16 logs.
fn decode_log(b: &[u8]) -> String {
    if b.len() >= 2 && b[0] == 0xff && b[1] == 0xfe {
        let units: Vec<u16> = b[2..].as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(b).into_owned()
    }
}

fn service_state() -> Option<String> {
    let (ok, out) = sh("sc.exe", &["query", "RmmAgent"]);
    if !ok {
        return None;
    }
    out.lines().find(|l| l.contains("STATE")).map(|l| l.split_whitespace().last().unwrap_or_default().to_string())
}

/// Processes whose command line contains `marker` (other than this query itself).
fn processes_with(marker: &str) -> usize {
    let (_, out) = powershell(&format!(
        "@(Get-CimInstance Win32_Process | Where-Object {{ $_.CommandLine -like '*{marker}*' -and $_.ProcessId -ne $PID }}).Count"
    ));
    out.trim().parse().unwrap_or(0)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "installs the agent service on this machine; see the module docs"]
async fn windows_end_to_end() {
    let admin_url = std::env::var("RMM_E2E_DATABASE_URL").expect("set RMM_E2E_DATABASE_URL (see the test's module docs)");
    let db_name = format!("rmm_e2e_{}", uuid::Uuid::new_v4().simple());
    let mut admin_conn = sqlx::PgConnection::connect(&admin_url).await.expect("connecting to RMM_E2E_DATABASE_URL");
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {db_name}"))).execute(&mut admin_conn).await.unwrap();
    let db_url = {
        let (base, _) = admin_url.rsplit_once('/').unwrap();
        format!("{base}/{db_name}")
    };
    let dir = std::env::temp_dir().join(&db_name);
    std::fs::create_dir_all(dir.join("web")).unwrap();
    std::fs::create_dir_all(dir.join("agents")).unwrap();
    std::fs::write(dir.join("web/200.html"), "<!doctype html><title>e2e</title>").unwrap();
    std::fs::copy(agent_bin(), dir.join("agents/rmm-agent-windows-x86_64.exe")).unwrap();
    println!("e2e scratch dir: {}", dir.display());

    let port = free_port();
    let url = format!("http://127.0.0.1:{port}");
    let log = std::fs::File::create(dir.join("server.log")).unwrap();
    let mut server: Child = Command::new(env!("CARGO_BIN_EXE_rmm-server"))
        .env("DATABASE_URL", &db_url)
        .env("RMM_BIND", format!("127.0.0.1:{port}"))
        .env("RMM_PUBLIC_URL", &url)
        .env("RMM_WEB_DIR", dir.join("web"))
        .env("RMM_AGENT_DIR", dir.join("agents"))
        .env("RMM_STORAGE_DIR", dir.join("storage"))
        .env("RMM_HEARTBEAT_SECS", "5")
        .env("RMM_ADMIN_EMAIL", ADMIN_EMAIL)
        .env("RMM_ADMIN_PASSWORD", ADMIN_PASSWORD)
        .env("RMM_DATA_KEY", "ab".repeat(32))
        .env("RUST_LOG", "info,rmm_server=debug")
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .stdin(Stdio::null())
        .spawn()
        .expect("starting rmm-server");

    let result = tokio::spawn(run(url, dir.clone())).await;

    // Leave the machine as we found it, whatever happened.
    if service_state().is_some() {
        let msi = dir.join("rmm-agent.msi");
        if msi.exists() {
            let _ = Command::new("msiexec.exe").arg("/x").arg(&msi).args(["/qn"]).status();
        }
        let _ = sh("sc.exe", &["stop", "RmmAgent"]);
        let _ = sh("sc.exe", &["delete", "RmmAgent"]);
    }
    let _ = server.kill();
    let _ = server.wait();
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP DATABASE IF EXISTS {db_name} WITH (FORCE)")))
        .execute(&mut admin_conn)
        .await
        .unwrap();
    if let Err(e) = result {
        std::panic::resume_unwind(e.into_panic());
    }
}

async fn run(url: String, dir: PathBuf) {
    eventually(60, "server healthy", || async {
        reqwest::get(format!("{url}/healthz")).await.ok().filter(|r| r.status().is_success()).map(|_| ())
    })
    .await;
    let http = reqwest::Client::new();
    let admin = Api::new(&url);
    admin.post("/auth/login", json!({ "email": ADMIN_EMAIL, "password": ADMIN_PASSWORD })).await;
    let setup = admin.post("/auth/totp/setup", json!({ "password": ADMIN_PASSWORD })).await;
    admin.post("/auth/totp/enable", json!({ "code": totp(setup["secret"].as_str().unwrap()) })).await;
    let client = admin.post("/clients", json!({ "name": "Windows e2e" })).await;
    let site = client["default_site_id"].as_str().unwrap();

    // --- install from the MSI -----------------------------------------------------------------
    let token = admin.post(&format!("/sites/{site}/enrollment-tokens"), json!({ "purpose": "package" })).await;
    let msi_url = token["windows_packages"]["msi"].as_str().expect("MSI link (is the Windows agent in RMM_AGENT_DIR?)");
    let msi = dir.join("rmm-agent.msi");
    let res = http.get(msi_url).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    std::fs::write(&msi, res.bytes().await.unwrap()).unwrap();
    msiexec(&dir, &["/i", msi.to_str().unwrap()], "install.log");

    let program_files = PathBuf::from(std::env::var("ProgramFiles").unwrap()).join("RMM").join("rmm-agent.exe");
    assert!(program_files.exists(), "the MSI installed {}", program_files.display());
    assert_eq!(service_state().as_deref(), Some("RUNNING"), "the service is running after install");
    let (_, qc) = sh("sc.exe", &["qfailure", "RmmAgent"]);
    assert!(qc.contains("RESTART"), "SCM restarts the agent on failure: {qc}");

    let agent = eventually(60, "the agent to enroll and come online", || async {
        admin.agents().await.into_iter().find(|a| a["online"] == true)
    })
    .await;
    let id = agent["id"].as_str().unwrap().to_string();
    println!("agent {id} online ({})", agent["os"]);

    // The data directory holds the agent secret: SYSTEM and Administrators only.
    let data = PathBuf::from(std::env::var("ProgramData").unwrap()).join("RMM");
    let (_, acl) = sh("icacls.exe", &[data.to_str().unwrap()]);
    assert!(!acl.contains("BUILTIN\\Users") && !acl.contains("Everyone") && !acl.contains("Authenticated Users"), "{acl}");
    assert!(data.join("logs").join("agent.log").exists(), "the service logs to a file");
    let install_log = std::fs::read_to_string(data.join("logs").join("install.log")).unwrap_or_default();
    assert!(install_log.contains("ok: enrolled as"), "{install_log}");

    // --- jobs ------------------------------------------------------------------------------------
    let j = admin.run("powershell", &id, "Write-Output 'hello from powershell'; [Console]::Error.WriteLine('oops'); exit 3", 60).await;
    let j = admin.wait_job(&j, 90).await;
    assert_eq!(j["status"], "failed", "{j}");
    assert_eq!(j["exit_code"], 3, "{j}");
    assert!(j["stdout"].as_str().unwrap().contains("hello from powershell"), "{j}");
    assert!(j["stderr"].as_str().unwrap().contains("oops"), "{j}");

    let j = admin.run("cmd", &id, "@echo off\necho hello from cmd\nver", 60).await;
    let j = admin.wait_job(&j, 60).await;
    assert_eq!(j["status"], "succeeded", "{j}");
    assert!(j["stdout"].as_str().unwrap().contains("hello from cmd"), "{j}");

    // A timeout kills the whole tree (Job Object), not just the interpreter.
    let marker = format!("rmm-e2e-{}", uuid::Uuid::new_v4().simple());
    let script = format!(
        "Start-Process powershell.exe -NoNewWindow -ArgumentList '-NoProfile','-Command','Start-Sleep 600 # {marker}'\n\
         Write-Output started\nStart-Sleep 600"
    );
    let j = admin.run("powershell", &id, &script, 8).await;
    eventually(60, "the grandchild to start", || async { (processes_with(&marker) > 0).then_some(()) }).await;
    let j = admin.wait_job(&j, 60).await;
    assert_eq!(j["status"], "timed_out", "{j}");
    eventually(15, "the timed-out job's grandchild to be killed", || async { (processes_with(&marker) == 0).then_some(()) }).await;

    // --- results survive a service restart --------------------------------------------------------
    let j = admin.run("powershell", &id, "Write-Output started; Start-Sleep 120", 300).await;
    eventually(60, "the job to start", || async { admin.job(&j).await["stdout"].as_str().unwrap_or_default().contains("started").then_some(()) }).await;
    let (ok, out) = powershell("Restart-Service RmmAgent -Force");
    assert!(ok, "{out}");
    let done = admin.wait_job(&j, 120).await;
    assert_eq!(done["status"], "error", "a job interrupted by a restart reports what it had: {done}");
    assert!(done["stdout"].as_str().unwrap().contains("started"), "{done}");
    assert!(done["stderr"].as_str().unwrap().contains("agent stopped"), "{done}");

    // --- services --------------------------------------------------------------------------------
    let services = eventually(120, "the agent to report services", || async {
        let v = admin.get(&format!("/agents/{id}/services")).await;
        v["services"].as_array().filter(|s| s.len() > 20).cloned()
    })
    .await;
    assert!(services.iter().any(|s| s.to_string().contains("RmmAgent")), "the agent lists its own service");
    println!("agent reported {} services", services.len());

    // --- upgrade: a newer download installs over the old one and keeps the identity -----------------
    let token_uses = || async {
        let list = admin.get(&format!("/sites/{site}/enrollment-tokens")).await;
        list.as_array().unwrap().iter().find(|t| t["id"] == token["id"]).map(|t| t["uses"].as_i64().unwrap())
    };
    let uses_before = token_uses().await;
    let res = http.get(msi_url).send().await.unwrap();
    std::fs::write(&msi, res.bytes().await.unwrap()).unwrap();
    msiexec(&dir, &["/i", msi.to_str().unwrap()], "upgrade.log");
    assert_eq!(service_state().as_deref(), Some("RUNNING"), "running again after the upgrade");
    let (_, products) = powershell(
        "@(Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Where-Object DisplayName -eq 'RMM Agent').Count",
    );
    assert_eq!(products.trim(), "1", "the upgrade replaced the old product instead of installing beside it");
    eventually(60, "the agent back online after the upgrade", || async {
        let agents = admin.agents().await;
        (agents.len() == 1 && agents[0]["id"] == id.as_str() && agents[0]["online"] == true).then_some(())
    })
    .await;
    assert_eq!(token_uses().await, uses_before, "keeping the enrollment doesn't spend a token use");

    // --- uninstall --------------------------------------------------------------------------------
    msiexec(&dir, &["/x", msi.to_str().unwrap()], "uninstall.log");
    assert_eq!(service_state(), None, "the service is removed");
    assert!(!program_files.exists(), "the binary is removed");
    assert!(data.join("agent.toml").exists(), "the enrollment is kept for a reinstall");
    eventually(60, "the agent to go offline", || async {
        (admin.get(&format!("/agents/{id}")).await["online"] == false).then_some(())
    })
    .await;
    let _ = std::fs::remove_dir_all(&data);
    println!("windows e2e: ok");
}
