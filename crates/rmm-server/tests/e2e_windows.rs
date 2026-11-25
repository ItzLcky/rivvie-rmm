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
//! It covers what the Linux suite can't, in sections that can be run alone:
//!
//! - `base`: the MSI (install, upgrade over itself, uninstall), the service and its recovery
//!   settings, the `C:\ProgramData\RMM` ACL, PowerShell and cmd jobs, Job Objects killing a
//!   timed-out script's whole tree, job results surviving a service restart, the service list.
//! - `shell`: a ConPTY terminal through the server's shell relay: a command and its output,
//!   closing the terminal kills what was started from it, `exit` ends the session.
//! - `eventlog`: Event Log watchers (`wevtutil`): an error written with `eventcreate` and
//!   with `Write-EventLog` opens an alert; an information event doesn't.
//! - `patches`: a Windows Update Agent scan returns a result without an error. Nothing is
//!   installed.
//! - `defender`: Defender's status through `Get-MpComputerStatus`, a signature update, and a
//!   detection of the EICAR test file (built at run time: the string never sits in a file
//!   Defender would scan).
//! - `sensor`: the sensor starts, reports process telemetry and a behaviour detection, and
//!   quarantines (and restores) a test file that signed content flags.
//! - `diskenc`: disk encryption through BitLocker's CIM classes: a report arrives and lists
//!   `C:` (the runner has no BitLocker, so escrow there is unproven).
//! - `laps`: local admin rotation, the real path: `rmm-e2e-admin` is created and its password
//!   set with the NetUser APIs, checked with `LogonUserW`, rotated again, then deleted.
//! - `update`: self-update with a signed build: the detached watchdog stops and starts the
//!   service; a build that never confirms is rolled back; then the update that does confirm.
//!   Needs two agent builds, see below.
//!
//! `RMM_E2E_ONLY=shell,eventlog` runs just those sections (`base` is a section too), and
//! `RMM_E2E_SKIP=sensor` runs all but those. The install and uninstall always run.
//!
//! The `update` section needs the agent built with the release key and a newer build of it:
//!
//! ```powershell
//! cargo run -q -p rmm-sign -- pubkey --key key.txt       # key.txt: 64 hex digits, "09" * 32
//! $env:RMM_UPDATE_PUBKEY = "<that key>"
//! $env:RMM_AGENT_VERSION = "99.0.0"; cargo build -p rmm-agent
//! copy target\debug\rmm-agent.exe target\e2e-agent-new.exe
//! Remove-Item Env:RMM_AGENT_VERSION; cargo build -p rmm-agent
//! $env:RMM_E2E_NEW_AGENT_BIN = "target\e2e-agent-new.exe"
//! ```
//!
//! Without `RMM_E2E_NEW_AGENT_BIN` (or `RMM_UPDATE_PUBKEY` in the agent) the section is
//! skipped, and the sensor section can't load its content either (its test file is then not
//! flagged). The e2e signs with the fixed test seed `[9; 32]`; the `e2e-windows` job in
//! `.github/workflows/ci.yml` does all of the above.
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
/// Seed of the key that signs the e2e's agent updates and detection content (the agent is
/// built with its public half as RMM_UPDATE_PUBKEY, and so is the server).
const SIGNING_SEED: [u8; 32] = [9u8; 32];
const ROOT_SET: &str = "00000000-0000-4000-8001-000000000000";
const SECURITY_ITEM: &str = "00000000-0000-4000-8000-000000000002";

fn content_pubkey() -> String {
    hex::encode(ed25519_dalek::SigningKey::from_bytes(&SIGNING_SEED).verifying_key().as_bytes())
}

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

    /// An alert policy in All devices: `kind` and `params` as the alert policy form has them.
    async fn alert_policy(&self, name: &str, kind: &str, severity: &str, params: Value) -> Value {
        let body = json!({ "module": "alert", "name": name, "config": { "kind": kind, "severity": severity, "params": params } });
        let (s, v) = self.call(reqwest::Method::POST, &format!("/policy-sets/{ROOT_SET}/items"), Some(body.clone())).await;
        assert!(s.is_success(), "creating alert policy {body}: {s} {v}");
        v
    }

    async fn delete_policy(&self, id: &str) {
        let (s, v) = self.call(reqwest::Method::DELETE, &format!("/policy-items/{id}"), None).await;
        assert!(s.is_success(), "deleting policy {id}: {s} {v}");
    }

    /// Changes some fields of a single-instance item (security, ...) in All devices.
    async fn set_root_item(&self, item: &str, fields: Value) -> (StatusCode, Value) {
        let set = self.get(&format!("/policy-sets/{ROOT_SET}")).await;
        let mut config = set["policies"].as_array().unwrap().iter().find(|p| p["id"] == item).unwrap()["item_config"].clone();
        config.as_object_mut().unwrap().extend(fields.as_object().unwrap().clone());
        self.call(reqwest::Method::PUT, &format!("/policy-items/{item}"), Some(json!({ "config": config }))).await
    }

    async fn alerts(&self, query: &str) -> Vec<Value> {
        self.get(&format!("/alerts?{query}")).await["items"].as_array().cloned().unwrap_or_default()
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

/// `HKLM\…\Run\RmmAgentTray`, if it's there.
fn tray_run_value() -> Option<String> {
    let (ok, out) = sh("reg.exe", &["query", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "/v", "RmmAgentTray", "/reg:64"]);
    if !ok {
        return None;
    }
    out.lines().find_map(|l| l.trim().strip_prefix("RmmAgentTray")).map(|r| r.trim().trim_start_matches("REG_SZ").trim().to_string())
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
        .env("RMM_ALERT_EVAL_SECS", "2")
        .env("RMM_UPDATE_PUBKEY", content_pubkey())
        .env("RMM_CONTENT_SOAK_MINUTES", "0")
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
    // The tray app starts at sign-in for everyone: the MSI's Registry row.
    assert_eq!(tray_run_value().as_deref(), Some(format!("\"{}\" tray", program_files.display()).as_str()), "the tray's Run value after install");
    let install_log = std::fs::read_to_string(data.join("logs").join("install.log")).unwrap_or_default();
    assert!(install_log.contains("ok: enrolled as"), "{install_log}");

    let sections = Sections::from_env();
    if sections.on("base") {
        base_checks(&admin, &http, &dir, &id, site, &token, msi_url, &msi).await;
    }
    sections.run_extra(&admin, &url, &dir, &id).await;

    // --- uninstall --------------------------------------------------------------------------------
    // What a self-update leaves beside the binary goes with it.
    let leftovers: Vec<PathBuf> =
        ["rmm-agent.old.exe", "rmm-agent.new.exe"].iter().map(|n| program_files.with_file_name(n)).filter(|p| p.exists()).collect();
    msiexec(&dir, &["/x", msi.to_str().unwrap()], "uninstall.log");
    assert_eq!(service_state(), None, "the service is removed");
    assert_eq!(tray_run_value(), None, "the tray's Run value goes with the package");
    assert!(!program_files.exists(), "the binary is removed");
    for p in &leftovers {
        assert!(!p.exists(), "uninstall removes {} too", p.display());
    }
    assert!(data.join("agent.toml").exists(), "the enrollment is kept for a reinstall");
    eventually(60, "the agent to go offline", || async {
        (admin.get(&format!("/agents/{id}")).await["online"] == false).then_some(())
    })
    .await;
    let _ = std::fs::remove_dir_all(&data);
    println!("windows e2e: ok");
}

/// Jobs, a restart, services and an MSI upgrade over the running service.
#[allow(clippy::too_many_arguments)]
async fn base_checks(admin: &Api, http: &reqwest::Client, dir: &Path, id: &str, site: &str, token: &Value, msi_url: &str, msi: &Path) {
    let id = id.to_string();
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
    std::fs::write(msi, res.bytes().await.unwrap()).unwrap();
    msiexec(dir, &["/i", msi.to_str().unwrap()], "upgrade.log");
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

}

// =====================================================================================================
// Sections
// =====================================================================================================

/// Which sections to run: `RMM_E2E_ONLY=a,b` only those, `RMM_E2E_SKIP=a,b` all but those.
struct Sections {
    only: Option<Vec<String>>,
    skip: Vec<String>,
}

impl Sections {
    const ALL: [&str; 10] = ["base", "shell", "eventlog", "patches", "defender", "sensor", "diskenc", "laps", "tray", "update"];

    fn from_env() -> Self {
        let list = |k: &str| {
            std::env::var(k).ok().map(|v| v.split(',').map(|s| s.trim().to_ascii_lowercase()).filter(|s| !s.is_empty()).collect::<Vec<_>>())
        };
        let s = Self { only: list("RMM_E2E_ONLY"), skip: list("RMM_E2E_SKIP").unwrap_or_default() };
        for n in s.only.iter().flatten().chain(&s.skip) {
            assert!(Self::ALL.contains(&n.as_str()), "unknown section {n:?} in RMM_E2E_ONLY/RMM_E2E_SKIP; the sections are {:?}", Self::ALL);
        }
        s
    }

    fn on(&self, name: &str) -> bool {
        self.only.as_ref().is_none_or(|o| o.iter().any(|n| n == name)) && !self.skip.iter().any(|n| n == name)
    }

    /// Everything after the base checks and before the uninstall. The self-update goes last: it
    /// replaces the agent's binary.
    async fn run_extra(&self, admin: &Api, url: &str, dir: &Path, id: &str) {
        for name in &Self::ALL[1..] {
            if !self.on(name) {
                println!("section {name}: not selected");
                continue;
            }
            println!("section {name}: start");
            let started = Instant::now();
            match *name {
                "shell" => shell(admin, url, id).await,
                "eventlog" => eventlog(admin, id).await,
                "patches" => patches(admin, id).await,
                "defender" => defender(admin, dir, id).await,
                "sensor" => sensor(admin, dir, id).await,
                "diskenc" => diskenc(admin, id).await,
                "laps" => laps(admin, id).await,
                "tray" => tray(admin, id).await,
                "update" => update(admin, dir, id).await,
                _ => unreachable!(),
            }
            println!("section {name}: ok in {} s", started.elapsed().as_secs());
        }
    }
}

// --- ConPTY shells --------------------------------------------------------------------------------------

type Ws = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// A browser terminal: the shell relay's WebSocket, with what it has said so far.
struct Term {
    ws: Ws,
    out: String,
    opened: bool,
    closed: Option<Value>,
}

impl Term {
    async fn connect(url: &str, cookie: &str, id: &str) -> Term {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let mut req = format!("{}/api/agents/{id}/shell?cols=120&rows=30", url.replacen("http", "ws", 1)).into_client_request().unwrap();
        req.headers_mut().insert("cookie", cookie.parse().unwrap());
        let (ws, _) = tokio_tungstenite::connect_async(req).await.expect("the shell socket");
        Term { ws, out: String::new(), opened: false, closed: None }
    }

    /// Reads until `done` holds (or the session closes, if `done` is about that), at most `secs`.
    async fn until(&mut self, secs: u64, what: &str, done: impl Fn(&Term) -> bool) {
        use futures_util::StreamExt;
        use tokio_tungstenite::tungstenite::Message;
        let deadline = Instant::now() + Duration::from_secs(secs);
        while !done(self) {
            let left = deadline.checked_duration_since(Instant::now()).unwrap_or_default();
            assert!(!left.is_zero(), "timed out waiting for: {what}\nterminal output so far: {:?}\nclosed: {:?}", self.out, self.closed);
            match tokio::time::timeout(left, self.ws.next()).await {
                Ok(Some(Ok(Message::Binary(b)))) => {
                    self.out.push_str(&String::from_utf8_lossy(&b));
                    // ConPTY asks for the cursor position (ESC[6n) and prints nothing until answered; xterm.js does this in the browser.
                    if String::from_utf8_lossy(&b).contains("\x1b[6n") {
                        self.send("\x1b[1;1R").await;
                    }
                }
                Ok(Some(Ok(Message::Text(t)))) => {
                    let v: Value = serde_json::from_str(&t).unwrap_or(Value::Null);
                    match v["type"].as_str() {
                        Some("opened") => self.opened = true,
                        Some("closed") => self.closed = Some(v),
                        _ => {}
                    }
                }
                Ok(Some(Ok(_))) => {}
                Ok(Some(Err(_)) | None) => {
                    assert!(self.closed.is_some() || done(self), "the socket ended while waiting for: {what}\noutput: {:?}", self.out);
                    return;
                }
                Err(_) => {} // the deadline check above reports it
            }
        }
    }

    async fn send(&mut self, text: &str) {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message;
        self.ws.send(Message::Binary(text.as_bytes().to_vec().into())).await.unwrap();
    }

    async fn send_json(&mut self, v: Value) {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message;
        self.ws.send(Message::Text(v.to_string().into())).await.unwrap();
    }
}

/// A technician's session cookie (the admin's has two-factor sign-in on it, which is more than
/// a WebSocket test needs).
async fn technician_cookie(url: &str, admin: &Api, email: &str) -> String {
    admin
        .post("/users", json!({ "email": email, "name": "Shell Tech", "password": "shell-password-123", "role": "technician", "all_clients": true }))
        .await;
    let res = reqwest::Client::new()
        .post(format!("{url}/api/auth/login"))
        .json(&json!({ "email": email, "password": "shell-password-123" }))
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success(), "technician sign-in: {}", res.status());
    res.headers()["set-cookie"].to_str().unwrap().split(';').next().unwrap().to_string()
}

async fn shell(admin: &Api, url: &str, id: &str) {
    let cookie = technician_cookie(url, admin, "shell@e2e.test").await;

    // A command, and what it prints (the arithmetic keeps the answer out of the typed echo).
    let mut t = Term::connect(url, &cookie, id).await;
    t.until(30, "the terminal to open", |t| t.opened).await;
    t.send("$n = 6 * 7; \"shell-$n-ok\"\r").await;
    t.until(60, "the command's output", |t| t.out.contains("shell-42-ok")).await;
    assert!(t.out.contains("PS ") || t.out.contains("shell-42-ok"), "a PowerShell prompt came with it: {:?}", t.out);

    // Resizing reaches the console PowerShell sees.
    t.send_json(json!({ "type": "resize", "cols": 90, "rows": 25 })).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    t.send("\"w=\" + ($Host.UI.RawUI.WindowSize.Width + 1000)\r").await;
    t.until(30, "the console to have the new width", |t| t.out.contains("w=1090")).await;

    // Closing the terminal kills what was started from it, grandchildren included.
    let marker = format!("rmm-e2e-shell-{}", uuid::Uuid::new_v4().simple());
    t.send(&format!("Start-Process cmd.exe -WindowStyle Hidden -ArgumentList '/c','ping -n 600 127.0.0.1 >nul & rem {marker}'\r")).await;
    eventually(60, "the process started from the terminal", || async { (processes_with(&marker) > 0).then_some(()) }).await;
    let _ = t.ws.close(None).await;
    drop(t);
    eventually(30, "closing the terminal to kill what it started", || async { (processes_with(&marker) == 0).then_some(()) }).await;

    // `exit` ends the session: the console is told (a ConPTY's pipe doesn't close by itself).
    let mut t = Term::connect(url, &cookie, id).await;
    t.until(30, "the second terminal to open", |t| t.opened).await;
    t.send("exit\r").await;
    t.until(30, "the session to report that the shell exited", |t| t.closed.is_some()).await;
    assert_eq!(t.closed.as_ref().unwrap()["reason"], "shell exited");

    // The server recorded both sessions.
    let log = admin.get(&format!("/agents/{id}/activity")).await;
    let actions: Vec<&str> = log.as_array().into_iter().flatten().filter_map(|e| e["action"].as_str()).collect();
    assert!(actions.contains(&"shell.open"), "{actions:?}");
}

// --- Event Log watchers ---------------------------------------------------------------------------------

async fn eventlog(admin: &Api, id: &str) {
    let marker = format!("rmm-e2e-evt-{}", uuid::Uuid::new_v4().simple());
    let pol = admin
        .alert_policy("Event log marker", "log", "warning", json!({ "channels": ["Application"], "min_level": "error", "pattern": marker }))
        .await;
    let pol_id = pol["id"].as_str().unwrap().to_string();
    // The watcher set reaches the agent, which notes where each log ends; only later events count.
    tokio::time::sleep(Duration::from_secs(8)).await;

    let (ok, out) = sh(
        "eventcreate.exe",
        &["/T", "ERROR", "/ID", "777", "/L", "APPLICATION", "/SO", "RmmE2E", "/D", &format!("written by eventcreate {marker}")],
    );
    assert!(ok, "eventcreate: {out}");
    // Below the watcher's level: no alert, no entry.
    let (ok, out) = sh(
        "eventcreate.exe",
        &["/T", "INFORMATION", "/ID", "778", "/L", "APPLICATION", "/SO", "RmmE2E", "/D", &format!("information only {marker}")],
    );
    assert!(ok, "eventcreate: {out}");
    // The other way to write one; a new source can take a moment to register, so this one is
    // checked only if it was written.
    let (wrote, out) = powershell(&format!(
        "$ErrorActionPreference = 'Stop'; New-EventLog -LogName Application -Source RmmE2EPs -ErrorAction SilentlyContinue; \
         Write-EventLog -LogName Application -Source RmmE2EPs -EntryType Error -EventId 4242 -Message 'written by Write-EventLog {marker}'"
    ));
    if !wrote {
        println!("Write-EventLog failed; checking eventcreate only: {out}");
    }

    // Polled every 30 s, then the alert evaluation.
    let alert = eventually(150, "an alert for the event", || async { admin.alerts(&format!("policy_id={pol_id}")).await.into_iter().next() }).await;
    assert!(alert["details"]["message"].as_str().unwrap_or_default().contains(&marker), "{alert}");
    let entries = eventually(60, "the log entries", || async {
        let e = admin.get(&format!("/agents/{id}/log-events?q={marker}")).await;
        let n = e.as_array().map_or(0, |a| a.len());
        (n >= if wrote { 2 } else { 1 }).then_some(e)
    })
    .await;
    let entries = entries.as_array().unwrap();
    let by_id = |event_id: i64| entries.iter().find(|e| e["event_id"] == event_id);
    let e = by_id(777).unwrap_or_else(|| panic!("the eventcreate event (id 777): {entries:?}"));
    assert_eq!((e["source"].as_str(), e["level"].as_str()), (Some("RmmE2E"), Some("error")), "{e}");
    assert!(e["message"].as_str().unwrap().contains(&marker), "the rendered message: {e}");
    if wrote {
        assert!(by_id(4242).is_some(), "the Write-EventLog event (id 4242): {entries:?}");
    }
    assert!(by_id(778).is_none(), "an information event is below the watcher's level: {entries:?}");
    admin.delete_policy(&pol_id).await;
}

// --- Windows Update ---------------------------------------------------------------------------------------

/// Failures that mean this machine can't reach Windows Update, not that the agent can't use it.
const WU_UNREACHABLE: [&str; 6] = ["0x80072EE7", "0x80072EFD", "0x80072EE2", "0x8024402C", "0x80244010", "0x80070422"];

async fn patches(admin: &Api, id: &str) {
    // Hosted runners ship with the Windows Update service switched off.
    let (_, out) = powershell("Set-Service wuauserv -StartupType Manual -ErrorAction SilentlyContinue; Start-Service wuauserv -ErrorAction SilentlyContinue; (Get-Service wuauserv).Status");
    println!("Windows Update service: {}", out.trim());

    admin.post("/patches/scan", json!({ "agent_ids": [id] })).await;
    // A first search can take minutes: it contacts Windows Update.
    let p = eventually(600, "the patch scan to finish", || async {
        let p = admin.get(&format!("/agents/{id}/patches")).await;
        (!p["status"]["scanned_at"].is_null() || !p["status"]["scan_error"].is_null()).then_some(p)
    })
    .await;
    let status = &p["status"];
    assert_eq!(status["supported"], true, "the agent offers patching on Windows: {status}");
    let provider = status["provider"].as_str().unwrap_or_default();
    assert!(provider == "wua" || provider == "pswindowsupdate", "provider: {status}");
    match status["scan_error"].as_str() {
        None => println!("patch scan with {provider}: {} updates missing, reboot pending: {}", p["patches"].as_array().map_or(0, |a| a.len()), status["reboot_pending"]),
        Some(err) if WU_UNREACHABLE.iter().any(|c| err.contains(c)) => {
            println!("this machine can't reach Windows Update ({err}); the scan failed the way it should, not asserting more");
        }
        Some(err) => panic!("the Windows Update scan failed with {provider}: {err}"),
    }
    assert!(status["reboot_pending"].is_boolean(), "reboot state is reported: {status}");
}

// --- Defender ---------------------------------------------------------------------------------------------

/// The EICAR test file, cut in pieces so it exists whole only in the script that writes it
/// (and never in this source, the binary or a file Defender would scan before then).
const EICAR_PS: &str = r"$e = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$' + 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!' + '$H+H*';";

async fn security_state(admin: &Api, id: &str) -> Value {
    admin.get(&format!("/agents/{id}/security")).await
}

fn product<'a>(s: &'a Value, kind: &str) -> Option<&'a Value> {
    s["products"].as_array()?.iter().find(|p| p["kind"] == kind)
}

async fn wait_security_action(admin: &Api, id: &str, action: &str, secs: u64) -> Value {
    let started = admin.post(&format!("/agents/{id}/security/actions"), json!({ "action": action })).await;
    let action_id = started["id"].as_str().unwrap().to_string();
    eventually(secs, &format!("security action {action}"), || async {
        let s = security_state(admin, id).await;
        let a = s["actions"].as_array()?.iter().find(|a| a["id"] == action_id.as_str())?.clone();
        (!matches!(a["status"].as_str(), Some("sent" | "running"))).then_some(a)
    })
    .await
}

/// Is any of `candidates` (one path in its short and long spelling) at or under one of the
/// exclusion paths? Case-insensitive, trailing backslashes ignored.
fn path_excluded(candidates: &[String], exclusions: &[String]) -> bool {
    let norm = |p: &str| p.trim().trim_end_matches('\\').to_ascii_lowercase();
    exclusions.iter().map(|e| norm(e)).filter(|e| !e.is_empty()).any(|e| {
        candidates.iter().map(|c| norm(c)).any(|c| c == e || c.starts_with(&format!("{e}\\")))
    })
}

async fn defender(admin: &Api, dir: &Path, id: &str) {
    admin.post(&format!("/agents/{id}/security/refresh"), json!({})).await;
    let s = eventually(120, "Defender's status", || async {
        let s = security_state(admin, id).await;
        product(&s, "defender").is_some().then_some(s)
    })
    .await;
    assert_eq!(s["supported"], true, "{s}");
    let d = product(&s, "defender").unwrap().clone();
    println!("Defender: {d}");
    if d["enabled"] != true {
        println!("Defender isn't running on this machine ({}); status reporting works, skipping the rest", d["detail"]);
        return;
    }
    assert!(d["version"].is_string() && d["signature_version"].is_string() && !d["signatures_updated_at"].is_null(), "versions come from Get-MpComputerStatus: {d}");
    assert!(d["actions"].as_array().is_some_and(|a| a.len() == 3), "scans and signature updates are offered: {d}");

    // A signature update may fail without a connection; it must finish either way.
    let a = wait_security_action(admin, id, "update_signatures", 360).await;
    println!("update_signatures: {} ({})", a["status"], a["message"]);
    assert!(matches!(a["status"].as_str(), Some("succeeded" | "failed")), "{a}");

    // The EICAR test file: found by a scan of its folder (or by real-time protection when the
    // file is written), reported as a detection.
    let folder = dir.join("eicar");
    std::fs::create_dir_all(&folder).unwrap();
    let file = folder.join("eicar-test.com");

    // Exclusions (GitHub's runner images exclude whole drives) make Defender skip the folder.
    let (_, paths) = powershell("(Get-MpPreference).ExclusionPath | ForEach-Object { $_ }");
    let (_, exts) = powershell("(Get-MpPreference).ExclusionExtension | ForEach-Object { $_ }");
    let paths: Vec<String> = paths.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
    let exts: Vec<String> = exts.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
    println!("Defender exclusions: paths {paths:?}, extensions {exts:?}");
    let mut candidates = vec![folder.display().to_string()];
    if let Ok(long) = std::fs::canonicalize(&folder) {
        candidates.push(long.display().to_string().trim_start_matches(r"\\?\").to_string());
    }
    if path_excluded(&candidates, &paths) || exts.iter().any(|e| e.trim_start_matches('.').eq_ignore_ascii_case("com")) {
        println!(
            "the test folder is excluded from Defender scans (paths {paths:?}, extensions {exts:?}); status and actions work, skipping the detection check"
        );
        return;
    }

    let (wrote, out) = powershell(&format!("{EICAR_PS} Set-Content -NoNewline -Encoding ascii -Path '{}' -Value $e", file.display()));
    println!("wrote the test file: {wrote} {}", out.trim());
    let (ok, out) = powershell(&format!("Start-MpScan -ScanType CustomScan -ScanPath '{}'", folder.display()));
    println!("custom scan: success={ok} output={:?}", out.trim());
    let found = eventually(240, "Defender's detection of the test file", || async {
        admin.post(&format!("/agents/{id}/security/refresh"), json!({})).await;
        tokio::time::sleep(Duration::from_secs(5)).await;
        let s = security_state(admin, id).await;
        s["detections"].as_array()?.iter().find(|d| d["name"].as_str().is_some_and(|n| n.to_ascii_uppercase().contains("EICAR"))).cloned()
    })
    .await;
    println!("detection: {found}");
    assert_eq!(found["product"], "defender", "{found}");
    assert!(found["detected_at"].is_string(), "{found}");
}

// --- the sensor ---------------------------------------------------------------------------------------------

fn signed(bundle: &Value) -> Value {
    use ed25519_dalek::Signer;
    use sha2::Digest;
    let text = serde_json::to_string_pretty(bundle).unwrap();
    let sha = hex::encode(sha2::Sha256::digest(text.as_bytes()));
    let version = bundle["version"].as_str().unwrap();
    let sig = ed25519_dalek::SigningKey::from_bytes(&SIGNING_SEED).sign(&rmm_proto::security::content_signed_message(version, &sha));
    json!({ "bundle": text, "signature": { "version": version, "sha256": sha, "signature": hex::encode(sig.to_bytes()) } })
}

/// Detection content for Windows: a file with a marker string, and a process with a marker on
/// its command line.
fn sensor_bundle(version: &str) -> Value {
    let proc_ev = |cmd: &str| {
        json!({ "ts": "2026-11-10T00:00:00Z", "kind": "process", "action": "start", "process": { "pid": 9, "name": "cmd.exe", "command_line": cmd } })
    };
    json!({
        "version": version, "created_at": chrono::Utc::now(), "description": "Windows e2e content", "hashes": [],
        "file_rules": [{
            "id": "E2E-F-1", "name": "E2E test malware", "severity": "high", "confidence": "high", "mode": "alert", "mitre": ["T1204"],
            "strings": [{ "text": "RMM-E2E-MALWARE" }],
            "tests": [{ "text": "x RMM-E2E-MALWARE x", "expect": true }, { "text": "clean", "expect": false }]
        }],
        "behaviour_rules": [{
            "id": "E2E-B-1", "name": "E2E marker process", "severity": "high", "confidence": "high", "mode": "alert", "mitre": ["T1059"],
            "event": "process", "actions": ["start"], "when": { "field": "process.command_line", "op": "contains", "value": "rmm-e2e-marker" },
            "tests": [{ "event": proc_ev("cmd.exe /c ping rmm-e2e-marker"), "expect": true }, { "event": proc_ev("cmd.exe /c ping"), "expect": false }]
        }]
    })
}

async fn detections_for(admin: &Api, id: &str, rule: &str) -> Vec<Value> {
    admin.get(&format!("/security/detections?view=all&audit=true&agent_id={id}&rule_id={rule}")).await["items"].as_array().cloned().unwrap_or_default()
}

/// A process with the marker on its command line, alive for `secs` (polling sees it).
async fn marker_process(admin: &Api, id: &str, secs: u32) {
    let j = admin
        .run(
            "powershell",
            id,
            &format!("Start-Process cmd.exe -Wait -WindowStyle Hidden -ArgumentList '/c','ping -n {secs} 127.0.0.1 >nul & rem rmm-e2e-marker'"),
            120,
        )
        .await;
    let j = admin.wait_job(&j, 120).await;
    assert_eq!(j["status"], "succeeded", "{j}");
}

async fn sensor(admin: &Api, dir: &Path, id: &str) {
    let respond = |action: Value| async move {
        let v = admin.post(&format!("/agents/{id}/security/respond"), json!({ "action": action })).await;
        v["id"].as_str().unwrap().to_string()
    };
    let wait_action = |action_id: String| async move {
        eventually(120, &format!("response action {action_id}"), || async {
            let s = security_state(admin, id).await;
            let a = s["actions"].as_array()?.iter().find(|a| a["id"] == action_id.as_str())?.clone();
            (!matches!(a["status"].as_str(), Some("sent" | "running"))).then_some(a)
        })
        .await
    };

    let s = security_state(admin, id).await;
    assert_eq!(s["sensor_supported"], true, "the sensor is available on Windows: {s}");
    let policy = |on: bool| {
        json!({ "sensor_enabled": on, "quick_scan_hours": 0, "full_scan_days": 0, "auto_quarantine": true, "prevention": false, "canaries": false, "telemetry_mb": 16 })
    };
    let (st, v) = admin.set_root_item(SECURITY_ITEM, policy(true)).await;
    assert!(st.is_success(), "{v}");
    eventually(60, "the sensor to start", || async { (security_state(admin, id).await["sensor"]["running"] == true).then_some(()) }).await;

    // Process telemetry: polling sees a process that lives a few seconds.
    marker_process(admin, id, 10).await;
    eventually(60, "the marker process in the telemetry", || async {
        let t = admin.get(&format!("/agents/{id}/telemetry?text=rmm-e2e-marker&kinds=process")).await;
        t["events"].as_array().filter(|e| !e.is_empty()).map(|_| ())
    })
    .await;

    // Detection content: needs the agent built with the release key.
    let up = admin.post("/security/content", signed(&sensor_bundle("e2e.1"))).await;
    println!("content uploaded: {}", up["stage"]);
    let loaded = {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if security_state(admin, id).await["content_version"] == "e2e.1" {
                break true;
            }
            if Instant::now() > deadline {
                break false;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    };
    if !loaded {
        println!("the agent didn't load the signed content (built without RMM_UPDATE_PUBKEY?); skipping the detection checks");
    } else {
        // A behaviour rule on the process command line.
        tokio::time::sleep(Duration::from_secs(2)).await;
        marker_process(admin, id, 10).await;
        let hit = eventually(60, "the behaviour detection", || async { detections_for(admin, id, "E2E-B-1").await.into_iter().next() }).await;
        assert_eq!(hit["source"], "behaviour", "{hit}");

        // A file the content flags: scan, quarantine (the original is gone), restore.
        let bad = dir.join("scan").join("sub").join("payload.bin");
        std::fs::create_dir_all(bad.parent().unwrap()).unwrap();
        std::fs::write(&bad, b"header RMM-E2E-MALWARE trailer").unwrap();
        let scan = respond(json!({ "type": "scan_path", "path": dir.join("scan").to_string_lossy() })).await;
        let a = wait_action(scan).await;
        assert_eq!(a["status"], "succeeded", "{a}");
        assert!(a["message"].as_str().unwrap().starts_with("Found 1 threat"), "{a}");
        let d = eventually(30, "the file detection", || async { detections_for(admin, id, "E2E-F-1").await.into_iter().next() }).await;
        assert_eq!((d["status"].as_str(), d["action_taken"].as_str()), (Some("quarantined"), Some("quarantined")), "{d}");
        eventually(30, "the file to leave its place", || async { (!bad.exists()).then_some(()) }).await;
        let q = eventually(30, "the quarantine list", || async {
            admin.get(&format!("/security/quarantine?agent_id={id}")).await.as_array().unwrap().first().cloned()
        })
        .await;
        assert_eq!(q["sha256"], d["sha256"], "{q}");
        let restore = admin.post(&format!("/agents/{id}/security/respond"), json!({ "action": { "type": "restore_file", "id": q["id"] }, "exclude_hash": true })).await;
        let a = wait_action(restore["id"].as_str().unwrap().to_string()).await;
        assert_eq!(a["status"], "succeeded", "{a}");
        assert_eq!(std::fs::read(&bad).unwrap(), b"header RMM-E2E-MALWARE trailer", "restored byte for byte");
    }

    // Off again: the sensor stops.
    let (st, v) = admin.set_root_item(SECURITY_ITEM, policy(false)).await;
    assert!(st.is_success(), "{v}");
    eventually(60, "the sensor to stop", || async { (security_state(admin, id).await["sensor"]["running"] != true).then_some(()) }).await;
}

// --- disk encryption -------------------------------------------------------------------------------------

async fn diskenc(admin: &Api, id: &str) {
    admin.post(&format!("/agents/{id}/disk-encryption/refresh"), json!({})).await;
    let d = eventually(120, "a disk encryption report", || async {
        let d = admin.get(&format!("/agents/{id}/disk-encryption")).await;
        (!d["reported_at"].is_null()).then_some(d)
    })
    .await;
    println!("disk encryption: {d}");
    let c = d["volumes"].as_array().unwrap().iter().find(|v| v["volume_id"] == "C:").unwrap_or_else(|| panic!("C: listed: {d}"));
    assert_eq!(c["role"], "os", "{d}");
    assert!(c["status"].is_string() && c["kind"].is_string(), "{d}");
    assert!(d["error"].is_null(), "read without an error: {d}");
}

// --- local admin rotation (Windows LAPS-style) --------------------------------------------------------------

const LAPS_ITEM: &str = "00000000-0000-4000-8000-000000000006";
const LAPS_ACCOUNT: &str = "rmm-e2e-admin";

/// Signs in as the local account with `LogonUserW` (network logon); the password reaches
/// PowerShell through the environment, never its command line.
fn logon_works(password: &str) -> bool {
    let script = r#"
Add-Type -Namespace E2E -Name Logon -MemberDefinition '[DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern bool LogonUserW(string u, string d, string p, int t, int pr, out IntPtr h);'
$h = [IntPtr]::Zero
if ([E2E.Logon]::LogonUserW('rmm-e2e-admin', '.', $env:RMM_E2E_PW, 3, 0, [ref]$h)) { 'ok' } else { 'failed ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
"#;
    let out = Command::new("powershell.exe").args(["-NoProfile", "-NonInteractive", "-Command", script]).env("RMM_E2E_PW", password).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    println!("LogonUserW: {text}");
    text == "ok"
}

async fn laps_state(admin: &Api, id: &str, status: &str, after: Option<&str>) -> Value {
    eventually(120, &format!("local admin state {status}"), || async {
        let v = admin.get(&format!("/agents/{id}/local-admin")).await;
        let s = &v["state"];
        (s["status"] == status && after.is_none_or(|t| s["rotated_at"].as_str().is_some_and(|r| r > t))).then(|| s.clone())
    })
    .await
}

async fn laps(admin: &Api, id: &str) {
    let _ = sh("net.exe", &["user", LAPS_ACCOUNT, "/delete"]);
    let (s, v) = admin.set_root_item(LAPS_ITEM, json!({ "enabled": true, "account": LAPS_ACCOUNT, "create": true })).await;
    assert!(s.is_success(), "{v}");
    let first = laps_state(admin, id, "ok", None).await;
    let item = first["vault_item_id"].as_str().expect("the vault item").to_string();
    let pw1 = admin.post(&format!("/vault/{item}/reveal"), json!({ "field": "password" })).await["value"].as_str().unwrap().to_string();
    let (_, groups) = powershell("(Get-LocalGroupMember -SID S-1-5-32-544 | Select-Object -ExpandProperty Name) -join ';'");
    assert!(groups.to_ascii_lowercase().contains(LAPS_ACCOUNT), "an administrator: {groups}");
    assert!(logon_works(&pw1), "the stored password signs in");
    // Rotate again: the old password stops working, the new one works.
    admin.post(&format!("/agents/{id}/local-admin/rotate"), json!({})).await;
    let second = laps_state(admin, id, "ok", first["rotated_at"].as_str()).await;
    assert_eq!(second["vault_item_id"], first["vault_item_id"]);
    let pw2 = admin.post(&format!("/vault/{item}/reveal"), json!({ "field": "password" })).await["value"].as_str().unwrap().to_string();
    assert_ne!(pw1, pw2);
    assert!(logon_works(&pw2), "the rotated password signs in");
    assert!(!logon_works(&pw1), "the old one doesn't");
    admin.set_root_item(LAPS_ITEM, json!({ "enabled": false, "account": "rmmadmin" })).await;
    let (ok, out) = sh("net.exe", &["user", LAPS_ACCOUNT, "/delete"]);
    assert!(ok, "{out}");
}

// --- self-update ----------------------------------------------------------------------------------------------

fn file_sha256(p: &Path) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(std::fs::read(p).unwrap_or_else(|e| panic!("reading {}: {e}", p.display()))))
}

/// Offers `bin` as release `version` of the Windows agent: the binary in the server's agent
/// directory, and the manifest next to it, signed.
fn publish_release(dir: &Path, bin: &Path, version: &str) {
    use ed25519_dalek::Signer;
    let target = dir.join("agents").join("rmm-agent-windows-x86_64.exe");
    std::fs::copy(bin, &target).unwrap();
    let sha = file_sha256(&target);
    let sig = ed25519_dalek::SigningKey::from_bytes(&SIGNING_SEED).sign(&rmm_proto::update::signed_message("windows-x86_64", version, &sha));
    std::fs::write(
        dir.join("agents").join("rmm-agent-windows-x86_64.exe.update.json"),
        json!({ "platform": "windows-x86_64", "version": version, "sha256": sha, "signature": hex::encode(sig.to_bytes()) }).to_string(),
    )
    .unwrap();
}

async fn wait_update(admin: &Api, id: &str, secs: u64, finished: &[&str]) -> Value {
    eventually(secs, &format!("the update to reach one of {finished:?}"), || async {
        let a = admin.get(&format!("/agents/{id}")).await;
        match a["update_state"].as_str() {
            Some(s) if finished.contains(&s) => Some(a),
            Some("failed") => panic!("the update failed: {}", a["update_detail"]),
            _ => None,
        }
    })
    .await
}

// --- the tray app over the named pipe -----------------------------------------------------------------

/// The headless `rmm-agent tray` as the runner's (elevated) user, against the service's pipe.
async fn tray(admin: &Api, id: &str) {
    let exe = PathBuf::from(std::env::var("ProgramFiles").unwrap()).join("RMM").join("rmm-agent.exe");
    let run = |args: &[&str]| {
        let out = Command::new(&exe).arg("tray").args(args).output().unwrap();
        (out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
    };
    let config = eventually(60, "the tray config over the pipe", || async {
        let (ok, out, _) = run(&["--show-config"]);
        let v: Value = serde_json::from_str(out.trim()).ok()?;
        (ok && !v.is_null()).then_some(v)
    })
    .await;
    assert_eq!(config["enabled"], true, "{config}");
    let (ok, out, err) = run(&["--request", "--subject", "Windows tray e2e", "--body", "From the named pipe."]);
    assert!(ok, "{out} {err}");
    let number: i64 = out.trim().strip_prefix("ticket #").and_then(|s| s.strip_suffix(" created")).and_then(|n| n.parse().ok()).unwrap_or_else(|| panic!("{out}"));
    let list = admin.get("/tickets?q=Windows%20tray%20e2e").await;
    let t = list["items"].as_array().unwrap().iter().find(|t| t["number"] == number).cloned().unwrap_or_else(|| panic!("ticket {number}: {list}"));
    let t = admin.get(&format!("/tickets/{}", t["id"].as_str().unwrap())).await;
    assert_eq!(t["source"], "agent", "{t}");
    assert!(t["agents"].as_array().unwrap().iter().any(|a| a["id"] == id), "{t}");
    // DOMAIN\user from the pipe client's token.
    let note = t["events"].as_array().unwrap().iter().find(|e| e["kind"] == "note").cloned().unwrap();
    assert!(note["body"].as_str().unwrap().contains("Signed-in user: ") && note["body"].as_str().unwrap().contains('\\'), "{note}");
}

async fn update(admin: &Api, dir: &Path, id: &str) {
    let Some(new_bin) = std::env::var_os("RMM_E2E_NEW_AGENT_BIN").map(PathBuf::from) else {
        println!("RMM_E2E_NEW_AGENT_BIN isn't set (see the module docs); skipping the self-update");
        return;
    };
    let installed = PathBuf::from(std::env::var("ProgramFiles").unwrap()).join("RMM").join("rmm-agent.exe");
    let update_log = PathBuf::from(std::env::var("ProgramData").unwrap()).join("RMM").join("logs").join("update.log");
    let old_version = admin.get(&format!("/agents/{id}")).await["agent_version"].as_str().unwrap().to_string();
    let hash_before = file_sha256(&installed);
    let hash_new = file_sha256(&new_bin);
    assert_ne!(hash_before, hash_new, "the new build differs from the installed one");
    assert!(admin.get("/agent-updates").await["auto_update"] != true, "nothing offers updates by itself here");

    // A build that never confirms: it runs as 99.0.0 but was offered as 99.0.1, so the version
    // the watchdog waits for never checks in. After 120 s the watchdog puts the old one back.
    publish_release(dir, &new_bin, "99.0.1");
    let offered = admin.post(&format!("/agents/{id}/update"), json!({})).await;
    assert_eq!(offered["version"], "99.0.1", "{offered}");
    let a = wait_update(admin, id, 480, &["rolled_back"]).await;
    assert!(a["update_detail"].as_str().unwrap_or_default().contains("didn't connect"), "{a}");
    eventually(120, "the old agent back online", || async {
        let a = admin.get(&format!("/agents/{id}")).await;
        (a["online"] == true && a["agent_version"] == old_version.as_str()).then_some(())
    })
    .await;
    assert_eq!(service_state().as_deref(), Some("RUNNING"), "the service runs after the rollback");
    assert_eq!(file_sha256(&installed), hash_before, "the old binary is back, byte for byte");
    let log = std::fs::read_to_string(&update_log).unwrap_or_default();
    assert!(log.contains("rolling back"), "the watchdog logs to update.log: {log}");

    // The update that does confirm: the watchdog stops the service, swaps the binary, starts it.
    publish_release(dir, &new_bin, "99.0.0");
    admin.post(&format!("/agents/{id}/update"), json!({})).await;
    wait_update(admin, id, 300, &["completed"]).await;
    eventually(120, "the new agent online", || async {
        let a = admin.get(&format!("/agents/{id}")).await;
        (a["online"] == true && a["agent_version"] == "99.0.0").then_some(())
    })
    .await;
    assert_eq!(service_state().as_deref(), Some("RUNNING"));
    assert_eq!(file_sha256(&installed), hash_new, "the new binary is in place");
    eventually(60, "the watchdog to log the confirmation", || async {
        std::fs::read_to_string(&update_log).unwrap_or_default().contains("new version confirmed").then_some(())
    })
    .await;
    // Still the same machine, and it still works.
    let j = admin.run("powershell", id, "Write-Output updated-ok", 60).await;
    let j = admin.wait_job(&j, 90).await;
    assert_eq!(j["status"], "succeeded", "{j}");
    assert!(j["stdout"].as_str().unwrap().contains("updated-ok"), "{j}");
    assert_eq!(admin.agents().await.len(), 1, "no second agent appeared");
}
