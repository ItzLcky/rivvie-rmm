//! Service inventory and control: systemd units on Linux, the Service Control Manager on
//! Windows. The list is polled and sent to the server only when it changes.

#![cfg_attr(not(any(target_os = "linux", windows)), allow(dead_code, unused_imports))]

use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use rmm_proto::{AgentMsg, ServiceAction, ServiceInfo, ServiceState, StartMode};
use tokio::process::Command;
use tokio::sync::mpsc;
use tracing::{debug, warn};
use uuid::Uuid;

/// How often the list is re-read. Linux asks systemd (cheap); Windows starts PowerShell.
const POLL: Duration = if cfg!(windows) { Duration::from_secs(120) } else { Duration::from_secs(60) };
const COMMAND_TIMEOUT: Duration = Duration::from_secs(90);

/// Sends the service list now, then again whenever it changes, until the connection closes.
/// `refresh` forces a send (the server asked, or a control action just ran).
pub async fn watch(tx: mpsc::Sender<AgentMsg>, mut refresh: mpsc::Receiver<()>) {
    let mut last: Option<Vec<ServiceInfo>> = None;
    let mut tick = tokio::time::interval(POLL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        let forced = tokio::select! {
            _ = tick.tick() => false,
            r = refresh.recv() => match r {
                Some(()) => true,
                None => return,
            },
        };
        let services = match list().await {
            Ok(s) => s,
            Err(e) => {
                debug!("listing services: {e:#}");
                continue;
            }
        };
        if !forced && last.as_ref() == Some(&services) {
            continue;
        }
        if tx.send(AgentMsg::Services { services: services.clone() }).await.is_err() {
            return;
        }
        last = Some(services);
    }
}

/// Runs a control action and reports the result. The name must be a service the machine
/// actually has, which also keeps option-like strings away from the service manager.
pub async fn control(request_id: Uuid, name: String, action: ServiceAction, tx: mpsc::Sender<AgentMsg>, refresh: mpsc::Sender<()>) {
    let result = async {
        let known = list().await?;
        if !known.iter().any(|s| s.name == name) {
            bail!("no service named {name:?} on this machine");
        }
        run_control(&name, action).await
    }
    .await;
    let (ok, message) = match result {
        Ok(()) => (true, format!("{} {name}: done", action.as_str())),
        Err(e) => {
            warn!(service = %name, action = action.as_str(), "service control failed: {e:#}");
            (false, format!("{e:#}"))
        }
    };
    let _ = tx.send(AgentMsg::ServiceControlResult { request_id, ok, message }).await;
    let _ = refresh.try_send(());
}

async fn output(mut cmd: Command) -> Result<String> {
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
    let out = tokio::time::timeout(COMMAND_TIMEOUT, cmd.output()).await.context("timed out")?.context("running command")?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let err = err.trim();
        bail!("{}", if err.is_empty() { format!("exit status {}", out.status) } else { err.chars().take(500).collect() });
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

// ---------------------------------------------------------------------------
// Linux: systemd
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub async fn list() -> Result<Vec<ServiceInfo>> {
    let systemctl = || {
        let mut c = Command::new("systemctl");
        c.env("SYSTEMD_COLORS", "0");
        c
    };
    let mut units = systemctl();
    units.args(["list-units", "--type=service", "--all", "--no-legend", "--plain", "--no-pager", "--full"]);
    let mut files = systemctl();
    files.args(["list-unit-files", "--type=service", "--no-legend", "--no-pager", "--full"]);
    let (units, files) = tokio::join!(output(units), output(files));
    Ok(parse_systemd(&units?, &files.unwrap_or_default()))
}

/// Merges `systemctl list-units` (loaded units and their state) with `list-unit-files`
/// (enablement, and installed units that aren't loaded, which are stopped).
#[cfg(any(target_os = "linux", test))]
fn parse_systemd(units: &str, files: &str) -> Vec<ServiceInfo> {
    use std::collections::BTreeMap;
    let mut out: BTreeMap<String, ServiceInfo> = BTreeMap::new();
    for line in units.lines() {
        // UNIT LOAD ACTIVE SUB DESCRIPTION...  (failed units may be prefixed with a marker)
        let line = line.trim_start_matches(['●', '*', ' ']);
        let mut parts = line.split_whitespace();
        let (Some(name), Some(load), Some(active), Some(_sub)) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        if !name.ends_with(".service") || load == "not-found" {
            continue;
        }
        let state = match active {
            "active" | "reloading" | "refreshing" => ServiceState::Running,
            "inactive" => ServiceState::Stopped,
            "failed" => ServiceState::Failed,
            "activating" => ServiceState::Starting,
            "deactivating" => ServiceState::Stopping,
            _ => ServiceState::Unknown,
        };
        let display_name = parts.collect::<Vec<_>>().join(" ");
        let start_mode = if load == "masked" { StartMode::Disabled } else { StartMode::Unknown };
        out.insert(name.to_string(), ServiceInfo { name: name.to_string(), display_name, state, start_mode });
    }
    for line in files.lines() {
        let mut parts = line.split_whitespace();
        let (Some(name), Some(enablement)) = (parts.next(), parts.next()) else { continue };
        // Templates (foo@.service) aren't services until instantiated; aliases repeat another unit.
        if !name.ends_with(".service") || name.contains("@.") || enablement == "alias" {
            continue;
        }
        let mode = match enablement {
            "enabled" | "enabled-runtime" => StartMode::Auto,
            "disabled" | "masked" | "masked-runtime" => StartMode::Disabled,
            "static" | "indirect" | "generated" | "transient" | "linked" | "linked-runtime" => StartMode::Manual,
            _ => StartMode::Unknown,
        };
        out.entry(name.to_string())
            .and_modify(|s| {
                if s.start_mode != StartMode::Disabled {
                    s.start_mode = mode
                }
            })
            .or_insert_with(|| ServiceInfo {
                name: name.to_string(),
                display_name: String::new(),
                state: ServiceState::Stopped,
                start_mode: mode,
            });
    }
    out.into_values().collect()
}

#[cfg(target_os = "linux")]
async fn run_control(name: &str, action: ServiceAction) -> Result<()> {
    let mut c = Command::new("systemctl");
    // `--` so a name can never be read as an option (it's also checked against the list).
    c.args([action.as_str(), "--no-ask-password", "--", name]);
    output(c).await.map(drop)
}

// ---------------------------------------------------------------------------
// Windows: Service Control Manager, through PowerShell
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn powershell(script: &str) -> Command {
    let mut c = Command::new("powershell.exe");
    c.args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script]);
    c
}

#[cfg(windows)]
pub async fn list() -> Result<Vec<ServiceInfo>> {
    // Tab-separated, one service per line. Tabs and newlines can't appear in these fields.
    let script = "[Console]::OutputEncoding = [Text.Encoding]::UTF8; \
        Get-CimInstance Win32_Service | ForEach-Object { \"$($_.Name)`t$($_.DisplayName)`t$($_.State)`t$($_.StartMode)\" }";
    Ok(parse_windows(&output(powershell(script)).await?))
}

#[cfg(any(windows, test))]
fn parse_windows(out: &str) -> Vec<ServiceInfo> {
    let mut list: Vec<ServiceInfo> = out
        .lines()
        .filter_map(|l| {
            let mut p = l.trim_end_matches('\r').split('\t');
            let name = p.next()?.trim();
            if name.is_empty() {
                return None;
            }
            let display_name = p.next().unwrap_or_default().trim().to_string();
            let state = match p.next().unwrap_or_default().trim() {
                "Running" => ServiceState::Running,
                "Stopped" => ServiceState::Stopped,
                "Start Pending" | "Continue Pending" => ServiceState::Starting,
                "Stop Pending" | "Pause Pending" => ServiceState::Stopping,
                "Paused" => ServiceState::Paused,
                _ => ServiceState::Unknown,
            };
            let start_mode = match p.next().unwrap_or_default().trim() {
                "Auto" | "Boot" | "System" => StartMode::Auto,
                "Manual" => StartMode::Manual,
                "Disabled" => StartMode::Disabled,
                _ => StartMode::Unknown,
            };
            Some(ServiceInfo { name: name.to_string(), display_name, state, start_mode })
        })
        .collect();
    list.sort_by_key(|s| s.name.to_lowercase());
    list
}

#[cfg(windows)]
async fn run_control(name: &str, action: ServiceAction) -> Result<()> {
    // The name travels in an environment variable, never inside the script text.
    let verb = match action {
        ServiceAction::Start => "Start-Service -Name $env:RMM_SERVICE -ErrorAction Stop",
        ServiceAction::Stop => "Stop-Service -Name $env:RMM_SERVICE -Force -ErrorAction Stop",
        ServiceAction::Restart => "Restart-Service -Name $env:RMM_SERVICE -Force -ErrorAction Stop",
    };
    let mut c = powershell(verb);
    c.env("RMM_SERVICE", name);
    output(c).await.map(drop)
}

// ---------------------------------------------------------------------------
// Elsewhere (macOS for now): no service support yet.
// ---------------------------------------------------------------------------

#[cfg(not(any(target_os = "linux", windows)))]
pub async fn list() -> Result<Vec<ServiceInfo>> {
    bail!("service monitoring isn't supported on this OS yet")
}

#[cfg(not(any(target_os = "linux", windows)))]
async fn run_control(_name: &str, _action: ServiceAction) -> Result<()> {
    bail!("service control isn't supported on this OS yet")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systemd_units_and_files_merge() {
        let units = "\
cron.service                 loaded    active   running Regular background program processing daemon
● nginx.service              loaded    failed   failed  A high performance web server
snapd.service                masked    inactive dead    snapd.service
ghost.service                not-found inactive dead    ghost.service
systemd-journald.socket      loaded    active   running Journal Socket
";
        let files = "\
cron.service                 enabled         enabled
nginx.service                enabled         enabled
snapd.service                masked          enabled
getty@.service               enabled         enabled
dbus-org.freedesktop.service alias           -
rsync.service                disabled        enabled
systemd-journald.service     static          -
";
        let list = parse_systemd(units, files);
        let get = |n: &str| list.iter().find(|s| s.name == n).cloned();
        let cron = get("cron.service").unwrap();
        assert_eq!((cron.state, cron.start_mode), (ServiceState::Running, StartMode::Auto));
        assert_eq!(cron.display_name, "Regular background program processing daemon");
        assert_eq!(get("nginx.service").unwrap().state, ServiceState::Failed);
        assert_eq!(get("snapd.service").unwrap().start_mode, StartMode::Disabled);
        let rsync = get("rsync.service").unwrap();
        assert_eq!((rsync.state, rsync.start_mode), (ServiceState::Stopped, StartMode::Disabled));
        assert_eq!(get("systemd-journald.service").unwrap().start_mode, StartMode::Manual);
        assert!(get("ghost.service").is_none() && get("getty@.service").is_none());
        assert!(get("dbus-org.freedesktop.service").is_none() && get("systemd-journald.socket").is_none());
    }

    #[test]
    fn windows_services_parse() {
        let out = "Spooler\tPrint Spooler\tRunning\tAuto\r\nwuauserv\tWindows Update\tStopped\tManual\r\n\r\nBad\t\t\t\r\n";
        let list = parse_windows(out);
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].name, "Bad");
        let spooler = list.iter().find(|s| s.name == "Spooler").unwrap();
        assert_eq!((spooler.state, spooler.start_mode), (ServiceState::Running, StartMode::Auto));
        assert_eq!(spooler.display_name, "Print Spooler");
    }
}
