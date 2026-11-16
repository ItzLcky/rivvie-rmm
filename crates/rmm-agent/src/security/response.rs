//! Response actions (Phase 8, milestone 5): kill a process tree, quarantine and restore
//! files, isolate the machine, collect a triage package. They run in the agent, not the
//! sensor, so they work with the sensor switched off.

use std::collections::HashSet;
use std::io::Write;
use std::path::Path;

use anyhow::{Result, bail};
use rmm_proto::telemetry::Proc;
use sha2::{Digest, Sha256};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};

use super::quarantine::Store;

/// Kills `pid` (and, with `tree`, everything started under it, children first).
pub fn kill_process(pid: u32, tree: bool) -> Result<(String, serde_json::Value)> {
    let mut sys = System::new()?;
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing());
    let root = sysinfo::Pid::from_u32(pid);
    let Some(p) = sys.process(root) else { bail!("no process {pid} on this machine (it may have exited)") };
    let as_proc = |p: &sysinfo::Process, pid: sysinfo::Pid| Proc {
        pid: pid.as_u32(),
        ppid: p.parent().map(|x| x.as_u32()).unwrap_or(0),
        name: p.name().to_string_lossy().into_owned(),
        ..Default::default()
    };
    if crate::sensor::procs::protected(&as_proc(p, root)) {
        bail!("{} ({pid}) is a protected system or agent process", p.name().to_string_lossy());
    }
    let mut order = vec![root];
    if tree {
        let mut i = 0;
        let mut seen: HashSet<sysinfo::Pid> = [root].into();
        while i < order.len() {
            let parent = order[i];
            for (cpid, c) in sys.processes() {
                if c.parent() == Some(parent) && seen.insert(*cpid) && c.thread_kind().is_none() {
                    order.push(*cpid);
                }
            }
            i += 1;
        }
    }
    let mut killed = Vec::new();
    let mut skipped = Vec::new();
    for pid in order.iter().rev() {
        let Some(p) = sys.process(*pid) else { continue };
        let name = p.name().to_string_lossy().into_owned();
        if crate::sensor::procs::protected(&as_proc(p, *pid)) {
            skipped.push(format!("{name} ({pid})"));
        } else if p.kill() {
            killed.push(format!("{name} ({pid})"));
        } else {
            skipped.push(format!("{name} ({pid}): couldn't kill"));
        }
    }
    if killed.is_empty() {
        bail!("nothing killed: {}", skipped.join(", "));
    }
    let mut msg = format!("Killed {}", killed.join(", "));
    if !skipped.is_empty() {
        msg.push_str(&format!("; left {}", skipped.join(", ")));
    }
    Ok((msg, serde_json::json!({ "killed": killed, "skipped": skipped })))
}

/// A technician's request: any absolute path, OS files included (no [`super::quarantine::guarded`]
/// check; that only stops automatic quarantine), but no `..`.
pub fn quarantine_file(path: &str) -> Result<(String, serde_json::Value)> {
    let path = crate::fsutil::checked_absolute(Path::new(path))?;
    let item = Store::open()?.quarantine(&path, Some("quarantined by a technician".into()), None)?;
    Ok((format!("Quarantined {} ({} bytes)", item.path, item.size), serde_json::to_value(&item)?))
}

pub fn restore_file(id: uuid::Uuid) -> Result<(String, serde_json::Value)> {
    let to = Store::open()?.restore(id, None)?;
    Ok((format!("Restored {to}"), serde_json::json!({ "id": id, "path": to })))
}

pub fn delete_quarantined(id: uuid::Uuid) -> Result<(String, serde_json::Value)> {
    let path = Store::open()?.delete(id)?;
    Ok((format!("Deleted the quarantined copy of {path}"), serde_json::json!({ "id": id, "path": path })))
}

// ---------------------------------------------------------------------------
// Triage
// ---------------------------------------------------------------------------

const PART_MAX: usize = 8 * 1024 * 1024;

fn command(program: &str, args: &[&str]) -> Vec<u8> {
    let log = crate::patch::cmd::Log::default();
    let opts = crate::patch::cmd::Opts { timeout: std::time::Duration::from_secs(120), log: false, ..Default::default() };
    match crate::patch::cmd::output(&log, program, args, opts) {
        Ok(o) => {
            let mut b = o.stdout.into_bytes();
            if !o.stderr.trim().is_empty() {
                b.extend_from_slice(format!("\n--- stderr ---\n{}", o.stderr).as_bytes());
            }
            b.truncate(PART_MAX);
            b
        }
        Err(e) => format!("{program} {}: {e:#}\n", args.join(" ")).into_bytes(),
    }
}

fn processes() -> serde_json::Value {
    let Ok(mut sys) = System::new() else { return serde_json::Value::Null };
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing().with_cmd(sysinfo::UpdateKind::Always).with_exe(sysinfo::UpdateKind::Always).with_user(sysinfo::UpdateKind::Always).with_memory(),
    );
    let Ok(users) = sysinfo::Users::new_with_refreshed_list() else { return serde_json::Value::Null };
    let mut list: Vec<serde_json::Value> = sys
        .processes()
        .iter()
        .filter(|(_, p)| p.thread_kind().is_none())
        .map(|(pid, p)| {
            serde_json::json!({
                "pid": pid.as_u32(),
                "ppid": p.parent().map(|x| x.as_u32()),
                "name": p.name().to_string_lossy(),
                "exe": p.exe().map(|e| e.to_string_lossy().into_owned()),
                "command_line": p.cmd().iter().map(|s| s.to_string_lossy().into_owned()).collect::<Vec<_>>().join(" "),
                "user": p.user_id().and_then(|u| users.get_user_by_id(u)).map(|u| u.name().to_string()),
                "started": p.start_time(),
                "memory": p.memory(),
            })
        })
        .collect();
    list.sort_by_key(|v| v["pid"].as_u64());
    serde_json::Value::Array(list)
}

/// Builds the package (a .tar.gz). Returns its bytes.
pub fn collect_triage(sensor: serde_json::Value) -> Result<Vec<u8>> {
    let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut tar = tar::Builder::new(gz);
    let mut add = |name: &str, data: &[u8]| -> Result<()> {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o600);
        h.set_mtime(chrono::Utc::now().timestamp().max(0) as u64);
        h.set_cksum();
        tar.append_data(&mut h, name, data)?;
        Ok(())
    };
    let system = serde_json::json!({
        "collected_at": chrono::Utc::now(),
        "agent_version": crate::collect::AGENT_VERSION,
        "system": crate::collect::system_info(),
        "isolation": super::isolation::state(),
        "sensor": sensor,
    });
    add("system.json", &serde_json::to_vec_pretty(&system)?)?;
    add("processes.json", &serde_json::to_vec_pretty(&processes())?)?;
    let conns: Vec<serde_json::Value> = crate::sensor::netconn::list()
        .into_iter()
        .map(|c| serde_json::json!({ "protocol": c.protocol, "local": format!("{}:{}", c.local_addr, c.local_port), "remote": format!("{}:{}", c.remote_addr, c.remote_port), "state": c.state, "pid": c.pid }))
        .collect();
    add("connections.json", &serde_json::to_vec_pretty(&conns)?)?;
    add("quarantine.json", &serde_json::to_vec_pretty(&Store::open().map(|s| s.list()).unwrap_or_default())?)?;
    if cfg!(windows) {
        add("autoruns/scheduled-tasks.csv", &command("schtasks.exe", &["/query", "/fo", "csv", "/v"]))?;
        add("autoruns/run-keys.txt", &command("reg.exe", &["query", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "/s"]))?;
        add("autoruns/services.txt", &command("sc.exe", &["query", "type=", "service", "state=", "all"]))?;
        add("logs/system.txt", &command("wevtutil.exe", &["qe", "System", "/c:2000", "/rd:true", "/f:text"]))?;
        add("logs/security.txt", &command("wevtutil.exe", &["qe", "Security", "/c:2000", "/rd:true", "/f:text"]))?;
        add("logs/application.txt", &command("wevtutil.exe", &["qe", "Application", "/c:1000", "/rd:true", "/f:text"]))?;
        add("users.txt", &command("query.exe", &["user"]))?;
        add("network/ipconfig.txt", &command("ipconfig.exe", &["/all"]))?;
        add("network/dns-cache.txt", &command("ipconfig.exe", &["/displaydns"]))?;
    } else if cfg!(target_os = "macos") {
        add("autoruns/launchctl.txt", &command("launchctl", &["list"]))?;
        add("logs/last-hour.txt", &command("log", &["show", "--last", "1h", "--style", "compact"]))?;
        add("users.txt", &command("last", &["-50"]))?;
        add("network/ifconfig.txt", &command("ifconfig", &[]))?;
    } else {
        add("autoruns/systemd-enabled.txt", &command("systemctl", &["list-unit-files", "--state=enabled", "--no-pager"]))?;
        add("autoruns/timers.txt", &command("systemctl", &["list-timers", "--all", "--no-pager"]))?;
        for f in ["/etc/crontab", "/etc/ld.so.preload", "/etc/rc.local", "/etc/passwd", "/etc/sudoers"] {
            if let Ok(b) = std::fs::read(f) {
                add(&format!("files{f}"), &b[..b.len().min(PART_MAX)])?;
            }
        }
        for pattern in ["/etc/cron.d/*", "/var/spool/cron/crontabs/*", "/var/spool/cron/*", "/root/.ssh/authorized_keys", "/home/*/.ssh/authorized_keys"] {
            let (dir, file) = pattern.rsplit_once('/').unwrap_or(("", pattern));
            for d in crate::sensor::watch::expand(dir) {
                let entries: Vec<std::path::PathBuf> =
                    if file == "*" { std::fs::read_dir(&d).into_iter().flatten().flatten().map(|e| e.path()).collect() } else { vec![d.join(file)] };
                for p in entries.into_iter().filter(|p| p.is_file()) {
                    if let Ok(b) = std::fs::read(&p) {
                        add(&format!("files{}", p.display()), &b[..b.len().min(PART_MAX)])?;
                    }
                }
            }
        }
        add("logs/journal.txt", &command("journalctl", &["-n", "5000", "--no-pager", "-o", "short-iso"]))?;
        add("logs/auth.txt", &command("journalctl", &["-n", "2000", "--no-pager", "-o", "short-iso", "SYSLOG_FACILITY=10"]))?;
        add("users.txt", &command("last", &["-n", "50"]))?;
        add("network/ip.txt", &command("ip", &["addr"]))?;
        add("network/routes.txt", &command("ip", &["route"]))?;
    }
    // The newest telemetry, raw, up to 32 MB.
    if let Ok(dir) = crate::sensor::store::dir() {
        let mut segs: Vec<std::path::PathBuf> = std::fs::read_dir(&dir).into_iter().flatten().flatten().map(|e| e.path()).collect();
        segs.sort();
        let mut budget: u64 = 32 * 1024 * 1024;
        for p in segs.into_iter().rev() {
            let Ok(b) = std::fs::read(&p) else { continue };
            if b.len() as u64 > budget {
                break;
            }
            budget -= b.len() as u64;
            add(&format!("telemetry/{}", p.file_name().unwrap_or_default().to_string_lossy()), &b)?;
        }
    }
    let mut gz = tar.into_inner()?;
    gz.flush()?;
    let out = gz.finish()?;
    if out.len() as u64 > rmm_proto::security::TRIAGE_MAX {
        bail!("the package came to {} MB, over the {} MB limit", out.len() / 1024 / 1024, rmm_proto::security::TRIAGE_MAX / 1024 / 1024);
    }
    Ok(out)
}

pub fn sha256(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Needs a POSIX shell's job control; Git's sh on Windows spawns differently.
    #[cfg(unix)]
    #[test]
    fn kills_a_process_tree_children_first() {
        let mut child = std::process::Command::new("sh").args(["-c", "sleep 60 & sleep 60 & wait"]).spawn().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300));
        let (msg, data) = kill_process(child.id(), true).unwrap();
        assert_eq!(data["killed"].as_array().unwrap().len(), 3, "{msg}");
        assert!(child.wait().is_ok());
        assert!(kill_process(1, false).unwrap_err().to_string().contains("protected"));
        assert!(kill_process(u32::MAX - 7, false).is_err());
    }

    /// Checked before the store is even opened, so this touches nothing.
    #[test]
    fn quarantine_needs_an_absolute_path_without_dotdot() {
        assert!(quarantine_file("evil.bin").unwrap_err().to_string().contains("absolute"));
        let up = if cfg!(windows) { "C:\\no-such-dir-rmm\\..\\evil.bin" } else { "/no-such-dir-rmm/../evil.bin" };
        assert!(quarantine_file(up).unwrap_err().to_string().contains(".."));
    }

    #[test]
    fn triage_package_is_a_tarball() {
        let dir = std::env::temp_dir().join(format!("rmm-triage-{}", uuid::Uuid::new_v4()));
        // SAFETY: tests in this module don't read the variable concurrently.
        unsafe { std::env::set_var("RMM_STATE_DIR", &dir) };
        let pkg = collect_triage(serde_json::json!({ "running": false })).unwrap();
        let mut ar = tar::Archive::new(flate2::read::GzDecoder::new(&pkg[..]));
        let names: Vec<String> = ar.entries().unwrap().map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned()).collect();
        assert!(names.contains(&"system.json".to_string()) && names.contains(&"processes.json".to_string()) && names.contains(&"connections.json".to_string()), "{names:?}");
        let _ = std::fs::remove_dir_all(dir);
    }
}
