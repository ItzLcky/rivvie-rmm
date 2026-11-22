//! Windows Package Manager (winget).
//!
//! The agent runs as SYSTEM, which has no `winget` on its PATH: the App Installer package lives
//! in `C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_<version>_x64__8wekyb3d8bbwe`,
//! which SYSTEM can read, so the agent finds the newest one itself and puts its directory on
//! the PATH of the process (its dependencies sit beside it). Sources are limited to `winget`
//! so the Store's agreements and certificate checks don't get in the way, and machine scope is
//! tried first, falling back to winget's choice for packages without a machine installer.

#![cfg_attr(not(windows), allow(dead_code))]

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Result, bail};
use rmm_proto::patch::PatchStage;
use rmm_proto::software::{Op, Package, Status};

use super::parse::{WingetExit, parse_winget_list, pick_winget_dir, winget_exit};
use super::{Done, Provider, RunCtx};
use crate::patch::cmd::{self, Log, Opts};

pub struct Winget {
    exe: Option<PathBuf>,
}

/// The directory name list of `WindowsApps` and the winget inside the newest App Installer.
fn locate() -> Option<PathBuf> {
    let root = std::env::var_os("ProgramFiles").map_or_else(|| PathBuf::from("C:\\Program Files"), PathBuf::from).join("WindowsApps");
    let names: Vec<String> = std::fs::read_dir(&root).ok()?.flatten().filter_map(|e| e.file_name().into_string().ok()).collect();
    let dir = pick_winget_dir(&names)?;
    let exe = root.join(dir).join("winget.exe");
    exe.is_file().then_some(exe)
}

const COMMON: &[&str] = &["--accept-source-agreements", "--disable-interactivity"];

impl Winget {
    pub fn new() -> Self {
        // A winget on PATH (a user-context agent, or a Server with a standalone copy) first.
        let exe = if cmd::which("winget") { Some(PathBuf::from("winget")) } else { locate() };
        Winget { exe }
    }

    fn exe(&self) -> Result<&PathBuf> {
        self.exe.as_ref().ok_or_else(|| anyhow::anyhow!("winget isn't installed on this machine"))
    }

    /// The environment: winget's own directory first on PATH.
    fn path_env(&self) -> Option<String> {
        let dir = self.exe.as_ref()?.parent()?;
        if dir.as_os_str().is_empty() {
            return None;
        }
        let old = std::env::var("PATH").unwrap_or_default();
        Some(format!("{};{old}", dir.display()))
    }

    fn output(&self, log: &Log, args: &[&str], timeout: Duration, to_log: bool, on_line: &mut dyn FnMut(&str)) -> Result<cmd::Output> {
        let exe = self.exe()?.to_string_lossy().into_owned();
        let path = self.path_env();
        let env: Vec<(&str, &str)> = path.as_deref().map(|p| ("PATH", p)).into_iter().collect();
        cmd::run(log, &exe, args, Opts { timeout, env: &env, log: to_log, detach: false }, on_line)
    }
}

impl Provider for Winget {
    fn name(&self) -> &'static str {
        "winget"
    }

    fn available(&self) -> bool {
        self.exe.is_some()
    }

    fn handles(&self, pkg: &Package) -> bool {
        pkg.winget.is_some()
    }

    fn scan(&self, pkgs: &[&Package], log: &Log, _refresh: bool) -> Result<Vec<Status>> {
        let mut args = vec!["list", "--source", "winget"];
        args.extend(COMMON);
        let out = self.output(log, &args, Duration::from_secs(300), false, &mut |_| {})?;
        // Exit 0 with a table; "no installed package found" is a failure code with no table.
        let rows = parse_winget_list(&out.stdout);
        if rows.is_empty() && !out.stdout.contains("No installed package found") && !out.success() {
            // Packages installed by other means show up in an unfiltered list instead.
            let mut args = vec!["list"];
            args.extend(COMMON);
            let all = self.output(log, &args, Duration::from_secs(300), false, &mut |_| {})?;
            if !all.success() {
                bail!("winget list failed: {}", all.reason());
            }
            return Ok(statuses(pkgs, &parse_winget_list(&all.stdout)));
        }
        Ok(statuses(pkgs, &rows))
    }

    fn run(&self, op: Op, pkg: &Package, ctx: &RunCtx) -> Result<Done> {
        let id = pkg.winget.as_deref().unwrap_or_default();
        let verb = match op {
            Op::Install => "install",
            Op::Upgrade => "upgrade",
            Op::Uninstall => "uninstall",
        };
        (ctx.progress)(PatchStage::Installing, Some(format!("winget {verb} {id}")));
        // `--scope machine` can't be satisfied by every package; the second try lets winget choose.
        for scope in [Some("machine"), None] {
            let mut args = vec![verb, "--exact", "--id", id, "--source", "winget", "--silent", "--accept-source-agreements", "--disable-interactivity"];
            if op != Op::Uninstall {
                args.push("--accept-package-agreements");
                if let Some(v) = &pkg.version {
                    args.extend(["--version", v.as_str()]);
                }
            }
            if let Some(s) = scope {
                args.extend(["--scope", s]);
            }
            let out = self.output(ctx.log, &args, Duration::from_secs(3600), true, &mut |line| {
                let l = line.trim();
                if l.starts_with("Downloading") {
                    (ctx.progress)(PatchStage::Downloading, Some(l.to_string()));
                }
            })?;
            match winget_exit(out.code) {
                WingetExit::Ok => return Ok(Done { reboot_required: false, note: None }),
                WingetExit::NothingToDo => return Ok(Done { reboot_required: false, note: Some("nothing to do (already installed or up to date)".into()) }),
                WingetExit::NoApplicableInstaller if scope.is_some() => continue,
                WingetExit::Failed if op == Op::Uninstall && out.stdout.contains("No installed package found") => {
                    return Ok(Done { reboot_required: false, note: Some("it wasn't installed".into()) });
                }
                _ => bail!("winget {verb} failed (exit {}): {}", out.code.map_or("none".into(), |c| format!("{c:#x}")), out.reason()),
            }
        }
        unreachable!("the loop returns or fails on its last iteration")
    }
}

fn statuses(pkgs: &[&Package], rows: &[super::parse::WingetRow]) -> Vec<Status> {
    pkgs.iter()
        .map(|p| {
            let id = p.winget.as_deref().unwrap_or_default();
            let row = rows.iter().find(|r| r.id.eq_ignore_ascii_case(id));
            Status {
                package_id: p.id,
                installed: row.map(|r| r.version.clone()).filter(|v| !v.is_empty()).or_else(|| row.map(|_| "unknown".to_string())),
                available: row.and_then(|r| r.available.clone()),
                provider: Some("winget".into()),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn statuses_match_ids_case_insensitively() {
        let rows = parse_winget_list("Name     Id               Version  Available  Source\n------------------------------------------------------\nFirefox  Mozilla.Firefox  124.0    125.0      winget\n");
        let mk = |id: &str| Package { id: Uuid::new_v4(), name: id.into(), version: None, winget: Some(id.into()), choco: None, apt: None, dnf: None, installer: None };
        let (a, b) = (mk("mozilla.firefox"), mk("Other.App"));
        let s = statuses(&[&a, &b], &rows);
        assert_eq!((s[0].installed.as_deref(), s[0].available.as_deref()), (Some("124.0"), Some("125.0")));
        assert_eq!((s[1].installed.as_deref(), s[1].provider.as_deref()), (None, Some("winget")));
    }
}
