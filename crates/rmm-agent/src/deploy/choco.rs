//! Chocolatey. Found on PATH or under `ChocolateyInstall`/`ProgramData`; when it's missing, a
//! run may install it with the official script, but only when the policy (or the person
//! deploying) allowed that: it downloads and runs a script from chocolatey.org.

#![cfg_attr(not(windows), allow(dead_code))]

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Result, bail};
use rmm_proto::patch::PatchStage;
use rmm_proto::software::{Op, Package, Status};

use super::parse::{choco_exit, parse_choco_list, parse_choco_outdated};
use super::{Done, Provider, RunCtx};
use crate::patch::cmd::{self, Log, Opts};

pub struct Choco;

fn locate() -> Option<PathBuf> {
    if cmd::which("choco") {
        return Some(PathBuf::from("choco"));
    }
    let roots = [std::env::var_os("ChocolateyInstall"), std::env::var_os("ProgramData").map(|p| PathBuf::from(p).join("chocolatey").into_os_string())];
    roots.into_iter().flatten().map(|r| PathBuf::from(r).join("bin").join("choco.exe")).find(|p| p.is_file())
}

impl Choco {
    pub fn new() -> Self {
        Choco
    }

    fn exe(&self) -> Option<String> {
        locate().map(|p| p.to_string_lossy().into_owned())
    }

    fn major(&self, exe: &str, log: &Log) -> u32 {
        cmd::output(log, exe, &["--version"], Opts { log: false, timeout: Duration::from_secs(60), ..Default::default() })
            .ok()
            .and_then(|o| o.stdout.lines().find_map(|l| l.trim().split('.').next()?.parse().ok()))
            .unwrap_or(2)
    }

    fn bootstrap(&self, ctx: &RunCtx) -> Result<String> {
        (ctx.progress)(PatchStage::Installing, Some("installing Chocolatey".into()));
        // The documented one-liner, run in a process of its own.
        let script = "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))";
        let out = cmd::output(ctx.log, "powershell.exe", &["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], Opts { timeout: Duration::from_secs(900), ..Default::default() })?;
        if !out.success() {
            bail!("installing Chocolatey failed: {}", out.reason());
        }
        self.exe().ok_or_else(|| anyhow::anyhow!("Chocolatey's installer finished but choco.exe isn't where it should be"))
    }
}

impl Provider for Choco {
    fn name(&self) -> &'static str {
        "choco"
    }

    fn available(&self) -> bool {
        locate().is_some()
    }

    fn can_bootstrap(&self) -> bool {
        true
    }

    fn handles(&self, pkg: &Package) -> bool {
        pkg.choco.is_some()
    }

    fn scan(&self, pkgs: &[&Package], log: &Log, _refresh: bool) -> Result<Vec<Status>> {
        let exe = self.exe().ok_or_else(|| anyhow::anyhow!("Chocolatey isn't installed on this machine"))?;
        // Chocolatey 2 lists only local packages; 1.x needs the flag (and lists remote ones without it).
        let list_args: &[&str] = if self.major(&exe, log) >= 2 { &["list", "--limit-output"] } else { &["list", "--local-only", "--limit-output"] };
        let list = cmd::output(log, &exe, list_args, Opts { log: false, timeout: Duration::from_secs(300), ..Default::default() })?;
        if !list.success() {
            bail!("choco list failed: {}", list.reason());
        }
        let installed = parse_choco_list(&list.stdout);
        // Exit 2 means "some packages are outdated".
        let out = cmd::output(log, &exe, &["outdated", "--limit-output", "--ignore-unfound"], Opts { log: false, timeout: Duration::from_secs(600), ..Default::default() })?;
        let available: HashMap<String, String> = if matches!(out.code, Some(0 | 2)) { parse_choco_outdated(&out.stdout) } else { HashMap::new() };
        Ok(pkgs
            .iter()
            .map(|p| {
                let id = p.choco.as_deref().unwrap_or_default().to_ascii_lowercase();
                Status { package_id: p.id, installed: installed.get(&id).cloned(), available: available.get(&id).cloned(), provider: Some("choco".into()) }
            })
            .collect())
    }

    fn run(&self, op: Op, pkg: &Package, ctx: &RunCtx) -> Result<Done> {
        let exe = match self.exe() {
            Some(e) => e,
            None if ctx.bootstrap_choco => self.bootstrap(ctx)?,
            None => bail!("Chocolatey isn't installed on this machine (the policy doesn't allow installing it)"),
        };
        let id = pkg.choco.as_deref().unwrap_or_default();
        let verb = match op {
            Op::Install => "install",
            Op::Upgrade => "upgrade",
            Op::Uninstall => "uninstall",
        };
        let mut args = vec![verb, id, "-y", "--no-progress", "--limit-output"];
        if op != Op::Uninstall
            && let Some(v) = &pkg.version
        {
            args.extend(["--version", v.as_str()]);
            // Moving to an exact version may mean going back.
            args.push("--allow-downgrade");
        }
        (ctx.progress)(PatchStage::Installing, Some(format!("choco {verb} {id}")));
        let out = cmd::run(ctx.log, &exe, &args, Opts { timeout: Duration::from_secs(3600), ..Default::default() }, &mut |_| {})?;
        match choco_exit(out.code) {
            Some(reboot) => Ok(Done { reboot_required: reboot, note: None }),
            None => bail!("choco {verb} failed (exit {}): {}", out.code.map_or("none".into(), |c| c.to_string()), out.reason()),
        }
    }
}
