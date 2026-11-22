//! Fedora, RHEL and derivatives: dnf (dnf5, or yum on old systems). Scans read the rpm
//! database and `check-update`; runs use the package manager non-interactively in its own
//! systemd scope.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::time::Duration;

use anyhow::{Result, bail};
use rmm_proto::patch::PatchStage;
use rmm_proto::software::{Op, Package, Status};

use super::parse::parse_rpm;
use super::{Done, Provider, RunCtx};
use crate::patch::cmd::{self, Log, Opts};

pub struct Dnf {
    bin: &'static str,
}

impl Dnf {
    pub fn new() -> Self {
        Dnf { bin: if cmd::which("dnf") { "dnf" } else { "dnf5" } }
    }

    pub fn yum() -> Self {
        Dnf { bin: "yum" }
    }
}

impl Provider for Dnf {
    fn name(&self) -> &'static str {
        "dnf"
    }

    fn available(&self) -> bool {
        cmd::which(self.bin)
    }

    fn handles(&self, pkg: &Package) -> bool {
        pkg.dnf.is_some()
    }

    fn scan(&self, pkgs: &[&Package], log: &Log, refresh: bool) -> Result<Vec<Status>> {
        let out = cmd::output(log, "rpm", &["-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"], Opts { log: false, ..Default::default() })?;
        if !out.success() {
            bail!("rpm -qa failed: {}", out.reason());
        }
        let installed = parse_rpm(&out.stdout);
        let args = ["-q", "check-update", if refresh { "--refresh" } else { "--cacheonly" }];
        let check = cmd::output(log, self.bin, &args, Opts { timeout: Duration::from_secs(900), log: false, ..Default::default() })?;
        // 100: updates available, 0: none, anything else: couldn't tell (versions on offer unknown).
        let upgrades = if check.code == Some(100) { crate::patch::dnf::parse_check_update(&check.stdout) } else { vec![] };
        Ok(pkgs
            .iter()
            .map(|p| {
                let name = p.dnf.as_deref().unwrap_or_default();
                Status {
                    package_id: p.id,
                    installed: installed.get(name).cloned(),
                    // Update ids are `name.arch`.
                    available: upgrades.iter().find(|u| u.id.rsplit_once('.').map(|(n, _)| n) == Some(name)).and_then(|u| u.version.clone()),
                    provider: Some("dnf".into()),
                }
            })
            .collect())
    }

    fn run(&self, op: Op, pkg: &Package, ctx: &RunCtx) -> Result<Done> {
        let name = pkg.dnf.as_deref().unwrap_or_default();
        let target = match (&pkg.version, op) {
            (Some(v), Op::Install | Op::Upgrade) => format!("{name}-{v}"),
            _ => name.to_string(),
        };
        // `install` of an exact version also upgrades or downgrades to it; without one, upgrade.
        let verb = match op {
            Op::Install => "install",
            Op::Upgrade if pkg.version.is_some() => "install",
            Op::Upgrade => "upgrade",
            Op::Uninstall => "remove",
        };
        let mut args = vec!["-y", verb];
        if pkg.version.is_some() && op != Op::Uninstall {
            args.push("--allowerasing");
        }
        args.push(&target);
        (ctx.progress)(PatchStage::Installing, Some(format!("{} {verb} {target}", self.bin)));
        let out = cmd::run(ctx.log, self.bin, &args, Opts { timeout: Duration::from_secs(3600), detach: true, ..Default::default() }, &mut |line| {
            if line.trim_start().starts_with("Downloading Packages") {
                (ctx.progress)(PatchStage::Downloading, None);
            }
        })?;
        if !out.success() {
            bail!("{} {verb} failed: {}", self.bin, out.reason());
        }
        Ok(Done::default())
    }
}
