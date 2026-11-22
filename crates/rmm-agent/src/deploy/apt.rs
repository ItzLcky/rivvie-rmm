//! Debian and Ubuntu: apt. Scans read dpkg's status and a simulated `dist-upgrade` (the same
//! source the patch scan uses); runs use `apt-get` non-interactively, in its own systemd scope
//! so an agent restart doesn't stop dpkg halfway.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::time::Duration;

use anyhow::{Result, bail};
use rmm_proto::patch::PatchStage;
use rmm_proto::software::{Op, Package, Status};

use super::parse::parse_dpkg;
use super::{Done, Provider, RunCtx};
use crate::patch::cmd::{self, Log, Opts};

pub struct Apt;

const ENV: &[(&str, &str)] = &[("DEBIAN_FRONTEND", "noninteractive"), ("NEEDRESTART_MODE", "a"), ("APT_LISTCHANGES_FRONTEND", "none")];

impl Provider for Apt {
    fn name(&self) -> &'static str {
        "apt"
    }

    fn available(&self) -> bool {
        cmd::which("apt-get")
    }

    fn handles(&self, pkg: &Package) -> bool {
        pkg.apt.is_some()
    }

    fn scan(&self, pkgs: &[&Package], log: &Log, refresh: bool) -> Result<Vec<Status>> {
        if refresh {
            // Best effort: stale lists only make the offered versions stale.
            let _ = cmd::output(log, "apt-get", &["update", "-q"], Opts { env: ENV, timeout: Duration::from_secs(900), ..Default::default() });
        }
        let out = cmd::output(log, "dpkg-query", &["-W", "-f=${Package}\t${Version}\t${Status}\n"], Opts { log: false, ..Default::default() })?;
        if !out.success() {
            bail!("dpkg-query failed: {}", out.reason());
        }
        let installed = parse_dpkg(&out.stdout);
        let sim = cmd::output(log, "apt-get", &["-s", "-q", "dist-upgrade"], Opts { env: ENV, log: false, ..Default::default() })?;
        let upgrades = if sim.success() { crate::patch::apt::parse_simulation(&sim.stdout) } else { vec![] };
        Ok(pkgs
            .iter()
            .map(|p| {
                let name = p.apt.as_deref().unwrap_or_default();
                let base = name.split(':').next().unwrap_or(name);
                Status {
                    package_id: p.id,
                    installed: installed.get(base).cloned(),
                    available: upgrades.iter().find(|u| u.id.split(':').next() == Some(base)).and_then(|u| u.version.clone()),
                    provider: Some("apt".into()),
                }
            })
            .collect())
    }

    fn run(&self, op: Op, pkg: &Package, ctx: &RunCtx) -> Result<Done> {
        let name = pkg.apt.as_deref().unwrap_or_default();
        let target = match (&pkg.version, op) {
            (Some(v), Op::Install | Op::Upgrade) => format!("{name}={v}"),
            _ => name.to_string(),
        };
        let mut args = vec!["-y", "-q", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "-o", "DPkg::Lock::Timeout=600"];
        match op {
            Op::Install => args.push("install"),
            Op::Upgrade => {
                args.push("install");
                args.push("--only-upgrade");
            }
            Op::Uninstall => args.push("remove"),
        }
        if pkg.version.is_some() && op != Op::Uninstall {
            args.push("--allow-downgrades");
        }
        args.push(&target);
        (ctx.progress)(PatchStage::Installing, Some(format!("apt-get {} {target}", args.iter().find(|a| matches!(**a, "install" | "remove")).unwrap_or(&""))));
        let out = cmd::run(ctx.log, "apt-get", &args, Opts { env: ENV, timeout: Duration::from_secs(3600), detach: true, ..Default::default() }, &mut |line| {
            if line.starts_with("Get:") {
                (ctx.progress)(PatchStage::Downloading, Some(line.to_string()));
            }
        })?;
        if !out.success() {
            bail!("apt-get failed: {}", out.reason());
        }
        Ok(Done { reboot_required: std::path::Path::new("/var/run/reboot-required").exists(), note: None })
    }
}
