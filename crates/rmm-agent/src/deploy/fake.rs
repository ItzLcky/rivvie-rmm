//! Debug builds only: a provider backed by a JSON file (`RMM_SOFTWARE_FAKE`), so end-to-end
//! tests exercise the whole scan, deploy and enforce path without touching a real package
//! manager. Packages are keyed by apt name, else dnf, Chocolatey or winget id, else name.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use rmm_proto::patch::PatchStage;
use rmm_proto::software::{Op, Package, Status};
use serde::{Deserialize, Serialize};

use super::{Done, Provider, RunCtx};
use crate::patch::Log;

#[derive(Default, Serialize, Deserialize)]
struct State {
    /// key → installed version
    #[serde(default)]
    installed: BTreeMap<String, String>,
    /// key → newer version on offer
    #[serde(default)]
    available: BTreeMap<String, String>,
    /// Keys whose runs fail.
    #[serde(default)]
    fail: Vec<String>,
    /// Keys that finish "successfully" without installing anything.
    #[serde(default)]
    ghost: Vec<String>,
    #[serde(default)]
    reboot: bool,
}

pub struct FileProvider(pub PathBuf);

fn key(p: &Package) -> String {
    p.apt.clone().or_else(|| p.dnf.clone()).or_else(|| p.choco.clone()).or_else(|| p.winget.clone()).unwrap_or_else(|| p.name.to_ascii_lowercase())
}

impl FileProvider {
    fn load(&self) -> Result<State> {
        match std::fs::read_to_string(&self.0) {
            Ok(s) => serde_json::from_str(&s).with_context(|| format!("parsing {}", self.0.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
            Err(e) => Err(e.into()),
        }
    }
}

impl Provider for FileProvider {
    fn name(&self) -> &'static str {
        "fake"
    }

    fn available(&self) -> bool {
        true
    }

    fn handles(&self, _: &Package) -> bool {
        true
    }

    fn scan(&self, pkgs: &[&Package], _: &Log, _: bool) -> Result<Vec<Status>> {
        let s = self.load()?;
        Ok(pkgs
            .iter()
            .map(|p| {
                let k = key(p);
                Status { package_id: p.id, installed: s.installed.get(&k).cloned(), available: s.available.get(&k).cloned(), provider: Some("fake".into()) }
            })
            .collect())
    }

    fn run(&self, op: Op, pkg: &Package, ctx: &RunCtx) -> Result<Done> {
        let mut s = self.load()?;
        let k = key(pkg);
        (ctx.progress)(PatchStage::Installing, Some(format!("{} {k}", op.as_str())));
        ctx.log.push(&format!("{} {k}\n", op.as_str()));
        if s.fail.contains(&k) {
            bail!("simulated failure installing {k}");
        }
        if !s.ghost.contains(&k) {
            match op {
                Op::Uninstall => {
                    s.installed.remove(&k);
                }
                Op::Install | Op::Upgrade => {
                    let version = pkg.version.clone().or_else(|| s.available.remove(&k)).unwrap_or_else(|| "1.0.0".into());
                    if s.available.get(&k).is_some_and(|a| a == &version) {
                        s.available.remove(&k);
                    }
                    s.installed.insert(k, version);
                }
            }
        }
        std::fs::write(&self.0, serde_json::to_vec_pretty(&s)?)?;
        Ok(Done { reboot_required: s.reboot, note: None })
    }
}
