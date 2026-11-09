//! Debug builds only: a provider backed by a JSON file (`RMM_PATCH_FAKE`), so end-to-end
//! tests exercise the whole scan/approve/install path without touching the real package
//! manager. Installing removes the updates from the file, except ids listed in `fail`.

use std::path::PathBuf;

use anyhow::{Context, Result};
use rmm_proto::patch::{PatchItemResult, PatchStage, PatchUpdate};
use serde::{Deserialize, Serialize};

use super::cmd::Log;
use super::{Installed, PatchProvider, Progress};

#[derive(Default, Serialize, Deserialize)]
struct State {
    #[serde(default)]
    updates: Vec<PatchUpdate>,
    #[serde(default)]
    reboot_pending: bool,
    #[serde(default)]
    fail: Vec<String>,
}

pub struct FileProvider(pub PathBuf);

impl FileProvider {
    fn load(&self) -> Result<State> {
        match std::fs::read_to_string(&self.0) {
            Ok(s) => serde_json::from_str(&s).with_context(|| format!("parsing {}", self.0.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
            Err(e) => Err(e.into()),
        }
    }
}

impl PatchProvider for FileProvider {
    fn name(&self) -> &'static str {
        "fake"
    }

    fn scan(&self, _: &Log, _: Progress, _: bool) -> Result<Vec<PatchUpdate>> {
        Ok(self.load()?.updates)
    }

    fn install(&self, ids: &[String], log: &Log, progress: Progress) -> Result<Installed> {
        let mut s = self.load()?;
        progress(PatchStage::Installing, Some(format!("installing {} updates", ids.len())), Some(50));
        let mut results = Vec::new();
        for id in ids {
            let ok = !s.fail.contains(id);
            log.push(&format!("{id}: {}\n", if ok { "installed" } else { "failed" }));
            if ok && let Some(i) = s.updates.iter().position(|u| &u.id == id) {
                s.reboot_pending |= s.updates.remove(i).requires_reboot;
            }
            results.push(PatchItemResult { id: id.clone(), ok, message: (!ok).then(|| "simulated failure".to_string()) });
        }
        std::fs::write(&self.0, serde_json::to_vec_pretty(&s)?)?;
        Ok(Installed { results, reboot_required: s.reboot_pending })
    }

    fn reboot_pending(&self) -> bool {
        self.load().is_ok_and(|s| s.reboot_pending)
    }
}
