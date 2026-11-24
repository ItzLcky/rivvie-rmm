//! Debug builds only: the disk encryption state read from a JSON file (`RMM_DISKENC_FAKE`)
//! while it exists, so the e2e suite can encrypt, suspend and re-key volumes. Without the file,
//! the real reader of the platform answers.
//!
//! The file holds a [`Report`] plus `keys` (protector id → recovery password) and `fail` (a
//! protector change fails with this message).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use rmm_proto::diskenc::{ProtectorOp, Report};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Default, Serialize, Deserialize)]
struct State {
    #[serde(flatten)]
    report: Report,
    #[serde(default)]
    keys: BTreeMap<String, String>,
    #[serde(default)]
    fail: Option<String>,
}

pub struct FileProvider {
    pub path: PathBuf,
    pub real: Arc<dyn super::Provider>,
}

impl FileProvider {
    fn load(&self) -> Result<Option<State>> {
        match std::fs::read_to_string(&self.path) {
            Ok(s) => Ok(Some(serde_json::from_str(&s).with_context(|| format!("parsing {}", self.path.display()))?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

/// 48 digits in eight groups, like BitLocker's.
fn new_key() -> String {
    let b = Uuid::new_v4().as_u128() ^ (Uuid::new_v4().as_u128() << 7);
    (0..8).map(|i| format!("{:06}", ((b >> (i * 16)) as u32 & 0xffff) as u64 * 11 % 1_000_000)).collect::<Vec<_>>().join("-")
}

impl super::Provider for FileProvider {
    fn report(&self) -> Report {
        match self.load() {
            Ok(Some(s)) => s.report,
            Ok(None) => self.real.report(),
            Err(e) => Report { error: Some(format!("{e:#}")), ..Default::default() },
        }
    }

    fn recovery_key(&self, volume_id: &str, protector_id: &str) -> Result<String> {
        let Some(s) = self.load()? else { return self.real.recovery_key(volume_id, protector_id) };
        s.keys.get(protector_id).cloned().with_context(|| format!("volume {volume_id} has no recovery password {protector_id}"))
    }

    fn protector(&self, volume_id: &str, op: ProtectorOp) -> Result<String> {
        let Some(mut s) = self.load()? else { return self.real.protector(volume_id, op) };
        if let Some(f) = &s.fail {
            bail!("{f}");
        }
        let Some(v) = s.report.volumes.iter_mut().find(|v| v.volume_id == volume_id) else { bail!("no volume {volume_id}") };
        let id = format!("{{{}}}", Uuid::new_v4().to_string().to_uppercase());
        if let Some(old) = v.recovery_protector_id.replace(id.clone()) {
            s.keys.remove(&old);
        }
        if !v.protectors.iter().any(|p| p == "recovery_password") {
            v.protectors.push("recovery_password".into());
        }
        s.keys.insert(id.clone(), new_key());
        std::fs::write(&self.path, serde_json::to_vec_pretty(&s)?)?;
        Ok(match op {
            ProtectorOp::AddRecovery => format!("Added recovery password {id}"),
            ProtectorOp::RotateRecovery => format!("Replaced the recovery password with {id}"),
        })
    }
}
