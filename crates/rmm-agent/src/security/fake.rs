//! Debug builds only: protection state read from a JSON file (`RMM_SECURITY_FAKE`), so
//! end-to-end tests can switch protection off, age signatures and plant detections.
//!
//! The file holds a [`Report`] plus test knobs: `scan_finds` (detections a scan "finds"),
//! `fail` (actions that fail) and `scan_ms` (how long actions take).

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chrono::Utc;
use rmm_proto::security::{Action, Detection, ProductKind, Report};
use serde::{Deserialize, Serialize};

#[derive(Default, Serialize, Deserialize)]
struct State {
    #[serde(flatten)]
    report: Report,
    #[serde(default)]
    scan_finds: Vec<Detection>,
    #[serde(default)]
    fail: Vec<Action>,
    #[serde(default)]
    scan_ms: u64,
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

impl super::Provider for FileProvider {
    fn status(&self) -> Report {
        match self.load() {
            Ok(s) => s.report,
            Err(e) => Report { error: Some(format!("{e:#}")), ..Default::default() },
        }
    }

    fn run(&self, product: ProductKind, action: Action) -> Result<String> {
        let mut s = self.load()?;
        std::thread::sleep(Duration::from_millis(s.scan_ms));
        if s.fail.contains(&action) {
            bail!("simulated {} failure", action.label());
        }
        let Some(p) = s.report.products.iter_mut().find(|p| p.kind == product && p.actions.contains(&action)) else {
            bail!("no product here can run a {}", action.label());
        };
        let now = Utc::now();
        let msg = match action {
            Action::QuickScan | Action::FullScan => {
                if action == Action::QuickScan {
                    p.last_quick_scan = Some(now);
                } else {
                    p.last_full_scan = Some(now);
                }
                let found = std::mem::take(&mut s.scan_finds);
                let n = found.len();
                s.report.detections.extend(found);
                if n == 0 { "No threats found".to_string() } else { format!("Found {n} threats") }
            }
            Action::UpdateSignatures => {
                p.signatures_updated_at = Some(now);
                "Signatures updated".to_string()
            }
        };
        std::fs::write(&self.0, serde_json::to_vec_pretty(&s)?)?;
        Ok(msg)
    }
}
