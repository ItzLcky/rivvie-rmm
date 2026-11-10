//! macOS: XProtect, which is always on. We report its signature version and date (from the
//! bundle), and whether Gatekeeper is enforcing. Signatures update with `xprotect update`
//! (macOS 15+); XProtect has no on-demand scan.

use rmm_proto::security::{Product, ProductKind};

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub const BUNDLE: &str = "/Library/Apple/System/Library/CoreServices/XProtect.bundle";

/// `spctl --status` prints `assessments enabled` or `assessments disabled`.
pub fn gatekeeper_enabled(out: &str) -> Option<bool> {
    let o = out.trim().to_ascii_lowercase();
    if o.contains("assessments enabled") {
        Some(true)
    } else if o.contains("assessments disabled") {
        Some(false)
    } else {
        None
    }
}

pub fn product(version: Option<String>, updated: Option<chrono::DateTime<chrono::Utc>>, gatekeeper: Option<bool>) -> Product {
    let mut p = Product::new(ProductKind::Xprotect, "XProtect");
    p.enabled = Some(version.is_some());
    p.realtime = Some(version.is_some());
    p.signature_version = version;
    p.signatures_updated_at = updated;
    p.detail = match gatekeeper {
        Some(false) => Some("Gatekeeper is turned off: unsigned apps run without checks".into()),
        Some(true) => Some("Gatekeeper is on".into()),
        None => None,
    };
    p
}

#[cfg(target_os = "macos")]
pub struct Xprotect;

#[cfg(target_os = "macos")]
impl super::Provider for Xprotect {
    fn status(&self) -> rmm_proto::security::Report {
        use crate::patch::cmd::{self, Log, Opts};
        let log = Log::default();
        let opts = Opts { timeout: std::time::Duration::from_secs(60), log: false, ..Default::default() };
        let plist = format!("{BUNDLE}/Contents/Info.plist");
        let version = cmd::output(&log, "plutil", &["-extract", "CFBundleShortVersionString", "raw", "-o", "-", &plist], opts)
            .ok()
            .filter(|o| o.success())
            .map(|o| o.stdout.trim().to_string())
            .filter(|v| !v.is_empty());
        let updated = std::fs::metadata(&plist).and_then(|m| m.modified()).ok().map(chrono::DateTime::<chrono::Utc>::from);
        let gatekeeper = cmd::output(&log, "spctl", &["--status"], opts).ok().and_then(|o| gatekeeper_enabled(&format!("{}{}", o.stdout, o.stderr)));
        let mut p = product(version, updated, gatekeeper);
        if std::path::Path::new("/usr/bin/xprotect").exists() {
            p.actions = vec![rmm_proto::security::Action::UpdateSignatures];
        }
        rmm_proto::security::Report { products: vec![p], detections: vec![], error: None }
    }

    fn run(&self, product: ProductKind, action: rmm_proto::security::Action) -> anyhow::Result<String> {
        use crate::patch::cmd::{self, Log, Opts};
        use rmm_proto::security::Action;
        if product != ProductKind::Xprotect || action != Action::UpdateSignatures {
            anyhow::bail!("XProtect only supports signature updates");
        }
        let log = Log::default();
        let out = cmd::output(&log, "/usr/bin/xprotect", &["update"], Opts { timeout: super::timeout(action), log: false, ..Default::default() })?;
        if !out.success() {
            anyhow::bail!("xprotect update failed: {}", out.reason());
        }
        let msg = out.stdout.trim();
        Ok(if msg.is_empty() { "Signatures checked".into() } else { msg.chars().take(500).collect() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gatekeeper_and_product() {
        assert_eq!(gatekeeper_enabled("assessments enabled\n"), Some(true));
        assert_eq!(gatekeeper_enabled("assessments disabled"), Some(false));
        assert_eq!(gatekeeper_enabled("spctl: error"), None);
        let p = product(Some("5287".into()), None, Some(false));
        assert_eq!((p.enabled, p.realtime, p.signature_version.as_deref()), (Some(true), Some(true), Some("5287")));
        assert!(p.detail.unwrap().contains("off"));
        assert_eq!(product(None, None, None).enabled, Some(false));
    }
}
