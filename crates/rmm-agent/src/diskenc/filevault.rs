//! macOS: FileVault from `fdesetup status` (and whether a personal or institutional recovery
//! key exists), the boot volume's device from `diskutil info -plist /`. FileVault protects the
//! whole APFS container the system boots from, so one volume (`/`) is reported. No escrow: the
//! personal recovery key can't be read after the fact.

use rmm_proto::diskenc::{Kind, Role, Status, Volume};
#[cfg(target_os = "macos")]
use rmm_proto::diskenc::{ProtectorOp, Report};

/// Status and progress from `fdesetup status`.
pub fn parse_status(out: &str) -> (Status, Option<f32>) {
    let on = out.lines().any(|l| l.trim().starts_with("FileVault is On"));
    let percent = out.lines().find_map(|l| l.split("Percent completed =").nth(1)).and_then(|p| p.trim().parse::<f32>().ok());
    let status = if out.contains("Encryption in progress") {
        Status::Encrypting
    } else if out.contains("Decryption in progress") {
        Status::Decrypting
    } else if on {
        Status::Encrypted
    } else if out.contains("FileVault is Off") {
        Status::Unencrypted
    } else {
        Status::Unknown
    };
    let percent = percent.or(match status {
        Status::Encrypted => Some(100.0),
        Status::Unencrypted => Some(0.0),
        _ => None,
    });
    (status, percent)
}

/// A `<key>name</key><string>value</string>` pair of a plist.
pub fn plist_string(plist: &str, key: &str) -> Option<String> {
    let at = plist.find(&format!("<key>{key}</key>"))?;
    let rest = &plist[at..];
    let start = rest.find("<string>")? + "<string>".len();
    let end = rest[start..].find("</string>")?;
    Some(rest[start..start + end].trim().to_string())
}

pub fn volume(status_out: &str, info_plist: Option<&str>, protectors: Vec<String>) -> Volume {
    let (status, percent) = parse_status(status_out);
    let encrypted = matches!(status, Status::Encrypted | Status::Encrypting | Status::Decrypting);
    Volume {
        volume_id: "/".into(),
        mount: "/".into(),
        device: info_plist.and_then(|p| plist_string(p, "DeviceIdentifier")).unwrap_or_default(),
        kind: if encrypted { Kind::Filevault } else { Kind::None },
        role: Role::Os,
        status,
        percent,
        method: encrypted.then(|| "XTS-AES-128".to_string()),
        protectors: if encrypted { protectors } else { vec![] },
        protection_on: status == Status::Encrypted,
        ..Default::default()
    }
}

#[cfg(target_os = "macos")]
pub struct Filevault;

#[cfg(target_os = "macos")]
fn run(program: &str, args: &[&str]) -> anyhow::Result<String> {
    use crate::patch::cmd::{self, Log, Opts};
    let out = cmd::output(&Log::default(), program, args, Opts { timeout: std::time::Duration::from_secs(30), log: false, ..Default::default() })?;
    if !out.success() {
        anyhow::bail!("{program}: {}", out.reason());
    }
    Ok(out.stdout)
}

#[cfg(target_os = "macos")]
impl super::Provider for Filevault {
    fn report(&self) -> Report {
        let status = match run("fdesetup", &["status"]) {
            Ok(s) => s,
            Err(e) => return Report { error: Some(format!("{e:#}")), ..Default::default() },
        };
        let info = run("diskutil", &["info", "-plist", "/"]).ok();
        let mut protectors = vec!["password".to_string()];
        if run("fdesetup", &["haspersonalrecoverykey"]).is_ok_and(|s| s.trim() == "true") {
            protectors.push("personal_recovery_key".into());
        }
        if run("fdesetup", &["hasinstitutionalrecoverykey"]).is_ok_and(|s| s.trim() == "true") {
            protectors.push("institutional_recovery_key".into());
        }
        Report { volumes: vec![volume(&status, info.as_deref(), protectors)], tpm: None, error: None }
    }

    fn recovery_key(&self, _: &str, _: &str) -> anyhow::Result<String> {
        anyhow::bail!("FileVault recovery keys can't be read after they are made; escrow them through an MDM")
    }

    fn protector(&self, _: &str, _: ProtectorOp) -> anyhow::Result<String> {
        anyhow::bail!("rotating a FileVault recovery key needs a user's credentials or an MDM bootstrap token")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fdesetup_states() {
        assert_eq!(parse_status(include_str!("fixtures/fdesetup-on.txt")), (Status::Encrypted, Some(100.0)));
        assert_eq!(parse_status(include_str!("fixtures/fdesetup-encrypting.txt")), (Status::Encrypting, Some(45.32)));
        assert_eq!(parse_status(include_str!("fixtures/fdesetup-off.txt")), (Status::Unencrypted, Some(0.0)));
        assert_eq!(parse_status("Error: something").0, Status::Unknown);
        let v = volume(include_str!("fixtures/fdesetup-on.txt"), Some(include_str!("fixtures/diskutil-info.plist")), vec!["password".into()]);
        assert_eq!((v.device.as_str(), v.kind, v.role, v.protection_on), ("disk3s1s1", Kind::Filevault, Role::Os, true));
        let off = volume(include_str!("fixtures/fdesetup-off.txt"), None, vec!["password".into()]);
        assert!(off.protectors.is_empty() && off.kind == Kind::None);
    }
}
