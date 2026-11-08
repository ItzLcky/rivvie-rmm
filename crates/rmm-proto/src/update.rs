//! Agent self-update: what gets signed, and version ordering.
//!
//! A release is signed offline with `rmm-sign` (ed25519). The signature covers the platform,
//! the version and the binary's SHA-256, so the server can't swap in another binary,
//! relabel one platform's build as another's, or replay an old version as a "new" one (the
//! agent also refuses anything not newer than itself). The agent has the public key built
//! in (`RMM_UPDATE_PUBKEY` at compile time), so a compromised server can't change it.

use serde::{Deserialize, Serialize};

/// Stored next to each agent binary as `<binary>.update.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    /// e.g. `linux-x86_64`, `windows-x86_64`
    pub platform: String,
    pub version: String,
    /// Hex SHA-256 of the binary.
    pub sha256: String,
    /// Hex ed25519 signature over [`signed_message`].
    pub signature: String,
}

/// The exact bytes the release key signs.
pub fn signed_message(platform: &str, version: &str, sha256_hex: &str) -> Vec<u8> {
    format!("rmm-agent-update-v1\n{platform}\n{version}\n{}\n", sha256_hex.to_ascii_lowercase()).into_bytes()
}

/// The platform id of the running build, matching the server's download ids.
pub fn current_platform() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

/// Numeric `major.minor.patch` plus the pre-release tag, if any.
type Parsed<'a> = ((u64, u64, u64), Option<&'a str>);

/// `major.minor.patch[-pre][+build]`. Build metadata is ignored; a pre-release sorts before
/// its release, and pre-release tags compare as strings.
fn parse(v: &str) -> Option<Parsed<'_>> {
    let v = v.trim().trim_start_matches('v');
    let v = v.split('+').next()?;
    let (core, pre) = match v.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (v, None),
    };
    let mut it = core.split('.').map(|p| p.parse::<u64>().ok());
    let triple = (it.next()??, it.next().flatten().unwrap_or(0), it.next().flatten().unwrap_or(0));
    Some((triple, pre))
}

/// Whether `candidate` is strictly newer than `current`. Unparseable versions never are.
pub fn is_newer(candidate: &str, current: &str) -> bool {
    let (Some((a, apre)), Some((b, bpre))) = (parse(candidate), parse(current)) else { return false };
    match a.cmp(&b) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => match (apre, bpre) {
            (None, Some(_)) => true,
            (Some(x), Some(y)) => x > y,
            _ => false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_order() {
        assert!(is_newer("0.2.0", "0.1.9"));
        assert!(is_newer("1.0.0", "0.99.99"));
        assert!(is_newer("0.1.10", "0.1.9"));
        assert!(is_newer("0.2.0", "0.2.0-rc.1"));
        assert!(is_newer("0.2.0-rc.2", "0.2.0-rc.1"));
        assert!(is_newer("v0.2.0", "0.1.0+abc"));
        assert!(!is_newer("0.1.0", "0.1.0"));
        assert!(!is_newer("0.1.0+build2", "0.1.0+build1"));
        assert!(!is_newer("0.1.0", "0.2.0"));
        assert!(!is_newer("0.2.0-rc.1", "0.2.0"));
        assert!(!is_newer("garbage", "0.1.0"));
        assert!(!is_newer("0.2.0", "garbage"));
    }

    #[test]
    fn message_is_stable() {
        assert_eq!(signed_message("linux-x86_64", "0.2.0", "ABCD"), b"rmm-agent-update-v1\nlinux-x86_64\n0.2.0\nabcd\n");
    }
}
