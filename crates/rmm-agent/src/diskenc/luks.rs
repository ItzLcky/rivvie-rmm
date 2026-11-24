//! Linux: LUKS/dm-crypt from `lsblk -J`. A mounted filesystem is encrypted when a block device
//! it sits on (itself or an ancestor: LVM on LUKS) is a `crypt` device or `crypto_LUKS`. Only
//! local, non-removable filesystems are listed, one volume per filesystem (`/` first, then
//! `/home`, else its shortest mount point); `/boot`, the EFI partition, swap, loop devices
//! (snaps) and network filesystems are left out. No escrow: adding a key slot needs an
//! existing passphrase.

use rmm_proto::diskenc::{Kind, Role, Status, Volume};
#[cfg(target_os = "linux")]
use rmm_proto::diskenc::{ProtectorOp, Report};
use serde::{Deserialize, Deserializer};

/// Filesystems that hold data worth encrypting.
const FILESYSTEMS: &[&str] = &["ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "jfs", "reiserfs", "zfs_member", "bcachefs", "nilfs2"];
const SKIP_MOUNTS: &[&str] = &["/boot", "/boot/efi", "/efi"];

#[derive(Deserialize)]
struct Lsblk {
    #[serde(default)]
    blockdevices: Vec<Dev>,
}

#[derive(Deserialize)]
struct Dev {
    name: String,
    #[serde(default, rename = "type")]
    ty: Option<String>,
    #[serde(default)]
    fstype: Option<String>,
    /// lsblk 2.37+ (`MOUNTPOINTS`): every mount of the device (btrfs subvolumes).
    #[serde(default)]
    mountpoints: Option<Vec<Option<String>>>,
    /// Older lsblk (`MOUNTPOINT`): one of them.
    #[serde(default)]
    mountpoint: Option<String>,
    #[serde(default, deserialize_with = "flag")]
    rm: bool,
    #[serde(default)]
    children: Vec<Dev>,
}

/// `true`/`false`, or `"0"`/`"1"` from older lsblk.
fn flag<'de, D: Deserializer<'de>>(d: D) -> Result<bool, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum F {
        B(bool),
        S(String),
    }
    Ok(match Option::<F>::deserialize(d)? {
        Some(F::B(b)) => b,
        Some(F::S(s)) => s.trim() == "1",
        None => false,
    })
}

impl Dev {
    fn mounts(&self) -> Vec<String> {
        let mut m: Vec<String> = match &self.mountpoints {
            Some(list) => list.iter().flatten().cloned().collect(),
            None => self.mountpoint.iter().cloned().collect(),
        };
        m.retain(|p| p.starts_with('/') && !SKIP_MOUNTS.contains(&p.as_str()));
        m
    }

    fn crypt(&self) -> bool {
        self.ty.as_deref() == Some("crypt") || self.fstype.as_deref() == Some("crypto_LUKS")
    }
}

fn walk(d: &Dev, encrypted: bool, removable: bool, out: &mut Vec<Volume>) {
    let encrypted = encrypted || d.crypt();
    let removable = removable || d.rm;
    let fs = d.fstype.as_deref().unwrap_or("");
    let mounts = d.mounts();
    if !removable && d.ty.as_deref() != Some("loop") && FILESYSTEMS.contains(&fs) && !mounts.is_empty() {
        let mount = mounts
            .iter()
            .find(|m| *m == "/")
            .or_else(|| mounts.iter().find(|m| *m == "/home"))
            .or_else(|| mounts.iter().min_by_key(|m| (m.len(), (*m).clone())))
            .cloned()
            .unwrap_or_default();
        out.push(Volume {
            volume_id: mount.clone(),
            role: if mount == "/" { Role::Os } else { Role::Data },
            mount,
            device: format!("/dev/{}", d.name),
            kind: if encrypted { Kind::Luks } else { Kind::None },
            status: if encrypted { Status::Encrypted } else { Status::Unencrypted },
            percent: Some(if encrypted { 100.0 } else { 0.0 }),
            protectors: if encrypted { vec!["passphrase".into()] } else { vec![] },
            protection_on: encrypted,
            ..Default::default()
        });
    }
    for c in &d.children {
        walk(c, encrypted, removable, out);
    }
}

pub fn parse(json: &str) -> anyhow::Result<Vec<Volume>> {
    let l: Lsblk = serde_json::from_str(json)?;
    let mut out = Vec::new();
    for d in &l.blockdevices {
        walk(d, false, false, &mut out);
    }
    // The OS volume first, then by mount point.
    out.sort_by(|a, b| (a.role != Role::Os, &a.mount).cmp(&(b.role != Role::Os, &b.mount)));
    out.dedup_by(|a, b| a.volume_id == b.volume_id);
    Ok(out)
}

#[cfg(target_os = "linux")]
pub struct Luks;

#[cfg(target_os = "linux")]
fn lsblk(columns: &str) -> anyhow::Result<String> {
    use crate::patch::cmd::{self, Log, Opts};
    let out = cmd::output(&Log::default(), "lsblk", &["-J", "-o", columns], Opts { timeout: std::time::Duration::from_secs(30), log: false, ..Default::default() })?;
    if !out.success() {
        anyhow::bail!("lsblk: {}", out.reason());
    }
    Ok(out.stdout)
}

#[cfg(target_os = "linux")]
impl super::Provider for Luks {
    fn report(&self) -> Report {
        // MOUNTPOINTS needs util-linux 2.37 (2021); older ones know MOUNTPOINT only.
        let out = lsblk("NAME,TYPE,FSTYPE,MOUNTPOINTS,UUID,PKNAME,RM").or_else(|_| lsblk("NAME,TYPE,FSTYPE,MOUNTPOINT,UUID,PKNAME,RM"));
        match out.and_then(|s| parse(&s)) {
            Ok(volumes) => Report { volumes, tpm: tpm(), error: None },
            Err(e) => Report { error: Some(format!("{e:#}")), ..Default::default() },
        }
    }

    fn recovery_key(&self, _: &str, _: &str) -> anyhow::Result<String> {
        anyhow::bail!("LUKS keys aren't escrowed: adding a key slot needs an existing passphrase")
    }

    fn protector(&self, _: &str, _: ProtectorOp) -> anyhow::Result<String> {
        anyhow::bail!("LUKS key slots aren't changed from the console")
    }
}

/// A TPM, as the kernel sees it.
#[cfg(target_os = "linux")]
fn tpm() -> Option<rmm_proto::diskenc::Tpm> {
    let dir = std::path::Path::new("/sys/class/tpm/tpm0");
    if !dir.exists() {
        return Some(rmm_proto::diskenc::Tpm { present: false, ..Default::default() });
    }
    let read = |f: &str| std::fs::read_to_string(dir.join(f)).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let version = read("tpm_version_major").map(|v| if v == "2" { "2.0".to_string() } else { v });
    Some(rmm_proto::diskenc::Tpm { present: true, version, ..Default::default() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_btrfs_and_a_second_disk() {
        let v = parse(include_str!("fixtures/lsblk-plain.json")).unwrap();
        let ids: Vec<&str> = v.iter().map(|v| v.volume_id.as_str()).collect();
        assert_eq!(ids, ["/", "/run/media/user/Data"], "one volume per filesystem; /boot and swap left out");
        assert_eq!((v[0].role, v[0].kind, v[0].status), (Role::Os, Kind::None, Status::Unencrypted));
        assert_eq!(v[0].device, "/dev/sda2");
        assert_eq!(v[1].role, Role::Data);
    }

    #[test]
    fn lvm_on_luks_with_older_lsblk() {
        let v = parse(include_str!("fixtures/lsblk-luks.json")).unwrap();
        let ids: Vec<&str> = v.iter().map(|v| v.volume_id.as_str()).collect();
        assert_eq!(ids, ["/", "/srv/data"], "removable media and snaps left out");
        assert_eq!((v[0].kind, v[0].status, v[0].protection_on), (Kind::Luks, Status::Encrypted, true));
        assert_eq!(v[0].device, "/dev/ubuntu--vg-ubuntu--lv");
        assert_eq!((v[1].kind, v[1].status), (Kind::None, Status::Unencrypted));
    }
}
