//! Disk encryption status and BitLocker recovery-key escrow (docs/design/disk-encryption.md).
//!
//! The agent reports the encryption state of its fixed volumes
//! ([`crate::AgentMsg::DiskEncryption`]) after connecting, every [`REPORT_SECS`] and when the
//! server asks ([`crate::ServerMsg::DiskEncryptionRefresh`]). A report carries **protector ids
//! only**: the server pulls one recovery password at a time with
//! [`crate::ServerMsg::DiskRecoveryRequest`] when a volume's recovery protector isn't the one it
//! escrowed. Only agents listing [`CAPABILITY`] get these messages.

use serde::{Deserialize, Serialize};

pub const CAPABILITY: &str = "diskenc";

/// How often an unchanged state is reported anyway.
pub const REPORT_SECS: u64 = 6 * 3600;
/// The most volumes one report carries.
pub const MAX_VOLUMES: usize = 64;

/// Which technology encrypts the volume.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Bitlocker,
    Filevault,
    Luks,
    #[default]
    #[serde(other)]
    None,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Bitlocker => "bitlocker",
            Kind::Filevault => "filevault",
            Kind::Luks => "luks",
            Kind::None => "none",
        }
    }
}

/// The volume the OS boots from, or another fixed one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Os,
    #[default]
    #[serde(other)]
    Data,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Os => "os",
            Role::Data => "data",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Encrypted,
    Encrypting,
    Decrypting,
    Unencrypted,
    /// Encrypted, but protection is off (BitLocker suspended: the key sits in the clear on disk).
    Suspended,
    #[default]
    #[serde(other)]
    Unknown,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Encrypted => "encrypted",
            Status::Encrypting => "encrypting",
            Status::Decrypting => "decrypting",
            Status::Unencrypted => "unencrypted",
            Status::Suspended => "suspended",
            Status::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Volume {
    /// Stable per machine: the drive letter on Windows (`C:`), the mount point elsewhere.
    pub volume_id: String,
    pub mount: String,
    /// The device (`\\?\Volume{...}`, `/dev/nvme0n1p3`, `disk3s1`).
    #[serde(default)]
    pub device: String,
    pub kind: Kind,
    pub role: Role,
    pub status: Status,
    /// Encrypted percentage, when the product says.
    #[serde(default)]
    pub percent: Option<f32>,
    /// `XtsAes128`, `aes-xts-plain64`...
    #[serde(default)]
    pub method: Option<String>,
    /// Kinds of key protector (`tpm`, `recovery_password`, `password`, `startup_key`...).
    #[serde(default)]
    pub protectors: Vec<String>,
    /// Protection is on (for BitLocker: not suspended).
    #[serde(default)]
    pub protection_on: bool,
    #[serde(default)]
    pub locked: bool,
    /// The id of the volume's numerical recovery password protector (BitLocker), if it has one.
    #[serde(default)]
    pub recovery_protector_id: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Tpm {
    pub present: bool,
    #[serde(default)]
    pub ready: Option<bool>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub activated: Option<bool>,
    /// `2.0`...
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub manufacturer: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub volumes: Vec<Volume>,
    #[serde(default)]
    pub tpm: Option<Tpm>,
    /// Why the state couldn't be read (in part or in full).
    #[serde(default)]
    pub error: Option<String>,
}

/// What [`crate::ServerMsg::DiskProtector`] asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectorOp {
    /// Add a numerical recovery password where the volume has none.
    AddRecovery,
    /// Replace the volume's recovery password with a new one (and remove the old).
    RotateRecovery,
}

impl ProtectorOp {
    pub fn as_str(self) -> &'static str {
        match self {
            ProtectorOp::AddRecovery => "add_recovery",
            ProtectorOp::RotateRecovery => "rotate_recovery",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_values_from_newer_agents() {
        assert_eq!(serde_json::from_str::<Status>("\"paused\"").unwrap(), Status::Unknown);
        assert_eq!(serde_json::from_str::<Kind>("\"veracrypt\"").unwrap(), Kind::None);
        assert_eq!(serde_json::from_str::<Role>("\"boot\"").unwrap(), Role::Data);
        let v: Volume = serde_json::from_str(r#"{"volume_id":"C:","mount":"C:\\","kind":"bitlocker","role":"os","status":"encrypted"}"#).unwrap();
        assert!(v.protectors.is_empty() && v.recovery_protector_id.is_none());
    }
}
