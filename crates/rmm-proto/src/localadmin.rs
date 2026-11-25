//! Local admin password rotation (docs/design/local-admin.md).
//!
//! The server generates the password, stores it in the client's vault **before** sending it
//! ([`crate::ServerMsg::LocalAdminSet`]), and the agent sets it on the managed local account,
//! creating the account when asked. It answers [`crate::AgentMsg::LocalAdminResult`]. Never
//! queued for an offline agent: the server retries when it reconnects. Only agents listing
//! [`CAPABILITY`] get the message.

use std::fmt;

use serde::{Deserialize, Serialize};

pub const CAPABILITY: &str = "local_admin";

/// The longest password the server sends.
pub const PASSWORD_MAX: usize = 128;

/// A secret that never shows in `Debug` output (logs, panics). Serialized as the plain string.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(pub String);

impl Secret {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(•••)")
    }
}

/// How a rotation ended on the device.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The password is set.
    Ok,
    /// This device can't have a managed local account (a domain controller, macOS, no
    /// `chpasswd`).
    Unsupported,
    /// Something else manages the account (Windows LAPS): we leave it alone.
    Conflict,
    /// Setting it failed (password policy, a missing tool...): `message` says why.
    #[default]
    #[serde(other)]
    Failed,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Ok => "ok",
            Outcome::Failed => "failed",
            Outcome::Unsupported => "unsupported",
            Outcome::Conflict => "conflict",
        }
    }
}

/// Account names the agent accepts: a portable subset of what Windows and `useradd` allow.
pub fn valid_account(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 20
        && b[0].is_ascii_lowercase()
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-' || *c == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_stay_out_of_debug() {
        let s = Secret("hunter2".into());
        assert!(!format!("{s:?}").contains("hunter2"));
        assert_eq!(serde_json::to_string(&s).unwrap(), "\"hunter2\"");
    }

    #[test]
    fn account_names() {
        for ok in ["rmmadmin", "rmm-e2e-admin", "it_admin2"] {
            assert!(valid_account(ok), "{ok}");
        }
        for bad in ["", "Admin", "1admin", "root;rm", "a b", "administrator-account-x", "ad$"] {
            assert!(!valid_account(bad), "{bad}");
        }
        assert_eq!(serde_json::from_str::<Outcome>("\"locked\"").unwrap(), Outcome::Failed);
    }
}
