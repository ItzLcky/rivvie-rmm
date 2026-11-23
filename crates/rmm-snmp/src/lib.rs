//! A minimal SNMP client in pure Rust: v2c and v3 (USM with MD5/SHA-1/SHA-2 authentication and
//! DES/AES-128 privacy), `GET`, `GETNEXT`, `GETBULK` and walks. Written for the RMM agent,
//! which only reads from devices, so there is no `SET`, no traps and no v1.
//!
//! [`sim`] is a small v2c responder for tests.

pub mod ber;
pub mod client;
pub mod mib;
pub mod sim;
pub mod usm;

pub use ber::{Oid, Value};
pub use client::{Client, Options};
pub use usm::{AuthProto, PrivProto};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("malformed SNMP data: {0}")]
    Decode(&'static str),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("no answer (timed out)")]
    Timeout,
    /// The device answered with an error status.
    #[error("the device answered: {0}")]
    Status(String),
    /// Wrong user name, key or privacy settings, or a security level the user doesn't have.
    #[error("authentication failed: {0}")]
    Auth(String),
    #[error("{0}")]
    Config(String),
}

/// How a device is reached.
#[derive(Clone, PartialEq, Eq)]
pub enum Creds {
    V2c { community: String },
    V3(V3),
}

#[derive(Clone, PartialEq, Eq)]
pub struct V3 {
    pub user: String,
    pub auth: Option<(AuthProto, String)>,
    /// Needs `auth`.
    pub privacy: Option<(PrivProto, String)>,
    /// The SNMP context (usually empty).
    pub context: String,
}

// Secrets never reach a log line by accident.
impl std::fmt::Debug for Creds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Creds::V2c { .. } => f.write_str("Creds::V2c(..)"),
            Creds::V3(v) => write!(f, "Creds::V3(user {:?}, auth {:?}, priv {:?})", v.user, v.auth.as_ref().map(|a| a.0), v.privacy.as_ref().map(|p| p.0)),
        }
    }
}

impl Creds {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Creds::V2c { community } if community.is_empty() => Err("the community string is empty".into()),
            Creds::V2c { community } if community.len() > 255 => Err("the community string is too long".into()),
            Creds::V2c { .. } => Ok(()),
            Creds::V3(v) => {
                if v.user.is_empty() || v.user.len() > 32 {
                    return Err("the SNMPv3 user name must be 1-32 characters".into());
                }
                if v.privacy.is_some() && v.auth.is_none() {
                    return Err("SNMPv3 privacy needs authentication".into());
                }
                for (what, pass) in [("authentication", v.auth.as_ref().map(|a| &a.1)), ("privacy", v.privacy.as_ref().map(|p| &p.1))] {
                    if pass.is_some_and(|p| p.len() < 8) {
                        return Err(format!("the SNMPv3 {what} passphrase must be at least 8 characters"));
                    }
                }
                Ok(())
            }
        }
    }
}
