//! Active Directory operations run by an agent on a domain controller
//! (docs/design/identity.md).
//!
//! The server sends [`crate::ServerMsg::Identity`] and the agent answers with one
//! [`crate::AgentMsg::IdentityReply`] per request. These are dedicated messages rather than
//! script jobs because a job's body and output are stored, and a password must never be.
//!
//! Only agents listing [`CAPABILITY`] get these: an agent advertises it only when Windows says
//! the machine is a domain controller (`ProductType` is `LanmanNT`).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const CAPABILITY: &str = "identity_ad";

/// Users (and groups) per [`Op::Sync`] page.
pub const PAGE: u32 = 500;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Op {
    /// Users and groups changed since `since_usn` (0: everything), page `page` (from 0) of
    /// [`PAGE`]. Answered with [`Reply::Sync`].
    Sync { since_usn: i64, page: u32 },
    Unlock { sid: String },
    /// The password travels only in this message and the agent's stdin to PowerShell.
    ResetPassword { sid: String, password: String, must_change: bool },
    SetEnabled { sid: String, enabled: bool },
    RemoveFromGroups { sid: String, group_sids: Vec<String> },
}

impl Op {
    /// For logs: never the password.
    pub fn name(&self) -> &'static str {
        match self {
            Op::Sync { .. } => "sync",
            Op::Unlock { .. } => "unlock",
            Op::ResetPassword { .. } => "reset_password",
            Op::SetEnabled { .. } => "set_enabled",
            Op::RemoveFromGroups { .. } => "remove_from_groups",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum Reply {
    Sync(SyncPage),
    /// The action was carried out.
    Done,
    Error(String),
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SyncPage {
    pub users: Vec<DirUser>,
    pub groups: Vec<DirGroup>,
    /// The domain's highest committed USN when the sync started: the next delta starts here.
    pub high_usn: i64,
    /// Another page follows.
    #[serde(default)]
    pub more: bool,
    /// Every user SID in the directory, sent with the last page of a full sync (`since_usn`
    /// 0), so the server can mark the rest deleted. Empty on deltas.
    #[serde(default)]
    pub all_user_sids: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DirUser {
    pub sid: String,
    /// `sAMAccountName`.
    pub username: String,
    #[serde(default)]
    pub upn: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub email: String,
    pub enabled: bool,
    #[serde(default)]
    pub locked: bool,
    /// `adminCount = 1`.
    #[serde(default)]
    pub admin_count: bool,
    #[serde(default)]
    pub last_logon_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub password_last_set: Option<DateTime<Utc>>,
    #[serde(default)]
    pub password_expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub department: String,
    #[serde(default)]
    pub title: String,
    /// SIDs of the groups it is a direct member of.
    #[serde(default)]
    pub member_of: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DirGroup {
    pub sid: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// `adminCount = 1` (protected groups: Domain Admins, Enterprise Admins...).
    #[serde(default)]
    pub admin_count: bool,
}

/// Whether `sid` is a domain account SID (`S-1-5-21-a-b-c-rid`). Everything sent to the agent
/// is checked with this on both sides.
pub fn valid_sid(sid: &str) -> bool {
    let Some(rest) = sid.strip_prefix("S-1-5-21-") else { return false };
    let parts: Vec<&str> = rest.split('-').collect();
    parts.len() == 4 && parts.iter().all(|p| !p.is_empty() && p.len() <= 10 && p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u32>().is_ok())
}

/// The relative id: the last part of the SID.
pub fn rid(sid: &str) -> Option<u32> {
    sid.rsplit('-').next()?.parse().ok()
}

/// Accounts that are never acted on: the built-in Administrator (500) and krbtgt (502).
pub fn protected_sid(sid: &str) -> bool {
    matches!(rid(sid), Some(500 | 502))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sids() {
        assert!(valid_sid("S-1-5-21-3623811015-3361044348-30300820-1013"));
        assert!(valid_sid("S-1-5-21-1-2-3-500"));
        for bad in [
            "",
            "S-1-5-32-544",
            "S-1-5-21-1-2-3",
            "S-1-5-21-1-2-3-4-5",
            "S-1-5-21-1-2-3-x",
            "S-1-5-21-1-2-3-4; Remove-ADUser",
            "S-1-5-21-1-2-3-99999999999",
            "S-1-5-21--2-3-4",
            "s-1-5-21-1-2-3-4",
        ] {
            assert!(!valid_sid(bad), "{bad}");
        }
        assert!(protected_sid("S-1-5-21-1-2-3-500"));
        assert!(protected_sid("S-1-5-21-1-2-3-502"));
        assert!(!protected_sid("S-1-5-21-1-2-3-501"));
        assert!(!protected_sid("S-1-5-21-1-2-3-1500"));
    }

    #[test]
    fn round_trip() {
        let op = Op::ResetPassword { sid: "S-1-5-21-1-2-3-1104".into(), password: "pw".into(), must_change: true };
        let msg = crate::ServerMsg::Identity { request_id: uuid::Uuid::nil(), op };
        let back: crate::ServerMsg = crate::decode(&crate::encode(&msg).unwrap()).unwrap();
        assert!(matches!(back, crate::ServerMsg::Identity { op: Op::ResetPassword { must_change: true, .. }, .. }));
        let reply = crate::AgentMsg::IdentityReply {
            request_id: uuid::Uuid::nil(),
            reply: Reply::Sync(SyncPage { users: vec![DirUser { sid: "S-1-5-21-1-2-3-1104".into(), ..Default::default() }], ..Default::default() }),
        };
        let back: crate::AgentMsg = crate::decode(&crate::encode(&reply).unwrap()).unwrap();
        assert!(matches!(back, crate::AgentMsg::IdentityReply { reply: Reply::Sync(p), .. } if p.users.len() == 1));
    }
}
