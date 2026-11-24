//! Active Directory operations for [`rmm_proto::ServerMsg::Identity`], on a domain controller
//! (docs/design/identity.md).
//!
//! Each op is one fixed PowerShell script using the ActiveDirectory module ([`ad`]); its
//! arguments go to the script as JSON on stdin and are never put into the script's text. SIDs
//! are checked before anything runs, and the built-in Administrator (RID 500) and krbtgt (502)
//! are always refused, whatever the server asks.
//!
//! Debug builds: `RMM_IDENTITY_FAKE=<file>` answers from a directory kept in that JSON file
//! instead ([`fake`]), and advertises the capability on any OS when the file exists at start.

mod ad;
#[cfg(debug_assertions)]
mod fake;

use rmm_proto::identity::{Op, Reply, protected_sid, valid_sid};

/// Whether to advertise [`rmm_proto::identity::CAPABILITY`]: a domain controller, or the fake.
pub fn available() -> bool {
    #[cfg(debug_assertions)]
    if let Some(p) = std::env::var_os("RMM_IDENTITY_FAKE")
        && std::path::Path::new(&p).exists()
    {
        return true;
    }
    is_domain_controller()
}

#[cfg(windows)]
fn is_domain_controller() -> bool {
    use winreg::{RegKey, enums::HKEY_LOCAL_MACHINE};
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey("SYSTEM\\CurrentControlSet\\Control\\ProductOptions")
        .and_then(|k| k.get_value::<String, _>("ProductType"))
        .is_ok_and(|p| p.eq_ignore_ascii_case("LanmanNT"))
}

#[cfg(not(windows))]
fn is_domain_controller() -> bool {
    false
}

/// Why `op` must not run, if it mustn't.
pub fn refuse(op: &Op) -> Option<String> {
    let (sid, groups): (&str, &[String]) = match op {
        Op::Sync { .. } => return None,
        Op::Unlock { sid } | Op::SetEnabled { sid, .. } => (sid, &[]),
        Op::ResetPassword { sid, password, .. } => {
            if password.is_empty() || password.chars().count() > 256 {
                return Some("the password must be 1-256 characters".into());
            }
            (sid, &[])
        }
        Op::RemoveFromGroups { sid, group_sids } => (sid, group_sids),
    };
    if !valid_sid(sid) {
        return Some("not a domain account SID".into());
    }
    if protected_sid(sid) {
        return Some("the built-in Administrator and krbtgt accounts are never changed".into());
    }
    if let Some(g) = groups.iter().find(|g| !valid_sid(g)) {
        return Some(format!("not a domain group SID: {}", g.chars().take(80).collect::<String>()));
    }
    if groups.len() > 500 {
        return Some("at most 500 groups at once".into());
    }
    None
}

pub async fn handle(op: Op) -> Reply {
    if let Some(why) = refuse(&op) {
        return Reply::Error(why);
    }
    tracing::info!(op = op.name(), "directory operation");
    #[cfg(debug_assertions)]
    if let Some(path) = std::env::var_os("RMM_IDENTITY_FAKE").map(std::path::PathBuf::from).filter(|p| p.exists()) {
        return tokio::task::spawn_blocking(move || fake::handle(&path, op)).await.unwrap_or_else(|e| Reply::Error(e.to_string()));
    }
    ad::handle(op).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusals() {
        let sid = "S-1-5-21-1-2-3-1104".to_string();
        assert!(refuse(&Op::Unlock { sid: sid.clone() }).is_none());
        assert!(refuse(&Op::Unlock { sid: "S-1-5-21-1-2-3-500".into() }).unwrap().contains("never"));
        assert!(refuse(&Op::SetEnabled { sid: "S-1-5-21-1-2-3-502".into(), enabled: false }).is_some());
        assert!(refuse(&Op::Unlock { sid: "jdoe".into() }).is_some());
        assert!(refuse(&Op::ResetPassword { sid: sid.clone(), password: String::new(), must_change: true }).is_some());
        assert!(refuse(&Op::RemoveFromGroups { sid: sid.clone(), group_sids: vec!["S-1-5-32-544".into()] }).is_some());
        assert!(refuse(&Op::RemoveFromGroups { sid, group_sids: vec!["S-1-5-21-1-2-3-512".into()] }).is_none());
        assert!(refuse(&Op::Sync { since_usn: 0, page: 0 }).is_none());
    }
}
