//! `RMM_IDENTITY_FAKE=<file>` (debug builds): a directory kept in a JSON file, for the e2e.
//!
//! `{"high_usn": 100, "users": [DirUser + "usn"...], "groups": [DirGroup...]}`. Actions change
//! the file and bump the user's `usn`, so a delta sync sees them. Every action is also appended
//! to `<file>.ops.jsonl` as `{"op": ..., "sid": ..., "password": ...}`: the test reads the
//! password the "directory" was given back from there.

use std::path::Path;

use rmm_proto::identity::{DirGroup, DirUser, Op, PAGE, Reply, SyncPage};
use serde::{Deserialize, Serialize};

#[derive(Default, Serialize, Deserialize)]
struct Dir {
    #[serde(default)]
    high_usn: i64,
    #[serde(default)]
    users: Vec<FakeUser>,
    #[serde(default)]
    groups: Vec<DirGroup>,
}

#[derive(Serialize, Deserialize)]
struct FakeUser {
    #[serde(flatten)]
    user: DirUser,
    #[serde(default)]
    usn: i64,
}

fn load(path: &Path) -> Result<Dir, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    serde_json::from_str(&raw).map_err(|e| format!("parsing {}: {e}", path.display()))
}

fn save(path: &Path, d: &Dir) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(d).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}

fn log(path: &Path, entry: serde_json::Value) {
    use std::io::Write;
    let mut p = path.as_os_str().to_owned();
    p.push(".ops.jsonl");
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(p) {
        let _ = writeln!(f, "{entry}");
    }
}

pub fn handle(path: &Path, op: Op) -> Reply {
    match run(path, op) {
        Ok(r) => r,
        Err(e) => Reply::Error(e),
    }
}

fn run(path: &Path, op: Op) -> Result<Reply, String> {
    let mut d = load(path)?;
    if let Op::Sync { since_usn, page } = op {
        let mut changed: Vec<&FakeUser> = d.users.iter().filter(|u| u.usn > since_usn).collect();
        changed.sort_by_key(|u| u.usn);
        let start = page as usize * PAGE as usize;
        let more = start + (PAGE as usize) < changed.len();
        return Ok(Reply::Sync(SyncPage {
            users: changed.iter().skip(start).take(PAGE as usize).map(|u| u.user.clone()).collect(),
            groups: if page == 0 { d.groups.clone() } else { vec![] },
            high_usn: d.high_usn,
            more,
            all_user_sids: if since_usn == 0 && !more { d.users.iter().map(|u| u.user.sid.clone()).collect() } else { vec![] },
        }));
    }
    let sid = match &op {
        Op::Unlock { sid } | Op::ResetPassword { sid, .. } | Op::SetEnabled { sid, .. } | Op::RemoveFromGroups { sid, .. } => sid.clone(),
        Op::Sync { .. } => unreachable!(),
    };
    d.high_usn += 1;
    let usn = d.high_usn;
    let u = d.users.iter_mut().find(|u| u.user.sid == sid).ok_or_else(|| format!("Cannot find an object with identity: '{sid}'"))?;
    u.usn = usn;
    let entry = match op {
        Op::Unlock { .. } => {
            u.user.locked = false;
            serde_json::json!({ "op": "unlock", "sid": sid })
        }
        Op::ResetPassword { password, must_change, .. } => {
            u.user.locked = false;
            u.user.password_last_set = Some(chrono::Utc::now());
            serde_json::json!({ "op": "reset_password", "sid": sid, "password": password, "must_change": must_change })
        }
        Op::SetEnabled { enabled, .. } => {
            u.user.enabled = enabled;
            serde_json::json!({ "op": "set_enabled", "sid": sid, "enabled": enabled })
        }
        Op::RemoveFromGroups { group_sids, .. } => {
            u.user.member_of.retain(|g| !group_sids.contains(g));
            serde_json::json!({ "op": "remove_from_groups", "sid": sid, "group_sids": group_sids })
        }
        Op::Sync { .. } => unreachable!(),
    };
    save(path, &d)?;
    log(path, entry);
    Ok(Reply::Done)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delta_after_an_action() {
        let dir = std::env::temp_dir().join(format!("rmm-idfake-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("dir.json");
        let sid = "S-1-5-21-1-2-3-1104";
        std::fs::write(
            &path,
            serde_json::json!({ "high_usn": 10, "users": [
                { "sid": sid, "username": "jdoe", "enabled": true, "locked": true, "usn": 5 },
                { "sid": "S-1-5-21-1-2-3-1105", "username": "bob", "enabled": true, "usn": 6 },
            ] })
            .to_string(),
        )
        .unwrap();
        let Reply::Sync(full) = handle(&path, Op::Sync { since_usn: 0, page: 0 }) else { panic!() };
        assert_eq!((full.users.len(), full.high_usn, full.all_user_sids.len()), (2, 10, 2));
        assert!(matches!(handle(&path, Op::Unlock { sid: sid.into() }), Reply::Done));
        let Reply::Sync(delta) = handle(&path, Op::Sync { since_usn: 10, page: 0 }) else { panic!() };
        assert_eq!(delta.users.len(), 1);
        assert!(!delta.users[0].locked);
        assert!(delta.all_user_sids.is_empty());
        assert!(matches!(handle(&path, Op::Unlock { sid: "S-1-5-21-1-2-3-9999".into() }), Reply::Error(_)));
        let ops = std::fs::read_to_string(dir.join("dir.json.ops.jsonl")).unwrap();
        assert!(ops.contains("\"unlock\""));
        let _ = std::fs::remove_dir_all(dir);
    }
}
