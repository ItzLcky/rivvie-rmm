//! Local admin password rotation (docs/design/local-admin.md): sets the password the server
//! generated (and already stored) on the managed local account, creating it if asked.
//!
//! - **Windows:** `NetUserSetInfo` level 1003, `NetUserAdd` and `NetLocalGroupAddMembers` into
//!   the group of SID `S-1-5-32-544` (its name is localised). Never `net user`: command lines
//!   show in process lists and EDR logs. Refused on a domain controller (`ProductType` is
//!   `LanmanNT`); `conflict` when Windows LAPS manages the same account.
//! - **Linux:** `chpasswd` with `user:password` on stdin; created with `useradd -m` and added to
//!   `sudo` or `wheel`, whichever exists.
//! - **macOS:** unsupported (`sysadminctl` and `dscl` take the password on argv).
//!
//! The password is never logged or written down. Debug builds: `RMM_LOCALADMIN_FAKE=<file>`
//! records what was set in that JSON file instead of touching real accounts ([`fake`]).

use rmm_proto::localadmin::{Outcome, valid_account};

/// What a set came to: `Ok(created)`, or the outcome and why.
pub type SetResult = Result<bool, (Outcome, String)>;

/// Sets `password` on `account` (runs on a blocking thread).
pub fn set(account: &str, password: &str, create: bool) -> SetResult {
    if !valid_account(account) {
        return Err((Outcome::Failed, format!("{account:?} isn't an account name this agent manages")));
    }
    if password.is_empty() || password.len() > rmm_proto::localadmin::PASSWORD_MAX || password.chars().any(|c| c.is_control()) {
        return Err((Outcome::Failed, "the password is empty, too long or has control characters".into()));
    }
    #[cfg(debug_assertions)]
    if let Some(path) = std::env::var_os("RMM_LOCALADMIN_FAKE") {
        return fake::set(std::path::Path::new(&path), account, password, create);
    }
    platform::set(account, password, create)
}

#[cfg(debug_assertions)]
mod fake {
    //! The file: `{"status": "unsupported" | "conflict" | null, "fail": "message" | null,
    //! "accounts": {"<name>": {"password", "created", "set_at", "sets"}}}`. `status` and `fail`
    //! make every set end that way until the test removes them.
    use std::collections::BTreeMap;
    use std::path::Path;

    use rmm_proto::localadmin::Outcome;
    use serde::{Deserialize, Serialize};

    #[derive(Default, Serialize, Deserialize)]
    struct State {
        #[serde(default)]
        status: Option<Outcome>,
        #[serde(default)]
        fail: Option<String>,
        #[serde(default)]
        accounts: BTreeMap<String, Account>,
    }

    #[derive(Serialize, Deserialize)]
    struct Account {
        password: String,
        created: bool,
        set_at: chrono::DateTime<chrono::Utc>,
        #[serde(default)]
        sets: u32,
    }

    pub fn set(path: &Path, account: &str, password: &str, create: bool) -> super::SetResult {
        let mut s: State = match std::fs::read_to_string(path) {
            Ok(t) => serde_json::from_str(&t).map_err(|e| (Outcome::Failed, format!("fake state: {e}")))?,
            Err(_) => State::default(),
        };
        if let Some(st) = s.status.filter(|o| *o != Outcome::Ok) {
            let why = match st {
                Outcome::Unsupported => "this device can't have a managed local account (fake)",
                Outcome::Conflict => "Windows LAPS manages this account (fake)",
                _ => "simulated failure",
            };
            return Err((st, why.into()));
        }
        if let Some(f) = &s.fail {
            return Err((Outcome::Failed, f.clone()));
        }
        let created = !s.accounts.contains_key(account);
        if created && !create {
            return Err((Outcome::Failed, format!("there is no local account {account}, and the policy doesn't create it")));
        }
        let sets = s.accounts.get(account).map_or(0, |a| a.sets) + 1;
        s.accounts.insert(account.into(), Account { password: password.into(), created, set_at: chrono::Utc::now(), sets });
        let body = serde_json::to_vec_pretty(&s).map_err(|e| (Outcome::Failed, e.to_string()))?;
        std::fs::write(path, body).map_err(|e| (Outcome::Failed, format!("fake state: {e}")))?;
        Ok(created)
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use std::io::Write as _;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use rmm_proto::localadmin::Outcome;

    use crate::patch::cmd::{self, Log, Opts};

    fn exists(account: &str) -> bool {
        let Ok(name) = std::ffi::CString::new(account) else { return false };
        // SAFETY: getpwnam reads a NUL-terminated name; the result is only checked for null.
        !unsafe { libc::getpwnam(name.as_ptr()) }.is_null()
    }

    fn group_exists(group: &str) -> bool {
        let Ok(name) = std::ffi::CString::new(group) else { return false };
        // SAFETY: as above.
        !unsafe { libc::getgrnam(name.as_ptr()) }.is_null()
    }

    fn run(program: &str, args: &[&str]) -> Result<(), String> {
        let out = cmd::output(&Log::default(), program, args, Opts { timeout: Duration::from_secs(60), log: false, ..Default::default() }).map_err(|e| format!("{program}: {e:#}"))?;
        if !out.success() {
            return Err(format!("{program}: {}", out.reason()));
        }
        Ok(())
    }

    /// `chpasswd` with the pair on stdin (never argv).
    fn chpasswd(account: &str, password: &str) -> Result<(), String> {
        let mut child = Command::new("chpasswd")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("chpasswd: {e}"))?;
        {
            let mut stdin = child.stdin.take().ok_or("chpasswd: no stdin")?;
            let mut line = format!("{account}:{password}\n").into_bytes();
            let res = stdin.write_all(&line);
            line.iter_mut().for_each(|b| *b = 0);
            res.map_err(|e| format!("chpasswd: {e}"))?;
        }
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            match child.try_wait() {
                Ok(Some(status)) if status.success() => return Ok(()),
                Ok(Some(status)) => {
                    let mut err = String::new();
                    if let Some(mut e) = child.stderr.take() {
                        let _ = std::io::Read::read_to_string(&mut e, &mut err);
                    }
                    let err = err.trim();
                    return Err(if err.is_empty() { format!("chpasswd failed ({status})") } else { format!("chpasswd: {err}") });
                }
                Ok(None) if Instant::now() > deadline => {
                    let _ = child.kill();
                    return Err("chpasswd timed out".into());
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                Err(e) => return Err(format!("chpasswd: {e}")),
            }
        }
    }

    pub fn set(account: &str, password: &str, create: bool) -> super::SetResult {
        if !cmd::which("chpasswd") {
            return Err((Outcome::Unsupported, "chpasswd isn't installed".into()));
        }
        // SAFETY: plain syscall.
        if unsafe { libc::geteuid() } != 0 {
            return Err((Outcome::Unsupported, "the agent isn't running as root".into()));
        }
        let mut created = false;
        if !exists(account) {
            if !create {
                return Err((Outcome::Failed, format!("there is no local account {account}, and the policy doesn't create it")));
            }
            run("useradd", &["-m", "-s", "/bin/bash", "-c", "RMM managed admin", account]).map_err(|e| (Outcome::Failed, e))?;
            created = true;
        }
        // Make sure it is an administrator, also when someone took it out of the group.
        let group = ["sudo", "wheel"].into_iter().find(|g| group_exists(g)).ok_or((Outcome::Unsupported, "neither a sudo nor a wheel group exists".to_string()))?;
        run("usermod", &["-aG", group, account]).map_err(|e| (Outcome::Failed, e))?;
        chpasswd(account, password).map_err(|e| (Outcome::Failed, e))?;
        Ok(created)
    }
}

#[cfg(windows)]
mod platform {
    use rmm_proto::localadmin::Outcome;
    use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_MEMBER_IN_ALIAS};
    use windows::Win32::NetworkManagement::NetManagement::{
        LOCALGROUP_MEMBERS_INFO_3, NERR_PasswordTooShort, NERR_Success, NERR_UserNotFound, NetApiBufferFree, NetLocalGroupAddMembers, NetUserAdd,
        NetUserGetInfo, NetUserSetInfo, UF_DONT_EXPIRE_PASSWD, UF_SCRIPT, USER_INFO_1, USER_INFO_1003, USER_PRIV_USER,
    };
    use windows::Win32::Security::{CreateWellKnownSid, LookupAccountSidW, PSID, SECURITY_MAX_SID_SIZE, SID_NAME_USE, WinBuiltinAdministratorsSid};
    use windows::core::{PCWSTR, PWSTR};
    use winreg::RegKey;
    use winreg::enums::HKEY_LOCAL_MACHINE;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn net_error(code: u32, what: &str) -> String {
        if code == NERR_PasswordTooShort {
            format!("{what}: the password doesn't meet the local password policy (length, complexity or history)")
        } else if code == ERROR_ACCESS_DENIED.0 {
            format!("{what}: access denied (the agent must run as SYSTEM)")
        } else {
            format!("{what} failed with error {code}")
        }
    }

    /// A domain controller: local accounts are domain accounts there.
    fn domain_controller() -> bool {
        RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey("SYSTEM\\CurrentControlSet\\Control\\ProductOptions")
            .and_then(|k| k.get_value::<String, _>("ProductType"))
            .is_ok_and(|t| t.eq_ignore_ascii_case("LanmanNT"))
    }

    /// Windows LAPS backs up (and so rotates) this account. It manages the built-in
    /// Administrator unless `AdministratorAccountName` names another.
    pub fn laps_manages(account: &str) -> bool {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        ["SOFTWARE\\Microsoft\\Policies\\LAPS", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\LAPS"].iter().any(|path| {
            let Ok(k) = hklm.open_subkey(path) else { return false };
            let backup: u32 = k.get_value("BackupDirectory").unwrap_or(0);
            let name: String = k.get_value("AdministratorAccountName").unwrap_or_default();
            backup != 0 && name.eq_ignore_ascii_case(account)
        })
    }

    /// The local Administrators group's name in this language.
    fn administrators() -> Result<Vec<u16>, String> {
        let mut sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut size = SECURITY_MAX_SID_SIZE;
        let psid = PSID(sid.as_mut_ptr().cast());
        // SAFETY: the buffer is SECURITY_MAX_SID_SIZE bytes, as `size` says.
        unsafe { CreateWellKnownSid(WinBuiltinAdministratorsSid, None, Some(psid), &mut size) }.map_err(|e| format!("CreateWellKnownSid: {e}"))?;
        let mut name = vec![0u16; 256];
        let mut domain = vec![0u16; 256];
        let (mut n, mut d) = (name.len() as u32, domain.len() as u32);
        let mut use_ = SID_NAME_USE::default();
        // SAFETY: both buffers are as long as their counts say; the SID was just made.
        unsafe { LookupAccountSidW(PCWSTR::null(), psid, Some(PWSTR(name.as_mut_ptr())), &mut n, Some(PWSTR(domain.as_mut_ptr())), &mut d, &mut use_) }
            .map_err(|e| format!("looking up the Administrators group: {e}"))?;
        name.truncate(n as usize);
        name.push(0);
        Ok(name)
    }

    fn exists(account: &[u16]) -> Result<bool, String> {
        let mut buf: *mut u8 = std::ptr::null_mut();
        // SAFETY: level 0 returns a buffer we free below.
        let rc = unsafe { NetUserGetInfo(PCWSTR::null(), PCWSTR(account.as_ptr()), 0, &mut buf) };
        if !buf.is_null() {
            // SAFETY: allocated by NetUserGetInfo.
            unsafe { NetApiBufferFree(Some(buf.cast())) };
        }
        if rc == NERR_Success {
            Ok(true)
        } else if rc == NERR_UserNotFound {
            Ok(false)
        } else {
            Err(net_error(rc, "NetUserGetInfo"))
        }
    }

    pub fn set(account: &str, password: &str, create: bool) -> super::SetResult {
        if domain_controller() {
            return Err((Outcome::Unsupported, "this is a domain controller: its local accounts are domain accounts".into()));
        }
        if laps_manages(account) {
            return Err((Outcome::Conflict, format!("Windows LAPS manages {account} on this device; turn one of them off")));
        }
        let name = wide(account);
        let mut pw = wide(password);
        let res = (|| {
            let mut created = false;
            if !exists(&name).map_err(|e| (Outcome::Failed, e))? {
                if !create {
                    return Err((Outcome::Failed, format!("there is no local account {account}, and the policy doesn't create it")));
                }
                let mut comment = wide("RMM managed admin");
                let info = USER_INFO_1 {
                    usri1_name: PWSTR(name.as_ptr() as *mut u16),
                    usri1_password: PWSTR(pw.as_mut_ptr()),
                    usri1_priv: USER_PRIV_USER,
                    usri1_comment: PWSTR(comment.as_mut_ptr()),
                    usri1_flags: UF_SCRIPT | UF_DONT_EXPIRE_PASSWD,
                    ..Default::default()
                };
                // SAFETY: every pointer in `info` outlives the call.
                let rc = unsafe { NetUserAdd(PCWSTR::null(), 1, (&info as *const USER_INFO_1).cast(), None) };
                if rc != NERR_Success {
                    return Err((Outcome::Failed, net_error(rc, "NetUserAdd")));
                }
                created = true;
            } else {
                let info = USER_INFO_1003 { usri1003_password: PWSTR(pw.as_mut_ptr()) };
                // SAFETY: as above.
                let rc = unsafe { NetUserSetInfo(PCWSTR::null(), PCWSTR(name.as_ptr()), 1003, (&info as *const USER_INFO_1003).cast(), None) };
                if rc != NERR_Success {
                    return Err((Outcome::Failed, net_error(rc, "NetUserSetInfo")));
                }
            }
            // Make sure it is an administrator, also when someone took it out of the group.
            let group = administrators().map_err(|e| (Outcome::Failed, e))?;
            let member = LOCALGROUP_MEMBERS_INFO_3 { lgrmi3_domainandname: PWSTR(name.as_ptr() as *mut u16) };
            // SAFETY: one entry, alive for the call.
            let rc = unsafe { NetLocalGroupAddMembers(PCWSTR::null(), PCWSTR(group.as_ptr()), 3, (&member as *const LOCALGROUP_MEMBERS_INFO_3).cast(), 1) };
            if rc != NERR_Success && rc != ERROR_MEMBER_IN_ALIAS.0 {
                return Err((Outcome::Failed, net_error(rc, "adding the account to Administrators")));
            }
            Ok(created)
        })();
        pw.iter_mut().for_each(|c| *c = 0);
        res
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
mod platform {
    use rmm_proto::localadmin::Outcome;

    pub fn set(_: &str, _: &str, _: bool) -> super::SetResult {
        Err((Outcome::Unsupported, "local admin rotation isn't supported on this platform".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bad_input_is_refused_before_anything_runs() {
        assert!(matches!(set("Root;x", "pw", true), Err((Outcome::Failed, _))));
        assert!(matches!(set("rmmadmin", "", true), Err((Outcome::Failed, _))));
        assert!(matches!(set("rmmadmin", "a\nb", true), Err((Outcome::Failed, _))));
    }

    #[cfg(debug_assertions)]
    #[test]
    fn fake_records_and_fails_on_demand() {
        let dir = std::env::temp_dir().join(format!("rmm-laps-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("laps.json");
        assert_eq!(fake::set(&f, "rmmadmin", "Pw-1", true), Ok(true));
        assert_eq!(fake::set(&f, "rmmadmin", "Pw-2", true), Ok(false));
        let s: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&f).unwrap()).unwrap();
        assert_eq!((s["accounts"]["rmmadmin"]["password"].as_str(), s["accounts"]["rmmadmin"]["sets"].as_u64()), (Some("Pw-2"), Some(2)));
        assert!(matches!(fake::set(&f, "other", "x", false), Err((Outcome::Failed, _))));
        std::fs::write(&f, r#"{"status":"conflict"}"#).unwrap();
        assert!(matches!(fake::set(&f, "rmmadmin", "x", true), Err((Outcome::Conflict, _))));
        let _ = std::fs::remove_dir_all(dir);
    }
}
