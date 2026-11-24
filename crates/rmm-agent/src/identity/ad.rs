//! The ActiveDirectory PowerShell module, present on every domain controller.
//!
//! One fixed script per op, passed with `-EncodedCommand`; the op's arguments (the SID, the
//! groups, the password) are written to the script's stdin as JSON and read with
//! `[Console]::In`, so nothing the server sends ever becomes part of a command line or of the
//! script. The password goes from the JSON straight into a `SecureString`.

#![cfg_attr(not(windows), allow(dead_code))]

use chrono::{DateTime, Utc};
use rmm_proto::identity::{DirGroup, DirUser, Op, PAGE, Reply, SyncPage};
use serde::Deserialize;

/// Wraps every script: stop on the first error and print only its message.
const PRELUDE: &str = "$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try {
Import-Module ActiveDirectory
$a = [Console]::In.ReadToEnd() | ConvertFrom-Json
";
const POSTLUDE: &str = "
} catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }";

/// `{size}` is replaced with [`PAGE`]. Users changed since the USN, in USN order, one page;
/// the groups (all of them, on the first page); every user SID on the last page of a full sync.
const SYNC: &str = r#"$since = [int64]$a.since_usn
$page = [int]$a.page
$size = {size}
$high = [int64](Get-ADRootDSE).highestCommittedUSN
$props = 'SamAccountName','UserPrincipalName','DisplayName','EmailAddress','Enabled','LockedOut','adminCount','lastLogonTimestamp','pwdLastSet','msDS-UserPasswordExpiryTimeComputed','Department','Title','MemberOf','uSNChanged'
$users = @(Get-ADUser -LDAPFilter "(uSNChanged>=$($since + 1))" -Properties $props | Sort-Object uSNChanged)
$groups = @(Get-ADGroup -Filter * -Properties Description,adminCount)
$dn = @{}
foreach ($g in $groups) { $dn[$g.DistinguishedName] = $g.SID.Value }
$more = (($page + 1) * $size) -lt $users.Count
$out = [ordered]@{ high_usn = $high; more = $more; users = @($users | Select-Object -Skip ($page * $size) -First $size | ForEach-Object {
  [ordered]@{ sid = $_.SID.Value; sam = $_.SamAccountName; upn = $_.UserPrincipalName; name = $_.DisplayName; mail = $_.EmailAddress
    enabled = [bool]$_.Enabled; locked = [bool]$_.LockedOut; admin_count = $_.adminCount
    last_logon = $_.lastLogonTimestamp; pwd_last_set = $_.pwdLastSet; pwd_expires = $_.'msDS-UserPasswordExpiryTimeComputed'
    department = $_.Department; title = $_.Title; member_of = @($_.MemberOf | ForEach-Object { $dn[$_] } | Where-Object { $_ }) } }) }
if ($page -eq 0) { $out.groups = @($groups | ForEach-Object { [ordered]@{ sid = $_.SID.Value; name = $_.Name; description = $_.Description; admin_count = $_.adminCount } }) }
if ($since -eq 0 -and -not $more) { $out.all_sids = @(Get-ADUser -Filter * | ForEach-Object { $_.SID.Value }) }
$out | ConvertTo-Json -Depth 6 -Compress"#;

const UNLOCK: &str = "Unlock-ADAccount -Identity $a.sid";

const RESET: &str = "$pw = ConvertTo-SecureString -String $a.password -AsPlainText -Force
$a.password = $null
Set-ADAccountPassword -Identity $a.sid -Reset -NewPassword $pw
if ($a.must_change) { Set-ADUser -Identity $a.sid -ChangePasswordAtLogon $true }";

const SET_ENABLED: &str = "if ($a.enabled) { Enable-ADAccount -Identity $a.sid } else { Disable-ADAccount -Identity $a.sid }";

const REMOVE_GROUPS: &str = "foreach ($g in @($a.group_sids)) { Remove-ADGroupMember -Identity $g -Members $a.sid -Confirm:$false }";

pub async fn handle(op: Op) -> Reply {
    let (script, input) = match &op {
        Op::Sync { since_usn, page } => (SYNC.replace("{size}", &PAGE.to_string()), serde_json::json!({ "since_usn": since_usn, "page": page })),
        Op::Unlock { sid } => (UNLOCK.to_string(), serde_json::json!({ "sid": sid })),
        Op::ResetPassword { sid, password, must_change } => {
            (RESET.to_string(), serde_json::json!({ "sid": sid, "password": password, "must_change": must_change }))
        }
        Op::SetEnabled { sid, enabled } => (SET_ENABLED.to_string(), serde_json::json!({ "sid": sid, "enabled": enabled })),
        Op::RemoveFromGroups { sid, group_sids } => (REMOVE_GROUPS.to_string(), serde_json::json!({ "sid": sid, "group_sids": group_sids })),
    };
    let out = match run(&script, input.to_string()).await {
        Ok(o) => o,
        Err(e) => return Reply::Error(e),
    };
    match op {
        Op::Sync { .. } => match parse_sync(&out) {
            Ok(p) => Reply::Sync(p),
            Err(e) => Reply::Error(e),
        },
        _ => Reply::Done,
    }
}

/// `-EncodedCommand` takes base64 of UTF-16LE.
fn encode_command(script: &str) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut s = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for c in bytes.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                s.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

#[cfg(windows)]
async fn run(script: &str, input: String) -> Result<String, String> {
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt;
    let full = format!("{PRELUDE}{script}{POSTLUDE}");
    let mut child = tokio::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", &encode_command(&full)])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("starting PowerShell: {e}"))?;
    let mut stdin = child.stdin.take().ok_or("no stdin")?;
    stdin.write_all(input.as_bytes()).await.map_err(|e| format!("writing to PowerShell: {e}"))?;
    drop(stdin);
    let out = tokio::time::timeout(std::time::Duration::from_secs(300), child.wait_with_output())
        .await
        .map_err(|_| "the directory operation took longer than 5 minutes".to_string())?
        .map_err(|e| format!("running PowerShell: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let line = err.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("PowerShell failed");
        return Err(line.chars().take(500).collect());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(not(windows))]
async fn run(_script: &str, _input: String) -> Result<String, String> {
    let _ = (PRELUDE, POSTLUDE);
    Err("Active Directory is only managed from a Windows domain controller".into())
}

/// A Windows FILETIME (100 ns since 1601). 0 and the "never" maximum are `None`.
fn filetime(v: Option<i64>) -> Option<DateTime<Utc>> {
    let v = v?;
    if v <= 0 || v == i64::MAX {
        return None;
    }
    const EPOCH_DIFF_SECS: i64 = 11_644_473_600;
    DateTime::from_timestamp(v / 10_000_000 - EPOCH_DIFF_SECS, ((v % 10_000_000) * 100) as u32)
}

#[derive(Deserialize)]
struct RawPage {
    high_usn: i64,
    #[serde(default)]
    more: bool,
    #[serde(default, deserialize_with = "one_or_many")]
    users: Vec<RawUser>,
    #[serde(default, deserialize_with = "one_or_many")]
    groups: Vec<RawGroup>,
    #[serde(default, deserialize_with = "one_or_many")]
    all_sids: Vec<String>,
}

#[derive(Deserialize)]
struct RawUser {
    sid: String,
    #[serde(default)]
    sam: Option<String>,
    #[serde(default)]
    upn: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    mail: Option<String>,
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    locked: bool,
    #[serde(default)]
    admin_count: Option<i64>,
    #[serde(default)]
    last_logon: Option<i64>,
    #[serde(default)]
    pwd_last_set: Option<i64>,
    #[serde(default)]
    pwd_expires: Option<i64>,
    #[serde(default)]
    department: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default, deserialize_with = "one_or_many")]
    member_of: Vec<String>,
}

#[derive(Deserialize)]
struct RawGroup {
    sid: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    admin_count: Option<i64>,
}

/// PowerShell 5.1 turns a one-element array into the element and an empty one into null.
fn one_or_many<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum M<T> {
        Many(Vec<T>),
        One(T),
        None(()),
    }
    Ok(match Option::<M<T>>::deserialize(d)? {
        Some(M::Many(v)) => v,
        Some(M::One(x)) => vec![x],
        Some(M::None(())) | None => vec![],
    })
}

pub(crate) fn parse_sync(json: &str) -> Result<SyncPage, String> {
    let raw: RawPage = serde_json::from_str(json.trim()).map_err(|e| format!("unreadable directory listing: {e}"))?;
    let s = |o: Option<String>| o.unwrap_or_default();
    Ok(SyncPage {
        high_usn: raw.high_usn,
        more: raw.more,
        users: raw
            .users
            .into_iter()
            .map(|u| DirUser {
                sid: u.sid,
                username: s(u.sam),
                upn: s(u.upn),
                display_name: s(u.name),
                email: s(u.mail),
                enabled: u.enabled,
                locked: u.locked,
                admin_count: u.admin_count == Some(1),
                last_logon_at: filetime(u.last_logon),
                password_last_set: filetime(u.pwd_last_set),
                password_expires_at: filetime(u.pwd_expires),
                department: s(u.department),
                title: s(u.title),
                member_of: u.member_of,
            })
            .collect(),
        groups: raw
            .groups
            .into_iter()
            .map(|g| DirGroup { sid: g.sid, name: s(g.name), description: s(g.description), admin_count: g.admin_count == Some(1) })
            .collect(),
        all_user_sids: raw.all_sids,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorded_listing() {
        let p = parse_sync(include_str!("fixtures/ad-sync.json")).unwrap();
        assert_eq!(p.high_usn, 41_234);
        assert!(!p.more);
        assert_eq!(p.users.len(), 3);
        let j = &p.users[0];
        assert_eq!((j.username.as_str(), j.upn.as_str(), j.email.as_str()), ("jdoe", "jdoe@corp.example", "jane.doe@corp.example"));
        assert!(j.enabled && !j.locked && !j.admin_count);
        assert_eq!(j.last_logon_at.unwrap().to_rfc3339(), "2026-11-20T08:13:20+00:00");
        assert!(j.password_expires_at.is_some());
        assert_eq!(j.member_of, vec!["S-1-5-21-1004336348-1177238915-682003330-1105"]);
        let admin = &p.users[1];
        assert!(admin.admin_count && admin.locked);
        assert_eq!(admin.password_expires_at, None, "never expires");
        assert_eq!(admin.member_of.len(), 1, "a single group is not an array in PowerShell 5.1");
        let never = &p.users[2];
        assert_eq!((never.last_logon_at, never.password_last_set), (None, None));
        assert!(never.member_of.is_empty() && never.display_name.is_empty());
        assert_eq!(p.groups.len(), 2);
        assert!(p.groups[1].admin_count);
        assert_eq!(p.all_user_sids.len(), 3);
    }

    #[test]
    fn filetimes() {
        assert_eq!(filetime(Some(0)), None);
        assert_eq!(filetime(Some(i64::MAX)), None);
        assert_eq!(filetime(None), None);
        assert_eq!(filetime(Some(116_444_736_000_000_000)).unwrap().timestamp(), 0);
    }

    #[test]
    fn encoded_command() {
        // [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('dir'))
        assert_eq!(encode_command("dir"), "ZABpAHIA");
        assert_eq!(encode_command("ab"), "YQBiAA==");
    }

    #[test]
    fn scripts_take_no_arguments_in_their_text() {
        for s in [SYNC, UNLOCK, RESET, SET_ENABLED, REMOVE_GROUPS] {
            assert!(!s.contains("{sid}") && !s.contains("{password}"));
        }
        assert!(RESET.contains("ConvertTo-SecureString -String $a.password"));
    }
}
