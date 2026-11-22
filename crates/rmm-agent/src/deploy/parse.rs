//! Parsers for package manager output and command-line helpers. Pure functions, so the
//! Windows ones are tested against recorded output on any host.

#![allow(dead_code)] // each platform uses its own subset

use std::collections::HashMap;

use anyhow::{Result, bail};

/// Splits installer arguments on whitespace; double quotes group (and are removed). No
/// escapes and no shell: the pieces go to the program as separate arguments.
pub fn split_args(s: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut started = false;
    for c in s.chars() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                started = true;
            }
            c if c == '\0' || c == '\n' || c == '\r' => bail!("installer arguments can't contain line breaks"),
            c if c.is_whitespace() && !in_quotes => {
                if started {
                    out.push(std::mem::take(&mut cur));
                    started = false;
                }
            }
            c => {
                cur.push(c);
                started = true;
            }
        }
    }
    if in_quotes {
        bail!("installer arguments have an unclosed double quote");
    }
    if started {
        out.push(cur);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// winget
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub struct WingetRow {
    pub name: String,
    pub id: String,
    pub version: String,
    pub available: Option<String>,
}

fn clean_version(v: &str) -> String {
    // winget marks truncated or unknown versions with a leading `<`, `>` or `~`.
    v.trim().trim_start_matches(['<', '>', '~']).trim().to_string()
}

/// `winget list` as a table: `Name  Id  Version  Available  Source`, columns aligned by
/// character position, a dashed line under the header, and spinner noise before it.
pub fn parse_winget_list(out: &str) -> Vec<WingetRow> {
    // Progress spinners overwrite themselves with carriage returns; keep what's left visible.
    let lines: Vec<Vec<char>> = out.split('\n').map(|l| l.rsplit('\r').find(|p| !p.trim().is_empty()).unwrap_or("").trim_end().chars().collect()).collect();
    let find = |line: &[char], word: &str| -> Option<usize> {
        let w: Vec<char> = word.chars().collect();
        (0..line.len().saturating_sub(w.len() - 1)).find(|&i| line[i..i + w.len()] == w[..] && (i == 0 || line[i - 1] == ' ') && line.get(i + w.len()).is_none_or(|c| *c == ' '))
    };
    let Some((h, id_at, ver_at)) = (0..lines.len().saturating_sub(1)).find_map(|i| {
        let under = &lines[i + 1];
        let dashes = under.len() > 4 && under.iter().all(|c| *c == '-');
        let name = lines[i].starts_with(&['N', 'a', 'm', 'e']);
        (dashes && name).then_some(())?;
        Some((i, find(&lines[i], "Id")?, find(&lines[i], "Version")?))
    }) else {
        return vec![];
    };
    let header = &lines[h];
    let avail_at = find(header, "Available");
    let source_at = find(header, "Source");
    let ver_end = avail_at.or(source_at);
    let slice = |l: &[char], a: usize, b: Option<usize>| -> String {
        let a = a.min(l.len());
        let b = b.map_or(l.len(), |b| b.min(l.len())).max(a);
        l[a..b].iter().collect::<String>().trim().to_string()
    };
    let mut rows = Vec::new();
    for l in lines.iter().skip(h + 2) {
        if l.is_empty() {
            // A blank line ends the table (what follows is a footer).
            break;
        }
        let id = slice(l, id_at, Some(ver_at));
        if id.is_empty() || id.contains(' ') {
            continue;
        }
        let available = avail_at.map(|a| clean_version(&slice(l, a, source_at))).filter(|v| !v.is_empty());
        rows.push(WingetRow { name: slice(l, 0, Some(id_at)), id, version: clean_version(&slice(l, ver_at, ver_end)), available });
    }
    rows
}

/// What a winget exit code means. Codes (HRESULTs) from winget's documented return codes.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum WingetExit {
    Ok,
    /// Nothing to do: already at the newest version, or already installed.
    NothingToDo,
    /// No installer for this scope or architecture (machine scope is tried first).
    NoApplicableInstaller,
    Failed,
}

pub fn winget_exit(code: Option<i32>) -> WingetExit {
    match code {
        Some(0) => WingetExit::Ok,
        // APPINSTALLER_CLI_ERROR_UPDATE_NOT_APPLICABLE, ..._PACKAGE_ALREADY_INSTALLED
        Some(-1978335189) | Some(-1978335135) => WingetExit::NothingToDo,
        // APPINSTALLER_CLI_ERROR_NO_APPLICABLE_INSTALLER
        Some(-1978335216) => WingetExit::NoApplicableInstaller,
        _ => WingetExit::Failed,
    }
}

/// Picks the newest `Microsoft.DesktopAppInstaller_<version>_x64__8wekyb3d8bbwe` directory name.
/// SYSTEM has no `winget` on its PATH, so the agent looks in WindowsApps itself.
pub fn pick_winget_dir(names: &[String]) -> Option<String> {
    names
        .iter()
        .filter_map(|n| {
            let rest = n.strip_prefix("Microsoft.DesktopAppInstaller_")?;
            let version = rest.strip_suffix("_x64__8wekyb3d8bbwe")?;
            Some((version, n))
        })
        .max_by(|a, b| rmm_proto::software::compare_versions(a.0, b.0))
        .map(|(_, n)| n.clone())
}

// ---------------------------------------------------------------------------
// Chocolatey
// ---------------------------------------------------------------------------

/// `choco list --limit-output`: `id|version`. Keys are lowercase (choco ids are
/// case-insensitive).
pub fn parse_choco_list(out: &str) -> HashMap<String, String> {
    out.lines()
        .filter_map(|l| {
            let mut p = l.trim().split('|');
            let (id, v) = (p.next()?.trim(), p.next()?.trim());
            (!id.is_empty() && !v.is_empty() && !id.contains(' ')).then(|| (id.to_ascii_lowercase(), v.to_string()))
        })
        .collect()
}

/// `choco outdated --limit-output`: `id|installed|available|pinned`; the map holds the
/// available version. Pinned packages are skipped (choco won't upgrade them).
pub fn parse_choco_outdated(out: &str) -> HashMap<String, String> {
    out.lines()
        .filter_map(|l| {
            let p: Vec<&str> = l.trim().split('|').map(str::trim).collect();
            if p.len() < 3 || p[0].is_empty() || p[0].contains(' ') || p[2].is_empty() {
                return None;
            }
            (p.get(3).copied() != Some("true")).then(|| (p[0].to_ascii_lowercase(), p[2].to_string()))
        })
        .collect()
}

/// Exit codes after which a Chocolatey install, upgrade or uninstall counts as done; the
/// boolean says a reboot is needed.
pub fn choco_exit(code: Option<i32>) -> Option<bool> {
    match code {
        Some(0) => Some(false),
        // 1605: not installed (uninstall), 1614: already uninstalled, 1641 and 3010: reboot.
        Some(1605) | Some(1614) => Some(false),
        Some(1641) | Some(3010) => Some(true),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Linux
// ---------------------------------------------------------------------------

/// `dpkg-query -W -f='${Package}\t${Version}\t${Status}\n'`: installed packages.
pub fn parse_dpkg(out: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for l in out.lines() {
        let mut p = l.split('\t');
        let (Some(name), Some(v), Some(status)) = (p.next(), p.next(), p.next()) else { continue };
        if status.trim() == "install ok installed" && !name.is_empty() {
            m.entry(name.trim().to_string()).or_insert_with(|| v.trim().to_string());
        }
    }
    m
}

/// `rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n'`. Several versions of one package (kernels)
/// keep the highest.
pub fn parse_rpm(out: &str) -> HashMap<String, String> {
    let mut m: HashMap<String, String> = HashMap::new();
    for l in out.lines() {
        let Some((name, v)) = l.split_once('\t') else { continue };
        let (name, v) = (name.trim(), v.trim());
        if name.is_empty() || v.is_empty() {
            continue;
        }
        match m.get(name) {
            Some(old) if rmm_proto::software::compare_versions(old, v).is_ge() => {}
            _ => {
                m.insert(name.to_string(), v.to_string());
            }
        }
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_installer_args() {
        assert_eq!(split_args("/S /D=C:\\Apps").unwrap(), ["/S", "/D=C:\\Apps"]);
        assert_eq!(split_args("  /qn   INSTALLDIR=\"C:\\Program Files\\X\" ALLUSERS=1 ").unwrap(), ["/qn", "INSTALLDIR=C:\\Program Files\\X", "ALLUSERS=1"]);
        assert_eq!(split_args("").unwrap(), Vec::<String>::new());
        assert_eq!(split_args("\"\"").unwrap(), [""]);
        assert!(split_args("/S \"oops").is_err());
        assert!(split_args("/S\n/Q").is_err());
    }

    const WINGET: &str = "\
   - \r   \\ \r   | \rName                          Id                          Version        Available      Source
---------------------------------------------------------------------------------------------------------
Mozilla Firefox (x64 en-US)   Mozilla.Firefox             124.0.1        125.0.3        winget
7-Zip 23.01 (x64)             7zip.7zip                   23.01          24.05          winget
Microsoft Edge                Microsoft.Edge              < 123.0.2420.97
Visual Studio Code            Microsoft.VisualStudioCode  1.88.1                        winget
Some Vendor App               ARP\\Machine\\X64\\SomeApp      2.1
3 upgrades available.
";

    #[test]
    fn parses_winget_list() {
        let rows = parse_winget_list(WINGET);
        let by: HashMap<&str, &WingetRow> = rows.iter().map(|r| (r.id.as_str(), r)).collect();
        assert_eq!(by["Mozilla.Firefox"].version, "124.0.1");
        assert_eq!(by["Mozilla.Firefox"].available.as_deref(), Some("125.0.3"));
        assert_eq!(by["Mozilla.Firefox"].name, "Mozilla Firefox (x64 en-US)");
        assert_eq!(by["7zip.7zip"].available.as_deref(), Some("24.05"));
        assert_eq!(by["Microsoft.Edge"].version, "123.0.2420.97");
        assert_eq!(by["Microsoft.Edge"].available, None);
        assert_eq!(by["Microsoft.VisualStudioCode"].available, None);
        assert_eq!(by["ARP\\Machine\\X64\\SomeApp"].version, "2.1");
        // The footer isn't a row.
        assert_eq!(rows.len(), 5);
    }

    #[test]
    fn winget_without_a_table_gives_nothing() {
        assert!(parse_winget_list("No installed package found matching input criteria.\n").is_empty());
        assert!(parse_winget_list("").is_empty());
    }

    #[test]
    fn winget_exit_codes() {
        assert_eq!(winget_exit(Some(0)), WingetExit::Ok);
        assert_eq!(winget_exit(Some(-1978335189)), WingetExit::NothingToDo);
        assert_eq!(winget_exit(Some(-1978335135)), WingetExit::NothingToDo);
        assert_eq!(winget_exit(Some(-1978335216)), WingetExit::NoApplicableInstaller);
        assert_eq!(winget_exit(Some(1)), WingetExit::Failed);
        assert_eq!(winget_exit(None), WingetExit::Failed);
    }

    #[test]
    fn picks_the_newest_winget() {
        let names: Vec<String> = [
            "Microsoft.DesktopAppInstaller_1.21.3482.0_x64__8wekyb3d8bbwe",
            "Microsoft.DesktopAppInstaller_1.22.10861.0_x64__8wekyb3d8bbwe",
            "Microsoft.DesktopAppInstaller_1.9.25180.0_x64__8wekyb3d8bbwe",
            "Microsoft.DesktopAppInstaller_1.22.10861.0_neutral_~_8wekyb3d8bbwe",
            "Microsoft.WindowsStore_22401.1400.6.0_x64__8wekyb3d8bbwe",
        ]
        .map(String::from)
        .to_vec();
        assert_eq!(pick_winget_dir(&names).as_deref(), Some("Microsoft.DesktopAppInstaller_1.22.10861.0_x64__8wekyb3d8bbwe"));
        assert_eq!(pick_winget_dir(&[]), None);
    }

    #[test]
    fn parses_choco() {
        let list = parse_choco_list("Chocolatey v2.2.2\ngooglechrome|124.0.6367.60\n7zip|23.1.0\nWarning: something|odd thing\n");
        assert_eq!(list["googlechrome"], "124.0.6367.60");
        assert_eq!(list["7zip"], "23.1.0");
        assert!(!list.contains_key("warning: something"));
        let out = parse_choco_outdated("Chocolatey v2.2.2\nOutdated Packages\ngooglechrome|124.0.6367.60|124.0.6367.118|false\nnotepadplusplus|8.6.4|8.6.5|true\n7zip|23.1.0|24.1.0|false\n");
        assert_eq!(out["googlechrome"], "124.0.6367.118");
        assert_eq!(out["7zip"], "24.1.0");
        assert!(!out.contains_key("notepadplusplus"), "pinned packages aren't offered");
        assert_eq!(choco_exit(Some(0)), Some(false));
        assert_eq!(choco_exit(Some(3010)), Some(true));
        assert_eq!(choco_exit(Some(1)), None);
    }

    #[test]
    fn parses_dpkg_and_rpm() {
        let d = parse_dpkg("curl\t8.5.0-2ubuntu10.4\tinstall ok installed\nold\t1.0\tdeinstall ok config-files\nvim\t2:9.1\tinstall ok installed\n");
        assert_eq!(d.len(), 2);
        assert_eq!(d["vim"], "2:9.1");
        let r = parse_rpm("kernel\t5.14.0-427.el9\nkernel\t5.14.0-503.el9\nbash\t5.1.8-9.el9\n");
        assert_eq!(r["kernel"], "5.14.0-503.el9");
        assert_eq!(r["bash"], "5.1.8-9.el9");
    }
}
