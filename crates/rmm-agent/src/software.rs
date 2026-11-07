//! Installed software enumeration.

use rmm_proto::Software;

#[cfg(target_os = "linux")]
pub fn installed() -> Vec<Software> {
    use std::process::Command;

    fn run(cmd: &str, args: &[&str]) -> Option<String> {
        let out = Command::new(cmd).args(args).output().ok()?;
        out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
    }

    // Try each package manager; a host can have more than one (e.g. dpkg + flatpak later).
    let mut list = Vec::new();
    if let Some(out) = run("dpkg-query", &["-W", "-f=${Package}\t${Version}\t${Maintainer}\n"]) {
        list.extend(parse_tsv(&out, "dpkg"));
    }
    if let Some(out) = run("rpm", &["-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n"]) {
        list.extend(parse_tsv(&out, "rpm"));
    }
    if let Some(out) = run("pacman", &["-Q"]) {
        list.extend(out.lines().filter_map(|l| {
            let (name, version) = l.split_once(' ')?;
            Some(Software { name: name.into(), version: version.into(), publisher: None, source: "pacman".into() })
        }));
    }
    list
}

#[cfg(target_os = "linux")]
fn parse_tsv(out: &str, source: &str) -> impl Iterator<Item = Software> {
    out.lines().filter_map(move |l| {
        let mut parts = l.split('\t');
        let name = parts.next()?.trim();
        if name.is_empty() {
            return None;
        }
        Some(Software {
            name: name.into(),
            version: parts.next().unwrap_or_default().into(),
            publisher: parts.next().map(str::trim).filter(|s| !s.is_empty() && *s != "(none)").map(Into::into),
            source: source.into(),
        })
    })
}

#[cfg(windows)]
pub fn installed() -> Vec<Software> {
    use winreg::RegKey;
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY};

    const UNINSTALL: &str = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let mut list = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for view in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
        let Ok(root) = hklm.open_subkey_with_flags(UNINSTALL, KEY_READ | view) else { continue };
        for sub in root.enum_keys().flatten() {
            let Ok(key) = root.open_subkey_with_flags(&sub, KEY_READ | view) else { continue };
            let Ok(name) = key.get_value::<String, _>("DisplayName") else { continue };
            // Hide updates/components the way "Apps & features" does.
            if key.get_value::<u32, _>("SystemComponent").unwrap_or(0) == 1
                || key.get_value::<String, _>("ParentKeyName").is_ok()
            {
                continue;
            }
            let version = key.get_value::<String, _>("DisplayVersion").unwrap_or_default();
            if !seen.insert((name.clone(), version.clone())) {
                continue;
            }
            list.push(Software {
                name,
                version,
                publisher: key.get_value::<String, _>("Publisher").ok(),
                source: "registry".into(),
            });
        }
    }
    list
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn installed() -> Vec<Software> {
    Vec::new()
}
