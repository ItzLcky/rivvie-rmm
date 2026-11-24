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
    if let Some(out) = run("dpkg-query", &["-W", DPKG_FORMAT]) {
        list.extend(parse_dpkg(&out));
    }
    if let Some(out) = run("rpm", &["-qa", "--qf", RPM_FORMAT]) {
        list.extend(parse_rpm(&out));
    }
    if let Some(out) = run("pacman", &["-Q"]) {
        list.extend(parse_pacman(&out));
    }
    if let Some(out) = run("apk", &["list", "--installed"]) {
        list.extend(parse_apk(&out));
    }
    list
}

/// `source:Package` is the source package (Debian's and Ubuntu's security data is keyed by
/// it); `db:Status-Abbrev` lets removed-but-configured (`rc`) packages be skipped, which would
/// otherwise look installed at an old version.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const DPKG_FORMAT: &str = "-f=${Package}\t${Version}\t${Maintainer}\t${source:Package}\t${db:Status-Abbrev}\n";

/// The epoch only when there is one (as `rpm -q` prints it); `SOURCERPM` names the source
/// package (`openssl-3.0.7-24.el9.src.rpm`).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const RPM_FORMAT: &str = "%{NAME}\t%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}\t%{VENDOR}\t%{SOURCERPM}\n";

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn publisher(s: Option<&str>) -> Option<String> {
    s.map(str::trim).filter(|s| !s.is_empty() && *s != "(none)").map(Into::into)
}

/// Kept only when it says something `name` doesn't.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn source_name(name: &str, src: Option<&str>) -> Option<String> {
    src.map(str::trim).filter(|s| !s.is_empty() && *s != "(none)" && *s != name).map(Into::into)
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_dpkg(out: &str) -> impl Iterator<Item = Software> + '_ {
    out.lines().filter_map(|l| {
        let mut parts = l.split('\t');
        let name = parts.next()?.trim();
        let version = parts.next().unwrap_or_default().trim();
        let maintainer = parts.next();
        let src = parts.next();
        // `ii `, `hi `: installed. A missing column (an old dpkg) counts as installed.
        if let Some(status) = parts.next()
            && status.as_bytes().get(1).is_some_and(|c| *c != b'i')
        {
            return None;
        }
        if name.is_empty() || version.is_empty() {
            return None;
        }
        Some(Software { name: name.into(), version: version.into(), publisher: publisher(maintainer), source: "dpkg".into(), source_name: source_name(name, src) })
    })
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_rpm(out: &str) -> impl Iterator<Item = Software> + '_ {
    out.lines().filter_map(|l| {
        let mut parts = l.split('\t');
        let name = parts.next()?.trim();
        if name.is_empty() {
            return None;
        }
        let version = parts.next().unwrap_or_default().trim();
        let vendor = parts.next();
        let src = parts.next().and_then(srpm_name);
        Some(Software { name: name.into(), version: version.into(), publisher: publisher(vendor), source: "rpm".into(), source_name: source_name(name, src) })
    })
}

/// `openssl-3.0.7-24.el9.src.rpm` -> `openssl` (name-version-release; the name may hold dashes).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn srpm_name(s: &str) -> Option<&str> {
    let s = s.trim();
    let base = s.strip_suffix(".src.rpm").or_else(|| s.strip_suffix(".nosrc.rpm"))?;
    let (rest, _release) = base.rsplit_once('-')?;
    let (name, _version) = rest.rsplit_once('-')?;
    (!name.is_empty()).then_some(name)
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_pacman(out: &str) -> impl Iterator<Item = Software> + '_ {
    out.lines().filter_map(|l| {
        let (name, version) = l.split_once(' ')?;
        Some(Software { name: name.into(), version: version.trim().into(), publisher: None, source: "pacman".into(), source_name: None })
    })
}

/// `apk list --installed`: `musl-1.2.4_git20230717-r4 x86_64 {musl} (MIT) [installed]`, where
/// `{...}` is the origin (source) package.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_apk(out: &str) -> impl Iterator<Item = Software> + '_ {
    out.lines().filter_map(|l| {
        let mut words = l.split_whitespace();
        let nvr = words.next()?;
        let (rest, rel) = nvr.rsplit_once('-')?;
        let (name, ver) = rest.rsplit_once('-')?;
        if name.is_empty() || !rel.starts_with('r') {
            return None;
        }
        let origin = l.split_once('{').and_then(|(_, r)| r.split_once('}')).map(|(o, _)| o);
        Some(Software {
            name: name.into(),
            version: format!("{ver}-{rel}"),
            publisher: None,
            source: "apk".into(),
            source_name: source_name(name, origin),
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
                source_name: None,
            });
        }
    }
    list
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn installed() -> Vec<Software> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpkg_source_packages_and_removed_ones() {
        let out = "libssl3\t3.0.11-1~deb12u2\tDebian OpenSSL Team <x@y>\topenssl\tii \n\
                   openssl\t3.0.11-1~deb12u2\tDebian OpenSSL Team <x@y>\topenssl\tii \n\
                   oldthing\t1.0-1\tSomeone\toldthing\trc \n\
                   held\t2.0-1\t\theld-src\thi \n\
                   legacy\t1.0\tMe\n";
        let got: Vec<Software> = parse_dpkg(out).collect();
        let names: Vec<(&str, Option<&str>)> = got.iter().map(|s| (s.name.as_str(), s.source_name.as_deref())).collect();
        assert_eq!(names, [("libssl3", Some("openssl")), ("openssl", None), ("held", Some("held-src")), ("legacy", None)]);
        assert_eq!(got[0].version, "3.0.11-1~deb12u2");
        assert_eq!(got[2].publisher, None);
    }

    #[test]
    fn rpm_epochs_and_source_rpms() {
        let out = "openssl-libs\t1:3.0.7-24.el9\tRocky Enterprise Software Foundation\topenssl-3.0.7-24.el9.src.rpm\n\
                   bash\t5.1.8-6.el9\t(none)\tbash-5.1.8-6.el9.src.rpm\n\
                   gpg-pubkey\t3228467c-613798eb\t(none)\t(none)\n\
                   python3-dbus-client-gen\t0.5-1.el9\tX\tpython-dbus-client-gen-0.5-1.el9.src.rpm\n";
        let got: Vec<Software> = parse_rpm(out).collect();
        assert_eq!(got[0].version, "1:3.0.7-24.el9");
        assert_eq!(got[0].source_name.as_deref(), Some("openssl"));
        assert_eq!((got[1].source_name.as_deref(), got[1].publisher.as_deref()), (None, None));
        assert_eq!(got[2].source_name, None);
        assert_eq!(got[3].source_name.as_deref(), Some("python-dbus-client-gen"));
        assert_eq!(srpm_name("nonsense"), None);
    }

    #[test]
    fn apk_list() {
        let got: Vec<Software> = parse_apk("musl-1.2.4_git20230717-r4 x86_64 {musl} (MIT) [installed]\nlibcrypto3-3.1.4-r5 x86_64 {openssl} (Apache-2.0) [installed]\nWARNING: junk\n").collect();
        assert_eq!(got.len(), 2);
        assert_eq!((got[0].name.as_str(), got[0].version.as_str(), got[0].source_name.as_deref()), ("musl", "1.2.4_git20230717-r4", None));
        assert_eq!((got[1].name.as_str(), got[1].source_name.as_deref()), ("libcrypto3", Some("openssl")));
    }

    #[test]
    fn pacman_list() {
        let got: Vec<Software> = parse_pacman("openssl 3.4.0-1\nlinux 1:6.12.1.arch1-1\n").collect();
        assert_eq!((got[1].name.as_str(), got[1].version.as_str()), ("linux", "1:6.12.1.arch1-1"));
    }
}
