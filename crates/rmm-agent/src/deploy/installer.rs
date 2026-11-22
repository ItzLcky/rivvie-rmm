//! Uploaded MSI and EXE installers. The agent downloads the file from the server (with its own
//! credentials), checks it against the SHA-256 the catalog recorded, and runs it silently.
//! Whether it's installed comes from the Uninstall registry keys: by product code (the key
//! name) or by DisplayName.

#![cfg_attr(not(windows), allow(dead_code))]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use rmm_proto::patch::PatchStage;
use rmm_proto::software::{Installer as Spec, InstallerKind, Op, Package, Status, compare_versions};
use sha2::{Digest, Sha256};

use super::parse::split_args;
use super::{Done, Provider, RunCtx};
use crate::patch::cmd::{self, Log, Opts};

pub struct Installer;

/// One entry under `...\CurrentVersion\Uninstall`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The key's name: a product code (`{GUID}`) for MSI products.
    pub key: String,
    pub name: String,
    pub version: String,
}

#[cfg(windows)]
fn entries() -> Vec<Entry> {
    use winreg::RegKey;
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY};

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let mut out = Vec::new();
    for view in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
        let Ok(root) = hklm.open_subkey_with_flags("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", KEY_READ | view) else { continue };
        for sub in root.enum_keys().flatten() {
            let Ok(key) = root.open_subkey_with_flags(&sub, KEY_READ | view) else { continue };
            let name = key.get_value::<String, _>("DisplayName").unwrap_or_default();
            out.push(Entry { key: sub, name, version: key.get_value::<String, _>("DisplayVersion").unwrap_or_default() });
        }
    }
    out
}

#[cfg(not(windows))]
fn entries() -> Vec<Entry> {
    Vec::new()
}

/// The entry that says this installer's product is installed.
pub fn find<'a>(spec: &Spec, entries: &'a [Entry]) -> Option<&'a Entry> {
    if let Some(code) = spec.product_code.as_deref() {
        return entries.iter().find(|e| e.key.eq_ignore_ascii_case(code));
    }
    let want = spec.detect_name.as_deref()?.to_ascii_lowercase();
    entries.iter().find(|e| !e.name.is_empty() && e.name.to_ascii_lowercase() == want).or_else(|| entries.iter().find(|e| !e.name.is_empty() && e.name.to_ascii_lowercase().contains(&want)))
}

/// The program and arguments that install the downloaded file.
pub fn install_command(spec: &Spec, file: &Path) -> Result<(String, Vec<String>)> {
    let extra = split_args(&spec.silent_args)?;
    Ok(match spec.kind {
        InstallerKind::Msi => {
            let mut a = vec!["/i".to_string(), file.to_string_lossy().into_owned(), "/qn".into(), "/norestart".into()];
            a.extend(extra);
            ("msiexec.exe".into(), a)
        }
        InstallerKind::Exe => (file.to_string_lossy().into_owned(), extra),
    })
}

/// The program and arguments that remove the product.
pub fn uninstall_command(spec: &Spec) -> Result<(String, Vec<String>)> {
    if let Some(code) = &spec.product_code {
        return Ok(("msiexec.exe".into(), vec!["/x".into(), code.clone(), "/qn".into(), "/norestart".into()]));
    }
    let Some(line) = spec.uninstall_cmd.as_deref().filter(|c| !c.trim().is_empty()) else {
        bail!("the catalog entry has no product code or uninstall command, so the agent doesn't know how to remove it");
    };
    let mut parts = split_args(line)?;
    if parts.is_empty() {
        bail!("the uninstall command is empty");
    }
    let program = parts.remove(0);
    Ok((program, parts))
}

/// 0 is success; 3010 and 1641 mean success, restart needed.
fn exit_ok(code: Option<i32>) -> Option<bool> {
    match code {
        Some(0) => Some(false),
        Some(3010) | Some(1641) => Some(true),
        _ => None,
    }
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

/// Downloads the installer into the state directory (once: a copy whose hash is right is kept
/// for the run), and verifies it.
fn fetch(pkg: &Package, spec: &Spec, ctx: &RunCtx) -> Result<PathBuf> {
    if spec.sha256.len() != 64 || !spec.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("the catalog entry's installer hash is malformed");
    }
    let dir = crate::config::state_subdir("software")?;
    let file = dir.join(format!("{}.{}", &spec.sha256[..32], spec.kind.as_str()));
    if file.is_file() && sha256_file(&file).is_ok_and(|h| h.eq_ignore_ascii_case(&spec.sha256)) {
        return Ok(file);
    }
    (ctx.progress)(PatchStage::Downloading, Some(format!("downloading the installer for {}", pkg.name)));
    let part = file.with_extension("part");
    let url = format!("{}/api/agent/software/{}/installer", ctx.server.url.trim_end_matches('/'), pkg.id);
    let headers = [("X-Rmm-Agent", ctx.server.agent_id.to_string()), ("Authorization", format!("Bearer {}", ctx.server.secret))];
    // The agent's async downloader; this runs on a blocking thread of the runtime.
    let handle = tokio::runtime::Handle::try_current().context("no runtime for the download")?;
    let mut last = None;
    for wait in [0, 5, 20] {
        if wait > 0 {
            std::thread::sleep(Duration::from_secs(wait));
        }
        match handle.block_on(crate::fetch::download(&url, &headers, &part, spec.size)) {
            Ok(()) => {
                last = None;
                break;
            }
            Err(e) => last = Some(e),
        }
    }
    if let Some(e) = last {
        bail!("couldn't download the installer: {e:#}");
    }
    let got = sha256_file(&part)?;
    if !got.eq_ignore_ascii_case(&spec.sha256) {
        let _ = std::fs::remove_file(&part);
        bail!("the downloaded installer's SHA-256 ({got}) isn't the one in the catalog; it was discarded");
    }
    std::fs::rename(&part, &file)?;
    Ok(file)
}

impl Provider for Installer {
    fn name(&self) -> &'static str {
        "installer"
    }

    fn available(&self) -> bool {
        cfg!(windows)
    }

    fn handles(&self, pkg: &Package) -> bool {
        pkg.installer.is_some()
    }

    fn scan(&self, pkgs: &[&Package], _log: &Log, _refresh: bool) -> Result<Vec<Status>> {
        let entries = entries();
        Ok(pkgs
            .iter()
            .map(|p| {
                let spec = p.installer.as_ref();
                let found = spec.and_then(|s| find(s, &entries));
                let installed = found.map(|e| if e.version.is_empty() { "unknown".to_string() } else { e.version.clone() });
                // The catalog's version is the one the uploaded file installs.
                let available = match (&installed, &p.version) {
                    (Some(i), Some(v)) if i != "unknown" && compare_versions(i, v).is_lt() => Some(v.clone()),
                    _ => None,
                };
                Status { package_id: p.id, installed, available, provider: Some("installer".into()) }
            })
            .collect())
    }

    fn run(&self, op: Op, pkg: &Package, ctx: &RunCtx) -> Result<Done> {
        let spec = pkg.installer.as_ref().context("no installer")?;
        let (program, args, file) = match op {
            Op::Install | Op::Upgrade => {
                let file = fetch(pkg, spec, ctx)?;
                let (p, a) = install_command(spec, &file)?;
                (p, a, Some(file))
            }
            Op::Uninstall => {
                let (p, a) = uninstall_command(spec)?;
                (p, a, None)
            }
        };
        (ctx.progress)(PatchStage::Installing, Some(format!("running {}", Path::new(&program).file_name().map_or(program.clone(), |f| f.to_string_lossy().into_owned()))));
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        let out = cmd::output(ctx.log, &program, &argv, Opts { timeout: Duration::from_secs(3600), ..Default::default() });
        if let Some(f) = &file {
            let _ = std::fs::remove_file(f);
        }
        let out = out?;
        match exit_ok(out.code) {
            Some(reboot) => Ok(Done { reboot_required: reboot, note: None }),
            None => bail!("the {} exited with code {}: {}", if op == Op::Uninstall { "uninstaller" } else { "installer" }, out.code.map_or("none".into(), |c| c.to_string()), out.reason()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(kind: InstallerKind) -> Spec {
        Spec { kind, size: 10, sha256: "a".repeat(64), silent_args: "/VERYSILENT /DIR=\"C:\\Program Files\\X\"".into(), uninstall_cmd: None, product_code: None, detect_name: None }
    }

    #[test]
    fn builds_install_commands() {
        let (p, a) = install_command(&spec(InstallerKind::Exe), Path::new("C:\\s\\x.exe")).unwrap();
        assert_eq!((p.as_str(), a.as_slice()), ("C:\\s\\x.exe", ["/VERYSILENT".to_string(), "/DIR=C:\\Program Files\\X".to_string()].as_slice()));
        let mut s = spec(InstallerKind::Msi);
        s.silent_args = "ALLUSERS=1".into();
        let (p, a) = install_command(&s, Path::new("C:\\s\\x.msi")).unwrap();
        assert_eq!(p, "msiexec.exe");
        assert_eq!(a, ["/i", "C:\\s\\x.msi", "/qn", "/norestart", "ALLUSERS=1"]);
        s.silent_args = "\"oops".into();
        assert!(install_command(&s, Path::new("x.msi")).is_err());
    }

    #[test]
    fn builds_uninstall_commands() {
        let mut s = spec(InstallerKind::Msi);
        assert!(uninstall_command(&s).is_err());
        s.product_code = Some("{11111111-2222-3333-4444-555555555555}".into());
        assert_eq!(uninstall_command(&s).unwrap().1, ["/x", "{11111111-2222-3333-4444-555555555555}", "/qn", "/norestart"]);
        let mut e = spec(InstallerKind::Exe);
        e.uninstall_cmd = Some("\"C:\\Program Files\\X\\unins000.exe\" /VERYSILENT".into());
        let (p, a) = uninstall_command(&e).unwrap();
        assert_eq!((p.as_str(), a.as_slice()), ("C:\\Program Files\\X\\unins000.exe", ["/VERYSILENT".to_string()].as_slice()));
    }

    #[test]
    fn finds_installed_entries() {
        let entries = vec![
            Entry { key: "{AAAA}".into(), name: "Acme Agent".into(), version: "2.0".into() },
            Entry { key: "AcmeTool".into(), name: "Acme Tool 5 (x64)".into(), version: "5.1".into() },
            Entry { key: "x".into(), name: String::new(), version: String::new() },
        ];
        let mut s = spec(InstallerKind::Msi);
        s.product_code = Some("{aaaa}".into());
        assert_eq!(find(&s, &entries).unwrap().version, "2.0");
        s.product_code = None;
        s.detect_name = Some("acme tool 5".into());
        assert_eq!(find(&s, &entries).unwrap().key, "AcmeTool");
        s.detect_name = Some("missing".into());
        assert!(find(&s, &entries).is_none());
        s.detect_name = None;
        assert!(find(&s, &entries).is_none());
    }

    #[test]
    fn exit_codes() {
        assert_eq!(exit_ok(Some(0)), Some(false));
        assert_eq!(exit_ok(Some(3010)), Some(true));
        assert_eq!(exit_ok(Some(1603)), None);
    }
}
