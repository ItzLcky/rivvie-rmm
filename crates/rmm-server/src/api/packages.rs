//! `.deb`, `.rpm` and `.msi` agent packages with the server URL and an enrollment token baked in.
//! The MSI is described in [`super::msi`]; the rest of this is about the Linux packages.
//!
//! `GET /api/agent-packages/{platform}/rmm-agent.deb?token=…` (or `.rpm`) builds the package
//! on the fly around the Linux agent binary in RMM_AGENT_DIR. It contains:
//!
//! - `/usr/bin/rmm-agent`
//! - `/etc/rmm-agent/enroll.toml` (mode 0600): server URL and token
//!
//! and its post-install script enrolls (if this machine isn't enrolled yet) and starts the
//! service, then deletes `enroll.toml`. Upgrading with a newer package keeps the existing
//! enrollment and restarts the service on the new binary.
//!
//! Packages get copied around, so the token must have both an expiry and a use limit; the
//! server refuses to bake an unbounded one.

use std::io::Write;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::header;
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::error::{ApiError, ApiResult};
use crate::ratelimit::ClientIp;
use crate::state::AppState;

const DESCRIPTION: &str = "Remote monitoring and management agent";

/// Shared by both formats; `$1` handling differs, so each gets its own wrapper.
const POSTINST: &str = r#"
ENROLL=/etc/rmm-agent/enroll.toml
if [ -f /etc/rmm-agent/agent.toml ]; then
    # Already enrolled (an upgrade or reinstall): keep the identity, run the new binary.
    /usr/bin/rmm-agent install >/dev/null 2>&1 || true
    systemctl restart rmm-agent.service || true
elif [ -f "$ENROLL" ]; then
    if ! /usr/bin/rmm-agent enroll --from-file "$ENROLL" --install; then
        echo "rmm-agent: enrollment or service setup failed (see above). Fix the cause, then retry" >&2
        echo "(re-running keeps the same agent record):" >&2
        echo "  sudo rmm-agent enroll --from-file $ENROLL --install" >&2
        exit 1
    fi
fi
rm -f "$ENROLL"
"#;

#[derive(Deserialize)]
pub struct TokenQuery {
    token: String,
}

pub async fn download(
    State(st): State<Arc<AppState>>,
    ClientIp(ip): ClientIp,
    Path((platform, file)): Path<(String, String)>,
    Query(q): Query<TokenQuery>,
) -> ApiResult<impl IntoResponse> {
    let (format, deb_arch, rpm_arch) = match (platform.as_str(), file.as_str()) {
        ("linux-x86_64", "rmm-agent.deb") => (Format::Deb, "amd64", "x86_64"),
        ("linux-x86_64", "rmm-agent.rpm") => (Format::Rpm, "amd64", "x86_64"),
        ("windows-x86_64", "rmm-agent.msi") => (Format::Msi, "", ""),
        ("linux-x86_64" | "windows-x86_64", _) => return Err(ApiError::NotFound("package")),
        _ => return Err(ApiError::NotFound("platform")),
    };
    super::downloads::token_site(&st, ip, &q.token).await?;
    let bounded: bool = sqlx::query_scalar(
        "SELECT expires_at IS NOT NULL AND max_uses IS NOT NULL FROM enrollment_tokens WHERE token_hash = $1",
    )
    .bind(crate::auth::token_hash(&q.token))
    .fetch_one(&st.db)
    .await?;
    if !bounded {
        return Err(ApiError::BadRequest(
            "packages can only carry a token with an expiry and a use limit; create one under Enroll agents → Package".into(),
        ));
    }
    let path = super::agent_binary_path(&st, &platform).ok_or(ApiError::NotFound("agent binary"))?;
    let binary = tokio::fs::read(&path).await.map_err(anyhow::Error::from)?;
    // The signed release's version if there is one; otherwise this server's (same workspace).
    let version = st.releases.get(&st, &platform).map(|r| r.manifest.version.clone()).unwrap_or_else(|| env!("CARGO_PKG_VERSION").into());
    // The package's client sees its own branding (the agent ends up on its machines).
    let client_id: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT s.client_id FROM enrollment_tokens t JOIN sites s ON s.id = t.site_id WHERE t.token_hash = $1")
            .bind(crate::auth::token_hash(&q.token))
            .fetch_optional(&st.db)
            .await?;
    let brand = crate::branding::resolve(&st, client_id);
    let icon = match (format, crate::branding::image(&st, client_id, crate::branding::Variant::Icon).await) {
        (Format::Msi, Ok(Some((png, _, _)))) => crate::branding::check_image(crate::branding::Variant::Icon, &png)
            .ok()
            .map(|i| crate::branding::ico(&png, i.width, i.height)),
        (_, Err(e)) => {
            tracing::warn!("branding icon for a package: {e:#}");
            None
        }
        _ => None,
    };
    let enroll = enroll_toml(&st.cfg.public_url, &q.token, brand.product_name.as_deref());
    let (server, token) = (st.cfg.public_url.clone(), q.token.clone());
    let company = st.company().company_name;
    let manufacturer = if company.trim().is_empty() { "RMM".to_string() } else { company };
    let (slug, agent_name, branded) = (brand.slug(), brand.agent_name(), brand.product_name.clone());
    let summary = match &branded {
        Some(p) => format!("{p} agent: remote monitoring and management"),
        None => DESCRIPTION.to_string(),
    };
    let (bytes, name) = tokio::task::spawn_blocking(move || -> anyhow::Result<(Vec<u8>, String)> {
        Ok(match format {
            Format::Deb => (deb(&binary, &enroll, &version, deb_arch, &summary)?, format!("{slug}-agent_{version}_{deb_arch}.deb")),
            Format::Rpm => (rpm(&binary, &enroll, &version, rpm_arch, &summary)?, format!("{slug}-agent-{version}-1.{rpm_arch}.rpm")),
            Format::Msi => {
                let input = super::msi::MsiInput {
                    binary: &binary,
                    server: &server,
                    token: &token,
                    version: &version,
                    manufacturer: &manufacturer,
                    product_name: &agent_name,
                    branded_name: branded.as_deref(),
                    icon: icon.as_deref(),
                };
                (super::msi::build(&input)?, format!("{slug}-agent-{version}-x64.msi"))
            }
        })
    })
    .await
    .map_err(anyhow::Error::from)??;
    Ok((
        [
            (header::CONTENT_TYPE, format.mime().to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{name}\"")),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        bytes,
    ))
}

#[derive(Clone, Copy)]
enum Format {
    Deb,
    Rpm,
    Msi,
}

impl Format {
    fn mime(self) -> &'static str {
        match self {
            Format::Deb => "application/vnd.debian.binary-package",
            Format::Rpm => "application/x-rpm",
            Format::Msi => "application/x-msi",
        }
    }
}

fn toml_str(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `product_name` (when branded) names the service; older agents ignore the key.
fn enroll_toml(server: &str, token: &str, product_name: Option<&str>) -> Vec<u8> {
    let mut out = format!("# Read once by the package's post-install script, then deleted.\nserver = {}\ntoken = {}\n", toml_str(server), toml_str(token));
    if let Some(p) = product_name {
        out.push_str(&format!("product_name = {}\n", toml_str(p)));
    }
    out.into_bytes()
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// .deb: an ar archive of debian-binary, control.tar.gz and data.tar.gz
// ---------------------------------------------------------------------------

/// The tray app on Linux desktops (docs/design/tray.md): a launcher that opens the request
/// form, and an autostart entry that stays connected for consent prompts and notices.
const TRAY_LAUNCHER: &str = "[Desktop Entry]\nType=Application\nName=Request help\nComment=Ask the help desk for help with this computer\n\
Exec=/usr/bin/rmm-agent tray\nIcon=help-browser\nTerminal=false\nCategories=Utility;\n";
const TRAY_AUTOSTART: &str = "[Desktop Entry]\nType=Application\nName=Help desk link\nComment=Shows the help desk's prompts and notices\n\
Exec=/usr/bin/rmm-agent tray --background\nTerminal=false\nNoDisplay=true\nX-GNOME-Autostart-enabled=true\n";

fn deb(binary: &[u8], enroll: &[u8], version: &str, arch: &str, summary: &str) -> anyhow::Result<Vec<u8>> {
    // One line: a newline would start another control field.
    let summary = summary.replace(['\n', '\r'], " ");
    let control = format!(
        "Package: rmm-agent\nVersion: {version}\nArchitecture: {arch}\nMaintainer: RMM <root@localhost>\n\
         Section: admin\nPriority: optional\nDepends: systemd\nInstalled-Size: {}\nDescription: {summary}\n \
         Installs the agent and enrolls it with the server it was downloaded from.\n",
        binary.len().div_ceil(1024)
    );
    let postinst = format!("#!/bin/sh\nset -e\nif [ \"$1\" = configure ]; then\n{POSTINST}\nfi\n");
    let prerm = "#!/bin/sh\nset -e\nif [ \"$1\" = remove ]; then\n    /usr/bin/rmm-agent uninstall || true\nfi\n";
    let postrm = "#!/bin/sh\nset -e\nif [ \"$1\" = purge ]; then\n    rm -rf /etc/rmm-agent\nfi\n";
    let control_tar = tar_gz(&[
        Entry::file("./control", 0o644, control.as_bytes()),
        Entry::file("./postinst", 0o755, postinst.as_bytes()),
        Entry::file("./prerm", 0o755, prerm.as_bytes()),
        Entry::file("./postrm", 0o755, postrm.as_bytes()),
    ])?;
    let data_tar = tar_gz(&[
        Entry::dir("./usr/", 0o755),
        Entry::dir("./usr/bin/", 0o755),
        Entry::file("./usr/bin/rmm-agent", 0o755, binary),
        Entry::dir("./etc/", 0o755),
        Entry::dir("./etc/rmm-agent/", 0o700),
        Entry::file("./etc/rmm-agent/enroll.toml", 0o600, enroll),
        Entry::dir("./etc/xdg/", 0o755),
        Entry::dir("./etc/xdg/autostart/", 0o755),
        Entry::file("./etc/xdg/autostart/rmm-tray.desktop", 0o644, TRAY_AUTOSTART.as_bytes()),
        Entry::dir("./usr/share/", 0o755),
        Entry::dir("./usr/share/applications/", 0o755),
        Entry::file("./usr/share/applications/rmm-tray.desktop", 0o644, TRAY_LAUNCHER.as_bytes()),
    ])?;
    let mut out = b"!<arch>\n".to_vec();
    for (name, data) in [("debian-binary", &b"2.0\n"[..]), ("control.tar.gz", &control_tar), ("data.tar.gz", &data_tar)] {
        ar_member(&mut out, name, data);
    }
    Ok(out)
}

fn ar_member(out: &mut Vec<u8>, name: &str, data: &[u8]) {
    let header = format!("{name:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n", now(), 0, 0, "100644", data.len());
    debug_assert_eq!(header.len(), 60);
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(data);
    if data.len() % 2 == 1 {
        out.push(b'\n');
    }
}

struct Entry<'a> {
    path: &'a str,
    mode: u32,
    data: Option<&'a [u8]>,
}

impl<'a> Entry<'a> {
    fn file(path: &'a str, mode: u32, data: &'a [u8]) -> Self {
        Self { path, mode, data: Some(data) }
    }
    fn dir(path: &'a str, mode: u32) -> Self {
        Self { path, mode, data: None }
    }
}

fn tar_gz(entries: &[Entry]) -> anyhow::Result<Vec<u8>> {
    let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut tar = tar::Builder::new(gz);
    let mtime = now();
    for e in entries {
        let mut h = tar::Header::new_gnu();
        h.set_mode(e.mode);
        h.set_uid(0);
        h.set_gid(0);
        h.set_username("root")?;
        h.set_groupname("root")?;
        h.set_mtime(mtime);
        match e.data {
            Some(data) => {
                h.set_entry_type(tar::EntryType::Regular);
                h.set_size(data.len() as u64);
                tar.append_data(&mut h, e.path, data)?;
            }
            None => {
                h.set_entry_type(tar::EntryType::Directory);
                h.set_size(0);
                tar.append_data(&mut h, e.path, std::io::empty())?;
            }
        }
    }
    let mut gz = tar.into_inner()?;
    gz.flush()?;
    Ok(gz.finish()?)
}

// ---------------------------------------------------------------------------
// .rpm
// ---------------------------------------------------------------------------

fn rpm(binary: &[u8], enroll: &[u8], version: &str, arch: &str, summary: &str) -> anyhow::Result<Vec<u8>> {
    // rpm versions can't contain '-'; a pre-release tag becomes part of the version.
    let version = version.replace('-', "~");
    // $1 is the number of instances left after the operation: 0 means a real uninstall.
    let preun = "if [ \"$1\" = 0 ]; then\n    /usr/bin/rmm-agent uninstall || true\nfi\n";
    let pkg = rpm::PackageBuilder::new("rmm-agent", &version, "AGPL-3.0-or-later", arch, summary)
        .description("Installs the agent and enrolls it with the server it was downloaded from.")
        .release("1")
        .using_config(rpm::BuildConfig::v4().compression(rpm::CompressionType::Gzip))
        .with_file_contents(binary.to_vec(), rpm::FileOptions::new("/usr/bin/rmm-agent").permissions(0o755))?
        .with_dir_entry(rpm::FileOptions::dir("/etc/rmm-agent").permissions(0o700))?
        .with_file_contents(enroll.to_vec(), rpm::FileOptions::new("/etc/rmm-agent/enroll.toml").permissions(0o600).missingok())?
        .with_file_contents(TRAY_AUTOSTART.as_bytes().to_vec(), rpm::FileOptions::new("/etc/xdg/autostart/rmm-tray.desktop").permissions(0o644))?
        .with_file_contents(TRAY_LAUNCHER.as_bytes().to_vec(), rpm::FileOptions::new("/usr/share/applications/rmm-tray.desktop").permissions(0o644))?
        .post_install_script(format!("set -e\n{POSTINST}"))
        .pre_uninstall_script(preun)
        .build()?;
    let mut out = Vec::new();
    pkg.write(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toml_escaping() {
        assert_eq!(toml_str(r#"a"b\c"#), r#""a\"b\\c""#);
        let raw = String::from_utf8(enroll_toml("https://rmm.example.com", "ab12", None)).unwrap();
        let v: toml_check::Enroll = toml_check::parse(&raw);
        assert_eq!(v.server, "https://rmm.example.com");
        assert_eq!(v.token, "ab12");
        assert!(!raw.contains("product_name"));
        let raw = String::from_utf8(enroll_toml("https://x", "t", Some("Acme \"Remote\""))).unwrap();
        assert!(raw.contains("product_name = \"Acme \\\"Remote\\\"\"\n"), "{raw}");
    }

    /// Minimal parser for the two-key file, so the test doesn't need a toml dependency.
    mod toml_check {
        pub struct Enroll {
            pub server: String,
            pub token: String,
        }
        pub fn parse(raw: &str) -> Enroll {
            let get = |k: &str| {
                raw.lines()
                    .find_map(|l| l.strip_prefix(&format!("{k} = ")))
                    .map(|v| v.trim_matches('"').to_string())
                    .unwrap()
            };
            Enroll { server: get("server"), token: get("token") }
        }
    }

    #[test]
    fn deb_layout() {
        let pkg = deb(b"\x7fELF fake", &enroll_toml("https://x", "t", None), "0.1.0", "amd64", DESCRIPTION).unwrap();
        assert!(pkg.starts_with(b"!<arch>\ndebian-binary   "));
        let names: Vec<String> = ar_names(&pkg);
        assert_eq!(names, ["debian-binary", "control.tar.gz", "data.tar.gz"]);
        // The data archive carries the tray's launcher and autostart entry.
        let data = ar_member_data(&pkg, "data.tar.gz");
        let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(&data[..]));
        let paths: Vec<String> = tar.entries().unwrap().map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned()).collect();
        assert!(paths.iter().any(|p| p == "./usr/share/applications/rmm-tray.desktop"), "{paths:?}");
        assert!(paths.iter().any(|p| p == "./etc/xdg/autostart/rmm-tray.desktop"), "{paths:?}");
        assert!(TRAY_AUTOSTART.contains("Exec=/usr/bin/rmm-agent tray --background\n"));
    }

    fn ar_member_data(pkg: &[u8], want: &str) -> Vec<u8> {
        let mut i = 8;
        while i + 60 <= pkg.len() {
            let h = &pkg[i..i + 60];
            let size: usize = String::from_utf8_lossy(&h[48..58]).trim().parse().unwrap();
            if String::from_utf8_lossy(&h[..16]).trim() == want {
                return pkg[i + 60..i + 60 + size].to_vec();
            }
            i += 60 + size + size % 2;
        }
        panic!("no {want}");
    }

    fn ar_names(pkg: &[u8]) -> Vec<String> {
        let mut out = vec![];
        let mut i = 8;
        while i + 60 <= pkg.len() {
            let h = &pkg[i..i + 60];
            out.push(String::from_utf8_lossy(&h[..16]).trim().to_string());
            let size: usize = String::from_utf8_lossy(&h[48..58]).trim().parse().unwrap();
            i += 60 + size + size % 2;
        }
        out
    }

    #[test]
    fn rpm_builds() {
        let pkg = rpm(b"\x7fELF fake", &enroll_toml("https://x", "t", None), "0.2.0-rc.1", "x86_64", "Acme agent").unwrap();
        assert_eq!(&pkg[..4], &[0xed, 0xab, 0xee, 0xdb], "rpm lead magic");
    }
}
