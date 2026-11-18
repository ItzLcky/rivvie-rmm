//! The engine end to end: hashes, rules and heuristics through containers.

use std::io::Write;

use super::*;
use crate::container::tests::{make_tar, make_zip};
use crate::db::tests::{pubkey, sealed};
use crate::db::{Algo, Builder, HashSig};

/// The EICAR test file, assembled at runtime so no source file contains it.
pub fn eicar() -> Vec<u8> {
    format!("X5O!P%@AP[4\\PZX54(P^)7CC)7{}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*", "}").into_bytes()
}

const RULES: &str = r#"
rule Macro_Shell {
  meta:
    id = "T-MACRO"
    severity = "high"
  strings:
    $auto = "AutoOpen" nocase
    $shell = "Shell" nocase
  condition:
    all of them
}
rule Marker {
  meta:
    id = "T-MARKER"
    confidence = "high"
    mode = "alert"
  strings:
    $m = "RMM-TEST-MARKER"
  condition:
    $m
}
rule Lnk_PowerShell {
  meta:
    id = "T-LNK"
  strings:
    $a = "arguments: -w hidden"
  condition:
    $a
}
"#;

fn engine(limits: Limits) -> Engine {
    let mut b = Builder::new("test.1", "");
    b.add_hash(HashSig { algo: Algo::Sha256, digest: hash::digests(&eicar(), false, false).sha256.to_vec(), size: None, name: "EICAR test file".into(), severity: ThreatSeverity::Low });
    b.add_hash(HashSig { algo: Algo::Md5, digest: hash::digests(b"clam md5 sample", true, false).md5.unwrap().to_vec(), size: Some(15), name: "Clam.Test".into(), severity: ThreatSeverity::High });
    b.add_yara(RULES);
    let db = db::Database::from_bytes(sealed(b), &pubkey()).unwrap();
    Engine::new(Some(Arc::new(db)), None, limits).unwrap()
}

fn ids(v: &Verdict) -> Vec<(String, Option<String>)> {
    let mut out: Vec<_> = v.matches.iter().map(|m| (m.id.clone(), m.part.clone())).collect();
    out.sort();
    out
}

fn gz(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

#[test]
fn hashes_of_files_and_members() {
    let e = engine(Limits::default());
    let v = e.scan_bytes(&eicar(), &Context::default());
    assert_eq!(ids(&v), [("RMM-HASH".to_string(), None)]);
    assert_eq!(v.matches[0].name, "EICAR test file");
    let z = make_zip(&[("readme.txt", b"hello", 0), ("sub/eicar.com", &eicar(), 8)]);
    let v = e.scan_bytes(&gz(&z), &Context::default());
    assert_eq!(ids(&v), [("RMM-HASH".to_string(), Some("gzip>sub/eicar.com".to_string()))]);
    let v = e.scan_bytes(b"clam md5 sample", &Context::default());
    assert_eq!(v.matches[0].name, "Clam.Test", "MD5 signatures are checked when the database has them");
    assert!(e.scan_bytes(b"clean", &Context::default()).clean());
}

#[cfg(feature = "yara")]
#[test]
fn rules_reach_into_documents_and_shortcuts() {
    let e = engine(Limits::default());
    let vba = crate::ole::tests::make_vba_project("ThisDocument", "Sub AutoOpen()\r\n  Shell \"cmd /c calc\"\r\nEnd Sub\r\n");
    let docm = make_zip(&[("[Content_Types].xml", b"<Types/>", 8), ("word/document.xml", b"<w:document/>", 8), ("word/vbaProject.bin", &vba, 8)]);
    let v = e.scan_bytes(&docm, &Context { path: Some("/home/u/report.docm") });
    assert_eq!(ids(&v), [("T-MACRO".to_string(), Some("word/vbaProject.bin>VBA/ThisDocument".to_string()))]);
    assert!(v.parts >= 4, "{}", v.parts);
    let m = &v.matches[0];
    assert_eq!((m.severity, m.mode), (ThreatSeverity::High, RuleMode::Audit));
    let lnk = crate::embedded::tests::make_lnk("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "-w hidden -c iex");
    assert_eq!(ids(&e.scan_bytes(&lnk, &Context::default())), [("T-LNK".to_string(), Some("lnk".to_string()))]);
    let t = make_tar(&[("a/b.txt", b"x RMM-TEST-MARKER x")]);
    assert_eq!(ids(&e.scan_bytes(&t, &Context::default())), [("T-MARKER".to_string(), Some("a/b.txt".to_string()))]);
}

#[test]
fn heuristics_and_bombs() {
    let e = engine(Limits::default());
    let v = e.scan_bytes(b"#!/bin/sh\necho Y3VybA== | base64 -d | sh\n", &Context { path: Some("/tmp/x.sh") });
    assert_eq!(ids(&v), [("RMM-H-0003".to_string(), None)]);
    assert_eq!(v.matches[0].mode, RuleMode::Audit);
    let pe = crate::exe::tests::make_pe(".text", &[0x90; 600], false, b"");
    let z = make_zip(&[("invoice.pdf.exe", &pe, 8)]);
    assert_eq!(ids(&e.scan_bytes(&z, &Context::default())), [("RMM-H-0002".to_string(), Some("invoice.pdf.exe".to_string()))]);
    // Nested deeper than allowed.
    let mut nested = b"inner".to_vec();
    for _ in 0..8 {
        nested = gz(&nested);
    }
    let v = e.scan_bytes(&nested, &Context::default());
    assert_eq!(ids(&v), [("RMM-H-0004".to_string(), None)]);
    assert!(v.matches[0].name.ends_with("nested deeper than the archive depth limit"), "{}", v.matches[0].name);
    assert_eq!(v.matches[0].severity, ThreatSeverity::Low);
    let zeros = make_zip(&[("z", &vec![0u8; 50 * 1024 * 1024], 8)]);
    assert_eq!(ids(&e.scan_bytes(&zeros, &Context::default()))[0].0, "RMM-H-0004");
}

#[test]
fn over_the_cap_is_hashed_only() {
    let e = engine(Limits { content_cap: 1000, ..Limits::default() });
    let mut big = b"RMM-TEST-MARKER".to_vec();
    big.resize(5000, b' ');
    let v = e.scan_reader(&big[..], &Context::default()).unwrap();
    assert!(v.clean() && v.truncated && v.file_type.is_none() && v.size == 5000);
    let v = e.scan_reader(&eicar()[..], &Context::default()).unwrap();
    assert_eq!(v.matches[0].id, "RMM-HASH", "hashes have no size limit");
}

#[test]
fn legacy_bundle_rules_still_work() {
    let b = rmm_content::Bundle::parse(rmm_content::STARTER.as_bytes()).unwrap();
    let m = FileMatcher::new(&b).unwrap();
    let e = Engine::new(None, Some((b.version.clone(), m)), Limits::default()).unwrap();
    let v = e.scan_bytes(&eicar(), &Context::default());
    assert_eq!((v.matches[0].kind, v.matches[0].name.as_str()), (Kind::BundleHash, "EICAR test file"));
    let z = make_zip(&[("shell.php", b"<?php system($_GET['c']); ?>", 8)]);
    assert_eq!(ids(&e.scan_bytes(&z, &Context::default())), [("RMM-F-0003".to_string(), Some("shell.php".to_string()))], "bundle rules reach into archives now");
    assert!(e.generation().contains(&b.version));
}

#[test]
fn hostile_files_never_panic() {
    let e = engine(Limits { max_unpacked: 8 * 1024 * 1024, content_cap: 2 * 1024 * 1024, ..Limits::default() });
    let vba = crate::ole::tests::make_vba_project("M", "Sub AutoOpen()\r\nShell 1\r\nEnd Sub\r\n");
    let docm = make_zip(&[("word/vbaProject.bin", &vba, 8), ("x.txt", b"RMM-TEST-MARKER", 0)]);
    let lnk = crate::embedded::tests::make_lnk("C:\\a.exe", "-w hidden");
    let pe = crate::exe::tests::make_pe("UPX0", b"abc", false, b"tail");
    let elf = crate::exe::tests::make_elf("/lib/ld.so", &[(".text", b"x")], true);
    let nested = gz(&make_tar(&[("a.zip", &docm)]));
    crate::fuzz::mutate(&[&docm, &vba, &lnk, &pe, &elf, &nested], 1500, |d| {
        let _ = e.scan_bytes(d, &Context { path: Some("/tmp/x") });
    });
}
