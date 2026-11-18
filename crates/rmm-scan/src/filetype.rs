//! File type from content, never from the name: a renamed executable is still an executable.
//! Only the first few KB are looked at.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileType {
    Pe,
    Elf,
    MachO,
    Zip,
    Gzip,
    Tar,
    Bzip2,
    Xz,
    SevenZip,
    Cab,
    Ole2,
    Pdf,
    Lnk,
    Rtf,
    Html,
    ShellScript,
    PowerShell,
    Vbs,
    JavaScript,
    Batch,
    Python,
    Php,
    Text,
    Unknown,
}

impl FileType {
    pub fn as_str(self) -> &'static str {
        match self {
            FileType::Pe => "pe",
            FileType::Elf => "elf",
            FileType::MachO => "macho",
            FileType::Zip => "zip",
            FileType::Gzip => "gzip",
            FileType::Tar => "tar",
            FileType::Bzip2 => "bzip2",
            FileType::Xz => "xz",
            FileType::SevenZip => "7z",
            FileType::Cab => "cab",
            FileType::Ole2 => "ole2",
            FileType::Pdf => "pdf",
            FileType::Lnk => "lnk",
            FileType::Rtf => "rtf",
            FileType::Html => "html",
            FileType::ShellScript => "shell",
            FileType::PowerShell => "powershell",
            FileType::Vbs => "vbs",
            FileType::JavaScript => "javascript",
            FileType::Batch => "batch",
            FileType::Python => "python",
            FileType::Php => "php",
            FileType::Text => "text",
            FileType::Unknown => "unknown",
        }
    }

    pub fn is_executable(self) -> bool {
        matches!(self, FileType::Pe | FileType::Elf | FileType::MachO)
    }

    pub fn is_script(self) -> bool {
        matches!(
            self,
            FileType::ShellScript | FileType::PowerShell | FileType::Vbs | FileType::JavaScript | FileType::Batch | FileType::Python | FileType::Php | FileType::Html
        )
    }
}

const LNK_HEADER: [u8; 20] = [0x4c, 0, 0, 0, 0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46];
const OLE2: [u8; 8] = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];

fn has(data: &[u8], at: usize, magic: &[u8]) -> bool {
    data.get(at..at.saturating_add(magic.len())) == Some(magic)
}

fn u32le(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

/// A tar header: its checksum field matches the header bytes.
fn is_tar(data: &[u8]) -> bool {
    let Some(h) = data.get(..512) else { return false };
    if has(h, 257, b"ustar") {
        return true;
    }
    let Some(field) = h.get(148..156) else { return false };
    let digits: String = field.iter().take_while(|b| **b != 0 && **b != b' ').map(|b| *b as char).collect();
    let Ok(want) = u32::from_str_radix(digits.trim(), 8) else { return false };
    let sum: u32 = h.iter().enumerate().map(|(i, b)| if (148..156).contains(&i) { 32 } else { u32::from(*b) }).sum();
    sum == want && h.first().is_some_and(|b| *b != 0)
}

pub fn identify(data: &[u8]) -> FileType {
    if has(data, 0, b"MZ")
        && let Some(off) = u32le(data, 0x3c)
        && has(data, off as usize, b"PE\0\0")
    {
        return FileType::Pe;
    }
    if has(data, 0, b"\x7fELF") {
        return FileType::Elf;
    }
    if let Some(m) = u32le(data, 0)
        && matches!(m, 0xfeedface | 0xfeedfacf | 0xcefaedfe | 0xcffaedfe | 0xbebafeca)
    {
        return FileType::MachO;
    }
    if has(data, 0, b"PK\x03\x04") || has(data, 0, b"PK\x05\x06") {
        return FileType::Zip;
    }
    if has(data, 0, &[0x1f, 0x8b]) {
        return FileType::Gzip;
    }
    if has(data, 0, b"BZh") && data.get(3).is_some_and(|b| (b'1'..=b'9').contains(b)) {
        return FileType::Bzip2;
    }
    if has(data, 0, &[0xfd, b'7', b'z', b'X', b'Z', 0]) {
        return FileType::Xz;
    }
    if has(data, 0, &[b'7', b'z', 0xbc, 0xaf, 0x27, 0x1c]) {
        return FileType::SevenZip;
    }
    if has(data, 0, b"MSCF") {
        return FileType::Cab;
    }
    if has(data, 0, &OLE2) {
        return FileType::Ole2;
    }
    if has(data, 0, &LNK_HEADER) {
        return FileType::Lnk;
    }
    if is_tar(data) {
        return FileType::Tar;
    }
    // PDF readers accept the header anywhere in the first KB.
    let head = data.get(..data.len().min(1024)).unwrap_or_default();
    if memfind(head, b"%PDF-").is_some() {
        return FileType::Pdf;
    }
    if has(data, 0, b"{\\rtf") {
        return FileType::Rtf;
    }
    text_type(data)
}

pub(crate) fn memfind(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn contains_nocase(hay: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| hay.contains(n))
}

/// Text that looks like a script. Decides on the first 4 KB, lowercased.
fn text_type(data: &[u8]) -> FileType {
    let head = data.get(..data.len().min(4096)).unwrap_or_default();
    // UTF-16 text (PowerShell and VBS are often saved that way): look at every other byte.
    let narrowed: Vec<u8>;
    let head = if head.len() >= 4 && (head.starts_with(&[0xff, 0xfe]) || head.get(1) == Some(&0) && head.get(3) == Some(&0)) {
        narrowed = head.iter().skip(if head.starts_with(&[0xff, 0xfe]) { 2 } else { 0 }).step_by(2).copied().collect();
        &narrowed[..]
    } else {
        head
    };
    let head = head.strip_prefix(b"\xef\xbb\xbf").unwrap_or(head);
    let printable = head.iter().filter(|b| b.is_ascii_graphic() || b.is_ascii_whitespace() || **b >= 0x80).count();
    if head.is_empty() || printable * 100 < head.len() * 95 {
        return FileType::Unknown;
    }
    let s = String::from_utf8_lossy(head).to_ascii_lowercase();
    let first = s.lines().next().unwrap_or_default().trim();
    if let Some(sb) = first.strip_prefix("#!") {
        return if sb.contains("python") {
            FileType::Python
        } else if sb.contains("pwsh") || sb.contains("powershell") {
            FileType::PowerShell
        } else if sb.contains("node") {
            FileType::JavaScript
        } else if sb.contains("php") {
            FileType::Php
        } else {
            FileType::ShellScript
        };
    }
    if s.contains("<?php") {
        return FileType::Php;
    }
    if contains_nocase(&s, &["<html", "<!doctype html", "<hta:application", "<script"]) {
        return FileType::Html;
    }
    if first.starts_with("@echo off") || contains_nocase(&s, &["\n@echo off", "%~dp0", "setlocal enabledelayedexpansion", "goto :eof"]) {
        return FileType::Batch;
    }
    if contains_nocase(&s, &["param(", "write-host", "invoke-expression", "new-object system.", "get-childitem", "$env:", "-executionpolicy", "[convert]::"]) {
        return FileType::PowerShell;
    }
    if contains_nocase(&s, &["createobject(", "wscript.", "dim ", "end sub", "end function", "on error resume next"]) {
        return FileType::Vbs;
    }
    if contains_nocase(&s, &["function(", "function (", "var ", "document.", "activexobject", "require(", "=> {", "const "]) {
        return FileType::JavaScript;
    }
    FileType::Text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn types() {
        let mut pe = vec![0u8; 256];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3c] = 0x80;
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        assert_eq!(identify(&pe), FileType::Pe);
        assert_eq!(identify(b"MZ only a dos stub"), FileType::Text, "MZ without a PE header isn't a PE");
        assert_eq!(identify(b"\x7fELF\x02\x01\x01"), FileType::Elf);
        assert_eq!(identify(b"PK\x03\x04...."), FileType::Zip);
        assert_eq!(identify(&[0x1f, 0x8b, 8, 0]), FileType::Gzip);
        assert_eq!(identify(b"BZh91AY&SY"), FileType::Bzip2);
        assert_eq!(identify(&OLE2), FileType::Ole2);
        assert_eq!(identify(&LNK_HEADER), FileType::Lnk);
        assert_eq!(identify(b"%PDF-1.7\n"), FileType::Pdf);
        assert_eq!(identify(b"#!/bin/sh\necho hi\n"), FileType::ShellScript);
        assert_eq!(identify(b"#!/usr/bin/env python3\n"), FileType::Python);
        assert_eq!(identify(b"<?php echo 1; ?>"), FileType::Php);
        assert_eq!(identify(b"@echo off\r\nset x=1\r\n"), FileType::Batch);
        assert_eq!(identify(b"$x = [Convert]::FromBase64String($s)\nWrite-Host $x"), FileType::PowerShell);
        assert_eq!(identify(b"Dim s\r\nSet o = CreateObject(\"WScript.Shell\")"), FileType::Vbs);
        assert_eq!(identify(b"var x = new ActiveXObject('x');"), FileType::JavaScript);
        assert_eq!(identify(b"<html><script>alert(1)</script></html>"), FileType::Html);
        assert_eq!(identify(b"just some notes"), FileType::Text);
        assert_eq!(identify(&[0u8, 1, 2, 3, 200, 7]), FileType::Unknown);
        let utf16: Vec<u8> = "\u{feff}Write-Host hi".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        assert_eq!(identify(&utf16), FileType::PowerShell);
        let mut tar = vec![0u8; 512];
        tar[..5].copy_from_slice(b"a.txt");
        tar[257..262].copy_from_slice(b"ustar");
        assert_eq!(identify(&tar), FileType::Tar);
    }

    #[test]
    fn hostile_input_never_panics() {
        crate::fuzz::mutate(&[&b"MZ\0\0"[..], b"#!/bin/sh\n", b"PK\x03\x04", &OLE2], 4000, |d| {
            identify(d);
        });
    }
}
