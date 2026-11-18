//! Executable features for heuristics and reports: PE (sections with entropy, imports and
//! imphash, overlay, signature directory, timestamp, packer section names) and ELF (sections,
//! interpreter, UPX). Read-only views over bytes; every offset comes from the file, so every
//! access is checked and every table is bounded.

use md5::{Digest, Md5};
use serde::Serialize;

fn u16le(d: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(d.get(at..at.checked_add(2)?)?.try_into().ok()?))
}

fn u32le(d: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

fn u64le(d: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(d.get(at..at.checked_add(8)?)?.try_into().ok()?))
}

/// Shannon entropy in bits per byte (0-8). Packed or encrypted data is close to 8.
pub fn entropy(d: &[u8]) -> f32 {
    if d.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in d {
        counts[*b as usize] += 1;
    }
    let n = d.len() as f64;
    let e: f64 = counts.iter().filter(|c| **c > 0).map(|c| {
        let p = f64::from(*c) / n;
        -p * p.log2()
    }).sum();
    e as f32
}

fn cstr(d: &[u8], at: usize, max: usize) -> Option<String> {
    let rest = d.get(at..)?;
    let rest = rest.get(..rest.len().min(max))?;
    let n = rest.iter().position(|b| *b == 0).unwrap_or(rest.len());
    Some(String::from_utf8_lossy(rest.get(..n)?).into_owned())
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Section {
    pub name: String,
    pub size: u64,
    pub entropy: f32,
    pub executable: bool,
    pub writable: bool,
}

#[derive(Debug, Clone, Serialize, Default, PartialEq)]
pub struct Pe {
    pub machine: u16,
    pub is_64: bool,
    pub is_dll: bool,
    pub timestamp: u32,
    pub sections: Vec<Section>,
    /// (dll, functions), as named in the file.
    pub imports: Vec<(String, Vec<String>)>,
    /// pefile's imphash (ordinals as `ordN`, without its ordinal-to-name table).
    pub imphash: Option<String>,
    /// Bytes after the last section (installers and droppers carry payloads there).
    pub overlay: u64,
    /// An Authenticode signature directory is present (not verified).
    pub signed: bool,
    pub packer: Option<&'static str>,
    /// .NET (a CLR header).
    pub dotnet: bool,
}

impl Pe {
    pub fn max_entropy(&self) -> f32 {
        self.sections.iter().filter(|s| s.size >= 512).map(|s| s.entropy).fold(0.0, f32::max)
    }

    /// Packer section names, or an executable section that is nearly random.
    pub fn looks_packed(&self) -> bool {
        self.packer.is_some() || self.sections.iter().any(|s| s.executable && s.size >= 4096 && s.entropy > 7.2)
    }
}

const PACKERS: &[(&str, &str)] = &[
    ("UPX0", "upx"),
    ("UPX1", "upx"),
    (".aspack", "aspack"),
    (".adata", "aspack"),
    ("MPRESS1", "mpress"),
    ("MPRESS2", "mpress"),
    (".petite", "petite"),
    (".themida", "themida"),
    (".vmp0", "vmprotect"),
    (".vmp1", "vmprotect"),
    (".enigma1", "enigma"),
    ("PEC2", "pecompact"),
    ("pebundle", "pebundle"),
    (".nsp0", "nspack"),
];

struct RawSection {
    va: u32,
    vsize: u32,
    raw: u32,
    rsize: u32,
}

fn rva_to_offset(secs: &[RawSection], rva: u32) -> Option<usize> {
    let s = secs.iter().find(|s| rva >= s.va && rva < s.va.saturating_add(s.vsize.max(s.rsize)))?;
    usize::try_from(rva - s.va).ok()?.checked_add(s.raw as usize)
}

pub fn pe(d: &[u8]) -> Option<Pe> {
    let off = u32le(d, 0x3c)? as usize;
    if d.get(off..off.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    let coff = off + 4;
    let mut p = Pe { machine: u16le(d, coff)?, timestamp: u32le(d, coff + 4)?, ..Default::default() };
    let nsec = u16le(d, coff + 2)? as usize;
    let opt_size = u16le(d, coff + 16)? as usize;
    p.is_dll = u16le(d, coff + 18)? & 0x2000 != 0;
    let opt = coff + 20;
    p.is_64 = u16le(d, opt)? == 0x20b;
    let dirs = opt + if p.is_64 { 112 } else { 96 };
    let ndirs = u32le(d, dirs - 4).unwrap_or(0).min(16) as usize;
    let dir = |i: usize| -> Option<(u32, u32)> { if i < ndirs { Some((u32le(d, dirs + i * 8)?, u32le(d, dirs + i * 8 + 4)?)) } else { None } };
    let mut raws = Vec::new();
    let mut end_of_sections = 0u64;
    let table = opt.checked_add(opt_size)?;
    for i in 0..nsec.min(96) {
        let h = table.saturating_add(i * 40);
        let Some(hdr) = d.get(h..h.saturating_add(40)) else { break };
        let name = cstr(hdr, 0, 8).unwrap_or_default();
        let (vsize, va, rsize, raw) = (u32le(hdr, 8)?, u32le(hdr, 12)?, u32le(hdr, 16)?, u32le(hdr, 20)?);
        let flags = u32le(hdr, 36)?;
        let body = d.get(raw as usize..(raw as usize).saturating_add(rsize as usize).min(d.len())).unwrap_or_default();
        if rsize > 0 {
            end_of_sections = end_of_sections.max(u64::from(raw).saturating_add(u64::from(rsize)));
        }
        if p.packer.is_none() {
            p.packer = PACKERS.iter().find(|(n, _)| name.eq_ignore_ascii_case(n)).map(|(_, k)| *k);
        }
        p.sections.push(Section { name, size: u64::from(rsize), entropy: entropy(body), executable: flags & 0x2000_0000 != 0, writable: flags & 0x8000_0000 != 0 });
        raws.push(RawSection { va, vsize, raw, rsize });
    }
    // The security directory's "RVA" is a file offset, and it lives after the sections: it
    // isn't overlay.
    let mut cert_end = 0u64;
    if let Some((at, size)) = dir(4)
        && at != 0
        && size >= 8
    {
        p.signed = true;
        cert_end = u64::from(at).saturating_add(u64::from(size));
    }
    p.dotnet = dir(14).is_some_and(|(a, s)| a != 0 && s != 0);
    let tail = end_of_sections.max(cert_end);
    if end_of_sections > 0 {
        p.overlay = (d.len() as u64).saturating_sub(tail);
    }
    if let Some((rva, _)) = dir(1).filter(|(r, _)| *r != 0) {
        imports(d, &raws, rva, p.is_64, &mut p.imports);
    }
    if !p.imports.is_empty() {
        let mut parts = Vec::new();
        for (dll, funcs) in &p.imports {
            let lib = dll.to_ascii_lowercase();
            let lib = ["ocx", "sys", "dll"].iter().find_map(|ext| lib.strip_suffix(&format!(".{ext}"))).unwrap_or(&lib).to_string();
            for f in funcs {
                parts.push(format!("{lib}.{}", f.to_ascii_lowercase()));
            }
        }
        p.imphash = Some(hex::encode(Md5::digest(parts.join(",").as_bytes())));
    }
    Some(p)
}

fn imports(d: &[u8], secs: &[RawSection], rva: u32, is_64: bool, out: &mut Vec<(String, Vec<String>)>) {
    let Some(mut at) = rva_to_offset(secs, rva) else { return };
    let mut total = 0usize;
    for _ in 0..4096 {
        let (Some(oft), Some(name), Some(ft)) = (u32le(d, at), u32le(d, at.saturating_add(12)), u32le(d, at.saturating_add(16))) else { return };
        if oft == 0 && name == 0 && ft == 0 {
            return;
        }
        let dll = rva_to_offset(secs, name).and_then(|o| cstr(d, o, 256)).unwrap_or_default();
        let mut funcs = Vec::new();
        let thunks = if oft != 0 { oft } else { ft };
        if let Some(mut t) = rva_to_offset(secs, thunks) {
            let step = if is_64 { 8 } else { 4 };
            while total < 20_000 {
                let v = if is_64 { u64le(d, t) } else { u32le(d, t).map(u64::from) };
                let Some(v) = v.filter(|v| *v != 0) else { break };
                let ordinal = if is_64 { v & (1 << 63) != 0 } else { v & (1 << 31) != 0 };
                if ordinal {
                    funcs.push(format!("ord{}", v & 0xffff));
                } else if let Some(o) = u32::try_from(v & 0x7fff_ffff).ok().and_then(|r| rva_to_offset(secs, r)) {
                    funcs.push(cstr(d, o.saturating_add(2), 256).unwrap_or_default());
                }
                total += 1;
                t = t.saturating_add(step);
            }
        }
        out.push((dll, funcs));
        at = at.saturating_add(20);
    }
}

#[derive(Debug, Clone, Serialize, Default, PartialEq)]
pub struct Elf {
    pub is_64: bool,
    /// ET_EXEC 2, ET_DYN 3 (PIE executables and libraries).
    pub kind: u16,
    pub machine: u16,
    pub interpreter: Option<String>,
    pub sections: Vec<Section>,
    pub upx: bool,
    /// No section headers at all: stripped by a packer or built by hand.
    pub no_sections: bool,
}

pub fn elf(d: &[u8]) -> Option<Elf> {
    if d.get(..4)? != b"\x7fELF" {
        return None;
    }
    let is_64 = *d.get(4)? == 2;
    // Big-endian ELF is rare on the platforms we run on; features only for little-endian.
    if *d.get(5)? != 1 {
        return Some(Elf { is_64, ..Default::default() });
    }
    let word = |at: usize| if is_64 { u64le(d, at) } else { u32le(d, at).map(u64::from) };
    let mut e = Elf { is_64, kind: u16le(d, 16)?, machine: u16le(d, 18)?, ..Default::default() };
    let (phoff, shoff) = if is_64 { (word(32)?, word(40)?) } else { (word(28)?, word(32)?) };
    let base = if is_64 { 52 } else { 40 };
    let (phentsize, phnum, shentsize, shnum, shstrndx) =
        (u16le(d, base + 2)? as usize, u16le(d, base + 4)? as usize, u16le(d, base + 6)? as usize, u16le(d, base + 8)? as usize, u16le(d, base + 10)? as usize);
    for i in 0..phnum.min(256) {
        let Some(h) = usize::try_from(phoff).ok().and_then(|o| o.checked_add(i.checked_mul(phentsize)?)) else { break };
        if u32le(d, h) == Some(3) {
            let (off, size) = if is_64 { (u64le(d, h.saturating_add(8)), u64le(d, h.saturating_add(32))) } else { (u32le(d, h.saturating_add(4)).map(u64::from), u32le(d, h.saturating_add(16)).map(u64::from)) };
            if let (Some(off), Some(size)) = (off, size) {
                e.interpreter = usize::try_from(off).ok().and_then(|o| cstr(d, o, (size as usize).min(256)));
            }
        }
    }
    let sh = |i: usize| -> Option<(u32, u64, u64, u64)> {
        let h = usize::try_from(shoff).ok()?.checked_add(i.checked_mul(shentsize)?)?;
        if is_64 { Some((u32le(d, h)?, u64le(d, h.saturating_add(8))?, u64le(d, h.saturating_add(24))?, u64le(d, h.saturating_add(32))?)) } else { Some((u32le(d, h)?, u64::from(u32le(d, h.saturating_add(8))?), u64::from(u32le(d, h.saturating_add(16))?), u64::from(u32le(d, h.saturating_add(20))?))) }
    };
    e.no_sections = shnum == 0 || shoff == 0;
    let strtab = sh(shstrndx).map(|(_, _, off, size)| (off, size));
    for i in 0..shnum.min(512) {
        let Some((name_off, flags, off, size)) = sh(i) else { break };
        let name = strtab
            .and_then(|(so, ss)| if u64::from(name_off) < ss { usize::try_from(so.saturating_add(u64::from(name_off))).ok() } else { None })
            .and_then(|o| cstr(d, o, 64))
            .unwrap_or_default();
        let body = usize::try_from(off).ok().and_then(|o| d.get(o..o.saturating_add(usize::try_from(size).unwrap_or(0)).min(d.len()))).unwrap_or_default();
        e.sections.push(Section { name, size, entropy: entropy(body), executable: flags & 4 != 0, writable: flags & 1 != 0 });
    }
    let head = d.get(..d.len().min(8192)).unwrap_or_default();
    let tail = d.get(d.len().saturating_sub(4096)..).unwrap_or_default();
    e.upx = crate::filetype::memfind(head, b"UPX!").is_some() || crate::filetype::memfind(tail, b"UPX!").is_some();
    Some(e)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A 32-bit PE with one `.text` section, one import (`kernel32.dll!WinExec`), and
    /// optionally a security directory and an overlay.
    pub fn make_pe(section: &str, body: &[u8], signed: bool, overlay: &[u8]) -> Vec<u8> {
        let mut d = vec![0u8; 0x400];
        d[..2].copy_from_slice(b"MZ");
        d[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        d[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        d[coff..coff + 2].copy_from_slice(&0x14cu16.to_le_bytes());
        d[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        d[coff + 4..coff + 8].copy_from_slice(&0x6000_0000u32.to_le_bytes());
        d[coff + 16..coff + 18].copy_from_slice(&224u16.to_le_bytes());
        d[coff + 18..coff + 20].copy_from_slice(&0x0102u16.to_le_bytes());
        let opt = coff + 20;
        d[opt..opt + 2].copy_from_slice(&0x10bu16.to_le_bytes());
        d[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes());
        let dirs = opt + 96;
        // Imports at RVA 0x1000 + body.len() (inside the section, after the body).
        let mut sec = body.to_vec();
        let imp_rva = 0x1000 + sec.len() as u32;
        let names_rva = imp_rva + 40;
        sec.extend_from_slice(&(names_rva + 16).to_le_bytes()); // OriginalFirstThunk
        sec.extend_from_slice(&[0; 8]);
        sec.extend_from_slice(&names_rva.to_le_bytes()); // Name
        sec.extend_from_slice(&(names_rva + 16).to_le_bytes()); // FirstThunk
        sec.extend_from_slice(&[0; 20]);
        sec.extend_from_slice(b"kernel32.dll\0\0\0\0");
        sec.extend_from_slice(&(names_rva + 24).to_le_bytes());
        sec.extend_from_slice(&[0; 4]);
        sec.extend_from_slice(b"\0\0WinExec\0");
        sec.resize(sec.len().div_ceil(512) * 512, 0);
        d[dirs + 8..dirs + 12].copy_from_slice(&imp_rva.to_le_bytes());
        d[dirs + 12..dirs + 16].copy_from_slice(&40u32.to_le_bytes());
        let table = opt + 224;
        d[table..table + section.len()].copy_from_slice(section.as_bytes());
        d[table + 8..table + 12].copy_from_slice(&(sec.len() as u32).to_le_bytes());
        d[table + 12..table + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        d[table + 16..table + 20].copy_from_slice(&(sec.len() as u32).to_le_bytes());
        d[table + 20..table + 24].copy_from_slice(&0x400u32.to_le_bytes());
        d[table + 36..table + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        d.extend_from_slice(&sec);
        if signed {
            let at = d.len() as u32;
            d[dirs + 32..dirs + 36].copy_from_slice(&at.to_le_bytes());
            d[dirs + 36..dirs + 40].copy_from_slice(&16u32.to_le_bytes());
            d.extend_from_slice(&[0u8; 16]);
        }
        d.extend_from_slice(overlay);
        d
    }

    /// A minimal 64-bit ELF executable with an interpreter and named sections.
    pub fn make_elf(interp: &str, sections: &[(&str, &[u8])], upx: bool) -> Vec<u8> {
        let mut d = vec![0u8; 64];
        d[..4].copy_from_slice(b"\x7fELF");
        d[4] = 2;
        d[5] = 1;
        d[6] = 1;
        d[16..18].copy_from_slice(&2u16.to_le_bytes());
        d[18..20].copy_from_slice(&62u16.to_le_bytes());
        // One program header (PT_INTERP) right after the ELF header.
        let interp_off = 64 + 56;
        d[32..40].copy_from_slice(&64u64.to_le_bytes());
        d[54..56].copy_from_slice(&56u16.to_le_bytes());
        d[56..58].copy_from_slice(&1u16.to_le_bytes());
        let mut ph = vec![0u8; 56];
        ph[..4].copy_from_slice(&3u32.to_le_bytes());
        ph[8..16].copy_from_slice(&(interp_off as u64).to_le_bytes());
        ph[32..40].copy_from_slice(&(interp.len() as u64 + 1).to_le_bytes());
        d.extend_from_slice(&ph);
        d.extend_from_slice(interp.as_bytes());
        d.push(0);
        if upx {
            d.extend_from_slice(b"UPX!");
        }
        let mut strtab = vec![0u8];
        let mut offs = vec![];
        for (n, body) in sections {
            offs.push((strtab.len() as u32, d.len() as u64, body.len() as u64));
            strtab.extend_from_slice(n.as_bytes());
            strtab.push(0);
            d.extend_from_slice(body);
        }
        let shstr_name = strtab.len() as u32;
        strtab.extend_from_slice(b".shstrtab\0");
        let strtab_off = d.len() as u64;
        d.extend_from_slice(&strtab);
        let shoff = d.len() as u64;
        d[40..48].copy_from_slice(&shoff.to_le_bytes());
        d[58..60].copy_from_slice(&64u16.to_le_bytes());
        d[60..62].copy_from_slice(&((sections.len() + 2) as u16).to_le_bytes());
        d[62..64].copy_from_slice(&((sections.len() + 1) as u16).to_le_bytes());
        d.extend_from_slice(&[0u8; 64]);
        for (name, off, size) in offs.iter().copied().chain([(shstr_name, strtab_off, strtab.len() as u64)]) {
            let mut h = vec![0u8; 64];
            h[..4].copy_from_slice(&name.to_le_bytes());
            h[8..16].copy_from_slice(&6u64.to_le_bytes());
            h[24..32].copy_from_slice(&off.to_le_bytes());
            h[32..40].copy_from_slice(&size.to_le_bytes());
            d.extend_from_slice(&h);
        }
        d
    }

    #[test]
    fn pe_features() {
        let random: Vec<u8> = { let mut r = crate::fuzz::Rng::new(3); (0..8192).map(|_| r.next() as u8).collect() };
        let p = pe(&make_pe("UPX1", &random, false, b"payload")).unwrap();
        assert_eq!((p.machine, p.is_64, p.is_dll, p.timestamp, p.signed, p.overlay), (0x14c, false, false, 0x6000_0000, false, 7));
        assert_eq!(p.packer, Some("upx"));
        assert!(p.sections[0].entropy > 7.0 && p.looks_packed(), "{:?}", p.sections);
        assert_eq!(p.imports, [("kernel32.dll".to_string(), vec!["WinExec".to_string()])]);
        assert_eq!(p.imphash.as_deref(), Some(hex::encode(Md5::digest(b"kernel32.winexec")).as_str()));
        let p = pe(&make_pe(".text", &[0x90; 4096], true, b"")).unwrap();
        assert!(p.signed && !p.looks_packed() && p.overlay == 0, "the certificate isn't overlay: {p:?}");
    }

    #[test]
    fn elf_features() {
        let e = elf(&make_elf("/lib64/ld-linux-x86-64.so.2", &[(".text", &[0x90; 100]), (".data", b"x")], true)).unwrap();
        assert_eq!(e.interpreter.as_deref(), Some("/lib64/ld-linux-x86-64.so.2"));
        let names: Vec<&str> = e.sections.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["", ".text", ".data", ".shstrtab"]);
        assert!(e.upx && e.is_64 && e.kind == 2 && !e.no_sections);
    }

    #[test]
    fn hostile_input_never_panics() {
        let a = make_pe(".text", b"\x90\x90", true, b"tail");
        let b = make_elf("/lib/ld.so", &[(".text", b"abc")], false);
        crate::fuzz::mutate(&[&a], 5000, |d| {
            let _ = pe(d);
        });
        crate::fuzz::mutate(&[&b], 5000, |d| {
            let _ = elf(d);
        });
    }
}
