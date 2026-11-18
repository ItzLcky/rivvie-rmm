//! Containers: zip (and everything built on it: jar, apk, OOXML), gzip, bzip2, xz and tar.
//! Each member comes out as bytes to scan like a file of its own.
//!
//! A [`Budget`] shared by the whole scan bounds the work: nesting depth, member count, total
//! bytes unpacked, and the compression ratio of any one member. Running out stops unpacking
//! and is recorded (the engine turns it into a low-severity `archive bomb` finding); it is
//! never a hang or an out-of-memory. 7z and cab aren't unpacked (no small pure-Rust reader);
//! they're still hashed and matched as files.

use std::io::{self, Read, Write};

use crate::Limits;

/// Why unpacking stopped early.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exceeded {
    Depth,
    Entries,
    Total,
    Ratio,
}

impl Exceeded {
    pub fn describe(self) -> &'static str {
        match self {
            Exceeded::Depth => "nested deeper than the archive depth limit",
            Exceeded::Entries => "more members than the archive entry limit",
            Exceeded::Total => "unpacks to more than the total size limit",
            Exceeded::Ratio => "a member's compression ratio is over the limit",
        }
    }
}

#[derive(Debug)]
pub struct Budget {
    pub limits: Limits,
    entries: u32,
    unpacked: u64,
    pub exceeded: Option<Exceeded>,
    /// Some member was larger than the content cap and was only partly checked.
    pub truncated: bool,
}

impl Budget {
    pub fn new(limits: Limits) -> Self {
        Budget { limits, entries: 0, unpacked: 0, exceeded: None, truncated: false }
    }

    pub fn stop(&mut self, why: Exceeded) {
        self.exceeded.get_or_insert(why);
    }

    pub fn stopped(&self) -> bool {
        self.exceeded.is_some()
    }

    /// One more member. False (and stopped) past the limit.
    pub fn entry(&mut self) -> bool {
        if self.stopped() {
            return false;
        }
        self.entries = self.entries.saturating_add(1);
        if self.entries > self.limits.max_entries {
            self.stop(Exceeded::Entries);
            return false;
        }
        true
    }

    /// Bytes left to unpack in this scan, at most one content cap per member.
    fn room(&self) -> u64 {
        self.limits.max_unpacked.saturating_sub(self.unpacked).min(self.limits.content_cap)
    }
}

/// Collects at most `max` bytes, then reports `Full` instead of growing.
struct Capped {
    buf: Vec<u8>,
    max: usize,
    full: bool,
}

impl Write for Capped {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let room = self.max.saturating_sub(self.buf.len());
        if data.len() > room {
            self.buf.extend_from_slice(data.get(..room).unwrap_or_default());
            self.full = true;
            return Err(io::Error::other("member larger than the cap"));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Reads a decompressor's output within the budget. `packed` is the member's compressed size
/// (for the ratio check). Returns what was read; a corrupt stream gives what came before the
/// error.
fn unpack(budget: &mut Budget, packed: u64, mut r: impl Read) -> Vec<u8> {
    let room = budget.room();
    let mut out = Capped { buf: Vec::new(), max: usize::try_from(room).unwrap_or(usize::MAX), full: false };
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        match r.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if out.write_all(chunk.get(..n).unwrap_or_default()).is_err() {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    finish(budget, packed, out)
}

fn finish(budget: &mut Budget, packed: u64, out: Capped) -> Vec<u8> {
    let n = out.buf.len() as u64;
    budget.unpacked = budget.unpacked.saturating_add(n);
    if out.full {
        if budget.unpacked >= budget.limits.max_unpacked {
            budget.stop(Exceeded::Total);
        } else {
            budget.truncated = true;
        }
    }
    // A big member from a tiny one: the classic bomb. Small members compress as they like.
    if n > 1024 * 1024 && n / packed.max(1) > u64::from(budget.limits.max_ratio) {
        budget.stop(Exceeded::Ratio);
    }
    out.buf
}

fn u16le(d: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(d.get(at..at.checked_add(2)?)?.try_into().ok()?))
}

fn u32le(d: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

fn u64le(d: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(d.get(at..at.checked_add(8)?)?.try_into().ok()?))
}

/// One member, unpacked (possibly cut short at the cap).
pub struct Member {
    pub name: String,
    pub data: Vec<u8>,
}

// --- zip ---------------------------------------------------------------------------------------

struct ZipEntry {
    name: String,
    method: u16,
    flags: u16,
    packed: u64,
    local: u64,
}

/// Zip64 sizes and offset from the extra field, for the fields that were 0xffffffff.
fn zip64_extra(extra: &[u8], e: &mut ZipEntry, need_size: bool, need_packed: bool, need_local: bool) {
    let mut i = 0usize;
    while let (Some(id), Some(len)) = (u16le(extra, i), u16le(extra, i.saturating_add(2))) {
        let body = i.saturating_add(4);
        let Some(field) = extra.get(body..body.saturating_add(len as usize)) else { return };
        if id == 1 {
            let mut at = 0;
            if need_size {
                at += 8;
            }
            if need_packed {
                e.packed = u64le(field, at).unwrap_or(e.packed);
                at += 8;
            }
            if need_local {
                e.local = u64le(field, at).unwrap_or(e.local);
            }
            return;
        }
        i = body.saturating_add(len as usize);
    }
}

fn central_directory(d: &[u8]) -> Option<Vec<ZipEntry>> {
    // The end record is in the last 64 KB + 22 bytes (its comment is at most 64 KB).
    let from = d.len().saturating_sub(65_557);
    let tail = d.get(from..)?;
    let eocd = from + tail.windows(4).rposition(|w| w == b"PK\x05\x06")?;
    let mut count = u64::from(u16le(d, eocd + 10)?);
    let mut cd_size = u64::from(u32le(d, eocd + 12)?);
    let mut cd_off = u64::from(u32le(d, eocd + 16)?);
    if (count == 0xffff || cd_off == 0xffff_ffff) && eocd >= 20 && d.get(eocd - 20..eocd - 16) == Some(b"PK\x06\x07") {
        let rec = usize::try_from(u64le(d, eocd - 12)?).ok()?;
        if d.get(rec..rec.checked_add(4)?) == Some(b"PK\x06\x06") {
            count = u64le(d, rec.checked_add(32)?)?;
            cd_size = u64le(d, rec.checked_add(40)?)?;
            cd_off = u64le(d, rec.checked_add(48)?)?;
        }
    }
    let start = usize::try_from(cd_off).ok()?;
    let cd = d.get(start..start.checked_add(usize::try_from(cd_size).ok()?)?)?;
    let mut out = Vec::new();
    let mut i = 0usize;
    // Every entry is at least 46 bytes, which bounds the loop by the directory's size.
    while (out.len() as u64) < count && cd.get(i..i + 4) == Some(b"PK\x01\x02") {
        let name_len = u16le(cd, i + 28)? as usize;
        let extra_len = u16le(cd, i + 30)? as usize;
        let comment_len = u16le(cd, i + 32)? as usize;
        let name = cd.get(i + 46..i + 46 + name_len)?;
        let extra = cd.get(i + 46 + name_len..i + 46 + name_len + extra_len).unwrap_or_default();
        let mut e = ZipEntry {
            name: String::from_utf8_lossy(name).into_owned(),
            flags: u16le(cd, i + 8)?,
            method: u16le(cd, i + 10)?,
            packed: u64::from(u32le(cd, i + 20)?),
            local: u64::from(u32le(cd, i + 42)?),
        };
        let (s, p, l) = (u32le(cd, i + 24)? == 0xffff_ffff, e.packed == 0xffff_ffff, e.local == 0xffff_ffff);
        if s || p || l {
            zip64_extra(extra, &mut e, s, p, l);
        }
        out.push(e);
        i = i.checked_add(46 + name_len + extra_len + comment_len)?;
    }
    Some(out)
}

/// No central directory (a cut-off download): walk the local headers from the start.
fn local_headers(d: &[u8]) -> Vec<ZipEntry> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while d.get(i..i + 4) == Some(b"PK\x03\x04") {
        let (Some(flags), Some(method), Some(packed), Some(nl), Some(el)) =
            (u16le(d, i + 6), u16le(d, i + 8), u32le(d, i + 18), u16le(d, i + 26), u16le(d, i + 28))
        else {
            break;
        };
        let name = d.get(i + 30..i + 30 + nl as usize).map(|n| String::from_utf8_lossy(n).into_owned()).unwrap_or_default();
        out.push(ZipEntry { name, method, flags, packed: u64::from(packed), local: i as u64 });
        // With a data descriptor the sizes aren't known here; stop rather than guess.
        if flags & 8 != 0 {
            break;
        }
        let next = (i as u64).saturating_add(30 + u64::from(nl) + u64::from(el)).saturating_add(u64::from(packed));
        match usize::try_from(next) {
            Ok(n) if n > i => i = n,
            _ => break,
        }
    }
    out
}

pub fn zip(d: &[u8], budget: &mut Budget, mut each: impl FnMut(Member, &mut Budget)) {
    let entries = central_directory(d).unwrap_or_else(|| local_headers(d));
    for e in entries {
        if e.name.ends_with('/') {
            continue;
        }
        if !budget.entry() {
            return;
        }
        // Encrypted members can't be read; the file is still matched as a whole.
        if e.flags & 1 != 0 {
            continue;
        }
        let Ok(local) = usize::try_from(e.local) else { continue };
        if d.get(local..local.saturating_add(4)) != Some(b"PK\x03\x04") {
            continue;
        }
        let (Some(nl), Some(el)) = (u16le(d, local.saturating_add(26)), u16le(d, local.saturating_add(28))) else { continue };
        let start = local.saturating_add(30 + nl as usize + el as usize);
        let end = usize::try_from(e.packed).ok().and_then(|p| start.checked_add(p)).map_or(d.len(), |end| end.min(d.len()));
        let Some(raw) = d.get(start..end) else { continue };
        let data = match e.method {
            0 => {
                let n = raw.len().min(usize::try_from(budget.room()).unwrap_or(usize::MAX));
                let mut out = Capped { buf: Vec::new(), max: n, full: raw.len() > n };
                out.buf.extend_from_slice(raw.get(..n).unwrap_or_default());
                finish(budget, raw.len() as u64, out)
            }
            8 => unpack(budget, raw.len() as u64, flate2::read::DeflateDecoder::new(raw)),
            _ => continue,
        };
        each(Member { name: e.name, data }, budget);
        if budget.stopped() {
            return;
        }
    }
}

// --- single-stream compressors -----------------------------------------------------------------

pub fn gzip(d: &[u8], budget: &mut Budget) -> Option<Member> {
    if !budget.entry() {
        return None;
    }
    let mut dec = flate2::read::MultiGzDecoder::new(d);
    let name = dec.header().and_then(|h| h.filename()).map(|n| String::from_utf8_lossy(n).into_owned());
    let data = unpack(budget, d.len() as u64, &mut dec);
    let name = name.or_else(|| dec.header().and_then(|h| h.filename()).map(|n| String::from_utf8_lossy(n).into_owned()));
    Some(Member { name: name.unwrap_or_else(|| "gzip".into()), data })
}

pub fn bzip2(d: &[u8], budget: &mut Budget) -> Option<Member> {
    if !budget.entry() {
        return None;
    }
    Some(Member { name: "bzip2".into(), data: unpack(budget, d.len() as u64, bzip2::read::MultiBzDecoder::new(d)) })
}

pub fn xz(d: &[u8], budget: &mut Budget) -> Option<Member> {
    if !budget.entry() {
        return None;
    }
    let room = budget.room();
    let mut out = Capped { buf: Vec::new(), max: usize::try_from(room).unwrap_or(usize::MAX), full: false };
    let mut input = io::BufReader::new(d);
    // lzma-rs grows its dictionary only as output is written, so the cap bounds its memory too.
    let _ = lzma_rs::xz_decompress(&mut input, &mut out);
    Some(Member { name: "xz".into(), data: finish(budget, d.len() as u64, out) })
}

/// A zlib stream (PDF's FlateDecode) within the budget. `None` when nothing decodes.
pub fn zlib(d: &[u8], budget: &mut Budget) -> Option<Vec<u8>> {
    let out = unpack(budget, d.len() as u64, flate2::read::ZlibDecoder::new(d));
    (!out.is_empty()).then_some(out)
}

// --- tar ---------------------------------------------------------------------------------------

fn octal(field: &[u8]) -> Option<u64> {
    // GNU base-256 for sizes over 8 GB.
    if field.first().is_some_and(|b| b & 0x80 != 0) {
        return field.get(1..)?.iter().try_fold(0u64, |acc, b| acc.checked_mul(256)?.checked_add(u64::from(*b)));
    }
    let s: String = field.iter().take_while(|b| **b != 0).map(|b| *b as char).collect();
    let s = s.trim();
    if s.is_empty() { Some(0) } else { u64::from_str_radix(s, 8).ok() }
}

pub fn tar(d: &[u8], budget: &mut Budget, mut each: impl FnMut(Member, &mut Budget)) {
    let mut i = 0usize;
    let mut long_name: Option<String> = None;
    while let Some(h) = d.get(i..i.saturating_add(512)) {
        if h.iter().all(|b| *b == 0) {
            break;
        }
        let Some(size) = h.get(124..136).and_then(octal) else { break };
        let kind = h.get(156).copied().unwrap_or(0);
        let start = i + 512;
        let padded = size.checked_add(511).map(|s| s / 512 * 512);
        let Some(next) = padded.and_then(|p| usize::try_from(p).ok()).and_then(|p| start.checked_add(p)) else { break };
        let body = d.get(start..start.saturating_add(usize::try_from(size).unwrap_or(usize::MAX)).min(d.len())).unwrap_or_default();
        let mut name = || {
            long_name.take().unwrap_or_else(|| {
                let field = |a: usize, b: usize| h.get(a..b).map(|f| String::from_utf8_lossy(f.split(|c| *c == 0).next().unwrap_or_default()).into_owned()).unwrap_or_default();
                let (prefix, base) = (field(345, 500), field(0, 100));
                if prefix.is_empty() || super::filetype::memfind(h.get(257..263).unwrap_or_default(), b"ustar").is_none() {
                    base
                } else {
                    format!("{prefix}/{base}")
                }
            })
        };
        match kind {
            b'L' => long_name = Some(String::from_utf8_lossy(body.split(|c| *c == 0).next().unwrap_or_default()).into_owned()),
            b'0' | 0 | b'7' => {
                let name = name();
                if !budget.entry() {
                    return;
                }
                let n = body.len().min(usize::try_from(budget.room()).unwrap_or(usize::MAX));
                let out = Capped { buf: body.get(..n).unwrap_or_default().to_vec(), max: n, full: body.len() > n };
                let data = finish(budget, body.len() as u64, out);
                each(Member { name, data }, budget);
                if budget.stopped() {
                    return;
                }
            }
            _ => {}
        }
        if next <= i {
            break;
        }
        i = next;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A zip with the given members, stored (0) or deflated (8).
    pub fn make_zip(members: &[(&str, &[u8], u16)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut cd = Vec::new();
        for (name, data, method) in members {
            let packed = if *method == 8 {
                let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
                e.write_all(data).unwrap();
                e.finish().unwrap()
            } else {
                data.to_vec()
            };
            let off = out.len() as u32;
            let crc = 0u32;
            out.extend_from_slice(b"PK\x03\x04");
            out.extend_from_slice(&[20, 0, 0, 0]);
            out.extend_from_slice(&method.to_le_bytes());
            out.extend_from_slice(&[0, 0, 0, 0]);
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&(packed.len() as u32).to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&[0, 0]);
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&packed);
            cd.extend_from_slice(b"PK\x01\x02");
            cd.extend_from_slice(&[20, 0, 20, 0, 0, 0]);
            cd.extend_from_slice(&method.to_le_bytes());
            cd.extend_from_slice(&[0, 0, 0, 0]);
            cd.extend_from_slice(&crc.to_le_bytes());
            cd.extend_from_slice(&(packed.len() as u32).to_le_bytes());
            cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
            cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
            cd.extend_from_slice(&[0; 12]);
            cd.extend_from_slice(&off.to_le_bytes());
            cd.extend_from_slice(name.as_bytes());
        }
        let cd_off = out.len() as u32;
        out.extend_from_slice(&cd);
        out.extend_from_slice(b"PK\x05\x06\0\0\0\0");
        out.extend_from_slice(&(members.len() as u16).to_le_bytes());
        out.extend_from_slice(&(members.len() as u16).to_le_bytes());
        out.extend_from_slice(&(cd.len() as u32).to_le_bytes());
        out.extend_from_slice(&cd_off.to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out
    }

    pub fn make_tar(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, data) in members {
            let mut h = [0u8; 512];
            h[..name.len()].copy_from_slice(name.as_bytes());
            h[100..107].copy_from_slice(b"0000644");
            h[124..135].copy_from_slice(format!("{:011o}", data.len()).as_bytes());
            h[156] = b'0';
            h[257..262].copy_from_slice(b"ustar");
            h[148..156].copy_from_slice(b"        ");
            let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
            h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
            out.extend_from_slice(&h);
            out.extend_from_slice(data);
            out.resize(out.len().div_ceil(512) * 512, 0);
        }
        out.extend_from_slice(&[0u8; 1024]);
        out
    }

    fn names_of(f: impl FnOnce(&mut Budget, &mut dyn FnMut(Member, &mut Budget)), limits: Limits) -> (Vec<(String, Vec<u8>)>, Budget) {
        let mut b = Budget::new(limits);
        let mut got = vec![];
        f(&mut b, &mut |m, _| got.push((m.name, m.data)));
        (got, b)
    }

    #[test]
    fn zip_and_tar_members() {
        let z = make_zip(&[("a.txt", b"hello", 0), ("dir/", b"", 0), ("b.bin", &[7u8; 5000], 8)]);
        let (got, b) = names_of(|b, f| zip(&z, b, f), Limits::default());
        assert_eq!(got.iter().map(|g| g.0.as_str()).collect::<Vec<_>>(), ["a.txt", "b.bin"]);
        assert_eq!(got[1].1, vec![7u8; 5000]);
        assert!(b.exceeded.is_none());
        // Cut off before the central directory: the local headers still give the members.
        let cut = &z[..z.len() - 40];
        let (got, _) = names_of(|b, f| zip(cut, b, f), Limits::default());
        assert_eq!(got.len(), 2);
        let t = make_tar(&[("x/one.sh", b"#!/bin/sh\n"), ("two", b"2")]);
        let (got, _) = names_of(|b, f| tar(&t, b, f), Limits::default());
        assert_eq!(got, [("x/one.sh".to_string(), b"#!/bin/sh\n".to_vec()), ("two".into(), b"2".to_vec())]);
    }

    #[test]
    fn compressed_streams() {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(b"inside gzip").unwrap();
        let gz = e.finish().unwrap();
        let mut b = Budget::new(Limits::default());
        assert_eq!(gzip(&gz, &mut b).unwrap().data, b"inside gzip");
        let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
        e.write_all(b"inside bzip2").unwrap();
        assert_eq!(bzip2(&e.finish().unwrap(), &mut b).unwrap().data, b"inside bzip2");
        let mut x = Vec::new();
        lzma_rs::xz_compress(&mut &b"inside xz"[..], &mut x).unwrap();
        assert_eq!(xz(&x, &mut b).unwrap().data, b"inside xz");
    }

    #[test]
    fn bombs_are_stopped() {
        // 64 MB of zeros deflates to about 64 KB: over the ratio limit.
        let zeros = vec![0u8; 64 * 1024 * 1024];
        let z = make_zip(&[("zeros", &zeros, 8)]);
        let (_, b) = names_of(|b, f| zip(&z, b, f), Limits::default());
        assert_eq!(b.exceeded, Some(Exceeded::Ratio));
        let many: Vec<(String, Vec<u8>, u16)> = (0..50).map(|i| (format!("f{i}"), vec![b'x'; 10], 0)).collect();
        let refs: Vec<(&str, &[u8], u16)> = many.iter().map(|(n, d, m)| (n.as_str(), d.as_slice(), *m)).collect();
        let z = make_zip(&refs);
        let (got, b) = names_of(|b, f| zip(&z, b, f), Limits { max_entries: 10, ..Limits::default() });
        assert_eq!((got.len(), b.exceeded), (10, Some(Exceeded::Entries)));
        let (_, b) = names_of(|b, f| zip(&z, b, f), Limits { max_unpacked: 100, ..Limits::default() });
        assert_eq!(b.exceeded, Some(Exceeded::Total));
        let big = make_zip(&[("big", &[1u8; 3000], 0)]);
        let (got, b) = names_of(|b, f| zip(&big, b, f), Limits { content_cap: 1000, ..Limits::default() });
        assert_eq!((got[0].1.len(), b.truncated, b.exceeded), (1000, true, None), "a large member is cut at the cap, not a bomb");
    }

    #[test]
    fn hostile_input_never_panics() {
        let z = make_zip(&[("a.txt", b"hello hello hello", 8), ("b", b"bbbb", 0)]);
        let t = make_tar(&[("a", b"data"), ("b", b"more")]);
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(b"gzip body gzip body").unwrap();
        let gz = e.finish().unwrap();
        let mut x = Vec::new();
        lzma_rs::xz_compress(&mut &b"xz body xz body"[..], &mut x).unwrap();
        let mut bz = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
        bz.write_all(b"bz body").unwrap();
        let bz = bz.finish().unwrap();
        let limits = Limits { max_unpacked: 4 * 1024 * 1024, content_cap: 1024 * 1024, ..Limits::default() };
        crate::fuzz::mutate(&[&z, &t], 3000, |d| {
            let mut b = Budget::new(limits);
            zip(d, &mut b, |_, _| {});
            let mut b = Budget::new(limits);
            tar(d, &mut b, |_, _| {});
        });
        crate::fuzz::mutate(&[&gz, &x, &bz], 1500, |d| {
            let mut b = Budget::new(limits);
            let _ = gzip(d, &mut b);
            let _ = xz(d, &mut b);
            let _ = bzip2(d, &mut b);
        });
    }
}
