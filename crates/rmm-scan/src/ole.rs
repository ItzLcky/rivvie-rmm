//! OLE2 (Compound File Binary): legacy Office documents, `vbaProject.bin` inside OOXML, MSI.
//! Gives the streams, then the VBA macro source ([MS-OVBA]) and files embedded with the
//! Packager (`\x01Ole10Native`).
//!
//! Sector chains come from the file, so every walk is bounded by the number of sectors (a
//! chain that loops stops), and nothing is allocated beyond the file's own size or the cap.

fn u16le(d: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(d.get(at..at.checked_add(2)?)?.try_into().ok()?))
}

fn u32le(d: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

const END: u32 = 0xffff_fffe;
const FREE: u32 = 0xffff_ffff;

struct Entry {
    name: String,
    kind: u8,
    left: u32,
    right: u32,
    child: u32,
    start: u32,
    size: u64,
}

pub struct Ole<'a> {
    data: &'a [u8],
    shift: u32,
    fat: Vec<u32>,
    minifat: Vec<u32>,
    ministream: Vec<u8>,
    cutoff: u64,
    entries: Vec<Entry>,
}

impl<'a> Ole<'a> {
    fn sector(&self, n: u32) -> Option<&'a [u8]> {
        let size = 1usize << self.shift;
        let off = (n as usize).checked_add(1)?.checked_mul(size)?;
        let end = off.checked_add(size)?;
        // The last sector may be short in a truncated file.
        self.data.get(off..end.min(self.data.len())).filter(|s| !s.is_empty())
    }

    fn sectors(&self) -> usize {
        (self.data.len() >> self.shift).saturating_add(1)
    }

    /// Follows a chain in `fat` from `start`, collecting from `get`, up to `max` bytes.
    fn chain(fat: &[u32], start: u32, limit: usize, max: usize, mut get: impl FnMut(u32) -> Option<Vec<u8>>) -> Vec<u8> {
        let mut out = Vec::new();
        let mut n = start;
        let mut steps = 0usize;
        while n != END && n != FREE && out.len() < max && steps < limit {
            let Some(s) = get(n) else { break };
            out.extend_from_slice(s.get(..s.len().min(max - out.len())).unwrap_or_default());
            n = fat.get(n as usize).copied().unwrap_or(END);
            steps += 1;
        }
        out
    }

    pub fn parse(data: &'a [u8]) -> Option<Ole<'a>> {
        if data.get(..8)? != [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1] {
            return None;
        }
        let shift = u32::from(u16le(data, 0x1e)?);
        if shift != 9 && shift != 12 {
            return None;
        }
        let mut ole = Ole { data, shift, fat: Vec::new(), minifat: Vec::new(), ministream: Vec::new(), cutoff: u64::from(u32le(data, 0x38)?), entries: Vec::new() };
        let total = ole.sectors();
        let per = (1usize << shift) / 4;
        // FAT sectors: 109 in the header, then the DIFAT chain.
        let mut fat_sectors: Vec<u32> = (0..109).filter_map(|i| u32le(data, 0x4c + i * 4)).filter(|s| *s < END).collect();
        let mut difat = u32le(data, 0x44)?;
        let mut steps = 0;
        while difat < END && steps < total {
            let Some(s) = ole.sector(difat) else { break };
            for i in 0..per.saturating_sub(1) {
                if let Some(v) = u32le(s, i * 4).filter(|v| *v < END) {
                    fat_sectors.push(v);
                }
            }
            difat = u32le(s, (per - 1) * 4).unwrap_or(END);
            steps += 1;
        }
        fat_sectors.truncate(total);
        for fs in fat_sectors {
            if let Some(s) = ole.sector(fs) {
                ole.fat.extend((0..s.len() / 4).filter_map(|i| u32le(s, i * 4)));
            }
            if ole.fat.len() > total.saturating_add(per) {
                break;
            }
        }
        let dir = Self::chain(&ole.fat, u32le(data, 0x30)?, total, data.len(), |n| ole.sector(n).map(<[u8]>::to_vec));
        for e in dir.as_chunks::<128>().0.iter().take(100_000) {
            let name_len = (u16le(e, 64).unwrap_or(0) as usize).min(64);
            let name: Vec<u16> = (0..name_len / 2).filter_map(|i| u16le(e, i * 2)).take_while(|c| *c != 0).collect();
            let size = u32le(e, 120).map(u64::from).unwrap_or(0) | if u16le(data, 0x1a) == Some(4) { u64::from(u32le(e, 124).unwrap_or(0)) << 32 } else { 0 };
            ole.entries.push(Entry {
                name: String::from_utf16_lossy(&name),
                kind: e.get(66).copied().unwrap_or(0),
                left: u32le(e, 68).unwrap_or(FREE),
                right: u32le(e, 72).unwrap_or(FREE),
                child: u32le(e, 76).unwrap_or(FREE),
                start: u32le(e, 116).unwrap_or(END),
                size,
            });
        }
        let minifat = Self::chain(&ole.fat, u32le(data, 0x3c)?, total, data.len(), |n| ole.sector(n).map(<[u8]>::to_vec));
        ole.minifat = (0..minifat.len() / 4).filter_map(|i| u32le(&minifat, i * 4)).collect();
        if let Some(root) = ole.entries.first().filter(|r| r.kind == 5) {
            let max = usize::try_from(root.size).unwrap_or(usize::MAX).min(data.len());
            ole.ministream = Self::chain(&ole.fat, root.start, total, max, |n| ole.sector(n).map(<[u8]>::to_vec));
        }
        Some(ole)
    }

    /// Every stream, as (path with `/` between storages, entry index).
    pub fn streams(&self) -> Vec<(String, usize)> {
        let mut out = Vec::new();
        let Some(root) = self.entries.first() else { return out };
        let mut seen = vec![false; self.entries.len()];
        let mut stack: Vec<(u32, String)> = vec![(root.child, String::new())];
        while let Some((i, prefix)) = stack.pop() {
            let Some(e) = self.entries.get(i as usize) else { continue };
            let Some(s) = seen.get_mut(i as usize) else { continue };
            if *s {
                continue;
            }
            *s = true;
            stack.push((e.left, prefix.clone()));
            stack.push((e.right, prefix.clone()));
            let path = if prefix.is_empty() { e.name.clone() } else { format!("{prefix}/{}", e.name) };
            match e.kind {
                1 => stack.push((e.child, path)),
                2 => out.push((path, i as usize)),
                _ => {}
            }
        }
        out
    }

    pub fn read(&self, idx: usize, max: usize) -> Vec<u8> {
        let Some(e) = self.entries.get(idx) else { return Vec::new() };
        let max = usize::try_from(e.size).unwrap_or(usize::MAX).min(max);
        if e.size < self.cutoff {
            let mini = 64usize;
            Self::chain(&self.minifat, e.start, self.ministream.len() / mini + 1, max, |n| {
                let off = (n as usize).checked_mul(mini)?;
                self.ministream.get(off..off.checked_add(mini)?.min(self.ministream.len())).filter(|s| !s.is_empty()).map(<[u8]>::to_vec)
            })
        } else {
            Self::chain(&self.fat, e.start, self.sectors(), max, |n| self.sector(n).map(<[u8]>::to_vec))
        }
    }

}

/// [MS-OVBA] 2.4.1 decompression, up to `max` bytes out.
pub fn ovba_decompress(d: &[u8], max: usize) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    if d.first() != Some(&1) {
        return out;
    }
    let mut i = 1usize;
    while i + 2 <= d.len() && out.len() < max {
        let Some(header) = u16le(d, i) else { break };
        i += 2;
        let size = (header & 0x0fff) as usize + 3;
        let chunk_end = (i - 2 + size).min(d.len());
        let start = out.len();
        if header & 0x8000 == 0 {
            // Uncompressed chunk: 4096 raw bytes.
            let end = (i + 4096).min(d.len());
            out.extend_from_slice(d.get(i..end).unwrap_or_default());
            i = end;
            continue;
        }
        while i < chunk_end && out.len() < max {
            let flags = d.get(i).copied().unwrap_or(0);
            i += 1;
            for bit in 0..8 {
                // A decompressed chunk is at most 4096 bytes; anything longer is corrupt.
                if i >= chunk_end || out.len() >= max || out.len() - start >= 4096 {
                    break;
                }
                if flags & (1 << bit) == 0 {
                    out.push(d.get(i).copied().unwrap_or(0));
                    i += 1;
                } else {
                    let Some(token) = u16le(d, i) else { break };
                    i += 2;
                    let diff = out.len() - start;
                    let bits = (usize::BITS - diff.saturating_sub(1).leading_zeros()).max(4);
                    let len_mask = 0xffffu16 >> bits;
                    let len = (token & len_mask) as usize + 3;
                    let off = ((token & !len_mask) >> (16 - bits)) as usize + 1;
                    if off > diff {
                        return out;
                    }
                    for _ in 0..len.min(max - out.len()) {
                        let b = out.get(out.len() - off).copied().unwrap_or(0);
                        out.push(b);
                    }
                }
            }
        }
        i = chunk_end.max(i);
    }
    out
}

/// One VBA module's source.
pub struct Module {
    pub name: String,
    pub source: Vec<u8>,
}

/// The macro source of every module, from the `VBA/dir` stream(s) of the file.
pub fn vba_modules(ole: &Ole, max: usize) -> Vec<Module> {
    let mut out = Vec::new();
    let streams = ole.streams();
    for (path, idx) in &streams {
        let Some(storage) = path.strip_suffix("/dir").filter(|s| s.rsplit('/').next().is_some_and(|l| l.eq_ignore_ascii_case("vba"))) else { continue };
        let dir = ovba_decompress(&ole.read(*idx, 4 * 1024 * 1024), 4 * 1024 * 1024);
        let mut i = 0usize;
        let mut stream: Option<String> = None;
        let mut offset = 0u32;
        let mut modules = Vec::new();
        while let (Some(id), Some(size)) = (u16le(&dir, i), u32le(&dir, i + 2)) {
            // PROJECTVERSION's size field says 4 but 6 bytes follow.
            let len = if id == 0x0009 { 6 } else { size as usize };
            let body = dir.get(i + 6..(i + 6).saturating_add(len).min(dir.len())).unwrap_or_default();
            match id {
                0x001a => stream = Some(String::from_utf8_lossy(body).into_owned()),
                0x0031 => offset = u32le(body, 0).unwrap_or(0),
                0x002b => {
                    if let Some(s) = stream.take() {
                        modules.push((s, offset));
                    }
                    offset = 0;
                }
                _ => {}
            }
            match (i + 6).checked_add(len) {
                Some(n) if n > i => i = n,
                _ => break,
            }
            if modules.len() > 1000 {
                break;
            }
        }
        for (name, off) in modules {
            let want = format!("{storage}/{name}");
            let Some(si) = streams.iter().find(|(p, _)| p.eq_ignore_ascii_case(&want)).map(|(_, i)| *i) else { continue };
            let raw = ole.read(si, max.saturating_mul(2));
            let source = ovba_decompress(raw.get(off as usize..).unwrap_or_default(), max);
            if !source.is_empty() {
                out.push(Module { name, source });
            }
        }
    }
    out
}

/// A file embedded with the Packager: (original name, content).
pub fn ole10native(d: &[u8], max: usize) -> Option<(String, Vec<u8>)> {
    let mut i = 4 + 2;
    let cstr = |i: &mut usize| -> Option<String> {
        let rest = d.get(*i..)?;
        let n = rest.iter().position(|b| *b == 0)?;
        let s = String::from_utf8_lossy(rest.get(..n)?).into_owned();
        *i += n + 1;
        Some(s)
    };
    let _label = cstr(&mut i)?;
    let name = cstr(&mut i)?;
    i += 8;
    let _tmp = cstr(&mut i)?;
    let size = u32le(d, i)? as usize;
    let body = d.get(i + 4..(i + 4).saturating_add(size.min(max)).min(d.len()))?;
    Some((name, body.to_vec()))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// [MS-OVBA] compression in its simplest valid form: literal tokens only.
    pub fn ovba_compress(src: &[u8]) -> Vec<u8> {
        let mut out = vec![1u8];
        // Literal-only chunks grow by one flag byte in eight; 3500 bytes keep them under the
        // 4098-byte chunk limit.
        for chunk in src.chunks(3500) {
            let mut body = Vec::new();
            for group in chunk.chunks(8) {
                body.push(0u8);
                body.extend_from_slice(group);
            }
            let header = 0xb000u16 | ((body.len() + 2 - 3) as u16 & 0x0fff);
            out.extend_from_slice(&header.to_le_bytes());
            out.extend_from_slice(&body);
        }
        out
    }

    /// A version 3 compound file with the given streams (all under the 4096-byte cutoff, so
    /// in the mini stream) inside `storage` (or at the root when empty).
    pub fn make_ole(storage: &str, streams: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let ss = 512usize;
        // Mini stream: 64-byte mini sectors, chained in order.
        let mut ministream = Vec::new();
        let mut minifat: Vec<u32> = Vec::new();
        let mut starts = Vec::new();
        for (_, data) in streams {
            let first = (ministream.len() / 64) as u32;
            starts.push(first);
            let n = data.len().div_ceil(64).max(1);
            for k in 0..n {
                minifat.push(if k + 1 == n { END } else { first + k as u32 + 1 });
            }
            let mut d = data.clone();
            d.resize(n * 64, 0);
            ministream.extend_from_slice(&d);
        }
        // Directory: root, [storage], streams. Siblings chained through `right`.
        let mut entries: Vec<(String, u8, u32, u32, u32, u64)> = vec![("Root Entry".into(), 5, FREE, FREE, 1, 0)];
        let first_stream = if storage.is_empty() { 1 } else { 2 };
        if !storage.is_empty() {
            entries.push((storage.into(), 1, FREE, FREE, 2, 0));
        }
        for (k, (name, data)) in streams.iter().enumerate() {
            let right = if k + 1 < streams.len() { (first_stream + k + 1) as u32 } else { FREE };
            entries.push((name.to_string(), 2, FREE, right, FREE, data.len() as u64));
        }
        let sec = |b: &[u8]| -> Vec<Vec<u8>> {
            b.chunks(ss).map(|c| {
                let mut v = c.to_vec();
                v.resize(ss, 0);
                v
            }).collect()
        };
        let mut dir = Vec::new();
        let mini_sectors = sec(&ministream);
        let minifat_bytes: Vec<u8> = minifat.iter().flat_map(|v| v.to_le_bytes()).collect();
        let minifat_sectors = sec(&minifat_bytes);
        for (i, (name, kind, left, right, child, size)) in entries.iter().enumerate() {
            let mut e = vec![0u8; 128];
            let utf16: Vec<u8> = name.encode_utf16().chain([0]).flat_map(|c| c.to_le_bytes()).collect();
            e[..utf16.len()].copy_from_slice(&utf16);
            e[64..66].copy_from_slice(&(utf16.len() as u16).to_le_bytes());
            e[66] = *kind;
            e[68..72].copy_from_slice(&left.to_le_bytes());
            e[72..76].copy_from_slice(&right.to_le_bytes());
            e[76..80].copy_from_slice(&child.to_le_bytes());
            // The mini stream is the first chain after the FAT sector.
            let (start, size) = if i == 0 { (1u32, ministream.len() as u64) } else if *kind == 2 { (starts[i - first_stream], *size) } else { (0, 0) };
            e[116..120].copy_from_slice(&start.to_le_bytes());
            e[120..124].copy_from_slice(&(size as u32).to_le_bytes());
            dir.extend_from_slice(&e);
        }
        let dir_sectors = sec(&dir);
        // Layout: sector 0 = FAT, then mini stream, mini FAT, directory.
        let mut fat: Vec<u32> = vec![0xffff_fffd];
        let chain = |n: usize, fat: &mut Vec<u32>| -> u32 {
            let first = fat.len() as u32;
            for k in 0..n {
                fat.push(if k + 1 == n { END } else { first + k as u32 + 1 });
            }
            first
        };
        let mini_start = chain(mini_sectors.len(), &mut fat);
        let minifat_start = chain(minifat_sectors.len(), &mut fat);
        let dir_start = chain(dir_sectors.len(), &mut fat);
        fat.resize(128, FREE);
        let mut h = vec![0u8; 512];
        h[..8].copy_from_slice(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
        h[0x1a..0x1c].copy_from_slice(&3u16.to_le_bytes());
        h[0x1c..0x1e].copy_from_slice(&0xfffeu16.to_le_bytes());
        h[0x1e..0x20].copy_from_slice(&9u16.to_le_bytes());
        h[0x20..0x22].copy_from_slice(&6u16.to_le_bytes());
        h[0x2c..0x30].copy_from_slice(&1u32.to_le_bytes());
        h[0x30..0x34].copy_from_slice(&dir_start.to_le_bytes());
        h[0x38..0x3c].copy_from_slice(&4096u32.to_le_bytes());
        h[0x3c..0x40].copy_from_slice(&minifat_start.to_le_bytes());
        h[0x40..0x44].copy_from_slice(&(minifat_sectors.len() as u32).to_le_bytes());
        h[0x44..0x48].copy_from_slice(&END.to_le_bytes());
        for i in 0..109 {
            h[0x4c + i * 4..0x50 + i * 4].copy_from_slice(&(if i == 0 { 0 } else { FREE }).to_le_bytes());
        }
        let mut out = h;
        out.extend(fat.iter().flat_map(|v| v.to_le_bytes()));
        let _ = mini_start;
        for s in mini_sectors.iter().chain(&minifat_sectors).chain(&dir_sectors) {
            out.extend_from_slice(s);
        }
        out
    }

    /// A `vbaProject.bin` with one module holding `source`.
    pub fn make_vba_project(module: &str, source: &str) -> Vec<u8> {
        let rec = |id: u16, body: &[u8]| -> Vec<u8> {
            let mut r = id.to_le_bytes().to_vec();
            r.extend_from_slice(&(body.len() as u32).to_le_bytes());
            r.extend_from_slice(body);
            r
        };
        let mut dir = Vec::new();
        dir.extend(rec(0x0001, &1u32.to_le_bytes()));
        dir.extend(0x0009u16.to_le_bytes());
        dir.extend(4u32.to_le_bytes());
        dir.extend([0u8; 6]);
        dir.extend(rec(0x0019, module.as_bytes()));
        dir.extend(rec(0x001a, module.as_bytes()));
        dir.extend(rec(0x0032, &module.encode_utf16().flat_map(|c| c.to_le_bytes()).collect::<Vec<_>>()));
        dir.extend(rec(0x0031, &0u32.to_le_bytes()));
        dir.extend(rec(0x002b, &[]));
        dir.extend(rec(0x0010, &[]));
        make_ole("VBA", &[("dir", ovba_compress(&dir)), (module, ovba_compress(source.as_bytes()))])
    }

    #[test]
    fn decompression() {
        let src = b"Attribute VB_Name = \"Module1\"\r\nSub AutoOpen()\r\nEnd Sub\r\n".repeat(200);
        assert_eq!(ovba_decompress(&ovba_compress(&src), usize::MAX), src);
        // "abcabcabc": three literals, then a copy token of length 6 at offset 3.
        let mut c = vec![1u8];
        let body = [0b0000_1000u8, b'a', b'b', b'c', 0, 0];
        let token: u16 = ((3 - 1) << 12) | (6 - 3);
        let mut body = body.to_vec();
        body.truncate(4);
        body.extend_from_slice(&token.to_le_bytes());
        c.extend_from_slice(&(0xb000u16 | (body.len() as u16 + 2 - 3)).to_le_bytes());
        c.extend_from_slice(&body);
        assert_eq!(ovba_decompress(&c, 100), b"abcabcabc");
    }

    #[test]
    fn macros_come_out() {
        let bin = make_vba_project("Module1", "Sub AutoOpen()\r\n  Shell \"calc\"\r\nEnd Sub\r\n");
        let ole = Ole::parse(&bin).unwrap();
        let names: Vec<String> = ole.streams().into_iter().map(|s| s.0).collect();
        assert_eq!(names, ["VBA/dir", "VBA/Module1"]);
        let m = vba_modules(&ole, 1 << 20);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].name, "Module1");
        assert!(String::from_utf8_lossy(&m[0].source).contains("Shell \"calc\""));
    }

    #[test]
    fn packager_objects() {
        let mut d = vec![0u8; 6];
        d.extend_from_slice(b"label\0C:\\x\\run.bat\0");
        d.extend_from_slice(&[0u8; 8]);
        d.extend_from_slice(b"C:\\tmp\\run.bat\0");
        d.extend_from_slice(&9u32.to_le_bytes());
        d.extend_from_slice(b"echo evil");
        assert_eq!(ole10native(&d, 100), Some(("C:\\x\\run.bat".into(), b"echo evil".to_vec())));
    }

    #[test]
    fn hostile_input_never_panics() {
        let bin = make_vba_project("Module1", "Sub AutoOpen()\r\nEnd Sub\r\n");
        let comp = ovba_compress(b"Sub X()\r\nMsgBox 1\r\nEnd Sub\r\n");
        crate::fuzz::mutate(&[&bin], 3000, |d| {
            if let Some(o) = Ole::parse(d) {
                let _ = vba_modules(&o, 1 << 16);
                for (_, i) in o.streams() {
                    let _ = o.read(i, 1 << 16);
                }
            }
        });
        crate::fuzz::mutate(&[&comp], 3000, |d| {
            let _ = ovba_decompress(d, 1 << 16);
            let _ = ole10native(d, 1 << 16);
        });
    }
}
