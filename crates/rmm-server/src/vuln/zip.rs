//! Just enough of the zip format to read OSV's `all.zip` dumps from a file one entry at a time:
//! the central directory (zip64 too: the larger dumps have more than 65535 entries), stored
//! and deflated entries. No encryption, no multi-disk archives.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use anyhow::{Context, Result, bail};

/// One advisory file is a few KB; anything far larger is not what we're looking for.
const MAX_ENTRY: u64 = 64 << 20;

pub struct Entry {
    pub name: String,
    method: u16,
    compressed: u64,
    size: u64,
    local_offset: u64,
}

fn u16le(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn u64le(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

pub struct Archive {
    file: File,
    pub entries: Vec<Entry>,
}

impl Archive {
    pub fn open(path: &Path) -> Result<Archive> {
        let mut file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
        let len = file.metadata()?.len();
        if len < 22 {
            bail!("not a zip file (too short)");
        }
        // The end-of-central-directory record is in the last 64 KiB + 22 bytes (comment).
        let tail_len = len.min(65_557);
        file.seek(SeekFrom::Start(len - tail_len))?;
        let mut tail = vec![0u8; tail_len as usize];
        file.read_exact(&mut tail)?;
        let eocd = (0..=tail.len() - 22).rev().find(|&i| u32le(&tail, i) == 0x0605_4b50).context("not a zip file (no end of central directory)")?;
        let mut count = u16le(&tail, eocd + 10) as u64;
        let mut cd_size = u32le(&tail, eocd + 12) as u64;
        let mut cd_offset = u32le(&tail, eocd + 16) as u64;
        if count == 0xFFFF || cd_offset == 0xFFFF_FFFF || cd_size == 0xFFFF_FFFF {
            // Zip64: a locator just before the EOCD points at the zip64 EOCD record.
            if eocd < 20 || u32le(&tail, eocd - 20) != 0x0706_4b50 {
                bail!("zip64 archive without a locator");
            }
            let at = u64le(&tail, eocd - 20 + 8);
            file.seek(SeekFrom::Start(at))?;
            let mut rec = [0u8; 56];
            file.read_exact(&mut rec)?;
            if u32le(&rec, 0) != 0x0606_4b50 {
                bail!("bad zip64 end of central directory");
            }
            count = u64le(&rec, 32);
            cd_size = u64le(&rec, 40);
            cd_offset = u64le(&rec, 48);
        }
        if cd_offset.saturating_add(cd_size) > len || cd_size > 1 << 30 {
            bail!("central directory out of range");
        }
        file.seek(SeekFrom::Start(cd_offset))?;
        let mut cd = vec![0u8; cd_size as usize];
        file.read_exact(&mut cd)?;
        let mut entries = Vec::with_capacity(count.min(1 << 20) as usize);
        let mut p = 0usize;
        while p + 46 <= cd.len() && u32le(&cd, p) == 0x0201_4b50 {
            let method = u16le(&cd, p + 10);
            let mut compressed = u32le(&cd, p + 20) as u64;
            let mut size = u32le(&cd, p + 24) as u64;
            let name_len = u16le(&cd, p + 28) as usize;
            let extra_len = u16le(&cd, p + 30) as usize;
            let comment_len = u16le(&cd, p + 32) as usize;
            let mut local_offset = u32le(&cd, p + 42) as u64;
            let end = p + 46 + name_len + extra_len + comment_len;
            if end > cd.len() {
                bail!("truncated central directory");
            }
            let name = String::from_utf8_lossy(&cd[p + 46..p + 46 + name_len]).into_owned();
            // Zip64 extra field: the 8-byte values of whichever fields are saturated, in order.
            let mut x = p + 46 + name_len;
            let xend = x + extra_len;
            while x + 4 <= xend {
                let id = u16le(&cd, x);
                let n = u16le(&cd, x + 2) as usize;
                if id == 0x0001 {
                    let mut q = x + 4;
                    let mut take = |v: &mut u64| {
                        if *v == 0xFFFF_FFFF && q + 8 <= x + 4 + n {
                            *v = u64le(&cd, q);
                            q += 8;
                        }
                    };
                    take(&mut size);
                    take(&mut compressed);
                    take(&mut local_offset);
                }
                x += 4 + n;
            }
            entries.push(Entry { name, method, compressed, size, local_offset });
            p = end;
        }
        Ok(Archive { file, entries })
    }

    /// The entry's contents, decompressed.
    pub fn read(&mut self, i: usize) -> Result<Vec<u8>> {
        let e = &self.entries[i];
        if e.size > MAX_ENTRY || e.compressed > MAX_ENTRY {
            bail!("{} is too large ({} bytes)", e.name, e.size);
        }
        self.file.seek(SeekFrom::Start(e.local_offset))?;
        let mut h = [0u8; 30];
        self.file.read_exact(&mut h)?;
        if u32le(&h, 0) != 0x0403_4b50 {
            bail!("{}: bad local header", e.name);
        }
        let skip = u16le(&h, 26) as i64 + u16le(&h, 28) as i64;
        self.file.seek(SeekFrom::Current(skip))?;
        let mut raw = vec![0u8; e.compressed as usize];
        self.file.read_exact(&mut raw)?;
        match e.method {
            0 => Ok(raw),
            8 => {
                let mut out = Vec::with_capacity(e.size as usize);
                flate2::read::DeflateDecoder::new(&raw[..]).take(MAX_ENTRY).read_to_end(&mut out)?;
                Ok(out)
            }
            m => bail!("{}: compression method {m} isn't supported", e.name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// A zip with one stored and one deflated entry, written the way zip tools do.
    pub fn build(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut cd = Vec::new();
        for (name, data, deflate) in entries {
            let body = if *deflate {
                let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
                e.write_all(data).unwrap();
                e.finish().unwrap()
            } else {
                data.to_vec()
            };
            let method: u16 = if *deflate { 8 } else { 0 };
            let offset = out.len() as u32;
            out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
            out.extend_from_slice(&[20, 0, 0, 0]);
            out.extend_from_slice(&method.to_le_bytes());
            out.extend_from_slice(&[0; 8]); // time, date, crc (unchecked here)
            out.extend_from_slice(&(body.len() as u32).to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&body);
            cd.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
            cd.extend_from_slice(&[20, 0, 20, 0, 0, 0]);
            cd.extend_from_slice(&method.to_le_bytes());
            cd.extend_from_slice(&[0; 8]);
            cd.extend_from_slice(&(body.len() as u32).to_le_bytes());
            cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
            cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
            cd.extend_from_slice(&[0; 12]); // extra, comment, disk, attrs
            cd.extend_from_slice(&offset.to_le_bytes());
            cd.extend_from_slice(name.as_bytes());
        }
        let cd_offset = out.len() as u32;
        out.extend_from_slice(&cd);
        out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(cd.len() as u32).to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    #[test]
    fn reads_stored_and_deflated_entries() {
        let dir = std::env::temp_dir().join(format!("rmm-zip-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("all.zip");
        let big = "{\"id\":\"X\"}".repeat(1000);
        std::fs::write(&path, build(&[("a.json", b"{\"id\":\"A\"}", false), ("b.json", big.as_bytes(), true)])).unwrap();
        let mut z = Archive::open(&path).unwrap();
        assert_eq!(z.entries.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), ["a.json", "b.json"]);
        assert_eq!(z.read(0).unwrap(), b"{\"id\":\"A\"}");
        assert_eq!(z.read(1).unwrap(), big.as_bytes());
        std::fs::write(&path, b"not a zip at all, but long enough to look").unwrap();
        assert!(Archive::open(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
