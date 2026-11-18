//! The verdict cache: files that scanned clean, so an unchanged file isn't read again.
//!
//! The key is what changes when a file does: device, inode, size, modification and change
//! time on Unix (ctime too, since `touch` can put mtime back but not ctime); path, size,
//! modification and creation time on Windows. It is hashed to 16 bytes. Only files with no
//! match at all are cached, so rule modes, exclusions and the kill switch never need to be
//! part of the key. The whole cache belongs to one `generation` (engine, database, content
//! bundle and limits); a different generation starts empty.
//!
//! Bounded in two halves: new entries go into `young`; when it is full, `old` is dropped and
//! `young` takes its place. A hit in `old` moves the entry back to `young`. Persisted as a
//! flat file of keys, written atomically.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

pub type Key = [u8; 16];

const MAGIC: &[u8; 8] = b"RMMVC001";

pub struct Cache {
    generation: Key,
    young: HashSet<Key>,
    old: HashSet<Key>,
    half: usize,
    path: Option<PathBuf>,
    dirty: bool,
    pub hits: u64,
    pub misses: u64,
}

pub fn generation(parts: &[&str]) -> Key {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p.as_bytes());
        h.update([0]);
    }
    h.finalize()[..16].try_into().unwrap_or_default()
}

/// The key for a file from its metadata, `None` if the metadata lacks what it needs.
pub fn key(path: &Path, md: &std::fs::Metadata) -> Option<Key> {
    let mut h = Sha256::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let _ = path;
        for v in [md.dev(), md.ino(), md.size(), md.mtime() as u64, md.mtime_nsec() as u64, md.ctime() as u64, md.ctime_nsec() as u64] {
            h.update(v.to_le_bytes());
        }
    }
    #[cfg(not(unix))]
    {
        let nanos = |t: std::io::Result<std::time::SystemTime>| t.ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_nanos());
        h.update(path.to_string_lossy().to_lowercase().as_bytes());
        h.update(md.len().to_le_bytes());
        h.update(nanos(md.modified())?.to_le_bytes());
        h.update(nanos(md.created()).unwrap_or(0).to_le_bytes());
    }
    h.finalize()[..16].try_into().ok()
}

impl Cache {
    pub fn new(generation: Key, capacity: usize) -> Self {
        Cache { generation, young: HashSet::new(), old: HashSet::new(), half: (capacity / 2).max(1), path: None, dirty: false, hits: 0, misses: 0 }
    }

    /// Loads from `path` if it was written for this generation; starts empty otherwise.
    pub fn load(path: &Path, generation: Key, capacity: usize) -> Self {
        let mut c = Cache::new(generation, capacity);
        c.path = Some(path.to_path_buf());
        if let Ok(d) = std::fs::read(path)
            && d.get(..8) == Some(&MAGIC[..])
            && d.get(8..24) == Some(&generation[..])
        {
            for k in d.get(24..).unwrap_or_default().as_chunks::<16>().0.iter().take(capacity) {
                c.insert(*k);
            }
            c.dirty = false;
        }
        c
    }

    pub fn generation(&self) -> Key {
        self.generation
    }

    pub fn len(&self) -> usize {
        self.young.len() + self.old.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clean(&mut self, k: &Key) -> bool {
        if self.young.contains(k) {
            self.hits += 1;
            return true;
        }
        if self.old.remove(k) {
            self.insert(*k);
            self.hits += 1;
            return true;
        }
        self.misses += 1;
        false
    }

    pub fn insert(&mut self, k: Key) {
        if self.young.len() >= self.half {
            self.old = std::mem::take(&mut self.young);
        }
        self.dirty |= self.young.insert(k);
    }

    pub fn save(&mut self) -> std::io::Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        if !self.dirty {
            return Ok(());
        }
        let mut out = Vec::with_capacity(24 + self.len() * 16);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.generation);
        // Old first, so loading into a smaller capacity keeps the young ones.
        for k in self.old.iter().chain(&self.young) {
            out.extend_from_slice(k);
        }
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &out)?;
        std::fs::rename(&tmp, path)?;
        self.dirty = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_persisted_and_tied_to_a_generation() {
        let g = generation(&["engine 1", "db v1"]);
        let mut c = Cache::new(g, 4);
        for i in 0..10u8 {
            c.insert([i; 16]);
        }
        assert!(c.len() <= 4);
        assert!(c.clean(&[9; 16]) && !c.clean(&[0; 16]));
        let p = std::env::temp_dir().join(format!("rmm-vc-{}", std::process::id()));
        let mut c = Cache::load(&p, g, 100);
        c.insert([1; 16]);
        c.save().unwrap();
        assert!(Cache::load(&p, g, 100).clean(&[1; 16]));
        assert!(!Cache::load(&p, generation(&["engine 1", "db v2"]), 100).clean(&[1; 16]), "a new database starts empty");
        std::fs::write(&p, b"garbage").unwrap();
        assert!(Cache::load(&p, g, 100).is_empty());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn a_changed_file_has_a_new_key() {
        let p = std::env::temp_dir().join(format!("rmm-vc-file-{}", std::process::id()));
        std::fs::write(&p, b"one").unwrap();
        let k1 = key(&p, &std::fs::metadata(&p).unwrap()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&p, b"two").unwrap();
        let k2 = key(&p, &std::fs::metadata(&p).unwrap()).unwrap();
        assert_ne!(k1, k2);
        let _ = std::fs::remove_file(&p);
    }
}
