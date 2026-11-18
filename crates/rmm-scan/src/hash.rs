//! Streamed hashing. SHA-256 always; MD5 and SHA-1 only when the database carries signatures
//! of that kind (ClamAV `.hdb`/`.hsb`), since each costs about as much again as reading.

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Digests {
    pub sha256: [u8; 32],
    pub md5: Option<[u8; 16]>,
    pub sha1: Option<[u8; 20]>,
    pub size: u64,
}

impl Digests {
    pub fn sha256_hex(&self) -> String {
        hex::encode(self.sha256)
    }
}

pub struct Hasher {
    sha256: Sha256,
    md5: Option<Md5>,
    sha1: Option<Sha1>,
    size: u64,
}

impl Hasher {
    pub fn new(md5: bool, sha1: bool) -> Self {
        Hasher { sha256: Sha256::new(), md5: md5.then(Md5::new), sha1: sha1.then(Sha1::new), size: 0 }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.sha256.update(data);
        if let Some(h) = &mut self.md5 {
            h.update(data);
        }
        if let Some(h) = &mut self.sha1 {
            h.update(data);
        }
        self.size = self.size.saturating_add(data.len() as u64);
    }

    pub fn finish(self) -> Digests {
        Digests {
            sha256: self.sha256.finalize().into(),
            md5: self.md5.map(|h| h.finalize().into()),
            sha1: self.sha1.map(|h| h.finalize().into()),
            size: self.size,
        }
    }
}

pub fn digests(data: &[u8], md5: bool, sha1: bool) -> Digests {
    let mut h = Hasher::new(md5, sha1);
    h.update(data);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_values() {
        let d = digests(b"abc", true, true);
        assert_eq!(d.sha256_hex(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(hex::encode(d.md5.unwrap()), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(hex::encode(d.sha1.unwrap()), "a9993e364706816aba3e25717850c26c9cd0d89d");
        let mut h = Hasher::new(false, false);
        h.update(b"a");
        h.update(b"bc");
        let s = h.finish();
        assert_eq!((s.sha256, s.md5, s.size), (d.sha256, None, 3), "streamed in pieces, the same digest");
    }
}
