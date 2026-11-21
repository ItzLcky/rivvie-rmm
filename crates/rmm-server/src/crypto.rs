//! Encryption at rest for sensitive columns (detection context: command lines can contain
//! passwords). The key is `RMM_DATA_KEY`: 32 bytes, hex or base64. Without it, data is
//! stored as-is and the server warns at startup.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

#[derive(Clone)]
pub struct DataKey(ChaCha20Poly1305);

impl std::fmt::Debug for DataKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DataKey(..)")
    }
}

impl DataKey {
    pub fn parse(s: &str) -> anyhow::Result<DataKey> {
        let s = s.trim();
        let raw = hex::decode(s).ok().filter(|b| b.len() == 32).or_else(|| data_encoding::BASE64.decode(s.as_bytes()).ok()).unwrap_or_default();
        let raw: [u8; 32] = raw.try_into().map_err(|_| anyhow::anyhow!("RMM_DATA_KEY must be 32 bytes, as hex (64 characters) or base64"))?;
        Ok(DataKey::from_bytes(raw))
    }

    /// A key from raw bytes (the vault's per-client keys).
    pub fn from_bytes(raw: [u8; 32]) -> DataKey {
        DataKey(ChaCha20Poly1305::new(&Key::from(raw)))
    }

    /// Like [`seal`](Self::seal), with associated data that must be given again to open it:
    /// the vault binds each ciphertext to its row and column this way, so one copied
    /// elsewhere won't open.
    pub fn seal_aad(&self, plain: &[u8], aad: &str) -> Vec<u8> {
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce).expect("OS RNG unavailable");
        let sealed = self
            .0
            .encrypt(&Nonce::from(nonce), Payload { msg: plain, aad: aad.as_bytes() })
            .expect("ChaCha20-Poly1305 only fails past 256 GiB");
        let mut out = nonce.to_vec();
        out.extend(sealed);
        out
    }

    pub fn open_aad(&self, sealed: &[u8], aad: &str) -> Option<Vec<u8>> {
        let nonce: [u8; 12] = sealed.get(..12)?.try_into().ok()?;
        self.0.decrypt(&Nonce::from(nonce), Payload { msg: &sealed[12..], aad: aad.as_bytes() }).ok()
    }

    /// nonce (12 bytes) || ciphertext.
    pub fn seal(&self, plain: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; 12];
        let _ = getrandom::fill(&mut nonce);
        let mut out = nonce.to_vec();
        out.extend(self.0.encrypt(&Nonce::from(nonce), plain).unwrap_or_default());
        out
    }

    pub fn open(&self, sealed: &[u8]) -> Option<Vec<u8>> {
        let nonce: [u8; 12] = sealed.get(..12)?.try_into().ok()?;
        self.0.decrypt(&Nonce::from(nonce), &sealed[12..]).ok()
    }
}

/// Stores `plain` (sealed when there's a key). Returns (bytes, encrypted).
pub fn store(key: Option<&DataKey>, plain: &[u8]) -> (Vec<u8>, bool) {
    match key {
        Some(k) => (k.seal(plain), true),
        None => (plain.to_vec(), false),
    }
}

pub fn load(key: Option<&DataKey>, bytes: &[u8], encrypted: bool) -> Option<Vec<u8>> {
    if encrypted { key?.open(bytes) } else { Some(bytes.to_vec()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_and_open() {
        let k = DataKey::parse(&"ab".repeat(32)).unwrap();
        let sealed = k.seal(b"cmd /c net user admin hunter2");
        assert!(!sealed.windows(7).any(|w| w == b"hunter2"));
        assert_eq!(k.open(&sealed).unwrap(), b"cmd /c net user admin hunter2");
        let other = DataKey::parse(&"cd".repeat(32)).unwrap();
        assert!(other.open(&sealed).is_none());
        assert!(DataKey::parse("short").is_err());
        assert_eq!(load(None, b"x", false).unwrap(), b"x");
        assert!(load(None, &sealed, true).is_none(), "no key, no plaintext");
    }

    #[test]
    fn associated_data() {
        let k = DataKey::from_bytes([7u8; 32]);
        let sealed = k.seal_aad(b"hunter2", "item-1:password");
        assert!(!sealed.windows(7).any(|w| w == b"hunter2"));
        assert_eq!(k.open_aad(&sealed, "item-1:password").unwrap(), b"hunter2");
        assert!(k.open_aad(&sealed, "item-1:notes").is_none(), "another column");
        assert!(k.open_aad(&sealed, "item-2:password").is_none(), "another row");
        assert!(k.open(&sealed).is_none(), "the AAD is required");
        assert!(DataKey::from_bytes([8u8; 32]).open_aad(&sealed, "item-1:password").is_none());
        assert_ne!(k.seal_aad(b"x", "a"), k.seal_aad(b"x", "a"), "fresh nonce each time");
        assert!(k.open_aad(b"short", "a").is_none());
    }
}
