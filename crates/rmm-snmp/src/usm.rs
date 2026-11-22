//! The user-based security model (RFC 3414, with RFC 3826 AES and RFC 7860 SHA-2): key
//! localization, message authentication and privacy.

use aes::Aes128;
use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use des::Des;
use hmac::{Hmac, Mac};
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};

use crate::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthProto {
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl AuthProto {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "md5" => Self::Md5,
            "sha" | "sha1" => Self::Sha1,
            "sha224" => Self::Sha224,
            "sha256" => Self::Sha256,
            "sha384" => Self::Sha384,
            "sha512" => Self::Sha512,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha224 => "sha224",
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }

    /// Length of the `msgAuthenticationParameters` (the HMAC, truncated).
    pub fn mac_len(self) -> usize {
        match self {
            Self::Md5 | Self::Sha1 => 12,
            Self::Sha224 => 16,
            Self::Sha256 => 24,
            Self::Sha384 => 32,
            Self::Sha512 => 48,
        }
    }

    fn hash(self, parts: &[&[u8]]) -> Vec<u8> {
        fn go<D: Digest>(parts: &[&[u8]]) -> Vec<u8> {
            let mut d = D::new();
            for p in parts {
                d.update(p);
            }
            d.finalize().to_vec()
        }
        match self {
            Self::Md5 => go::<Md5>(parts),
            Self::Sha1 => go::<Sha1>(parts),
            Self::Sha224 => go::<Sha224>(parts),
            Self::Sha256 => go::<Sha256>(parts),
            Self::Sha384 => go::<Sha384>(parts),
            Self::Sha512 => go::<Sha512>(parts),
        }
    }

    fn hmac(self, key: &[u8], msg: &[u8]) -> Vec<u8> {
        macro_rules! go {
            ($d:ty) => {{
                let mut m = <Hmac<$d> as hmac::KeyInit>::new_from_slice(key).expect("HMAC takes keys of any length");
                m.update(msg);
                m.finalize().into_bytes().to_vec()
            }};
        }
        match self {
            Self::Md5 => go!(Md5),
            Self::Sha1 => go!(Sha1),
            Self::Sha224 => go!(Sha224),
            Self::Sha256 => go!(Sha256),
            Self::Sha384 => go!(Sha384),
            Self::Sha512 => go!(Sha512),
        }
    }

    /// Password to key (RFC 3414 A.2.1): the hash of the password repeated to a megabyte.
    pub fn password_to_key(self, password: &str) -> Vec<u8> {
        let p = password.as_bytes();
        let mut buf = Vec::with_capacity(64 * 1024 + p.len());
        // One megabyte of the password repeated, in 64 KiB blocks so the hash isn't fed byte by byte.
        const TOTAL: usize = 1_048_576;
        let mut fed = 0;
        let mut parts: Vec<Vec<u8>> = Vec::new();
        while fed < TOTAL {
            buf.clear();
            while buf.len() < 64 * 1024 && fed + buf.len() < TOTAL {
                let take = p.len().min(TOTAL - fed - buf.len());
                buf.extend_from_slice(&p[..take]);
            }
            fed += buf.len();
            parts.push(std::mem::take(&mut buf));
        }
        let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        self.hash(&refs)
    }

    /// The key bound to one engine (RFC 3414 A.2.2).
    pub fn localize(self, password: &str, engine_id: &[u8]) -> Vec<u8> {
        let ku = self.password_to_key(password);
        self.hash(&[&ku, engine_id, &ku])
    }

    /// The authentication parameters for `message` (which has zeros where they go).
    pub fn sign(self, key: &[u8], message: &[u8]) -> Vec<u8> {
        let mut mac = self.hmac(key, message);
        mac.truncate(self.mac_len());
        mac
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivProto {
    Des,
    Aes128,
}

impl PrivProto {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "des" => Self::Des,
            "aes" | "aes128" => Self::Aes128,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Des => "des",
            Self::Aes128 => "aes128",
        }
    }
}

/// Encrypts a scoped PDU. Returns the ciphertext and the privacy parameters (the salt).
/// `salt` is a counter the caller increments.
pub fn encrypt(proto: PrivProto, key: &[u8], boots: u32, time: u32, salt: u64, plain: &[u8]) -> (Vec<u8>, Vec<u8>) {
    match proto {
        PrivProto::Aes128 => {
            let salt = salt.to_be_bytes();
            let iv = aes_iv(boots, time, &salt);
            (aes_cfb(&key[..16], &iv, plain, true), salt.to_vec())
        }
        PrivProto::Des => {
            // The salt is the engine's boots and a 32-bit counter; the IV is that XOR the key's second half.
            let mut s = [0u8; 8];
            s[..4].copy_from_slice(&boots.to_be_bytes());
            s[4..].copy_from_slice(&(salt as u32).to_be_bytes());
            let iv = des_iv(&key[8..16], &s);
            (des_cbc(&key[..8], &iv, plain, true), s.to_vec())
        }
    }
}

pub fn decrypt(proto: PrivProto, key: &[u8], boots: u32, time: u32, salt: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    let salt: [u8; 8] = salt.try_into().map_err(|_| Error::Auth("bad privacy parameters".into()))?;
    match proto {
        PrivProto::Aes128 => Ok(aes_cfb(&key[..16], &aes_iv(boots, time, &salt), data, false)),
        PrivProto::Des => {
            if data.is_empty() || !data.len().is_multiple_of(8) {
                return Err(Error::Auth("the encrypted data isn't a whole number of DES blocks".into()));
            }
            Ok(des_cbc(&key[..8], &des_iv(&key[8..16], &salt), data, false))
        }
    }
}

fn aes_iv(boots: u32, time: u32, salt: &[u8; 8]) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[..4].copy_from_slice(&boots.to_be_bytes());
    iv[4..8].copy_from_slice(&time.to_be_bytes());
    iv[8..].copy_from_slice(salt);
    iv
}

fn des_iv(pre: &[u8], salt: &[u8; 8]) -> [u8; 8] {
    let mut iv = [0u8; 8];
    for i in 0..8 {
        iv[i] = pre[i] ^ salt[i];
    }
    iv
}

/// AES in 128-bit cipher feedback mode: the keystream is the encryption of the previous
/// ciphertext block, so both directions only ever encrypt.
fn aes_cfb(key: &[u8], iv: &[u8; 16], data: &[u8], encrypt: bool) -> Vec<u8> {
    let cipher = Aes128::new_from_slice(key).expect("16-byte key");
    let mut reg = *iv;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let mut ks = aes::Block::from(reg);
        cipher.encrypt_block(&mut ks);
        let o: Vec<u8> = chunk.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect();
        // The register for the next block is the ciphertext of this one.
        let ct = if encrypt { &o[..] } else { chunk };
        if ct.len() == 16 {
            reg.copy_from_slice(ct);
        }
        out.extend(o);
    }
    out
}

fn des_cbc(key: &[u8], iv: &[u8; 8], data: &[u8], encrypt: bool) -> Vec<u8> {
    let cipher = Des::new_from_slice(key).expect("8-byte key");
    let mut prev = *iv;
    let mut out = Vec::with_capacity(data.len() + 8);
    if encrypt {
        let mut padded = data.to_vec();
        while !padded.len().is_multiple_of(8) {
            padded.push(0);
        }
        for chunk in padded.chunks(8) {
            let mut b = [0u8; 8];
            for i in 0..8 {
                b[i] = chunk[i] ^ prev[i];
            }
            let mut blk = aes::cipher::Block::<Des>::from(b);
            cipher.encrypt_block(&mut blk);
            prev.copy_from_slice(&blk);
            out.extend_from_slice(&blk);
        }
    } else {
        for chunk in data.as_chunks::<8>().0 {
            let mut blk = aes::cipher::Block::<Des>::from(*chunk);
            cipher.decrypt_block(&mut blk);
            for i in 0..8 {
                out.push(blk[i] ^ prev[i]);
            }
            prev = *chunk;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 3414 appendix A.3: password "maplesyrup", engine 00 00 00 00 00 00 00 00 00 00 00 02.
    #[test]
    fn key_localization_matches_the_rfc() {
        let engine = hex::decode("000000000000000000000002").unwrap();
        let ku = AuthProto::Md5.password_to_key("maplesyrup");
        assert_eq!(hex::encode(ku), "9faf3283884e92834ebc9847d8edd963");
        assert_eq!(hex::encode(AuthProto::Md5.localize("maplesyrup", &engine)), "526f5eed9fcce26f8964c2930787d82b");
        assert_eq!(hex::encode(AuthProto::Sha1.password_to_key("maplesyrup")), "9fb5cc0381497b3793528939ff788d5d79145211");
        assert_eq!(hex::encode(AuthProto::Sha1.localize("maplesyrup", &engine)), "6695febc9288e36282235fc7151f128497b38f3f");
    }

    #[test]
    fn hmac_is_truncated_per_protocol() {
        for (p, n) in [(AuthProto::Md5, 12), (AuthProto::Sha1, 12), (AuthProto::Sha256, 24), (AuthProto::Sha512, 48)] {
            let k = p.localize("passphrase1", b"engine");
            assert_eq!(p.sign(&k, b"message").len(), n);
            assert_ne!(p.sign(&k, b"message"), p.sign(&k, b"messagf"));
        }
        // RFC 2202 test case 2 for HMAC-SHA1 ("Jefe" / "what do ya want for nothing?") before truncation.
        assert_eq!(hex::encode(AuthProto::Sha1.hmac(b"Jefe", b"what do ya want for nothing?")), "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
        assert_eq!(hex::encode(AuthProto::Md5.hmac(b"Jefe", b"what do ya want for nothing?")), "750c783e6ab0b503eaa86e310a5db738");
    }

    #[test]
    fn aes_matches_the_nist_cfb128_vector() {
        // NIST SP 800-38A F.3.13, CFB128-AES128.Encrypt, first two blocks.
        let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let iv: [u8; 16] = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap().try_into().unwrap();
        let pt = hex::decode("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51").unwrap();
        let ct = aes_cfb(&key, &iv, &pt, true);
        assert_eq!(hex::encode(&ct), "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b");
        assert_eq!(aes_cfb(&key, &iv, &ct, false), pt);
    }

    #[test]
    fn privacy_roundtrips_for_odd_lengths() {
        let key = AuthProto::Sha1.localize("privpassphrase", b"engine-id");
        for proto in [PrivProto::Aes128, PrivProto::Des] {
            for len in [1usize, 7, 8, 15, 16, 17, 100] {
                let plain: Vec<u8> = (0..len as u8).collect();
                let (ct, salt) = encrypt(proto, &key, 3, 1000, 42, &plain);
                assert_ne!(ct[..plain.len().min(ct.len())], plain[..plain.len().min(ct.len())], "{proto:?} {len}");
                let back = decrypt(proto, &key, 3, 1000, &salt, &ct).unwrap();
                // DES pads to a block; the BER inside says where the data ends.
                assert_eq!(&back[..plain.len()], &plain[..], "{proto:?} {len}");
            }
        }
        assert!(decrypt(PrivProto::Des, &key, 1, 1, &[0; 8], &[1, 2, 3]).is_err());
        assert!(decrypt(PrivProto::Aes128, &key, 1, 1, &[0; 3], &[1, 2, 3]).is_err());
    }
}
