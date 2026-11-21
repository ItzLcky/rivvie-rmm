//! RFC 6238 TOTP (SHA-1, 6 digits, 30 s) as used by every common authenticator app,
//! plus single-use recovery codes. [`code`] covers the other algorithms, digit counts and
//! periods, for the vault's stored TOTP secrets.

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

pub const STEP_SECS: i64 = 30;
pub const SECRET_LEN: usize = 20;
pub const RECOVERY_CODES: usize = 10;

pub fn new_secret() -> Vec<u8> {
    let mut s = vec![0u8; SECRET_LEN];
    getrandom::fill(&mut s).expect("OS RNG unavailable");
    s
}

pub fn encode_secret(secret: &[u8]) -> String {
    BASE32_NOPAD.encode(secret)
}

/// `otpauth://` URI that authenticator apps import from the QR code.
pub fn otpauth_uri(secret: &[u8], issuer: &str, account: &str) -> String {
    let enc = |s: &str| {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'@' => (b as char).to_string(),
                _ => format!("%{b:02X}"),
            })
            .collect::<String>()
    };
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period={STEP_SECS}",
        enc(issuer),
        enc(account),
        encode_secret(secret),
        enc(issuer)
    )
}

pub fn qr_svg(data: &str) -> anyhow::Result<String> {
    let code = qrcode::QrCode::new(data.as_bytes())?;
    Ok(code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(200, 200)
        .dark_color(qrcode::render::svg::Color("#000000"))
        .light_color(qrcode::render::svg::Color("#ffffff"))
        .build())
}

fn hotp(secret: &[u8], counter: u64, digits: u32) -> u32 {
    hotp_with(Algorithm::Sha1, secret, counter, digits)
}

/// The HMAC behind a TOTP code. Sign-in only uses SHA-1; vault items (other people's
/// accounts) can use any of the three RFC 6238 allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl Algorithm {
    pub fn parse(s: &str) -> Option<Algorithm> {
        match s.to_ascii_uppercase().replace('-', "").as_str() {
            "SHA1" => Some(Algorithm::Sha1),
            "SHA256" => Some(Algorithm::Sha256),
            "SHA512" => Some(Algorithm::Sha512),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Algorithm::Sha1 => "SHA1",
            Algorithm::Sha256 => "SHA256",
            Algorithm::Sha512 => "SHA512",
        }
    }
}

fn hmac<M: Mac + KeyInit>(secret: &[u8], counter: u64) -> Vec<u8> {
    let mut mac = <M as KeyInit>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&counter.to_be_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn hotp_with(alg: Algorithm, secret: &[u8], counter: u64, digits: u32) -> u32 {
    let h = match alg {
        Algorithm::Sha1 => hmac::<Hmac<Sha1>>(secret, counter),
        Algorithm::Sha256 => hmac::<Hmac<sha2::Sha256>>(secret, counter),
        Algorithm::Sha512 => hmac::<Hmac<sha2::Sha512>>(secret, counter),
    };
    let off = (h[h.len() - 1] & 0x0f) as usize;
    let bin = u32::from_be_bytes([h[off] & 0x7f, h[off + 1], h[off + 2], h[off + 3]]);
    bin % 10u32.pow(digits)
}

/// The code for `unix` (seconds), zero-padded to `digits`.
pub fn code(secret: &[u8], alg: Algorithm, digits: u32, period: u32, unix: i64) -> String {
    let step = unix.div_euclid(period.max(1) as i64).max(0) as u64;
    format!("{:0width$}", hotp_with(alg, secret, step, digits), width = digits as usize)
}

/// A TOTP secret with its parameters, as an authenticator app would import it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spec {
    pub secret: Vec<u8>,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u32,
}

/// Reads a base32 secret (spaces, dashes, lowercase and padding allowed) or an
/// `otpauth://totp/...` URI, whose `algorithm`, `digits` and `period` override the defaults
/// (SHA-1, 6, 30). The error never echoes the input: it's a secret.
pub fn parse_spec(input: &str) -> Result<Spec, &'static str> {
    const BAD: &str = "the TOTP secret must be base32 or an otpauth://totp/ URI";
    let input = input.trim();
    let mut spec = Spec { secret: Vec::new(), algorithm: Algorithm::Sha1, digits: 6, period: STEP_SECS as u32 };
    let secret = if input.get(..10).is_some_and(|s| s.eq_ignore_ascii_case("otpauth://")) {
        let rest = &input[10..];
        if !rest.get(..5).is_some_and(|t| t.eq_ignore_ascii_case("totp/")) {
            return Err("only time-based (otpauth://totp/) codes are supported");
        }
        let query = rest.split_once('?').map(|(_, q)| q).unwrap_or("");
        let mut secret = None;
        for (k, v) in query.split('&').filter_map(|kv| kv.split_once('=')) {
            let v = percent_decode(v).ok_or(BAD)?;
            match k.to_ascii_lowercase().as_str() {
                "secret" => secret = Some(v),
                "algorithm" => spec.algorithm = Algorithm::parse(&v).ok_or("the TOTP algorithm must be SHA1, SHA256 or SHA512")?,
                "digits" => spec.digits = v.parse().map_err(|_| "TOTP digits must be 6, 7 or 8")?,
                "period" => spec.period = v.parse().map_err(|_| "the TOTP period must be 1-300 seconds")?,
                _ => {}
            }
        }
        secret.ok_or("the otpauth URI has no secret")?
    } else {
        input.to_string()
    };
    if !(6..=8).contains(&spec.digits) {
        return Err("TOTP digits must be 6, 7 or 8");
    }
    if !(1..=300).contains(&spec.period) {
        return Err("the TOTP period must be 1-300 seconds");
    }
    let b32: String = secret.chars().filter(|c| !matches!(c, ' ' | '-' | '=')).map(|c| c.to_ascii_uppercase()).collect();
    spec.secret = BASE32_NOPAD.decode(b32.as_bytes()).map_err(|_| BAD)?;
    if spec.secret.len() < 5 || spec.secret.len() > 128 {
        return Err(BAD);
    }
    Ok(spec)
}

fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                out.push(u8::from_str_radix(s.get(i + 1..i + 3)?, 16).ok()?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

pub fn step_at(unix_secs: i64) -> i64 {
    unix_secs.div_euclid(STEP_SECS)
}

/// The time step `code` matches, allowing one step of clock drift either way.
/// Callers must reject a step at or below the last one used (replay protection).
pub fn verify(secret: &[u8], code: &str, now_unix: i64) -> Option<i64> {
    let code = code.trim().replace(' ', "");
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let want: u32 = code.parse().ok()?;
    let now = step_at(now_unix);
    // Constant-time compare per candidate; the loop itself always runs all three.
    let mut hit = None;
    for step in [now - 1, now, now + 1] {
        if step >= 0 && subtle::ConstantTimeEq::ct_eq(&hotp(secret, step as u64, 6), &want).into() {
            hit = Some(step);
        }
    }
    hit
}

/// Looks like a 6-digit TOTP code rather than a recovery code.
pub fn is_totp_shaped(code: &str) -> bool {
    let c = code.trim().replace(' ', "");
    c.len() == 6 && c.bytes().all(|b| b.is_ascii_digit())
}

/// Recovery codes look like `k3vq7-m2xpa` (50 bits each). Returned once, stored hashed.
pub fn new_recovery_codes() -> Vec<String> {
    const ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789"; // no 0/o, 1/l/i
    (0..RECOVERY_CODES)
        .map(|_| {
            let mut buf = [0u8; 10];
            getrandom::fill(&mut buf).expect("OS RNG unavailable");
            // 31 symbols; modulo bias on a u8 is negligible next to 50 bits of entropy.
            let s: String = buf.iter().map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char).collect();
            format!("{}-{}", &s[..5], &s[5..])
        })
        .collect()
}

/// Lowercased with separators removed, so `K3VQ7 M2XPA` matches `k3vq7-m2xpa`.
pub fn normalize_recovery_code(code: &str) -> String {
    code.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_lowercase()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 appendix B, SHA-1 key; last 6 digits of the 8-digit values.
    const KEY: &[u8] = b"12345678901234567890";

    #[test]
    fn rfc6238_vectors() {
        for (t, want) in [(59, 94287082), (1111111109, 7081804), (1234567890, 89005924), (2000000000, 69279037)] {
            assert_eq!(hotp(KEY, step_at(t) as u64, 8), want, "t={t}");
            assert_eq!(verify(KEY, &format!("{:06}", want % 1_000_000), t), Some(step_at(t)));
        }
    }

    /// RFC 6238 appendix B: every time and algorithm, 8 digits.
    #[test]
    fn rfc6238_all_algorithms() {
        let k1 = b"12345678901234567890".as_slice();
        let k256 = b"12345678901234567890123456789012".as_slice();
        let k512 = b"1234567890123456789012345678901234567890123456789012345678901234".as_slice();
        for (t, sha1, sha256, sha512) in [
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ] {
            assert_eq!(code(k1, Algorithm::Sha1, 8, 30, t), sha1, "SHA1 t={t}");
            assert_eq!(code(k256, Algorithm::Sha256, 8, 30, t), sha256, "SHA256 t={t}");
            assert_eq!(code(k512, Algorithm::Sha512, 8, 30, t), sha512, "SHA512 t={t}");
        }
        assert_eq!(code(k1, Algorithm::Sha1, 6, 30, 1111111109), "081804", "zero-padded");
        assert_eq!(code(k1, Algorithm::Sha1, 6, 60, 119), code(k1, Algorithm::Sha1, 6, 30, 30), "both are step 1");
    }

    #[test]
    fn specs() {
        let plain = parse_spec("gezd gnbv-gy3t qojq gezd gnbv gy3t qojq").unwrap();
        assert_eq!(plain, Spec { secret: KEY.to_vec(), algorithm: Algorithm::Sha1, digits: 6, period: 30 });
        let uri = parse_spec("otpauth://totp/Acme%20VPN:dana?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Acme&algorithm=SHA256&digits=8&period=60").unwrap();
        assert_eq!((uri.algorithm, uri.digits, uri.period, uri.secret.as_slice()), (Algorithm::Sha256, 8, 60, KEY));
        assert_eq!(parse_spec(&otpauth_uri(KEY, "x", "y")).unwrap().secret, KEY);
        assert!(parse_spec("otpauth://hotp/x?secret=GEZDGNBV&counter=1").is_err());
        assert!(parse_spec("otpauth://totp/x?issuer=a").is_err());
        assert!(parse_spec("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&digits=9").is_err());
        assert!(parse_spec("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&algorithm=MD5").is_err());
        assert!(parse_spec("not base32!").is_err());
        assert!(parse_spec("").is_err());
        let e = parse_spec("hunter2 is my password").unwrap_err();
        assert!(!e.contains("hunter2"), "errors never echo the secret");
    }

    #[test]
    fn drift_window() {
        let t = 1234567890;
        let code = format!("{:06}", hotp(KEY, step_at(t) as u64, 6));
        assert!(verify(KEY, &code, t + STEP_SECS).is_some());
        assert!(verify(KEY, &code, t - STEP_SECS).is_some());
        assert!(verify(KEY, &code, t + 3 * STEP_SECS).is_none());
        assert!(verify(KEY, "12345", t).is_none());
        assert!(verify(KEY, "abcdef", t).is_none());
    }

    #[test]
    fn recovery_codes() {
        let codes = new_recovery_codes();
        assert_eq!(codes.len(), RECOVERY_CODES);
        assert!(codes.iter().all(|c| c.len() == 11 && !is_totp_shaped(c)));
        assert_eq!(normalize_recovery_code(" K3VQ7 M2XPA "), "k3vq7m2xpa");
    }

    #[test]
    fn uri() {
        let u = otpauth_uri(KEY, "Acme IT RMM", "a@b.com");
        assert!(u.starts_with("otpauth://totp/Acme%20IT%20RMM:a@b.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&"));
    }
}
