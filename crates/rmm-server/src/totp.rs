//! RFC 6238 TOTP (SHA-1, 6 digits, 30 s) as used by every common authenticator app,
//! plus single-use recovery codes.

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
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&counter.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let off = (h[h.len() - 1] & 0x0f) as usize;
    let bin = u32::from_be_bytes([h[off] & 0x7f, h[off + 1], h[off + 2], h[off + 3]]);
    bin % 10u32.pow(digits)
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
