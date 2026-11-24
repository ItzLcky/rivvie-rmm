//! Reads the few fields of an X.509 certificate a monitor reports: validity, subject, issuer
//! and subject alternative names. DER is BER with definite lengths, so the `rmm-snmp` reader
//! does; nothing here checks signatures (rustls has done that, or deliberately not).

use chrono::{DateTime, NaiveDate, Utc};
use rmm_snmp::ber::Reader;
use rmm_snmp::Oid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cert {
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    /// `CN=example.com, O=Example`.
    pub subject: String,
    pub issuer: String,
    /// DNS names and IP addresses.
    pub sans: Vec<String>,
}

impl Cert {
    /// Whole days from `now` until it expires (negative once it has).
    pub fn days_left(&self, now: DateTime<Utc>) -> i64 {
        (self.not_after - now).num_seconds().div_euclid(86_400)
    }
}

const SET: u8 = 0x31;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;

fn err(_: rmm_snmp::Error) -> String {
    "malformed certificate".into()
}

fn time(tag: u8, c: &[u8]) -> Result<DateTime<Utc>, String> {
    let s = std::str::from_utf8(c).map_err(|_| "bad certificate time")?;
    let s = s.strip_suffix('Z').ok_or("certificate time isn't UTC")?;
    let (year, rest) = match tag {
        UTC_TIME if s.len() >= 10 => {
            // Two-digit years: 50-99 are 19xx (RFC 5280).
            let y: i32 = s[..2].parse().map_err(|_| "bad year")?;
            (if y >= 50 { 1900 + y } else { 2000 + y }, &s[2..])
        }
        GENERALIZED_TIME if s.len() >= 12 => (s[..4].parse().map_err(|_| "bad year")?, &s[4..]),
        _ => return Err("bad certificate time".into()),
    };
    let n = |i: usize| -> Result<u32, String> { rest.get(i..i + 2).unwrap_or("00").parse().map_err(|_| "bad certificate time".to_string()) };
    let date = NaiveDate::from_ymd_opt(year, n(0)?, n(2)?).ok_or("bad certificate date")?;
    let dt = date.and_hms_opt(n(4)?, n(6)?, if rest.len() >= 10 { n(8)? } else { 0 }).ok_or("bad certificate time")?;
    Ok(dt.and_utc())
}

fn attr_name(oid: &Oid) -> String {
    match oid.to_string().as_str() {
        "2.5.4.3" => "CN".into(),
        "2.5.4.6" => "C".into(),
        "2.5.4.7" => "L".into(),
        "2.5.4.8" => "ST".into(),
        "2.5.4.10" => "O".into(),
        "2.5.4.11" => "OU".into(),
        "1.2.840.113549.1.9.1" => "emailAddress".into(),
        other => other.to_string(),
    }
}

fn string_value(tag: u8, c: &[u8]) -> String {
    match tag {
        // BMPString: UTF-16BE.
        0x1e => {
            let units: Vec<u16> = c.as_chunks::<2>().0.iter().map(|p| u16::from_be_bytes(*p)).collect();
            String::from_utf16_lossy(&units)
        }
        _ => String::from_utf8_lossy(c).into_owned(),
    }
}

/// A distinguished name as `CN=..., O=...`, in the certificate's order.
fn name(mut r: Reader) -> Result<String, String> {
    let mut parts = Vec::new();
    while !r.is_empty() {
        let mut set = Reader::new(r.expect(SET).map_err(err)?);
        while !set.is_empty() {
            let mut atv = set.sequence().map_err(err)?;
            let oid = atv.oid().map_err(err)?;
            let (tag, c) = atv.read().map_err(err)?;
            parts.push(format!("{}={}", attr_name(&oid), string_value(tag, c)));
        }
    }
    Ok(parts.join(", "))
}

fn sans(der: &[u8]) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut r = Reader::new(der).sequence().map_err(err)?;
    while !r.is_empty() {
        let (tag, c) = r.read().map_err(err)?;
        match tag {
            // dNSName [2] IMPLICIT IA5String
            0x82 => out.push(String::from_utf8_lossy(c).into_owned()),
            // iPAddress [7] IMPLICIT OCTET STRING
            0x87 if c.len() == 4 => out.push(std::net::Ipv4Addr::new(c[0], c[1], c[2], c[3]).to_string()),
            0x87 if c.len() == 16 => {
                let b: [u8; 16] = c.try_into().unwrap_or([0; 16]);
                out.push(std::net::Ipv6Addr::from(b).to_string());
            }
            _ => {}
        }
        if out.len() >= 100 {
            break;
        }
    }
    Ok(out)
}

/// Parses a DER certificate.
pub fn parse(der: &[u8]) -> Result<Cert, String> {
    let mut cert = Reader::new(der).sequence().map_err(err)?;
    let mut tbs = cert.sequence().map_err(err)?;
    // version [0] EXPLICIT, absent for v1.
    let (mut tag, mut c) = tbs.read().map_err(err)?;
    if tag == 0xa0 {
        (tag, c) = tbs.read().map_err(err)?;
    }
    // That was the serial number (any length; not read).
    let _ = (tag, c);
    tbs.sequence().map_err(err)?; // signature algorithm
    let issuer = name(tbs.sequence().map_err(err)?)?;
    let mut validity = tbs.sequence().map_err(err)?;
    let (t1, c1) = validity.read().map_err(err)?;
    let (t2, c2) = validity.read().map_err(err)?;
    let (not_before, not_after) = (time(t1, c1)?, time(t2, c2)?);
    let subject = name(tbs.sequence().map_err(err)?)?;
    tbs.sequence().map_err(err)?; // subject public key info
    let mut alt = Vec::new();
    while !tbs.is_empty() {
        let (tag, c) = tbs.read().map_err(err)?;
        // extensions [3] EXPLICIT SEQUENCE OF Extension
        if tag != 0xa3 {
            continue;
        }
        let mut exts = Reader::new(c).sequence().map_err(err)?;
        while !exts.is_empty() {
            let mut ext = exts.sequence().map_err(err)?;
            let oid = ext.oid().map_err(err)?;
            let (mut t, mut v) = ext.read().map_err(err)?;
            if t == 0x01 {
                // critical BOOLEAN
                (t, v) = ext.read().map_err(err)?;
            }
            if t == 0x04 && oid.to_string() == "2.5.29.17" {
                alt = sans(v)?;
            }
        }
    }
    Ok(Cert { not_before, not_after, subject, issuer, sans: alt })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_certificate() {
        let c = parse(include_bytes!("../fixtures/leaf.der")).unwrap();
        assert_eq!(c.not_before.to_rfc3339(), "2026-01-01T00:00:00+00:00");
        assert_eq!(c.not_after.to_rfc3339(), "2030-12-31T23:59:59+00:00");
        assert_eq!(c.subject, "CN=fixture.example, O=RMM Test");
        assert_eq!(c.issuer, c.subject, "self-signed");
        assert_eq!(c.sans, ["fixture.example", "www.fixture.example", "192.0.2.7"]);
        let now = "2030-12-17T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
        assert_eq!(c.days_left(now), 14);
        assert_eq!(c.days_left("2031-01-02T00:00:00Z".parse().unwrap()), -2, "expired");
    }

    #[test]
    fn generalized_time_and_no_extensions() {
        // RSA, with a notAfter past 2049 (GeneralizedTime), no SANs.
        let c = parse(include_bytes!("../fixtures/long.der")).unwrap();
        assert_eq!(c.not_after.to_rfc3339(), "2051-06-01T12:00:00+00:00");
        assert_eq!(c.not_before.to_rfc3339(), "2020-01-01T00:00:00+00:00");
        assert_eq!(c.subject, "C=GB, O=Long Lived, CN=old.example");
        assert!(c.sans.is_empty());
    }

    #[test]
    fn garbage_is_an_error_not_a_panic() {
        let good = include_bytes!("../fixtures/leaf.der");
        for cut in [0, 1, 10, 50, 100, 200, good.len() - 1] {
            assert!(parse(&good[..cut]).is_err(), "cut at {cut}");
        }
        assert!(parse(&[0x30, 0x03, 0x02, 0x01, 0x01]).is_err());
        assert_eq!(time(UTC_TIME, b"491231235959Z").unwrap().to_rfc3339(), "2049-12-31T23:59:59+00:00");
        assert_eq!(time(UTC_TIME, b"500101000000Z").unwrap().to_rfc3339(), "1950-01-01T00:00:00+00:00");
        assert!(time(UTC_TIME, b"501301000000Z").is_err(), "month 13");
    }
}
