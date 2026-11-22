//! Who made a network card: the IEEE's registered 24-bit prefixes (MA-L), with company names
//! shortened (`src/oui.txt.gz`, about 40,000 of them in 340 KB). Decompressed on first use.

use std::sync::OnceLock;

static TABLE: &[u8] = include_bytes!("oui.txt.gz");

/// `(prefix, name)` sorted by prefix, the prefix as six lower-case hex digits.
fn entries() -> &'static [(&'static str, &'static str)] {
    static E: OnceLock<Vec<(&'static str, &'static str)>> = OnceLock::new();
    E.get_or_init(|| {
        use std::io::Read;
        let mut text = String::new();
        if flate2::read::GzDecoder::new(TABLE).read_to_string(&mut text).is_err() {
            return Vec::new();
        }
        // Leaked once: the table lives as long as the process.
        let text: &'static str = Box::leak(text.into_boxed_str());
        text.lines().filter_map(|l| l.split_once(' ')).filter(|(p, _)| p.len() == 6).collect()
    })
}

/// The manufacturer of a MAC address (`aa:bb:cc:...`, any separator and case).
/// Locally administered addresses (random, virtual) have none.
pub fn vendor(mac: &str) -> Option<&'static str> {
    let hex: String = mac.chars().filter(char::is_ascii_hexdigit).take(6).map(|c| c.to_ascii_lowercase()).collect();
    if hex.len() != 6 {
        return None;
    }
    // Bit 1 of the first octet: locally administered.
    if u8::from_str_radix(&hex[..2], 16).ok()? & 0x02 != 0 {
        return None;
    }
    let e = entries();
    e.binary_search_by(|(p, _)| (*p).cmp(hex.as_str())).ok().map(|i| e[i].1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_prefixes() {
        assert_eq!(vendor("00:00:0c:12:34:56"), Some("Cisco Systems"));
        assert_eq!(vendor("B8-27-EB-00-00-01"), Some("Raspberry Pi Foundation"));
        assert_eq!(vendor("3c5ab4aabbcc"), Some("Google"));
        assert!(entries().len() > 30_000, "the table is loaded: {}", entries().len());
    }

    #[test]
    fn unknown_and_random_addresses_have_no_vendor() {
        assert_eq!(vendor("02:00:00:00:00:01"), None, "locally administered");
        assert_eq!(vendor("fe:ff:ff:00:00:00"), None);
        assert_eq!(vendor("nonsense"), None);
        assert_eq!(vendor(""), None);
    }
}
