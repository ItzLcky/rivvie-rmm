//! The small part of ASN.1 BER that SNMP uses: definite lengths, the universal types and the
//! SNMP application types.

use std::fmt;

use crate::Error;

pub const INTEGER: u8 = 0x02;
pub const OCTET_STRING: u8 = 0x04;
pub const NULL: u8 = 0x05;
pub const OID: u8 = 0x06;
pub const SEQUENCE: u8 = 0x30;
pub const IP_ADDRESS: u8 = 0x40;
pub const COUNTER32: u8 = 0x41;
pub const GAUGE32: u8 = 0x42;
pub const TIME_TICKS: u8 = 0x43;
pub const OPAQUE: u8 = 0x44;
pub const COUNTER64: u8 = 0x46;
pub const NO_SUCH_OBJECT: u8 = 0x80;
pub const NO_SUCH_INSTANCE: u8 = 0x81;
pub const END_OF_MIB_VIEW: u8 = 0x82;

/// An object identifier. Ordered numerically component by component, which is the order an
/// agent walks its tree in.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Oid(pub Vec<u32>);

impl Oid {
    /// `1.3.6.1.2.1.1.1.0` (a leading dot is allowed).
    pub fn parse(s: &str) -> Option<Oid> {
        let parts: Option<Vec<u32>> = s.trim_start_matches('.').split('.').map(|p| p.parse().ok()).collect();
        parts.filter(|p| p.len() >= 2 && p[0] <= 2 && (p[0] == 2 || p[1] < 40)).map(Oid)
    }

    /// For constants. Panics on a malformed string.
    pub fn of(s: &str) -> Oid {
        Oid::parse(s).unwrap_or_else(|| panic!("bad OID {s}"))
    }

    pub fn starts_with(&self, prefix: &Oid) -> bool {
        self.0.starts_with(&prefix.0)
    }

    /// This OID with `n` more components.
    pub fn child(&self, n: &[u32]) -> Oid {
        let mut v = self.0.clone();
        v.extend_from_slice(n);
        Oid(v)
    }

    /// The components after `prefix`, if this is below it.
    pub fn suffix(&self, prefix: &Oid) -> Option<&[u32]> {
        self.0.strip_prefix(prefix.0.as_slice())
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let c = &self.0;
        let first = c.first().copied().unwrap_or(0) * 40 + c.get(1).copied().unwrap_or(0);
        push_base128(&mut out, first);
        for &n in c.iter().skip(2) {
            push_base128(&mut out, n);
        }
        out
    }

    fn decode(b: &[u8]) -> Result<Oid, Error> {
        let mut out = Vec::new();
        let mut n: u64 = 0;
        let mut first = true;
        if b.is_empty() {
            return Err(Error::Decode("empty OID"));
        }
        for &x in b {
            n = (n << 7) | u64::from(x & 0x7f);
            if n > u64::from(u32::MAX) * 80 {
                return Err(Error::Decode("OID component too large"));
            }
            if x & 0x80 == 0 {
                if first {
                    let (a, b2) = if n < 40 { (0, n) } else if n < 80 { (1, n - 40) } else { (2, n - 80) };
                    out.push(a as u32);
                    out.push(b2 as u32);
                    first = false;
                } else {
                    out.push(u32::try_from(n).map_err(|_| Error::Decode("OID component too large"))?);
                }
                n = 0;
            }
        }
        if n != 0 || b.last().is_some_and(|l| l & 0x80 != 0) {
            return Err(Error::Decode("truncated OID"));
        }
        Ok(Oid(out))
    }
}

fn push_base128(out: &mut Vec<u8>, mut n: u32) {
    let mut tmp = [0u8; 5];
    let mut i = tmp.len();
    loop {
        i -= 1;
        tmp[i] = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            break;
        }
    }
    for (j, b) in tmp[i..].iter().enumerate() {
        out.push(if i + j == tmp.len() - 1 { *b } else { *b | 0x80 });
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s: Vec<String> = self.0.iter().map(u32::to_string).collect();
        f.write_str(&s.join("."))
    }
}

impl fmt::Debug for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Oid({self})")
    }
}

/// A value in a variable binding.
#[derive(Clone, PartialEq, Debug)]
pub enum Value {
    Integer(i64),
    OctetString(Vec<u8>),
    Null,
    ObjectId(Oid),
    IpAddress([u8; 4]),
    Counter32(u32),
    Gauge32(u32),
    TimeTicks(u32),
    Opaque(Vec<u8>),
    Counter64(u64),
    NoSuchObject,
    NoSuchInstance,
    EndOfMibView,
}

impl Value {
    /// Any numeric type as a signed integer.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Integer(i) => Some(*i),
            Value::Counter32(n) | Value::Gauge32(n) | Value::TimeTicks(n) => Some(i64::from(*n)),
            Value::Counter64(n) => i64::try_from(*n).ok(),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Integer(i) => u64::try_from(*i).ok(),
            Value::Counter32(n) | Value::Gauge32(n) | Value::TimeTicks(n) => Some(u64::from(*n)),
            Value::Counter64(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::OctetString(b) | Value::Opaque(b) => Some(b),
            _ => None,
        }
    }

    /// Text from an octet string: UTF-8 (lossy), control characters other than newline and
    /// tab dropped, surrounding whitespace trimmed.
    pub fn as_text(&self) -> Option<String> {
        let b = self.as_bytes()?;
        let s = String::from_utf8_lossy(b);
        Some(s.chars().filter(|c| !c.is_control() || matches!(c, '\n' | '\t')).collect::<String>().trim().to_string())
    }

    /// The agent has no such object: not a value at all.
    pub fn is_missing(&self) -> bool {
        matches!(self, Value::NoSuchObject | Value::NoSuchInstance | Value::EndOfMibView)
    }
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

pub fn length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
}

/// `tag`, the length of `content`, `content`.
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    length(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

pub fn int(n: i64) -> Vec<u8> {
    tlv(INTEGER, &int_bytes(n))
}

fn int_bytes(n: i64) -> Vec<u8> {
    let b = n.to_be_bytes();
    let mut i = 0;
    while i < 7 && ((b[i] == 0 && b[i + 1] & 0x80 == 0) || (b[i] == 0xff && b[i + 1] & 0x80 != 0)) {
        i += 1;
    }
    b[i..].to_vec()
}

fn uint_bytes(n: u64) -> Vec<u8> {
    let b = n.to_be_bytes();
    let skip = b.iter().take_while(|x| **x == 0).count().min(7);
    let mut v = b[skip..].to_vec();
    if v[0] & 0x80 != 0 {
        v.insert(0, 0);
    }
    v
}

pub fn octets(b: &[u8]) -> Vec<u8> {
    tlv(OCTET_STRING, b)
}

pub fn oid(o: &Oid) -> Vec<u8> {
    tlv(OID, &o.encode())
}

pub fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(SEQUENCE, &parts.concat())
}

pub fn value(v: &Value) -> Vec<u8> {
    match v {
        Value::Integer(i) => int(*i),
        Value::OctetString(b) => octets(b),
        Value::Null => tlv(NULL, &[]),
        Value::ObjectId(o) => oid(o),
        Value::IpAddress(a) => tlv(IP_ADDRESS, a),
        Value::Counter32(n) => tlv(COUNTER32, &uint_bytes(u64::from(*n))),
        Value::Gauge32(n) => tlv(GAUGE32, &uint_bytes(u64::from(*n))),
        Value::TimeTicks(n) => tlv(TIME_TICKS, &uint_bytes(u64::from(*n))),
        Value::Opaque(b) => tlv(OPAQUE, b),
        Value::Counter64(n) => tlv(COUNTER64, &uint_bytes(*n)),
        Value::NoSuchObject => tlv(NO_SUCH_OBJECT, &[]),
        Value::NoSuchInstance => tlv(NO_SUCH_INSTANCE, &[]),
        Value::EndOfMibView => tlv(END_OF_MIB_VIEW, &[]),
    }
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// A cursor over BER data.
#[derive(Clone, Copy)]
pub struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf }
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn rest(&self) -> &'a [u8] {
        self.buf
    }

    /// The next element: its tag and content.
    pub fn read(&mut self) -> Result<(u8, &'a [u8]), Error> {
        let (&tag, rest) = self.buf.split_first().ok_or(Error::Decode("truncated"))?;
        if tag & 0x1f == 0x1f {
            return Err(Error::Decode("multi-byte tags aren't used by SNMP"));
        }
        let (&l0, rest) = rest.split_first().ok_or(Error::Decode("truncated length"))?;
        let (len, rest) = if l0 & 0x80 == 0 {
            (usize::from(l0), rest)
        } else {
            let n = usize::from(l0 & 0x7f);
            if n == 0 || n > 4 || rest.len() < n {
                return Err(Error::Decode("bad length"));
            }
            (rest[..n].iter().fold(0usize, |a, b| (a << 8) | usize::from(*b)), &rest[n..])
        };
        if rest.len() < len {
            return Err(Error::Decode("content past the end"));
        }
        self.buf = &rest[len..];
        Ok((tag, &rest[..len]))
    }

    /// The next element, which must have this tag.
    pub fn expect(&mut self, tag: u8) -> Result<&'a [u8], Error> {
        let (t, c) = self.read()?;
        if t == tag { Ok(c) } else { Err(Error::Decode("unexpected type")) }
    }

    pub fn int(&mut self) -> Result<i64, Error> {
        parse_int(self.expect(INTEGER)?)
    }

    pub fn octets(&mut self) -> Result<&'a [u8], Error> {
        self.expect(OCTET_STRING)
    }

    pub fn sequence(&mut self) -> Result<Reader<'a>, Error> {
        Ok(Reader::new(self.expect(SEQUENCE)?))
    }

    pub fn oid(&mut self) -> Result<Oid, Error> {
        Oid::decode(self.expect(OID)?)
    }

    pub fn value(&mut self) -> Result<Value, Error> {
        let (tag, c) = self.read()?;
        decode_value(tag, c)
    }
}

pub fn parse_int(c: &[u8]) -> Result<i64, Error> {
    if c.is_empty() || c.len() > 8 {
        return Err(Error::Decode("bad integer"));
    }
    let mut n: i64 = if c[0] & 0x80 != 0 { -1 } else { 0 };
    for b in c {
        n = (n << 8) | i64::from(*b);
    }
    Ok(n)
}

fn parse_uint(c: &[u8]) -> Result<u64, Error> {
    let c = if c.len() == 9 && c[0] == 0 { &c[1..] } else { c };
    if c.is_empty() || c.len() > 8 {
        return Err(Error::Decode("bad unsigned integer"));
    }
    Ok(c.iter().fold(0u64, |a, b| (a << 8) | u64::from(*b)))
}

pub fn decode_value(tag: u8, c: &[u8]) -> Result<Value, Error> {
    Ok(match tag {
        INTEGER => Value::Integer(parse_int(c)?),
        OCTET_STRING => Value::OctetString(c.to_vec()),
        NULL => Value::Null,
        OID => Value::ObjectId(Oid::decode(c)?),
        IP_ADDRESS => Value::IpAddress(c.try_into().map_err(|_| Error::Decode("bad IpAddress"))?),
        COUNTER32 => Value::Counter32(u32::try_from(parse_uint(c)?).map_err(|_| Error::Decode("Counter32 too large"))?),
        GAUGE32 => Value::Gauge32(u32::try_from(parse_uint(c)?).map_err(|_| Error::Decode("Gauge32 too large"))?),
        TIME_TICKS => Value::TimeTicks(u32::try_from(parse_uint(c)?).map_err(|_| Error::Decode("TimeTicks too large"))?),
        OPAQUE => Value::Opaque(c.to_vec()),
        COUNTER64 => Value::Counter64(parse_uint(c)?),
        NO_SUCH_OBJECT => Value::NoSuchObject,
        NO_SUCH_INSTANCE => Value::NoSuchInstance,
        END_OF_MIB_VIEW => Value::EndOfMibView,
        _ => return Err(Error::Decode("unknown value type")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oids_roundtrip() {
        for s in ["1.3.6.1.2.1.1.1.0", "1.3.6.1.4.1.8072.3.2.10", "2.100.3", "1.3.6.1.2.1.31.1.1.1.6.100000"] {
            let o = Oid::of(s);
            let enc = oid(&o);
            assert_eq!(Reader::new(&enc).oid().unwrap(), o, "{s}");
        }
        // 1.3.6.1.2.1.1.1.0 is 2b 06 01 02 01 01 01 00.
        assert_eq!(oid(&Oid::of("1.3.6.1.2.1.1.1.0")), [0x06, 8, 0x2b, 6, 1, 2, 1, 1, 1, 0]);
        // A component over 127 takes two bytes.
        assert_eq!(oid(&Oid::of("1.3.200")), [0x06, 3, 0x2b, 0x81, 0x48]);
        assert!(Oid::parse("1").is_none() && Oid::parse("3.1").is_none() && Oid::parse("1.50").is_none() && Oid::parse("a.b").is_none());
        assert!(Oid::of("1.3.6.1.2").starts_with(&Oid::of("1.3.6")) && Oid::of("1.3.6.1.2") < Oid::of("1.3.6.1.10"));
    }

    #[test]
    fn integers_use_the_shortest_form() {
        for (n, enc) in [(0i64, &[0u8][..]), (127, &[0x7f]), (128, &[0, 0x80]), (-1, &[0xff]), (-128, &[0x80]), (-129, &[0xff, 0x7f]), (256, &[1, 0])] {
            assert_eq!(int_bytes(n), enc, "{n}");
            assert_eq!(parse_int(enc).unwrap(), n);
        }
        for n in [i64::MIN, i64::MAX, 0x7fff_ffff, -0x8000_0000] {
            assert_eq!(parse_int(&int_bytes(n)).unwrap(), n);
        }
        // Unsigned values with the top bit set get a leading zero.
        assert_eq!(uint_bytes(0xffff_ffff), [0, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(parse_uint(&uint_bytes(u64::MAX)).unwrap(), u64::MAX);
    }

    #[test]
    fn values_roundtrip() {
        for v in [
            Value::Integer(-5),
            Value::OctetString(b"hello".to_vec()),
            Value::Null,
            Value::ObjectId(Oid::of("1.3.6.1.4.1.9.1.1")),
            Value::IpAddress([10, 0, 0, 1]),
            Value::Counter32(u32::MAX),
            Value::Gauge32(7),
            Value::TimeTicks(123456),
            Value::Counter64(u64::MAX),
            Value::NoSuchInstance,
            Value::EndOfMibView,
        ] {
            let enc = value(&v);
            assert_eq!(Reader::new(&enc).value().unwrap(), v);
        }
    }

    #[test]
    fn long_lengths_and_garbage() {
        let big = vec![7u8; 300];
        let enc = octets(&big);
        assert_eq!(&enc[..4], &[0x04, 0x82, 0x01, 0x2c]);
        assert_eq!(Reader::new(&enc).octets().unwrap(), &big[..]);
        // Truncated, absurd lengths and an indefinite length are errors, not panics.
        for bad in [&[0x04u8, 0x05, 1, 2][..], &[0x04, 0x84, 0xff, 0xff, 0xff, 0xff], &[0x30, 0x80], &[0x04], &[], &[0x1f, 0x01, 0x00]] {
            assert!(Reader::new(bad).read().is_err(), "{bad:?}");
        }
        assert!(Reader::new(&[0x06, 0x02, 0x2b, 0x86]).oid().is_err(), "an OID ending mid-component");
        assert!(Reader::new(&[0x41, 0x05, 1, 0, 0, 0, 0]).value().is_err(), "Counter32 over 32 bits");
    }

    #[test]
    fn text_is_cleaned() {
        assert_eq!(Value::OctetString(b"  Cisco IOS\x00\r\n ".to_vec()).as_text().unwrap(), "Cisco IOS");
        assert_eq!(Value::Integer(1).as_text(), None);
    }
}
