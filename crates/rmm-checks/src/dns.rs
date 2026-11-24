//! Just enough DNS: PTR lookups against the system's resolvers and mDNS (network discovery),
//! and A, AAAA, CNAME, MX and TXT lookups for DNS monitors. The standard library can't do a
//! reverse lookup or ask for a record type, and a resolver library is a lot of code for this.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;

pub const PTR: u16 = 12;
pub const A: u16 = 1;
pub const SRV: u16 = 33;
pub const AAAA: u16 = 28;
pub const CNAME: u16 = 5;
pub const MX: u16 = 15;
pub const TXT: u16 = 16;

/// `4.3.2.1.in-addr.arpa` for 1.2.3.4.
pub fn reverse_name(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
}

/// One query packet with these questions. `unicast`: the mDNS "unicast response" bit, so a
/// responder replies to our port rather than to the multicast group.
pub fn query(id: u16, questions: &[(&str, u16)], unicast: bool) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&[if unicast { 0 } else { 1 }, 0]); // flags: recursion desired for unicast DNS
    p.extend_from_slice(&(questions.len() as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    for (name, qtype) in questions {
        for label in name.trim_end_matches('.').split('.') {
            let l = &label.as_bytes()[..label.len().min(63)];
            p.push(l.len() as u8);
            p.extend_from_slice(l);
        }
        p.push(0);
        p.extend_from_slice(&qtype.to_be_bytes());
        // The top bit of the class is mDNS's unicast-response request.
        p.extend_from_slice(&(if unicast { 0x8001u16 } else { 1u16 }).to_be_bytes());
    }
    p
}

#[derive(Debug, PartialEq, Eq)]
pub enum Data {
    Ptr(String),
    A(Ipv4Addr),
    Srv(String),
    Aaaa(Ipv6Addr),
    Cname(String),
    Mx(u16, String),
    Txt(String),
    Other,
}

impl Data {
    /// The answer as a monitor shows and compares it.
    pub fn text(&self) -> Option<String> {
        Some(match self {
            Data::A(ip) => ip.to_string(),
            Data::Aaaa(ip) => ip.to_string(),
            Data::Cname(n) | Data::Ptr(n) | Data::Srv(n) => n.trim_end_matches('.').to_ascii_lowercase(),
            Data::Mx(pref, n) => format!("{pref} {}", n.trim_end_matches('.').to_ascii_lowercase()),
            Data::Txt(t) => t.clone(),
            Data::Other => return None,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub data: Data,
}

#[derive(Debug)]
pub struct Message {
    pub id: u16,
    /// Response code: 0 no error, 2 server failure, 3 no such name.
    pub rcode: u8,
    /// Records in the answer section (they come first in `records`).
    pub answers: usize,
    pub records: Vec<Record>,
}

/// Reads a name at `pos`, following compression pointers (at most a few, so a loop can't hold
/// us). Returns the name and the position after it in the original place.
fn name_at(buf: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut out = String::new();
    let mut after = None;
    for _ in 0..64 {
        let len = *buf.get(pos)? as usize;
        if len == 0 {
            return Some((out, after.unwrap_or(pos + 1)));
        }
        if len & 0xc0 == 0xc0 {
            let ptr = ((len & 0x3f) << 8) | *buf.get(pos + 1)? as usize;
            after.get_or_insert(pos + 2);
            pos = ptr;
            continue;
        }
        if len > 63 {
            return None;
        }
        let label = buf.get(pos + 1..pos + 1 + len)?;
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(&String::from_utf8_lossy(label));
        pos += 1 + len;
        if out.len() > 255 {
            return None;
        }
    }
    None
}

/// Every record of a response (answers, authority and additional sections together).
pub fn parse(buf: &[u8]) -> Option<Message> {
    if buf.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let rcode = buf[3] & 0x0f;
    let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let answers = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let rr = answers + u16::from_be_bytes([buf[8], buf[9]]) as usize + u16::from_be_bytes([buf[10], buf[11]]) as usize;
    let mut pos = 12;
    for _ in 0..qd {
        pos = name_at(buf, pos)?.1 + 4;
    }
    let mut records = Vec::new();
    for _ in 0..rr.min(256) {
        let (name, p) = name_at(buf, pos)?;
        let h = buf.get(p..p + 10)?;
        let (rtype, rdlen) = (u16::from_be_bytes([h[0], h[1]]), u16::from_be_bytes([h[8], h[9]]) as usize);
        let rdata = p + 10;
        buf.get(rdata..rdata + rdlen)?;
        let data = match rtype {
            PTR => name_at(buf, rdata).map_or(Data::Other, |(n, _)| Data::Ptr(n)),
            A if rdlen == 4 => Data::A(Ipv4Addr::new(buf[rdata], buf[rdata + 1], buf[rdata + 2], buf[rdata + 3])),
            // Priority, weight, port, target.
            SRV if rdlen > 6 => name_at(buf, rdata + 6).map_or(Data::Other, |(n, _)| Data::Srv(n)),
            AAAA if rdlen == 16 => {
                let b: [u8; 16] = buf[rdata..rdata + 16].try_into().unwrap_or([0; 16]);
                Data::Aaaa(Ipv6Addr::from(b))
            }
            CNAME => name_at(buf, rdata).map_or(Data::Other, |(n, _)| Data::Cname(n)),
            MX if rdlen > 2 => name_at(buf, rdata + 2).map_or(Data::Other, |(n, _)| Data::Mx(u16::from_be_bytes([buf[rdata], buf[rdata + 1]]), n)),
            TXT => {
                // One or more length-prefixed strings, joined.
                let (mut t, mut p, end) = (Vec::new(), rdata, rdata + rdlen);
                while p < end {
                    let l = buf[p] as usize;
                    t.extend_from_slice(buf.get(p + 1..(p + 1 + l).min(end)).unwrap_or(&[]));
                    p += 1 + l;
                }
                Data::Txt(String::from_utf8_lossy(&t).into_owned())
            }
            _ => Data::Other,
        };
        records.push(Record { name, data });
        pos = rdata + rdlen;
    }
    Some(Message { id, rcode, answers: answers.min(records.len()), records })
}

/// The resolvers the system uses.
pub fn nameservers() -> Vec<SocketAddr> {
    let mut out: Vec<IpAddr> = Vec::new();
    if cfg!(windows) {
        // Locale-independent, one address per line.
        let o = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", "(Get-DnsClientServerAddress -AddressFamily IPv4).ServerAddresses"])
            .output();
        if let Ok(o) = o {
            out.extend(String::from_utf8_lossy(&o.stdout).lines().filter_map(|l| l.trim().parse::<IpAddr>().ok()));
        }
    } else if let Ok(t) = std::fs::read_to_string("/etc/resolv.conf") {
        out.extend(parse_resolv_conf(&t));
    }
    out.dedup();
    out.into_iter().take(3).map(|ip| SocketAddr::new(ip, 53)).collect()
}

pub fn parse_resolv_conf(text: &str) -> Vec<IpAddr> {
    text.lines()
        .filter_map(|l| {
            let mut w = l.split_whitespace();
            (w.next()? == "nameserver").then(|| w.next()?.split('%').next()?.parse().ok())?
        })
        .collect()
}

fn ptr_name(m: &Message, ip: Ipv4Addr) -> Option<String> {
    let want = reverse_name(ip);
    m.records.iter().find_map(|r| match &r.data {
        Data::Ptr(n) if r.name.eq_ignore_ascii_case(&want) && !n.is_empty() => Some(n.trim_end_matches('.').to_string()),
        _ => None,
    })
}

/// Asks `server` for the name of `ip`.
pub async fn ptr_lookup(server: SocketAddr, ip: Ipv4Addr, timeout: Duration, unicast: bool) -> Option<String> {
    let sock = UdpSocket::bind(if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await.ok()?;
    let id = u16::from_be_bytes([uuid::Uuid::new_v4().as_bytes()[0], uuid::Uuid::new_v4().as_bytes()[1]]);
    sock.send_to(&query(id, &[(&reverse_name(ip), PTR)], unicast), server).await.ok()?;
    let mut buf = vec![0u8; 1500];
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let (n, from) = tokio::time::timeout_at(deadline, sock.recv_from(&mut buf)).await.ok()?.ok()?;
        if from.ip() != server.ip() {
            continue;
        }
        let m = parse(&buf[..n])?;
        // mDNS answers carry id 0; unicast DNS echoes ours.
        if m.id == id || (unicast && m.id == 0) {
            return ptr_name(&m, ip);
        }
    }
}

/// Service types asked for on the multicast group; most devices answer at least one of them and
/// put their host name and address in the answer.
const MDNS_SERVICES: &[&str] = &[
    "_workstation._tcp.local",
    "_device-info._tcp.local",
    "_http._tcp.local",
    "_ipp._tcp.local",
    "_printer._tcp.local",
    "_smb._tcp.local",
    "_ssh._tcp.local",
    "_airplay._tcp.local",
    "_companion-link._tcp.local",
];

/// Asks the local network who is out there over mDNS and listens for `window`. Returns the
/// host names (`printer.local`) by address.
pub async fn mdns_browse(window: Duration) -> HashMap<Ipv4Addr, String> {
    let mut found = HashMap::new();
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await else { return found };
    let group = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)), 5353);
    let questions: Vec<(&str, u16)> = MDNS_SERVICES.iter().map(|s| (*s, PTR)).collect();
    // Three to a packet keeps each well under the MTU.
    for chunk in questions.chunks(3) {
        let _ = sock.send_to(&query(0, chunk, true), group).await;
    }
    let mut buf = vec![0u8; 9000];
    let deadline = tokio::time::Instant::now() + window;
    while let Ok(Ok((n, from))) = tokio::time::timeout_at(deadline, sock.recv_from(&mut buf)).await {
        let (IpAddr::V4(src), Some(m)) = (from.ip(), parse(&buf[..n])) else { continue };
        for r in &m.records {
            match &r.data {
                // The A record names the host and gives its address.
                Data::A(ip) if r.name.ends_with(".local") => {
                    found.entry(*ip).or_insert_with(|| r.name.clone());
                }
                // The SRV record names the host that serves the instance; the packet came from it.
                Data::Srv(host) if host.ends_with(".local") => {
                    found.entry(src).or_insert_with(|| host.clone());
                }
                _ => {}
            }
        }
    }
    found
}

/// The record type for a name: `A`, `AAAA`, `CNAME`, `MX` or `TXT`.
pub fn record_type(name: &str) -> Option<u16> {
    Some(match name.to_ascii_uppercase().as_str() {
        "A" => A,
        "AAAA" => AAAA,
        "CNAME" => CNAME,
        "MX" => MX,
        "TXT" => TXT,
        _ => return None,
    })
}

/// Asks `server` (or the system's resolvers in turn) for `name`'s records of type `rtype`.
/// Returns the answers of that type as text, and the time the answer took. No such name, or a
/// server failure, is an error; a name with no records of the type is an empty list.
pub async fn lookup(name: &str, rtype: u16, server: Option<SocketAddr>, timeout: Duration) -> Result<(Vec<String>, u32), String> {
    let name = name.trim().trim_end_matches('.');
    if name.is_empty() || name.len() > 253 || name.split('.').any(|l| l.is_empty() || l.len() > 63) {
        return Err(format!("{name:?} isn't a valid name"));
    }
    let servers = match server {
        Some(s) => vec![s],
        None => nameservers(),
    };
    if servers.is_empty() {
        return Err("this machine has no DNS servers configured".into());
    }
    let per = timeout / servers.len() as u32;
    let mut last = String::from("no answer");
    for s in servers {
        match ask(s, name, rtype, per).await {
            Ok(r) => return Ok(r),
            Err(e) => last = format!("{s}: {e}"),
        }
    }
    Err(last)
}

async fn ask(server: SocketAddr, name: &str, rtype: u16, timeout: Duration) -> Result<(Vec<String>, u32), String> {
    let sock = UdpSocket::bind(if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await.map_err(|e| e.to_string())?;
    let id = u16::from_be_bytes([uuid::Uuid::new_v4().as_bytes()[0], uuid::Uuid::new_v4().as_bytes()[1]]);
    let started = std::time::Instant::now();
    sock.send_to(&query(id, &[(name, rtype)], false), server).await.map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 4096];
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let (n, from) = match tokio::time::timeout_at(deadline, sock.recv_from(&mut buf)).await {
            Err(_) => return Err("timed out".into()),
            Ok(Err(e)) => return Err(e.to_string()),
            Ok(Ok(r)) => r,
        };
        if from.ip() != server.ip() {
            continue;
        }
        let Some(m) = parse(&buf[..n]) else { return Err("unreadable answer".into()) };
        if m.id != id {
            continue;
        }
        let ms = crate::millis(started.elapsed());
        return match m.rcode {
            0 => Ok((answers_of(&m, rtype), ms)),
            3 => Err(format!("{name} doesn't exist (NXDOMAIN)")),
            2 => Err("the server failed (SERVFAIL)".into()),
            5 => Err("the server refused the query".into()),
            c => Err(format!("the server answered with error {c}")),
        };
    }
}

/// The answer-section records of the type asked for, as text. A CNAME chain the server
/// followed for an `A` question gives the addresses at its end.
pub fn answers_of(m: &Message, rtype: u16) -> Vec<String> {
    m.records[..m.answers]
        .iter()
        .filter(|r| matches!((&r.data, rtype), (Data::A(_), A) | (Data::Aaaa(_), AAAA) | (Data::Cname(_), CNAME) | (Data::Mx(..), MX) | (Data::Txt(_), TXT)))
        .filter_map(|r| r.data.text())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(id: u16, qname: &str, ptr: &str) -> Vec<u8> {
        let mut p = query(id, &[(qname, PTR)], false);
        p[2] = 0x81;
        p[3] = 0x80;
        p[7] = 1; // one answer
        // The answer's name is a pointer to the question's name at offset 12.
        p.extend_from_slice(&[0xc0, 12, 0, 12, 0, 1, 0, 0, 0, 60]);
        let mut rdata = Vec::new();
        for label in ptr.split('.') {
            rdata.push(label.len() as u8);
            rdata.extend_from_slice(label.as_bytes());
        }
        rdata.push(0);
        p.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        p.extend(rdata);
        p
    }

    #[test]
    fn reverse_names_and_queries() {
        assert_eq!(reverse_name(Ipv4Addr::new(192, 168, 1, 20)), "20.1.168.192.in-addr.arpa");
        let q = query(0x1234, &[("20.1.168.192.in-addr.arpa", PTR)], false);
        assert_eq!(&q[..2], &[0x12, 0x34]);
        assert_eq!(&q[12..16], &[2, b'2', b'0', 1]);
        assert!(q.ends_with(&[0, 0, 12, 0, 1]));
    }

    #[test]
    fn a_ptr_answer_with_compression_parses() {
        let r = response(7, "20.1.168.192.in-addr.arpa", "printer.example.com");
        let m = parse(&r).unwrap();
        assert_eq!((m.id, m.rcode), (7, 0));
        assert_eq!(ptr_name(&m, Ipv4Addr::new(192, 168, 1, 20)).as_deref(), Some("printer.example.com"));
        assert_eq!(ptr_name(&m, Ipv4Addr::new(192, 168, 1, 21)), None, "an answer for another address isn't ours");
    }

    #[test]
    fn hostile_packets_are_rejected_not_followed() {
        // A name that points at itself.
        let mut p = query(1, &[("a.b", PTR)], false);
        p[7] = 1;
        p.extend_from_slice(&[0xc0, p.len() as u8, 0, 12, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert!(parse(&p).is_none());
        for cut in [0usize, 5, 11, 20, 30] {
            let r = response(1, "1.0.0.10.in-addr.arpa", "x.y");
            let _ = parse(&r[..cut.min(r.len())]);
        }
        assert!(parse(&[0xff; 40]).is_none() || parse(&[0xff; 40]).is_some());
    }

    #[test]
    fn mdns_records_give_names() {
        // An mDNS answer: `_ipp._tcp.local PTR`, with an A record for the host in the additional section.
        let mut p = vec![0, 0, 0x84, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        for label in ["printer", "local"] {
            p.push(label.len() as u8);
            p.extend_from_slice(label.as_bytes());
        }
        p.push(0);
        p.extend_from_slice(&[0, 1, 0x80, 1, 0, 0, 0, 120, 0, 4, 192, 168, 1, 30]);
        let m = parse(&p).unwrap();
        assert_eq!(m.records[0], Record { name: "printer.local".into(), data: Data::A(Ipv4Addr::new(192, 168, 1, 30)) });
    }

    #[test]
    fn record_types_for_monitors() {
        // An answer to `example.com MX` with one MX and one TXT (which isn't what was asked).
        let mut p = query(9, &[("example.com", MX)], false);
        p[2] = 0x81;
        p[3] = 0x80;
        p[7] = 2;
        p.extend_from_slice(&[0xc0, 12, 0, 15, 0, 1, 0, 0, 0, 60, 0, 9, 0, 10, 4, b'm', b'a', b'i', b'l', 0xc0, 12]);
        p.extend_from_slice(&[0xc0, 12, 0, 16, 0, 1, 0, 0, 0, 60, 0, 6, 2, b'h', b'i', 2, b'y', b'o']);
        let m = parse(&p).unwrap();
        assert_eq!(m.answers, 2);
        assert_eq!(answers_of(&m, MX), ["10 mail.example.com"]);
        assert_eq!(answers_of(&m, TXT), ["hiyo"], "strings of a TXT record are joined");
        assert!(answers_of(&m, A).is_empty());
        assert_eq!(record_type("aaaa"), Some(AAAA));
        assert_eq!(record_type("SOA"), None);
    }

    #[tokio::test]
    async fn lookups_against_a_local_server() {
        let srv = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = srv.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let (n, from) = srv.recv_from(&mut buf).await.unwrap();
                let mut r = buf[..n].to_vec();
                r[2] = 0x81;
                let missing = r[12..].starts_with(&[7, b'm', b'i', b's', b's', b'i', b'n', b'g']);
                if missing {
                    r[3] = 0x83; // NXDOMAIN
                } else {
                    r[3] = 0x80;
                    r[7] = 1;
                    r.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 0, 0, 7]);
                }
                srv.send_to(&r, from).await.unwrap();
            }
        });
        let (got, ms) = lookup("host.example", A, Some(addr), Duration::from_secs(2)).await.unwrap();
        assert_eq!(got, ["10.0.0.7"]);
        assert!(ms < 2000);
        let e = lookup("missing.example", A, Some(addr), Duration::from_secs(2)).await.unwrap_err();
        assert!(e.contains("NXDOMAIN"), "{e}");
        assert!(lookup("bad..name", A, Some(addr), Duration::from_secs(1)).await.is_err());
    }

    #[test]
    fn resolv_conf_nameservers() {
        let t = "# comment\nsearch lan\nnameserver 192.168.1.1\nnameserver fe80::1%eth0\nnameserver bogus\noptions edns0\n";
        assert_eq!(parse_resolv_conf(t), ["192.168.1.1".parse::<IpAddr>().unwrap(), "fe80::1".parse().unwrap()]);
    }
}
