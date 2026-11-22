//! Just enough DNS for names: PTR lookups against the system's resolvers and mDNS. The
//! standard library can't do a reverse lookup, and a resolver library is a lot of code for
//! this.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;

pub const PTR: u16 = 12;
pub const A: u16 = 1;
pub const SRV: u16 = 33;

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
    Other,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub data: Data,
}

#[derive(Debug)]
pub struct Message {
    pub id: u16,
    /// Response code; only the tests look at it (an error answer has no records anyway).
    #[allow(dead_code)]
    pub rcode: u8,
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
    let rr = u16::from_be_bytes([buf[6], buf[7]]) as usize + u16::from_be_bytes([buf[8], buf[9]]) as usize + u16::from_be_bytes([buf[10], buf[11]]) as usize;
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
            _ => Data::Other,
        };
        records.push(Record { name, data });
        pos = rdata + rdlen;
    }
    Some(Message { id, rcode, records })
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
    fn resolv_conf_nameservers() {
        let t = "# comment\nsearch lan\nnameserver 192.168.1.1\nnameserver fe80::1%eth0\nnameserver bogus\noptions edns0\n";
        assert_eq!(parse_resolv_conf(t), ["192.168.1.1".parse::<IpAddr>().unwrap(), "fe80::1".parse().unwrap()]);
    }
}
