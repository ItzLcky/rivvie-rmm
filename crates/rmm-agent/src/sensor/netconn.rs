//! Network connections, polled: new established connections and listening sockets become
//! `connect` / `listen` events with the owning process.

use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Conn {
    pub protocol: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    /// `established` or `listen`.
    pub state: String,
    pub pid: Option<u32>,
}

/// `0100007F:1F90` (little-endian IPv4) or the 32-hex-digit IPv6 form, from /proc/net/tcp*.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn parse_proc_addr(s: &str) -> Option<(String, u16)> {
    let (a, p) = s.split_once(':')?;
    let port = u16::from_str_radix(p, 16).ok()?;
    let addr = match a.len() {
        8 => {
            let n = u32::from_str_radix(a, 16).ok()?;
            std::net::Ipv4Addr::from(n.to_le_bytes()).to_string()
        }
        32 => {
            let mut b = [0u8; 16];
            for i in 0..4 {
                let w = u32::from_str_radix(&a[i * 8..i * 8 + 8], 16).ok()?;
                b[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
            }
            let v6 = std::net::Ipv6Addr::from(b);
            v6.to_ipv4_mapped().map(|v4| v4.to_string()).unwrap_or_else(|| v6.to_string())
        }
        _ => return None,
    };
    Some((addr, port))
}

/// One /proc/net/tcp(6) table: (local, remote, state, inode).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn parse_proc_net(table: &str, protocol: &str) -> Vec<(Conn, u64)> {
    table
        .lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 10 {
                return None;
            }
            let state = match f[3] {
                "01" => "established",
                "0A" => "listen",
                _ => return None,
            };
            let (la, lp) = parse_proc_addr(f[1])?;
            let (ra, rp) = parse_proc_addr(f[2])?;
            let inode = f[9].parse().ok()?;
            Some((Conn { protocol: protocol.into(), local_addr: la, local_port: lp, remote_addr: ra, remote_port: rp, state: state.into(), pid: None }, inode))
        })
        .collect()
}

#[cfg(target_os = "linux")]
pub fn list() -> Vec<Conn> {
    use std::collections::HashMap;
    let mut conns = Vec::new();
    for (file, proto) in [("/proc/net/tcp", "tcp"), ("/proc/net/tcp6", "tcp")] {
        if let Ok(t) = std::fs::read_to_string(file) {
            conns.extend(parse_proc_net(&t, proto));
        }
    }
    if conns.is_empty() {
        return vec![];
    }
    let wanted: HashSet<u64> = conns.iter().map(|c| c.1).collect();
    let mut owner: HashMap<u64, u32> = HashMap::new();
    for e in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() else { continue };
        for fd in std::fs::read_dir(e.path().join("fd")).into_iter().flatten().flatten() {
            if let Ok(link) = std::fs::read_link(fd.path()) {
                let l = link.to_string_lossy();
                if let Some(ino) = l.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')).and_then(|s| s.parse::<u64>().ok())
                    && wanted.contains(&ino)
                {
                    owner.insert(ino, pid);
                }
            }
        }
    }
    conns.into_iter().map(|(mut c, ino)| {
        c.pid = owner.get(&ino).copied();
        c
    }).collect()
}

/// `netstat -ano -p TCP` (and TCPv6) on Windows.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn parse_netstat_windows(out: &str) -> Vec<Conn> {
    let split = |s: &str| -> Option<(String, u16)> {
        let (a, p) = s.rsplit_once(':')?;
        Some((a.trim_matches(['[', ']']).to_string(), p.parse().ok()?))
    };
    out.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() != 5 || !f[0].eq_ignore_ascii_case("tcp") {
                return None;
            }
            let state = match f[3] {
                "ESTABLISHED" => "established",
                "LISTENING" => "listen",
                _ => return None,
            };
            let (la, lp) = split(f[1])?;
            let (ra, rp) = split(f[2])?;
            Some(Conn { protocol: "tcp".into(), local_addr: la, local_port: lp, remote_addr: ra, remote_port: rp, state: state.into(), pid: f[4].parse().ok() })
        })
        .collect()
}

/// `lsof -nP -iTCP -sTCP:ESTABLISHED,LISTEN` on macOS.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn parse_lsof(out: &str) -> Vec<Conn> {
    let split = |s: &str| -> Option<(String, u16)> {
        let (a, p) = s.rsplit_once(':')?;
        Some((a.trim_matches(['[', ']']).to_string(), p.parse().ok()?))
    };
    out.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 10 {
                return None;
            }
            let pid = f[1].parse().ok();
            let name = f[8];
            let state = f[9].trim_matches(['(', ')']);
            let (state, (la, lp), (ra, rp)) = match state {
                "ESTABLISHED" => {
                    let (l, r) = name.split_once("->")?;
                    ("established", split(l)?, split(r)?)
                }
                "LISTEN" => ("listen", split(name)?, (String::new(), 0)),
                _ => return None,
            };
            Some(Conn { protocol: "tcp".into(), local_addr: la, local_port: lp, remote_addr: ra, remote_port: rp, state: state.into(), pid })
        })
        .collect()
}

#[cfg(windows)]
pub fn list() -> Vec<Conn> {
    let log = crate::patch::cmd::Log::default();
    let opts = crate::patch::cmd::Opts { timeout: std::time::Duration::from_secs(30), log: false, ..Default::default() };
    crate::patch::cmd::output(&log, "netstat.exe", &["-ano"], opts).map(|o| parse_netstat_windows(&o.stdout)).unwrap_or_default()
}

#[cfg(target_os = "macos")]
pub fn list() -> Vec<Conn> {
    let log = crate::patch::cmd::Log::default();
    let opts = crate::patch::cmd::Opts { timeout: std::time::Duration::from_secs(30), log: false, ..Default::default() };
    crate::patch::cmd::output(&log, "lsof", &["-nP", "-iTCP", "-sTCP:ESTABLISHED,LISTEN"], opts).map(|o| parse_lsof(&o.stdout)).unwrap_or_default()
}

#[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
pub fn list() -> Vec<Conn> {
    vec![]
}

/// Remembers what was already reported.
#[derive(Default)]
pub struct Tracker {
    seen: HashSet<Conn>,
    primed: bool,
}

impl Tracker {
    /// Connections new since the last call. The first call reports listeners only (what's
    /// already connected at startup isn't news).
    pub fn diff(&mut self, now: Vec<Conn>) -> Vec<Conn> {
        let now: HashSet<Conn> = now.into_iter().collect();
        let new: Vec<Conn> = now.iter().filter(|c| !self.seen.contains(*c) && (self.primed || c.state == "listen")).cloned().collect();
        self.seen = now;
        self.primed = true;
        new
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_net_parses() {
        let t = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000\n   1: 0500000A:C350 1471CB0C:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 23456 1 0000\n   2: 0500000A:C351 1471CB0C:01BB 06 00000000:00000000 00:00000000 00000000  1000        0 0 1 0000\n";
        let c = parse_proc_net(t, "tcp");
        assert_eq!(c.len(), 2, "TIME_WAIT is skipped");
        assert_eq!((c[0].0.local_addr.as_str(), c[0].0.local_port, c[0].0.state.as_str(), c[0].1), ("127.0.0.1", 8080, "listen", 12345));
        assert_eq!((c[1].0.remote_addr.as_str(), c[1].0.remote_port), ("12.203.113.20", 443));
        assert_eq!(parse_proc_addr("0000000000000000FFFF00000100007F:0016"), Some(("127.0.0.1".into(), 22)));
        assert_eq!(parse_proc_addr("00000000000000000000000001000000:0050"), Some(("::1".into(), 80)));
    }

    #[test]
    fn netstat_and_lsof_parse() {
        let ns = "\r\nActive Connections\r\n\r\n  Proto  Local Address          Foreign Address        State           PID\r\n  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1012\r\n  TCP    10.0.0.5:50123         140.82.112.3:443       ESTABLISHED     4242\r\n  TCP    [::1]:5432             [::1]:50211            ESTABLISHED     900\r\n  UDP    0.0.0.0:5353           *:*                                    2000\r\n";
        let c = parse_netstat_windows(ns);
        assert_eq!(c.len(), 3);
        assert_eq!((c[1].remote_addr.as_str(), c[1].remote_port, c[1].pid), ("140.82.112.3", 443, Some(4242)));
        assert_eq!(c[2].local_addr, "::1");
        let ls = "COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\nlaunchd     1 root   10u  IPv6 0x1      0t0  TCP *:22 (LISTEN)\nSafari    600 bob    20u  IPv4 0x2      0t0  TCP 10.0.0.5:50123->17.253.144.10:443 (ESTABLISHED)\n";
        let c = parse_lsof(ls);
        assert_eq!(c.len(), 2);
        assert_eq!((c[1].pid, c[1].remote_port, c[0].state.as_str()), (Some(600), 443, "listen"));
    }

    #[test]
    fn tracker_reports_new_ones() {
        let c = |p: u16, s: &str| Conn { protocol: "tcp".into(), local_addr: "a".into(), local_port: p, remote_addr: "b".into(), remote_port: 1, state: s.into(), pid: None };
        let mut t = Tracker::default();
        assert_eq!(t.diff(vec![c(1, "established"), c(2, "listen")]).len(), 1, "only listeners at first");
        assert!(t.diff(vec![c(1, "established"), c(2, "listen")]).is_empty());
        assert_eq!(t.diff(vec![c(1, "established"), c(3, "established")]), vec![c(3, "established")]);
    }
}
