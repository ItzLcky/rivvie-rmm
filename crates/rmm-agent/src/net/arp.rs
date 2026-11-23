//! The neighbour table: which MAC address answered for which IP on the local network. A
//! connection attempt to a host on the same subnet makes the kernel ask for its address, so
//! after probing, the table shows every host that is really there, even one that drops
//! pings and refuses nothing.

use std::net::Ipv4Addr;

use super::addr::normalize_mac;

/// Reads the table. Entries that never completed are left out.
pub fn read() -> Vec<(Ipv4Addr, String)> {
    #[cfg(target_os = "linux")]
    if let Ok(text) = std::fs::read_to_string("/proc/net/arp") {
        return parse_proc(&text);
    }
    let out = std::process::Command::new("arp").arg("-a").output();
    match out {
        Ok(o) if o.status.success() => parse_arp_a(&String::from_utf8_lossy(&o.stdout)),
        _ => Vec::new(),
    }
}

#[cfg(any(target_os = "linux", test))]
/// `/proc/net/arp`: `IP address, HW type, Flags, HW address, Mask, Device`. Flag 0x2 is "complete".
pub fn parse_proc(text: &str) -> Vec<(Ipv4Addr, String)> {
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let flags = u32::from_str_radix(f.get(2)?.trim_start_matches("0x"), 16).ok()?;
            if flags & 0x2 == 0 {
                return None;
            }
            Some((f.first()?.parse().ok()?, normalize_mac(f.get(3)?)?))
        })
        .collect()
}

/// `arp -a` on Windows (`  192.168.1.1  aa-bb-cc-dd-ee-ff  dynamic`) and on macOS and BSD
/// (`? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ...`).
pub fn parse_arp_a(text: &str) -> Vec<(Ipv4Addr, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut ip = None;
        let mut mac = None;
        for tok in line.split_whitespace() {
            let t = tok.trim_matches(|c| c == '(' || c == ')');
            if ip.is_none()
                && let Ok(a) = t.parse::<Ipv4Addr>()
            {
                ip = Some(a);
            } else if mac.is_none() {
                mac = normalize_mac(t);
            }
        }
        if let (Some(ip), Some(mac)) = (ip, mac) {
            out.push((ip, mac));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_table_skips_incomplete_entries() {
        let t = "IP address       HW type     Flags       HW address            Mask     Device\n\
                 192.168.1.1      0x1         0x2         AA:BB:CC:DD:EE:01     *        eth0\n\
                 192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        eth0\n\
                 192.168.1.20     0x1         0x6         aa:bb:cc:dd:ee:20     *        eth0\n";
        assert_eq!(parse_proc(t), [("192.168.1.1".parse().unwrap(), "aa:bb:cc:dd:ee:01".into()), ("192.168.1.20".parse().unwrap(), "aa:bb:cc:dd:ee:20".into())]);
    }

    #[test]
    fn windows_and_macos_output_parse() {
        let win = "\nInterface: 192.168.1.5 --- 0x7\n  Internet Address      Physical Address      Type\n  192.168.1.1           aa-bb-cc-dd-ee-01     dynamic   \n  192.168.1.255         ff-ff-ff-ff-ff-ff     static    \n  224.0.0.22            01-00-5e-00-00-16     static    \n";
        assert_eq!(
            parse_arp_a(win),
            [("192.168.1.1".parse().unwrap(), "aa:bb:cc:dd:ee:01".into()), ("224.0.0.22".parse().unwrap(), "01:00:5e:00:00:16".into())]
        );
        let mac = "? (192.168.1.1) at aa:bb:cc:dd:ee:1 on en0 ifscope [ethernet]\n? (192.168.1.9) at (incomplete) on en0 ifscope [ethernet]\n";
        assert_eq!(parse_arp_a(mac), [("192.168.1.1".parse().unwrap(), "aa:bb:cc:dd:ee:01".into())]);
    }
}
