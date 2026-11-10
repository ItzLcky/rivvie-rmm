//! Network isolation: block everything except the management channel to the RMM server
//! (plus DNS and DHCP, so the agent can keep finding the server and the machine keeps its
//! address). Used to contain a compromised machine while it's investigated.
//!
//! | OS | Mechanism | Release |
//! |---|---|---|
//! | Linux | an `inet rmm_isolation` nftables table (drop policy, so other tables can't let traffic past); `iptables` chains when `nft` is missing | delete the table / chains |
//! | Windows | Windows Firewall: export the policy, block by default, disable every rule, add ours | import the exported policy |
//! | macOS | a pf ruleset | reload `/etc/pf.conf` |
//!
//! The state is kept in `state_dir()/isolation.json`, so the rules come back after a reboot
//! (when the agent starts) and the server addresses are re-resolved while isolated.

use std::net::{IpAddr, ToSocketAddrs};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct State {
    pub isolated: bool,
    #[serde(default)]
    pub since: Option<DateTime<Utc>>,
    /// Extra hosts allowed besides the server.
    #[serde(default)]
    pub extra: Vec<String>,
    #[serde(default)]
    pub ips: Vec<IpAddr>,
    #[serde(default)]
    pub method: String,
}

fn state_path() -> PathBuf {
    crate::config::state_dir().join("isolation.json")
}

pub fn state() -> State {
    std::fs::read(state_path()).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

fn save(s: &State) -> Result<()> {
    crate::config::state_subdir("")?;
    std::fs::write(state_path(), serde_json::to_vec_pretty(s)?)?;
    Ok(())
}

/// `https://rmm.example.com:8443/x` -> ("rmm.example.com", 8443); `host:port`, `host`, IPs.
pub fn host_port(s: &str) -> Option<(String, u16)> {
    let (scheme_port, rest) = match s.split_once("://") {
        Some(("https" | "wss", r)) => (443, r),
        Some(("http" | "ws", r)) => (80, r),
        Some((_, r)) => (443, r),
        None => (443, s),
    };
    let authority = rest.split('/').next()?.trim();
    if authority.is_empty() {
        return None;
    }
    if let Some(v6) = authority.strip_prefix('[') {
        let (host, after) = v6.split_once(']')?;
        let port = after.strip_prefix(':').and_then(|p| p.parse().ok()).unwrap_or(scheme_port);
        return Some((host.to_string(), port));
    }
    if authority.parse::<std::net::Ipv6Addr>().is_ok() {
        return Some((authority.to_string(), scheme_port));
    }
    match authority.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() => Some((h.to_string(), p.parse().ok()?)),
        _ => Some((authority.to_string(), scheme_port)),
    }
}

/// The addresses to keep reachable: the server and any extra hosts.
pub fn resolve(server_url: &str, extra: &[String]) -> Result<Vec<IpAddr>> {
    let mut ips = Vec::new();
    for target in std::iter::once(server_url.to_string()).chain(extra.iter().cloned()) {
        let Some((host, port)) = host_port(&target) else { continue };
        let addrs = (host.as_str(), port).to_socket_addrs().with_context(|| format!("resolving {host}"))?;
        for a in addrs {
            if !ips.contains(&a.ip()) {
                ips.push(a.ip());
            }
        }
    }
    if ips.is_empty() {
        bail!("couldn't resolve the server's address; not isolating (the agent would lose its connection)");
    }
    ips.sort();
    Ok(ips)
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn split(ips: &[IpAddr]) -> (Vec<String>, Vec<String>) {
    let v4 = ips.iter().filter(|i| i.is_ipv4()).map(|i| i.to_string()).collect();
    let v6 = ips.iter().filter(|i| i.is_ipv6()).map(|i| i.to_string()).collect();
    (v4, v6)
}

/// The nftables ruleset. Loading it replaces any earlier version atomically.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn nft_ruleset(ips: &[IpAddr]) -> String {
    let (v4, v6) = split(ips);
    let allow = |dir: &str| {
        let mut s = String::new();
        if !v4.is_empty() {
            s.push_str(&format!("    ip {dir} {{ {} }} accept\n", v4.join(", ")));
        }
        if !v6.is_empty() {
            s.push_str(&format!("    ip6 {dir} {{ {} }} accept\n", v6.join(", ")));
        }
        s
    };
    format!(
        "table inet rmm_isolation {{}}\ndelete table inet rmm_isolation\ntable inet rmm_isolation {{\n  chain input {{\n    type filter hook input priority -10; policy drop;\n    iif \"lo\" accept\n    ct state established,related accept\n{}    udp sport 67 udp dport 68 accept\n    icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert }} accept\n  }}\n  chain output {{\n    type filter hook output priority -10; policy drop;\n    oif \"lo\" accept\n    ct state established,related accept\n{}    udp dport 53 accept\n    tcp dport 53 accept\n    udp sport 68 udp dport 67 accept\n    icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit }} accept\n  }}\n}}\n",
        allow("saddr"),
        allow("daddr")
    )
}

/// iptables/ip6tables commands, for machines without nft.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn iptables_cmds(ips: &[IpAddr]) -> Vec<(&'static str, Vec<String>)> {
    let (v4, v6) = split(ips);
    let mut out = Vec::new();
    for (bin, list) in [("iptables", v4), ("ip6tables", v6)] {
        let a = |args: &[&str]| (bin, args.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        out.push(a(&["-N", "RMM-ISO-IN"]));
        out.push(a(&["-N", "RMM-ISO-OUT"]));
        out.push(a(&["-A", "RMM-ISO-IN", "-i", "lo", "-j", "ACCEPT"]));
        out.push(a(&["-A", "RMM-ISO-IN", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]));
        out.push(a(&["-A", "RMM-ISO-OUT", "-o", "lo", "-j", "ACCEPT"]));
        out.push(a(&["-A", "RMM-ISO-OUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]));
        for ip in &list {
            out.push(a(&["-A", "RMM-ISO-IN", "-s", ip, "-j", "ACCEPT"]));
            out.push(a(&["-A", "RMM-ISO-OUT", "-d", ip, "-j", "ACCEPT"]));
        }
        out.push(a(&["-A", "RMM-ISO-OUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT"]));
        out.push(a(&["-A", "RMM-ISO-OUT", "-p", "tcp", "--dport", "53", "-j", "ACCEPT"]));
        out.push(a(&["-A", "RMM-ISO-OUT", "-p", "udp", "--dport", "67", "-j", "ACCEPT"]));
        out.push(a(&["-A", "RMM-ISO-IN", "-p", "udp", "--sport", "67", "-j", "ACCEPT"]));
        out.push(a(&["-A", "RMM-ISO-IN", "-j", "DROP"]));
        out.push(a(&["-A", "RMM-ISO-OUT", "-j", "DROP"]));
        out.push(a(&["-I", "INPUT", "1", "-j", "RMM-ISO-IN"]));
        out.push(a(&["-I", "OUTPUT", "1", "-j", "RMM-ISO-OUT"]));
    }
    out
}

/// Windows Firewall commands after the policy has been exported.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn netsh_cmds(ips: &[IpAddr]) -> Vec<Vec<String>> {
    let list = ips.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",");
    let c = |s: &str| s.split(' ').map(str::to_string).collect::<Vec<_>>();
    vec![
        c("advfirewall set allprofiles state on"),
        c("advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound"),
        c("advfirewall firewall set rule name=all new enable=no"),
        c(&format!("advfirewall firewall add rule name=RMM-isolation-server dir=out action=allow remoteip={list}")),
        c(&format!("advfirewall firewall add rule name=RMM-isolation-server dir=in action=allow remoteip={list}")),
        c("advfirewall firewall add rule name=RMM-isolation-dns dir=out action=allow protocol=UDP remoteport=53"),
        c("advfirewall firewall add rule name=RMM-isolation-dns dir=out action=allow protocol=TCP remoteport=53"),
        c("advfirewall firewall add rule name=RMM-isolation-dhcp dir=out action=allow protocol=UDP localport=68 remoteport=67"),
    ]
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn pf_rules(ips: &[IpAddr]) -> String {
    let list = ips.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", ");
    format!(
        "set skip on lo0\nblock drop all\npass out quick proto {{ tcp udp }} to any port 53 keep state\npass out quick proto udp from any port 68 to any port 67 keep state\npass quick to {{ {list} }} keep state\npass quick from {{ {list} }} keep state\n"
    )
}

fn run(program: &str, args: &[String], input: Option<&str>) -> Result<()> {
    use std::io::Write;
    let mut cmd = std::process::Command::new(program);
    cmd.args(args).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    if input.is_some() {
        cmd.stdin(std::process::Stdio::piped());
    }
    let mut child = cmd.spawn().with_context(|| format!("starting {program}"))?;
    if let Some(i) = input
        && let Some(mut s) = child.stdin.take()
    {
        s.write_all(i.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("{program} {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply(ips: &[IpAddr]) -> Result<String> {
    if crate::patch::cmd::which("nft") {
        run("nft", &["-f".into(), "-".into()], Some(&nft_ruleset(ips)))?;
        return Ok("nftables".into());
    }
    if crate::patch::cmd::which("iptables") {
        remove_iptables();
        for (bin, args) in iptables_cmds(ips) {
            if bin == "ip6tables" && !crate::patch::cmd::which("ip6tables") {
                continue;
            }
            run(bin, &args, None)?;
        }
        return Ok("iptables".into());
    }
    bail!("neither nft nor iptables is installed")
}

#[cfg(target_os = "linux")]
fn remove_iptables() {
    for bin in ["iptables", "ip6tables"] {
        let r = |a: &[&str]| run(bin, &a.iter().map(|s| s.to_string()).collect::<Vec<_>>(), None);
        while r(&["-D", "INPUT", "-j", "RMM-ISO-IN"]).is_ok() {}
        while r(&["-D", "OUTPUT", "-j", "RMM-ISO-OUT"]).is_ok() {}
        for c in ["RMM-ISO-IN", "RMM-ISO-OUT"] {
            let _ = r(&["-F", c]);
            let _ = r(&["-X", c]);
        }
    }
}

#[cfg(target_os = "linux")]
fn remove(method: &str) -> Result<()> {
    match method {
        "iptables" => {
            remove_iptables();
            Ok(())
        }
        _ => run("nft", &["delete".into(), "table".into(), "inet".into(), "rmm_isolation".into()], None).or_else(|e| {
            if e.to_string().contains("No such file") { Ok(()) } else { Err(e) }
        }),
    }
}

#[cfg(windows)]
fn backup_path() -> PathBuf {
    crate::config::state_dir().join("isolation-firewall.wfw")
}

#[cfg(windows)]
fn apply(ips: &[IpAddr]) -> Result<String> {
    let backup = backup_path();
    // Only the first isolation exports: a re-apply must not overwrite the real policy with ours.
    if !backup.exists() {
        crate::config::state_subdir("")?;
        run("netsh", &["advfirewall".into(), "export".into(), backup.to_string_lossy().into_owned()], None)?;
    } else {
        let _ = run("netsh", &["advfirewall".into(), "firewall".into(), "delete".into(), "rule".into(), "name=RMM-isolation-server".into()], None);
    }
    for args in netsh_cmds(ips) {
        run("netsh", &args, None)?;
    }
    Ok("windows-firewall".into())
}

#[cfg(windows)]
fn remove(_: &str) -> Result<()> {
    let backup = backup_path();
    if backup.exists() {
        run("netsh", &["advfirewall".into(), "import".into(), backup.to_string_lossy().into_owned()], None)?;
        let _ = std::fs::remove_file(backup);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn apply(ips: &[IpAddr]) -> Result<String> {
    let path = crate::config::state_subdir("")?.join("isolation.pf.conf");
    std::fs::write(&path, pf_rules(ips))?;
    run("pfctl", &["-E".into(), "-f".into(), path.to_string_lossy().into_owned()], None)?;
    Ok("pf".into())
}

#[cfg(target_os = "macos")]
fn remove(_: &str) -> Result<()> {
    run("pfctl", &["-f".into(), "/etc/pf.conf".into()], None)
}

#[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
fn apply(_: &[IpAddr]) -> Result<String> {
    bail!("isolation isn't supported on this OS")
}

#[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
fn remove(_: &str) -> Result<()> {
    Ok(())
}

/// Isolates the machine. Returns a description of what was done.
pub fn isolate(server_url: &str, extra: &[String]) -> Result<String> {
    let ips = resolve(server_url, extra)?;
    let method = apply(&ips)?;
    let prev = state();
    let s = State { isolated: true, since: prev.since.filter(|_| prev.isolated).or(Some(Utc::now())), extra: extra.to_vec(), ips: ips.clone(), method: method.clone() };
    save(&s)?;
    let list: Vec<String> = ips.iter().map(|i| i.to_string()).collect();
    Ok(format!("Isolated with {method}; only {} (the server), DNS and DHCP are reachable", list.join(", ")))
}

pub fn release() -> Result<String> {
    let s = state();
    remove(if s.method.is_empty() { "nftables" } else { &s.method })?;
    save(&State::default())?;
    Ok(if s.isolated { "Network access restored".into() } else { "The machine wasn't isolated".into() })
}

/// After a restart, or when the server's address may have changed: put the rules back if
/// the machine is meant to be isolated. Returns whether it is.
pub fn reapply(server_url: &str) -> bool {
    let s = state();
    if !s.isolated {
        return false;
    }
    match resolve(server_url, &s.extra) {
        Ok(ips) if ips == s.ips && is_applied(&s.method) => {}
        Ok(_) | Err(_) => {
            if let Err(e) = isolate(server_url, &s.extra) {
                tracing::error!("re-applying network isolation: {e:#}");
            }
        }
    }
    true
}

#[cfg(target_os = "linux")]
fn is_applied(method: &str) -> bool {
    match method {
        "iptables" => run("iptables", &["-n".into(), "-L".into(), "RMM-ISO-OUT".into()], None).is_ok(),
        _ => run("nft", &["list".into(), "table".into(), "inet".into(), "rmm_isolation".into()], None).is_ok(),
    }
}

#[cfg(not(target_os = "linux"))]
fn is_applied(_: &str) -> bool {
    // Windows and macOS keep firewall rules across reboots; re-applying is cheap anyway.
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_and_ports() {
        assert_eq!(host_port("https://rmm.example.com"), Some(("rmm.example.com".into(), 443)));
        assert_eq!(host_port("http://10.0.0.5:8080/api"), Some(("10.0.0.5".into(), 8080)));
        assert_eq!(host_port("https://[2001:db8::1]:8443"), Some(("2001:db8::1".into(), 8443)));
        assert_eq!(host_port("updates.example.com:80"), Some(("updates.example.com".into(), 80)));
        assert_eq!(host_port("2001:db8::2"), Some(("2001:db8::2".into(), 443)));
        assert_eq!(resolve("http://127.0.0.1:8080", &["::1".into()]).unwrap(), vec!["127.0.0.1".parse::<IpAddr>().unwrap(), "::1".parse().unwrap()]);
    }

    #[test]
    fn rulesets_keep_the_server_reachable() {
        let ips: Vec<IpAddr> = vec!["203.0.113.10".parse().unwrap(), "2001:db8::10".parse().unwrap()];
        let nft = nft_ruleset(&ips);
        assert!(nft.starts_with("table inet rmm_isolation {}\ndelete table inet rmm_isolation\n"), "replaces atomically");
        assert!(nft.contains("ip daddr { 203.0.113.10 } accept") && nft.contains("ip6 daddr { 2001:db8::10 } accept"));
        assert!(nft.contains("policy drop") && nft.contains("udp dport 53 accept"));
        let v4only: Vec<IpAddr> = vec!["203.0.113.10".parse().unwrap()];
        assert!(!nft_ruleset(&v4only).contains("ip6 daddr {"), "no empty sets");
        let ipt = iptables_cmds(&ips);
        assert!(ipt.iter().any(|(b, a)| *b == "iptables" && a.join(" ") == "-A RMM-ISO-OUT -d 203.0.113.10 -j ACCEPT"));
        assert!(ipt.iter().any(|(b, a)| *b == "ip6tables" && a.join(" ") == "-A RMM-ISO-OUT -d 2001:db8::10 -j ACCEPT"));
        assert_eq!(ipt.last().unwrap().1.join(" "), "-I OUTPUT 1 -j RMM-ISO-OUT", "the jump goes in last, once the chain is complete");
        let ns = netsh_cmds(&ips);
        assert!(ns.iter().any(|a| a.join(" ").contains("remoteip=203.0.113.10,2001:db8::10")));
        assert!(pf_rules(&ips).contains("pass quick to { 203.0.113.10, 2001:db8::10 }"));
    }
}
