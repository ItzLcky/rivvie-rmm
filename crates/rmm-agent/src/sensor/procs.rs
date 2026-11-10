//! Process telemetry.
//!
//! - Everywhere: a snapshot poll (sysinfo) every second or two, diffed against the last one.
//!   Very short-lived processes can slip between polls.
//! - Linux as root: the kernel's process connector (netlink `CN_IDX_PROC`) reports every
//!   exec as it happens, and the poll reconciles. Windows ETW and macOS Endpoint Security are
//!   the planned real-time sources there.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::mpsc::Sender;

use chrono::{TimeZone, Utc};
use rmm_proto::telemetry::{Event, EventKind, Proc};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind, Users};

/// Running processes by pid, with what was known when they started. Feeds parent lookups and
/// the ancestry attached to detections.
#[derive(Default)]
pub struct Table {
    procs: HashMap<u32, Proc>,
}

impl Table {
    pub fn get(&self, pid: u32) -> Option<&Proc> {
        self.procs.get(&pid)
    }

    pub fn insert(&mut self, p: Proc) {
        self.procs.insert(p.pid, p);
    }

    pub fn remove(&mut self, pid: u32) {
        self.procs.remove(&pid);
    }

    /// The parent chain, nearest first, at most `depth` long.
    pub fn ancestry(&self, pid: u32, depth: usize) -> Vec<Proc> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut cur = self.procs.get(&pid).map(|p| p.ppid);
        while let Some(pp) = cur {
            if pp == 0 || !seen.insert(pp) || out.len() >= depth {
                break;
            }
            match self.procs.get(&pp) {
                Some(p) => {
                    out.push(p.clone());
                    cur = Some(p.ppid);
                }
                None => break,
            }
        }
        out
    }

    /// `pid` and everything started under it.
    pub fn tree(&self, pid: u32) -> Vec<u32> {
        let mut out = vec![pid];
        let mut i = 0;
        while i < out.len() {
            let parent = out[i];
            let kids: Vec<u32> = self.procs.values().filter(|p| p.ppid == parent && p.pid != parent && !out.contains(&p.pid)).map(|p| p.pid).collect();
            out.extend(kids);
            i += 1;
        }
        out
    }
}

pub struct Poller {
    sys: System,
    users: Users,
    users_at: std::time::Instant,
    /// pid -> start time key, from the last poll.
    known: HashMap<u32, u64>,
    primed: bool,
}

impl Poller {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Poller { sys: System::new()?, users: Users::new_with_refreshed_list()?, users_at: std::time::Instant::now(), known: HashMap::new(), primed: false })
    }

    fn refresh(&mut self) {
        if self.users_at.elapsed().as_secs() > 300 {
            self.users.refresh();
            self.users_at = std::time::Instant::now();
        }
        self.sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing().with_cmd(UpdateKind::OnlyIfNotSet).with_exe(UpdateKind::OnlyIfNotSet).with_user(UpdateKind::OnlyIfNotSet),
        );
    }

    fn proc_of(&self, pid: &sysinfo::Pid, p: &sysinfo::Process) -> Proc {
        let cmd: Vec<String> = p.cmd().iter().map(|s| s.to_string_lossy().into_owned()).collect();
        Proc {
            pid: pid.as_u32(),
            ppid: p.parent().map(|x| x.as_u32()).unwrap_or(0),
            name: p.name().to_string_lossy().into_owned(),
            exe: p.exe().map(|e| e.to_string_lossy().into_owned()),
            command_line: cmd.join(" "),
            user: p.user_id().and_then(|u| self.users.get_user_by_id(u)).map(|u| u.name().to_string()),
            sha256: None,
            started_at: Utc.timestamp_opt(p.start_time() as i64, 0).single(),
        }
    }

    /// Every running process, without producing events (for the table at startup).
    pub fn all(&mut self) -> Vec<Proc> {
        self.refresh();
        let procs: Vec<Proc> = self.sys.processes().iter().map(|(pid, p)| self.proc_of(pid, p)).collect();
        self.known = self.sys.processes().iter().map(|(pid, p)| (pid.as_u32(), p.start_time())).collect();
        self.primed = true;
        procs
    }

    /// Processes started and ended since the last poll.
    pub fn poll(&mut self) -> (Vec<Proc>, Vec<u32>) {
        if !self.primed {
            self.all();
            return (vec![], vec![]);
        }
        self.refresh();
        let mut started = Vec::new();
        let mut now: HashMap<u32, u64> = HashMap::with_capacity(self.known.len());
        for (pid, p) in self.sys.processes() {
            // Threads show up as processes on Linux; only thread-group leaders count.
            if p.thread_kind().is_some() {
                continue;
            }
            let key = p.start_time();
            if self.known.get(&pid.as_u32()) != Some(&key) {
                started.push(self.proc_of(pid, p));
            }
            now.insert(pid.as_u32(), key);
        }
        let ended = self.known.keys().filter(|pid| !now.contains_key(pid)).copied().collect();
        self.known = now;
        (started, ended)
    }

    pub fn cpu_and_rss(&mut self, pid: u32) -> (f32, u64) {
        let p = sysinfo::Pid::from_u32(pid);
        self.sys.refresh_processes_specifics(ProcessesToUpdate::Some(&[p]), false, ProcessRefreshKind::nothing().with_cpu().with_memory());
        self.sys.process(p).map(|x| (x.cpu_usage(), x.memory())).unwrap_or((0.0, 0))
    }
}

pub fn start_event(p: Proc, parent: Option<Proc>) -> Event {
    let mut e = Event::new(EventKind::Process, "start");
    if let Some(t) = p.started_at {
        // Polled processes are seen late; their start time is the better timestamp.
        e.ts = t.min(Utc::now());
    }
    e.process = Some(p);
    e.parent = parent;
    e
}

pub fn exit_event(p: Option<Proc>, pid: u32) -> Event {
    let mut e = Event::new(EventKind::Process, "exit");
    e.process = Some(p.unwrap_or(Proc { pid, name: String::new(), ..Default::default() }));
    e
}

/// SHA-256 of an executable, cached by path, size and modification time. Large images are
/// skipped (`None`).
#[derive(Default)]
pub struct HashCache {
    cache: HashMap<String, (u64, Option<std::time::SystemTime>, String)>,
}

pub const HASH_MAX: u64 = 128 * 1024 * 1024;

impl HashCache {
    pub fn get(&mut self, path: &str) -> Option<String> {
        let md = std::fs::metadata(path).ok()?;
        let (size, mtime) = (md.len(), md.modified().ok());
        if let Some((s, m, h)) = self.cache.get(path)
            && *s == size
            && *m == mtime
        {
            return Some(h.clone());
        }
        if size > HASH_MAX {
            return None;
        }
        let h = sha256_file(Path::new(path))?;
        if self.cache.len() > 20_000 {
            self.cache.clear();
        }
        self.cache.insert(path.to_string(), (size, mtime, h.clone()));
        Some(h)
    }
}

pub fn sha256_file(path: &Path) -> Option<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut f = std::fs::File::open(path).ok()?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Some(hex::encode(h.finalize()))
}

/// What the kernel told us, for the main loop to look up.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub enum Live {
    Exec(u32),
    Exit(u32),
}

/// Linux: subscribes to the process connector and sends execs and exits until the receiver
/// goes away. Fails without CAP_NET_ADMIN (not root), and the caller falls back to polling.
#[cfg(target_os = "linux")]
pub fn proc_connector(tx: Sender<Live>) -> std::io::Result<()> {
    use std::mem::size_of;
    // SAFETY: plain socket syscalls on a descriptor we own; buffers are sized and initialised.
    unsafe {
        let fd = libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, libc::NETLINK_CONNECTOR);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut addr: libc::sockaddr_nl = std::mem::zeroed();
        addr.nl_family = libc::AF_NETLINK as u16;
        addr.nl_pid = std::process::id();
        addr.nl_groups = 1; // CN_IDX_PROC
        if libc::bind(fd, &addr as *const _ as *const libc::sockaddr, size_of::<libc::sockaddr_nl>() as u32) < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        // nlmsghdr (16) + cn_msg (20) + op (4)
        let mut msg = [0u8; 40];
        msg[0..4].copy_from_slice(&40u32.to_ne_bytes());
        msg[4..6].copy_from_slice(&3u16.to_ne_bytes()); // NLMSG_DONE
        msg[12..16].copy_from_slice(&std::process::id().to_ne_bytes());
        msg[16..20].copy_from_slice(&1u32.to_ne_bytes()); // CN_IDX_PROC
        msg[20..24].copy_from_slice(&1u32.to_ne_bytes()); // CN_VAL_PROC
        msg[32..34].copy_from_slice(&4u16.to_ne_bytes()); // payload length
        msg[36..40].copy_from_slice(&1u32.to_ne_bytes()); // PROC_CN_MCAST_LISTEN
        if libc::send(fd, msg.as_ptr() as *const libc::c_void, msg.len(), 0) < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        std::thread::Builder::new().name("proc-connector".into()).spawn(move || {
            let mut buf = vec![0u8; 8192];
            loop {
                let n = libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0);
                if n <= 0 {
                    continue;
                }
                let n = n as usize;
                let mut off = 0;
                while off + 16 <= n {
                    let len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
                    if len < 16 || off + len > n {
                        break;
                    }
                    // proc_event starts after nlmsghdr (16) + cn_msg (20).
                    let ev = off + 36;
                    if ev + 24 <= off + len {
                        let what = u32::from_ne_bytes(buf[ev..ev + 4].try_into().unwrap());
                        let pid = u32::from_ne_bytes(buf[ev + 16..ev + 20].try_into().unwrap());
                        let tgid = u32::from_ne_bytes(buf[ev + 20..ev + 24].try_into().unwrap());
                        let sent = match what {
                            0x0000_0002 if pid == tgid => tx.send(Live::Exec(tgid)),
                            0x8000_0000 if pid == tgid => tx.send(Live::Exit(tgid)),
                            _ => Ok(()),
                        };
                        if sent.is_err() {
                            libc::close(fd);
                            return;
                        }
                    }
                    off += (len + 3) & !3;
                }
            }
        })?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn proc_connector(_tx: Sender<Live>) -> std::io::Result<()> {
    Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "no real-time process source on this OS yet"))
}

/// Linux: reads one process from /proc right after its exec.
#[cfg(target_os = "linux")]
pub fn read_proc(pid: u32, users: &Users) -> Option<Proc> {
    let base = format!("/proc/{pid}");
    let status = std::fs::read_to_string(format!("{base}/status")).ok()?;
    let field = |k: &str| status.lines().find_map(|l| l.strip_prefix(k)).map(|v| v.trim().to_string());
    let name = field("Name:").unwrap_or_default();
    let ppid = field("PPid:").and_then(|v| v.parse().ok()).unwrap_or(0);
    let uid = field("Uid:").and_then(|v| v.split_whitespace().next().and_then(|u| u.parse::<u32>().ok()));
    let cmd = std::fs::read(format!("{base}/cmdline")).unwrap_or_default();
    let command_line = String::from_utf8_lossy(&cmd).split('\0').filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" ");
    let exe = std::fs::read_link(format!("{base}/exe")).ok().map(|p| p.to_string_lossy().into_owned());
    let user = uid.and_then(|u| users.iter().find(|x| **x.id() == u).map(|x| x.name().to_string()));
    Some(Proc { pid, ppid, name, exe, command_line, user, sha256: None, started_at: Some(Utc::now()) })
}

#[cfg(not(target_os = "linux"))]
pub fn read_proc(_pid: u32, _users: &Users) -> Option<Proc> {
    None
}

/// Processes that must never be killed by a rule or a technician.
pub fn protected(p: &Proc) -> bool {
    let me = std::process::id();
    let n = p.name.to_ascii_lowercase();
    p.pid <= 4
        || p.pid == me
        || p.ppid == me && n.contains("rmm-agent")
        || n.starts_with("rmm-agent")
        || [
            "systemd", "init", "launchd", "kernel_task", "csrss.exe", "wininit.exe", "winlogon.exe", "smss.exe", "services.exe", "lsass.exe",
            "lsaiso.exe", "system", "registry", "memory compression",
        ]
        .contains(&n.as_str())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ancestry_and_tree() {
        let mut t = Table::default();
        for (pid, ppid, name) in [(1, 0, "init"), (10, 1, "sshd"), (20, 10, "bash"), (30, 20, "curl"), (31, 20, "sh"), (40, 31, "nc")] {
            t.insert(Proc { pid, ppid, name: name.into(), ..Default::default() });
        }
        let chain: Vec<String> = t.ancestry(30, 8).into_iter().map(|p| p.name).collect();
        assert_eq!(chain, ["bash", "sshd", "init"]);
        let mut tree = t.tree(20);
        tree.sort();
        assert_eq!(tree, [20, 30, 31, 40]);
        assert!(protected(&Proc { pid: 1, name: "systemd".into(), ..Default::default() }));
        assert!(protected(&Proc { pid: 700, name: "lsass.exe".into(), ..Default::default() }));
        assert!(!protected(&Proc { pid: 900, name: "curl".into(), ..Default::default() }));
    }

    #[test]
    fn poller_sees_a_new_process() {
        let mut p = Poller::new().unwrap();
        p.poll();
        let mut child = std::process::Command::new("sleep").arg("5").spawn().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(200));
        let (started, _) = p.poll();
        let me = started.iter().find(|x| x.pid == child.id()).expect("the new process");
        assert_eq!(me.name, "sleep");
        assert!(me.command_line.contains("sleep 5"));
        child.kill().unwrap();
        child.wait().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(200));
        let (_, ended) = p.poll();
        assert!(ended.contains(&child.id()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reads_a_live_process() {
        let users = Users::new_with_refreshed_list().unwrap();
        let me = read_proc(std::process::id(), &users).unwrap();
        assert!(me.exe.is_some() && !me.command_line.is_empty());
    }
}

/// Needs root (CAP_NET_ADMIN) in the host's network namespace (the kernel only reports there):
/// `sudo cargo test -p rmm-agent proc_connector_live -- --ignored`.
#[cfg(all(test, target_os = "linux"))]
mod live_tests {
    #[test]
    #[ignore]
    fn proc_connector_live() {
        let (tx, rx) = std::sync::mpsc::channel();
        super::proc_connector(tx).expect("subscribing (run as root)");
        let mut child = std::process::Command::new("sleep").arg("1").spawn().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if let Ok(super::Live::Exec(pid)) = rx.recv_timeout(std::time::Duration::from_millis(200))
                && pid == child.id()
            {
                let _ = child.wait();
                return;
            }
        }
        let _ = child.wait();
        panic!("no exec event for {}", child.id());
    }
}
