//! On-access protection on Linux (antivirus milestone 3): fanotify permission events decide
//! every exec before the program runs (`FAN_OPEN_EXEC_PERM`), and files are scanned after
//! they're written (`FAN_CLOSE_WRITE`), on every local filesystem.
//!
//! The rule above all others: this must never hang the machine. So
//!
//! - one reader thread owns the decisions. It answers at once from the verdict cache, for our
//!   own processes and our own binary, and when the workers are all busy; everything else goes
//!   to a worker with a deadline. When the deadline passes the reader allows the exec itself
//!   (counted as a timeout), and the worker finishes the scan in the background: a blocking
//!   verdict then kills the process and quarantines the file, like scan-after-start does.
//! - the reader never takes a lock it could wait on (the cache with `try_lock`, the rules
//!   behind an `RwLock` written only to swap an `Arc`), never writes to the agent's pipe and
//!   never opens a file the normal way: the event's own descriptor doesn't raise events, and
//!   paths are only read for exclusions.
//! - the sensor never execs anything, so its own threads can't wait on themselves; events from
//!   our own process and the agent are allowed unscanned anyway.
//! - if the reader stops making progress for 5 seconds the process aborts. The kernel allows
//!   every pending permission event when the fanotify descriptor closes, which is also what
//!   happens when the sensor crashes or is killed. A stopped (SIGSTOP) sensor is caught by
//!   the agent, which kills a sensor that hasn't said it's alive for 10 seconds
//!   (`security::supervisor::QUIET`).
//!
//! Network filesystems (a scan would read across the network while a program waits), FUSE
//! (its daemon could be the one waiting on us) and pseudo filesystems are skipped. New mounts
//! are picked up from `/proc/self/mountinfo`.
//!
//! Package-manager writes (dpkg, rpm, pacman... and anything they start) are scanned but never
//! quarantined: half-installed packages break machines. Their programs are still decided at
//! exec like any other.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use rmm_proto::security::{RealtimeMode, RuleMode, SensorPolicy};
use rmm_scan::Engine;
use rmm_scan::cache::Cache;

use super::policy::Exclusions;
use super::scan::Finding;

/// How long a program waits for its verdict, at most.
pub const EXEC_DEADLINE: Duration = Duration::from_millis(500);
/// Execs queued for the workers, at most; past that they're allowed unscanned.
const EXEC_QUEUE: usize = 64;
/// Written files queued; past that they're dropped (and counted). Each holds a descriptor,
/// so the soft descriptor limit is raised to make room.
const WRITE_QUEUE: usize = 4096;
const WRITE_WORKERS: usize = 2;
/// The reader made no progress for this long: abort, and the kernel allows what's pending.
const STUCK: Duration = Duration::from_secs(5);

/// What decisions are made with. Swapped whole by the sensor when content or policy changes.
pub struct Rules {
    pub engine: Option<Arc<Engine>>,
    pub policy: SensorPolicy,
    pub overrides: HashMap<String, RuleMode>,
    pub excl: Exclusions,
}

#[derive(Default)]
pub struct Stats {
    pub decisions: AtomicU64,
    pub denied: AtomicU64,
    pub cache_hits: AtomicU64,
    pub timeouts: AtomicU64,
    pub overloaded: AtomicU64,
    pub write_scans: AtomicU64,
    pub write_dropped: AtomicU64,
    /// Decision times (µs) since the last health report.
    pub latency: Mutex<Vec<u32>>,
}

impl Stats {
    fn took(&self, since: Instant) {
        let mut l = self.latency.lock().unwrap_or_else(|e| e.into_inner());
        if l.len() < 100_000 {
            l.push(since.elapsed().as_micros().min(u32::MAX as u128) as u32);
        }
    }

    /// Median and 99th percentile since the last call.
    pub fn percentiles(&self) -> (u64, u64) {
        let mut l = std::mem::take(&mut *self.latency.lock().unwrap_or_else(|e| e.into_inner()));
        if l.is_empty() {
            return (0, 0);
        }
        l.sort_unstable();
        let at = |q: f64| u64::from(l[((l.len() - 1) as f64 * q).round() as usize]);
        (at(0.5), at(0.99))
    }
}

/// What a worker found, for the sensor's main loop to report and act on.
pub struct Hit {
    pub finding: Finding,
    pub what: HitKind,
}

pub enum HitKind {
    Exec {
        pid: u32,
        /// The exec was refused.
        denied: bool,
        /// The deadline passed first: the program was allowed and is running.
        late: bool,
        /// Of the file, so a late kill hits the program that was scanned and not a reused pid.
        /// (Inode and size, not the device: on overlayfs the event can be for the file under it.)
        ino: u64,
        size: u64,
    },
    Write {
        /// Written by a package manager: never quarantined.
        package_manager: bool,
    },
}

/// An exec as the kernel shows it twice on overlayfs (a container's root, and every container
/// on a Docker host): once for the overlay file and once for the file under it, one after the
/// other, with the same inode number and times but another device. The second is answered as
/// the first was when the first was allowed; only allows are remembered, so retrying a denied
/// exec is denied again, and changing the file (its ctime) makes it a new exec.
type ExecKey = (u32, u64, u64, i64, i64, i64, i64);

fn exec_key(pid: u32, md: &std::fs::Metadata) -> ExecKey {
    (pid, md.ino(), md.size(), md.mtime(), md.mtime_nsec(), md.ctime(), md.ctime_nsec())
}

/// Execs allowed in the last moment.
#[derive(Default)]
struct Allowed(Mutex<HashMap<ExecKey, Instant>>);

const ALLOWED_FOR: Duration = Duration::from_secs(2);

impl Allowed {
    fn insert(&self, k: ExecKey) {
        let mut m = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if m.len() > 1024 {
            m.retain(|_, t| t.elapsed() < ALLOWED_FOR);
        }
        m.insert(k, Instant::now());
    }

    /// From the decision thread: never waits on the lock.
    fn recent(&self, k: &ExecKey) -> bool {
        self.0.try_lock().is_ok_and(|m| m.get(k).is_some_and(|t| t.elapsed() < ALLOWED_FOR))
    }
}

/// One exec waiting for its answer. Answered exactly once, by whoever gets there first.
struct Decision {
    fd: RawFd,
    key: ExecKey,
    done: AtomicBool,
}

impl Decision {
    fn answer(&self, fan: RawFd, allow: bool, allowed: &Allowed) -> bool {
        if self.done.swap(true, Ordering::AcqRel) {
            return false;
        }
        if allow {
            allowed.insert(self.key);
        }
        respond(fan, self.fd, allow);
        true
    }
}

fn respond(fan: RawFd, fd: RawFd, allow: bool) {
    let r = libc::fanotify_response { fd, response: if allow { libc::FAN_ALLOW } else { libc::FAN_DENY } };
    // SAFETY: writes a plain struct to the fanotify descriptor we own.
    unsafe {
        libc::write(fan, &r as *const _ as *const libc::c_void, std::mem::size_of::<libc::fanotify_response>());
    }
}

struct ExecJob {
    file: File,
    decision: Arc<Decision>,
    pid: u32,
    path: String,
    at: Instant,
}

/// A written file, or an exec allowed unscanned because the exec workers were all busy (its
/// pid): scanned in the background either way.
struct WriteJob {
    file: File,
    path: String,
    package_manager: bool,
    exec: Option<u32>,
}

/// The fanotify descriptor, closed when the last thread using it lets go.
struct Fan(RawFd);

impl Drop for Fan {
    fn drop(&mut self) {
        // SAFETY: our descriptor, closed once.
        unsafe {
            libc::close(self.0);
        }
    }
}

/// Running on-access protection. Dropping it stops it: the reader allows whatever is pending
/// and closes the descriptor.
pub struct Handle {
    stop: Arc<AtomicBool>,
    pub stats: Arc<Stats>,
    pub scan_on_write: bool,
    pub filesystems: Arc<AtomicU64>,
    /// Device numbers of the watched filesystems.
    devs: Arc<Mutex<HashSet<u64>>>,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl Handle {
    /// Execs of this file are decided before they run (it's on a watched filesystem).
    pub fn decides(&self, path: &str) -> bool {
        std::fs::metadata(path).is_ok_and(|m| self.devs.lock().unwrap_or_else(|e| e.into_inner()).contains(&m.dev()))
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.reader.take() {
            let _ = t.join();
        }
    }
}

fn os_err(what: &str) -> String {
    let e = std::io::Error::last_os_error();
    match e.raw_os_error() {
        Some(libc::EPERM) => format!("{what}: not permitted (the sensor needs root, CAP_SYS_ADMIN)"),
        Some(libc::ENOSYS) => format!("{what}: this kernel has no fanotify"),
        Some(libc::EINVAL) => format!("{what}: this kernel has no fanotify exec permission events (Linux 5.0 or later, CONFIG_FANOTIFY_ACCESS_PERMISSIONS)"),
        _ => format!("{what}: {e}"),
    }
}

/// Filesystems never watched: pseudo filesystems, network ones, FUSE.
pub fn skipped_fs(fstype: &str) -> bool {
    const SKIP: &[&str] = &[
        "proc", "sysfs", "devtmpfs", "devpts", "cgroup", "cgroup2", "debugfs", "tracefs", "securityfs", "pstore", "bpf", "configfs", "fusectl", "mqueue",
        "hugetlbfs", "autofs", "binfmt_misc", "efivarfs", "selinuxfs", "rpc_pipefs", "nsfs", "nfsd", "nfs", "nfs4", "cifs", "smb3", "smbfs", "9p", "ceph",
        "glusterfs", "afs", "ncpfs", "davfs", "coda", "lustre", "gpfs", "ocfs2", "virtiofs", "fuse", "fuseblk",
    ];
    SKIP.contains(&fstype) || fstype.starts_with("fuse.")
}

/// A mount from `/proc/self/mountinfo`: (mount id, device "major:minor", mount point, type).
pub fn parse_mountinfo(text: &str) -> Vec<(String, String, PathBuf, String)> {
    let unescape = |s: &str| {
        let b = s.as_bytes();
        let mut out = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'\\' && i + 3 < b.len() && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
                out.push((b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0'));
                i += 4;
            } else {
                out.push(b[i]);
                i += 1;
            }
        }
        PathBuf::from(<std::ffi::OsString as std::os::unix::ffi::OsStringExt>::from_vec(out))
    };
    text.lines()
        .filter_map(|l| {
            let (left, right) = l.split_once(" - ")?;
            let f: Vec<&str> = left.split(' ').collect();
            let fstype = right.split(' ').next()?;
            Some((f.first()?.to_string(), f.get(2)?.to_string(), unescape(f.get(4)?), fstype.to_string()))
        })
        .collect()
}

/// Marks what isn't marked yet. Filesystem marks (one per superblock) where the kernel takes
/// them, else mount marks. `devs` gets the device numbers files on them have.
fn mark_all(fan: RawFd, mask: u64, done: &mut HashSet<String>, devs: &Mutex<HashSet<u64>>) -> (u32, Option<String>) {
    let text = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    let mut added = 0;
    let mut last_err = None;
    for (id, dev, point, fstype) in parse_mountinfo(&text) {
        if skipped_fs(&fstype) || done.contains(&dev) || done.contains(&format!("m{id}")) {
            continue;
        }
        let Ok(c) = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(point.as_os_str())) else { continue };
        // SAFETY: plain syscalls on our descriptor and a NUL-terminated path.
        let fs = unsafe { libc::fanotify_mark(fan, libc::FAN_MARK_ADD | libc::FAN_MARK_FILESYSTEM, mask, libc::AT_FDCWD, c.as_ptr()) };
        let watched = |devs: &Mutex<HashSet<u64>>| {
            if let Ok(m) = std::fs::metadata(&point) {
                devs.lock().unwrap_or_else(|e| e.into_inner()).insert(m.dev());
            }
        };
        if fs == 0 {
            done.insert(dev);
            watched(devs);
            added += 1;
            continue;
        }
        let fs_err = os_err(&format!("watching {}", point.display()));
        // SAFETY: as above.
        if unsafe { libc::fanotify_mark(fan, libc::FAN_MARK_ADD | libc::FAN_MARK_MOUNT, mask, libc::AT_FDCWD, c.as_ptr()) } == 0 {
            done.insert(format!("m{id}"));
            watched(devs);
            added += 1;
        } else {
            tracing::debug!("{fs_err}; {}", os_err("as a mount"));
            last_err = Some(fs_err);
        }
    }
    (added, last_err)
}

fn fd_path(fd: RawFd) -> String {
    std::fs::read_link(format!("/proc/self/fd/{fd}")).map(|p| p.to_string_lossy().into_owned()).unwrap_or_default()
}

/// Our own binary, by device and inode: its execs (the agent restarting the sensor, updates
/// running the new version's checks) are never held up.
fn own_exe() -> Option<(u64, u64)> {
    std::fs::metadata("/proc/self/exe").ok().map(|m| (m.dev(), m.ino()))
}

const PACKAGE_MANAGERS: &[&str] = &[
    "dpkg", "apt", "apt-get", "aptitude", "unattended-upgr", "rpm", "dnf", "dnf5", "yum", "microdnf", "zypper", "pacman", "apk", "snapd", "flatpak",
    "packagekitd", "rpm-ostree", "xbps-install", "emerge",
];

/// A process's name and parent, from `/proc/<pid>/stat`.
fn stat(pid: u32) -> Option<(String, u32)> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // pid (comm) state ppid ...: comm may hold spaces and parentheses.
    let (open, close) = (stat.find('(')?, stat.rfind(')')?);
    let ppid = stat.get(close + 1..)?.split_whitespace().nth(1)?.parse().ok()?;
    Some((stat.get(open + 1..close)?.to_string(), ppid))
}

/// Whether processes are, or run under, a package manager. Asked as each write event is read
/// (a writer like `cp` from a maintainer script is often gone by the time its file is
/// scanned), so answers are cached by pid: a new process costs one read of `/proc`.
#[derive(Default)]
pub struct PackageManagers {
    known: HashMap<u32, bool>,
}

impl PackageManagers {
    pub fn check(&mut self, pid: u32) -> bool {
        let mut chain = Vec::new();
        let mut cur = pid;
        let found = loop {
            if let Some(k) = self.known.get(&cur) {
                break *k;
            }
            if cur <= 1 || chain.len() >= 12 {
                break false;
            }
            let Some((comm, ppid)) = stat(cur) else { break false };
            chain.push(cur);
            if PACKAGE_MANAGERS.contains(&comm.as_str()) {
                break true;
            }
            cur = ppid;
        };
        // Pids are reused: forget everything now and then.
        if self.known.len() > 8192 {
            self.known.clear();
        }
        for p in chain {
            self.known.insert(p, found);
        }
        found
    }
}

/// Starts watching. Fails (with the reason) where fanotify permission events aren't
/// available; the sensor then scans programs just after they start.
pub fn start(rules: Arc<RwLock<Arc<Rules>>>, cache: Arc<Mutex<Cache>>, hits: Sender<Hit>, scan_on_write: bool) -> Result<Handle, String> {
    // SAFETY: plain syscall; the descriptor is ours.
    let fan = unsafe {
        libc::fanotify_init(
            libc::FAN_CLASS_CONTENT | libc::FAN_CLOEXEC | libc::FAN_NONBLOCK,
            (libc::O_RDONLY | libc::O_LARGEFILE | libc::O_CLOEXEC) as u32,
        )
    };
    if fan < 0 {
        return Err(os_err("fanotify"));
    }
    let fan = Arc::new(Fan(fan));
    let mask = libc::FAN_OPEN_EXEC_PERM | if scan_on_write { libc::FAN_CLOSE_WRITE } else { 0 };
    let mut marked = HashSet::new();
    let devs = Arc::new(Mutex::new(HashSet::new()));
    let (n, err) = mark_all(fan.0, mask, &mut marked, &devs);
    if n == 0 {
        return Err(err.unwrap_or_else(|| "no local filesystem to watch".into()));
    }
    let stats = Arc::new(Stats::default());
    let filesystems = Arc::new(AtomicU64::new(u64::from(n)));
    let stop = Arc::new(AtomicBool::new(false));
    let allowed = Arc::new(Allowed::default());
    let (exec_tx, exec_rx) = std::sync::mpsc::sync_channel::<ExecJob>(EXEC_QUEUE);
    let exec_rx = Arc::new(Mutex::new(exec_rx));
    let workers = std::thread::available_parallelism().map_or(2, |n| n.get()).clamp(2, 4);
    for i in 0..workers {
        let (rx, fan, rules, cache, hits, stats, allowed) = (exec_rx.clone(), fan.clone(), rules.clone(), cache.clone(), hits.clone(), stats.clone(), allowed.clone());
        std::thread::Builder::new()
            .name(format!("onaccess-exec-{i}"))
            .spawn(move || {
                normal_priority();
                exec_worker(&rx, &fan, &rules, &cache, &hits, &stats, &allowed)
            })
            .map_err(|e| e.to_string())?;
    }
    raise_fd_limit(EXEC_QUEUE + WRITE_QUEUE + 1024);
    let (write_tx, write_rx) = std::sync::mpsc::sync_channel::<WriteJob>(WRITE_QUEUE);
    let write_rx = Arc::new(Mutex::new(write_rx));
    for i in 0..WRITE_WORKERS {
        let (rx, rules, cache, hits, stats) = (write_rx.clone(), rules.clone(), cache.clone(), hits.clone(), stats.clone());
        std::thread::Builder::new().name(format!("onaccess-write-{i}")).spawn(move || write_worker(&rx, &rules, &cache, &hits, &stats)).map_err(|e| e.to_string())?;
    }
    let alive = Arc::new(AtomicU64::new(0));
    let epoch = Instant::now();
    {
        let (alive, stop) = (alive.clone(), stop.clone());
        std::thread::Builder::new()
            .name("onaccess-watchdog".into())
            .spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_secs(1));
                    let last = Duration::from_millis(alive.load(Ordering::SeqCst));
                    if !stop.load(Ordering::SeqCst) && epoch.elapsed().saturating_sub(last) > STUCK {
                        // Closing the descriptor (by dying) is the one way to release every
                        // program waiting on us. The agent restarts the sensor.
                        tracing::error!("on-access: the decision thread is stuck; aborting so the kernel allows what's pending");
                        std::process::abort();
                    }
                }
            })
            .map_err(|e| e.to_string())?;
    }
    let reader = {
        let (stop, stats, filesystems, devs) = (stop.clone(), stats.clone(), filesystems.clone(), devs.clone());
        std::thread::Builder::new()
            .name("onaccess".into())
            .spawn(move || {
                normal_priority();
                let mut r = Reader {
                    fan,
                    mask,
                    marked,
                    rules,
                    cache,
                    stats,
                    exec_tx,
                    write_tx,
                    pending: Vec::new(),
                    me: std::process::id(),
                    // SAFETY: plain syscall.
                    agent: unsafe { libc::getppid() } as u32,
                    own_exe: own_exe(),
                    state_dir: crate::config::state_dir(),
                    filesystems,
                    pm: PackageManagers::default(),
                    allowed,
                    devs,
                };
                r.run(&stop, &alive, epoch);
            })
            .map_err(|e| e.to_string())?
    };
    tracing::info!(filesystems = n, scan_on_write, "on-access protection on (fanotify)");
    Ok(Handle { stop, stats, scan_on_write, filesystems, devs, reader: Some(reader) })
}

/// Raises the soft limit on open descriptors to at least `want` (within the hard limit).
fn raise_fd_limit(want: usize) {
    let mut l = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: reads and sets our own resource limit through a valid struct.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut l) == 0 && (l.rlim_cur as usize) < want {
            l.rlim_cur = (want as libc::rlim_t).min(l.rlim_max);
            libc::setrlimit(libc::RLIMIT_NOFILE, &l);
        }
    }
}

/// The sensor runs at low priority; deciding execs mustn't (a busy machine would time out
/// every decision). Root may raise a thread back to normal.
fn normal_priority() {
    // SAFETY: changes this thread's own nice value.
    unsafe {
        libc::setpriority(libc::PRIO_PROCESS, libc::gettid() as libc::id_t, 0);
    }
}

struct Reader {
    fan: Arc<Fan>,
    mask: u64,
    marked: HashSet<String>,
    rules: Arc<RwLock<Arc<Rules>>>,
    cache: Arc<Mutex<Cache>>,
    stats: Arc<Stats>,
    exec_tx: SyncSender<ExecJob>,
    write_tx: SyncSender<WriteJob>,
    pending: Vec<(Instant, Arc<Decision>)>,
    me: u32,
    agent: u32,
    own_exe: Option<(u64, u64)>,
    state_dir: PathBuf,
    filesystems: Arc<AtomicU64>,
    pm: PackageManagers,
    allowed: Arc<Allowed>,
    devs: Arc<Mutex<HashSet<u64>>>,
}

impl Reader {
    fn run(&mut self, stop: &AtomicBool, alive: &AtomicU64, epoch: Instant) {
        let mounts = std::ffi::CString::new("/proc/self/mountinfo").ok();
        // SAFETY: opening a proc file read-only; closed below.
        let mfd = mounts.map_or(-1, |m| unsafe { libc::open(m.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) });
        let mut buf = vec![0u8; 64 * 1024];
        while !stop.load(Ordering::SeqCst) {
            alive.store(epoch.elapsed().as_millis() as u64, Ordering::SeqCst);
            let now = Instant::now();
            self.expire(now);
            let wait = self.pending.iter().map(|(d, _)| d.saturating_duration_since(now)).min().unwrap_or(Duration::from_millis(250)).min(Duration::from_millis(250));
            let mut fds = [
                libc::pollfd { fd: self.fan.0, events: libc::POLLIN, revents: 0 },
                libc::pollfd { fd: mfd, events: libc::POLLPRI, revents: 0 },
            ];
            // SAFETY: polls descriptors we own, with a correctly sized array.
            let n = unsafe { libc::poll(fds.as_mut_ptr(), if mfd >= 0 { 2 } else { 1 }, wait.as_millis().max(1) as i32) };
            if n <= 0 {
                continue;
            }
            if fds[1].revents & (libc::POLLPRI | libc::POLLERR) != 0 {
                // The mount table changed: watch what's new (unmounted ones drop out by themselves).
                let (added, _) = mark_all(self.fan.0, self.mask, &mut self.marked, &self.devs);
                if added > 0 {
                    self.filesystems.fetch_add(u64::from(added), Ordering::Relaxed);
                    tracing::info!(added, "on-access: new filesystems watched");
                }
                // SAFETY: rewinds our descriptor so the next change is reported again.
                unsafe {
                    libc::lseek(mfd, 0, libc::SEEK_SET);
                    let mut b = [0u8; 4096];
                    while libc::read(mfd, b.as_mut_ptr() as *mut libc::c_void, b.len()) > 0 {}
                }
            }
            if fds[0].revents & libc::POLLIN != 0 {
                self.read_events(&mut buf);
            }
        }
        // Stopping: nobody may be left waiting.
        for (_, d) in self.pending.drain(..) {
            d.answer(self.fan.0, true, &self.allowed);
        }
        if mfd >= 0 {
            // SAFETY: our descriptor, closed once.
            unsafe {
                libc::close(mfd);
            }
        }
    }

    fn expire(&mut self, now: Instant) {
        let fan = self.fan.0;
        let (stats, allowed) = (&self.stats, &self.allowed);
        self.pending.retain(|(deadline, d)| {
            if d.done.load(Ordering::Acquire) {
                return false;
            }
            if *deadline <= now {
                if d.answer(fan, true, allowed) {
                    stats.timeouts.fetch_add(1, Ordering::Relaxed);
                    stats.latency.lock().unwrap_or_else(|e| e.into_inner()).push(EXEC_DEADLINE.as_micros() as u32);
                }
                return false;
            }
            true
        });
    }

    fn read_events(&mut self, buf: &mut [u8]) {
        loop {
            // SAFETY: reads into our buffer, within its length.
            let n = unsafe { libc::read(self.fan.0, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n <= 0 {
                return;
            }
            let n = n as usize;
            let mut off = 0;
            let size = std::mem::size_of::<libc::fanotify_event_metadata>();
            while off + size <= n {
                // SAFETY: the kernel wrote a whole metadata record here; read it unaligned.
                let m: libc::fanotify_event_metadata = unsafe { std::ptr::read_unaligned(buf.as_ptr().add(off) as *const _) };
                let len = m.event_len as usize;
                if len < size || m.vers != libc::FANOTIFY_METADATA_VERSION {
                    return;
                }
                self.event(&m);
                off += len;
            }
        }
    }

    fn event(&mut self, m: &libc::fanotify_event_metadata) {
        if m.mask & libc::FAN_Q_OVERFLOW != 0 || m.fd < 0 {
            self.stats.write_dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        // SAFETY: the kernel gave us this descriptor; we own it from here and close it once.
        let file = unsafe { File::from_raw_fd(m.fd) };
        let pid = m.pid as u32;
        if m.mask & libc::FAN_OPEN_EXEC_PERM != 0 {
            let at = Instant::now();
            self.stats.decisions.fetch_add(1, Ordering::Relaxed);
            let fan = self.fan.0;
            let allow = |stats: &Stats| {
                respond(fan, m.fd, true);
                stats.took(at);
            };
            if pid == self.me || pid == self.agent {
                return allow(&self.stats);
            }
            let Ok(md) = file.metadata() else { return allow(&self.stats) };
            if !md.is_file() {
                return allow(&self.stats);
            }
            let key = exec_key(pid, &md);
            if self.allowed.recent(&key) {
                // The second half of an overlayfs exec: not a decision of its own.
                self.stats.decisions.fetch_sub(1, Ordering::Relaxed);
                return respond(fan, m.fd, true);
            }
            let allow = |stats: &Stats| {
                self.allowed.insert(key);
                allow(stats)
            };
            if self.own_exe == Some((md.dev(), md.ino())) {
                return allow(&self.stats);
            }
            let rules = self.rules.read().unwrap_or_else(|e| e.into_inner()).clone();
            if rules.engine.is_none() {
                return allow(&self.stats);
            }
            let path = fd_path(m.fd);
            tracing::debug!(pid, %path, dev = md.dev(), ino = md.ino(), "exec decision");
            if rules.excl.path(&path) {
                return allow(&self.stats);
            }
            if let Some(k) = rmm_scan::cache::key(std::path::Path::new(&path), &md)
                && let Ok(mut c) = self.cache.try_lock()
                && c.clean(&k)
            {
                self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                return allow(&self.stats);
            }
            let decision = Arc::new(Decision { fd: m.fd, key, done: AtomicBool::new(false) });
            match self.exec_tx.try_send(ExecJob { file, decision: decision.clone(), pid, path, at }) {
                Ok(()) => self.pending.push((at + EXEC_DEADLINE, decision)),
                Err(TrySendError::Full(job) | TrySendError::Disconnected(job)) => {
                    self.stats.overloaded.fetch_add(1, Ordering::Relaxed);
                    job.decision.answer(fan, true, &self.allowed);
                    self.stats.took(at);
                    // Still scanned, after the fact, like a decision past its deadline.
                    let _ = self.write_tx.try_send(WriteJob { file: job.file, path: job.path, package_manager: false, exec: Some(pid) });
                }
            }
        } else if m.mask & libc::FAN_CLOSE_WRITE != 0 {
            if pid == self.me {
                return;
            }
            let path = fd_path(m.fd);
            if path.is_empty() || path.ends_with(" (deleted)") || std::path::Path::new(&path).starts_with(&self.state_dir) {
                return;
            }
            let package_manager = self.pm.check(pid);
            if self.write_tx.try_send(WriteJob { file, path, package_manager, exec: None }).is_err() {
                self.stats.write_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Scans an open file; `None` when clean (and then cached) or every match is excluded.
fn scan(rules: &Rules, cache: &Mutex<Cache>, file: &File, path: &str) -> Option<(Finding, RuleMode)> {
    let engine = rules.engine.as_ref()?;
    let md = file.metadata().ok()?;
    let key = rmm_scan::cache::key(std::path::Path::new(path), &md);
    let v = engine.scan_reader(file, &rmm_scan::Context { path: Some(path) }).ok()?;
    if v.clean() {
        if let Some(k) = key {
            cache.lock().unwrap_or_else(|e| e.into_inner()).insert(k);
        }
        return None;
    }
    if rules.excl.hash(&v.sha256) {
        return None;
    }
    let matches: Vec<_> = v.matches.into_iter().filter(|m| !rules.excl.rule(&m.id)).collect();
    let f = Finding { path: path.into(), sha256: v.sha256, matches };
    let mode = super::best(&f, &rules.policy, &rules.overrides, &rules.excl)?.1;
    Some((f, mode))
}

fn exec_worker(rx: &Mutex<Receiver<ExecJob>>, fan: &Fan, rules: &RwLock<Arc<Rules>>, cache: &Mutex<Cache>, hits: &Sender<Hit>, stats: &Stats, allowed: &Allowed) {
    loop {
        let job = match rx.lock().unwrap_or_else(|e| e.into_inner()).recv() {
            Ok(j) => j,
            Err(_) => return,
        };
        let r = rules.read().unwrap_or_else(|e| e.into_inner()).clone();
        let found = scan(&r, cache, &job.file, &job.path);
        let deny = found.as_ref().is_some_and(|(_, mode)| *mode == RuleMode::Block) && r.policy.realtime == RealtimeMode::Block;
        let in_time = job.decision.answer(fan.0, !deny, allowed);
        if in_time {
            stats.took(job.at);
            if deny {
                stats.denied.fetch_add(1, Ordering::Relaxed);
            }
        }
        if let Some((finding, _)) = found {
            let (ino, size) = job.file.metadata().map(|m| (m.ino(), m.size())).unwrap_or_default();
            let _ = hits.send(Hit { finding, what: HitKind::Exec { pid: job.pid, denied: deny && in_time, late: !in_time, ino, size } });
        }
        // The file (and with it the event's descriptor) closes only now, after the answer.
        drop(job.file);
    }
}

fn write_worker(rx: &Mutex<Receiver<WriteJob>>, rules: &RwLock<Arc<Rules>>, cache: &Mutex<Cache>, hits: &Sender<Hit>, stats: &Stats) {
    loop {
        let Ok(job) = rx.lock().unwrap_or_else(|e| e.into_inner()).recv() else { return };
        let r = rules.read().unwrap_or_else(|e| e.into_inner()).clone();
        let Some(engine) = &r.engine else { continue };
        if let Some(pid) = job.exec {
            if let Some((finding, _)) = scan(&r, cache, &job.file, &job.path) {
                let (ino, size) = job.file.metadata().map(|m| (m.ino(), m.size())).unwrap_or_default();
                let _ = hits.send(Hit { finding, what: HitKind::Exec { pid, denied: false, late: true, ino, size } });
            }
            continue;
        }
        // Bigger files are only worth a hash, and a big written file is usually a log or an
        // archive being built; programs among them are decided when they're run.
        if job.file.metadata().map_or(true, |m| m.len() == 0 || m.len() > engine.limits().content_cap) || r.excl.path(&job.path) {
            continue;
        }
        stats.write_scans.fetch_add(1, Ordering::Relaxed);
        if let Some((finding, _)) = scan(&r, cache, &job.file, &job.path) {
            let _ = hits.send(Hit { finding, what: HitKind::Write { package_manager: job.package_manager } });
        }
    }
}

/// The process `pid` still runs the file with this inode and size.
pub fn runs(pid: u32, ino: u64, size: u64) -> bool {
    std::fs::metadata(format!("/proc/{pid}/exe")).is_ok_and(|m| m.ino() == ino && m.size() == size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mountinfo_and_filesystem_choice() {
        let t = "22 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw\n\
                 23 22 0:21 / /proc rw - proc proc rw\n\
                 40 22 0:35 / /mnt/my\\040share rw - cifs //nas/share rw\n\
                 41 22 0:36 / /tmp rw - tmpfs tmpfs rw\n\
                 42 22 0:37 / /home/me/remote rw - fuse.sshfs me@host: rw\n";
        let m = parse_mountinfo(t);
        assert_eq!(m.len(), 5);
        assert_eq!(m[2].2, PathBuf::from("/mnt/my share"), "octal escapes");
        let watched: Vec<&str> = m.iter().filter(|x| !skipped_fs(&x.3)).map(|x| x.2.to_str().unwrap()).collect();
        assert_eq!(watched, ["/", "/tmp"], "network, FUSE and pseudo filesystems are skipped");
    }

    #[test]
    fn percentiles() {
        let s = Stats::default();
        s.latency.lock().unwrap().extend((1..=100).rev());
        assert_eq!(s.percentiles(), (51, 99));
        assert_eq!(s.percentiles(), (0, 0), "cleared after each report");
    }

    #[test]
    fn package_managers_by_ancestry() {
        let mut pm = PackageManagers::default();
        assert!(!pm.check(std::process::id()), "the test runner isn't one");
        assert!(!pm.check(0) && !pm.check(u32::MAX));
        // A child of a process named like a package manager counts, and stays known after it
        // exits.
        let dir = std::env::temp_dir().join(format!("rmm-pm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dpkg = dir.join("dpkg");
        std::fs::copy("/bin/sh", &dpkg).unwrap();
        let mut c = std::process::Command::new(&dpkg).args(["-c", "sleep 2; true"]).spawn().unwrap();
        std::thread::sleep(Duration::from_millis(300));
        let kids = std::fs::read_to_string(format!("/proc/{0}/task/{0}/children", c.id())).unwrap_or_default();
        let kid: Option<u32> = kids.split_whitespace().next().and_then(|k| k.parse().ok());
        assert!(pm.check(c.id()));
        if let Some(k) = kid {
            assert!(pm.check(k), "its child sleep");
        }
        c.kill().unwrap();
        c.wait().unwrap();
        assert!(pm.check(c.id()), "cached after it's gone");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
