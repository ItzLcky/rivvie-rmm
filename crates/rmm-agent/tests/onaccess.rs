//! On-access protection (fanotify) against the real sensor process, driven the way the agent
//! drives it: JSON lines on stdin and stdout. Needs root, so it's ignored by default:
//!
//! ```sh
//! scripts/test-onaccess.sh            # in a privileged Docker container (no sudo needed)
//! sudo -E cargo test -p rmm-agent --test onaccess -- --ignored --test-threads=1 --nocapture
//! ```
//!
//! No malware: the "bad" programs are copies of `/bin/sleep` and `/bin/true` with a marker
//! appended (still valid programs), listed by hash in a database signed with a throwaway key;
//! the written file is the EICAR string, assembled here at runtime.
//!
//! `RMM_ONACCESS_BIN` runs another agent binary (a release build made with
//! `RMM_UPDATE_PUBKEY` set to [`pubkey`]); debug builds take the key from the environment.
//! `RMM_ONACCESS_BENCH=1` also measures exec latency and prints it.

#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use sha2::Digest;

const SEED: [u8; 32] = [7u8; 32];

fn pubkey() -> String {
    hex::encode(SigningKey::from_bytes(&SEED).verifying_key().as_bytes())
}

fn eicar() -> Vec<u8> {
    format!("X5O!P%@AP[4\\PZX54(P^)7CC)7{}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*", "}").into_bytes()
}

fn sha(b: &[u8]) -> Vec<u8> {
    sha2::Sha256::digest(b).to_vec()
}

/// A copy of a system program with `marker` appended: runs the same, hashes differently.
/// `pad` zero bytes (a hole: no disk space) before the marker make it big.
fn program(dir: &Path, name: &str, from: &str, marker: &str, pad: u64) -> (PathBuf, Vec<u8>) {
    let b = std::fs::read(from).unwrap();
    let p = dir.join(name);
    let _ = std::fs::remove_file(&p);
    let mut f = std::fs::File::create(&p).unwrap();
    f.write_all(&b).unwrap();
    if pad <= 64 << 20 {
        // Real bytes, like a real program of that size.
        f.write_all(&(0..pad).map(|i| (i * 31 % 251) as u8).collect::<Vec<u8>>()).unwrap();
    }
    f.set_len(b.len() as u64 + pad).unwrap();
    std::io::Seek::seek(&mut f, std::io::SeekFrom::End(0)).unwrap();
    f.write_all(marker.as_bytes()).unwrap();
    drop(f);
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    // The system's sha256sum: this test binary is a debug build, slow to hash gigabytes.
    let out = Command::new("sha256sum").arg(&p).output().unwrap();
    let h = hex::decode(&String::from_utf8_lossy(&out.stdout)[..64]).unwrap();
    (p, h)
}

fn database(dir: &Path, hashes: &[(&str, Vec<u8>)]) -> PathBuf {
    let mut b = rmm_scan::db::Builder::new("onaccess-test.1", "on-access tests");
    for (name, h) in hashes {
        b.add_hash(rmm_scan::db::HashSig { algo: rmm_scan::db::Algo::Sha256, digest: h.clone(), size: None, name: name.to_string(), severity: rmm_proto::security::ThreatSeverity::High });
    }
    let key = SigningKey::from_bytes(&SEED);
    let file = rmm_scan::db::seal(b.build().unwrap(), "onaccess-test.1", |m| key.sign(m).to_bytes());
    let p = dir.join("test.rmmdb");
    std::fs::write(&p, file).unwrap();
    p
}

struct Sensor {
    child: Child,
    stdin: ChildStdin,
    out: Receiver<Value>,
    log: Receiver<String>,
}

impl Sensor {
    fn start(state: &Path) -> Sensor {
        let bin = std::env::var("RMM_ONACCESS_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_rmm-agent").to_string());
        let mut child = Command::new(bin)
            .arg("sensor")
            .env("RMM_STATE_DIR", state)
            .env("RMM_CONTENT_PUBKEY", pubkey())
            .env("RUST_LOG", std::env::var("RMM_ONACCESS_LOG").unwrap_or_else(|_| "info".into()))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let (tx, out) = channel();
        let stdout = child.stdout.take().unwrap();
        std::thread::spawn(move || {
            for l in BufReader::new(stdout).lines().map_while(Result::ok) {
                if let Ok(v) = serde_json::from_str::<Value>(&l) {
                    let _ = tx.send(v);
                }
            }
        });
        let (tx, log) = channel();
        let stderr = child.stderr.take().unwrap();
        std::thread::spawn(move || {
            for l in BufReader::new(stderr).lines().map_while(Result::ok) {
                eprintln!("  sensor: {l}");
                let _ = tx.send(l);
            }
        });
        Sensor { child, stdin, out, log }
    }

    fn send(&mut self, v: Value) {
        let mut b = serde_json::to_vec(&v).unwrap();
        b.push(b'\n');
        self.stdin.write_all(&b).unwrap();
        self.stdin.flush().unwrap();
    }

    fn configure(&mut self, realtime: &str, db: Option<&Path>) {
        self.configure_with(realtime, db, true)
    }

    fn configure_with(&mut self, realtime: &str, db: Option<&Path>, auto_quarantine: bool) {
        let policy = json!({ "enabled": true, "prevention": true, "auto_quarantine": auto_quarantine, "telemetry_mb": 16, "canaries": false,
                             "realtime": realtime, "scan_on_write": true });
        let database = db.map(|p| json!({ "current": { "version": "onaccess-test.1", "path": p }, "previous": null }));
        self.send(json!({ "t": "configure", "policy": policy, "content": null, "database": database }));
    }

    fn wait_log(&self, what: &str, secs: u64) {
        let end = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < end {
            if let Ok(l) = self.log.recv_timeout(Duration::from_millis(200))
                && l.contains(what)
            {
                return;
            }
        }
        panic!("the sensor never logged {what:?}");
    }

    /// The next detection whose resources mention `path`.
    fn detection(&self, path: &Path, secs: u64) -> Value {
        let end = Instant::now() + Duration::from_secs(secs);
        let p = path.to_string_lossy();
        while Instant::now() < end {
            if let Ok(v) = self.out.recv_timeout(Duration::from_millis(200))
                && v["t"] == "detection"
                && v["resources"].as_array().is_some_and(|r| r.iter().any(|x| x.as_str() == Some(&p)))
            {
                return v;
            }
        }
        panic!("no detection for {p}");
    }

    fn pid(&self) -> i32 {
        self.child.id() as i32
    }
}

impl Drop for Sensor {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn root() -> bool {
    // SAFETY: plain syscall.
    unsafe { libc::geteuid() == 0 }
}

/// Runs `p args` with a time limit; `Err` carries the spawn error (a denied exec is EPERM).
fn run(p: &Path, args: &[&str], secs: u64) -> std::io::Result<std::process::ExitStatus> {
    let mut c = Command::new(p).args(args).stdout(Stdio::null()).stderr(Stdio::null()).spawn()?;
    let end = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(s) = c.try_wait()? {
            return Ok(s);
        }
        if Instant::now() > end {
            let _ = c.kill();
            panic!("{} didn't finish in {secs} s", p.display());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("rmm-onaccess-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("state")).unwrap();
    d
}

#[test]
#[ignore]
fn on_access() {
    assert!(root(), "fanotify permission events need root: run scripts/test-onaccess.sh, or this test with sudo");
    let d = scratch("main");
    let (bad, bad_h) = program(&d, "bad-sleep", "/bin/sleep", "rmm-onaccess-test: bad", 0);
    let (audit_bad, audit_h) = program(&d, "audit-sleep", "/bin/sleep", "rmm-onaccess-test: audit", 0);
    let (clean, _) = program(&d, "clean-true", "/bin/true", "rmm-onaccess-test: clean", 0);
    // Big enough that hashing it takes longer than the 500 ms deadline (a release build hashes
    // about 1 GB/s here, a debug build a few MB/s).
    let pad = if std::env::var_os("RMM_ONACCESS_BIN").is_some() { 3 << 30 } else { 400 << 20 };
    let (big, big_h) = program(&d, "big-sleep", "/bin/sleep", "rmm-onaccess-test: big", pad);
    let (stuck, stuck_h) = program(&d, "stuck-true", "/bin/true", "rmm-onaccess-test: stuck", 0);
    let dpkg = d.join("dpkg");
    std::fs::copy("/bin/cp", &dpkg).unwrap();
    let db = database(&d, &[("Test.Bad", bad_h), ("Test.Audit", audit_h), ("Test.Big", big_h), ("Test.Stuck", stuck_h), ("EICAR", sha(&eicar()))]);

    let mut s = Sensor::start(&d.join("state"));
    s.configure("block", Some(&db));
    s.wait_log("on-access protection on", 20);

    // A clean program runs; again from the cache.
    assert!(run(&clean, &[], 10).unwrap().success());
    assert!(run(&clean, &[], 10).unwrap().success());

    // A program on the database is refused before it runs.
    let t = Instant::now();
    let e = run(&bad, &["5"], 10).expect_err("the exec must be denied");
    assert_eq!(e.raw_os_error(), Some(libc::EPERM), "{e}");
    println!("denied in {:?}", t.elapsed());
    let det = s.detection(&bad, 10);
    assert_eq!((det["found_by"].as_str(), det["denied"].as_bool(), det["status"].as_str()), (Some("on_exec"), Some(true), Some("quarantined")), "{det}");
    assert!(!bad.exists(), "and quarantined");

    // Written and closed: detected and quarantined.
    let written = d.join("downloaded.txt");
    std::fs::write(&written, eicar()).unwrap();
    let det = s.detection(&written, 10);
    assert_eq!((det["found_by"].as_str(), det["status"].as_str()), (Some("on_write"), Some("quarantined")), "{det}");
    std::thread::sleep(Duration::from_millis(200));
    assert!(!written.exists());

    // Written by a package manager (here `cp` named dpkg, fed through a pipe so it writes the
    // only copy): reported, never quarantined.
    let pkg = d.join("from-package.txt");
    let status = Command::new("sh").arg("-c").arg(format!("printf '%s' \"$EICAR\" | {} /dev/stdin {}", dpkg.display(), pkg.display())).env("EICAR", String::from_utf8(eicar()).unwrap()).status().unwrap();
    assert!(status.success());
    let det = s.detection(&pkg, 10);
    assert!(det["action_taken"].as_str().unwrap_or("").contains("package manager"), "{det}");
    assert!(pkg.exists(), "a package manager's file stays where it is");

    // Over the deadline: allowed, then found in the background, killed and quarantined.
    let t = Instant::now();
    let mut c = Command::new(&big).arg("60").spawn().expect("allowed after the deadline");
    let started = t.elapsed();
    println!("big program allowed after {started:?}");
    assert!(started < Duration::from_secs(3), "the deadline let it run: {started:?}");
    let det = s.detection(&big, 120);
    assert!(det["action_taken"].as_str().unwrap_or("").contains("killed"), "{det}");
    assert_eq!(det["denied"], false);
    let end = Instant::now() + Duration::from_secs(10);
    while c.try_wait().unwrap().is_none() {
        assert!(Instant::now() < end, "the late verdict killed it");
        std::thread::sleep(Duration::from_millis(50));
    }

    // Audit: decided, reported, never denied.
    s.configure("audit", None);
    std::thread::sleep(Duration::from_millis(500));
    assert!(run(&audit_bad, &["0"], 10).unwrap().success(), "audit never denies");
    let det = s.detection(&audit_bad, 10);
    assert_eq!(det["denied"], false);
    assert!(det["action_taken"].as_str().unwrap_or("").contains("audit"), "{det}");
    assert!(audit_bad.exists(), "audit doesn't quarantine");

    // A sensor that is stopped holds every exec; killing it releases them at once.
    s.configure("block", None);
    std::thread::sleep(Duration::from_millis(500));
    // SAFETY: signals the child we started.
    unsafe { libc::kill(s.pid(), libc::SIGSTOP) };
    let waiting = {
        let stuck = stuck.clone();
        std::thread::spawn(move || {
            let t = Instant::now();
            let r = run(&stuck, &[], 60);
            (r.map(|s| s.success()).map_err(|e| e.raw_os_error()), t.elapsed())
        })
    };
    std::thread::sleep(Duration::from_secs(2));
    assert!(!waiting.is_finished(), "the exec waits on the stopped sensor");
    // SAFETY: as above.
    unsafe { libc::kill(s.pid(), libc::SIGKILL) };
    let (r, took) = waiting.join().unwrap();
    println!("exec released {took:?} after it started (sensor killed at 2 s)");
    assert_eq!(r, Ok(true), "allowed when the sensor died");
    assert!(took < Duration::from_secs(4), "{took:?}");
    drop(s);

    // The agent restarts it: protection comes back, decisions too.
    let (bad2, _) = program(&d, "bad-sleep", "/bin/sleep", "rmm-onaccess-test: bad", 0);
    let mut s = Sensor::start(&d.join("state"));
    s.configure("block", Some(&db));
    s.wait_log("on-access protection on", 20);
    let e = run(&bad2, &["5"], 10).expect_err("denied again after a restart");
    assert_eq!(e.raw_os_error(), Some(libc::EPERM));
    // Many restarts while programs run: nothing hangs.
    for _ in 0..5 {
        // SAFETY: as above.
        unsafe { libc::kill(s.pid(), libc::SIGKILL) };
        drop(s);
        s = Sensor::start(&d.join("state"));
        s.configure("block", Some(&db));
        for _ in 0..20 {
            assert!(run(&clean, &[], 10).unwrap().success());
        }
    }
    s.wait_log("on-access protection on", 20);
    drop(s);
    if std::env::var("RMM_ONACCESS_BENCH").is_ok_and(|v| !v.is_empty()) {
        bench(&d, &db);
    }
    let _ = std::fs::remove_dir_all(&d);
}

/// Pids of processes whose parent is `ppid` and whose command line ends in `sensor`.
fn sensors_of(ppid: u32) -> Vec<u32> {
    std::fs::read_dir("/proc")
        .unwrap()
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .filter(|pid| {
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
            let parent = stat.rfind(')').and_then(|i| stat[i + 1..].split_whitespace().nth(1)?.parse::<u32>().ok());
            let cmd = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
            parent == Some(ppid) && String::from_utf8_lossy(&cmd).trim_end_matches('\0').ends_with("sensor")
        })
        .collect()
}

/// The real supervisor (`rmm-agent supervise-sensor`, the agent's own code without a server)
/// against a sensor that is stopped with SIGSTOP while real-time protection is on: an exec waits
/// on it until the supervisor notices the silence (`supervisor::QUIET`, 10 s) and kills it, which
/// releases the exec; then the supervisor starts a new sensor and protection comes back.
#[test]
#[ignore]
fn supervisor_kills_a_stopped_sensor() {
    assert!(root(), "fanotify permission events need root: run scripts/test-onaccess.sh, or this test with sudo");
    let d = scratch("supervisor");
    let state = d.join("state");
    let (fresh, _) = program(&d, "fresh-true", "/bin/true", "rmm-onaccess-test: supervisor", 0);
    let (listed, listed_h) = program(&d, "listed-sleep", "/bin/sleep", "rmm-onaccess-test: supervisor listed", 0);
    let db = database(&d, &[("Test.Listed", listed_h)]);
    // What the agent keeps in its state directory: the policy, and the database it verified.
    let sec = state.join("security");
    std::fs::create_dir_all(sec.join("db")).unwrap();
    let bytes = std::fs::read(&db).unwrap();
    let sha = hex::encode(sha(&bytes));
    std::fs::write(sec.join("db").join(format!("{}.rmmdb", &sha[..32])), &bytes).unwrap();
    std::fs::write(
        sec.join("database.json"),
        serde_json::to_vec(&json!({ "current": { "version": "onaccess-test.1", "sha256": sha, "size": bytes.len(), "created_at": "2026-11-15T00:00:00Z" }, "previous": null })).unwrap(),
    )
    .unwrap();
    std::fs::write(
        sec.join("policy.json"),
        serde_json::to_vec(&json!({ "enabled": true, "prevention": true, "auto_quarantine": false, "telemetry_mb": 16, "canaries": false, "realtime": "block", "scan_on_write": false }))
            .unwrap(),
    )
    .unwrap();

    let bin = std::env::var("RMM_ONACCESS_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_rmm-agent").to_string());
    let mut sup = Command::new(bin)
        .arg("supervise-sensor")
        .env("RMM_STATE_DIR", &state)
        .env("RMM_CONTENT_PUBKEY", pubkey())
        .env("RUST_LOG", std::env::var("RMM_ONACCESS_LOG").unwrap_or_else(|_| "info".into()))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let (tx, status) = channel::<Value>();
    let stdout = sup.stdout.take().unwrap();
    std::thread::spawn(move || {
        for l in BufReader::new(stdout).lines().map_while(Result::ok) {
            if let Ok(v) = serde_json::from_str::<Value>(&l) {
                let _ = tx.send(v);
            }
        }
    });
    let wait = |what: &str, secs: u64, f: &dyn Fn(&Value) -> bool| -> Value {
        let end = Instant::now() + Duration::from_secs(secs);
        let mut last = Value::Null;
        while Instant::now() < end {
            if let Ok(v) = status.recv_timeout(Duration::from_millis(200)) {
                if f(&v) {
                    return v;
                }
                last = v;
            }
        }
        panic!("timed out waiting for {what}; last status: {last}");
    };
    let on = |v: &Value| v["running"] == true && v["health"]["realtime"]["state"] == "on";
    wait("real-time protection on", 60, &on);
    let e = run(&listed, &["5"], 10).expect_err("the supervised sensor denies a listed program");
    assert_eq!(e.raw_os_error(), Some(libc::EPERM));

    let pids = sensors_of(sup.id());
    assert_eq!(pids.len(), 1, "one sensor under the supervisor: {pids:?}");
    let stopped = pids[0];
    // SAFETY: signals the sensor this test's supervisor started.
    unsafe { libc::kill(stopped as i32, libc::SIGSTOP) };
    let t = Instant::now();
    let waiting = std::thread::spawn(move || {
        let r = run(&fresh, &[], 60);
        (r.map(|s| s.success()).map_err(|e| e.raw_os_error()), t.elapsed())
    });
    std::thread::sleep(Duration::from_secs(2));
    assert!(!waiting.is_finished(), "the exec waits on the stopped sensor");
    let (r, took) = waiting.join().unwrap();
    println!("exec held {took:?} by a stopped sensor before the supervisor killed it");
    assert_eq!(r, Ok(true), "allowed once the stopped sensor was killed");
    // QUIET is 10 s from the last message (at most 2 s before the stop), checked every 2 s.
    assert!(took >= Duration::from_secs(7) && took < Duration::from_secs(16), "released by the supervisor's watchdog: {took:?}");
    assert!(!Path::new(&format!("/proc/{stopped}")).exists() || std::fs::read_to_string(format!("/proc/{stopped}/stat")).is_ok_and(|s| s.contains(") Z ")), "the stopped sensor was killed");

    let v = wait("the supervisor to report the restart", 30, &|v| v["restarts"].as_u64() >= Some(1));
    assert!(v["error"].as_str().unwrap_or("").contains("stopped answering"), "{v}");
    wait("a new sensor with real-time protection on", 60, &on);
    let new = sensors_of(sup.id());
    assert!(new.len() == 1 && new[0] != stopped, "{new:?}");
    let (listed2, _) = program(&d, "listed-sleep", "/bin/sleep", "rmm-onaccess-test: supervisor listed", 0);
    let e = run(&listed2, &["5"], 10).expect_err("denied by the new sensor");
    assert_eq!(e.raw_os_error(), Some(libc::EPERM));

    // Closing its stdin isn't how the agent stops; killing the supervisor closes the sensor's.
    let _ = sup.kill();
    let _ = sup.wait();
    let end = Instant::now() + Duration::from_secs(15);
    while Path::new(&format!("/proc/{}", new[0])).exists() && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = std::fs::remove_dir_all(&d);
}

/// Median wall time of `n` runs of `p`, `prep` before each.
fn median(n: usize, p: &Path, mut prep: impl FnMut()) -> Duration {
    let mut t: Vec<Duration> = (0..n)
        .map(|_| {
            prep();
            let s = Instant::now();
            assert!(Command::new(p).status().unwrap().success());
            s.elapsed()
        })
        .collect();
    t.sort();
    t[n / 2]
}

/// A database like a real one: a million hashes and the first-party YARA rules.
fn bench_database(dir: &Path) -> PathBuf {
    let mut b = rmm_scan::db::Builder::new("onaccess-test.1", "on-access benchmark");
    for i in 0..1_000_000u32 {
        b.add_hash(rmm_scan::db::HashSig { algo: rmm_scan::db::Algo::Sha256, digest: sha(&i.to_le_bytes()), size: None, name: format!("Bench.{}", i % 50), severity: rmm_proto::security::ThreatSeverity::High });
    }
    let yara = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../content/yara");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&yara).unwrap().flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "yar")).collect();
    files.sort();
    for f in files {
        let ns = f.file_stem().unwrap().to_string_lossy().into_owned();
        b.add_yara(&format!("{}{ns}\n{}", rmm_scan::rules::NAMESPACE_MARKER, std::fs::read_to_string(&f).unwrap()));
    }
    let key = SigningKey::from_bytes(&SEED);
    let file = rmm_scan::db::seal(b.build().unwrap(), "onaccess-test.1", |m| key.sign(m).to_bytes());
    let p = dir.join("bench.rmmdb");
    std::fs::write(&p, file).unwrap();
    p
}

fn sh(cmd: &str) -> Duration {
    let t = Instant::now();
    let s = Command::new("sh").arg("-c").arg(cmd).stdout(Stdio::null()).status().unwrap();
    assert!(s.success(), "{cmd}");
    t.elapsed()
}

/// Added latency per exec of a ~10 MB program on a cache hit and a miss, then real workloads
/// with the sensor off, running with real-time protection off, and in block mode.
fn bench(d: &Path, _db: &Path) {
    let db = bench_database(d);
    let (p, _) = program(d, "ten-mb-true", "/bin/true", "rmm-onaccess-bench", 10 << 20);
    // A miss: changing ctime (chmod to the same mode) gives the file a new cache key.
    let touch = || std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    let n = 201;
    let off_hit = median(n, &p, || {});
    let off_miss = median(n, &p, touch);
    let mut s = Sensor::start(&d.join("state"));
    s.configure("block", Some(&db));
    s.wait_log("on-access protection on", 60);
    let on_miss = median(n, &p, touch);
    let on_hit = median(n, &p, || {});
    drop(s);
    println!("BENCH exec of a 10 MB program, median of {n}:");
    println!("BENCH   no sensor: {off_hit:?} (unchanged file), {off_miss:?} (chmod before each)");
    println!("BENCH   block, cache hit: {on_hit:?}, added {:?}", on_hit.saturating_sub(off_hit));
    println!("BENCH   block, cache miss: {on_miss:?}, added {:?}", on_miss.saturating_sub(off_miss));

    let pkgs = std::env::var("RMM_ONACCESS_APT").unwrap_or_else(|_| "default-jre-headless python3-numpy".into());
    // Our own archive folder: Docker images delete apt's after every dpkg run.
    let archives = d.join("apt-archives");
    std::fs::create_dir_all(archives.join("partial")).unwrap();
    let apt = format!("DEBIAN_FRONTEND=noninteractive apt-get -y -qq -o Dir::Cache::Archives={}/", archives.display());
    sh(&format!("apt-get update -qq && {apt} install --download-only {pkgs}"));
    let install = format!("{apt} install --no-download {pkgs}");
    let purge = format!("DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq --auto-remove {pkgs}");
    // Unpacking and compiling: this workspace's sources copied out (a few hundred files
    // written), then the scan engine and its dependencies compiled offline with 4 jobs (rustc,
    // build scripts and the linker run a few hundred times).
    let w = d.join("build");
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let build = Some(format!(
        "rm -rf {w} && mkdir -p {w}/content && cp -r {src}/Cargo.toml {src}/Cargo.lock {src}/crates {w}/ && cp {src}/content/starter.json {src}/content/benign.jsonl {w}/content/ \
         && cd {w} && sed -i 's|^members = .*|members = [\"crates/rmm-proto\", \"crates/rmm-content\", \"crates/rmm-scan\"]|' Cargo.toml \
         && CARGO_TARGET_DIR={w}/target cargo build --offline -q -j4 -p rmm-scan",
        w = w.display(),
        src = src.display()
    ));
    // Rounds, each running every configuration once, so drift (caches warming, apt's
    // triggers) hits them alike.
    let modes = [("no sensor", None), ("sensor, real-time off", Some("off")), ("sensor, block", Some("block"))];
    let mut apt: Vec<Vec<Duration>> = vec![vec![]; modes.len()];
    let mut make: Vec<Vec<Duration>> = vec![vec![]; modes.len()];
    let mut counters = String::new();
    for _ in 0..7 {
        for (i, (_, mode)) in modes.iter().enumerate() {
            // Auto-quarantine off: the copied sources include the content bundle, whose rule
            // strings match its own rules when written (and the build would lose the file).
            let mut s = mode.map(|m| {
                let mut s = Sensor::start(&d.join("state"));
                s.configure_with(m, Some(&db), false);
                if m == "block" {
                    s.wait_log("on-access protection on", 60);
                } else {
                    std::thread::sleep(Duration::from_secs(2));
                }
                s
            });
            sh(&purge);
            apt[i].push(sh(&install));
            if let Some(b) = &build {
                make[i].push(sh(b));
            }
            if let Some((s, m)) = s.as_mut().zip(*mode).filter(|(_, m)| *m == "block") {
                // Configuring again reports health at once, with the decision counters.
                while s.out.try_recv().is_ok() {}
                s.configure_with(m, None, false);
                let end = Instant::now() + Duration::from_secs(10);
                while Instant::now() < end {
                    if let Ok(v) = s.out.recv_timeout(Duration::from_millis(200))
                        && v["t"] == "health"
                    {
                        counters = format!("{}", v["realtime"]);
                        break;
                    }
                }
            }
            drop(s);
        }
    }
    let stat = |v: &mut Vec<Duration>| {
        v.sort();
        format!("median {:.2} s, min {:.2} s, max {:.2} s", v[v.len() / 2].as_secs_f64(), v[0].as_secs_f64(), v[v.len() - 1].as_secs_f64())
    };
    for (i, (label, _)) in modes.iter().enumerate() {
        println!("BENCH {label}: apt-get install {pkgs}: {}", stat(&mut apt[i]));
        if !make[i].is_empty() {
            println!("BENCH {label}: copy the sources and build rmm-scan: {}", stat(&mut make[i]));
        }
    }
    println!("BENCH block, last round's counters: {counters}");
    sh(&purge);
}

/// `scripts/test-onaccess.sh --release` builds a release agent that trusts this test's key.
#[test]
fn the_script_has_the_test_key() {
    let script = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../scripts/test-onaccess.sh")).unwrap();
    assert!(script.contains(&pubkey()), "set TEST_KEY in scripts/test-onaccess.sh to {}", pubkey());
}
