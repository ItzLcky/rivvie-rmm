//! One-shot script execution with streamed output.
//!
//! Jobs outlive connections. Output goes through a [`Tracker`] that keeps a copy (up to
//! [`JOB_OUTPUT_BUFFER`] per stream) and forwards it to whichever connection is current.
//! After a reconnect the agent resends each job's output and any unacknowledged result,
//! so a dropped socket or server restart no longer loses the job.
//!
//! The tracker also keeps each job on disk ([`Store`]), so an agent restart (crash, reboot,
//! self-update) doesn't lose finished results either. A job that was still running when the
//! agent stopped is reported as `error` with the output it had produced.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rmm_proto::{AgentMsg, Interpreter, JOB_OUTPUT_BUFFER, JobStatus, OutputStream, ScriptJob};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::sync::mpsc;
use tracing::{info, warn};
use uuid::Uuid;

/// Finished results wait this long for the server's ack (an older server never sends one).
const KEEP_UNACKED: Duration = Duration::from_secs(24 * 3600);
const MAX_UNACKED: usize = 500;

#[derive(Default)]
struct Tracked {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    /// The `JobFinished` message, once the job is done, and when.
    finished: Option<(AgentMsg, Instant)>,
}

#[derive(Default)]
pub struct Tracker {
    /// Held while sending, so a reconnect's resend and live output can't interleave.
    jobs: tokio::sync::Mutex<HashMap<Uuid, Tracked>>,
    /// The current connection's outbound queue; `None` while disconnected. A plain mutex so
    /// [`Tracker::detach`] never waits behind a send stuck on a dying socket.
    link: std::sync::Mutex<Option<mpsc::Sender<AgentMsg>>>,
    /// `None` in tests, or when the state directory can't be created.
    store: Option<Store>,
}

impl Tracker {
    /// A tracker backed by the agent's state directory, holding whatever the previous run
    /// left there.
    pub fn open() -> Self {
        match crate::config::state_subdir("job-results") {
            Ok(dir) => Self::with_store(Store::new(dir)),
            Err(e) => {
                warn!("job results won't survive an agent restart: {e:#}");
                Self::default()
            }
        }
    }

    fn with_store(store: Store) -> Self {
        let mut jobs = store.load();
        for id in prune(&mut jobs) {
            store.remove(id);
        }
        if !jobs.is_empty() {
            info!(jobs = jobs.len(), "loaded job results from the previous run");
        }
        Self { jobs: tokio::sync::Mutex::new(jobs), link: Default::default(), store: Some(store) }
    }

    fn prune(&self, jobs: &mut HashMap<Uuid, Tracked>) {
        for id in prune(jobs) {
            if let Some(s) = &self.store {
                s.remove(id);
            }
        }
    }

    fn link(&self) -> Option<mpsc::Sender<AgentMsg>> {
        self.link.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    async fn emit(&self, msg: AgentMsg) {
        if let Some(tx) = self.link() {
            // A failure means the connection just died; the next attach resends.
            let _ = tx.send(msg).await;
        }
    }

    /// Jobs still held, for the `Auth` message.
    pub async fn ids(&self) -> Vec<Uuid> {
        self.jobs.lock().await.keys().copied().collect()
    }

    /// Jobs still executing (not just awaiting an ack).
    pub async fn running(&self) -> usize {
        self.jobs.lock().await.values().filter(|j| j.finished.is_none()).count()
    }

    /// New connection: resend what each job has produced so far, then stream live.
    pub async fn attach(&self, tx: mpsc::Sender<AgentMsg>) {
        let mut jobs = self.jobs.lock().await;
        self.prune(&mut jobs);
        for (&job_id, job) in jobs.iter() {
            let _ = tx.send(AgentMsg::JobSync { job_id, stdout: job.stdout.clone(), stderr: job.stderr.clone() }).await;
            if let Some((done, _)) = &job.finished {
                let _ = tx.send(done.clone()).await;
            }
        }
        if !jobs.is_empty() {
            info!(jobs = jobs.len(), "resent job state after reconnect");
        }
        *self.link.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);
    }

    pub fn detach(&self) {
        *self.link.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// Registers a job; false if it's already known (the server sent it twice).
    async fn start(&self, job_id: Uuid) -> bool {
        let mut jobs = self.jobs.lock().await;
        self.prune(&mut jobs);
        if jobs.contains_key(&job_id) {
            return false;
        }
        jobs.insert(job_id, Tracked::default());
        if let Some(s) = &self.store {
            s.started(job_id);
        }
        true
    }

    async fn output(&self, job_id: Uuid, stream: OutputStream, data: Vec<u8>) {
        let mut jobs = self.jobs.lock().await;
        if let Some(job) = jobs.get_mut(&job_id) {
            let buf = match stream {
                OutputStream::Stdout => &mut job.stdout,
                OutputStream::Stderr => &mut job.stderr,
            };
            let room = JOB_OUTPUT_BUFFER.saturating_sub(buf.len());
            let kept = &data[..data.len().min(room)];
            buf.extend_from_slice(kept);
            if let Some(s) = &self.store
                && !kept.is_empty()
            {
                s.append(job_id, stream, kept);
            }
        }
        self.emit(AgentMsg::JobOutput { job_id, stream, data }).await;
        drop(jobs);
    }

    async fn finish(&self, msg: AgentMsg) {
        let AgentMsg::JobFinished { job_id, .. } = msg else { return };
        let mut jobs = self.jobs.lock().await;
        if let Some(job) = jobs.get_mut(&job_id) {
            job.finished = Some((msg.clone(), Instant::now()));
            if let Some(s) = &self.store {
                s.finished(job_id, &msg, unix_now());
            }
        }
        self.emit(msg).await;
        drop(jobs);
    }

    /// The server stored the result.
    pub async fn ack(&self, job_id: Uuid) {
        let mut jobs = self.jobs.lock().await;
        if jobs.get(&job_id).is_some_and(|j| j.finished.is_some()) {
            jobs.remove(&job_id);
            if let Some(s) = &self.store {
                s.remove(job_id);
            }
        }
    }
}

/// Drops results nobody acknowledged: too old, or too many (oldest first). Returns the
/// dropped ids.
fn prune(jobs: &mut HashMap<Uuid, Tracked>) -> Vec<Uuid> {
    let mut dropped: Vec<Uuid> = jobs
        .iter()
        .filter(|(_, j)| j.finished.as_ref().is_some_and(|(_, at)| at.elapsed() >= KEEP_UNACKED))
        .map(|(id, _)| *id)
        .collect();
    for id in &dropped {
        jobs.remove(id);
    }
    let mut done: Vec<(Instant, Uuid)> = jobs.iter().filter_map(|(id, j)| j.finished.as_ref().map(|(_, at)| (*at, *id))).collect();
    if done.len() > MAX_UNACKED {
        done.sort();
        for (_, id) in &done[..done.len() - MAX_UNACKED] {
            jobs.remove(id);
            dropped.push(*id);
        }
    }
    dropped
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

const RESTARTED_NOTE: &str = "\n[rmm-agent] the agent stopped while this job was running; output up to that point is above\n";

/// Each job as a directory under the agent's state directory:
///
/// - `started`: unix seconds, written when the job starts;
/// - `stdout`, `stderr`: appended as output arrives (capped like the in-memory copy);
/// - `finished.json`: the `JobFinished` message and when, written atomically.
///
/// The directory is removed once the server acknowledges the result. Write failures are
/// logged once and otherwise ignored: the job itself must not fail because the disk is full.
struct Store {
    dir: PathBuf,
    warned: AtomicBool,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct StoredFinish {
    at: u64,
    msg: AgentMsg,
}

impl Store {
    fn new(dir: PathBuf) -> Self {
        Self { dir, warned: AtomicBool::new(false) }
    }

    fn job_dir(&self, id: Uuid) -> PathBuf {
        self.dir.join(id.to_string())
    }

    fn check(&self, what: &str, res: std::io::Result<()>) {
        if let Err(e) = res
            && !self.warned.swap(true, Ordering::Relaxed)
        {
            warn!("can't save job state ({what}) in {}: {e}; results may not survive an agent restart", self.dir.display());
        }
    }

    fn started(&self, id: Uuid) {
        let d = self.job_dir(id);
        let res = std::fs::create_dir_all(&d).and_then(|()| std::fs::write(d.join("started"), unix_now().to_string()));
        self.check("start", res);
    }

    fn append(&self, id: Uuid, stream: OutputStream, data: &[u8]) {
        let name = match stream {
            OutputStream::Stdout => "stdout",
            OutputStream::Stderr => "stderr",
        };
        let res = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.job_dir(id).join(name))
            .and_then(|mut f| std::io::Write::write_all(&mut f, data));
        self.check("output", res);
    }

    fn finished(&self, id: Uuid, msg: &AgentMsg, at: u64) {
        let d = self.job_dir(id);
        let body = serde_json::to_vec(&StoredFinish { at, msg: msg.clone() }).unwrap_or_default();
        let tmp = d.join("finished.json.tmp");
        let res = std::fs::create_dir_all(&d)
            .and_then(|()| std::fs::write(&tmp, body))
            .and_then(|()| std::fs::rename(&tmp, d.join("finished.json")));
        self.check("result", res);
    }

    fn remove(&self, id: Uuid) {
        let _ = std::fs::remove_dir_all(self.job_dir(id));
    }

    /// Everything the previous run left. Jobs that never finished are closed off as `error`
    /// (and saved that way, so another restart reports the same thing).
    fn load(&self) -> HashMap<Uuid, Tracked> {
        let mut jobs = HashMap::new();
        let Ok(entries) = std::fs::read_dir(&self.dir) else { return jobs };
        let now = unix_now();
        for entry in entries.flatten() {
            let Some(id) = entry.file_name().to_str().and_then(|n| Uuid::parse_str(n).ok()) else { continue };
            let d = entry.path();
            match self.load_one(id, &d, now) {
                Some(job) => {
                    jobs.insert(id, job);
                }
                None => {
                    let _ = std::fs::remove_dir_all(&d);
                }
            }
        }
        jobs
    }

    fn load_one(&self, id: Uuid, d: &Path, now: u64) -> Option<Tracked> {
        let read = |name: &str| {
            let mut b = std::fs::read(d.join(name)).unwrap_or_default();
            b.truncate(JOB_OUTPUT_BUFFER);
            b
        };
        let mut job = Tracked { stdout: read("stdout"), stderr: read("stderr"), finished: None };
        let ago = |at: u64| Instant::now().checked_sub(Duration::from_secs(now.saturating_sub(at))).unwrap_or_else(Instant::now);
        if let Some(f) = std::fs::read(d.join("finished.json")).ok().and_then(|b| serde_json::from_slice::<StoredFinish>(&b).ok()) {
            if !matches!(&f.msg, AgentMsg::JobFinished { job_id, .. } if *job_id == id) {
                return None;
            }
            job.finished = Some((f.msg, ago(f.at)));
            return Some(job);
        }
        // Started but never finished: the agent stopped mid-job, and the process went with it.
        let started: u64 = std::fs::read_to_string(d.join("started")).ok()?.trim().parse().ok()?;
        let room = JOB_OUTPUT_BUFFER.saturating_sub(job.stderr.len());
        let note = &RESTARTED_NOTE.as_bytes()[..RESTARTED_NOTE.len().min(room)];
        job.stderr.extend_from_slice(note);
        self.append(id, OutputStream::Stderr, note);
        let msg = AgentMsg::JobFinished {
            job_id: id,
            status: JobStatus::Error,
            exit_code: None,
            duration_ms: now.saturating_sub(started).saturating_mul(1000),
        };
        self.finished(id, &msg, now);
        job.finished = Some((msg, Instant::now()));
        warn!(job_id = %id, "job was interrupted by an agent restart");
        Some(job)
    }
}

pub async fn run(job: ScriptJob, tracker: Arc<Tracker>) {
    let started = Instant::now();
    let job_id = job.job_id;
    if !tracker.start(job_id).await {
        warn!(%job_id, "job already received; ignoring the duplicate");
        return;
    }
    info!(%job_id, interpreter = ?job.interpreter, "running script");

    let (status, exit_code) = match execute(&job, &tracker).await {
        Ok(r) => r,
        Err(e) => {
            warn!(%job_id, "script failed to start: {e:#}");
            tracker.output(job_id, OutputStream::Stderr, format!("agent error: {e:#}\n").into_bytes()).await;
            (JobStatus::Error, None)
        }
    };

    tracker
        .finish(AgentMsg::JobFinished { job_id, status, exit_code, duration_ms: started.elapsed().as_millis() as u64 })
        .await;
}

/// The longest environment value the server may send, and all of them together.
const ENV_VALUE_MAX: usize = 8 * 1024;
const ENV_TOTAL_MAX: usize = 24 * 1024;

/// Checks the job's environment again (the server built it): only `RMM_[A-Z0-9_]+` names, so a
/// job can't set `PATH` or `LD_PRELOAD`, and bounded values (a Windows environment block is
/// limited). Errors never include a value: some are secrets.
fn check_env(env: &[(String, String)]) -> Result<()> {
    let mut total = 0;
    for (k, v) in env {
        let name_ok = k.strip_prefix("RMM_").is_some_and(|r| !r.is_empty() && r.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'));
        anyhow::ensure!(name_ok, "refusing environment variable {k:?}: only RMM_ names may be set");
        anyhow::ensure!(v.len() <= ENV_VALUE_MAX && !v.contains('\0'), "the value of {k} is too long (or holds a NUL)");
        total += k.len() + v.len() + 2;
    }
    anyhow::ensure!(total <= ENV_TOTAL_MAX, "the script's environment is larger than {} KiB", ENV_TOTAL_MAX / 1024);
    Ok(())
}

async fn execute(job: &ScriptJob, tracker: &Arc<Tracker>) -> Result<(JobStatus, Option<i32>)> {
    check_env(&job.env)?;
    let script = ScriptFile::create(job)?;
    let mut cmd = command_for(job.interpreter, &script.path)?;
    // Parameters reach the script only as environment variables (never in its text or argv).
    cmd.envs(job.env.iter().map(|(k, v)| (k, v)));
    cmd.args(&job.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    // Own process group, so a timeout kills grandchildren too (they'd otherwise hold the pipes open).
    #[cfg(unix)]
    cmd.process_group(0);

    let mut child = cmd.spawn().context("spawning interpreter")?;
    // Windows: the tree goes in a Job Object, the counterpart of the process group. It's
    // kill-on-close while the script runs, so an agent that stops mid-job takes the tree with
    // it (as systemd does on Linux), and released once the script exits: like on Unix, what
    // a script leaves running in the background survives it. A timeout kills the tree.
    #[cfg(windows)]
    let tree = child.raw_handle().and_then(|h| match crate::winjob::ProcessTree::new(h, true) {
        Ok(t) => Some(t),
        Err(e) => {
            warn!(job_id = %job.job_id, "a timeout will only kill the interpreter: {e:#}");
            None
        }
    });
    #[cfg(not(windows))]
    let tree = ();
    let stdout = child.stdout.take().expect("piped");
    let stderr = child.stderr.take().expect("piped");
    let pump_out = tokio::spawn(pump(stdout, OutputStream::Stdout, job.job_id, tracker.clone()));
    let pump_err = tokio::spawn(pump(stderr, OutputStream::Stderr, job.job_id, tracker.clone()));

    let timeout = Duration::from_secs(job.timeout_secs.max(1) as u64);
    let result = match tokio::time::timeout(timeout, child.wait()).await {
        Ok(status) => {
            let status = status?;
            #[cfg(windows)]
            if let Some(Err(e)) = tree.as_ref().map(|t| t.release()) {
                warn!(job_id = %job.job_id, "processes the script left running may be killed: {e:#}");
            }
            let code = status.code();
            (if status.success() { JobStatus::Succeeded } else { JobStatus::Failed }, code)
        }
        Err(_) => {
            kill_tree(&mut child, &tree).await;
            (JobStatus::TimedOut, None)
        }
    };
    // Drain remaining output so JobFinished arrives after the last chunk, but don't
    // let a detached grandchild that inherited the pipe hold the job open forever.
    for pump in [pump_out, pump_err] {
        let abort = pump.abort_handle();
        if tokio::time::timeout(Duration::from_secs(3), pump).await.is_err() {
            abort.abort();
        }
    }
    Ok(result)
}

#[cfg(windows)]
type Tree = Option<crate::winjob::ProcessTree>;
#[cfg(not(windows))]
type Tree = ();

async fn kill_tree(child: &mut tokio::process::Child, tree: &Tree) {
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        // SAFETY: plain syscall; negative pid targets the process group we created.
        unsafe {
            libc::kill(-(pid as i32), libc::SIGKILL);
        }
    }
    #[cfg(windows)]
    if let Some(t) = tree {
        t.kill();
    }
    #[cfg(not(windows))]
    let () = tree;
    let _ = child.kill().await;
}

async fn pump(mut r: impl AsyncRead + Unpin, stream: OutputStream, job_id: Uuid, tracker: Arc<Tracker>) {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match r.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => tracker.output(job_id, stream, buf[..n].to_vec()).await,
        }
    }
}

fn command_for(interp: Interpreter, path: &std::path::Path) -> Result<Command> {
    let windows = cfg!(windows);
    let cmd = match interp {
        Interpreter::Sh if !windows => {
            let mut c = Command::new("/bin/sh");
            c.arg(path);
            c
        }
        Interpreter::Bash => {
            let mut c = Command::new("bash");
            c.arg(path);
            c
        }
        Interpreter::PowerShell => {
            let mut c = Command::new(if windows { "powershell.exe" } else { "pwsh" });
            c.args(["-NoProfile", "-NonInteractive"]);
            if windows {
                c.args(["-ExecutionPolicy", "Bypass"]);
            }
            c.arg("-File").arg(path);
            c
        }
        Interpreter::Cmd if windows => {
            let mut c = Command::new("cmd.exe");
            c.arg("/D").arg("/C").arg(path);
            c
        }
        Interpreter::Python => {
            let mut c = Command::new(if windows { "python" } else { "python3" });
            c.arg(path);
            c
        }
        other => anyhow::bail!("interpreter {other:?} is not supported on this OS"),
    };
    Ok(cmd)
}

/// On Windows, SYSTEM's temp dir is shared with other accounts' scratch files, so use the
/// agent's locked-down data directory. On Unix, /tmp with O_EXCL and mode 0700 is fine.
#[cfg(windows)]
fn scratch_dir() -> Result<PathBuf> {
    let dir = crate::config::data_dir().context("no data directory")?.join("jobs");
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}

#[cfg(not(windows))]
fn scratch_dir() -> Result<PathBuf> {
    Ok(std::env::temp_dir())
}

/// Script written to a private temp file, removed on drop.
struct ScriptFile {
    path: PathBuf,
}

impl ScriptFile {
    fn create(job: &ScriptJob) -> Result<Self> {
        let ext = match job.interpreter {
            Interpreter::PowerShell => "ps1",
            Interpreter::Cmd => "cmd",
            Interpreter::Python => "py",
            Interpreter::Sh | Interpreter::Bash => "sh",
        };
        let path = scratch_dir()?.join(format!("rmm-job-{}.{ext}", job.job_id));
        let mut opts = std::fs::OpenOptions::new();
        // create_new => O_EXCL, so a pre-planted symlink in /tmp can't redirect the write.
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o700);
        }
        let mut f = opts.open(&path).with_context(|| format!("creating {}", path.display()))?;
        let mut body = job.script.clone();
        if matches!(job.interpreter, Interpreter::Cmd) {
            body = body.replace("\r\n", "\n").replace('\n', "\r\n");
        }
        std::io::Write::write_all(&mut f, body.as_bytes())?;
        Ok(Self { path })
    }
}

impl Drop for ScriptFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finished(job_id: Uuid) -> AgentMsg {
        AgentMsg::JobFinished { job_id, status: JobStatus::Succeeded, exit_code: Some(0), duration_ms: 1 }
    }

    async fn drain(rx: &mut mpsc::Receiver<AgentMsg>) -> Vec<AgentMsg> {
        let mut out = vec![];
        while let Ok(m) = rx.try_recv() {
            out.push(m);
        }
        out
    }

    #[tokio::test]
    async fn output_while_disconnected_is_resent_on_attach() {
        let t = Tracker::default();
        let id = Uuid::new_v4();
        assert!(t.start(id).await);
        assert!(!t.start(id).await, "duplicate dispatch is ignored");

        let (tx1, mut rx1) = mpsc::channel(16);
        t.attach(tx1).await;
        t.output(id, OutputStream::Stdout, b"one ".to_vec()).await;
        assert!(matches!(drain(&mut rx1).await.as_slice(), [AgentMsg::JobSync { .. }, AgentMsg::JobOutput { .. }]));

        // Connection drops; the job keeps producing output and finishes.
        t.detach();
        t.output(id, OutputStream::Stdout, b"two".to_vec()).await;
        t.output(id, OutputStream::Stderr, b"warn".to_vec()).await;
        t.finish(finished(id)).await;
        assert_eq!(t.ids().await, vec![id]);
        assert_eq!(t.running().await, 0);

        let (tx2, mut rx2) = mpsc::channel(16);
        t.attach(tx2).await;
        match drain(&mut rx2).await.as_slice() {
            [AgentMsg::JobSync { job_id, stdout, stderr }, AgentMsg::JobFinished { .. }] => {
                assert_eq!(*job_id, id);
                assert_eq!(stdout, b"one two");
                assert_eq!(stderr, b"warn");
            }
            other => panic!("unexpected {other:?}"),
        }

        t.ack(id).await;
        assert!(t.ids().await.is_empty());
    }

    #[tokio::test]
    async fn ack_of_running_job_is_ignored_and_buffer_is_capped() {
        let t = Tracker::default();
        let id = Uuid::new_v4();
        t.start(id).await;
        t.ack(id).await;
        assert_eq!(t.running().await, 1);
        t.output(id, OutputStream::Stdout, vec![b'x'; JOB_OUTPUT_BUFFER + 10]).await;
        assert_eq!(t.jobs.lock().await[&id].stdout.len(), JOB_OUTPUT_BUFFER);
    }

    fn scratch() -> PathBuf {
        let d = std::env::temp_dir().join(format!("rmm-jobstore-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[tokio::test]
    async fn results_survive_a_restart_until_acked() {
        let dir = scratch();
        let id = Uuid::new_v4();
        {
            let t = Tracker::with_store(Store::new(dir.clone()));
            t.start(id).await;
            t.output(id, OutputStream::Stdout, b"hello ".to_vec()).await;
            t.output(id, OutputStream::Stdout, b"world".to_vec()).await;
            t.output(id, OutputStream::Stderr, b"careful".to_vec()).await;
            t.finish(finished(id)).await;
        }
        // "Restart": a new tracker on the same directory resends everything.
        let t = Tracker::with_store(Store::new(dir.clone()));
        assert_eq!(t.ids().await, vec![id]);
        let (tx, mut rx) = mpsc::channel(16);
        t.attach(tx).await;
        match drain(&mut rx).await.as_slice() {
            [AgentMsg::JobSync { stdout, stderr, .. }, AgentMsg::JobFinished { status: JobStatus::Succeeded, exit_code: Some(0), .. }] => {
                assert_eq!(stdout, b"hello world");
                assert_eq!(stderr, b"careful");
            }
            other => panic!("unexpected {other:?}"),
        }
        t.ack(id).await;
        assert!(!dir.join(id.to_string()).exists(), "acked results are deleted");
        assert!(Tracker::with_store(Store::new(dir.clone())).ids().await.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_job_interrupted_by_a_restart_is_reported_as_error() {
        let dir = scratch();
        let id = Uuid::new_v4();
        {
            let t = Tracker::with_store(Store::new(dir.clone()));
            t.start(id).await;
            t.output(id, OutputStream::Stdout, b"partial".to_vec()).await;
        }
        for _ in 0..2 {
            // Twice: the second load must report the same result, not a fresh one.
            let t = Tracker::with_store(Store::new(dir.clone()));
            assert_eq!(t.running().await, 0);
            let (tx, mut rx) = mpsc::channel(16);
            t.attach(tx).await;
            match drain(&mut rx).await.as_slice() {
                [AgentMsg::JobSync { stdout, stderr, .. }, AgentMsg::JobFinished { status: JobStatus::Error, exit_code: None, .. }] => {
                    assert_eq!(stdout, b"partial");
                    assert_eq!(String::from_utf8_lossy(stderr).matches("agent stopped").count(), 1, "{stderr:?}");
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn junk_in_the_store_is_ignored() {
        let dir = scratch();
        std::fs::create_dir_all(dir.join("not-a-uuid")).unwrap();
        let id = Uuid::new_v4();
        std::fs::create_dir_all(dir.join(id.to_string())).unwrap();
        std::fs::write(dir.join(id.to_string()).join("finished.json"), b"{garbage").unwrap();
        let t = Tracker::with_store(Store::new(dir.clone()));
        assert!(t.ids().await.is_empty());
        assert!(!dir.join(id.to_string()).exists(), "unreadable job directories are cleaned up");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn env_is_checked() {
        let ok = vec![("RMM_PARAM_X".to_string(), "$(touch /tmp/x)".to_string()), ("RMM_JOB_ID".into(), "1".into())];
        assert!(check_env(&ok).is_ok());
        for bad in ["PATH", "LD_PRELOAD", "RMM_", "RMM_param", "RMM_A-B", "RMM_A=B"] {
            assert!(check_env(&[(bad.to_string(), "v".to_string())]).is_err(), "{bad}");
        }
        let e = check_env(&[("RMM_PARAM_X".into(), "s".repeat(ENV_VALUE_MAX + 1))]).unwrap_err().to_string();
        assert!(!e.contains("sss"), "no value in the error");
        let many: Vec<(String, String)> = (0..4).map(|i| (format!("RMM_PARAM_{i}"), "v".repeat(ENV_VALUE_MAX))).collect();
        assert!(check_env(&many).is_err(), "the total is capped");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn parameters_arrive_as_environment_values() {
        let t = Arc::new(Tracker::default());
        let job = ScriptJob {
            job_id: Uuid::new_v4(),
            interpreter: Interpreter::Sh,
            script: "printf '%s' \"$RMM_PARAM_X\"".into(),
            args: vec![],
            timeout_secs: 10,
            env: vec![("RMM_PARAM_X".into(), "$(echo injected); \"`".into())],
        };
        t.start(job.job_id).await;
        let (status, _) = execute(&job, &t).await.unwrap();
        assert_eq!(status, JobStatus::Succeeded);
        assert_eq!(t.jobs.lock().await[&job.job_id].stdout, b"$(echo injected); \"`");
    }

    #[test]
    fn prune_caps_unacked_results() {
        let mut jobs = HashMap::new();
        for _ in 0..MAX_UNACKED + 5 {
            let id = Uuid::new_v4();
            jobs.insert(id, Tracked { finished: Some((finished(id), Instant::now())), ..Default::default() });
        }
        jobs.insert(Uuid::new_v4(), Tracked::default());
        prune(&mut jobs);
        assert_eq!(jobs.len(), MAX_UNACKED + 1, "running jobs are never pruned");
    }
}
