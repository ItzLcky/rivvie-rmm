//! One-shot script execution with streamed output.
//!
//! Jobs outlive connections. Output goes through a [`Tracker`] that keeps a copy (up to
//! [`JOB_OUTPUT_BUFFER`] per stream) and forwards it to whichever connection is current.
//! After a reconnect the agent resends each job's output and any unacknowledged result,
//! so a dropped socket or server restart no longer loses the job.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

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
}

impl Tracker {
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
        prune(&mut jobs);
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
        prune(&mut jobs);
        if jobs.contains_key(&job_id) {
            return false;
        }
        jobs.insert(job_id, Tracked::default());
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
            buf.extend_from_slice(&data[..data.len().min(room)]);
        }
        self.emit(AgentMsg::JobOutput { job_id, stream, data }).await;
        drop(jobs);
    }

    async fn finish(&self, msg: AgentMsg) {
        let AgentMsg::JobFinished { job_id, .. } = msg else { return };
        let mut jobs = self.jobs.lock().await;
        if let Some(job) = jobs.get_mut(&job_id) {
            job.finished = Some((msg.clone(), Instant::now()));
        }
        self.emit(msg).await;
        drop(jobs);
    }

    /// The server stored the result.
    pub async fn ack(&self, job_id: Uuid) {
        let mut jobs = self.jobs.lock().await;
        if jobs.get(&job_id).is_some_and(|j| j.finished.is_some()) {
            jobs.remove(&job_id);
        }
    }
}

/// Drops results nobody acknowledged: too old, or too many (oldest first).
fn prune(jobs: &mut HashMap<Uuid, Tracked>) {
    jobs.retain(|_, j| j.finished.as_ref().is_none_or(|(_, at)| at.elapsed() < KEEP_UNACKED));
    let mut done: Vec<(Instant, Uuid)> = jobs.iter().filter_map(|(id, j)| j.finished.as_ref().map(|(_, at)| (*at, *id))).collect();
    if done.len() > MAX_UNACKED {
        done.sort();
        for (_, id) in &done[..done.len() - MAX_UNACKED] {
            jobs.remove(id);
        }
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

async fn execute(job: &ScriptJob, tracker: &Arc<Tracker>) -> Result<(JobStatus, Option<i32>)> {
    let script = ScriptFile::create(job)?;
    let mut cmd = command_for(job.interpreter, &script.path)?;
    cmd.args(&job.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    // Own process group, so a timeout kills grandchildren too (they'd otherwise hold the pipes open).
    #[cfg(unix)]
    cmd.process_group(0);

    let mut child = cmd.spawn().context("spawning interpreter")?;
    let stdout = child.stdout.take().expect("piped");
    let stderr = child.stderr.take().expect("piped");
    let pump_out = tokio::spawn(pump(stdout, OutputStream::Stdout, job.job_id, tracker.clone()));
    let pump_err = tokio::spawn(pump(stderr, OutputStream::Stderr, job.job_id, tracker.clone()));

    let timeout = Duration::from_secs(job.timeout_secs.max(1) as u64);
    let result = match tokio::time::timeout(timeout, child.wait()).await {
        Ok(status) => {
            let status = status?;
            let code = status.code();
            (if status.success() { JobStatus::Succeeded } else { JobStatus::Failed }, code)
        }
        Err(_) => {
            kill_tree(&mut child).await;
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

async fn kill_tree(child: &mut tokio::process::Child) {
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        // SAFETY: plain syscall; negative pid targets the process group we created.
        unsafe {
            libc::kill(-(pid as i32), libc::SIGKILL);
        }
    }
    // TODO(windows): assign jobs to a Job Object so the whole tree dies with it.
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
