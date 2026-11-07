//! One-shot script execution with streamed output.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use rmm_proto::{AgentMsg, Interpreter, JobStatus, OutputStream, ScriptJob};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::sync::mpsc;
use tracing::{info, warn};

pub async fn run(job: ScriptJob, out: mpsc::Sender<AgentMsg>) {
    let started = Instant::now();
    let job_id = job.job_id;
    info!(%job_id, interpreter = ?job.interpreter, "running script");

    let (status, exit_code) = match execute(&job, &out).await {
        Ok(r) => r,
        Err(e) => {
            warn!(%job_id, "script failed to start: {e:#}");
            let _ = out
                .send(AgentMsg::JobOutput { job_id, stream: OutputStream::Stderr, data: format!("agent error: {e:#}\n").into_bytes() })
                .await;
            (JobStatus::Error, None)
        }
    };

    let _ = out
        .send(AgentMsg::JobFinished { job_id, status, exit_code, duration_ms: started.elapsed().as_millis() as u64 })
        .await;
}

async fn execute(job: &ScriptJob, out: &mpsc::Sender<AgentMsg>) -> Result<(JobStatus, Option<i32>)> {
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
    let pump_out = tokio::spawn(pump(stdout, OutputStream::Stdout, job.job_id, out.clone()));
    let pump_err = tokio::spawn(pump(stderr, OutputStream::Stderr, job.job_id, out.clone()));

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

async fn pump(mut r: impl AsyncRead + Unpin, stream: OutputStream, job_id: uuid::Uuid, out: mpsc::Sender<AgentMsg>) {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match r.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if out.send(AgentMsg::JobOutput { job_id, stream, data: buf[..n].to_vec() }).await.is_err() {
                    break;
                }
            }
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
        let path = std::env::temp_dir().join(format!("rmm-job-{}.{ext}", job.job_id));
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
