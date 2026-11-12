//! Running package manager commands: timeouts, captured output, and a shared log.

use std::io::{BufRead, BufReader, Read};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use rmm_proto::patch::OUTPUT_MAX;

/// Everything the package manager printed during one operation, for the run's log.
#[derive(Default)]
pub struct Log(Mutex<String>);

impl Log {
    pub fn push(&self, s: &str) {
        let mut l = self.0.lock().unwrap_or_else(|e| e.into_inner());
        // Keep the head and the tail; the tail is where failures are.
        if l.len() > OUTPUT_MAX * 2 {
            let keep = rmm_proto::patch::tail(&l, OUTPUT_MAX).to_string();
            *l = format!("[... earlier output trimmed ...]\n{keep}");
        }
        l.push_str(s);
    }

    pub fn text(&self) -> String {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

pub struct Output {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }

    /// The last lines of stderr (else stdout), for an error message.
    pub fn reason(&self) -> String {
        let s = if self.stderr.trim().is_empty() { &self.stdout } else { &self.stderr };
        let lines: Vec<&str> = s.lines().filter(|l| !l.trim().is_empty()).collect();
        lines[lines.len().saturating_sub(5)..].join("\n")
    }
}

#[derive(Clone, Copy)]
pub struct Opts<'a> {
    pub timeout: Duration,
    pub env: &'a [(&'a str, &'a str)],
    /// Write the command and its output to the log.
    pub log: bool,
    /// Keep it running if the agent stops (an install mustn't die halfway through because
    /// the agent restarted). On Linux under systemd it runs in its own transient scope, out
    /// of the agent service's cgroup, and writes to files instead of pipes.
    pub detach: bool,
}

impl Default for Opts<'_> {
    fn default() -> Self {
        Opts { timeout: Duration::from_secs(600), env: &[], log: true, detach: false }
    }
}

/// `systemd-run`, when commands can be moved into their own scope: systemd is running and
/// we're root.
fn scope_runner() -> Option<&'static str> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: plain syscall.
        let root = unsafe { libc::geteuid() } == 0;
        if root && std::path::Path::new("/run/systemd/system").is_dir() && which("systemd-run") {
            return Some("systemd-run");
        }
    }
    None
}

/// Reads a file another process is still writing: at the end it waits for more until
/// `done` is set, then returns what's left.
struct Tail {
    file: std::fs::File,
    done: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Read for Tail {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            // Checked before reading, so the last read after `done` sees everything written.
            let done = self.done.load(std::sync::atomic::Ordering::Acquire);
            let n = self.file.read(buf)?;
            if n > 0 || done {
                return Ok(n);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// Runs `program args`, killing it after `opts.timeout`. Calls `on_line` with each stdout
/// line as it arrives. A non-zero exit is not an error here; callers decide.
pub fn run(log: &Log, program: &str, args: &[&str], opts: Opts, on_line: &mut dyn FnMut(&str)) -> Result<Output> {
    let scope = if opts.detach { scope_runner() } else { None };
    // Output files for a detached command: pipes would break (and SIGPIPE it) when the agent
    // goes away. Removed when this returns; a command that outlives the agent keeps writing
    // to the unlinked files, which is harmless.
    let files = opts.detach.then(|| {
        let base = std::env::temp_dir().join(format!("rmm-patch-{}", uuid::Uuid::new_v4().simple()));
        (base.with_extension("out"), base.with_extension("err"))
    });
    struct Cleanup(Option<(std::path::PathBuf, std::path::PathBuf)>);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            if let Some((o, e)) = &self.0 {
                let _ = std::fs::remove_file(o);
                let _ = std::fs::remove_file(e);
            }
        }
    }
    let _cleanup = Cleanup(files.clone());
    let mut cmd = match scope {
        Some(runner) => {
            let mut c = Command::new(runner);
            let unit = format!("rmm-patch-{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
            c.args(["--scope", "--quiet", "--collect", "--unit", &unit, "--description", "RMM agent: installing updates", "--"]);
            c.arg(program);
            c
        }
        None => Command::new(program),
    };
    cmd.args(args).stdin(Stdio::null());
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let tails = match &files {
        Some((out, err)) => {
            let (wo, we) = (std::fs::File::create(out)?, std::fs::File::create(err)?);
            cmd.stdout(wo).stderr(we);
            Some((Tail { file: std::fs::File::open(out)?, done: done.clone() }, Tail { file: std::fs::File::open(err)?, done: done.clone() }))
        }
        None => {
            cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
            None
        }
    };
    // Untranslated output: the parsers expect English.
    cmd.env("LC_ALL", "C").env("LANG", "C");
    for (k, v) in opts.env {
        cmd.env(k, v);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    if opts.log {
        log.push(&format!("$ {program} {}\n", args.join(" ")));
    }
    let mut child = cmd.spawn().with_context(|| format!("starting {program}"))?;
    let (stdout, mut stderr): (Box<dyn Read + Send>, Box<dyn Read + Send>) = match tails {
        Some((o, e)) => (Box::new(o), Box::new(e)),
        None => (Box::new(child.stdout.take().expect("piped")), Box::new(child.stderr.take().expect("piped"))),
    };

    let (line_tx, line_rx) = std::sync::mpsc::channel::<String>();
    let out_thread = std::thread::spawn(move || {
        let mut r = BufReader::new(stdout);
        let mut buf = Vec::new();
        loop {
            buf.clear();
            match r.read_until(b'\n', &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if line_tx.send(String::from_utf8_lossy(&buf).into_owned()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    let err_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr.read_to_end(&mut buf);
        String::from_utf8_lossy(&buf).into_owned()
    });

    let deadline = Instant::now() + opts.timeout;
    let mut stdout_text = String::new();
    let mut timed_out = false;
    let status = loop {
        while let Ok(line) = line_rx.try_recv() {
            consume(&line, &mut stdout_text, log, opts.log, on_line);
        }
        if let Some(s) = child.try_wait()? {
            break Some(s);
        }
        if Instant::now() >= deadline {
            timed_out = true;
            kill(&mut child);
            break child.wait().ok();
        }
        // Blocks until output or the poll interval, so lines arrive promptly.
        if let Ok(line) = line_rx.recv_timeout(Duration::from_millis(200)) {
            consume(&line, &mut stdout_text, log, opts.log, on_line);
        }
    };
    done.store(true, std::sync::atomic::Ordering::Release);
    // A grandchild that kept the pipes open mustn't hang us: wait briefly for the readers.
    let reader_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match line_rx.recv_timeout(Duration::from_millis(50)) {
            Ok(line) => consume(&line, &mut stdout_text, log, opts.log, on_line),
            Err(_) if (out_thread.is_finished() && err_thread.is_finished()) || Instant::now() >= reader_deadline => break,
            Err(_) => {}
        }
    }
    while let Ok(line) = line_rx.try_recv() {
        consume(&line, &mut stdout_text, log, opts.log, on_line);
    }
    let stderr_text = if err_thread.is_finished() { err_thread.join().unwrap_or_default() } else { String::new() };
    if opts.log && !stderr_text.is_empty() {
        log.push(&stderr_text);
        if !stderr_text.ends_with('\n') {
            log.push("\n");
        }
    }
    if timed_out {
        bail!("{program} didn't finish within {} minutes and was stopped", opts.timeout.as_secs() / 60);
    }
    let code = status.and_then(|s| s.code());
    if opts.log {
        log.push(&format!("[exit {}]\n", code.map_or("signal".to_string(), |c| c.to_string())));
    }
    Ok(Output { code, stdout: stdout_text, stderr: stderr_text })
}

fn consume(line: &str, all: &mut String, log: &Log, to_log: bool, on_line: &mut dyn FnMut(&str)) {
    if all.len() < 16 * 1024 * 1024 {
        all.push_str(line);
    }
    if to_log {
        log.push(line);
    }
    on_line(line.trim_end());
}

fn kill(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        // SAFETY: plain syscall on the process group created for the child.
        unsafe {
            libc::kill(-(child.id() as i32), libc::SIGKILL);
        }
    }
    let _ = child.kill();
}

/// Shorthand: run and capture, logging.
pub fn output(log: &Log, program: &str, args: &[&str], opts: Opts) -> Result<Output> {
    run(log, program, args, opts, &mut |_| {})
}

/// Whether `program` is on PATH.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn which(program: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else { return false };
    std::env::split_paths(&path).any(|d| {
        let p = d.join(program);
        p.is_file() || (cfg!(windows) && p.with_extension("exe").is_file())
    })
}

/// Schedules a reboot about a minute out, so the result has time to leave and signed-in
/// users get a warning.
pub fn reboot() -> Result<()> {
    let log = Log::default();
    let msg = "Restarting to finish installing updates (RMM)";
    let out = if cfg!(windows) {
        output(&log, "shutdown.exe", &["/r", "/t", "60", "/c", msg, "/d", "p:2:17"], Opts::default())?
    } else {
        output(&log, "shutdown", &["-r", "+1", msg], Opts::default())?
    };
    if !out.success() {
        bail!("shutdown failed: {}", out.reason());
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn captures_lines_and_exit_code() {
        let log = Log::default();
        let mut lines = vec![];
        let out = run(&log, "sh", &["-c", "echo one; echo two; echo oops >&2; exit 3"], Opts::default(), &mut |l| lines.push(l.to_string()))
            .unwrap();
        assert_eq!(lines, ["one", "two"]);
        assert_eq!(out.code, Some(3));
        assert_eq!(out.reason(), "oops");
        let text = log.text();
        assert!(text.starts_with("$ sh -c") && text.contains("oops") && text.contains("[exit 3]"), "{text}");
    }

    #[test]
    fn detached_output_comes_through_files() {
        // Without root/systemd this runs normally; either way the output must arrive.
        let log = Log::default();
        let mut lines = vec![];
        let opts = Opts { detach: true, ..Default::default() };
        let out = run(&log, "sh", &["-c", "echo one; sleep 0.3; echo two; echo bad >&2; exit 2"], opts, &mut |l| lines.push(l.to_string())).unwrap();
        assert_eq!(lines, ["one", "two"]);
        assert_eq!(out.code, Some(2));
        assert_eq!(out.reason(), "bad");
    }

    #[test]
    fn times_out() {
        let log = Log::default();
        let opts = Opts { timeout: Duration::from_millis(300), ..Default::default() };
        let started = Instant::now();
        let err = output(&log, "sh", &["-c", "sleep 30"], opts).err().unwrap();
        assert!(err.to_string().contains("didn't finish"));
        assert!(started.elapsed() < Duration::from_secs(10));
    }
}
