//! Finding the graphical session on Linux and starting the helper in it.
//!
//! The agent runs as root under systemd, with no display of its own. The X server it should
//! show is found from the environment of the processes already running in it (every
//! session's processes carry `DISPLAY` and usually `XAUTHORITY`). The helper then runs as
//! that display's user, so it only gets what that user's own X clients get.

use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use rmm_proto::desktop::Consent;

use super::session::{Helper, helper_command, spawn_command};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Display {
    pub display: String,
    pub xauthority: Option<PathBuf>,
    pub uid: u32,
    pub gid: u32,
    pub home: Option<PathBuf>,
}

/// One process's view of its session.
#[derive(Debug, Default, Clone)]
struct ProcEnv {
    uid: u32,
    gid: u32,
    display: Option<String>,
    xauthority: Option<String>,
    wayland: bool,
    home: Option<String>,
}

impl Display {
    pub fn find() -> Result<Display> {
        let me = std::process::id();
        let mut envs = Vec::new();
        for entry in std::fs::read_dir("/proc")?.flatten() {
            let Some(pid) = entry.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
            if pid == me {
                continue;
            }
            let Ok(meta) = entry.metadata() else { continue };
            let Ok(raw) = std::fs::read(entry.path().join("environ")) else { continue };
            envs.push(parse_environ(&raw, meta.uid(), meta.gid()));
        }
        choose(&envs)
    }

    pub fn spawn(&self, exe: &Path) -> Result<Helper> {
        let mut cmd = helper_command(exe);
        self.prepare(&mut cmd)?;
        spawn_command(cmd)
    }

    /// Runs `cmd` in this session, as its user.
    fn prepare(&self, cmd: &mut Command) -> Result<()> {
        cmd.env_clear().env("DISPLAY", &self.display).env("PATH", "/usr/local/bin:/usr/bin:/bin").env("LANG", "C.UTF-8");
        if let Some(x) = &self.xauthority {
            cmd.env("XAUTHORITY", x);
        }
        if let Some(h) = &self.home {
            cmd.env("HOME", h).current_dir(h);
        } else {
            cmd.current_dir("/");
        }
        if let Ok(rust_log) = std::env::var("RUST_LOG") {
            cmd.env("RUST_LOG", rust_log);
        }
        // SAFETY: getuid has no preconditions.
        let me = unsafe { libc::getuid() };
        if self.uid != me {
            if me != 0 {
                bail!("the display belongs to uid {} and the agent isn't running as root", self.uid);
            }
            // std drops supplementary groups when switching uid as root.
            cmd.uid(self.uid).gid(self.gid);
        }
        Ok(())
    }

    /// Shows an Allow/Deny dialog on the display with whichever tool is installed. `None`
    /// when nobody is signed in to ask.
    pub fn ask(&self, c: &Consent) -> Result<Option<bool>> {
        // A display manager's greeter (a system account) means nobody is signed in.
        if self.uid < 1000 {
            return Ok(None);
        }
        let host = crate::collect::system_info().hostname;
        let (title, text) = super::session::consent_text(c, &host);
        let secs = c.timeout_secs.max(5);
        let (mut cmd, allowed): (Command, fn(i32) -> bool) = if let Some(z) = which("zenity") {
            let mut cmd = Command::new(z);
            cmd.args(["--question", "--title", &title, "--text", &text, "--ok-label=Allow", "--cancel-label=Deny"])
                .arg(format!("--timeout={secs}"));
            (cmd, |code| code == 0)
        } else if let Some(k) = which("kdialog") {
            let mut cmd = Command::new(k);
            cmd.args(["--title", &title, "--yes-label", "Allow", "--no-label", "Deny", "--yesno", &text]);
            (cmd, |code| code == 0)
        } else if let Some(x) = which("xmessage") {
            // Exit status 2 is Allow; a timeout exits 0, so it counts as Deny.
            let mut cmd = Command::new(x);
            cmd.args(["-center", "-buttons", "Deny:1,Allow:2", "-timeout"]).arg(secs.to_string()).arg(format!("{title}\n\n{text}"));
            (cmd, |code| code == 2)
        } else {
            bail!("can't ask for consent: install zenity, kdialog or xmessage on this machine, or turn off the consent prompt for this client");
        };
        self.prepare(&mut cmd)?;
        let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn()?;
        let deadline = Instant::now() + Duration::from_secs(u64::from(secs) + 5);
        loop {
            if let Some(st) = child.try_wait()? {
                return Ok(Some(st.code().is_some_and(allowed)));
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Ok(Some(false));
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

fn which(name: &str) -> Option<PathBuf> {
    ["/usr/bin", "/bin", "/usr/local/bin"].iter().map(|d| Path::new(d).join(name)).find(|p| p.exists())
}

fn parse_environ(raw: &[u8], uid: u32, gid: u32) -> ProcEnv {
    let mut env = ProcEnv { uid, gid, ..Default::default() };
    for kv in raw.split(|b| *b == 0) {
        let Ok(kv) = std::str::from_utf8(kv) else { continue };
        let Some((k, v)) = kv.split_once('=') else { continue };
        match k {
            "DISPLAY" if !v.is_empty() => env.display = Some(v.to_string()),
            "XAUTHORITY" if !v.is_empty() => env.xauthority = Some(v.to_string()),
            "WAYLAND_DISPLAY" if !v.is_empty() => env.wayland = true,
            "XDG_SESSION_TYPE" if v == "wayland" => env.wayland = true,
            "HOME" => env.home = Some(v.to_string()),
            _ => {}
        }
    }
    env
}

/// Picks the session to show: a signed-in user's X session over a display manager's
/// greeter, over root. Wayland sessions are refused with an explanation: capturing them
/// needs the compositor's cooperation (a screencast portal or PipeWire), which isn't built yet.
fn choose(envs: &[ProcEnv]) -> Result<Display> {
    let rank = |e: &ProcEnv| match e.uid {
        0 => 0,
        1..=999 => 1,
        _ => 2,
    };
    // Per (display, uid), whether any of its processes said Wayland, and the best details.
    let mut sessions: HashMap<(String, u32), (ProcEnv, bool)> = HashMap::new();
    let mut wayland_only = false;
    for e in envs {
        // Remote displays (`localhost:10` from ssh -X) aren't this machine's screen.
        let Some(d) = e.display.as_ref().filter(|d| d.starts_with(':') || d.starts_with("unix:")) else {
            wayland_only |= e.wayland;
            continue;
        };
        let entry = sessions.entry((d.clone(), e.uid)).or_insert_with(|| (e.clone(), false));
        entry.1 |= e.wayland;
        if entry.0.xauthority.is_none() && e.xauthority.is_some() {
            entry.0.xauthority.clone_from(&e.xauthority);
        }
    }
    let x11: Vec<&ProcEnv> = sessions.values().filter(|(_, w)| !w).map(|(e, _)| e).collect();
    let Some(best) = x11.iter().max_by_key(|e| (rank(e), e.xauthority.is_some(), std::cmp::Reverse(e.display.clone()))) else {
        if wayland_only || !sessions.is_empty() {
            bail!("this machine is running a Wayland session; remote desktop supports X11 sessions only for now (choose an \"Xorg\" session at the sign-in screen)");
        }
        bail!("nobody is using a graphical desktop on this machine (no X display found)");
    };
    let home = best.home.clone().map(PathBuf::from);
    let xauthority = best
        .xauthority
        .clone()
        .map(PathBuf::from)
        .or_else(|| home.as_ref().map(|h| h.join(".Xauthority")).filter(|p| p.exists()));
    Ok(Display { display: best.display.clone().unwrap_or_default(), xauthority, uid: best.uid, gid: best.gid, home })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(uid: u32, s: &str) -> ProcEnv {
        parse_environ(s.replace(' ', "\0").as_bytes(), uid, uid)
    }

    #[test]
    fn prefers_signed_in_user_over_greeter() {
        let envs = [
            env(0, "PATH=/bin"),
            env(120, "DISPLAY=:0 XAUTHORITY=/run/lightdm/lightdm/xauthority HOME=/var/lib/lightdm"),
            env(1000, "DISPLAY=:1 HOME=/home/ann"),
            env(1000, "DISPLAY=:1 XAUTHORITY=/home/ann/.Xauthority HOME=/home/ann"),
            env(1001, "DISPLAY=localhost:10 HOME=/home/bob"),
        ];
        let d = choose(&envs).unwrap();
        assert_eq!((d.display.as_str(), d.uid), (":1", 1000));
        assert_eq!(d.xauthority.as_deref(), Some(Path::new("/home/ann/.Xauthority")));
        // Only the greeter: that's what gets shown (the sign-in screen).
        assert_eq!(choose(&envs[..2]).unwrap().uid, 120);
    }

    #[test]
    fn wayland_and_nothing_are_explained() {
        let e = choose(&[env(1000, "WAYLAND_DISPLAY=wayland-0 XDG_SESSION_TYPE=wayland")]).unwrap_err().to_string();
        assert!(e.contains("Wayland"), "{e}");
        // XWayland: DISPLAY is set, but the session is Wayland.
        let e = choose(&[env(1000, "DISPLAY=:0 XDG_SESSION_TYPE=wayland")]).unwrap_err().to_string();
        assert!(e.contains("Wayland"), "{e}");
        let e = choose(&[env(0, "PATH=/bin")]).unwrap_err().to_string();
        assert!(e.contains("no X display"), "{e}");
    }
}
