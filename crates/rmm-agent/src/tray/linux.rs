//! Linux: no persistent icon in v1 (a StatusNotifierItem needs a D-Bus stack). The launcher
//! opens the request form with zenity or kdialog, the tools the consent prompt already uses;
//! `--background` (the XDG autostart entry) stays connected and shows consent prompts and
//! notices with the same tools.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use rmm_proto::tray::Config;

use super::ipc::AgentToTray;
use super::{Client, Ui};

fn which(name: &str) -> Option<PathBuf> {
    ["/usr/bin", "/bin", "/usr/local/bin"].iter().map(|d| Path::new(d).join(name)).find(|p| p.exists())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tool {
    Zenity,
    Kdialog,
}

fn tool() -> Result<(Tool, PathBuf)> {
    if let Some(z) = which("zenity") {
        return Ok((Tool::Zenity, z));
    }
    if let Some(k) = which("kdialog") {
        return Ok((Tool::Kdialog, k));
    }
    bail!("install zenity or kdialog to use the help desk app, or use `rmm-agent tray --request`")
}

/// Runs a dialog; `Some(stdout)` when the user pressed OK.
fn dialog(path: &Path, args: &[String]) -> Option<String> {
    let out = Command::new(path).args(args).stdin(Stdio::null()).stderr(Stdio::null()).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim_end_matches('\n').to_string())
}

fn info(t: (Tool, &Path), title: &str, text: &str, error: bool) {
    let args: Vec<String> = match t.0 {
        Tool::Zenity => vec![if error { "--error" } else { "--info" }.into(), "--no-markup".into(), "--title".into(), title.into(), "--text".into(), text.into()],
        Tool::Kdialog => vec!["--title".into(), title.into(), if error { "--error" } else { "--msgbox" }.into(), text.into()],
    };
    let _ = dialog(t.1, &args);
}

fn title(c: Option<&Config>) -> String {
    match c.map(|c| c.product_name.trim()).filter(|p| !p.is_empty()) {
        Some(p) => format!("{p}: help"),
        None => "Help".into(),
    }
}

fn card(c: Option<&Config>) -> String {
    let Some(c) = c else { return String::new() };
    let mut text = super::contact_text(c);
    for l in c.links.iter().filter(|l| super::safe_url(&l.url)) {
        text.push_str(&format!("\n{}: {}", l.label, l.url));
    }
    text
}

/// The launcher: one request form, then exit.
pub fn gui() -> Result<()> {
    let (kind, path) = tool()?;
    let t = (kind, path.as_path());
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let config = match rt.block_on(async { Client::connect(false).await?.config().await }) {
        Ok(c) => c,
        Err(e) => {
            info(t, "Help", &format!("The support agent isn't running on this computer.\n\n{e:#}"), true);
            return Err(e);
        }
    };
    let title = title(config.as_ref());
    let card = card(config.as_ref());
    if config.as_ref().is_some_and(|c| !c.enabled || !c.request_help) {
        let text = if card.is_empty() { "Help requests are turned off for this computer.".to_string() } else { card };
        info(t, &title, &text, false);
        return Ok(());
    }
    // Before the form opens, so the form isn't in it. Wayland sessions can't be captured.
    let wayland = std::env::var_os("WAYLAND_DISPLAY").is_some() && std::env::var_os("DISPLAY").is_none();
    let shot = if wayland { None } else { crate::desktop::screenshot_jpeg().ok() };

    let intro = if card.is_empty() { "Describe the problem and we'll get back to you.".to_string() } else { format!("Describe the problem and we'll get back to you.\n\n{card}") };
    let (subject, body) = match kind {
        Tool::Zenity => {
            let sep = "\u{1e}";
            let args: Vec<String> = [
                "--forms", "--title", &title, "--text", &intro, "--separator", sep, "--add-entry", "Subject", "--add-multiline-entry", "Description",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect();
            let Some(out) = dialog(&path, &args) else { return Ok(()) };
            let (s, b) = out.split_once(sep).unwrap_or((&out, ""));
            (s.to_string(), b.to_string())
        }
        Tool::Kdialog => {
            let Some(s) = dialog(&path, &["--title".into(), title.clone(), "--inputbox".into(), format!("{intro}\n\nSubject:")]) else { return Ok(()) };
            let Some(b) = dialog(&path, &["--title".into(), title.clone(), "--textinputbox".into(), "Description:".into()]) else { return Ok(()) };
            (s, b)
        }
    };
    if subject.trim().is_empty() {
        info(t, &title, "Give the request a subject.", true);
        return Ok(());
    }
    let mut screenshot = vec![];
    if let Some(shot) = shot {
        let default_yes = config.as_ref().is_none_or(|c| c.screenshot_default);
        let q = "Attach a picture of your screen to the request?";
        let yes = match kind {
            Tool::Zenity => {
                let mut args = vec!["--question".to_string(), "--title".into(), title.clone(), "--text".into(), q.into()];
                if !default_yes {
                    args.push("--default-cancel".into());
                }
                dialog(&path, &args).is_some()
            }
            Tool::Kdialog => dialog(&path, &["--title".into(), title.clone(), "--yesno".into(), q.into()]).is_some(),
        };
        if yes {
            screenshot = shot;
        }
    }
    let reply = rt.block_on(async { Client::connect(false).await?.request(&subject, &body, screenshot).await });
    match reply {
        Ok(AgentToTray::HelpResult { error: Some(e), .. }) => info(t, &title, &e, true),
        Ok(AgentToTray::HelpResult { ticket_number: Some(n), .. }) => info(t, &title, &format!("Thanks. Your request is ticket #{n}."), false),
        Ok(AgentToTray::HelpResult { .. }) => {
            info(t, &title, "This computer can't reach the help desk right now. Your request is saved and will be sent as soon as it can.", false)
        }
        Ok(_) => {}
        Err(e) => info(t, &title, &format!("The request couldn't be sent: {e:#}"), true),
    }
    Ok(())
}

struct Dialogs {
    kind: Tool,
    path: PathBuf,
}

impl Ui for Dialogs {
    fn config(&self, _c: Option<Config>) {}

    fn consent(&self, title: &str, text: &str, timeout_secs: u32) -> bool {
        let secs = timeout_secs.max(5);
        let mut cmd = Command::new(&self.path);
        match self.kind {
            Tool::Zenity => {
                cmd.args(["--question", "--no-markup", "--title", title, "--text", text, "--ok-label=Allow", "--cancel-label=Deny"]).arg(format!("--timeout={secs}"));
            }
            Tool::Kdialog => {
                cmd.args(["--title", title, "--yes-label", "Allow", "--no-label", "Deny", "--yesno", text]);
            }
        }
        let Ok(mut child) = cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn() else { return false };
        let deadline = Instant::now() + Duration::from_secs(u64::from(secs) + 2);
        loop {
            match child.try_wait() {
                Ok(Some(st)) => return st.code() == Some(0),
                Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(200)),
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return false;
                }
            }
        }
    }

    fn notice(&self, text: &str, _active: bool) {
        let mut cmd = match which("notify-send") {
            Some(n) => {
                let mut c = Command::new(n);
                c.arg(text);
                c
            }
            None if self.kind == Tool::Zenity => {
                let mut c = Command::new(&self.path);
                c.args(["--notification", "--text", text]);
                c
            }
            None => {
                let mut c = Command::new(&self.path);
                c.args(["--passivepopup", text, "10"]);
                c
            }
        };
        let _ = cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn();
    }
}

/// `--background`: stays connected for prompts and notices.
pub fn background() -> Result<()> {
    let (kind, path) = tool()?;
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    rt.block_on(super::run_link(Arc::new(Dialogs { kind, path })));
    Ok(())
}
