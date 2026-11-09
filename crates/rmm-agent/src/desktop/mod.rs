//! Remote desktop.
//!
//! The agent never touches the screen itself. For each session it starts a helper process
//! (`rmm-agent desktop-helper`, hidden) *inside the user's graphical session*: on Windows a
//! SYSTEM process placed in the active console session, so it can follow the desktop to the
//! sign-in screen and UAC prompts; on Linux a process running as the owner of the X display.
//! The helper captures, encodes and injects input; the agent relays between it and the
//! server. A crash or leak in capture code therefore can't take the agent down, and the
//! frame buffers go away with the session.
//!
//! Agent and helper talk over the helper's stdin/stdout: length-prefixed (u32 LE)
//! MessagePack messages, [`ToHelper`] one way and [`FromHelper`] the other. Closing stdin
//! stops the helper.

mod encode;
mod fake;
mod keymap;
mod session;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod x11;
#[cfg(windows)]
mod win;

use std::io::{Read, Write};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use rmm_proto::desktop::{FRAME_WINDOW, Frame, InputEvent, Monitor, Settings};
use serde::{Deserialize, Serialize};

pub use session::DesktopSession;

/// Shortest gap between captures while the screen is changing (20 fps).
const BUSY_INTERVAL: Duration = Duration::from_millis(50);
/// And while it isn't.
const IDLE_INTERVAL: Duration = Duration::from_millis(120);
/// How often the helper looks for added or removed monitors.
const MONITOR_POLL: Duration = Duration::from_secs(2);
const MAX_MESSAGE: usize = 64 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub(crate) enum ToHelper {
    Settings { settings: Settings },
    Input { events: Vec<InputEvent> },
    Ack { seq: u32 },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub(crate) enum FromHelper {
    Info { monitors: Vec<Monitor>, monitor: u32 },
    Frame { frame: Frame },
    /// Fatal: the helper exits after sending this.
    Error { message: String },
}

pub(crate) fn write_msg<T: Serialize>(w: &mut impl Write, msg: &T) -> Result<()> {
    let buf = rmm_proto::encode(msg)?;
    w.write_all(&(buf.len() as u32).to_le_bytes())?;
    w.write_all(&buf)?;
    w.flush()?;
    Ok(())
}

/// `None` at a clean end of stream.
pub(crate) fn read_msg<T: for<'a> Deserialize<'a>>(r: &mut impl Read) -> Result<Option<T>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_MESSAGE {
        bail!("message of {len} bytes");
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(Some(rmm_proto::decode(&buf)?))
}

/// What the helper captures from and injects into.
pub(crate) trait Screen {
    fn monitors(&mut self) -> Result<Vec<Monitor>>;
    /// The monitor's pixels as packed 32-bit BGRX rows (`width * 4` bytes each) into `buf`.
    fn capture(&mut self, m: &Monitor, buf: &mut Vec<u8>) -> Result<()>;
    /// Pointer position on the virtual desktop.
    fn cursor(&mut self) -> Option<(i32, i32)>;
    /// Coordinates in `ev` are relative to `m`.
    fn input(&mut self, m: &Monitor, ev: &InputEvent) -> Result<()>;
}

fn open_screen() -> Result<Box<dyn Screen>> {
    if let Some(path) = std::env::var_os("RMM_DESKTOP_FAKE") {
        return Ok(Box::new(fake::FakeScreen::new(path.into())));
    }
    #[cfg(target_os = "linux")]
    return Ok(Box::new(x11::X11Screen::connect()?));
    #[cfg(windows)]
    return Ok(Box::new(win::GdiScreen::new()?));
    #[allow(unreachable_code)]
    {
        bail!("remote desktop isn't supported on this platform yet")
    }
}

/// `rmm-agent desktop-helper`: runs until stdin closes. Logs go to stderr, which the agent
/// forwards to its own log; stdout carries [`FromHelper`] messages only.
pub fn helper_main() -> Result<()> {
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::with_capacity(256 * 1024, stdout.lock());
    let result = serve(&mut out);
    if let Err(e) = &result {
        let _ = write_msg(&mut out, &FromHelper::Error { message: format!("{e:#}") });
    }
    result
}

fn serve(out: &mut impl Write) -> Result<()> {
    let (tx, rx) = mpsc::channel::<ToHelper>();
    std::thread::Builder::new().name("desktop-stdin".into()).spawn(move || {
        let mut stdin = std::io::stdin().lock();
        while let Ok(Some(msg)) = read_msg::<ToHelper>(&mut stdin) {
            if tx.send(msg).is_err() {
                break;
            }
        }
    })?;

    let mut screen = open_screen()?;
    let mut monitors = screen.monitors().context("listing monitors")?;
    if monitors.is_empty() {
        bail!("no monitors found");
    }
    let mut monitors_checked = Instant::now();

    // Nothing is captured until the agent sends the settings.
    let mut settings = match rx.recv() {
        Ok(ToHelper::Settings { settings }) => settings,
        _ => return Ok(()),
    };
    let mut current = pick(&monitors, settings.monitor);
    let (q, scale) = settings.quality.params();
    let mut encoder = encode::Encoder::new(q, scale);
    write_msg(out, &FromHelper::Info { monitors: monitors.clone(), monitor: current as u32 })?;

    let mut next_seq: u32 = 1;
    let mut acked: u32 = 0;
    let mut last_capture = Instant::now() - BUSY_INTERVAL;
    let mut last_change = Instant::now();
    let mut last_cursor = None;
    let mut buf = Vec::new();

    loop {
        // Input and acks first, then capture when the window and the frame rate allow.
        let interval = if last_change.elapsed() > Duration::from_secs(1) { IDLE_INTERVAL } else { BUSY_INTERVAL };
        let in_flight = next_seq - 1 - acked;
        let wait = if in_flight >= FRAME_WINDOW { Duration::from_millis(200) } else { interval.saturating_sub(last_capture.elapsed()) };
        let first = match rx.recv_timeout(wait) {
            Ok(m) => Some(m),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => return Ok(()),
        };
        for msg in first.into_iter().chain(rx.try_iter()) {
            match msg {
                ToHelper::Ack { seq } => {
                    if seq < next_seq {
                        acked = acked.max(seq);
                    }
                }
                ToHelper::Input { events } => {
                    let m = &monitors[current];
                    for ev in &events {
                        if let Err(e) = screen.input(m, ev) {
                            tracing::debug!("input: {e:#}");
                        }
                    }
                    last_change = Instant::now();
                }
                ToHelper::Settings { settings: s } => {
                    settings = s;
                    current = pick(&monitors, settings.monitor);
                    let (q, scale) = settings.quality.params();
                    encoder = encode::Encoder::new(q, scale);
                    write_msg(out, &FromHelper::Info { monitors: monitors.clone(), monitor: current as u32 })?;
                }
            }
        }

        if monitors_checked.elapsed() >= MONITOR_POLL {
            monitors_checked = Instant::now();
            if let Ok(now) = screen.monitors()
                && !now.is_empty()
                && now != monitors
            {
                monitors = now;
                current = pick(&monitors, settings.monitor);
                encoder.reset();
                write_msg(out, &FromHelper::Info { monitors: monitors.clone(), monitor: current as u32 })?;
            }
        }

        if next_seq - 1 - acked >= FRAME_WINDOW || last_capture.elapsed() < interval {
            continue;
        }
        last_capture = Instant::now();
        let m = &monitors[current];
        screen.capture(m, &mut buf).with_context(|| format!("capturing {}", m.name))?;
        let img = encode::Image { data: &buf, width: m.width as usize, height: m.height as usize };
        let rects = encoder.encode(&img);
        let cursor = screen.cursor().map(|(x, y)| (x - m.x, y - m.y));
        if rects.is_empty() && cursor == last_cursor {
            continue;
        }
        if !rects.is_empty() {
            last_change = Instant::now();
        }
        last_cursor = cursor;
        let (width, height) = encoder.output_size(img.width, img.height);
        let frame = Frame {
            seq: next_seq,
            screen_width: m.width,
            screen_height: m.height,
            width: width as u32,
            height: height as u32,
            rects,
            cursor,
        };
        write_msg(out, &FromHelper::Frame { frame })?;
        next_seq += 1;
    }
}

/// The requested monitor, else the primary, else the first.
fn pick(monitors: &[Monitor], wanted: u32) -> usize {
    let wanted = wanted as usize;
    if wanted < monitors.len() {
        return wanted;
    }
    monitors.iter().position(|m| m.primary).unwrap_or(0)
}

/// Clamps monitor-relative coordinates onto the monitor and makes them absolute.
pub(crate) fn absolute(m: &Monitor, x: i32, y: i32) -> (i32, i32) {
    (m.x + x.clamp(0, m.width as i32 - 1), m.y + y.clamp(0, m.height as i32 - 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_roundtrip_and_eof() {
        let mut buf = Vec::new();
        write_msg(&mut buf, &ToHelper::Ack { seq: 9 }).unwrap();
        let mut r = &buf[..];
        assert!(matches!(read_msg::<ToHelper>(&mut r).unwrap(), Some(ToHelper::Ack { seq: 9 })));
        assert!(read_msg::<ToHelper>(&mut r).unwrap().is_none());
    }

    #[test]
    fn monitor_choice_and_clamping() {
        let m = |primary| Monitor { name: "m".into(), x: 100, y: -50, width: 800, height: 600, primary };
        assert_eq!(pick(&[m(false), m(true)], 7), 1);
        assert_eq!(pick(&[m(false), m(true)], 0), 0);
        assert_eq!(absolute(&m(true), -5, 9999), (100, 549));
    }
}
