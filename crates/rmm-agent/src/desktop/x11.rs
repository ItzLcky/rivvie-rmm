//! X11 capture (MIT-SHM, falling back to plain GetImage) and input (XTEST).

use anyhow::{Context, Result, bail};
use rmm_proto::desktop::{Button, InputEvent, Monitor};
use x11rb::connection::{Connection, RequestConnection};
use x11rb::protocol::randr::ConnectionExt as _;
use x11rb::protocol::shm::ConnectionExt as _;
use x11rb::protocol::xproto::{
    BUTTON_PRESS_EVENT, BUTTON_RELEASE_EVENT, ConnectionExt as _, ImageFormat, ImageOrder, KEY_PRESS_EVENT, KEY_RELEASE_EVENT,
    MOTION_NOTIFY_EVENT, Window,
};
use x11rb::protocol::xtest::ConnectionExt as _;
use x11rb::rust_connection::RustConnection;

use super::keymap;

/// evdev + 8, the X keycodes of the modifiers used for Ctrl+Alt+Del and shifted characters.
const KC_SHIFT: u8 = 50;
const KC_CTRL: u8 = 37;
const KC_ALT: u8 = 64;
const KC_DELETE: u8 = 119;

pub struct X11Screen {
    conn: RustConnection,
    root: Window,
    width: u16,
    height: u16,
    shm: Option<Shm>,
    shm_available: bool,
    xtest: bool,
    min_keycode: u8,
    max_keycode: u8,
}

/// A SysV shared memory segment the X server writes captures into.
struct Shm {
    seg: u32,
    addr: *mut u8,
    size: usize,
}

impl X11Screen {
    pub fn connect() -> Result<Self> {
        let display = std::env::var("DISPLAY").unwrap_or_default();
        let (conn, screen) = x11rb::connect(None).with_context(|| format!("connecting to X display {display:?}"))?;
        let setup = conn.setup();
        let s = &setup.roots[screen];
        let bpp = setup.pixmap_formats.iter().find(|f| f.depth == s.root_depth).map(|f| f.bits_per_pixel);
        if setup.image_byte_order != ImageOrder::LSB_FIRST || !(s.root_depth == 24 || s.root_depth == 32) || bpp != Some(32) {
            bail!("unsupported X pixel format (depth {}, {:?} bpp); only 24/32-bit little-endian displays are supported", s.root_depth, bpp);
        }
        let (root, width, height) = (s.root, s.width_in_pixels, s.height_in_pixels);
        let (min_keycode, max_keycode) = (setup.min_keycode, setup.max_keycode);
        let shm_available = conn.extension_information(x11rb::protocol::shm::X11_EXTENSION_NAME)?.is_some();
        let xtest = conn.extension_information(x11rb::protocol::xtest::X11_EXTENSION_NAME)?.is_some();
        if !xtest {
            tracing::warn!("the X server has no XTEST extension: view only");
        }
        Ok(X11Screen { conn, root, width, height, shm: None, shm_available, xtest, min_keycode, max_keycode })
    }

    fn shm_for(&mut self, size: usize) -> Option<&Shm> {
        if self.shm.as_ref().is_some_and(|s| s.size >= size) {
            return self.shm.as_ref();
        }
        if let Some(old) = self.shm.take() {
            self.free_shm(old);
        }
        if !self.shm_available {
            return None;
        }
        match self.new_shm(size) {
            Ok(s) => self.shm = Some(s),
            Err(e) => {
                tracing::info!("MIT-SHM unavailable ({e:#}); using GetImage");
                self.shm_available = false;
            }
        }
        self.shm.as_ref()
    }

    fn new_shm(&self, size: usize) -> Result<Shm> {
        // SAFETY: plain SysV calls; the segment is detached and removed in `free_shm`/on error.
        unsafe {
            let id = libc::shmget(libc::IPC_PRIVATE, size, libc::IPC_CREAT | 0o600);
            if id < 0 {
                bail!("shmget: {}", std::io::Error::last_os_error());
            }
            let addr = libc::shmat(id, std::ptr::null(), 0);
            if addr as isize == -1 {
                libc::shmctl(id, libc::IPC_RMID, std::ptr::null_mut());
                bail!("shmat: {}", std::io::Error::last_os_error());
            }
            let seg = self.conn.generate_id()?;
            let attached = self.conn.shm_attach(seg, id as u32, false).map_err(anyhow::Error::from).and_then(|c| Ok(c.check()?));
            // Removed now; it lives until both sides detach.
            libc::shmctl(id, libc::IPC_RMID, std::ptr::null_mut());
            if let Err(e) = attached {
                libc::shmdt(addr);
                return Err(e);
            }
            Ok(Shm { seg, addr: addr.cast(), size })
        }
    }

    fn free_shm(&self, s: Shm) {
        let _ = self.conn.shm_detach(s.seg);
        let _ = self.conn.flush();
        // SAFETY: `addr` came from shmat and isn't used after this.
        unsafe {
            libc::shmdt(s.addr.cast());
        }
    }

    fn fake(&self, kind: u8, detail: u8, x: i32, y: i32) -> Result<()> {
        if !self.xtest {
            return Ok(());
        }
        self.conn.xtest_fake_input(kind, detail, 0, self.root, x as i16, y as i16, 0)?;
        Ok(())
    }

    fn key(&self, keycode: u8, down: bool) -> Result<()> {
        self.fake(if down { KEY_PRESS_EVENT } else { KEY_RELEASE_EVENT }, keycode, 0, 0)
    }

    fn tap(&self, keycode: u8, shift: bool) -> Result<()> {
        if shift {
            self.key(KC_SHIFT, true)?;
        }
        self.key(keycode, true)?;
        self.key(keycode, false)?;
        if shift {
            self.key(KC_SHIFT, false)?;
        }
        Ok(())
    }

    /// Types text by keysym: keys already producing the character are pressed (with Shift
    /// for the second level); anything else is mapped onto a spare keycode for the moment.
    fn type_text(&self, text: &str) -> Result<()> {
        let count = self.max_keycode - self.min_keycode + 1;
        let map = self.conn.get_keyboard_mapping(self.min_keycode, count)?.reply()?;
        let per = usize::from(map.keysyms_per_keycode);
        if per == 0 {
            return Ok(());
        }
        let find = |sym: u32| -> Option<(u8, bool)> {
            map.keysyms.chunks(per).enumerate().find_map(|(i, syms)| {
                let kc = self.min_keycode + i as u8;
                if syms.first() == Some(&sym) {
                    Some((kc, false))
                } else if syms.get(1) == Some(&sym) {
                    Some((kc, true))
                } else {
                    None
                }
            })
        };
        let spare = map.keysyms.chunks(per).enumerate().rev().find(|(_, s)| s.iter().all(|k| *k == 0)).map(|(i, _)| self.min_keycode + i as u8);
        let mut remapped = false;
        for c in text.chars() {
            let sym = keysym(c);
            if let Some((kc, shift)) = find(sym) {
                self.tap(kc, shift)?;
            } else if let Some(kc) = spare {
                self.conn.change_keyboard_mapping(1, kc, per as u8, &vec![sym; per])?;
                // Round trip so the mapping is in place before the key press.
                self.conn.get_input_focus()?.reply()?;
                std::thread::sleep(std::time::Duration::from_millis(15));
                self.tap(kc, false)?;
                self.conn.get_input_focus()?.reply()?;
                remapped = true;
            }
        }
        if let (true, Some(kc)) = (remapped, spare) {
            std::thread::sleep(std::time::Duration::from_millis(15));
            self.conn.change_keyboard_mapping(1, kc, per as u8, &vec![0; per])?;
        }
        Ok(())
    }
}

impl Drop for X11Screen {
    fn drop(&mut self) {
        if let Some(s) = self.shm.take() {
            self.free_shm(s);
        }
    }
}

fn keysym(c: char) -> u32 {
    let u = c as u32;
    match c {
        '\n' | '\r' => 0xff0d,
        '\t' => 0xff09,
        _ if (0x20..=0x7e).contains(&u) || (0xa0..=0xff).contains(&u) => u,
        _ => 0x0100_0000 | u,
    }
}

impl super::Screen for X11Screen {
    fn monitors(&mut self) -> Result<Vec<Monitor>> {
        let whole = || vec![Monitor { name: "Screen".into(), x: 0, y: 0, width: self.width.into(), height: self.height.into(), primary: true }];
        // Monitor objects need RandR 1.5.
        let has_randr = self.conn.extension_information(x11rb::protocol::randr::X11_EXTENSION_NAME)?.is_some();
        if !has_randr {
            return Ok(whole());
        }
        let v = self.conn.randr_query_version(1, 5)?.reply()?;
        if (v.major_version, v.minor_version) < (1, 5) {
            return Ok(whole());
        }
        let reply = self.conn.randr_get_monitors(self.root, true)?.reply()?;
        let mut out = Vec::new();
        for m in reply.monitors {
            let name = self.conn.get_atom_name(m.name)?.reply().map(|r| String::from_utf8_lossy(&r.name).into_owned()).unwrap_or_default();
            if m.width == 0 || m.height == 0 {
                continue;
            }
            out.push(Monitor { name, x: m.x.into(), y: m.y.into(), width: m.width.into(), height: m.height.into(), primary: m.primary });
        }
        if out.is_empty() {
            return Ok(whole());
        }
        if !out.iter().any(|m| m.primary) {
            out[0].primary = true;
        }
        Ok(out)
    }

    fn capture(&mut self, m: &Monitor, buf: &mut Vec<u8>) -> Result<()> {
        let (w, h) = (m.width as usize, m.height as usize);
        let size = w * h * 4;
        let (x, y, cw, ch) = (m.x as i16, m.y as i16, m.width as u16, m.height as u16);
        let format = ImageFormat::Z_PIXMAP.into();
        if let Some(shm) = self.shm_for(size) {
            let (seg, addr) = (shm.seg, shm.addr);
            let reply = self.conn.shm_get_image(self.root, x, y, cw, ch, !0, format, seg, 0)?.reply();
            if reply.is_ok() {
                buf.clear();
                // SAFETY: the segment is at least `size` bytes and the X server has finished
                // writing (we have its reply).
                buf.extend_from_slice(unsafe { std::slice::from_raw_parts(addr, size) });
                return Ok(());
            }
        }
        let reply = self.conn.get_image(ImageFormat::Z_PIXMAP, self.root, x, y, cw, ch, !0)?.reply()?;
        if reply.data.len() < size {
            bail!("short image from the X server ({} of {size} bytes)", reply.data.len());
        }
        buf.clear();
        buf.extend_from_slice(&reply.data[..size]);
        Ok(())
    }

    fn cursor(&mut self) -> Option<(i32, i32)> {
        let r = self.conn.query_pointer(self.root).ok()?.reply().ok()?;
        Some((r.root_x.into(), r.root_y.into()))
    }

    fn input(&mut self, m: &Monitor, ev: &InputEvent) -> Result<()> {
        match ev {
            InputEvent::Move { x, y } => {
                let (x, y) = super::absolute(m, *x, *y);
                self.fake(MOTION_NOTIFY_EVENT, 0, x, y)?;
            }
            InputEvent::Button { button, down, x, y } => {
                let (x, y) = super::absolute(m, *x, *y);
                self.fake(MOTION_NOTIFY_EVENT, 0, x, y)?;
                let b = match button {
                    Button::Left => 1,
                    Button::Middle => 2,
                    Button::Right => 3,
                    Button::Back => 8,
                    Button::Forward => 9,
                };
                self.fake(if *down { BUTTON_PRESS_EVENT } else { BUTTON_RELEASE_EVENT }, b, 0, 0)?;
            }
            InputEvent::Wheel { dx, dy } => {
                for (n, neg, pos) in [(*dy, 4, 5), (*dx, 6, 7)] {
                    let b = if n < 0 { neg } else { pos };
                    for _ in 0..n.unsigned_abs().min(100) {
                        self.fake(BUTTON_PRESS_EVENT, b, 0, 0)?;
                        self.fake(BUTTON_RELEASE_EVENT, b, 0, 0)?;
                    }
                }
            }
            InputEvent::Key { code, down } => {
                if let Some(k) = keymap::lookup(code) {
                    let kc = k.evdev + 8;
                    if (u16::from(self.min_keycode)..=u16::from(self.max_keycode)).contains(&kc) {
                        self.key(kc as u8, *down)?;
                    }
                }
            }
            InputEvent::Text { text } => self.type_text(text)?,
            InputEvent::CtrlAltDel => {
                for (kc, down) in [(KC_CTRL, true), (KC_ALT, true), (KC_DELETE, true), (KC_DELETE, false), (KC_ALT, false), (KC_CTRL, false)] {
                    self.key(kc, down)?;
                }
            }
        }
        self.conn.flush()?;
        Ok(())
    }
}
