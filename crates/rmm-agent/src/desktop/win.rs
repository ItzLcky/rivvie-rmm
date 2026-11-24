//! Windows: starting the helper in the console session, GDI capture, `SendInput`, and
//! Ctrl+Alt+Del through `SendSAS`.
//!
//! The agent service runs as SYSTEM in session 0, which has no access to anyone's screen.
//! The helper is started with a copy of the service's own token moved into the active
//! console session (`SetTokenInformation(TokenSessionId)` + `CreateProcessAsUserW`). Running
//! as SYSTEM there lets it switch to whichever desktop has the input: the user's
//! (`Default`), the sign-in screen and UAC prompts (`Winlogon`).

use std::fs::File;
use std::os::windows::io::{FromRawHandle, RawHandle};
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use rmm_proto::desktop::{Button, Consent, InputEvent, Monitor};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HANDLE_FLAG_INHERIT, LPARAM, RECT, SetHandleInformation};
use windows::Win32::Graphics::Gdi::{
    BI_RGB, BITMAPINFO, BITMAPINFOHEADER, BitBlt, CAPTUREBLT, CreateCompatibleDC, CreateDIBSection, DIB_RGB_COLORS, DeleteDC,
    DeleteObject, EnumDisplayMonitors, GetDC, GetMonitorInfoW, HBITMAP, HDC, HGDIOBJ, HMONITOR, MONITORINFOEXW, ReleaseDC, SRCCOPY,
    SelectObject,
};
use windows::Win32::Security::{
    DuplicateTokenEx, SECURITY_ATTRIBUTES, SecurityImpersonation, SetTokenInformation, TOKEN_ACCESS_MASK, TOKEN_ADJUST_DEFAULT,
    TOKEN_ADJUST_SESSIONID, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_QUERY, TokenPrimary, TokenSessionId,
};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::System::Pipes::CreatePipe;
use windows::Win32::System::RemoteDesktop::{
    WTS_CURRENT_SERVER_HANDLE, WTSFreeMemory, WTSGetActiveConsoleSessionId, WTSQuerySessionInformationW, WTSSendMessageW, WTSUserName,
};
use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, DESKTOP_ACCESS_FLAGS, DESKTOP_CONTROL_FLAGS, GetUserObjectInformationW, HDESK, OpenInputDesktop, SetThreadDesktop,
    UOI_NAME,
};
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, CreateProcessAsUserW, GetCurrentProcess, OpenProcessToken, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
    TerminateProcess, WaitForSingleObject,
};
use windows::Win32::UI::HiDpi::{DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, SetProcessDpiAwarenessContext};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBD_EVENT_FLAGS, KEYBDINPUT, KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE,
    KEYEVENTF_UNICODE, MOUSE_EVENT_FLAGS, MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_HWHEEL, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP,
    MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_VIRTUALDESK,
    MOUSEEVENTF_WHEEL, MOUSEEVENTF_XDOWN, MOUSEEVENTF_XUP, MOUSEINPUT, SendInput, VIRTUAL_KEY, VK_RETURN,
};
use windows::Win32::UI::WindowsAndMessaging::{
    GetCursorPos, GetSystemMetrics, IDYES, MB_ICONQUESTION, MB_SETFOREGROUND, MB_TOPMOST, MB_YESNO, MESSAGEBOX_RESULT, MONITORINFOF_PRIMARY,
    SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
};
use windows::core::{BOOL, PCWSTR, PWSTR, s, w};

use super::keymap::{self, WinKey};
use super::session::{Helper, Process};

const GENERIC_ALL: u32 = 0x1000_0000;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The session with the physical console (the one at the monitor and keyboard).
#[derive(Debug, Clone, Copy)]
pub struct ConsoleSession {
    id: u32,
}

impl ConsoleSession {
    pub fn active() -> Result<Self> {
        // SAFETY: no arguments.
        let id = unsafe { WTSGetActiveConsoleSessionId() };
        if id == u32::MAX {
            bail!("no console session is attached (the machine may be switching users)");
        }
        Ok(ConsoleSession { id })
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    /// The signed-in user's name, if anyone is signed in to the console.
    fn user(&self) -> Option<String> {
        let mut buf = PWSTR::null();
        let mut len = 0u32;
        // SAFETY: the buffer is allocated by WTS and freed below.
        unsafe {
            WTSQuerySessionInformationW(Some(WTS_CURRENT_SERVER_HANDLE), self.id, WTSUserName, &mut buf, &mut len).ok()?;
            let name = buf.to_string().unwrap_or_default();
            WTSFreeMemory(buf.0.cast());
            Some(name).filter(|n| !n.is_empty())
        }
    }

    /// A Yes/No message box in the console session. Nobody signed in: nobody to ask.
    pub fn ask(&self, c: &Consent) -> Result<Option<bool>> {
        if self.user().is_none() {
            return Ok(None);
        }
        let host = crate::collect::system_info().hostname;
        let (title, text) = super::session::consent_text(c, &host);
        let (title, text) = (wide(&title), wide(&text));
        let mut response = MESSAGEBOX_RESULT(0);
        // SAFETY: the strings outlive the call; lengths are in bytes without the terminator.
        unsafe {
            WTSSendMessageW(
                Some(WTS_CURRENT_SERVER_HANDLE),
                self.id,
                PCWSTR(title.as_ptr()),
                ((title.len() - 1) * 2) as u32,
                PCWSTR(text.as_ptr()),
                ((text.len() - 1) * 2) as u32,
                MB_YESNO | MB_ICONQUESTION | MB_TOPMOST | MB_SETFOREGROUND,
                c.timeout_secs.max(5),
                &mut response,
                true,
            )
            .context("showing the consent prompt")?;
        }
        // IDNO, and IDTIMEOUT when nobody answered, both deny.
        Ok(Some(response == IDYES))
    }

    pub fn spawn(&self, exe: &Path) -> Result<Helper> {
        // SAFETY: Win32 calls with owned handles, each closed on every path below.
        unsafe {
            let mut own = HANDLE::default();
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
                &mut own,
            )
            .context("opening the service token")?;
            let mut token = HANDLE::default();
            let dup = DuplicateTokenEx(own, TOKEN_ACCESS_MASK(0x000F_01FF), None, SecurityImpersonation, TokenPrimary, &mut token);
            let _ = CloseHandle(own);
            dup.context("duplicating the service token")?;
            let session = self.id;
            if let Err(e) = SetTokenInformation(token, TokenSessionId, (&raw const session).cast(), 4) {
                let _ = CloseHandle(token);
                return Err(e).context("moving the token into the console session (is the agent running as SYSTEM?)");
            }

            let sa = SECURITY_ATTRIBUTES { nLength: size_of::<SECURITY_ATTRIBUTES>() as u32, bInheritHandle: BOOL(1), ..Default::default() };
            let pipe = || -> Result<(HANDLE, HANDLE)> {
                let (mut r, mut w) = (HANDLE::default(), HANDLE::default());
                CreatePipe(&mut r, &mut w, Some(&sa), 0)?;
                Ok((r, w))
            };
            let (in_r, in_w) = pipe()?;
            let (out_r, out_w) = pipe()?;
            let (err_r, err_w) = pipe()?;
            // Our ends must not be inherited, or the helper would keep its own stdin open.
            for h in [in_w, out_r, err_r] {
                SetHandleInformation(h, HANDLE_FLAG_INHERIT.0, Default::default())?;
            }

            let mut desktop = wide("winsta0\\default");
            let si = STARTUPINFOW {
                cb: size_of::<STARTUPINFOW>() as u32,
                lpDesktop: PWSTR(desktop.as_mut_ptr()),
                dwFlags: STARTF_USESTDHANDLES,
                hStdInput: in_r,
                hStdOutput: out_w,
                hStdError: err_w,
                ..Default::default()
            };
            let mut cmdline = wide(&format!("\"{}\" desktop-helper", exe.display()));
            let app = wide(&exe.to_string_lossy());
            let mut pi = PROCESS_INFORMATION::default();
            let created = CreateProcessAsUserW(
                Some(token),
                PCWSTR(app.as_ptr()),
                Some(PWSTR(cmdline.as_mut_ptr())),
                None,
                None,
                true,
                CREATE_NO_WINDOW,
                None,
                PCWSTR::null(),
                &si,
                &mut pi,
            );
            for h in [token, in_r, out_w, err_w] {
                let _ = CloseHandle(h);
            }
            if let Err(e) = created {
                for h in [in_w, out_r, err_r] {
                    let _ = CloseHandle(h);
                }
                return Err(e).context("starting the desktop helper in the console session");
            }
            let _ = CloseHandle(pi.hThread);
            let file = |h: HANDLE| File::from_raw_handle(h.0 as RawHandle);
            Ok(Helper {
                stdin: Box::new(file(in_w)),
                stdout: Box::new(file(out_r)),
                stderr: Box::new(file(err_r)),
                process: Box::new(WinProcess(pi.hProcess.0 as isize)),
            })
        }
    }
}

/// Process handle (as an integer: `HANDLE` isn't `Send`).
struct WinProcess(isize);

impl Process for WinProcess {
    fn kill(&mut self) {
        let h = HANDLE(self.0 as *mut _);
        // SAFETY: the handle is ours and closed exactly once.
        unsafe {
            let _ = TerminateProcess(h, 1);
            let _ = WaitForSingleObject(h, 5000);
            let _ = CloseHandle(h);
        }
    }
}

/// Ctrl+Alt+Del. Only works from a service, and only when the `SoftwareSASGeneration`
/// policy allows services to send it, so the policy is turned on first if it's off.
pub fn send_sas() -> Result<()> {
    use winreg::RegKey;
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE};
    let key = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", KEY_READ | KEY_WRITE)
        .context("opening the System policies key")?;
    let current: u32 = key.get_value("SoftwareSASGeneration").unwrap_or(0);
    // 1 = services, 3 = services and Ease of Access applications.
    if current & 1 == 0 {
        key.set_value("SoftwareSASGeneration", &(current | 1)).context("allowing services to send Ctrl+Alt+Del")?;
        tracing::info!("set SoftwareSASGeneration to {} so remote sessions can send Ctrl+Alt+Del", current | 1);
    }
    // SAFETY: SendSAS has the documented signature `void SendSAS(BOOL AsUser)`.
    unsafe {
        let lib = LoadLibraryW(w!("sas.dll")).context("loading sas.dll")?;
        let f = GetProcAddress(lib, s!("SendSAS")).context("sas.dll has no SendSAS")?;
        let send: unsafe extern "system" fn(BOOL) = std::mem::transmute(f);
        send(BOOL(0));
    }
    Ok(())
}

/// Cached GDI objects for one capture size.
struct Surface {
    dc: HDC,
    bitmap: HBITMAP,
    old: HGDIOBJ,
    bits: *mut u8,
    width: i32,
    height: i32,
}

pub struct GdiScreen {
    desktop: Option<(HDESK, String)>,
    checked: Instant,
    surface: Option<Surface>,
}

impl GdiScreen {
    pub fn new() -> Result<Self> {
        // Physical pixels everywhere, on scaled displays too.
        // SAFETY: process-wide setting made before any window or DC exists.
        unsafe {
            let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        }
        let mut s = GdiScreen { desktop: None, checked: Instant::now(), surface: None };
        s.follow_input_desktop()?;
        Ok(s)
    }

    /// Switches this thread to the desktop receiving input (it changes on sign-in, lock and
    /// UAC prompts). Returns whether it changed.
    fn follow_input_desktop(&mut self) -> Result<bool> {
        self.checked = Instant::now();
        // SAFETY: the desktop handle is closed when replaced or on drop.
        unsafe {
            let desk = OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_ACCESS_FLAGS(GENERIC_ALL)).context("opening the input desktop")?;
            let mut name = [0u16; 128];
            let mut needed = 0u32;
            let _ = GetUserObjectInformationW(HANDLE(desk.0), UOI_NAME, Some(name.as_mut_ptr().cast()), (name.len() * 2) as u32, Some(&mut needed));
            let len = name.iter().position(|c| *c == 0).unwrap_or(name.len());
            let name = String::from_utf16_lossy(&name[..len]);
            if self.desktop.as_ref().is_some_and(|(_, n)| *n == name) {
                let _ = CloseDesktop(desk);
                return Ok(false);
            }
            self.drop_surface();
            SetThreadDesktop(desk).with_context(|| format!("switching to the {name} desktop"))?;
            if let Some((old, _)) = self.desktop.replace((desk, name.clone())) {
                let _ = CloseDesktop(old);
            }
            tracing::info!("following input to the {name} desktop");
            Ok(true)
        }
    }

    fn maybe_follow(&mut self) {
        if self.checked.elapsed() >= Duration::from_millis(250)
            && let Err(e) = self.follow_input_desktop()
        {
            tracing::debug!("{e:#}");
        }
    }

    fn drop_surface(&mut self) {
        if let Some(s) = self.surface.take() {
            // SAFETY: objects created in `surface_for` and not used after this.
            unsafe {
                SelectObject(s.dc, s.old);
                let _ = DeleteObject(s.bitmap.into());
                let _ = DeleteDC(s.dc);
            }
        }
    }

    fn surface_for(&mut self, screen: HDC, width: i32, height: i32) -> Result<&Surface> {
        if !self.surface.as_ref().is_some_and(|s| s.width == width && s.height == height) {
            self.drop_surface();
            // SAFETY: GDI object creation; everything is released in `drop_surface`.
            unsafe {
                let dc = CreateCompatibleDC(Some(screen));
                let bmi = BITMAPINFO {
                    bmiHeader: BITMAPINFOHEADER {
                        biSize: size_of::<BITMAPINFOHEADER>() as u32,
                        biWidth: width,
                        biHeight: -height, // top-down rows
                        biPlanes: 1,
                        biBitCount: 32,
                        biCompression: BI_RGB.0,
                        ..Default::default()
                    },
                    ..Default::default()
                };
                let mut bits = std::ptr::null_mut();
                let bitmap = match CreateDIBSection(Some(dc), &bmi, DIB_RGB_COLORS, &mut bits, None, 0) {
                    Ok(b) => b,
                    Err(e) => {
                        let _ = DeleteDC(dc);
                        return Err(e).context("CreateDIBSection");
                    }
                };
                let old = SelectObject(dc, bitmap.into());
                self.surface = Some(Surface { dc, bitmap, old, bits: bits.cast(), width, height });
            }
        }
        Ok(self.surface.as_ref().expect("just created"))
    }

    fn grab(&mut self, m: &Monitor, buf: &mut Vec<u8>) -> Result<()> {
        let (w, h) = (m.width as i32, m.height as i32);
        // SAFETY: the screen DC is released below; the DIB is `w * h * 4` bytes.
        unsafe {
            let screen = GetDC(None);
            if screen.is_invalid() {
                bail!("GetDC failed");
            }
            let res = (|| -> Result<()> {
                let s = self.surface_for(screen, w, h)?;
                BitBlt(s.dc, 0, 0, w, h, Some(screen), m.x, m.y, SRCCOPY | CAPTUREBLT).context("BitBlt")?;
                buf.clear();
                buf.extend_from_slice(std::slice::from_raw_parts(s.bits, (w * h * 4) as usize));
                Ok(())
            })();
            ReleaseDC(None, screen);
            res
        }
    }
}

impl Drop for GdiScreen {
    fn drop(&mut self) {
        self.drop_surface();
        if let Some((d, _)) = self.desktop.take() {
            // SAFETY: our handle.
            unsafe {
                let _ = CloseDesktop(d);
            }
        }
    }
}

unsafe extern "system" fn monitor_cb(mon: HMONITOR, _: HDC, _: *mut RECT, data: LPARAM) -> BOOL {
    // SAFETY: `data` is the Vec passed by `monitors` and outlives the enumeration.
    unsafe {
        let out = &mut *(data.0 as *mut Vec<Monitor>);
        let mut info = MONITORINFOEXW::default();
        info.monitorInfo.cbSize = size_of::<MONITORINFOEXW>() as u32;
        if GetMonitorInfoW(mon, &mut info.monitorInfo).as_bool() {
            let r = info.monitorInfo.rcMonitor;
            let len = info.szDevice.iter().position(|c| *c == 0).unwrap_or(info.szDevice.len());
            let name = String::from_utf16_lossy(&info.szDevice[..len]).trim_start_matches(r"\\.\").to_string();
            out.push(Monitor {
                name,
                x: r.left,
                y: r.top,
                width: (r.right - r.left).max(1) as u32,
                height: (r.bottom - r.top).max(1) as u32,
                primary: info.monitorInfo.dwFlags & MONITORINFOF_PRIMARY != 0,
            });
        }
    }
    BOOL(1)
}

fn send(inputs: &[INPUT]) {
    // SAFETY: a slice of initialised INPUT structures.
    unsafe {
        SendInput(inputs, size_of::<INPUT>() as i32);
    }
}

fn mouse(dx: i32, dy: i32, data: i32, flags: MOUSE_EVENT_FLAGS) -> INPUT {
    INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 { mi: MOUSEINPUT { dx, dy, mouseData: data as _, dwFlags: flags, time: 0, dwExtraInfo: 0 } },
    }
}

fn key(vk: u16, scan: u16, flags: KEYBD_EVENT_FLAGS) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 { ki: KEYBDINPUT { wVk: VIRTUAL_KEY(vk), wScan: scan, dwFlags: flags, time: 0, dwExtraInfo: 0 } },
    }
}

/// An absolute move to virtual-desktop pixel (x, y), in SendInput's 0..65535 units.
fn move_to(x: i32, y: i32) -> INPUT {
    // SAFETY: plain metric queries.
    let (vx, vy, vw, vh) = unsafe {
        (
            GetSystemMetrics(SM_XVIRTUALSCREEN),
            GetSystemMetrics(SM_YVIRTUALSCREEN),
            GetSystemMetrics(SM_CXVIRTUALSCREEN).max(2),
            GetSystemMetrics(SM_CYVIRTUALSCREEN).max(2),
        )
    };
    let nx = ((x - vx) as i64 * 65535 / (vw - 1) as i64) as i32;
    let ny = ((y - vy) as i64 * 65535 / (vh - 1) as i64) as i32;
    mouse(nx, ny, 0, MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK)
}

impl super::Screen for GdiScreen {
    fn monitors(&mut self) -> Result<Vec<Monitor>> {
        let mut out: Vec<Monitor> = Vec::new();
        // SAFETY: the callback only touches `out`, which outlives the call.
        unsafe {
            let _ = EnumDisplayMonitors(None, None, Some(monitor_cb), LPARAM(&raw mut out as isize));
        }
        if !out.is_empty() && !out.iter().any(|m| m.primary) {
            out[0].primary = true;
        }
        Ok(out)
    }

    fn capture(&mut self, m: &Monitor, buf: &mut Vec<u8>) -> Result<()> {
        self.maybe_follow();
        match self.grab(m, buf) {
            Ok(()) => Ok(()),
            // Usually the input desktop just changed (sign-in screen, UAC): follow and retry.
            Err(_) if self.follow_input_desktop().unwrap_or(false) => self.grab(m, buf),
            Err(e) => Err(e),
        }
    }

    fn cursor(&mut self) -> Option<(i32, i32)> {
        let mut p = Default::default();
        // SAFETY: writes the point.
        unsafe { GetCursorPos(&mut p).ok()? };
        Some((p.x, p.y))
    }

    fn input(&mut self, m: &Monitor, ev: &InputEvent) -> Result<()> {
        self.maybe_follow();
        match ev {
            InputEvent::Move { x, y } => {
                let (x, y) = super::absolute(m, *x, *y);
                send(&[move_to(x, y)]);
            }
            InputEvent::Button { button, down, x, y } => {
                let (x, y) = super::absolute(m, *x, *y);
                let (flags, data) = match (button, down) {
                    (Button::Left, true) => (MOUSEEVENTF_LEFTDOWN, 0),
                    (Button::Left, false) => (MOUSEEVENTF_LEFTUP, 0),
                    (Button::Right, true) => (MOUSEEVENTF_RIGHTDOWN, 0),
                    (Button::Right, false) => (MOUSEEVENTF_RIGHTUP, 0),
                    (Button::Middle, true) => (MOUSEEVENTF_MIDDLEDOWN, 0),
                    (Button::Middle, false) => (MOUSEEVENTF_MIDDLEUP, 0),
                    (Button::Back, true) => (MOUSEEVENTF_XDOWN, 1),
                    (Button::Back, false) => (MOUSEEVENTF_XUP, 1),
                    (Button::Forward, true) => (MOUSEEVENTF_XDOWN, 2),
                    (Button::Forward, false) => (MOUSEEVENTF_XUP, 2),
                };
                send(&[move_to(x, y), mouse(0, 0, data, flags)]);
            }
            InputEvent::Wheel { dx, dy } => {
                // WHEEL_DELTA per notch; positive is away from the user (up).
                if *dy != 0 {
                    send(&[mouse(0, 0, -dy * 120, MOUSEEVENTF_WHEEL)]);
                }
                if *dx != 0 {
                    send(&[mouse(0, 0, dx * 120, MOUSEEVENTF_HWHEEL)]);
                }
            }
            InputEvent::Key { code, down } => {
                if let Some(k) = keymap::lookup(code) {
                    let up = if *down { KEYBD_EVENT_FLAGS(0) } else { KEYEVENTF_KEYUP };
                    send(&[match k.win {
                        WinKey::Scan(sc, ext) => key(0, sc, KEYEVENTF_SCANCODE | up | if ext { KEYEVENTF_EXTENDEDKEY } else { KEYBD_EVENT_FLAGS(0) }),
                        WinKey::Vk(vk) => key(vk, 0, up),
                    }]);
                }
            }
            InputEvent::Text { text } => {
                let mut inputs = Vec::new();
                for c in text.chars() {
                    if c == '\r' {
                        continue;
                    }
                    if c == '\n' {
                        inputs.push(key(VK_RETURN.0, 0, KEYBD_EVENT_FLAGS(0)));
                        inputs.push(key(VK_RETURN.0, 0, KEYEVENTF_KEYUP));
                        continue;
                    }
                    let mut units = [0u16; 2];
                    for u in c.encode_utf16(&mut units) {
                        inputs.push(key(0, *u, KEYEVENTF_UNICODE));
                        inputs.push(key(0, *u, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP));
                    }
                }
                for chunk in inputs.chunks(64) {
                    send(chunk);
                }
            }
            // Sent by the agent service with SendSAS; nothing to do in the helper.
            InputEvent::CtrlAltDel => {}
        }
        Ok(())
    }
}
