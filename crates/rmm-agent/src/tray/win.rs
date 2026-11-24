//! Windows: the named pipe (service side, with its DACL and peer identity), the `Run` value
//! that starts the tray at sign-in, and the tray itself: a notification-area icon, its menu,
//! the request form and message boxes, in raw Win32.

use std::os::windows::io::{AsRawHandle, RawHandle};
use std::sync::atomic::{AtomicIsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use rmm_proto::tray::Config;
use tokio::net::windows::named_pipe::{NamedPipeClient, NamedPipeServer, ServerOptions};
use tracing::{info, warn};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HINSTANCE, HLOCAL, HWND, LPARAM, LRESULT, LocalFree, POINT, WPARAM};
use windows::Win32::Graphics::Gdi::{DEFAULT_GUI_FONT, GetStockObject};
use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
use windows::Win32::Security::{
    GetTokenInformation, LookupAccountSidW, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, SID_NAME_USE, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows::Win32::Storage::FileSystem::{CreateFileW, FILE_FLAG_OVERLAPPED, FILE_SHARE_NONE, OPEN_EXISTING};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress, LoadLibraryW};
use windows::Win32::System::Pipes::{GetNamedPipeClientProcessId, GetNamedPipeServerProcessId};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::Threading::{OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION};
use windows::Win32::UI::Shell::{
    NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP, NIIF_INFO, NIM_ADD, NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW, ShellExecuteW, Shell_NotifyIconW,
};
use windows::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, BM_GETCHECK, BM_SETCHECK, BS_AUTOCHECKBOX, BS_DEFPUSHBUTTON, BS_PUSHBUTTON, CW_USEDEFAULT, CreateIconFromResourceEx,
    CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu, DestroyWindow, DispatchMessageW, ES_AUTOHSCROLL, ES_AUTOVSCROLL,
    ES_MULTILINE, ES_WANTRETURN, GetCursorPos, GetMessageW, GetSystemMetrics, GetWindowTextLengthW, GetWindowTextW, HICON, HMENU,
    IDI_APPLICATION, IDYES, IsDialogMessageW, LR_DEFAULTCOLOR, LoadIconW, MB_ICONERROR, MB_ICONINFORMATION, MB_ICONQUESTION, MB_OK,
    MB_SETFOREGROUND, MB_TOPMOST, MB_YESNO, MESSAGEBOX_STYLE, MF_SEPARATOR, MF_STRING, MSG, MessageBoxW, PostMessageW, PostQuitMessage,
    RegisterClassW, RegisterWindowMessageW, SM_CXSMICON, SW_SHOWNORMAL, SendMessageW, SetForegroundWindow, TPM_NONOTIFY, TPM_RETURNCMD,
    TPM_RIGHTBUTTON, TrackPopupMenu, WINDOW_EX_STYLE, WINDOW_STYLE, WM_APP, WM_COMMAND, WM_CONTEXTMENU, WM_DESTROY, WM_LBUTTONUP,
    WM_RBUTTONUP, WM_SETFONT, WNDCLASSW, WS_BORDER, WS_CAPTION, WS_CHILD, WS_EX_DLGMODALFRAME, WS_EX_TOPMOST, WS_OVERLAPPED, WS_SYSMENU,
    WS_TABSTOP, WS_VISIBLE, WS_VSCROLL,
};
use windows::core::{PCWSTR, PWSTR, s, w};

use super::ipc::AgentToTray;
use super::{Client, Peer, Tray, Ui};

pub const PIPE: &str = r"\\.\pipe\rmm-agent-tray";
const RUN_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
/// The `Run` value's name (the MSI's Registry table writes the same one).
pub const RUN_VALUE: &str = "RmmAgentTray";

/// SYSTEM and Administrators: everything. Interactive users: read and write data, read
/// attributes, synchronize; not FILE_CREATE_PIPE_INSTANCE, so nobody can stand up a second
/// server instance and take connections meant for the agent.
const SDDL: PCWSTR = w!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x120083;;;IU)");
/// What a tray asks for when it opens the pipe (within the grant above).
const CLIENT_ACCESS: u32 = 0x0001 | 0x0002 | 0x0080 | 0x0010_0000;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// `DOMAIN\user`, or the bare name when there is no domain.
pub fn account(domain: &str, name: &str) -> String {
    if domain.is_empty() { name.to_string() } else { format!("{domain}\\{name}") }
}

/// The `Run` value's data: the agent's binary, quoted, and the subcommand.
pub fn run_command(exe: &std::path::Path) -> String {
    format!("\"{}\" tray", exe.display())
}

pub fn set_run_key(exe: &std::path::Path) -> Result<()> {
    let hklm = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE);
    let (key, _) = hklm.create_subkey(RUN_KEY).context("opening the Run key")?;
    key.set_value(RUN_VALUE, &run_command(exe)).context("writing the tray's Run value")?;
    Ok(())
}

pub fn remove_run_key() {
    let hklm = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE);
    if let Ok(key) = hklm.open_subkey_with_flags(RUN_KEY, winreg::enums::KEY_SET_VALUE) {
        let _ = key.delete_value(RUN_VALUE);
    }
}

// ---------------------------------------------------------------------------
// Service side
// ---------------------------------------------------------------------------

fn create_instance(first: bool) -> std::io::Result<NamedPipeServer> {
    // SAFETY: the descriptor is allocated by the conversion and freed after the pipe is created
    // (the pipe keeps its own copy); the attributes point at it only for the call.
    unsafe {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(SDDL, SDDL_REVISION_1, &mut sd, None).map_err(std::io::Error::other)?;
        let mut sa = SECURITY_ATTRIBUTES { nLength: size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: sd.0, bInheritHandle: false.into() };
        let res = ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .max_instances(64)
            .create_with_security_attributes_raw(PIPE, (&mut sa as *mut SECURITY_ATTRIBUTES).cast());
        let _ = LocalFree(Some(HLOCAL(sd.0)));
        res
    }
}

/// Accepts tray connections until the service stops.
pub async fn listen(tray: Arc<Tray>) -> Result<()> {
    // First instance: if anything else already owns the name, refuse to serve under it.
    let mut server = create_instance(true).context("creating the tray pipe (is another process using it?)")?;
    info!("tray pipe at {PIPE}");
    loop {
        if let Err(e) = server.connect().await {
            warn!("tray pipe connect: {e}");
        }
        let connected = server;
        server = loop {
            match create_instance(false) {
                Ok(s) => break s,
                Err(e) => {
                    warn!("tray pipe: {e}");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        };
        match peer(connected.as_raw_handle()) {
            Ok(p) => {
                tokio::spawn(tray.clone().serve(connected, p));
            }
            Err(e) => warn!("tray pipe: who connected: {e:#}"),
        }
    }
}

/// The connected client's account and session, from the kernel's view of the pipe.
fn peer(h: RawHandle) -> Result<Peer> {
    // SAFETY: Win32 calls on handles owned here, each closed below; buffers sized by the calls.
    unsafe {
        let mut pid = 0u32;
        GetNamedPipeClientProcessId(HANDLE(h), &mut pid).context("client process id")?;
        let mut session = 0u32;
        ProcessIdToSessionId(pid, &mut session).context("client session")?;
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).context("opening the client process")?;
        let mut token = HANDLE::default();
        let opened = OpenProcessToken(process, TOKEN_QUERY, &mut token);
        let _ = CloseHandle(process);
        opened.context("opening the client's token")?;
        let mut len = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
        // u64s: TOKEN_USER must be aligned.
        let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
        let got = GetTokenInformation(token, TokenUser, Some(buf.as_mut_ptr().cast()), len, &mut len);
        let _ = CloseHandle(token);
        got.context("reading the client's token")?;
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        let (mut name, mut domain) = (vec![0u16; 256], vec![0u16; 256]);
        let (mut nlen, mut dlen) = (name.len() as u32, domain.len() as u32);
        let mut kind = SID_NAME_USE::default();
        LookupAccountSidW(
            PCWSTR::null(),
            user.User.Sid,
            Some(PWSTR(name.as_mut_ptr())),
            &mut nlen,
            Some(PWSTR(domain.as_mut_ptr())),
            &mut dlen,
            &mut kind,
        )
        .context("looking up the client's account")?;
        let name = String::from_utf16_lossy(&name[..nlen as usize]);
        let domain = String::from_utf16_lossy(&domain[..dlen as usize]);
        Ok(Peer { user: account(&domain, &name), session })
    }
}

// ---------------------------------------------------------------------------
// Tray side
// ---------------------------------------------------------------------------

/// Opens the pipe with only the access the DACL grants a user, and checks that the other end
/// is a service (session 0), not another user's process squatting on the name.
pub async fn connect() -> Result<NamedPipeClient> {
    let name = wide(PIPE);
    let deadline = Instant::now() + Duration::from_secs(5);
    let handle = loop {
        // SAFETY: `name` outlives the call; the handle is owned by the client below.
        let res = unsafe { CreateFileW(PCWSTR(name.as_ptr()), CLIENT_ACCESS, FILE_SHARE_NONE, None, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, None) };
        match res {
            Ok(h) => break h,
            // ERROR_PIPE_BUSY: every instance is taken for a moment.
            Err(e) if e.code().0 as u32 == 0x8007_00e7 && Instant::now() < deadline => tokio::time::sleep(Duration::from_millis(50)).await,
            Err(e) => bail!("connecting to the agent at {PIPE} (is the agent service running?): {e}"),
        }
    };
    // SAFETY: an overlapped pipe handle we own.
    let client = unsafe { NamedPipeClient::from_raw_handle(handle.0) }?;
    let mut pid = 0u32;
    let mut session = u32::MAX;
    // SAFETY: plain queries on the handle just opened.
    unsafe {
        GetNamedPipeServerProcessId(HANDLE(client.as_raw_handle()), &mut pid).context("agent process id")?;
        ProcessIdToSessionId(pid, &mut session).context("agent session")?;
    }
    if session != 0 {
        bail!("{PIPE} isn't served by the agent service (its server runs in session {session})");
    }
    Ok(client)
}

const WM_TRAY: u32 = WM_APP + 1;
const WM_CONFIG: u32 = WM_APP + 2;
const WM_NOTICE: u32 = WM_APP + 3;
const ID_REQUEST: usize = 1;
const ID_CONTACT: usize = 2;
const ID_HIDE: usize = 3;
const ID_LINK: usize = 100;

static MAIN: AtomicIsize = AtomicIsize::new(0);
static TASKBAR_CREATED: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

#[derive(Default)]
struct State {
    /// `None` until the agent answers; the tray then behaves as if everything is on.
    config: Option<Config>,
    notice: Option<(String, bool)>,
    icon: Option<isize>,
    shown: bool,
}

static STATE: Mutex<State> = Mutex::new(State { config: None, notice: None, icon: None, shown: false });

fn state() -> std::sync::MutexGuard<'static, State> {
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}

fn main_hwnd() -> HWND {
    HWND(MAIN.load(Ordering::SeqCst) as _)
}

fn product(c: Option<&Config>) -> String {
    c.map(|c| c.product_name.trim().to_string()).filter(|p| !p.is_empty()).unwrap_or_else(|| "Help desk".into())
}

fn message_box(title: &str, text: &str, style: MESSAGEBOX_STYLE) -> bool {
    let (t, x) = (wide(title), wide(text));
    // SAFETY: the strings outlive the call.
    unsafe { MessageBoxW(None, PCWSTR(x.as_ptr()), PCWSTR(t.as_ptr()), style | MB_TOPMOST | MB_SETFOREGROUND) == IDYES }
}

/// A Yes/No box that closes itself (user32's MessageBoxTimeoutW, present since XP but not in
/// the headers). Falls back to an ordinary box; the service enforces the timeout anyway.
fn ask_with_timeout(title: &str, text: &str, secs: u32) -> bool {
    type Func = unsafe extern "system" fn(HWND, PCWSTR, PCWSTR, u32, u16, u32) -> i32;
    let (t, x) = (wide(title), wide(text));
    // SAFETY: user32 is always loaded in a GUI process; the signature matches the export.
    unsafe {
        if let Ok(user32) = LoadLibraryW(w!("user32.dll"))
            && let Some(f) = GetProcAddress(user32, s!("MessageBoxTimeoutW"))
        {
            let f: Func = std::mem::transmute(f);
            let style = (MB_YESNO | MB_ICONQUESTION | MB_TOPMOST | MB_SETFOREGROUND).0;
            return f(HWND::default(), PCWSTR(x.as_ptr()), PCWSTR(t.as_ptr()), style, 0, secs.max(5) * 1000) == IDYES.0;
        }
    }
    message_box(title, text, MB_YESNO | MB_ICONQUESTION)
}

struct WinUi;

impl Ui for WinUi {
    fn config(&self, c: Option<Config>) {
        state().config = c;
        // SAFETY: posting to our own window; a failure just leaves the old look.
        unsafe {
            let _ = PostMessageW(Some(main_hwnd()), WM_CONFIG, WPARAM(0), LPARAM(0));
        }
    }

    fn consent(&self, title: &str, text: &str, timeout_secs: u32) -> bool {
        ask_with_timeout(title, text, timeout_secs)
    }

    fn notice(&self, text: &str, active: bool) {
        state().notice = Some((text.to_string(), active));
        // SAFETY: as above.
        unsafe {
            let _ = PostMessageW(Some(main_hwnd()), WM_NOTICE, WPARAM(0), LPARAM(0));
        }
    }
}

fn copy_into(dst: &mut [u16], s: &str) {
    let n = dst.len() - 1;
    for (d, c) in dst.iter_mut().zip(s.encode_utf16().take(n).chain(std::iter::repeat(0))) {
        *d = c;
    }
}

fn icon_for(c: Option<&Config>) -> HICON {
    // SAFETY: CreateIconFromResourceEx reads the PNG bytes (Vista+ accepts PNG icon images);
    // LoadIconW with a stock id needs no module.
    unsafe {
        if let Some(png) = c.map(|c| c.icon_png.as_slice()).filter(|p| !p.is_empty()) {
            let size = GetSystemMetrics(SM_CXSMICON).max(16);
            if let Ok(h) = CreateIconFromResourceEx(png, true, 0x0003_0000, size, size, LR_DEFAULTCOLOR) {
                return h;
            }
        }
        LoadIconW(None, IDI_APPLICATION).unwrap_or_default()
    }
}

/// Adds, updates or removes the icon to match the config.
fn refresh_icon(force_add: bool) {
    let mut st = state();
    let want = st.config.as_ref().is_none_or(|c| c.enabled);
    let mut data = NOTIFYICONDATAW { cbSize: size_of::<NOTIFYICONDATAW>() as u32, hWnd: main_hwnd(), uID: 1, ..Default::default() };
    // SAFETY: `data` is fully initialised; the shell copies what it needs.
    unsafe {
        if !want {
            if st.shown {
                let _ = Shell_NotifyIconW(NIM_DELETE, &data);
                st.shown = false;
            }
            return;
        }
        let icon = icon_for(st.config.as_ref());
        st.icon = Some(icon.0 as isize);
        data.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
        data.uCallbackMessage = WM_TRAY;
        data.hIcon = icon;
        copy_into(&mut data.szTip, &product(st.config.as_ref()));
        let op = if st.shown && !force_add { NIM_MODIFY } else { NIM_ADD };
        st.shown = Shell_NotifyIconW(op, &data).as_bool() || st.shown;
    }
}

fn balloon(text: &str) {
    let st = state();
    if !st.shown {
        return;
    }
    let mut data = NOTIFYICONDATAW { cbSize: size_of::<NOTIFYICONDATAW>() as u32, hWnd: main_hwnd(), uID: 1, uFlags: NIF_INFO, dwInfoFlags: NIIF_INFO, ..Default::default() };
    copy_into(&mut data.szInfo, text);
    copy_into(&mut data.szInfoTitle, &product(st.config.as_ref()));
    // SAFETY: as in refresh_icon.
    unsafe {
        let _ = Shell_NotifyIconW(NIM_MODIFY, &data);
    }
}

fn show_menu(hwnd: HWND) {
    let config = state().config.clone();
    let can_request = config.as_ref().is_none_or(|c| c.request_help);
    let links: Vec<_> = config.as_ref().map(|c| c.links.iter().filter(|l| super::safe_url(&l.url)).cloned().collect()).unwrap_or_default();
    // SAFETY: the menu is created, shown and destroyed here; strings outlive each call.
    let chosen = unsafe {
        let Ok(menu) = CreatePopupMenu() else { return };
        let add = |id: usize, text: &str| {
            let t = wide(text);
            let _ = AppendMenuW(menu, MF_STRING, id, PCWSTR(t.as_ptr()));
        };
        if can_request {
            add(ID_REQUEST, "Request help...");
        }
        let card = config.as_ref().map(super::contact_text).unwrap_or_default();
        if !card.is_empty() {
            add(ID_CONTACT, "Contact the help desk...");
        }
        for (i, l) in links.iter().enumerate() {
            add(ID_LINK + i, &l.label);
        }
        let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
        add(ID_HIDE, "Hide until next sign-in");
        let mut pt = POINT::default();
        let _ = GetCursorPos(&mut pt);
        // Without this the menu doesn't close when clicking elsewhere.
        let _ = SetForegroundWindow(hwnd);
        let cmd = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON, pt.x, pt.y, None, hwnd, None).0 as usize;
        let _ = DestroyMenu(menu);
        cmd
    };
    let title = product(config.as_ref());
    match chosen {
        ID_REQUEST => {
            // Captured before the form opens, so the form isn't in it.
            let shot = crate::desktop::screenshot_jpeg().ok();
            let default = config.as_ref().is_none_or(|c| c.screenshot_default);
            std::thread::spawn(move || request_flow(title, shot, default));
        }
        ID_CONTACT => {
            let card = config.as_ref().map(super::contact_text).unwrap_or_default();
            std::thread::spawn(move || message_box(&title, &card, MB_OK | MB_ICONINFORMATION));
        }
        ID_HIDE => unsafe {
            // SAFETY: our own window.
            let _ = DestroyWindow(hwnd);
        },
        n if n >= ID_LINK && n - ID_LINK < links.len() => {
            let url = wide(&links[n - ID_LINK].url);
            // SAFETY: the string outlives the call; only http(s) URLs got here.
            unsafe {
                ShellExecuteW(None, w!("open"), PCWSTR(url.as_ptr()), PCWSTR::null(), PCWSTR::null(), SW_SHOWNORMAL);
            }
        }
        _ => {}
    }
}

fn request_flow(title: String, shot: Option<Vec<u8>>, checked: bool) {
    let Some((subject, body, attach)) = request_dialog(&title, shot.is_some(), checked) else { return };
    let screenshot = if attach { shot.unwrap_or_default() } else { vec![] };
    let reply = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(anyhow::Error::from)
        .and_then(|rt| rt.block_on(async { Client::connect(false).await?.request(&subject, &body, screenshot).await }));
    match reply {
        Ok(AgentToTray::HelpResult { error: Some(e), .. }) => {
            message_box(&title, &e, MB_OK | MB_ICONERROR);
        }
        Ok(AgentToTray::HelpResult { ticket_number: Some(n), .. }) => {
            message_box(&title, &format!("Thanks. Your request is ticket #{n}."), MB_OK | MB_ICONINFORMATION);
        }
        Ok(_) => {
            message_box(
                &title,
                "This computer can't reach the help desk right now. Your request is saved and will be sent as soon as it can.",
                MB_OK | MB_ICONINFORMATION,
            );
        }
        Err(e) => {
            message_box(&title, &format!("The request couldn't be sent: {e:#}"), MB_OK | MB_ICONERROR);
        }
    }
}

const ID_SUBJECT: usize = 101;
const ID_BODY: usize = 102;
const ID_ATTACH: usize = 103;
const ID_OK: usize = 1;
const ID_CANCEL: usize = 2;

/// The open form's controls, and what was submitted.
struct Form {
    subject: isize,
    body: isize,
    attach: isize,
    submitted: Option<(String, String, bool)>,
}

thread_local! {
    static FORM: std::cell::RefCell<Form> = const { std::cell::RefCell::new(Form { subject: 0, body: 0, attach: 0, submitted: None }) };
}

fn text_of(h: isize) -> String {
    let h = HWND(h as _);
    // SAFETY: reading a control's text into a buffer of its length.
    unsafe {
        let n = GetWindowTextLengthW(h).max(0) as usize;
        let mut buf = vec![0u16; n + 1];
        let got = GetWindowTextW(h, &mut buf).max(0) as usize;
        String::from_utf16_lossy(&buf[..got])
    }
}

unsafe extern "system" fn form_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    // SAFETY: called by Windows for our form window, on the thread that created it.
    unsafe {
        match msg {
            WM_COMMAND => {
                let id = wp.0 & 0xffff;
                if id == ID_OK {
                    FORM.with(|f| {
                        let mut f = f.borrow_mut();
                        let attach = f.attach != 0 && SendMessageW(HWND(f.attach as _), BM_GETCHECK, None, None).0 == 1;
                        f.submitted = Some((text_of(f.subject), text_of(f.body), attach));
                    });
                    let _ = DestroyWindow(hwnd);
                } else if id == ID_CANCEL {
                    let _ = DestroyWindow(hwnd);
                }
                LRESULT(0)
            }
            WM_DESTROY => {
                PostQuitMessage(0);
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wp, lp),
        }
    }
}

/// The request form, on its own thread with its own message loop. `None` if cancelled.
fn request_dialog(title: &str, has_shot: bool, checked: bool) -> Option<(String, String, bool)> {
    let title_w = wide(&format!("{title}: request help"));
    // SAFETY: Win32 window creation and a message loop on this thread; every string outlives
    // the call that uses it.
    unsafe {
        let module = GetModuleHandleW(None).ok()?;
        let inst = HINSTANCE(module.0);
        let class = w!("RmmTrayForm");
        let wc = WNDCLASSW { lpfnWndProc: Some(form_proc), hInstance: inst, lpszClassName: class, hbrBackground: windows::Win32::Graphics::Gdi::HBRUSH(16 as _), ..Default::default() };
        RegisterClassW(&wc);
        let hwnd = CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_DLGMODALFRAME,
            class,
            PCWSTR(title_w.as_ptr()),
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            480,
            430,
            None,
            None,
            Some(inst),
            None,
        )
        .ok()?;
        let font = GetStockObject(DEFAULT_GUI_FONT);
        let child = |class: PCWSTR, text: &str, style: WINDOW_STYLE, ex: WINDOW_EX_STYLE, (x, y, w, h): (i32, i32, i32, i32), id: usize| -> isize {
            let t = wide(text);
            let h = CreateWindowExW(ex, class, PCWSTR(t.as_ptr()), WS_CHILD | WS_VISIBLE | style, x, y, w, h, Some(hwnd), Some(HMENU(id as _)), Some(inst), None)
                .unwrap_or_default();
            SendMessageW(h, WM_SETFONT, Some(WPARAM(font.0 as usize)), Some(LPARAM(1)));
            h.0 as isize
        };
        let none = WINDOW_EX_STYLE(0);
        let edge = WINDOW_EX_STYLE(0x200); // WS_EX_CLIENTEDGE
        child(w!("STATIC"), "Describe the problem and we'll get back to you.", WINDOW_STYLE(0), none, (16, 12, 440, 20), 0);
        child(w!("STATIC"), "Subject", WINDOW_STYLE(0), none, (16, 40, 440, 18), 0);
        let subject = child(w!("EDIT"), "", WS_TABSTOP | WS_BORDER | WINDOW_STYLE(ES_AUTOHSCROLL as u32), edge, (16, 60, 440, 24), ID_SUBJECT);
        child(w!("STATIC"), "What's happening?", WINDOW_STYLE(0), none, (16, 94, 440, 18), 0);
        let body = child(
            w!("EDIT"),
            "",
            WS_TABSTOP | WS_BORDER | WS_VSCROLL | WINDOW_STYLE((ES_MULTILINE | ES_AUTOVSCROLL | ES_WANTRETURN) as u32),
            edge,
            (16, 114, 440, 190),
            ID_BODY,
        );
        let attach = if has_shot {
            let h = child(w!("BUTTON"), "Attach a picture of my screen", WS_TABSTOP | WINDOW_STYLE(BS_AUTOCHECKBOX as u32), none, (16, 314, 440, 22), ID_ATTACH);
            SendMessageW(HWND(h as _), BM_SETCHECK, Some(WPARAM(usize::from(checked))), None);
            h
        } else {
            0
        };
        child(w!("BUTTON"), "Send", WS_TABSTOP | WINDOW_STYLE(BS_DEFPUSHBUTTON as u32), none, (264, 350, 92, 28), ID_OK);
        child(w!("BUTTON"), "Cancel", WS_TABSTOP | WINDOW_STYLE(BS_PUSHBUTTON as u32), none, (364, 350, 92, 28), ID_CANCEL);
        FORM.with(|f| *f.borrow_mut() = Form { subject, body, attach, submitted: None });
        let _ = SetForegroundWindow(hwnd);
        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).as_bool() {
            // Tab between fields, Enter and Esc for the buttons.
            if !IsDialogMessageW(hwnd, &msg).as_bool() {
                let _ = windows::Win32::UI::WindowsAndMessaging::TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        let (s, b, a) = FORM.with(|f| f.borrow_mut().submitted.take())?;
        if s.trim().is_empty() {
            message_box(title, "Give the request a subject.", MB_OK | MB_ICONERROR);
            return None;
        }
        Some((s, b, a))
    }
}

unsafe extern "system" fn main_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    // SAFETY: called by Windows for the tray's hidden window.
    unsafe {
        match msg {
            WM_TRAY => {
                let event = (lp.0 & 0xffff) as u32;
                if event == WM_RBUTTONUP || event == WM_LBUTTONUP || event == WM_CONTEXTMENU {
                    show_menu(hwnd);
                }
                LRESULT(0)
            }
            WM_CONFIG => {
                refresh_icon(false);
                LRESULT(0)
            }
            WM_NOTICE => {
                let n = state().notice.clone();
                if let Some((text, _)) = n {
                    balloon(&text);
                }
                LRESULT(0)
            }
            WM_DESTROY => {
                let data = NOTIFYICONDATAW { cbSize: size_of::<NOTIFYICONDATAW>() as u32, hWnd: hwnd, uID: 1, ..Default::default() };
                let _ = Shell_NotifyIconW(NIM_DELETE, &data);
                PostQuitMessage(0);
                LRESULT(0)
            }
            // Explorer restarted: the icon has to be added again.
            m if m != 0 && m == TASKBAR_CREATED.load(Ordering::SeqCst) => {
                state().shown = false;
                refresh_icon(true);
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wp, lp),
        }
    }
}

/// `rmm-agent tray`: the icon, until sign-out or "Hide".
pub fn gui() -> Result<()> {
    // SAFETY: window creation and the message loop on the main thread.
    unsafe {
        let module = GetModuleHandleW(None)?;
        let inst = HINSTANCE(module.0);
        let class = w!("RmmTray");
        let wc = WNDCLASSW { lpfnWndProc: Some(main_proc), hInstance: inst, lpszClassName: class, ..Default::default() };
        RegisterClassW(&wc);
        TASKBAR_CREATED.store(RegisterWindowMessageW(w!("TaskbarCreated")), Ordering::SeqCst);
        let hwnd = CreateWindowExW(WINDOW_EX_STYLE(0), class, w!("RMM tray"), WS_OVERLAPPED, 0, 0, 0, 0, None, None, Some(inst), None)?;
        MAIN.store(hwnd.0 as isize, Ordering::SeqCst);
        refresh_icon(true);
        std::thread::Builder::new().name("tray-link".into()).spawn(|| {
            match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                Ok(rt) => rt.block_on(super::run_link(Arc::new(WinUi))),
                Err(e) => warn!("tray link runtime: {e}"),
            }
        })?;
        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).as_bool() {
            let _ = windows::Win32::UI::WindowsAndMessaging::TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(account("ACME", "jsmith"), "ACME\\jsmith");
        assert_eq!(account("", "jsmith"), "jsmith");
        assert_eq!(run_command(std::path::Path::new(r"C:\Program Files\RMM\rmm-agent.exe")), r#""C:\Program Files\RMM\rmm-agent.exe" tray"#);
        let mut tip = [1u16; 4];
        copy_into(&mut tip, "abcdef");
        assert_eq!(tip, [97, 98, 99, 0]);
    }
}
