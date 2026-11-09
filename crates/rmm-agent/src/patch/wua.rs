//! Windows: the Windows Update Agent COM API (`IUpdateSession`), which is what Settings >
//! Windows Update uses. PSWindowsUpdate is the fallback when the API can't be reached
//! (it wraps the same API, so this mostly helps when COM activation is blocked by policy
//! but the module was installed and allowed).
//!
//! The ids are Windows Update ids (`IUpdateIdentity::UpdateID`, a GUID). Scans search for
//! `IsInstalled=0 and IsHidden=0`: software updates and drivers. Categories come from the
//! update classification, severity from the MSRC rating.
//!
//! Every call here blocks (searches can take minutes), so it runs on a blocking thread with
//! its own COM apartment.

use anyhow::{Context, Result, anyhow, bail};
use rmm_proto::patch::{Category, PatchItemResult, PatchStage, PatchUpdate, Severity};
use windows::Win32::Foundation::{DECIMAL, VARIANT_BOOL};
use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize};
use windows::Win32::System::UpdateAgent::{
    ISystemInformation, IUpdate, IUpdateCollection, IUpdateSession, SystemInformation, UpdateCollection, UpdateSession, orcSucceeded,
    orcSucceededWithErrors,
};
use windows::core::BSTR;

use super::cmd::{self, Log, Opts};
use super::winparse::{category, parse_ps};
use super::{Installed, PatchProvider, Progress};

const CRITERIA: &str = "IsInstalled=0 and IsHidden=0";

/// The WUA provider, or PSWindowsUpdate if the API can't be used and the module is there.
pub fn provider() -> Box<dyn PatchProvider> {
    // Probe on a plain thread: COM initialisation is per thread, and this one is throwaway.
    let probe = std::thread::spawn(|| Com::init().and_then(|_com| session().map(|_| ()))).join();
    match probe {
        Ok(Ok(())) => Box::new(Wua),
        Ok(Err(e)) if PsWindowsUpdate::available() => {
            tracing::warn!("Windows Update Agent API unavailable ({e:#}); using PSWindowsUpdate");
            Box::new(PsWindowsUpdate)
        }
        // Keep WUA: its scans report the error, which is more useful than "unsupported".
        _ => Box::new(Wua),
    }
}

/// COM initialised on this thread for as long as it lives.
struct Com;

impl Com {
    fn init() -> Result<Com> {
        // SAFETY: plain call; S_FALSE (already initialised) is success too.
        unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.ok().context("CoInitializeEx")?;
        Ok(Com)
    }
}

impl Drop for Com {
    fn drop(&mut self) {
        // SAFETY: balances the successful CoInitializeEx above.
        unsafe { CoUninitialize() };
    }
}

fn session() -> Result<IUpdateSession> {
    // SAFETY: COM is initialised by the caller; the CLSID is the documented UpdateSession.
    let s: IUpdateSession = unsafe { CoCreateInstance(&UpdateSession, None, CLSCTX_INPROC_SERVER) }.context("creating IUpdateSession")?;
    unsafe { s.SetClientApplicationID(&BSTR::from("RMM agent")) }?;
    Ok(s)
}

fn yes(b: VARIANT_BOOL) -> bool {
    b.0 != 0
}

fn hresult(h: i32) -> String {
    format!("0x{:08X}", h as u32)
}

/// Bytes, from the DECIMAL the API uses for sizes.
fn decimal_bytes(d: &DECIMAL) -> Option<u64> {
    // SAFETY: DECIMAL's unions are plain integers; any bit pattern is valid.
    let (lo, scale, sign) = unsafe { (d.Anonymous2.Lo64, d.Anonymous1.Anonymous.scale, d.Anonymous1.Anonymous.sign) };
    (d.Hi32 == 0 && scale == 0 && sign == 0 && lo > 0).then_some(lo)
}

/// Reads one update. Fields that fail to read are left empty rather than failing the scan.
fn describe(u: &IUpdate) -> Result<PatchUpdate> {
    // SAFETY: (this whole function) COM calls on a live interface; errors are Results.
    let id = unsafe { u.Identity()?.UpdateID()? }.to_string();
    let title = unsafe { u.Title() }.map(|t| t.to_string()).unwrap_or_default();
    let kb = unsafe { u.KBArticleIDs() }.ok().and_then(|c| unsafe { c.get_Item(0) }.ok()).map(|k| {
        let k = k.to_string();
        if k.to_ascii_uppercase().starts_with("KB") { k } else { format!("KB{k}") }
    });
    let severity = unsafe { u.MsrcSeverity() }.ok().and_then(|s| Severity::from_vendor(&s.to_string()));
    let size = unsafe { u.MaxDownloadSize() }.ok().as_ref().and_then(decimal_bytes);
    let requires_reboot = unsafe { u.InstallationBehavior().and_then(|b| b.RebootBehavior()) }
        .is_ok_and(|r| r != windows::Win32::System::UpdateAgent::irbNeverReboots);
    let mut cat = None;
    if let Ok(cats) = unsafe { u.Categories() } {
        for i in 0..unsafe { cats.Count() }.unwrap_or(0) {
            let Ok(c) = (unsafe { cats.get_Item(i) }) else { continue };
            let kind = unsafe { c.Type() }.map(|t| t.to_string()).unwrap_or_default();
            if kind != "UpdateClassification" {
                continue;
            }
            let cid = unsafe { c.CategoryID() }.map(|t| t.to_string()).unwrap_or_default();
            let name = unsafe { c.Name() }.map(|t| t.to_string()).unwrap_or_default();
            cat = category(&cid, &name);
            break;
        }
    }
    let is_driver = unsafe { u.Type() }.is_ok_and(|t| t == windows::Win32::System::UpdateAgent::utDriver);
    let category = cat.unwrap_or(if is_driver { Category::Driver } else { Category::Update });
    // MSRC rates security updates only; a security update without a rating is still security.
    Ok(PatchUpdate { id, title, kb, severity, category, size, requires_reboot, version: None, current_version: None })
}

fn search(s: &IUpdateSession) -> Result<IUpdateCollection> {
    // SAFETY: COM calls on live interfaces.
    unsafe {
        let searcher = s.CreateUpdateSearcher()?;
        let result = searcher.Search(&BSTR::from(CRITERIA)).context("searching Windows Update")?;
        let code = result.ResultCode()?;
        if code != orcSucceeded && code != orcSucceededWithErrors {
            bail!("Windows Update search failed (result code {})", code.0);
        }
        Ok(result.Updates()?)
    }
}

pub struct Wua;

impl PatchProvider for Wua {
    fn name(&self) -> &'static str {
        "wua"
    }

    fn scan(&self, _log: &Log, progress: Progress, _refresh: bool) -> Result<Vec<PatchUpdate>> {
        let _com = Com::init()?;
        progress(PatchStage::Refreshing, Some("searching Windows Update".into()), None);
        let s = session()?;
        let updates = search(&s)?;
        let n = unsafe { updates.Count() }?;
        let mut out = Vec::with_capacity(n as usize);
        for i in 0..n {
            let u = unsafe { updates.get_Item(i) }?;
            match describe(&u) {
                Ok(p) => out.push(p),
                Err(e) => tracing::warn!("skipping an update that can't be read: {e:#}"),
            }
        }
        Ok(out)
    }

    fn install(&self, ids: &[String], log: &Log, progress: Progress) -> Result<Installed> {
        let _com = Com::init()?;
        progress(PatchStage::Refreshing, Some("searching Windows Update".into()), None);
        let s = session()?;
        let found = search(&s)?;
        // SAFETY: (below) COM calls on live interfaces created here.
        let chosen: IUpdateCollection = unsafe { CoCreateInstance(&UpdateCollection, None, CLSCTX_INPROC_SERVER) }?;
        let mut order: Vec<String> = Vec::new();
        for i in 0..unsafe { found.Count() }? {
            let u = unsafe { found.get_Item(i) }?;
            let id = unsafe { u.Identity()?.UpdateID()? }.to_string();
            if !ids.iter().any(|x| x.eq_ignore_ascii_case(&id)) {
                continue;
            }
            if !yes(unsafe { u.EulaAccepted() }.unwrap_or_default()) {
                unsafe { u.AcceptEula() }.with_context(|| format!("accepting the licence for {id}"))?;
            }
            unsafe { chosen.Add(&u) }?;
            order.push(id);
        }
        let mut results: Vec<PatchItemResult> = ids
            .iter()
            .filter(|id| !order.iter().any(|o| o.eq_ignore_ascii_case(id)))
            .map(|id| PatchItemResult { id: id.clone(), ok: true, message: Some("no longer offered (already installed or superseded)".into()) })
            .collect();
        if order.is_empty() {
            return Ok(Installed { results, reboot_required: reboot_pending() });
        }
        log.push(&format!("installing {} updates through the Windows Update Agent\n", order.len()));

        let installer = unsafe { s.CreateUpdateInstaller() }?;
        if yes(unsafe { installer.RebootRequiredBeforeInstallation() }.unwrap_or_default()) {
            log.push("Windows needs to restart before these updates can install\n");
            results.extend(order.iter().map(|id| PatchItemResult {
                id: id.clone(),
                ok: false,
                message: Some("Windows must restart before this update can install".into()),
            }));
            return Ok(Installed { results, reboot_required: true });
        }

        progress(PatchStage::Downloading, Some(format!("downloading {} updates", order.len())), Some(5));
        let downloader = unsafe { s.CreateUpdateDownloader() }?;
        unsafe { downloader.SetUpdates(&chosen) }?;
        let download = unsafe { downloader.Download() }.context("downloading updates")?;
        let mut download_errors = std::collections::HashMap::new();
        for (i, id) in order.iter().enumerate() {
            if let Ok(r) = unsafe { download.GetUpdateResult(i as i32) } {
                let code = unsafe { r.ResultCode() }.unwrap_or_default();
                if code != orcSucceeded && code != orcSucceededWithErrors {
                    let h = unsafe { r.HResult() }.unwrap_or_default();
                    log.push(&format!("download of {id} failed: {}\n", hresult(h)));
                    download_errors.insert(id.clone(), format!("download failed ({})", hresult(h)));
                }
            }
        }

        progress(PatchStage::Installing, Some(format!("installing {} updates", order.len())), Some(50));
        unsafe { installer.SetUpdates(&chosen) }?;
        let result = unsafe { installer.Install() }.context("installing updates")?;
        let reboot_required = yes(unsafe { result.RebootRequired() }.unwrap_or_default());
        for (i, id) in order.iter().enumerate() {
            let r = unsafe { result.GetUpdateResult(i as i32) };
            let (ok, message) = match r {
                Ok(r) => {
                    let code = unsafe { r.ResultCode() }.unwrap_or_default();
                    let ok = code == orcSucceeded || code == orcSucceededWithErrors;
                    let h = unsafe { r.HResult() }.unwrap_or_default();
                    let msg = if ok {
                        yes(unsafe { r.RebootRequired() }.unwrap_or_default()).then(|| "installed; restart required".to_string())
                    } else {
                        Some(download_errors.get(id).cloned().unwrap_or_else(|| format!("install failed ({})", hresult(h))))
                    };
                    (ok, msg)
                }
                Err(e) => (false, Some(format!("no result: {e}"))),
            };
            log.push(&format!("{id}: {}\n", if ok { "installed" } else { message.as_deref().unwrap_or("failed") }));
            results.push(PatchItemResult { id: id.clone(), ok, message });
        }
        Ok(Installed { results, reboot_required: reboot_required || reboot_pending() })
    }

    fn reboot_pending(&self) -> bool {
        reboot_pending()
    }
}

/// Windows Update (or a servicing stack) is waiting for a restart.
fn reboot_pending() -> bool {
    let from_com = Com::init().ok().and_then(|_com| {
        // SAFETY: documented SystemInformation CLSID; COM initialised just above.
        let info: ISystemInformation = unsafe { CoCreateInstance(&SystemInformation, None, CLSCTX_INPROC_SERVER) }.ok()?;
        unsafe { info.RebootRequired() }.ok().map(yes)
    });
    from_com.unwrap_or(false) || registry_reboot_pending()
}

fn registry_reboot_pending() -> bool {
    use winreg::RegKey;
    use winreg::enums::HKEY_LOCAL_MACHINE;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
    ]
    .iter()
    .any(|k| hklm.open_subkey(k).is_ok())
}

/// The PSWindowsUpdate module, driven through PowerShell.
pub struct PsWindowsUpdate;

impl PsWindowsUpdate {
    fn available() -> bool {
        let log = Log::default();
        cmd::output(&log, "powershell.exe", &["-NoProfile", "-NonInteractive", "-Command", "if (Get-Module -ListAvailable PSWindowsUpdate) { exit 0 } else { exit 1 }"], Opts { log: false, ..Default::default() })
            .is_ok_and(|o| o.success())
    }

    fn ps(log: &Log, script: &str, timeout: std::time::Duration) -> Result<cmd::Output> {
        let full = format!("$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'; Import-Module PSWindowsUpdate; {script}");
        let out = cmd::output(log, "powershell.exe", &["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", &full], Opts { timeout, ..Default::default() })?;
        if !out.success() {
            bail!("PSWindowsUpdate failed: {}", out.reason());
        }
        Ok(out)
    }
}

impl PatchProvider for PsWindowsUpdate {
    fn name(&self) -> &'static str {
        "pswindowsupdate"
    }

    fn scan(&self, log: &Log, progress: Progress, _refresh: bool) -> Result<Vec<PatchUpdate>> {
        progress(PatchStage::Refreshing, Some("Get-WindowsUpdate".into()), None);
        let out = Self::ps(
            log,
            "@(Get-WindowsUpdate | ForEach-Object { [pscustomobject]@{ Id = $_.Identity.UpdateID; Title = $_.Title; KB = $_.KB; \
             MsrcSeverity = $_.MsrcSeverity; Size = [uint64]$_.MaxDownloadSize; Reboot = ($_.InstallationBehavior.RebootBehavior -ne 0); \
             Categories = (($_.Categories | ForEach-Object { $_.Name }) -join ';') } }) | ConvertTo-Json -Compress -Depth 3",
            std::time::Duration::from_secs(1800),
        )?;
        parse_ps(&out.stdout)
    }

    fn install(&self, ids: &[String], log: &Log, progress: Progress) -> Result<Installed> {
        progress(PatchStage::Installing, Some(format!("Install-WindowsUpdate ({} updates)", ids.len())), None);
        for id in ids {
            if !id.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
                return Err(anyhow!("not a Windows Update id: {id}"));
            }
        }
        let list = ids.iter().map(|i| format!("'{i}'")).collect::<Vec<_>>().join(",");
        Self::ps(log, &format!("Get-WindowsUpdate -UpdateID {list} -Install -AcceptAll -IgnoreReboot -Confirm:$false | Out-String -Width 200"), std::time::Duration::from_secs(4 * 3600))?;
        Ok(Installed { results: vec![], reboot_required: reboot_pending() })
    }

    fn reboot_pending(&self) -> bool {
        reboot_pending()
    }
}
