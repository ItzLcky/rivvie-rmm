//! Windows: BitLocker through CIM (`Win32_EncryptableVolume` in
//! `root/CIMV2/Security/MicrosoftVolumeEncryption`), which works without the BitLocker
//! PowerShell module, and the TPM from `Win32_Tpm`. If CIM fails for another reason than the
//! class being absent, `manage-bde -status` is parsed instead (no protector ids then, so no
//! escrow). A Windows without BitLocker (Server without the feature, Home) reports its fixed
//! drives as unencrypted, not an error.
//!
//! Recovery passwords are read one at a time (`GetKeyProtectorNumericalPassword`) when the
//! server asks; added and rotated with `ProtectKeyWithNumericalPassword` (Windows makes the
//! password) and `DeleteKeyProtector`. Scripts get only a drive letter and a protector id, both
//! checked here first; a key only ever travels on stdout.

use rmm_proto::diskenc::{Kind, Report, Role, Status, Tpm, Volume};
use serde::{Deserialize, Deserializer};

/// Prints one JSON object; each part fails on its own.
#[cfg_attr(not(windows), allow(dead_code))]
pub const STATUS_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$out = @{ system = "$env:SystemDrive"; fixed = @(); volumes = @(); error = $null; missing = $false; tpm = $null; tpm_error = $null }
try { $out.fixed = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { "$($_.DeviceID)" }) } catch {}
try {
  $vols = @(Get-CimInstance -Namespace root/CIMV2/Security/MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume)
  $out.volumes = @($vols | Where-Object { $_.DriveLetter -and $_.VolumeType -ne 2 } | ForEach-Object {
    $v = $_
    $c = Invoke-CimMethod -InputObject $v -MethodName GetConversionStatus
    $m = Invoke-CimMethod -InputObject $v -MethodName GetEncryptionMethod
    $l = Invoke-CimMethod -InputObject $v -MethodName GetLockStatus
    $ids = (Invoke-CimMethod -InputObject $v -MethodName GetKeyProtectors -Arguments @{ KeyProtectorType = [uint32]0 }).VolumeKeyProtectorID
    $prot = @($ids | Where-Object { $_ } | ForEach-Object {
      $t = Invoke-CimMethod -InputObject $v -MethodName GetKeyProtectorType -Arguments @{ VolumeKeyProtectorID = "$_" }
      @{ id = "$_"; type = [int]$t.KeyProtectorType }
    })
    @{ drive = "$($v.DriveLetter)"; device = "$($v.DeviceID)"; volume_type = [int]$v.VolumeType
       protection = [int]$v.ProtectionStatus; conversion = [int]$c.ConversionStatus; percent = [double]$c.EncryptionPercentage
       method = [int]$m.EncryptionMethod; lock = [int]$l.LockStatus; protectors = $prot }
  })
} catch {
  if ("$($_.Exception.Message)" -match 'Invalid (class|namespace)|not found') { $out.missing = $true } else { $out.error = "$($_.Exception.Message)" }
}
try {
  $t = Get-CimInstance -Namespace root/CIMV2/Security/MicrosoftTpm -ClassName Win32_Tpm
  if ($t) {
    $out.tpm = @{ enabled = $t.IsEnabled_InitialValue; activated = $t.IsActivated_InitialValue; spec = "$($t.SpecVersion)"; maker = "$($t.ManufacturerIdTxt)"
                  ready = $(try { [bool](Invoke-CimMethod -InputObject $t -MethodName IsReady).IsReady } catch { $null }) }
  }
} catch { $out.tpm_error = "$($_.Exception.Message)" }
$out | ConvertTo-Json -Depth 6 -Compress
"#;

/// `C:`, upper case.
pub fn valid_drive(d: &str) -> bool {
    let b = d.as_bytes();
    b.len() == 2 && b[0].is_ascii_uppercase() && b[1] == b':'
}

/// `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`.
pub fn valid_protector(id: &str) -> bool {
    let Some(inner) = id.strip_prefix('{').and_then(|s| s.strip_suffix('}')) else { return false };
    inner.len() == 36 && inner.chars().enumerate().all(|(i, c)| if [8, 13, 18, 23].contains(&i) { c == '-' } else { c.is_ascii_hexdigit() })
}

fn volume_lookup(drive: &str) -> String {
    format!(
        "$ErrorActionPreference = 'Stop'
$v = Get-CimInstance -Namespace root/CIMV2/Security/MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume -Filter \"DriveLetter='{drive}'\"
if (-not $v) {{ throw 'BitLocker does not know volume {drive}' }}
function Check($r, $what) {{ if ($r.ReturnValue -ne 0) {{ throw (\"$what failed: 0x{{0:X8}}\" -f $r.ReturnValue) }} }}
"
    )
}

/// Prints the recovery password of one protector.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn key_script(drive: &str, protector: &str) -> Option<String> {
    (valid_drive(drive) && valid_protector(protector)).then(|| {
        format!(
            "{}$r = Invoke-CimMethod -InputObject $v -MethodName GetKeyProtectorNumericalPassword -Arguments @{{ VolumeKeyProtectorID = '{protector}' }}
Check $r 'GetKeyProtectorNumericalPassword'
$r.NumericalPassword",
            volume_lookup(drive)
        )
    })
}

/// Adds a recovery password; with `replace`, then removes the volume's other recovery passwords.
/// Prints the new protector's id.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn protector_script(drive: &str, replace: bool) -> Option<String> {
    valid_drive(drive).then(|| {
        let mut s = volume_lookup(drive);
        s.push_str(
            "$old = @((Invoke-CimMethod -InputObject $v -MethodName GetKeyProtectors -Arguments @{ KeyProtectorType = [uint32]3 }).VolumeKeyProtectorID | Where-Object { $_ })\n",
        );
        if !replace {
            s.push_str("if ($old.Count -gt 0) { throw 'the volume already has a recovery password' }\n");
        }
        s.push_str(
            "$r = Invoke-CimMethod -InputObject $v -MethodName ProtectKeyWithNumericalPassword -Arguments @{ FriendlyName = 'RMM recovery password' }
Check $r 'ProtectKeyWithNumericalPassword (Group Policy may forbid recovery passwords)'
",
        );
        if replace {
            s.push_str(
                "foreach ($o in $old) { $d = Invoke-CimMethod -InputObject $v -MethodName DeleteKeyProtector -Arguments @{ VolumeKeyProtectorID = \"$o\" }; Check $d 'DeleteKeyProtector' }\n",
            );
        }
        s.push_str("$r.VolumeKeyProtectorID");
        s
    })
}

fn many<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Vec<T>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany<T> {
        Many(Vec<T>),
        One(T),
    }
    Ok(match Option::<OneOrMany<T>>::deserialize(d)? {
        None => vec![],
        Some(OneOrMany::Many(v)) => v,
        Some(OneOrMany::One(v)) => vec![v],
    })
}

#[derive(Deserialize)]
struct Raw {
    #[serde(default)]
    system: Option<String>,
    #[serde(default, deserialize_with = "many")]
    fixed: Vec<String>,
    #[serde(default, deserialize_with = "many")]
    volumes: Vec<RawVolume>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    missing: bool,
    #[serde(default)]
    tpm: Option<RawTpm>,
}

#[derive(Deserialize)]
struct RawVolume {
    drive: String,
    #[serde(default)]
    device: String,
    #[serde(default)]
    volume_type: i64,
    #[serde(default)]
    protection: i64,
    #[serde(default)]
    conversion: i64,
    #[serde(default)]
    percent: f64,
    #[serde(default)]
    method: i64,
    #[serde(default)]
    lock: i64,
    #[serde(default, deserialize_with = "many")]
    protectors: Vec<RawProtector>,
}

#[derive(Deserialize)]
struct RawProtector {
    id: String,
    #[serde(rename = "type")]
    ty: i64,
}

#[derive(Deserialize)]
struct RawTpm {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    activated: Option<bool>,
    #[serde(default)]
    ready: Option<bool>,
    #[serde(default)]
    spec: Option<String>,
    #[serde(default)]
    maker: Option<String>,
}

fn protector_kind(t: i64) -> &'static str {
    match t {
        1 => "tpm",
        2 => "external_key",
        3 => "recovery_password",
        4 => "tpm_pin",
        5 => "tpm_startup_key",
        6 => "tpm_pin_startup_key",
        7 => "public_key",
        8 => "passphrase",
        9 => "tpm_certificate",
        10 => "sid",
        _ => "unknown",
    }
}

fn method(m: i64) -> Option<&'static str> {
    Some(match m {
        1 => "AES-128 (diffuser)",
        2 => "AES-256 (diffuser)",
        3 => "AES-128",
        4 => "AES-256",
        5 => "Hardware",
        6 => "XTS-AES-128",
        7 => "XTS-AES-256",
        _ => return None,
    })
}

fn status(conversion: i64, protection: i64) -> Status {
    match conversion {
        0 => Status::Unencrypted,
        1 if protection == 1 => Status::Encrypted,
        1 => Status::Suspended,
        2 | 4 => Status::Encrypting,
        3 | 5 => Status::Decrypting,
        _ => Status::Unknown,
    }
}

fn unencrypted(drive: &str, system: &str) -> Volume {
    Volume {
        volume_id: drive.to_string(),
        mount: format!("{drive}\\"),
        role: if drive.eq_ignore_ascii_case(system) { Role::Os } else { Role::Data },
        status: Status::Unencrypted,
        percent: Some(0.0),
        ..Default::default()
    }
}

fn sort(v: &mut [Volume]) {
    v.sort_by(|a, b| (a.role != Role::Os, &a.volume_id).cmp(&(b.role != Role::Os, &b.volume_id)));
}

/// The status script's output. `Err` when CIM failed in a way `manage-bde` may get around.
pub fn parse(out: &str) -> anyhow::Result<Report> {
    let raw: Raw = serde_json::from_str(out.trim_start_matches('\u{feff}').trim())?;
    let system = raw.system.unwrap_or_else(|| "C:".into());
    let tpm = raw.tpm.map(|t| Tpm {
        present: true,
        ready: t.ready,
        enabled: t.enabled,
        activated: t.activated,
        // "2.0, 0, 1.38": the first is the version.
        version: t.spec.as_deref().and_then(|s| s.split(',').next()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
        manufacturer: t.maker.filter(|s| !s.trim().is_empty()),
    });
    if let Some(e) = raw.error.filter(|e| !e.trim().is_empty()) {
        anyhow::bail!("{e}");
    }
    if raw.missing {
        let mut volumes: Vec<Volume> = raw.fixed.iter().filter(|d| valid_drive(d)).map(|d| unencrypted(d, &system)).collect();
        sort(&mut volumes);
        return Ok(Report { volumes, tpm, error: None });
    }
    let mut volumes: Vec<Volume> = raw
        .volumes
        .into_iter()
        // Removable drives Windows calls fixed (USB disks) aren't in the fixed list.
        .filter(|v| raw.fixed.is_empty() || raw.fixed.iter().any(|f| f.eq_ignore_ascii_case(&v.drive)))
        .map(|v| {
            let st = status(v.conversion, v.protection);
            let encrypted = st != Status::Unencrypted;
            Volume {
                volume_id: v.drive.to_ascii_uppercase(),
                mount: format!("{}\\", v.drive.to_ascii_uppercase()),
                device: v.device,
                kind: if encrypted { Kind::Bitlocker } else { Kind::None },
                role: if v.volume_type == 0 { Role::Os } else { Role::Data },
                status: st,
                percent: Some(v.percent as f32),
                method: method(v.method).map(String::from),
                protectors: v.protectors.iter().map(|p| protector_kind(p.ty).to_string()).collect(),
                protection_on: v.protection == 1,
                locked: v.lock == 1,
                recovery_protector_id: v.protectors.iter().find(|p| p.ty == 3).map(|p| p.id.clone()),
            }
        })
        .collect();
    // Fixed drives BitLocker didn't list (rare: unsupported file systems) are unencrypted.
    for d in raw.fixed.iter().filter(|d| valid_drive(d)) {
        if !volumes.iter().any(|v| v.volume_id.eq_ignore_ascii_case(d)) {
            volumes.push(unencrypted(d, &system));
        }
    }
    sort(&mut volumes);
    Ok(Report { volumes, tpm, error: None })
}

/// `manage-bde -status` (English output; other languages give an empty list).
pub fn parse_manage_bde(out: &str) -> Vec<Volume> {
    let mut vols: Vec<Volume> = Vec::new();
    let mut in_protectors = false;
    for line in out.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("Volume ") {
            let drive = rest.split_whitespace().next().unwrap_or("").to_ascii_uppercase();
            if valid_drive(&drive) {
                vols.push(Volume {
                    volume_id: drive.clone(),
                    mount: format!("{drive}\\"),
                    role: if rest.contains("[OS]") { Role::Os } else { Role::Data },
                    ..Default::default()
                });
            }
            in_protectors = false;
            continue;
        }
        let Some(v) = vols.last_mut() else { continue };
        let (key, value) = match t.split_once(':') {
            Some((k, val)) => (k.trim(), val.trim()),
            None => ("", t),
        };
        match key {
            "Conversion Status" => {
                v.status = match value {
                    "Fully Encrypted" | "Used Space Only Encrypted" => Status::Encrypted,
                    "Fully Decrypted" => Status::Unencrypted,
                    s if s.starts_with("Encryption") => Status::Encrypting,
                    s if s.starts_with("Decryption") => Status::Decrypting,
                    _ => Status::Unknown,
                };
            }
            "Percentage Encrypted" => v.percent = value.trim_end_matches('%').trim().parse().ok(),
            "Encryption Method" => v.method = (value != "None").then(|| value.replace("XTS-AES ", "XTS-AES-").replace("AES ", "AES-")),
            "Protection Status" => v.protection_on = value.contains("On"),
            "Lock Status" => v.locked = value == "Locked",
            "Key Protectors" => {
                in_protectors = value.is_empty();
            }
            "" if in_protectors && !value.is_empty() => {
                let kind = match value {
                    "TPM" => "tpm",
                    "Numerical Password" => "recovery_password",
                    "TPM And PIN" => "tpm_pin",
                    "TPM And Startup Key" => "tpm_startup_key",
                    "External Key" | "External Key (Required for automatic unlock)" => "external_key",
                    "Password" => "passphrase",
                    _ => "unknown",
                };
                v.protectors.push(kind.into());
            }
            _ => in_protectors = false,
        }
    }
    for v in &mut vols {
        if v.status == Status::Encrypted && !v.protection_on {
            v.status = Status::Suspended;
        }
        v.kind = if v.status == Status::Unencrypted { Kind::None } else { Kind::Bitlocker };
    }
    sort(&mut vols);
    vols
}

#[cfg(windows)]
pub struct Bitlocker;

#[cfg(windows)]
fn powershell(script: &str) -> anyhow::Result<String> {
    use crate::patch::cmd::{self, Log, Opts};
    let out = cmd::output(
        &Log::default(),
        "powershell.exe",
        &["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
        Opts { timeout: std::time::Duration::from_secs(120), log: false, ..Default::default() },
    )?;
    if !out.success() {
        anyhow::bail!("{}", out.reason());
    }
    Ok(out.stdout)
}

#[cfg(windows)]
impl super::Provider for Bitlocker {
    fn report(&self) -> Report {
        let cim = powershell(STATUS_SCRIPT).and_then(|o| parse(&o));
        match cim {
            Ok(r) => r,
            Err(e) => {
                use crate::patch::cmd::{self, Log, Opts};
                let bde = cmd::output(&Log::default(), "manage-bde.exe", &["-status"], Opts { timeout: std::time::Duration::from_secs(60), log: false, ..Default::default() });
                match bde {
                    Ok(o) if o.success() && !parse_manage_bde(&o.stdout).is_empty() => {
                        Report { volumes: parse_manage_bde(&o.stdout), tpm: None, error: Some(format!("BitLocker's CIM classes failed ({e:#}); read manage-bde instead, without recovery key escrow")) }
                    }
                    _ => Report { error: Some(format!("{e:#}")), ..Default::default() },
                }
            }
        }
    }

    fn recovery_key(&self, volume_id: &str, protector_id: &str) -> anyhow::Result<String> {
        let script = key_script(volume_id, protector_id).ok_or_else(|| anyhow::anyhow!("not a drive letter and a key protector id"))?;
        let key = powershell(&script)?.trim().to_string();
        // 48 digits in eight groups of six.
        let digits = key.chars().filter(char::is_ascii_digit).count();
        if digits != 48 || key.len() != 55 {
            anyhow::bail!("BitLocker returned something that isn't a recovery password");
        }
        Ok(key)
    }

    fn protector(&self, volume_id: &str, op: rmm_proto::diskenc::ProtectorOp) -> anyhow::Result<String> {
        use rmm_proto::diskenc::ProtectorOp;
        let replace = op == ProtectorOp::RotateRecovery;
        let script = protector_script(volume_id, replace).ok_or_else(|| anyhow::anyhow!("not a drive letter"))?;
        let id = powershell(&script)?.trim().to_string();
        Ok(if replace { format!("Replaced the recovery password of {volume_id} (new protector {id})") } else { format!("Added a recovery password to {volume_id} ({id})") })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cim_report() {
        let r = parse(include_str!("fixtures/bitlocker-cim.json")).unwrap();
        let ids: Vec<&str> = r.volumes.iter().map(|v| v.volume_id.as_str()).collect();
        assert_eq!(ids, ["C:", "D:", "E:"], "the USB disk F: isn't fixed");
        let c = &r.volumes[0];
        assert_eq!((c.kind, c.role, c.status, c.protection_on), (Kind::Bitlocker, Role::Os, Status::Encrypted, true));
        assert_eq!(c.protectors, ["tpm", "recovery_password"]);
        assert_eq!(c.recovery_protector_id.as_deref(), Some("{6C2F8A31-1D3B-4E5A-9F0C-7B8D9E0A1B2C}"));
        assert_eq!(c.method.as_deref(), Some("XTS-AES-128"));
        let d = &r.volumes[1];
        assert_eq!((d.status, d.recovery_protector_id.as_deref()), (Status::Suspended, None), "encrypted with protection off");
        let e = &r.volumes[2];
        assert_eq!((e.kind, e.status, e.percent), (Kind::None, Status::Unencrypted, Some(0.0)));
        let t = r.tpm.unwrap();
        assert_eq!((t.version.as_deref(), t.ready), (Some("2.0"), Some(true)));
    }

    #[test]
    fn windows_without_bitlocker() {
        let r = parse(include_str!("fixtures/bitlocker-missing.json")).unwrap();
        assert!(r.error.is_none(), "not an error");
        let ids: Vec<(&str, Role, Status)> = r.volumes.iter().map(|v| (v.volume_id.as_str(), v.role, v.status)).collect();
        assert_eq!(ids, [("C:", Role::Os, Status::Unencrypted), ("D:", Role::Data, Status::Unencrypted)]);
        assert!(parse(r#"{"error":"Access denied","volumes":[]}"#).is_err(), "a real failure falls back to manage-bde");
    }

    #[test]
    fn manage_bde() {
        let v = parse_manage_bde(include_str!("fixtures/manage-bde-status.txt"));
        assert_eq!(v.len(), 2);
        assert_eq!((v[0].volume_id.as_str(), v[0].role, v[0].status, v[0].kind), ("C:", Role::Os, Status::Encrypted, Kind::Bitlocker));
        assert_eq!(v[0].protectors, ["tpm", "recovery_password"]);
        assert_eq!((v[0].method.as_deref(), v[0].percent), (Some("XTS-AES-128"), Some(100.0)));
        assert_eq!((v[1].volume_id.as_str(), v[1].status, v[1].kind), ("D:", Status::Unencrypted, Kind::None));
        assert!(v[1].protectors.is_empty());
    }

    #[test]
    fn scripts_take_only_checked_values() {
        assert!(key_script("C:", "{6C2F8A31-1D3B-4E5A-9F0C-7B8D9E0A1B2C}").unwrap().contains("DriveLetter='C:'"));
        assert!(key_script("C:'; rm", "{6C2F8A31-1D3B-4E5A-9F0C-7B8D9E0A1B2C}").is_none());
        assert!(key_script("C:", "{6C2F8A31-1D3B-4E5A-9F0C-7B8D9E0A1B2'}").is_none());
        assert!(key_script("c:", "{6C2F8A31-1D3B-4E5A-9F0C-7B8D9E0A1B2C}").is_none());
        let add = protector_script("D:", false).unwrap();
        assert!(add.contains("already has a recovery password") && !add.contains("DeleteKeyProtector"));
        assert!(protector_script("D:", true).unwrap().contains("DeleteKeyProtector"));
    }
}
