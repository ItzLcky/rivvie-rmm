//! Windows: Microsoft Defender through its PowerShell module (`Get-MpComputerStatus`,
//! `Get-MpThreatDetection`, `Start-MpScan`, `Update-MpSignature`), plus any other antivirus
//! registered with Windows Security Center (`root/SecurityCenter2`, workstations only).

use chrono::{DateTime, Utc};
use rmm_proto::security::{Action, Detection, Product, ProductKind, Report, ThreatSeverity, ThreatStatus, MAX_DETECTIONS};
use serde::{Deserialize, Deserializer};

/// Prints one JSON object. Dates are converted to ISO 8601 UTC here, because Windows
/// PowerShell 5.1 serialises them as `\/Date(...)\/`. Each part fails on its own.
#[cfg_attr(not(windows), allow(dead_code))]
pub const STATUS_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
function D($d) { if ($d -and $d.Year -gt 1601) { $d.ToUniversalTime().ToString('o') } else { $null } }
$out = @{ defender = $null; defender_error = $null; av = @(); threats = @() }
try {
  $s = Get-MpComputerStatus
  $out.defender = @{
    mode = "$($s.AMRunningMode)"; product_version = "$($s.AMProductVersion)"; engine_version = "$($s.AMEngineVersion)"
    antivirus = [bool]$s.AntivirusEnabled; realtime = [bool]$s.RealTimeProtectionEnabled; tamper = $s.IsTamperProtected
    signature_version = "$($s.AntivirusSignatureVersion)"; signatures = D $s.AntivirusSignatureLastUpdated
    quick_scan = D $s.QuickScanEndTime; full_scan = D $s.FullScanEndTime
  }
  try {
    $names = @{}
    Get-MpThreat | ForEach-Object { $names["$($_.ThreatID)"] = $_ }
    $out.threats = @(Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 200 | ForEach-Object {
      $t = $names["$($_.ThreatID)"]
      @{
        id = "$($_.DetectionID)"; threat_id = "$($_.ThreatID)"
        name = if ($t) { "$($t.ThreatName)" } else { $null }
        severity = if ($t) { [int]$t.SeverityID } else { 0 }
        status = [int]$_.ThreatStatusID
        resources = @($_.Resources | ForEach-Object { "$_" })
        detected = D $_.InitialDetectionTime
        process = "$($_.ProcessName)"; user = "$($_.DomainUser)"
      }
    })
  } catch {}
} catch { $out.defender_error = "$($_.Exception.Message)" }
try {
  $out.av = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object {
    @{ name = "$($_.displayName)"; state = [int64]$_.productState }
  })
} catch {}
$out | ConvertTo-Json -Depth 5 -Compress
"#;

#[cfg_attr(not(windows), allow(dead_code))]
pub fn action_script(action: Action) -> &'static str {
    match action {
        Action::QuickScan => "$ErrorActionPreference = 'Stop'; Start-MpScan -ScanType QuickScan",
        Action::FullScan => "$ErrorActionPreference = 'Stop'; Start-MpScan -ScanType FullScan",
        Action::UpdateSignatures => "$ErrorActionPreference = 'Stop'; Update-MpSignature",
    }
}

/// PowerShell's ConvertTo-Json writes a one-element array as the element itself in some
/// versions; accept both, and null.
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

fn opt_string<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Ok(Option::<String>::deserialize(d)?.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()))
}

#[derive(Deserialize)]
struct Raw {
    defender: Option<RawDefender>,
    #[serde(default, deserialize_with = "opt_string")]
    defender_error: Option<String>,
    #[serde(default, deserialize_with = "many")]
    av: Vec<RawAv>,
    #[serde(default, deserialize_with = "many")]
    threats: Vec<RawThreat>,
}

#[derive(Deserialize)]
struct RawDefender {
    #[serde(default, deserialize_with = "opt_string")]
    mode: Option<String>,
    #[serde(default, deserialize_with = "opt_string")]
    product_version: Option<String>,
    #[serde(default, deserialize_with = "opt_string")]
    engine_version: Option<String>,
    #[serde(default)]
    antivirus: bool,
    #[serde(default)]
    realtime: bool,
    #[serde(default)]
    tamper: Option<bool>,
    #[serde(default, deserialize_with = "opt_string")]
    signature_version: Option<String>,
    #[serde(default)]
    signatures: Option<DateTime<Utc>>,
    #[serde(default)]
    quick_scan: Option<DateTime<Utc>>,
    #[serde(default)]
    full_scan: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
struct RawAv {
    #[serde(default)]
    name: String,
    #[serde(default)]
    state: i64,
}

#[derive(Deserialize)]
struct RawThreat {
    #[serde(default)]
    id: String,
    #[serde(default, deserialize_with = "opt_string")]
    threat_id: Option<String>,
    #[serde(default, deserialize_with = "opt_string")]
    name: Option<String>,
    #[serde(default)]
    severity: i64,
    #[serde(default)]
    status: i64,
    #[serde(default, deserialize_with = "many")]
    resources: Vec<String>,
    #[serde(default)]
    detected: Option<DateTime<Utc>>,
    #[serde(default, deserialize_with = "opt_string")]
    process: Option<String>,
    #[serde(default, deserialize_with = "opt_string")]
    user: Option<String>,
}

/// `ThreatStatusID` from `Get-MpThreatDetection`.
fn threat_status(id: i64) -> ThreatStatus {
    match id {
        // 1 detected; 102-107: quarantine/remove/allow/block failed, abandoned.
        1 | 102..=107 => ThreatStatus::Active,
        2 | 4 => ThreatStatus::Removed,
        3 => ThreatStatus::Quarantined,
        5 => ThreatStatus::Allowed,
        6 => ThreatStatus::Blocked,
        _ => ThreatStatus::Unknown,
    }
}

/// `SeverityID` from `Get-MpThreat`.
fn threat_severity(id: i64) -> ThreatSeverity {
    match id {
        5 => ThreatSeverity::Severe,
        4 => ThreatSeverity::High,
        2 => ThreatSeverity::Moderate,
        1 => ThreatSeverity::Low,
        _ => ThreatSeverity::Unknown,
    }
}

/// Security Center's `productState`: bits 12-15 say whether the scanner is on (1) and bits
/// 4-7 whether its definitions are out of date (1). Returns (on, up to date).
pub fn decode_product_state(state: i64) -> (bool, bool) {
    let scanner = (state >> 12) & 0xF;
    let defs = (state >> 4) & 0xF;
    (scanner == 1, defs == 0)
}

fn is_defender(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("defender") && (n.contains("windows") || n.contains("microsoft"))
}

pub fn parse(json: &str) -> Result<Report, serde_json::Error> {
    let raw: Raw = serde_json::from_str(json.trim().trim_start_matches('\u{feff}'))?;
    let mut products = Vec::new();
    let mut error = None;
    let others: Vec<&RawAv> = raw.av.iter().filter(|a| !a.name.trim().is_empty() && !is_defender(&a.name)).collect();
    let have_defender = raw.defender.is_some();
    match raw.defender {
        Some(d) => {
            let mut p = Product::new(ProductKind::Defender, "Microsoft Defender Antivirus");
            let passive = d.mode.as_deref().is_some_and(|m| m.to_ascii_lowercase().contains("passive"));
            p.version = d.product_version;
            p.enabled = Some(d.antivirus && !passive);
            p.realtime = Some(d.antivirus && !passive && d.realtime);
            p.tamper_protection = d.tamper;
            p.signature_version = d.signature_version;
            p.signatures_updated_at = d.signatures;
            p.last_quick_scan = d.quick_scan;
            p.last_full_scan = d.full_scan;
            p.actions = vec![Action::QuickScan, Action::FullScan, Action::UpdateSignatures];
            if passive {
                p.detail = Some(format!("{} (another antivirus is primary)", d.mode.unwrap_or_default()));
            } else if let Some(engine) = d.engine_version {
                p.detail = Some(format!("Engine {engine}"));
            }
            products.push(p);
        }
        // Defender is switched off when another product registers; that's expected.
        None if others.is_empty() => {
            let mut p = Product::new(ProductKind::Defender, "Microsoft Defender Antivirus");
            p.enabled = Some(false);
            p.realtime = Some(false);
            p.detail = raw.defender_error.clone().map(|e| format!("Not running: {e}"));
            products.push(p);
        }
        None => {}
    }
    if !have_defender
        && others.is_empty()
        && let Some(e) = &raw.defender_error
    {
        error = Some(format!("reading Defender status: {e}"));
    }
    for a in others {
        let (on, current) = decode_product_state(a.state);
        let mut p = Product::new(ProductKind::Other, a.name.trim());
        p.enabled = Some(on);
        p.realtime = Some(on);
        p.signatures_current = Some(current);
        p.detail = Some("Reported by Windows Security Center".into());
        products.push(p);
    }
    let detections = raw
        .threats
        .into_iter()
        .filter(|t| !t.id.trim().is_empty())
        .take(MAX_DETECTIONS)
        .map(|t| Detection {
            id: t.id.trim().to_string(),
            product: ProductKind::Defender,
            name: t.name.unwrap_or_else(|| format!("Threat {}", t.threat_id.unwrap_or_default())),
            severity: threat_severity(t.severity),
            status: threat_status(t.status),
            resources: t.resources.into_iter().map(|r| r.trim().to_string()).filter(|r| !r.is_empty()).take(20).collect(),
            detected_at: t.detected,
            process: t.process.filter(|p| p != "Unknown"),
            user: t.user,
        })
        .collect();
    Ok(Report { products, detections, error })
}

#[cfg(windows)]
pub struct Defender;

#[cfg(windows)]
impl super::Provider for Defender {
    fn status(&self) -> Report {
        match powershell(STATUS_SCRIPT, std::time::Duration::from_secs(120)) {
            Ok(out) => parse(&out).unwrap_or_else(|e| Report { error: Some(format!("unexpected Defender output: {e}")), ..Default::default() }),
            Err(e) => Report { error: Some(format!("{e:#}")), ..Default::default() },
        }
    }

    fn run(&self, product: ProductKind, action: Action) -> anyhow::Result<String> {
        if product != ProductKind::Defender {
            anyhow::bail!("only Microsoft Defender can be controlled from here");
        }
        powershell(action_script(action), super::timeout(action))?;
        Ok(match action {
            Action::QuickScan => "Quick scan finished".into(),
            Action::FullScan => "Full scan finished".into(),
            Action::UpdateSignatures => "Signatures updated".into(),
        })
    }
}

#[cfg(windows)]
fn powershell(script: &str, timeout: std::time::Duration) -> anyhow::Result<String> {
    use crate::patch::cmd::{self, Log, Opts};
    let log = Log::default();
    let out = cmd::output(
        &log,
        "powershell.exe",
        &["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
        Opts { timeout, log: false, ..Default::default() },
    )?;
    if !out.success() {
        anyhow::bail!("{}", out.reason());
    }
    Ok(out.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_state_decodes() {
        // 397568 = 0x061100: on, up to date (Defender). 393472 = 0x060100: off.
        assert_eq!(decode_product_state(397568), (true, true));
        assert_eq!(decode_product_state(393472), (false, true));
        // 266256 = 0x041010: on, out of date.
        assert_eq!(decode_product_state(266256), (true, false));
    }

    #[test]
    fn defender_status_parses() {
        let json = r#"{"defender":{"mode":"Normal","product_version":"4.18.24090.11","engine_version":"1.1.24090.11",
            "antivirus":true,"realtime":true,"tamper":true,"signature_version":"1.421.123.0",
            "signatures":"2024-11-06T09:35:43.1234567Z","quick_scan":"2024-11-05T02:00:00.0000000Z","full_scan":null},
            "defender_error":null,"av":[{"name":"Windows Defender","state":397568}],
            "threats":{"id":"{A1B2}","threat_id":"2147519003","name":"Virus:DOS/EICAR_Test_File","severity":5,"status":3,
              "resources":"file:_C:\\Users\\bob\\Downloads\\eicar.com","detected":"2024-11-06T10:00:00Z","process":"Unknown","user":"PC\\bob"}}"#;
        let r = parse(json).unwrap();
        assert_eq!(r.products.len(), 1, "Security Center's Defender entry is folded into Defender");
        let p = &r.products[0];
        assert_eq!((p.kind, p.enabled, p.realtime, p.tamper_protection), (ProductKind::Defender, Some(true), Some(true), Some(true)));
        assert_eq!(p.signatures_updated_at.unwrap().to_rfc3339(), "2024-11-06T09:35:43.123456700+00:00");
        assert!(p.last_full_scan.is_none() && p.actions.len() == 3);
        let d = &r.detections[0];
        assert_eq!((d.status, d.severity), (ThreatStatus::Quarantined, ThreatSeverity::Severe));
        assert_eq!(d.resources, ["file:_C:\\Users\\bob\\Downloads\\eicar.com"]);
        assert_eq!((d.process.as_deref(), d.user.as_deref()), (None, Some("PC\\bob")));
    }

    #[test]
    fn third_party_product_and_passive_defender() {
        let json = "\u{feff}{\"defender\":{\"mode\":\"Passive Mode\",\"antivirus\":true,\"realtime\":true},\"av\":[{\"name\":\"Windows Defender\",\"state\":393472},{\"name\":\"Sophos Anti-Virus\",\"state\":266256}],\"threats\":[]}";
        let r = parse(json).unwrap();
        let d = r.products.iter().find(|p| p.kind == ProductKind::Defender).unwrap();
        assert_eq!((d.enabled, d.realtime), (Some(false), Some(false)));
        assert!(d.detail.as_deref().unwrap().contains("Passive"));
        let s = r.products.iter().find(|p| p.kind == ProductKind::Other).unwrap();
        assert_eq!((s.name.as_str(), s.enabled, s.signatures_current), ("Sophos Anti-Virus", Some(true), Some(false)));
        assert!(s.actions.is_empty());
    }

    #[test]
    fn defender_missing() {
        let r = parse(r#"{"defender":null,"defender_error":"The service cannot be started","av":null,"threats":[]}"#).unwrap();
        assert_eq!(r.products[0].enabled, Some(false));
        assert!(r.error.unwrap().contains("cannot be started"));
        // ...but not when another product took over.
        let r = parse(r#"{"defender":null,"defender_error":"x","av":{"name":"ESET Security","state":397312},"threats":[]}"#).unwrap();
        assert_eq!(r.products.len(), 1);
        assert_eq!(r.products[0].kind, ProductKind::Other);
        assert!(r.error.is_none());
    }

    #[test]
    fn threat_statuses() {
        assert_eq!(threat_status(1), ThreatStatus::Active);
        assert_eq!(threat_status(103), ThreatStatus::Active);
        assert_eq!(threat_status(4), ThreatStatus::Removed);
        assert_eq!(threat_status(6), ThreatStatus::Blocked);
        assert_eq!(threat_status(42), ThreatStatus::Unknown);
    }
}
