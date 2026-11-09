//! Windows Update parsing that doesn't need Windows, so it's tested everywhere.

#![cfg_attr(not(windows), allow(dead_code))]

use anyhow::Result;
use rmm_proto::patch::{Category, PatchUpdate, Severity};

/// Update classification GUIDs (stable across languages, unlike the names).
pub fn category(id: &str, name: &str) -> Option<Category> {
    Some(match id.to_ascii_uppercase().as_str() {
        "0FA1201D-4330-4FA8-8AE9-B877473B6441" => Category::Security,
        "E6CF1350-C01B-414D-A61F-263D14D133B4" => Category::Critical,
        "E0789628-CE08-4437-BE74-2495B842F43B" => Category::Definition,
        "EBFC1FC5-71A4-4F7B-9ACA-3B9A503104A0" => Category::Driver,
        "B54E7D24-7ADD-428F-8B75-90A396FA584F" | "68C5B0A3-D1A6-4553-AE49-01D3A7827828" | "3689BDC8-B205-4AF4-8D4A-A63924C5E9D5" => {
            Category::Feature
        }
        "28BC880E-0592-4CBF-8F95-C79B17911D5F" => Category::Rollup,
        "CD5FFD1E-E932-4E3A-BF74-18BF0B1BBD83" => Category::Update,
        "B4832BD8-E735-4761-8DAF-37F882276DAB" => Category::Other,
        _ => return category_by_name(name),
    })
}

pub fn category_by_name(name: &str) -> Option<Category> {
    let n = name.to_ascii_lowercase();
    Some(if n.contains("security") {
        Category::Security
    } else if n.contains("critical") {
        Category::Critical
    } else if n.contains("definition") {
        Category::Definition
    } else if n.contains("driver") {
        Category::Driver
    } else if n.contains("feature") || n.contains("service pack") || n.contains("upgrade") {
        Category::Feature
    } else if n.contains("rollup") {
        Category::Rollup
    } else if n == "updates" {
        Category::Update
    } else {
        return None;
    })
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PsUpdate {
    id: String,
    title: Option<String>,
    #[serde(rename = "KB")]
    kb: Option<String>,
    msrc_severity: Option<String>,
    size: Option<u64>,
    reboot: Option<bool>,
    categories: Option<String>,
}

pub fn parse_ps(json: &str) -> Result<Vec<PatchUpdate>> {
    let json = json.trim();
    if json.is_empty() {
        return Ok(vec![]);
    }
    // ConvertTo-Json writes a lone object, not an array, for one update.
    let list: Vec<PsUpdate> = if json.starts_with('[') { serde_json::from_str(json)? } else { vec![serde_json::from_str(json)?] };
    Ok(list
        .into_iter()
        .map(|u| PatchUpdate {
            id: u.id,
            title: u.title.unwrap_or_default(),
            kb: u.kb.filter(|k| !k.is_empty()).map(|k| if k.starts_with("KB") { k } else { format!("KB{k}") }),
            severity: u.msrc_severity.as_deref().and_then(Severity::from_vendor),
            category: u.categories.as_deref().and_then(|c| c.split(';').find_map(category_by_name)).unwrap_or(Category::Update),
            size: u.size.filter(|s| *s > 0),
            requires_reboot: u.reboot.unwrap_or(false),
            version: None,
            current_version: None,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifications() {
        assert_eq!(category("0fa1201d-4330-4fa8-8ae9-b877473b6441", "Sicherheitsupdates"), Some(Category::Security));
        assert_eq!(category("unknown", "Definition Updates"), Some(Category::Definition));
        assert_eq!(category("unknown", "Updates"), Some(Category::Update));
        assert_eq!(category("unknown", "Mystery"), None);
    }

    #[test]
    fn parses_pswindowsupdate_json() {
        let one = r#"{"Id":"5c5f2d7e-0000-4000-8000-000000000001","Title":"2024-11 Cumulative Update","KB":"5046617","MsrcSeverity":"Critical","Size":812345678,"Reboot":true,"Categories":"Security Updates;Windows 11"}"#;
        let u = parse_ps(one).unwrap();
        assert_eq!(u.len(), 1);
        assert_eq!((u[0].kb.as_deref(), u[0].severity, u[0].category), (Some("KB5046617"), Some(Severity::Critical), Category::Security));
        assert!(u[0].requires_reboot);
        let many = format!("[{one},{{\"Id\":\"x\",\"Title\":null,\"KB\":\"\",\"MsrcSeverity\":\"\",\"Size\":0,\"Reboot\":false,\"Categories\":\"Drivers\"}}]");
        let u = parse_ps(&many).unwrap();
        assert_eq!((u[1].kb.as_deref(), u[1].size, u[1].category), (None, None, Category::Driver));
        assert!(parse_ps("  ").unwrap().is_empty());
    }
}
