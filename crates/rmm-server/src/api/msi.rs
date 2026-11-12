//! A Windows Installer package for the agent, built on the fly like the `.deb`/`.rpm`.
//!
//! The database is written from scratch with the `msi` crate, with the binary in an embedded
//! cabinet, so the server needs no WiX toolchain. It's deliberately small:
//!
//! - installs `rmm-agent.exe` to `C:\Program Files\RMM` (where `rmm-agent install` would copy
//!   it anyway, so the service runs the file the MSI owns);
//! - a deferred custom action, as SYSTEM, runs `rmm-agent.exe enroll --keep-existing
//!   --install` with the baked-in `RMM_SERVER` and `RMM_TOKEN`. On a machine that's already
//!   enrolled with that server (an upgrade, a repair, a reinstall) it keeps the identity and
//!   only re-registers the service on the new binary;
//! - a `ServiceControl` row stops the service before files are replaced and stops and deletes
//!   it on uninstall. `C:\ProgramData\RMM` (config, state, logs) is left behind, so a reinstall
//!   keeps the same agent record;
//! - every package has a new ProductCode under a fixed UpgradeCode, and the Upgrade table
//!   removes any other installed version first (a major upgrade).
//!
//! `RMM_SERVER` and `RMM_TOKEN` are public properties, so `msiexec /i rmm-agent.msi
//! RMM_TOKEN=…` overrides them. `RMM_TOKEN` is hidden from verbose logs.

use std::io::{Cursor, Write};

use anyhow::Context;
use msi::{Column, Insert, Package, PackageType, Value};

/// Fixed for the product family: every package upgrades every other one.
const UPGRADE_CODE: &str = "{5A9D78D5-1751-45F5-BB90-D6D799EB8E90}";
/// The agent binary's component. Fixed so every version installs "the same" component.
const COMPONENT_ID: &str = "{037A78A8-13FF-4752-B2EB-8B761DE76E4F}";
/// File table key, also the file's name inside the cabinet.
const FILE_KEY: &str = "rmm_agent.exe";
const CABINET: &str = "agent.cab";
const SERVICE_NAME: &str = "RmmAgent";

// CustomAction types: 18 = run an EXE installed by this package (Source = File key,
// Target = arguments), plus deferred (in the install script), no impersonation (as SYSTEM)
// and hide target (the arguments carry the token).
const CA_EXE_FROM_FILE: i32 = 18;
const CA_IN_SCRIPT: i32 = 0x0400;
const CA_NO_IMPERSONATE: i32 = 0x0800;
const CA_HIDE_TARGET: i32 = 0x2000;

// ServiceControl events: stop on install, stop and delete on uninstall.
const SC_INSTALL_STOP: i32 = 0x0001;
const SC_UNINSTALL_STOP: i32 = 0x0010;
const SC_UNINSTALL_DELETE: i32 = 0x0080;

/// msidbComponentAttributes64bit.
const COMPONENT_64BIT: i32 = 0x0100;
/// msidbUpgradeAttributesVersionMinInclusive.
const UPGRADE_MIN_INCLUSIVE: i32 = 0x0100;

pub struct MsiInput<'a> {
    pub binary: &'a [u8],
    pub server: &'a str,
    pub token: &'a str,
    pub version: &'a str,
    pub manufacturer: &'a str,
}

/// Windows Installer versions are `major.minor.build` with major and minor below 256 and
/// build below 65536. Anything after the numbers (a pre-release tag) is dropped.
pub fn product_version(v: &str) -> String {
    let limits = [255u32, 255, 65535];
    let parts: Vec<u32> = v
        .split(['-', '+'])
        .next()
        .unwrap_or_default()
        .split('.')
        .take(3)
        .map(|p| p.parse::<u32>().unwrap_or(0))
        .collect();
    (0..3).map(|i| parts.get(i).copied().unwrap_or(0).min(limits[i]).to_string()).collect::<Vec<_>>().join(".")
}

fn guid() -> String {
    format!("{{{}}}", uuid::Uuid::new_v4().to_string().to_uppercase())
}

fn s(v: &str) -> Value {
    Value::from(v)
}

fn i(v: i32) -> Value {
    Value::Int(v)
}

fn cabinet(binary: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut builder = cab::CabinetBuilder::new();
    builder.add_folder(cab::CompressionType::MsZip).add_file(FILE_KEY);
    let mut writer = builder.build(Cursor::new(Vec::new()))?;
    while let Some(mut f) = writer.next_file()? {
        f.write_all(binary)?;
    }
    Ok(writer.finish()?.into_inner())
}

pub fn build(input: &MsiInput) -> anyhow::Result<Vec<u8>> {
    let version = product_version(input.version);
    let size = i32::try_from(input.binary.len()).context("agent binary too large for an MSI")?;
    let cab = cabinet(input.binary).context("building the cabinet")?;

    let mut pkg = Package::create(PackageType::Installer, Cursor::new(Vec::new()))?;
    {
        let si = pkg.summary_info_mut();
        si.set_title("Installation Database");
        si.set_subject("RMM Agent");
        si.set_author(input.manufacturer);
        si.set_comments("Installs the RMM agent and enrolls it with the server it was downloaded from.");
        si.set_arch("x64");
        si.set_languages(&[msi::LanguageId::from_lcid(1033)]);
        // The package code: unique per package.
        si.set_uuid(uuid::Uuid::new_v4());
        // 500 = Windows Installer 5.0 (x64 packages need at least 2.0).
        si.set_page_count(500);
        // 2 = long file names, compressed source.
        si.set_word_count(2);
        si.set_creating_application(concat!("rmm-server ", env!("CARGO_PKG_VERSION")));
        si.set_creation_time_to_now();
    }

    let id = |name: &str, len: usize| Column::build(name).id_string(len);
    let text = |name: &str, len: usize| Column::build(name).text_string(len);
    let fmt = |name: &str, len: usize| Column::build(name).formatted_string(len);

    pkg.create_table("Property", vec![Column::build("Property").primary_key().id_string(72), Column::build("Value").text_string(0)])?;
    let product_code = guid();
    let mut props: Vec<(&str, String)> = vec![
        ("ProductCode", product_code),
        ("ProductName", "RMM Agent".into()),
        ("ProductVersion", version.clone()),
        ("ProductLanguage", "1033".into()),
        ("Manufacturer", input.manufacturer.into()),
        ("UpgradeCode", UPGRADE_CODE.into()),
        ("ALLUSERS", "1".into()),
        ("ARPNOMODIFY", "1".into()),
        ("SecureCustomProperties", "OLDPRODUCTS;RMM_SERVER;RMM_TOKEN".into()),
        ("MsiHiddenProperties", "RMM_TOKEN".into()),
    ];
    // Property values can't be empty; an unset property is simply absent.
    if !input.server.is_empty() {
        props.push(("RMM_SERVER", input.server.into()));
    }
    if !input.token.is_empty() {
        props.push(("RMM_TOKEN", input.token.into()));
    }
    pkg.insert_rows(Insert::into("Property").rows(props.into_iter().map(|(k, v)| vec![s(k), s(&v)]).collect()))?;

    pkg.create_table(
        "Directory",
        vec![Column::build("Directory").primary_key().id_string(72), Column::build("Directory_Parent").nullable().id_string(72), Column::build("DefaultDir").text_string(255)],
    )?;
    pkg.insert_rows(Insert::into("Directory").rows(vec![
        vec![s("TARGETDIR"), Value::Null, s("SourceDir")],
        vec![s("ProgramFiles64Folder"), s("TARGETDIR"), s(".")],
        vec![s("INSTALLDIR"), s("ProgramFiles64Folder"), s("RMM")],
    ]))?;

    pkg.create_table(
        "Component",
        vec![
            Column::build("Component").primary_key().id_string(72),
            Column::build("ComponentId").nullable().string(38),
            id("Directory_", 72),
            Column::build("Attributes").int16(),
            Column::build("Condition").nullable().string(255),
            Column::build("KeyPath").nullable().id_string(72),
        ],
    )?;
    pkg.insert_rows(Insert::into("Component").row(vec![s("AgentExe"), s(COMPONENT_ID), s("INSTALLDIR"), i(COMPONENT_64BIT), Value::Null, s(FILE_KEY)]))?;

    pkg.create_table(
        "Feature",
        vec![
            Column::build("Feature").primary_key().id_string(38),
            Column::build("Feature_Parent").nullable().id_string(38),
            Column::build("Title").nullable().text_string(64),
            Column::build("Description").nullable().text_string(255),
            Column::build("Display").nullable().int16(),
            Column::build("Level").int16(),
            Column::build("Directory_").nullable().id_string(72),
            Column::build("Attributes").int16(),
        ],
    )?;
    pkg.insert_rows(Insert::into("Feature").row(vec![s("Agent"), Value::Null, s("RMM Agent"), Value::Null, i(0), i(1), s("INSTALLDIR"), i(0)]))?;

    pkg.create_table("FeatureComponents", vec![Column::build("Feature_").primary_key().id_string(38), Column::build("Component_").primary_key().id_string(72)])?;
    pkg.insert_rows(Insert::into("FeatureComponents").row(vec![s("Agent"), s("AgentExe")]))?;

    pkg.create_table(
        "File",
        vec![
            Column::build("File").primary_key().id_string(72),
            id("Component_", 72),
            text("FileName", 255),
            Column::build("FileSize").int32(),
            Column::build("Version").nullable().string(72),
            Column::build("Language").nullable().string(20),
            Column::build("Attributes").nullable().int16(),
            Column::build("Sequence").int16(),
        ],
    )?;
    // The binary has no version resource. Giving it a version here makes the installer treat
    // it as versioned, and a versioned file always replaces an unversioned one on disk (such
    // as one the agent's self-update wrote), so an MSI upgrade always lays down its binary.
    pkg.insert_rows(Insert::into("File").row(vec![
        s(FILE_KEY),
        s("AgentExe"),
        s("RMMAGENT.EXE|rmm-agent.exe"),
        i(size),
        s(&format!("{version}.0")),
        Value::Null,
        Value::Null,
        i(1),
    ]))?;

    pkg.create_table(
        "Media",
        vec![
            Column::build("DiskId").primary_key().int16(),
            Column::build("LastSequence").int16(),
            Column::build("DiskPrompt").nullable().text_string(64),
            Column::build("Cabinet").nullable().string(255),
            Column::build("VolumeLabel").nullable().text_string(32),
            Column::build("Source").nullable().string(72),
        ],
    )?;
    pkg.insert_rows(Insert::into("Media").row(vec![i(1), i(1), Value::Null, s(&format!("#{CABINET}")), Value::Null, Value::Null]))?;

    pkg.create_table(
        "ServiceControl",
        vec![
            Column::build("ServiceControl").primary_key().id_string(72),
            fmt("Name", 255),
            Column::build("Event").int16(),
            Column::build("Arguments").nullable().formatted_string(255),
            Column::build("Wait").nullable().int16(),
            id("Component_", 72),
        ],
    )?;
    pkg.insert_rows(Insert::into("ServiceControl").row(vec![
        s("AgentService"),
        s(SERVICE_NAME),
        i(SC_INSTALL_STOP | SC_UNINSTALL_STOP | SC_UNINSTALL_DELETE),
        Value::Null,
        i(1),
        s("AgentExe"),
    ]))?;

    pkg.create_table(
        "CustomAction",
        vec![
            Column::build("Action").primary_key().id_string(72),
            Column::build("Type").int16(),
            Column::build("Source").nullable().string(72),
            Column::build("Target").nullable().formatted_string(255),
        ],
    )?;
    // Properties are expanded when the action is scheduled, so the deferred action gets the
    // values. Errors go to install.log next to the agent's own log.
    let target = "enroll --server \"[RMM_SERVER]\" --token \"[RMM_TOKEN]\" --install --keep-existing \
                  --log-file \"[CommonAppDataFolder]RMM\\logs\\install.log\"";
    pkg.insert_rows(Insert::into("CustomAction").row(vec![
        s("EnrollAgent"),
        i(CA_EXE_FROM_FILE | CA_IN_SCRIPT | CA_NO_IMPERSONATE | CA_HIDE_TARGET),
        s(FILE_KEY),
        s(target),
    ]))?;

    pkg.create_table(
        "Upgrade",
        vec![
            Column::build("UpgradeCode").primary_key().string(38),
            Column::build("VersionMin").primary_key().nullable().string(20),
            Column::build("VersionMax").primary_key().nullable().string(20),
            Column::build("Language").primary_key().nullable().string(255),
            Column::build("Attributes").primary_key().int32(),
            Column::build("Remove").nullable().formatted_string(255),
            id("ActionProperty", 72),
        ],
    )?;
    // Every other version, older or newer: whatever package was installed last wins, and the
    // agent's self-update takes it from there.
    pkg.insert_rows(Insert::into("Upgrade").row(vec![
        s(UPGRADE_CODE),
        s("0.0.0"),
        Value::Null,
        Value::Null,
        i(UPGRADE_MIN_INCLUSIVE),
        Value::Null,
        s("OLDPRODUCTS"),
    ]))?;

    let sequence_columns =
        || vec![Column::build("Action").primary_key().id_string(72), Column::build("Condition").nullable().string(255), Column::build("Sequence").nullable().int16()];
    pkg.create_table("InstallExecuteSequence", sequence_columns())?;
    let execute: &[(&str, Option<&str>, i32)] = &[
        ("FindRelatedProducts", None, 25),
        ("CostInitialize", None, 800),
        ("FileCost", None, 900),
        ("CostFinalize", None, 1000),
        ("MigrateFeatureStates", None, 1200),
        ("InstallValidate", None, 1400),
        ("InstallInitialize", None, 1500),
        // Early: the old version (and its service) goes before anything new is laid down.
        ("RemoveExistingProducts", None, 1510),
        ("ProcessComponents", None, 1600),
        ("UnpublishFeatures", None, 1800),
        ("StopServices", Some("VersionNT"), 1900),
        ("DeleteServices", Some("VersionNT"), 2000),
        ("RemoveFiles", None, 3500),
        ("InstallFiles", None, 4000),
        ("RegisterUser", None, 6000),
        ("RegisterProduct", None, 6100),
        ("PublishFeatures", None, 6300),
        ("PublishProduct", None, 6400),
        ("EnrollAgent", Some("NOT REMOVE~=\"ALL\""), 6500),
        ("InstallFinalize", None, 6600),
    ];
    pkg.insert_rows(
        Insert::into("InstallExecuteSequence")
            .rows(execute.iter().map(|(a, c, n)| vec![s(a), c.map(s).unwrap_or(Value::Null), i(*n)]).collect()),
    )?;
    // No dialogs: a double-click shows the basic progress bar and a UAC prompt.
    pkg.create_table("InstallUISequence", sequence_columns())?;
    let ui: &[(&str, i32)] =
        &[("FindRelatedProducts", 25), ("CostInitialize", 800), ("FileCost", 900), ("CostFinalize", 1000), ("MigrateFeatureStates", 1200), ("ExecuteAction", 1300)];
    pkg.insert_rows(Insert::into("InstallUISequence").rows(ui.iter().map(|(a, n)| vec![s(a), Value::Null, i(*n)]).collect()))?;

    {
        let mut w = pkg.write_stream(CABINET)?;
        w.write_all(&cab)?;
    }
    pkg.flush()?;
    Ok(pkg.into_inner()?.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn sample() -> Vec<u8> {
        build(&MsiInput {
            binary: b"MZ fake agent binary",
            server: "https://rmm.example.com",
            token: "abc123",
            version: "0.4.2-rc.1",
            manufacturer: "Acme IT",
        })
        .unwrap()
    }

    #[test]
    fn versions() {
        assert_eq!(product_version("0.4.2-rc.1"), "0.4.2");
        assert_eq!(product_version("1.2"), "1.2.0");
        assert_eq!(product_version("300.1.70000"), "255.1.65535");
        assert_eq!(product_version("garbage"), "0.0.0");
    }

    #[test]
    fn package_reads_back() {
        let bytes = sample();
        let mut pkg = Package::open(Cursor::new(bytes)).unwrap();
        assert_eq!(pkg.summary_info().arch(), Some("x64"));

        let props: std::collections::HashMap<String, String> = pkg
            .select_rows(msi::Select::table("Property"))
            .unwrap()
            .map(|r| (r[0].as_str().unwrap().to_string(), r[1].as_str().unwrap().to_string()))
            .collect();
        assert_eq!(props["RMM_SERVER"], "https://rmm.example.com");
        assert_eq!(props["RMM_TOKEN"], "abc123");
        assert_eq!(props["ProductVersion"], "0.4.2");
        assert_eq!(props["UpgradeCode"], UPGRADE_CODE);
        assert!(props["SecureCustomProperties"].contains("OLDPRODUCTS"));

        let ca: Vec<_> = pkg.select_rows(msi::Select::table("CustomAction")).unwrap().collect();
        assert_eq!(ca.len(), 1);
        assert_eq!(ca[0][1].as_int(), Some(18 | 0x400 | 0x800 | 0x2000));
        assert!(ca[0][3].as_str().unwrap().contains("--keep-existing"));

        let seq: Vec<(String, i32)> = pkg
            .select_rows(msi::Select::table("InstallExecuteSequence"))
            .unwrap()
            .map(|r| (r[0].as_str().unwrap().to_string(), r[2].as_int().unwrap()))
            .collect();
        let at = |a: &str| seq.iter().find(|(n, _)| n == a).unwrap().1;
        assert!(at("InstallFiles") < at("EnrollAgent") && at("EnrollAgent") < at("InstallFinalize"));
        assert!(at("StopServices") < at("RemoveFiles"));

        // The cabinet holds the binary under the File table's key.
        let mut cab_bytes = Vec::new();
        pkg.read_stream(CABINET).unwrap().read_to_end(&mut cab_bytes).unwrap();
        let mut cabinet = cab::Cabinet::new(Cursor::new(cab_bytes)).unwrap();
        let mut file = Vec::new();
        cabinet.read_file(FILE_KEY).unwrap().read_to_end(&mut file).unwrap();
        assert_eq!(file, b"MZ fake agent binary");
    }

    #[test]
    fn each_package_is_a_new_product() {
        let codes: Vec<String> = (0..2)
            .map(|_| {
                let mut pkg = Package::open(Cursor::new(sample())).unwrap();
                pkg.select_rows(msi::Select::table("Property"))
                    .unwrap()
                    .find(|r| r[0].as_str() == Some("ProductCode"))
                    .map(|r| r[1].as_str().unwrap().to_string())
                    .unwrap()
            })
            .collect();
        assert_ne!(codes[0], codes[1]);
    }
}
