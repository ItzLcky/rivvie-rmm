//! Policy management core (docs/design/policies.md): module configs and their validation,
//! the merge rule, rebuilding `policy_effective`, resolving which set each agent uses, and the
//! fan-out after a change.
//!
//! Every write goes through one transaction: [`lock`], the change, [`rebuild`] for the items it
//! touches, [`validate_effective`] (the merged config of every set the item reaches must still
//! be valid), [`reresolve`] when assignments, defaults or sets changed, commit, then
//! [`changed`] with the agents that may now run under different policies.

use std::collections::{BTreeMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;

use chrono::NaiveTime;
use rmm_proto::patch::{Category, RebootPolicy, Severity};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sqlx::PgConnection;
use tracing::warn;
use uuid::Uuid;

use crate::alerts::Rule;
use crate::state::AppState;

/// All devices: the root of the tree.
pub const ROOT: Uuid = Uuid::from_u128(0x00000000_0000_4000_8001_000000000000);
/// Single-instance items, in [`ROOT`] (patch is `...0001`, security `...0002`: the ids of the
/// MSP-wide rows they replaced; the views in 0022_policies.sql name them).
pub const REMOTE_ITEM: Uuid = Uuid::from_u128(0x00000000_0000_4000_8000_000000000003);
pub const AGENT_ITEM: Uuid = Uuid::from_u128(0x00000000_0000_4000_8000_000000000004);
/// Levels below All devices a set may sit at (the built-in OS and platform levels count).
pub const MAX_DEPTH: i32 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Module {
    Alert,
    Schedule,
    Patch,
    Security,
    RemoteAccess,
    Agent,
    Software,
    Automation,
}

impl Module {
    pub fn parse(s: &str) -> Option<Module> {
        Some(match s {
            "alert" => Module::Alert,
            "schedule" => Module::Schedule,
            "patch" => Module::Patch,
            "security" => Module::Security,
            "remote_access" => Module::RemoteAccess,
            "agent" => Module::Agent,
            "software" => Module::Software,
            "automation" => Module::Automation,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Module::Alert => "alert",
            Module::Schedule => "schedule",
            Module::Patch => "patch",
            Module::Security => "security",
            Module::RemoteAccess => "remote_access",
            Module::Agent => "agent",
            Module::Software => "software",
            Module::Automation => "automation",
        }
    }

    /// Lives once, in All devices; everything else can only override it.
    pub fn single(self) -> bool {
        !matches!(
            self,
            Module::Alert | Module::Schedule | Module::Software | Module::Automation
        )
    }

    /// Top-level config fields a descendant set may override.
    fn overridable(self, field: &str) -> bool {
        match self {
            // The rule's type is what its open alerts mean.
            Module::Alert => field != "kind" && ALERT_FIELDS.contains(&field),
            // One cron clock per item.
            Module::Schedule => matches!(field, "args" | "timeout_secs"),
            Module::Patch => PATCH_FIELDS.contains(&field),
            Module::Security => SECURITY_FIELDS.contains(&field),
            Module::RemoteAccess => REMOTE_FIELDS.contains(&field),
            Module::Agent => field == "auto_update",
            // Which package is what the item is; the rest can differ per set.
            Module::Software => SOFTWARE_FIELDS.contains(&field),
            // One trigger and one script per item; the rest tunes how it runs.
            Module::Automation => AUTOMATION_OVERRIDABLE.contains(&field),
        }
    }
}

const AUTOMATION_OVERRIDABLE: &[&str] =
    &["args", "timeout_secs", "retry_failed", "max_attempts", "retry_minutes", "cooldown_minutes", "max_runs_per_hour", "respect_window"];

const ALERT_FIELDS: &[&str] = &[
    "kind",
    "params",
    "severity",
    "channel_ids",
    "notify_resolved",
    "renotify_minutes",
    "ticket_board_id",
    "ticket_priority",
    "ticket_auto_resolve",
    "run_script_id",
];
const PATCH_FIELDS: &[&str] = &["auto_approve_severities", "auto_approve_categories", "deferral_days", "auto_install", "reboot_policy", "window"];
const SECURITY_FIELDS: &[&str] = &[
    "sensor_enabled",
    "quick_scan_hours",
    "full_scan_days",
    "auto_quarantine",
    "prevention",
    "canaries",
    "telemetry_mb",
    "realtime",
    "scan_on_write",
    "archive_depth",
    "database_max_age_hours",
];
const SOFTWARE_FIELDS: &[&str] = &["state", "bootstrap_choco", "window"];
const REMOTE_FIELDS: &[&str] = &["desktop_enabled", "desktop_consent", "shell_enabled", "files_enabled"];

// ---------------------------------------------------------------------------
// Module configs
// ---------------------------------------------------------------------------

fn yes() -> bool {
    true
}
fn p3() -> i16 {
    3
}
fn utc() -> String {
    "UTC".into()
}
fn thirty() -> i32 {
    30
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlertConfig {
    pub kind: String,
    #[serde(default)]
    pub params: Value,
    pub severity: String,
    #[serde(default)]
    pub channel_ids: Vec<Uuid>,
    #[serde(default = "yes")]
    pub notify_resolved: bool,
    /// Remind the channels this often while an alert stays open and unacknowledged.
    #[serde(default)]
    pub renotify_minutes: Option<i32>,
    /// Open a ticket on this board for each alert.
    #[serde(default)]
    pub ticket_board_id: Option<Uuid>,
    #[serde(default = "p3")]
    pub ticket_priority: i16,
    #[serde(default)]
    pub ticket_auto_resolve: bool,
    /// Run this script on the agent once, when an alert opens (not when it opens muted).
    #[serde(default)]
    pub run_script_id: Option<Uuid>,
}

impl AlertConfig {
    pub fn rule(&self) -> Result<Rule, String> {
        let params = if self.params.is_null() { json!({}) } else { self.params.clone() };
        Rule::parse(&self.kind, &params)
    }

    fn validate(&self) -> Result<(), String> {
        if !matches!(self.severity.as_str(), "critical" | "warning" | "info") {
            return Err("severity must be critical, warning or info".into());
        }
        self.rule()?.validate()?;
        if self.renotify_minutes.is_some_and(|m| !(15..=10080).contains(&m)) {
            return Err("reminders must be every 15 minutes to 7 days".into());
        }
        if !(1..=4).contains(&self.ticket_priority) {
            return Err("ticket priority must be 1-4".into());
        }
        if self.channel_ids.len() > 20 {
            return Err("at most 20 channels".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduleConfig {
    pub script_id: Uuid,
    pub cron: String,
    #[serde(default = "utc")]
    pub timezone: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// None: the script's own timeout.
    #[serde(default)]
    pub timeout_secs: Option<i32>,
    /// Finished runs are deleted after this many days.
    #[serde(default = "thirty")]
    pub retain_days: i32,
}

impl ScheduleConfig {
    fn validate(&self) -> Result<(), String> {
        if !(1..=3650).contains(&self.retain_days) {
            return Err("keep runs for 1-3650 days".into());
        }
        if self.timeout_secs.is_some_and(|t| !(1..=86400).contains(&t)) {
            return Err("timeout must be 1-86400 seconds".into());
        }
        if self.args.len() > 50 || self.args.iter().any(|a| a.len() > 4096) {
            return Err("at most 50 arguments of at most 4096 characters".into());
        }
        crate::scheduler::next_run(&self.cron, &self.timezone, chrono::Utc::now()).map(|_| ())
    }
}

/// What starts an automation (docs/design/automations.md). `run_once` has no event: it runs on
/// every device the item reaches, once. [`crate::automation::fire`] is the one entry point
/// events use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Trigger {
    /// The agent's first connection.
    Enrollment,
    /// The agent connects after being offline for `offline_minutes` or more.
    AgentOnline,
    /// An alert of `alert_kind` opens on the agent.
    AlertOpened,
    /// A patch install finished and the machine still needs a restart.
    PatchRebootPending,
    RunOnce,
    /// A tag (`tag_id`) is put on the agent.
    TagAdded,
    /// A custom field (`field_id`) of the agent changes, to `field_value` if one is named.
    FieldChanged,
}

impl Trigger {
    pub fn as_str(self) -> &'static str {
        match self {
            Trigger::Enrollment => "enrollment",
            Trigger::AgentOnline => "agent_online",
            Trigger::AlertOpened => "alert_opened",
            Trigger::PatchRebootPending => "patch_reboot_pending",
            Trigger::RunOnce => "run_once",
            Trigger::TagAdded => "tag_added",
            Trigger::FieldChanged => "field_changed",
        }
    }

    /// One row per device and item, ever: the row is the record that it ran.
    pub fn once_per_device(self) -> bool {
        matches!(self, Trigger::Enrollment | Trigger::RunOnce)
    }
}

fn three() -> i32 {
    3
}
fn sixty() -> i32 {
    60
}
fn hundred() -> i32 {
    100
}

/// The alert kinds `alert_opened` can name (the `kind` of an alert item).
pub const ALERT_KINDS: &[&str] = &["offline", "cpu", "memory", "disk", "service", "job_failed", "log", "security", "patch", "backup"];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationConfig {
    pub trigger: Trigger,
    pub script_id: Uuid,
    #[serde(default)]
    pub args: Vec<String>,
    /// None: the script's own timeout.
    #[serde(default)]
    pub timeout_secs: Option<i32>,
    /// `agent_online`: how long the agent must have been offline.
    #[serde(default)]
    pub offline_minutes: Option<i32>,
    /// `alert_opened`: the kind of alert (cpu, disk, offline, ...).
    #[serde(default)]
    pub alert_kind: Option<String>,
    /// `tag_added`: the tag.
    #[serde(default)]
    pub tag_id: Option<Uuid>,
    /// `field_changed`: the agent custom field.
    #[serde(default)]
    pub field_id: Option<Uuid>,
    /// `field_changed`: only when the field becomes this value (as the field's kind reads it from
    /// text: `"yes"` for a bool, a choice for a select). None: any change, clearing included.
    #[serde(default)]
    pub field_value: Option<String>,
    /// `enrollment` and `run_once`: run again when the script fails, up to `max_attempts`
    /// times in all, `retry_minutes` apart.
    #[serde(default)]
    pub retry_failed: bool,
    #[serde(default = "three")]
    pub max_attempts: i32,
    #[serde(default = "thirty")]
    pub retry_minutes: i32,
    /// Event triggers: the same device doesn't run this automation again within this many
    /// minutes (0: no limit).
    #[serde(default = "sixty")]
    pub cooldown_minutes: i32,
    /// At most this many runs of this automation start in any hour, across all devices.
    /// Event runs over it are skipped; `enrollment` and `run_once` runs wait their turn.
    #[serde(default = "hundred")]
    pub max_runs_per_hour: i32,
    /// Hold runs until the site's maintenance window is open (sites without one run at once).
    #[serde(default)]
    pub respect_window: bool,
    /// Event runs are forgotten after this many days (`enrollment` and `run_once` rows are the
    /// record that the script ran, and stay).
    #[serde(default = "thirty")]
    pub retain_days: i32,
}

impl AutomationConfig {
    fn validate(&self) -> Result<(), String> {
        match (self.trigger, self.offline_minutes) {
            (Trigger::AgentOnline, Some(m)) if (5..=43200).contains(&m) => {}
            (Trigger::AgentOnline, _) => return Err("offline_minutes (5 minutes to 30 days) says how long the agent must have been offline".into()),
            (_, Some(_)) => return Err("offline_minutes belongs to the agent_online trigger".into()),
            _ => {}
        }
        match (self.trigger, self.alert_kind.as_deref()) {
            (Trigger::AlertOpened, Some(k)) if ALERT_KINDS.contains(&k) => {}
            (Trigger::AlertOpened, _) => return Err(format!("alert_kind is one of {}", ALERT_KINDS.join(", "))),
            (_, Some(_)) => return Err("alert_kind belongs to the alert_opened trigger".into()),
            _ => {}
        }
        match (self.trigger, self.tag_id) {
            (Trigger::TagAdded, Some(_)) => {}
            (Trigger::TagAdded, None) => return Err("tag_id says which tag starts the automation".into()),
            (_, Some(_)) => return Err("tag_id belongs to the tag_added trigger".into()),
            _ => {}
        }
        match (self.trigger, self.field_id) {
            (Trigger::FieldChanged, Some(_)) => {}
            (Trigger::FieldChanged, None) => return Err("field_id says which custom field starts the automation".into()),
            (_, Some(_)) => return Err("field_id belongs to the field_changed trigger".into()),
            _ => {}
        }
        match (&self.field_value, self.trigger) {
            (Some(v), Trigger::FieldChanged) if v.trim().is_empty() || v.chars().count() > crate::fields::TEXT_MAX => {
                return Err("field_value is a value of the field (leave it out for any change)".into());
            }
            (Some(_), t) if t != Trigger::FieldChanged => return Err("field_value belongs to the field_changed trigger".into()),
            _ => {}
        }
        if self.retry_failed && !self.trigger.once_per_device() {
            return Err("retrying belongs to enrollment and run_once automations; event runs are not repeated".into());
        }
        if !(1..=10).contains(&self.max_attempts) {
            return Err("attempts must be 1-10".into());
        }
        if !(5..=1440).contains(&self.retry_minutes) {
            return Err("retry after 5 minutes to 24 hours".into());
        }
        if !(0..=10080).contains(&self.cooldown_minutes) {
            return Err("cooldown must be 0 minutes to 7 days".into());
        }
        if !(1..=10000).contains(&self.max_runs_per_hour) {
            return Err("at most 1-10000 runs per hour".into());
        }
        if !(1..=3650).contains(&self.retain_days) {
            return Err("keep runs for 1-3650 days".into());
        }
        if self.timeout_secs.is_some_and(|t| !(1..=86400).contains(&t)) {
            return Err("timeout must be 1-86400 seconds".into());
        }
        if self.args.len() > 50 || self.args.iter().any(|a| a.len() > 4096) {
            return Err("at most 50 arguments of at most 4096 characters".into());
        }
        Ok(())
    }
}

/// A patch window of the policy's own (otherwise the site's maintenance window applies).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchWindow {
    /// 0 = Sunday ... 6 = Saturday. Empty: no window, installs may start at any time.
    pub days: Vec<i16>,
    /// `HH:MM`, local to `tz`.
    pub start: String,
    pub minutes: i32,
    /// A time zone, or `site` for the site's.
    pub tz: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchConfig {
    pub auto_approve_severities: Vec<String>,
    pub auto_approve_categories: Vec<String>,
    pub deferral_days: i32,
    pub auto_install: bool,
    pub reboot_policy: String,
    pub window: Option<PatchWindow>,
}

impl PatchConfig {
    fn validate(&self) -> Result<(), String> {
        if let Some(bad) = self.auto_approve_severities.iter().find(|s| Severity::parse(s).is_none()) {
            return Err(format!("unknown severity {bad}"));
        }
        if let Some(bad) = self.auto_approve_categories.iter().find(|s| Category::parse(s).is_none()) {
            return Err(format!("unknown category {bad}"));
        }
        if !(0..=365).contains(&self.deferral_days) {
            return Err("deferral_days must be 0-365".into());
        }
        if RebootPolicy::parse(&self.reboot_policy).is_none() {
            return Err("reboot_policy must be never, if_required or always".into());
        }
        if let Some(w) = &self.window {
            validate_window(w)?;
        }
        Ok(())
    }
}

fn validate_window(w: &PatchWindow) -> Result<(), String> {
    if w.days.iter().any(|d| !(0..=6).contains(d)) {
        return Err("window days are 0 (Sunday) to 6 (Saturday)".into());
    }
    NaiveTime::parse_from_str(w.start.trim(), "%H:%M").map_err(|_| "window start must be a time like 02:00".to_string())?;
    if !(15..=1440).contains(&w.minutes) {
        return Err("the window must last 15 minutes to 24 hours".into());
    }
    if w.tz != "site" && chrono_tz::Tz::from_str(&w.tz).is_err() {
        return Err(format!("unknown time zone {}", w.tz));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    pub sensor_enabled: bool,
    pub quick_scan_hours: i32,
    pub full_scan_days: i32,
    pub auto_quarantine: bool,
    pub prevention: bool,
    pub canaries: bool,
    pub telemetry_mb: i32,
    /// Real-time protection: off, audit or block.
    pub realtime: String,
    pub scan_on_write: bool,
    pub archive_depth: i32,
    /// Our signature database older than this (hours; 0 = no limit) puts the agent at risk.
    pub database_max_age_hours: i32,
}

impl SecurityConfig {
    fn validate(&self) -> Result<(), String> {
        if !(0..=720).contains(&self.quick_scan_hours) || !(0..=90).contains(&self.full_scan_days) || !(16..=4096).contains(&self.telemetry_mb) {
            return Err("quick scans 0-720 hours apart, full scans 0-90 days, telemetry 16-4096 MB".into());
        }
        if rmm_proto::security::RealtimeMode::parse(&self.realtime).is_none() {
            return Err("real-time protection is off, audit or block".into());
        }
        if !(1..=20).contains(&self.archive_depth) {
            return Err("archive depth 1-20".into());
        }
        if !(0..=8760).contains(&self.database_max_age_hours) {
            return Err("the database age limit is 0-8760 hours (0: none)".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteAccessConfig {
    pub desktop_enabled: bool,
    /// Ask the person at the machine before a remote desktop session starts.
    pub desktop_consent: bool,
    pub shell_enabled: bool,
    pub files_enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    /// Offer the newest signed agent release when the agent connects.
    pub auto_update: bool,
}

/// One package requirement: the package, and whether it must be there, kept current, or gone.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoftwareConfig {
    pub package_id: Uuid,
    pub state: crate::software::Want,
    /// Install Chocolatey if a package needs it and the machine doesn't have it. It downloads
    /// and runs Chocolatey's installer script, so it's off unless asked for.
    #[serde(default)]
    pub bootstrap_choco: bool,
    /// When upgrades of an installed package may start: `null` is the site's maintenance
    /// window. (Installs and removals don't wait.)
    #[serde(default)]
    pub window: Option<PatchWindow>,
}

impl SoftwareConfig {
    fn validate(&self) -> Result<(), String> {
        if let Some(w) = &self.window {
            validate_window(w)?;
        }
        Ok(())
    }
}

fn parse<T: serde::de::DeserializeOwned>(v: &Value) -> Result<T, String> {
    serde_json::from_value(v.clone()).map_err(|e| e.to_string())
}

/// Checks a whole config (an item's, or a merged one) and returns it normalized: defaults
/// filled in, alert params in their canonical form.
pub fn validate(module: Module, config: &Value) -> Result<Value, String> {
    let out = match module {
        Module::Alert => {
            let mut c: AlertConfig = parse(config)?;
            c.validate()?;
            c.params = c.rule()?.params();
            serde_json::to_value(c)
        }
        Module::Schedule => {
            let c: ScheduleConfig = parse(config)?;
            c.validate()?;
            serde_json::to_value(c)
        }
        Module::Patch => {
            let c: PatchConfig = parse(config)?;
            c.validate()?;
            serde_json::to_value(c)
        }
        Module::Security => {
            let c: SecurityConfig = parse(config)?;
            c.validate()?;
            serde_json::to_value(c)
        }
        Module::RemoteAccess => serde_json::to_value(parse::<RemoteAccessConfig>(config)?),
        Module::Agent => serde_json::to_value(parse::<AgentConfig>(config)?),
        Module::Software => {
            let c: SoftwareConfig = parse(config)?;
            c.validate()?;
            serde_json::to_value(c)
        }
        Module::Automation => {
            let c: AutomationConfig = parse(config)?;
            c.validate()?;
            serde_json::to_value(c)
        }
    };
    out.map_err(|e| e.to_string())
}

/// Checks an override's shape (only fields the module lets descendants change) and drops empty
/// objects, which change nothing. Its values are checked by validating the merged configs.
pub fn clean_override(module: Module, config: &Value) -> Result<Value, String> {
    let Value::Object(m) = config else { return Err("an override's config is an object of the fields that differ".into()) };
    if let Some(bad) = m.keys().find(|k| !module.overridable(k)) {
        return Err(match (module, bad.as_str()) {
            (Module::Alert, "kind") => "an alert's type can't be overridden".into(),
            (Module::Schedule, _) => format!("{bad} can't be overridden: a scheduled script's overrides are limited to enabled, args and timeout_secs"),
            (Module::Automation, _) => format!("{bad} can't be overridden: an automation's trigger and script are fixed; its args, timeout, retries and limits can change"),
            _ => format!("{bad} isn't a {} setting", module.as_str()),
        });
    }
    let mut v = config.clone();
    strip_empty(&mut v);
    Ok(v)
}

fn strip_empty(v: &mut Value) {
    if let Value::Object(m) = v {
        for x in m.values_mut() {
            strip_empty(x);
        }
        m.retain(|_, x| !matches!(x, Value::Object(o) if o.is_empty()));
    }
}

/// The merge rule, as `jsonb_merge_deep` in the database applies it (which is what builds
/// `policy_effective`): objects merge key by key, recursively; anything else in `over` replaces.
#[cfg(test)]
pub fn merge(base: &Value, over: &Value) -> Value {
    match (base, over) {
        (Value::Object(a), Value::Object(b)) => {
            let mut out = a.clone();
            for (k, v) in b {
                let merged = match a.get(k) {
                    Some(old) => merge(old, v),
                    None => v.clone(),
                };
                out.insert(k.clone(), merged);
            }
            Value::Object(out)
        }
        _ => over.clone(),
    }
}

/// Which set each field's value comes from (dotted paths of the leaves, `params.threshold`),
/// given the item's set and config and the overrides on the way down, in order.
pub fn field_sources(origin: Uuid, config: &Value, overrides: &[(Uuid, &Value)]) -> BTreeMap<String, Uuid> {
    fn leaves(v: &Value, prefix: &str, out: &mut BTreeMap<String, Uuid>, set: Uuid) {
        match v {
            Value::Object(m) if !m.is_empty() => {
                for (k, x) in m {
                    leaves(x, &join(prefix, k), out, set);
                }
            }
            _ if !prefix.is_empty() => {
                out.insert(prefix.to_string(), set);
            }
            _ => {}
        }
    }
    fn apply(o: &Map<String, Value>, prefix: &str, out: &mut BTreeMap<String, Uuid>, set: Uuid) {
        for (k, v) in o {
            let p = join(prefix, k);
            match v {
                // Merges: fields it doesn't name keep their source. A leaf it lands on is replaced.
                Value::Object(m) if !m.is_empty() => {
                    out.remove(&p);
                    apply(m, &p, out, set);
                }
                _ => {
                    let nested = format!("{p}.");
                    out.retain(|key, _| !key.starts_with(&nested));
                    out.insert(p, set);
                }
            }
        }
    }
    let mut out = BTreeMap::new();
    leaves(config, "", &mut out, origin);
    for (set, o) in overrides {
        if let Value::Object(m) = o {
            apply(m, "", &mut out, *set);
        }
    }
    out
}

fn join(prefix: &str, k: &str) -> String {
    if prefix.is_empty() { k.to_string() } else { format!("{prefix}.{k}") }
}

/// Why a device uses the set it uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    Pin,
    Site,
    Client,
    Default,
}

/// Which set a device uses: its pin, else the assignment for its site and category, else the
/// one for its client and category, else the category's default. (`policy_set_for` in the
/// database is what stores it; this explains it.)
pub fn resolve(pin: Option<Uuid>, site: Option<Uuid>, client: Option<Uuid>, default: Uuid) -> (Uuid, Reason) {
    match (pin, site, client) {
        (Some(p), _, _) => (p, Reason::Pin),
        (None, Some(s), _) => (s, Reason::Site),
        (None, None, Some(c)) => (c, Reason::Client),
        (None, None, None) => (default, Reason::Default),
    }
}

/// The effective remote access policy for an agent, and the name of its set (for messages).
pub async fn remote_access(st: &AppState, agent_id: Uuid) -> sqlx::Result<(RemoteAccessConfig, String)> {
    let (config, set): (Value, String) = sqlx::query_as(
        "SELECT e.config, ps.name FROM agents a JOIN policy_sets ps ON ps.id = a.policy_set_id
           JOIN policy_effective e ON e.set_id = a.policy_set_id AND e.item_id = $2
          WHERE a.id = $1",
    )
    .bind(agent_id)
    .bind(REMOTE_ITEM)
    .fetch_one(&st.db)
    .await?;
    let c = serde_json::from_value(config).unwrap_or(RemoteAccessConfig { desktop_enabled: true, desktop_consent: false, shell_enabled: true, files_enabled: true });
    Ok((c, set))
}

/// Whether the agent's policy has automatic agent updates on.
pub async fn auto_update(st: &AppState, agent_id: Uuid) -> sqlx::Result<bool> {
    let v: Option<Option<bool>> = sqlx::query_scalar(
        "SELECT (e.config ->> 'auto_update')::boolean FROM agents a
           JOIN policy_effective e ON e.set_id = a.policy_set_id AND e.item_id = $2 WHERE a.id = $1",
    )
    .bind(agent_id)
    .bind(AGENT_ITEM)
    .fetch_optional(&st.db)
    .await?;
    Ok(v.flatten().unwrap_or(false))
}

// ---------------------------------------------------------------------------
// Writes
// ---------------------------------------------------------------------------

/// Serializes policy writes: rebuilds and re-resolves must not interleave.
pub async fn lock(tx: &mut PgConnection) -> sqlx::Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('rmm.policy'))").execute(&mut *tx).await?;
    Ok(())
}

/// Recomputes `policy_effective` for these items (None: all, after the tree changed).
pub async fn rebuild(tx: &mut PgConnection, items: Option<&[Uuid]>) -> sqlx::Result<()> {
    sqlx::query("SELECT policy_rebuild($1)").bind(items).execute(&mut *tx).await?;
    Ok(())
}

/// Every merged config of these items (in every set they reach) must still be valid. The error
/// names the set.
pub async fn validate_effective(tx: &mut PgConnection, items: &[Uuid]) -> sqlx::Result<Result<(), String>> {
    let rows: Vec<(String, String, Value)> = sqlx::query_as(
        "SELECT ps.name, e.module, e.config FROM policy_effective e JOIN policy_sets ps ON ps.id = e.set_id
          WHERE e.item_id = ANY($1) ORDER BY ps.parent_id NULLS FIRST, ps.name",
    )
    .bind(items)
    .fetch_all(&mut *tx)
    .await?;
    let mut seen = HashSet::new();
    for (set, module, config) in rows {
        if !seen.insert((module.clone(), config.to_string())) {
            continue;
        }
        let Some(m) = Module::parse(&module) else { continue };
        if let Err(e) = validate(m, &config) {
            return Ok(Err(format!("in {set}: {e}")));
        }
    }
    Ok(Ok(()))
}

/// Re-resolves every agent's set (after assignments, category defaults or pins changed).
/// Returns the agents that moved.
pub async fn reresolve(tx: &mut PgConnection) -> sqlx::Result<Vec<Uuid>> {
    sqlx::query_scalar(
        "WITH n AS (SELECT id, policy_set_for(policy_pin_id, site_id, category_id) AS want FROM agents)
         UPDATE agents a SET policy_set_id = n.want FROM n
          WHERE a.id = n.id AND a.policy_set_id IS DISTINCT FROM n.want
          RETURNING a.id",
    )
    .fetch_all(&mut *tx)
    .await
}

/// Agents whose set any of these items reaches.
pub async fn agents_reached(tx: &mut PgConnection, items: &[Uuid]) -> sqlx::Result<Vec<Uuid>> {
    sqlx::query_scalar("SELECT DISTINCT a.id FROM agents a JOIN policy_effective e ON e.set_id = a.policy_set_id WHERE e.item_id = ANY($1)")
        .bind(items)
        .fetch_all(&mut *tx)
        .await
}

/// Agents using this set or one below it.
pub async fn agents_under(tx: &mut PgConnection, set_id: Uuid) -> sqlx::Result<Vec<Uuid>> {
    sqlx::query_scalar(
        "WITH RECURSIVE t AS (SELECT $1::uuid AS id UNION ALL SELECT c.id FROM policy_sets c JOIN t ON c.parent_id = t.id)
         SELECT a.id FROM agents a WHERE a.policy_set_id IN (SELECT id FROM t)",
    )
    .bind(set_id)
    .fetch_all(&mut *tx)
    .await
}

/// What a committed change may have affected.
#[derive(Debug, Default)]
pub struct Change {
    /// Alert items whose config changed: re-checked against the agents they cover.
    pub items: Vec<Uuid>,
    /// Agents that may run under different policies now (None: maybe all of them).
    pub agents: Option<Vec<Uuid>>,
}

impl Change {
    pub fn agents(agents: Vec<Uuid>) -> Change {
        Change { items: vec![], agents: Some(agents) }
    }
}

/// After a committed policy change: close alerts whose item no longer applies (quietly, as
/// `policy`), give open alerts the new severity, re-check what can be re-checked now, re-push
/// log watchers and the sensor policy to the agents affected, and re-apply patch approvals.
pub async fn changed(st: &Arc<AppState>, ch: Change) {
    crate::alerts::close_inapplicable(st).await;
    let agents = ch.agents.as_deref();
    if let Err(e) = sqlx::query(
        "UPDATE alerts al SET severity = policy_config(al.policy_id, al.agent_id) ->> 'severity'
          WHERE al.resolved_at IS NULL AND al.policy_id IS NOT NULL
            AND (al.policy_id = ANY($1) OR $2::uuid[] IS NULL OR al.agent_id = ANY($2))
            AND al.severity IS DISTINCT FROM policy_config(al.policy_id, al.agent_id) ->> 'severity'",
    )
    .bind(&ch.items)
    .bind(agents)
    .execute(&st.db)
    .await
    {
        warn!("updating alert severities: {e}");
    }
    if agents.is_some_and(|a| a.is_empty()) && ch.items.is_empty() {
        return;
    }
    for item in ch.items.iter().copied() {
        let st = st.clone();
        tokio::spawn(async move { crate::alerts::recheck_item(&st, item).await });
    }
    if let Some(list) = ch.agents.clone() {
        let st = st.clone();
        tokio::spawn(async move {
            for agent in list {
                crate::alerts::recheck_agent(&st, agent).await;
            }
        });
    }
    crate::alerts::push_watchers(st, agents).await;
    crate::checks::push(st, agents, &[]).await;
    crate::security::push_policies_to(st, agents).await;
    let res = async { crate::patches::apply_policies(&mut *st.db.acquire().await?, agents).await }.await;
    if let Err(e) = res {
        warn!("re-applying patch approvals: {e}");
    }
    // Devices that joined a set, and requirements added or changed: scan what's missing and enforce.
    let st = st.clone();
    let list = ch.agents;
    tokio::spawn(async move { crate::software::policy_changed(&st, list.as_deref()).await });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(kind: &str, params: Value) -> Value {
        json!({ "kind": kind, "params": params, "severity": "warning" })
    }

    #[test]
    fn resolution_order() {
        let (pin, site, client, default) = (Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3), Uuid::from_u128(4));
        assert_eq!(resolve(Some(pin), Some(site), Some(client), default), (pin, Reason::Pin));
        assert_eq!(resolve(None, Some(site), Some(client), default), (site, Reason::Site));
        assert_eq!(resolve(None, None, Some(client), default), (client, Reason::Client));
        assert_eq!(resolve(None, None, None, default), (default, Reason::Default));
    }

    #[test]
    fn merge_objects_recursively_and_replace_the_rest() {
        let base = json!({ "kind": "cpu", "params": { "threshold": 90, "minutes": 5 }, "channel_ids": ["a", "b"], "renotify_minutes": 60 });
        let over = json!({ "params": { "threshold": 95 }, "channel_ids": ["c"], "renotify_minutes": null });
        assert_eq!(
            merge(&base, &over),
            json!({ "kind": "cpu", "params": { "threshold": 95, "minutes": 5 }, "channel_ids": ["c"], "renotify_minutes": null })
        );
        assert_eq!(merge(&json!({ "window": null }), &json!({ "window": { "days": [1] } })), json!({ "window": { "days": [1] } }));
        assert_eq!(merge(&json!({ "window": { "days": [1] } }), &json!({ "window": null })), json!({ "window": null }));
        assert_eq!(merge(&base, &json!({})), base, "an empty override changes nothing");
    }

    #[test]
    fn sources_follow_the_overrides_down() {
        let (root, mid, leaf) = (Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3));
        let cfg = json!({ "kind": "cpu", "params": { "threshold": 90, "minutes": 5 }, "severity": "warning" });
        let o1 = json!({ "params": { "threshold": 95 } });
        let o2 = json!({ "severity": "critical", "params": { "minutes": 10 } });
        let s = field_sources(root, &cfg, &[(mid, &o1), (leaf, &o2)]);
        assert_eq!(s["kind"], root);
        assert_eq!(s["params.threshold"], mid);
        assert_eq!(s["params.minutes"], leaf);
        assert_eq!(s["severity"], leaf);
        // Replacing an object with a scalar takes its leaves with it.
        let s = field_sources(root, &json!({ "window": { "days": [1], "start": "02:00" } }), &[(mid, &json!({ "window": null }))]);
        assert_eq!(s.into_iter().collect::<Vec<_>>(), vec![("window".to_string(), mid)]);
    }

    #[test]
    fn validation_by_module() {
        let ok = validate(Module::Alert, &alert("cpu", json!({ "threshold": 90, "minutes": 5 }))).unwrap();
        assert_eq!((ok["notify_resolved"].as_bool(), ok["ticket_priority"].as_i64()), (Some(true), Some(3)), "defaults filled in: {ok}");
        assert!(validate(Module::Alert, &alert("cpu", json!({ "threshold": 500, "minutes": 5 }))).is_err());
        assert!(validate(Module::Alert, &json!({ "kind": "cpu", "params": { "threshold": 90, "minutes": 5 }, "severity": "loud" })).is_err());
        assert!(validate(Module::Alert, &json!({ "kind": "offline", "params": { "minutes": 5 }, "severity": "info", "color": "red" })).is_err(), "unknown field");
        let sched = json!({ "script_id": Uuid::nil(), "cron": "0 3 * * *" });
        assert_eq!(validate(Module::Schedule, &sched).unwrap()["retain_days"], 30);
        assert!(validate(Module::Schedule, &json!({ "script_id": Uuid::nil(), "cron": "every day" })).is_err());
        let patch = json!({ "auto_approve_severities": [], "auto_approve_categories": ["security"], "deferral_days": 0, "auto_install": true,
                            "reboot_policy": "never", "window": { "days": [6], "start": "22:00", "minutes": 120, "tz": "site" } });
        assert!(validate(Module::Patch, &patch).is_ok());
        assert!(validate(Module::Patch, &merge(&patch, &json!({ "window": { "tz": "Mars/Olympus" } }))).is_err());
        assert!(validate(Module::Patch, &merge(&patch, &json!({ "reboot_policy": "sometimes" }))).is_err());
        assert!(validate(Module::RemoteAccess, &json!({ "desktop_enabled": true, "desktop_consent": false, "shell_enabled": true })).is_err(), "missing field");
    }

    #[test]
    fn automations_are_checked_per_trigger() {
        let id = Uuid::nil();
        let ok = |v: Value| validate(Module::Automation, &v);
        let base = |trigger: &str, extra: Value| {
            let mut v = json!({ "trigger": trigger, "script_id": id });
            v.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
            v
        };
        let c = ok(base("enrollment", json!({}))).unwrap();
        assert_eq!((c["cooldown_minutes"].as_i64(), c["max_runs_per_hour"].as_i64(), c["max_attempts"].as_i64()), (Some(60), Some(100), Some(3)), "defaults filled in: {c}");
        assert!(ok(base("run_once", json!({ "retry_failed": true, "max_attempts": 5, "retry_minutes": 10 }))).is_ok());
        // Each trigger takes its own parameter and refuses the others'.
        assert!(ok(base("agent_online", json!({}))).is_err(), "needs offline_minutes");
        assert!(ok(base("agent_online", json!({ "offline_minutes": 4 }))).is_err(), "at least 5 minutes");
        assert!(ok(base("agent_online", json!({ "offline_minutes": 30 }))).is_ok());
        assert!(ok(base("enrollment", json!({ "offline_minutes": 30 }))).is_err());
        assert!(ok(base("alert_opened", json!({}))).is_err(), "needs alert_kind");
        assert!(ok(base("alert_opened", json!({ "alert_kind": "weather" }))).is_err());
        assert!(ok(base("alert_opened", json!({ "alert_kind": "disk" }))).is_ok());
        assert!(ok(base("patch_reboot_pending", json!({ "alert_kind": "disk" }))).is_err());
        assert!(ok(base("alert_opened", json!({ "alert_kind": "disk", "retry_failed": true }))).is_err(), "events aren't retried");
        assert!(ok(base("volcano", json!({}))).is_err(), "unknown trigger");
        let (tag, field) = (Uuid::new_v4(), Uuid::new_v4());
        assert!(ok(base("tag_added", json!({}))).is_err(), "needs tag_id");
        assert!(ok(base("tag_added", json!({ "tag_id": tag }))).is_ok());
        assert!(ok(base("tag_added", json!({ "tag_id": tag, "field_id": field }))).is_err());
        assert!(ok(base("enrollment", json!({ "tag_id": tag }))).is_err(), "tags belong to tag_added");
        assert!(ok(base("field_changed", json!({}))).is_err(), "needs field_id");
        assert!(ok(base("field_changed", json!({ "field_id": field }))).is_ok(), "any change");
        assert!(ok(base("field_changed", json!({ "field_id": field, "field_value": "Gold" }))).is_ok());
        assert!(ok(base("field_changed", json!({ "field_id": field, "field_value": "  " }))).is_err(), "no blank match; leave it out");
        assert!(ok(base("field_changed", json!({ "field_id": field, "tag_id": tag }))).is_err());
        assert!(ok(base("run_once", json!({ "field_value": "x" }))).is_err());
        assert!(ok(base("tag_added", json!({ "tag_id": tag, "retry_failed": true }))).is_err(), "events aren't retried");
        for bad in [json!({ "max_attempts": 0 }), json!({ "retry_minutes": 1 }), json!({ "cooldown_minutes": -1 }), json!({ "max_runs_per_hour": 0 }), json!({ "timeout_secs": 0 }), json!({ "color": "red" })] {
            assert!(ok(base("enrollment", bad.clone())).is_err(), "{bad}");
        }
        // Overrides tune how it runs, never what starts it or which script.
        assert!(clean_override(Module::Automation, &json!({ "args": ["-q"], "max_runs_per_hour": 5, "respect_window": true })).is_ok());
        assert!(clean_override(Module::Automation, &json!({ "trigger": "run_once" })).is_err());
        assert!(clean_override(Module::Automation, &json!({ "script_id": id })).is_err());
        assert!(!Module::Automation.single(), "defined in any set, like alerts and schedules");
    }

    #[test]
    fn overrides_are_limited_per_module() {
        assert!(clean_override(Module::Alert, &json!({ "kind": "memory" })).is_err());
        assert_eq!(clean_override(Module::Alert, &json!({ "params": {}, "severity": "info" })).unwrap(), json!({ "severity": "info" }));
        assert!(clean_override(Module::Schedule, &json!({ "cron": "* * * * *" })).is_err());
        assert!(clean_override(Module::Schedule, &json!({ "args": ["x"], "timeout_secs": 60 })).is_ok());
        assert!(clean_override(Module::Security, &json!({ "sensor": true })).is_err());
        assert!(clean_override(Module::Patch, &json!([])).is_err());
    }
}
