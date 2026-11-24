//! Script parameters (docs/design/script-params.md).
//!
//! A saved script declares typed parameters ([`Spec`]); a run gives them values, and the agent
//! sets each one on the script's process as the environment variable `RMM_PARAM_<NAME>`. The
//! script body and its arguments are never rewritten: a value can't become code, whatever it
//! holds, for any of the five interpreters.
//!
//! Every job also gets the built-ins ([`Builtins`]): `RMM_AGENT_ID`, `RMM_AGENT_HOSTNAME`,
//! `RMM_AGENT_OS`, `RMM_AGENT_PLATFORM`, `RMM_CLIENT_ID`, `RMM_CLIENT_NAME`, `RMM_SITE_ID`,
//! `RMM_SITE_NAME` and `RMM_JOB_ID`.
//!
//! **Placeholders.** A `text` value may hold `{{agent.hostname}}`, `{{agent.id}}`,
//! `{{agent.os}}`, `{{client.name}}`, `{{site.name}}` or `{{field.<name>}}`; the server expands
//! them per device before the job exists, and the result is still only an environment value. A
//! custom field is read from the agent, then its site, then its client. An unknown placeholder
//! is refused when the value is saved.
//!
//! **Secrets.** A `secret` value is shown as [`MASK`] in `jobs.params` and the audit log; the
//! real value waits in `jobs.env_sealed` (sealed with `RMM_DATA_KEY`, associated data
//! `job-env:<job id>`) until the job reaches its agent, and is dropped when the job is past
//! `queued`/`sent` (a trigger in 0036). Policy items name a vault item instead of holding a
//! secret: `vault:<uuid>`, read at launch from the device's client vault.
//!
//! **Delivery.** Whatever starts a job stores its parameters; [`job_env`] builds the environment
//! when the job is sent (at once, or when the agent reconnects). An agent that doesn't list
//! [`rmm_proto::SCRIPT_ENV_CAPABILITY`] can't receive parameters: such a job ends as `error`
//! instead of running without them.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sqlx::PgPool;
use uuid::Uuid;

use crate::crypto::DataKey;
use crate::state::AppState;

/// Parameters a script may declare.
pub const MAX_PARAMS: usize = 30;
/// The longest value, in bytes, after placeholders are expanded (the agent checks it again).
pub const VALUE_MAX: usize = 8 * 1024;
/// All parameter values of one job together, in bytes; the agent allows 24 KiB with the
/// built-ins.
pub const TOTAL_MAX: usize = 20 * 1024;
/// How a secret's value is shown.
pub const MASK: &str = "•••";
/// Fields one value set may reference (each becomes a lookup per device).
const FIELDS_MAX: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Text,
    Number,
    Bool,
    Select,
    Secret,
}

/// One declared parameter, as stored in `scripts.params`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    /// `[a-z][a-z0-9_]{0,39}`; the variable is `RMM_PARAM_` and the name in capitals.
    pub name: String,
    #[serde(default)]
    pub label: String,
    #[serde(rename = "type")]
    pub kind: Kind,
    #[serde(default)]
    pub required: bool,
    /// Used when a run gives no value. Never for a secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<Value>,
    /// The options of a `select`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub choices: Vec<String>,
    #[serde(default)]
    pub description: String,
}

pub fn valid_name(n: &str) -> bool {
    let mut c = n.chars();
    matches!(c.next(), Some('a'..='z')) && n.len() <= 40 && c.all(|c| matches!(c, 'a'..='z' | '0'..='9' | '_'))
}

/// The variable a parameter is passed in.
pub fn env_name(param: &str) -> String {
    format!("RMM_PARAM_{}", param.to_ascii_uppercase())
}

/// Checks `scripts.params` as sent and returns it normalized (labels filled in, defaults
/// coerced).
pub fn validate_specs(v: &Value) -> Result<Vec<Spec>, String> {
    let mut specs: Vec<Spec> = match v {
        Value::Null => return Ok(vec![]),
        v => serde_json::from_value(v.clone()).map_err(|e| format!("params: {e}"))?,
    };
    if specs.len() > MAX_PARAMS {
        return Err(format!("a script has at most {MAX_PARAMS} parameters"));
    }
    let mut seen = BTreeSet::new();
    for s in &mut specs {
        if !valid_name(&s.name) {
            return Err(format!("parameter name {:?}: a lowercase letter, then letters, digits or _ (up to 40)", s.name));
        }
        if !seen.insert(s.name.clone()) {
            return Err(format!("parameter {} is declared twice", s.name));
        }
        s.label = s.label.split_whitespace().collect::<Vec<_>>().join(" ");
        if s.label.is_empty() {
            s.label = s.name.clone();
        }
        if s.label.chars().count() > 80 || s.description.chars().count() > 500 {
            return Err(format!("parameter {}: the label is up to 80 characters, the description up to 500", s.name));
        }
        match s.kind {
            Kind::Select => {
                s.choices = s.choices.iter().map(|c| c.trim().to_string()).collect();
                let distinct: BTreeSet<&String> = s.choices.iter().collect();
                if s.choices.is_empty() || s.choices.len() > 50 || distinct.len() != s.choices.len() {
                    return Err(format!("parameter {}: a select has 1-50 different choices", s.name));
                }
                if s.choices.iter().any(|c| c.is_empty() || c.chars().count() > 200 || c.contains("{{")) {
                    return Err(format!("parameter {}: each choice is 1-200 characters", s.name));
                }
            }
            _ if !s.choices.is_empty() => return Err(format!("parameter {}: only a select has choices", s.name)),
            _ => {}
        }
        if let Some(d) = s.default.take() {
            if s.kind == Kind::Secret {
                return Err(format!("parameter {}: a secret can't have a default (it would be stored in the clear)", s.name));
            }
            if s.kind != Kind::Text && d.as_str().is_some_and(|t| t.contains("{{")) {
                return Err(format!("parameter {}: placeholders are only allowed in text parameters", s.name));
            }
            if let Some(t) = d.as_str() {
                placeholders(t).map_err(|e| format!("parameter {}: {e}", s.name))?;
            }
            s.default = coerce(s, &d).map_err(|e| format!("default of {}: {e}", s.name))?;
        }
    }
    Ok(specs)
}

/// The value to pass for `input`, as `fields::coerce` reads it for the kind (strings are accepted
/// for every kind: `"42"`, `"yes"`). `None`: no value (null or empty).
pub fn coerce(spec: &Spec, input: &Value) -> Result<Option<Value>, String> {
    match spec.kind {
        Kind::Secret => match input {
            Value::Null => Ok(None),
            Value::String(s) if s.is_empty() => Ok(None),
            Value::String(s) if s.len() > VALUE_MAX => Err(format!("longer than {VALUE_MAX} bytes")),
            Value::String(s) if s.contains('\0') => Err("contains a NUL character".into()),
            Value::String(s) => Ok(Some(Value::String(s.clone()))),
            _ => Err("expected text".into()),
        },
        Kind::Text => {
            let v = crate::fields::coerce("text", &[], input)?;
            if v.as_ref().and_then(Value::as_str).is_some_and(|s| s.len() > VALUE_MAX) {
                return Err(format!("longer than {VALUE_MAX} bytes"));
            }
            Ok(v)
        }
        Kind::Number => crate::fields::coerce("number", &[], input),
        Kind::Bool => crate::fields::coerce("bool", &[], input),
        Kind::Select => crate::fields::coerce("select", &spec.choices, input),
    }
}

/// A placeholder of a text value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Placeholder {
    AgentHostname,
    AgentId,
    AgentOs,
    ClientName,
    SiteName,
    Field(String),
}

impl Placeholder {
    fn parse(key: &str) -> Option<Self> {
        Some(match key {
            "agent.hostname" => Placeholder::AgentHostname,
            "agent.id" => Placeholder::AgentId,
            "agent.os" => Placeholder::AgentOs,
            "client.name" => Placeholder::ClientName,
            "site.name" => Placeholder::SiteName,
            k => match k.strip_prefix("field.") {
                Some(f) if crate::fields::valid_name(f) => Placeholder::Field(f.to_string()),
                _ => return None,
            },
        })
    }
}

/// Every `{{...}}` of `s` with where it is (byte range of the whole placeholder). Inner spaces
/// are allowed (`{{ agent.hostname }}`). An unknown or unclosed one is an error.
fn scan(s: &str) -> Result<Vec<(std::ops::Range<usize>, Placeholder)>, String> {
    let mut out = Vec::new();
    let mut at = 0;
    while let Some(i) = s[at..].find("{{") {
        let start = at + i;
        let Some(j) = s[start + 2..].find("}}") else { return Err("a {{ placeholder isn't closed with }}".into()) };
        let end = start + 2 + j + 2;
        let key = s[start + 2..end - 2].trim();
        let p = Placeholder::parse(key).ok_or_else(|| {
            format!("unknown placeholder {{{{{key}}}}}: use agent.hostname, agent.id, agent.os, client.name, site.name or field.<name>")
        })?;
        out.push((start..end, p));
        at = end;
    }
    Ok(out)
}

/// The placeholders of `s` (an error for an unknown one).
pub fn placeholders(s: &str) -> Result<Vec<Placeholder>, String> {
    Ok(scan(s)?.into_iter().map(|(_, p)| p).collect())
}

/// What placeholders expand to for one device.
#[derive(Debug, Clone, Default)]
pub struct Ctx {
    pub agent_id: Uuid,
    pub hostname: String,
    pub os: String,
    pub client_name: String,
    pub site_name: String,
    /// The custom fields referenced, by name (absent: no value anywhere, expands to "").
    pub fields: HashMap<String, String>,
}

/// `s` with its placeholders replaced. Values that don't parse are left as they are (they were
/// refused when saved).
pub fn expand(s: &str, ctx: &Ctx) -> String {
    let Ok(found) = scan(s) else { return s.to_string() };
    let mut out = String::with_capacity(s.len());
    let mut at = 0;
    for (range, p) in found {
        out.push_str(&s[at..range.start]);
        match p {
            Placeholder::AgentHostname => out.push_str(&ctx.hostname),
            Placeholder::AgentId => out.push_str(&ctx.agent_id.to_string()),
            Placeholder::AgentOs => out.push_str(&ctx.os),
            Placeholder::ClientName => out.push_str(&ctx.client_name),
            Placeholder::SiteName => out.push_str(&ctx.site_name),
            Placeholder::Field(f) => out.push_str(ctx.fields.get(&f).map(String::as_str).unwrap_or("")),
        }
        at = range.end;
    }
    out.push_str(&s[at..]);
    out
}

/// A checked value.
#[derive(Debug, Clone, PartialEq)]
pub enum Val {
    /// Text (possibly with placeholders), a number, a bool or a choice.
    Plain(Value),
    /// A secret given as is.
    Secret(String),
    /// A secret to read from this vault item of the device's client.
    Vault(Uuid),
}

/// Where values come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The run dialog or `POST /jobs`. API keys can't name vault items (the vault isn't public).
    Run { api_key: bool },
    /// A schedule or automation item: secrets only as `vault:<uuid>`, never stored in the item.
    Policy,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Checked {
    pub vals: BTreeMap<String, Val>,
    /// Custom field names the placeholders reference.
    pub fields: BTreeSet<String>,
}

impl Checked {
    pub fn vault_items(&self) -> Vec<Uuid> {
        self.vals.values().filter_map(|v| if let Val::Vault(id) = v { Some(*id) } else { None }).collect::<BTreeSet<_>>().into_iter().collect()
    }

    pub fn has_secrets(&self) -> bool {
        self.vals.values().any(|v| !matches!(v, Val::Plain(_)))
    }

    /// Whether any value differs per device.
    pub fn expands(&self) -> bool {
        self.vals.values().any(|v| matches!(v, Val::Plain(Value::String(s)) if s.contains("{{")))
    }

    /// Names and non-secret values, for the audit log.
    pub fn audit(&self) -> Value {
        let shown: Map<String, Value> = self
            .vals
            .iter()
            .map(|(k, v)| {
                let v = match v {
                    Val::Plain(p) => p.clone(),
                    Val::Secret(_) => json!(MASK),
                    Val::Vault(id) => json!(format!("vault:{id}")),
                };
                (k.clone(), v)
            })
            .collect();
        Value::Object(shown)
    }
}

/// Parses `vault:<uuid>`.
pub fn vault_ref(s: &str) -> Option<Uuid> {
    s.trim().strip_prefix("vault:").and_then(|id| Uuid::parse_str(id).ok())
}

/// Checks `values` against the script's `specs`: every name declared, required ones present
/// (or defaulted), each value of its type, placeholders only in text and all known, secrets in
/// the form `mode` allows. Defaults fill in what isn't given.
pub fn check_values(specs: &[Spec], values: &Map<String, Value>, mode: Mode) -> Result<Checked, String> {
    if let Some(k) = values.keys().find(|k| !specs.iter().any(|s| &s.name == *k)) {
        return Err(format!("the script has no parameter {k}"));
    }
    let mut out = Checked::default();
    let mut total = 0;
    for s in specs {
        let given = values.get(&s.name).filter(|v| !v.is_null() && v.as_str() != Some(""));
        let Some(given) = given.or(s.default.as_ref()) else {
            if s.required {
                return Err(format!("parameter {} ({}) is required", s.name, s.label));
            }
            continue;
        };
        let text = given.as_str();
        if s.kind != Kind::Text && s.kind != Kind::Secret && text.is_some_and(|t| t.contains("{{")) {
            return Err(format!("parameter {}: placeholders are only allowed in text parameters", s.name));
        }
        let val = if s.kind == Kind::Secret {
            match (text.and_then(vault_ref), mode) {
                (Some(_), Mode::Run { api_key: true }) => return Err(format!("parameter {}: API keys can't use vault items", s.name)),
                (Some(id), _) => Val::Vault(id),
                (None, Mode::Policy) => {
                    return Err(format!("parameter {}: a policy can't store a secret; choose a vault item (vault:<id>)", s.name));
                }
                (None, Mode::Run { .. }) => match coerce(s, given).map_err(|e| format!("parameter {}: {e}", s.name))? {
                    Some(Value::String(v)) => Val::Secret(v),
                    _ if s.required => return Err(format!("parameter {} ({}) is required", s.name, s.label)),
                    _ => continue,
                },
            }
        } else {
            match coerce(s, given).map_err(|e| format!("parameter {}: {e}", s.name))? {
                Some(v) => {
                    if let Some(t) = v.as_str() {
                        for p in placeholders(t).map_err(|e| format!("parameter {}: {e}", s.name))? {
                            if let Placeholder::Field(f) = p {
                                out.fields.insert(f);
                            }
                        }
                    }
                    Val::Plain(v)
                }
                None if s.required => return Err(format!("parameter {} ({}) is required", s.name, s.label)),
                None => continue,
            }
        };
        total += match &val {
            Val::Plain(v) => env_value(v).map_or(0, |v| v.len()),
            Val::Secret(v) => v.len(),
            Val::Vault(_) => 0,
        };
        out.vals.insert(s.name.clone(), val);
    }
    if total > TOTAL_MAX {
        return Err(format!("the parameter values add up to more than {} KiB", TOTAL_MAX / 1024));
    }
    if out.fields.len() > FIELDS_MAX {
        return Err(format!("at most {FIELDS_MAX} different custom fields can be referenced"));
    }
    Ok(out)
}

/// A value as the script sees it.
pub fn env_value(v: &Value) -> Option<String> {
    match v {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        Value::Bool(b) => Some(if *b { "true" } else { "false" }.into()),
        other => Some(other.to_string()),
    }
}

/// One job's parameters, ready to store: `public` goes to `jobs.params` (secrets as [`MASK`]),
/// `secrets` is sealed into `jobs.env_sealed`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Prepared {
    pub public: Map<String, Value>,
    pub secrets: BTreeMap<String, String>,
}

impl Prepared {
    /// Expands the placeholders for one device; `vault` holds the vault items' passwords.
    pub fn new(checked: &Checked, ctx: &Ctx, vault: &HashMap<Uuid, String>) -> Result<Self, String> {
        let mut p = Prepared::default();
        for (k, v) in &checked.vals {
            match v {
                Val::Plain(Value::String(s)) => {
                    let s = expand(s, ctx);
                    if s.len() > VALUE_MAX {
                        return Err(format!("parameter {k} is longer than {VALUE_MAX} bytes once expanded"));
                    }
                    p.public.insert(k.clone(), Value::String(s));
                }
                Val::Plain(v) => {
                    p.public.insert(k.clone(), v.clone());
                }
                Val::Secret(s) => {
                    p.public.insert(k.clone(), json!(MASK));
                    p.secrets.insert(k.clone(), s.clone());
                }
                Val::Vault(id) => {
                    let s = vault.get(id).ok_or_else(|| format!("parameter {k}: the vault item has no password"))?;
                    if s.len() > VALUE_MAX || s.contains('\0') {
                        return Err(format!("parameter {k}: the vault item's password can't be passed in a variable"));
                    }
                    p.public.insert(k.clone(), json!(MASK));
                    p.secrets.insert(k.clone(), s.clone());
                }
            }
        }
        let total: usize = p.public.iter().map(|(k, v)| p.secrets.get(k).map_or_else(|| env_value(v).map_or(0, |v| v.len()), |s| s.len())).sum();
        if total > TOTAL_MAX {
            return Err(format!("the parameter values add up to more than {} KiB", TOTAL_MAX / 1024));
        }
        Ok(p)
    }

    /// `jobs.env_sealed` for job `job_id` (None without secrets).
    pub fn seal(&self, key: &DataKey, job_id: Uuid) -> Option<Vec<u8>> {
        (!self.secrets.is_empty()).then(|| key.seal_aad(&serde_json::to_vec(&self.secrets).unwrap_or_default(), &format!("job-env:{job_id}")))
    }
}

/// The secrets [`Prepared::seal`] sealed.
pub fn open_secrets(key: &DataKey, job_id: Uuid, sealed: &[u8]) -> Option<BTreeMap<String, String>> {
    key.open_aad(sealed, &format!("job-env:{job_id}")).and_then(|b| serde_json::from_slice(&b).ok())
}

/// The variables every job gets.
#[derive(Debug, Clone, Default)]
pub struct Builtins {
    pub job_id: Uuid,
    pub agent_id: Uuid,
    pub hostname: String,
    pub os: String,
    pub platform: String,
    pub client_id: Uuid,
    pub client_name: String,
    pub site_id: Uuid,
    pub site_name: String,
}

/// The whole environment of a job: the built-ins, then each parameter (a secret from
/// `secrets`).
pub fn env_vars(b: &Builtins, public: &Map<String, Value>, secrets: &BTreeMap<String, String>) -> Vec<(String, String)> {
    let mut env = vec![
        ("RMM_AGENT_ID".to_string(), b.agent_id.to_string()),
        ("RMM_AGENT_HOSTNAME".into(), b.hostname.clone()),
        ("RMM_AGENT_OS".into(), b.os.clone()),
        ("RMM_AGENT_PLATFORM".into(), b.platform.clone()),
        ("RMM_CLIENT_ID".into(), b.client_id.to_string()),
        ("RMM_CLIENT_NAME".into(), b.client_name.clone()),
        ("RMM_SITE_ID".into(), b.site_id.to_string()),
        ("RMM_SITE_NAME".into(), b.site_name.clone()),
        ("RMM_JOB_ID".into(), b.job_id.to_string()),
    ];
    for (k, v) in public {
        if !valid_name(k) {
            continue;
        }
        let value = match secrets.get(k) {
            Some(s) => Some(s.clone()),
            None => env_value(v),
        };
        if let Some(value) = value {
            env.push((env_name(k), value));
        }
    }
    env
}

// ---------------------------------------------------------------------------
// With the database
// ---------------------------------------------------------------------------

/// A script's declared parameters (none for an unknown script).
pub async fn script_specs(db: impl sqlx::PgExecutor<'_>, script: Uuid) -> sqlx::Result<Vec<Spec>> {
    let v: Option<Value> = sqlx::query_scalar("SELECT params FROM scripts WHERE id = $1").bind(script).fetch_optional(db).await?;
    Ok(v.and_then(|v| serde_json::from_value(v).ok()).unwrap_or_default())
}

/// An error unless a custom field of each name exists (any entity; a placeholder reads the
/// agent's, then the site's, then the client's).
pub async fn fields_exist(db: impl sqlx::PgExecutor<'_>, names: &BTreeSet<String>) -> sqlx::Result<Result<(), String>> {
    if names.is_empty() {
        return Ok(Ok(()));
    }
    let names: Vec<&String> = names.iter().collect();
    let known: Vec<String> = sqlx::query_scalar("SELECT DISTINCT name FROM custom_fields WHERE name = ANY($1)").bind(&names).fetch_all(db).await?;
    Ok(match names.iter().find(|n| !known.contains(n)) {
        Some(n) => Err(format!("unknown placeholder {{{{field.{n}}}}}: there is no custom field {n}")),
        None => Ok(()),
    })
}

/// The placeholder contexts of these agents, with the referenced fields.
pub async fn contexts(db: &PgPool, agents: &[Uuid], fields: &BTreeSet<String>) -> sqlx::Result<HashMap<Uuid, Ctx>> {
    let rows: Vec<(Uuid, String, String, String, String)> = sqlx::query_as(
        "SELECT a.id, a.hostname, a.os_family, c.name, s.name
           FROM agents a JOIN sites s ON s.id = a.site_id JOIN clients c ON c.id = s.client_id WHERE a.id = ANY($1)",
    )
    .bind(agents)
    .fetch_all(db)
    .await?;
    let mut out: HashMap<Uuid, Ctx> = rows
        .into_iter()
        .map(|(id, hostname, os, client_name, site_name)| (id, Ctx { agent_id: id, hostname, os, client_name, site_name, fields: HashMap::new() }))
        .collect();
    if !fields.is_empty() {
        let names: Vec<&String> = fields.iter().collect();
        let values: Vec<(Uuid, String, Value)> = sqlx::query_as(
            "SELECT a.id, n.name, coalesce(av.value, sv.value, cv.value)
               FROM agents a JOIN sites s ON s.id = a.site_id CROSS JOIN unnest($2::text[]) AS n(name)
               LEFT JOIN LATERAL (SELECT v.value FROM custom_field_values v JOIN custom_fields f ON f.id = v.field_id
                                   WHERE f.entity = 'agent' AND f.name = n.name AND v.agent_id = a.id LIMIT 1) av ON true
               LEFT JOIN LATERAL (SELECT v.value FROM custom_field_values v JOIN custom_fields f ON f.id = v.field_id
                                   WHERE f.entity = 'site' AND f.name = n.name AND v.site_id = s.id LIMIT 1) sv ON true
               LEFT JOIN LATERAL (SELECT v.value FROM custom_field_values v JOIN custom_fields f ON f.id = v.field_id
                                   WHERE f.entity = 'client' AND f.name = n.name AND v.client_id = s.client_id LIMIT 1) cv ON true
              WHERE a.id = ANY($1) AND coalesce(av.value, sv.value, cv.value) IS NOT NULL",
        )
        .bind(agents)
        .bind(&names)
        .fetch_all(db)
        .await?;
        for (agent, name, v) in values {
            if let (Some(ctx), Some(v)) = (out.get_mut(&agent), env_value(&v)) {
                ctx.fields.insert(name, v);
            }
        }
    }
    Ok(out)
}

/// The passwords of the vault items `checked` names, which must belong to `client`. Errors are
/// for the person or log reading them (no secret in them).
pub async fn vault_secrets(st: &AppState, client: Uuid, checked: &Checked) -> Result<HashMap<Uuid, String>, String> {
    let items = checked.vault_items();
    let mut out = HashMap::new();
    if items.is_empty() {
        return Ok(out);
    }
    let master = st.cfg.data_key.as_ref().ok_or_else(|| "secret parameters need RMM_DATA_KEY to be set on the server".to_string())?;
    for id in items {
        match crate::vault::read_password(&st.db, master, client, id).await {
            Ok(Some(p)) => {
                out.insert(id, p);
            }
            Ok(None) => return Err(format!("vault item {id} has no password")),
            Err(crate::error::ApiError::NotFound(_)) => return Err(format!("vault item {id} isn't in this device's client vault")),
            Err(e) => return Err(format!("reading vault item {id}: {e}")),
        }
    }
    Ok(out)
}

/// Records that a job was given vault items (`vault.use`, one entry per item).
pub async fn audit_vault_use(db: &PgPool, user: Option<Uuid>, checked: &Checked, client: Uuid, job: Uuid, via: &str) {
    for id in checked.vault_items() {
        crate::auth::audit(db, user, "vault.use", Some(("vault_item", id)), json!({ "client_id": client, "job_id": job, "via": via })).await;
    }
}

/// For the server's own launchers (schedules, automations, alert scripts): the stored values
/// of a policy item, checked against `script` and prepared for job `job_id` on `agent_id`
/// (of `client`). Returns `jobs.params` and `jobs.env_sealed`; an error says why the job can't
/// run (the caller ends it as `error` with that text).
pub async fn env_for(
    st: &AppState,
    script: Uuid,
    values: &BTreeMap<String, String>,
    agent_id: Uuid,
    client: Uuid,
    job_id: Uuid,
    via: &str,
) -> anyhow::Result<Result<(Value, Option<Vec<u8>>), String>> {
    let specs = script_specs(&st.db, script).await?;
    let given: Map<String, Value> = values.iter().map(|(k, v)| (k.clone(), Value::String(v.clone()))).collect();
    let checked = match check_values(&specs, &given, Mode::Policy) {
        Ok(c) => c,
        Err(e) => return Ok(Err(e)),
    };
    if checked.vals.is_empty() {
        return Ok(Ok((json!({}), None)));
    }
    let ctx = contexts(&st.db, &[agent_id], &checked.fields).await?.remove(&agent_id).unwrap_or_default();
    let vault = match vault_secrets(st, client, &checked).await {
        Ok(v) => v,
        Err(e) => return Ok(Err(e)),
    };
    let prepared = match Prepared::new(&checked, &ctx, &vault) {
        Ok(p) => p,
        Err(e) => return Ok(Err(e)),
    };
    let sealed = match (&st.cfg.data_key, prepared.secrets.is_empty()) {
        (_, true) => None,
        (Some(k), false) => prepared.seal(k, job_id),
        (None, false) => return Ok(Err("secret parameters need RMM_DATA_KEY to be set on the server".into())),
    };
    audit_vault_use(&st.db, None, &checked, client, job_id, via).await;
    Ok(Ok((Value::Object(prepared.public), sealed)))
}

/// Checks the parameters of a schedule or automation config (merged or at its origin) against
/// its script: the values fit, the placeholders' fields exist, and vault items belong to
/// `item_client`, the client the item is limited to (an item for every client can't name one).
pub async fn check_policy(tx: &mut sqlx::PgConnection, config: &Value, item_client: Option<Uuid>) -> sqlx::Result<Result<(), String>> {
    let Some(script) = config.get("script_id").and_then(Value::as_str).and_then(|s| Uuid::parse_str(s).ok()) else { return Ok(Ok(())) };
    let given: Map<String, Value> = config.get("params").and_then(Value::as_object).cloned().unwrap_or_default();
    let specs = script_specs(&mut *tx, script).await?;
    let checked = match check_values(&specs, &given, Mode::Policy) {
        Ok(c) => c,
        Err(e) => return Ok(Err(e)),
    };
    if let Err(e) = fields_exist(&mut *tx, &checked.fields).await? {
        return Ok(Err(e));
    }
    let items = checked.vault_items();
    if !items.is_empty() {
        let Some(client) = item_client else {
            return Ok(Err("a policy that takes a secret from the vault must be limited to that vault's client".into()));
        };
        let ok: i64 = sqlx::query_scalar("SELECT count(*) FROM vault_items WHERE id = ANY($1) AND client_id = $2").bind(&items).bind(client).fetch_one(&mut *tx).await?;
        if ok as usize != items.len() {
            return Ok(Err("a vault item the parameters name isn't in the client vault of the client this policy is limited to".into()));
        }
    }
    Ok(Ok(()))
}

/// Why a job can't be delivered, or its environment.
pub type JobEnv = Result<Vec<(String, String)>, String>;

/// The environment of each of these jobs, built when it is sent. An `Err` ends the job as
/// `error` with that text: the agent doesn't support parameters, or the secrets can't be opened.
pub async fn job_env(st: &AppState, jobs: &[Uuid]) -> sqlx::Result<HashMap<Uuid, JobEnv>> {
    #[allow(clippy::type_complexity)]
    let rows: Vec<(Uuid, Value, Option<Vec<u8>>, bool, Uuid, String, String, Option<String>, Uuid, String, Uuid, String)> = sqlx::query_as(
        "SELECT j.id, j.params, j.env_sealed, $2 = ANY(a.capabilities), a.id, a.hostname, a.os_family, a.platform,
                c.id, c.name, s.id, s.name
           FROM jobs j JOIN agents a ON a.id = j.agent_id JOIN sites s ON s.id = a.site_id JOIN clients c ON c.id = s.client_id
          WHERE j.id = ANY($1)",
    )
    .bind(jobs)
    .bind(rmm_proto::SCRIPT_ENV_CAPABILITY)
    .fetch_all(&st.db)
    .await?;
    let mut out = HashMap::new();
    for (job_id, params, sealed, capable, agent_id, hostname, os, platform, client_id, client_name, site_id, site_name) in rows {
        let public = match params {
            Value::Object(m) => m,
            _ => Map::new(),
        };
        let b = Builtins { job_id, agent_id, hostname, os, platform: platform.unwrap_or_default(), client_id, client_name, site_id, site_name };
        let env = if (!public.is_empty() || sealed.is_some()) && !capable {
            Err("agent too old for script parameters".to_string())
        } else {
            match sealed {
                None => Ok(env_vars(&b, &public, &BTreeMap::new())),
                Some(s) => match st.cfg.data_key.as_ref().and_then(|k| open_secrets(k, job_id, &s)) {
                    Some(secrets) => Ok(env_vars(&b, &public, &secrets)),
                    None => Err("the job's secret parameters can't be opened: RMM_DATA_KEY is missing or has changed".to_string()),
                },
            }
        };
        out.insert(job_id, env);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn specs() -> Vec<Spec> {
        validate_specs(&json!([
            { "name": "target", "type": "text", "required": true },
            { "name": "count", "type": "number", "default": 3 },
            { "name": "force", "type": "bool" },
            { "name": "mode", "label": "Mode", "type": "select", "choices": ["fast", "safe"], "default": "safe" },
            { "name": "token", "type": "secret" },
        ]))
        .unwrap()
    }

    #[test]
    fn spec_validation() {
        let s = specs();
        assert_eq!(s[0].label, "target", "the label defaults to the name");
        assert_eq!(s[1].default, Some(json!(3)));
        for bad in [
            json!([{ "name": "Bad", "type": "text" }]),
            json!([{ "name": "a", "type": "text" }, { "name": "a", "type": "bool" }]),
            json!([{ "name": "s", "type": "select" }]),
            json!([{ "name": "s", "type": "select", "choices": ["x", "x"] }]),
            json!([{ "name": "t", "type": "text", "choices": ["x"] }]),
            json!([{ "name": "p", "type": "secret", "default": "hunter2" }]),
            json!([{ "name": "n", "type": "number", "default": "lots" }]),
            json!([{ "name": "n", "type": "number", "default": "{{agent.id}}" }]),
            json!([{ "name": "t", "type": "text", "default": "{{agent.nope}}" }]),
            json!([{ "name": "t", "type": "file" }]),
            json!([{ "name": "t", "type": "text", "extra": 1 }]),
        ] {
            assert!(validate_specs(&bad).is_err(), "{bad}");
        }
        let many: Vec<Value> = (0..31).map(|i| json!({ "name": format!("p{i}"), "type": "text" })).collect();
        assert!(validate_specs(&Value::Array(many)).is_err());
        assert_eq!(validate_specs(&Value::Null).unwrap(), vec![]);
    }

    #[test]
    fn coercion_and_defaults() {
        let s = specs();
        let c = check_values(&s, json!({ "target": "web01", "force": "yes", "token": "t0k" }).as_object().unwrap(), Mode::Run { api_key: false }).unwrap();
        assert_eq!(c.vals["target"], Val::Plain(json!("web01")));
        assert_eq!(c.vals["count"], Val::Plain(json!(3)), "default");
        assert_eq!(c.vals["force"], Val::Plain(json!(true)));
        assert_eq!(c.vals["mode"], Val::Plain(json!("safe")));
        assert_eq!(c.vals["token"], Val::Secret("t0k".into()));
        assert_eq!(c.audit()["token"], json!(MASK), "secrets never reach the audit log");
        let run = Mode::Run { api_key: false };
        assert!(check_values(&s, &Map::new(), run).is_err(), "target is required");
        assert!(check_values(&s, json!({ "target": "x", "nope": 1 }).as_object().unwrap(), run).is_err());
        assert!(check_values(&s, json!({ "target": "x", "count": "many" }).as_object().unwrap(), run).is_err());
        assert!(check_values(&s, json!({ "target": "x", "mode": "reckless" }).as_object().unwrap(), run).is_err());
        assert!(check_values(&s, json!({ "target": "x", "count": "{{agent.id}}" }).as_object().unwrap(), run).is_err());
        assert!(check_values(&s, json!({ "target": "{{agent.bogus}}" }).as_object().unwrap(), run).is_err());
        // Secrets: literal in a run, a vault item in a policy, never a vault item from an API key.
        let v = format!("vault:{}", Uuid::nil());
        assert!(check_values(&s, json!({ "target": "x", "token": "lit" }).as_object().unwrap(), Mode::Policy).is_err());
        let c = check_values(&s, json!({ "target": "x", "token": v }).as_object().unwrap(), Mode::Policy).unwrap();
        assert_eq!(c.vault_items(), vec![Uuid::nil()]);
        assert!(check_values(&s, json!({ "target": "x", "token": v }).as_object().unwrap(), Mode::Run { api_key: true }).is_err());
        let big = "x".repeat(VALUE_MAX + 1);
        assert!(check_values(&s, json!({ "target": big }).as_object().unwrap(), run).is_err());
    }

    #[test]
    fn expansion() {
        let ctx = Ctx {
            agent_id: Uuid::nil(),
            hostname: "web01".into(),
            os: "linux".into(),
            client_name: "Acme".into(),
            site_name: "HQ".into(),
            fields: HashMap::from([("rack".to_string(), "R7".to_string())]),
        };
        assert_eq!(expand("{{agent.hostname}}.{{ client.name }}/{{site.name}}", &ctx), "web01.Acme/HQ");
        assert_eq!(expand("rack={{field.rack}} none={{field.other}}", &ctx), "rack=R7 none=");
        assert_eq!(expand("{{agent.id}} {{agent.os}}", &ctx), format!("{} linux", Uuid::nil()));
        assert_eq!(expand("no placeholders {braces}", &ctx), "no placeholders {braces}");
        assert_eq!(
            placeholders("{{field.rack}}{{agent.os}}").unwrap(),
            vec![Placeholder::Field("rack".into()), Placeholder::AgentOs]
        );
        assert!(placeholders("{{agent.hostname").is_err());
        assert!(placeholders("{{field.Bad}}").is_err());
        // A placeholder's value is inserted as text, never re-scanned.
        let evil = Ctx { hostname: "{{client.name}}".into(), ..ctx };
        assert_eq!(expand("{{agent.hostname}}", &evil), "{{client.name}}");
    }

    #[test]
    fn env_names_and_values() {
        assert_eq!(env_name("target_host"), "RMM_PARAM_TARGET_HOST");
        let s = specs();
        let c = check_values(
            &s,
            json!({ "target": "$(touch /tmp/x); \"'`", "token": "s3cret", "force": false }).as_object().unwrap(),
            Mode::Run { api_key: false },
        )
        .unwrap();
        let p = Prepared::new(&c, &Ctx::default(), &HashMap::new()).unwrap();
        assert_eq!(p.public["token"], json!(MASK));
        assert_eq!(p.secrets["token"], "s3cret");
        let b = Builtins { hostname: "h".into(), ..Default::default() };
        let env: HashMap<String, String> = env_vars(&b, &p.public, &p.secrets).into_iter().collect();
        assert_eq!(env["RMM_PARAM_TARGET"], "$(touch /tmp/x); \"'`", "passed verbatim");
        assert_eq!(env["RMM_PARAM_TOKEN"], "s3cret");
        assert_eq!(env["RMM_PARAM_FORCE"], "false");
        assert_eq!(env["RMM_PARAM_COUNT"], "3");
        assert_eq!(env["RMM_AGENT_HOSTNAME"], "h");
        assert!(env.keys().all(|k| k.starts_with("RMM_") && k.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')));
    }

    #[test]
    fn secrets_are_sealed_per_job() {
        let key = DataKey::from_bytes([5; 32]);
        let p = Prepared { public: Map::new(), secrets: BTreeMap::from([("token".to_string(), "s3cret".to_string())]) };
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let sealed = p.seal(&key, a).unwrap();
        assert!(!sealed.windows(6).any(|w| w == b"s3cret"));
        assert_eq!(open_secrets(&key, a, &sealed).unwrap()["token"], "s3cret");
        assert!(open_secrets(&key, b, &sealed).is_none(), "bound to its job");
        assert!(Prepared::default().seal(&key, a).is_none(), "nothing to seal");
    }

    #[test]
    fn the_body_is_never_touched() {
        // Parameters only ever become environment values: nothing here takes or returns a
        // script body, and the jobs code passes the body through unchanged (see e2e
        // `script_params`). This pins the placeholder syntax to values only.
        let body = "echo {{agent.hostname}} $RMM_PARAM_TARGET";
        let ctx = Ctx { hostname: "web01".into(), ..Default::default() };
        // `expand` is applied to values; a body with braces would only change if someone
        // called it on the body, which no caller does.
        assert_ne!(expand(body, &ctx), body);
        let src = include_str!("api/jobs.rs");
        assert!(!src.contains("expand(&body") && !src.contains("expand(body"), "the job body is never expanded");
    }
}
