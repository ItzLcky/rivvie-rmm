//! Custom fields: what a value may be, and how scripts set them.
//!
//! A field has a kind (text, number, bool, date, select); its values are stored as JSON of that
//! kind (see migration 0029). People, API keys and scripts all go through [`coerce`], so a value
//! is checked the same way wherever it comes from.
//!
//! **Script output → field.** A script run on an agent can set fields of that agent by printing
//! lines of the form
//!
//! ```text
//! RMM-FIELD warranty_end=2027-03-01
//! ```
//!
//! on **stdout**, starting in the first column. When the job finishes with `succeeded`, the
//! server reads the stored output ([`apply_job_output`]) and for each marker:
//!
//! * the field must exist for agents, be flagged *script-writable* by an admin, and apply to the
//!   agent's client (a field limited to another client is ignored);
//! * the value is checked against the field's kind (a select must be one of its options) and
//!   anything that doesn't fit is skipped, never stored;
//! * an empty value clears the field; when a name is printed twice the last line wins;
//! * the change is recorded in the audit log (`agent.field_script`) with the job, the fields set
//!   and what was refused and why.
//!
//! A marker is only a request: a field nobody flagged can't be written, and a script can only
//! reach the agent it ran on. Because the marker is plain text, a script that echoes untrusted
//! content (a log file, a web page) could be made to print one; flag only the fields where that
//! is acceptable. Only the first [`JOB_OUTPUT_CAP`](crate::agent_ws) bytes of output are stored, so print
//! markers early in a chatty script.

use chrono::NaiveDate;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::state::AppState;

/// The longest text value, in characters.
pub const TEXT_MAX: usize = 2000;
/// Markers read from one job's output; more are ignored.
const MARKER_MAX: usize = 64;

pub const KINDS: &[&str] = &["text", "number", "bool", "date", "select"];

/// The value to store for `input` in a field of `kind`: `Ok(None)` clears the field (JSON `null`
/// or an empty string), `Err` says why it doesn't fit. Strings are accepted for every kind (a
/// script only has strings): `"42"` for a number, `"yes"` for a bool.
pub fn coerce(kind: &str, options: &[String], input: &Value) -> Result<Option<Value>, String> {
    if input.is_null() {
        return Ok(None);
    }
    // An empty (or blank) string clears the field.
    let text = input.as_str().map(str::trim);
    if text == Some("") {
        return Ok(None);
    }
    match kind {
        "text" => {
            let Value::String(s) = input else { return Err("expected text".into()) };
            let s = s.trim();
            if s.chars().count() > TEXT_MAX {
                return Err(format!("longer than {TEXT_MAX} characters"));
            }
            if s.chars().any(|c| c.is_control() && c != '\n' && c != '\t') {
                return Err("contains control characters".into());
            }
            Ok(Some(Value::String(s.to_string())))
        }
        "number" => {
            let n = match input {
                Value::Number(n) => n.as_f64(),
                Value::String(_) => text.and_then(|t| t.parse::<f64>().ok()),
                _ => None,
            };
            match n {
                Some(n) if n.is_finite() && n.abs() < 1e15 => {
                    // Whole numbers stay integers, so 42 reads back as 42 and not 42.0.
                    if n.fract() == 0.0 { Ok(Some(json!(n as i64))) } else { Ok(Some(json!(n))) }
                }
                _ => Err("expected a number".into()),
            }
        }
        "bool" => match input {
            Value::Bool(b) => Ok(Some(Value::Bool(*b))),
            Value::String(_) => match text.map(str::to_ascii_lowercase).as_deref() {
                Some("true" | "yes" | "y" | "1" | "on") => Ok(Some(Value::Bool(true))),
                Some("false" | "no" | "n" | "0" | "off") => Ok(Some(Value::Bool(false))),
                _ => Err("expected true or false".into()),
            },
            _ => Err("expected true or false".into()),
        },
        "date" => {
            let Value::String(_) = input else { return Err("expected a date as YYYY-MM-DD".into()) };
            match text.and_then(|t| NaiveDate::parse_from_str(t, "%Y-%m-%d").ok()) {
                Some(d) => Ok(Some(Value::String(d.format("%Y-%m-%d").to_string()))),
                None => Err("expected a date as YYYY-MM-DD".into()),
            }
        }
        "select" => {
            let Value::String(_) = input else { return Err("expected one of the options".into()) };
            let t = text.unwrap_or_default();
            // Exact match first, then ignoring case (scripts are careless about it).
            let hit = options.iter().find(|o| o.as_str() == t).or_else(|| options.iter().find(|o| o.eq_ignore_ascii_case(t)));
            match hit {
                Some(o) => Ok(Some(Value::String(o.clone()))),
                None => Err(format!("not one of: {}", options.join(", "))),
            }
        }
        k => Err(format!("unknown field type {k}")),
    }
}

/// `(name, value)` of every `RMM-FIELD name=value` line of `stdout`, in order.
pub fn parse_markers(stdout: &str) -> Vec<(String, String)> {
    stdout
        .lines()
        .filter_map(|line| {
            let rest = line.trim_end_matches('\r').strip_prefix("RMM-FIELD ")?;
            let (name, value) = rest.split_once('=')?;
            let name = name.trim().to_ascii_lowercase();
            valid_name(&name).then(|| (name, value.trim().to_string()))
        })
        .take(MARKER_MAX)
        .collect()
}

/// A field's `name`: lowercase letters, digits and underscores, starting with a letter.
pub fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && name.len() <= 40
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Reads the output of a job that just succeeded and sets the agent's script-writable fields it
/// asks for (see the module docs). Never fails the job: problems are logged and audited.
pub async fn apply_job_output(st: &AppState, agent_id: Uuid, job_id: Uuid) {
    if let Err(e) = apply(st, agent_id, job_id).await {
        tracing::warn!(%agent_id, %job_id, "setting fields from script output failed: {e}");
    }
}

#[derive(sqlx::FromRow)]
struct Def {
    id: Uuid,
    name: String,
    kind: String,
    options: Vec<String>,
    script_writable: bool,
}

async fn apply(st: &AppState, agent_id: Uuid, job_id: Uuid) -> Result<(), sqlx::Error> {
    let stdout: Option<String> = sqlx::query_scalar("SELECT stdout FROM jobs WHERE id = $1 AND agent_id = $2 AND status = 'succeeded'")
        .bind(job_id)
        .bind(agent_id)
        .fetch_optional(&st.db)
        .await?;
    // The marker is cheap to look for; most jobs have none.
    let Some(stdout) = stdout.filter(|s| s.contains("RMM-FIELD ")) else { return Ok(()) };
    let markers = parse_markers(&stdout);
    if markers.is_empty() {
        return Ok(());
    }
    let client: Option<Uuid> = sqlx::query_scalar("SELECT s.client_id FROM agents a JOIN sites s ON s.id = a.site_id WHERE a.id = $1")
        .bind(agent_id)
        .fetch_optional(&st.db)
        .await?;
    let Some(client) = client else { return Ok(()) };
    let defs: Vec<Def> = sqlx::query_as(
        "SELECT id, name, kind, options, script_writable FROM custom_fields
          WHERE entity = 'agent' AND (client_id IS NULL OR client_id = $1)",
    )
    .bind(client)
    .fetch_all(&st.db)
    .await?;

    // The last line of a name wins.
    let mut last: Vec<(String, String)> = Vec::new();
    for (n, v) in markers {
        last.retain(|(k, _)| *k != n);
        last.push((n, v));
    }
    let mut set = Vec::new();
    let mut refused = Vec::new();
    let mut tx = st.db.begin().await?;
    for (name, raw) in last {
        let Some(def) = defs.iter().find(|d| d.name == name) else {
            refused.push(json!({ "name": name, "reason": "no such field for this agent" }));
            continue;
        };
        if !def.script_writable {
            refused.push(json!({ "name": name, "reason": "the field isn't flagged as script-writable" }));
            continue;
        }
        match coerce(&def.kind, &def.options, &Value::String(raw)) {
            Ok(Some(value)) => {
                sqlx::query(
                    "INSERT INTO custom_field_values (field_id, agent_id, value, source, updated_by, job_id, updated_at)
                     VALUES ($1, $2, $3, 'script', NULL, $4, now())
                     ON CONFLICT (agent_id, field_id) WHERE agent_id IS NOT NULL
                     DO UPDATE SET value = $3, source = 'script', updated_by = NULL, job_id = $4, updated_at = now()",
                )
                .bind(def.id)
                .bind(agent_id)
                .bind(&value)
                .bind(job_id)
                .execute(&mut *tx)
                .await?;
                set.push(json!({ "name": name, "value": value }));
            }
            Ok(None) => {
                sqlx::query("DELETE FROM custom_field_values WHERE field_id = $1 AND agent_id = $2")
                    .bind(def.id)
                    .bind(agent_id)
                    .execute(&mut *tx)
                    .await?;
                set.push(json!({ "name": name, "value": Value::Null }));
            }
            Err(reason) => refused.push(json!({ "name": name, "reason": reason })),
        }
    }
    tx.commit().await?;
    crate::auth::audit(&st.db, None, "agent.field_script", Some(("agent", agent_id)), json!({ "job_id": job_id, "set": set, "refused": refused })).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(o: &[&str]) -> Vec<String> {
        o.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn text_is_trimmed_and_bounded() {
        assert_eq!(coerce("text", &[], &json!("  hello  ")).unwrap(), Some(json!("hello")));
        assert_eq!(coerce("text", &[], &json!("")).unwrap(), None);
        assert_eq!(coerce("text", &[], &json!("   ")).unwrap(), None);
        assert_eq!(coerce("text", &[], &Value::Null).unwrap(), None);
        assert!(coerce("text", &[], &json!(5)).is_err());
        assert!(coerce("text", &[], &json!("a\u{0007}b")).is_err());
        assert!(coerce("text", &[], &json!("x".repeat(TEXT_MAX + 1))).is_err());
        assert!(coerce("text", &[], &json!("x".repeat(TEXT_MAX))).is_ok());
        assert_eq!(coerce("text", &[], &json!("a\nb\tc")).unwrap(), Some(json!("a\nb\tc")));
    }

    #[test]
    fn numbers_come_from_numbers_and_strings() {
        assert_eq!(coerce("number", &[], &json!(42)).unwrap(), Some(json!(42)));
        assert_eq!(coerce("number", &[], &json!("42")).unwrap(), Some(json!(42)));
        assert_eq!(coerce("number", &[], &json!("42.0")).unwrap(), Some(json!(42)));
        assert_eq!(coerce("number", &[], &json!(" -3.5 ")).unwrap(), Some(json!(-3.5)));
        for bad in ["abc", "NaN", "inf", "1e999", "1e16", "4 2"] {
            assert!(coerce("number", &[], &json!(bad)).is_err(), "{bad}");
        }
        assert!(coerce("number", &[], &json!(true)).is_err());
    }

    #[test]
    fn bools_accept_the_usual_words() {
        for t in ["true", "TRUE", "yes", "Y", "1", "on"] {
            assert_eq!(coerce("bool", &[], &json!(t)).unwrap(), Some(json!(true)), "{t}");
        }
        for f in ["false", "No", "n", "0", "OFF"] {
            assert_eq!(coerce("bool", &[], &json!(f)).unwrap(), Some(json!(false)), "{f}");
        }
        assert_eq!(coerce("bool", &[], &json!(true)).unwrap(), Some(json!(true)));
        assert!(coerce("bool", &[], &json!("maybe")).is_err());
        assert!(coerce("bool", &[], &json!(1)).is_err());
    }

    #[test]
    fn dates_are_iso_days() {
        assert_eq!(coerce("date", &[], &json!("2027-03-01")).unwrap(), Some(json!("2027-03-01")));
        assert_eq!(coerce("date", &[], &json!("2027-3-1")).unwrap(), Some(json!("2027-03-01")));
        for bad in ["2027-02-30", "01/03/2027", "yesterday", "2027-03-01T10:00:00Z"] {
            assert!(coerce("date", &[], &json!(bad)).is_err(), "{bad}");
        }
        assert!(coerce("date", &[], &json!(20270301)).is_err());
    }

    #[test]
    fn selects_must_be_an_option() {
        let o = opts(&["Gold", "Silver", "Bronze"]);
        assert_eq!(coerce("select", &o, &json!("Gold")).unwrap(), Some(json!("Gold")));
        assert_eq!(coerce("select", &o, &json!("silver")).unwrap(), Some(json!("Silver")));
        assert!(coerce("select", &o, &json!("Platinum")).unwrap_err().contains("Gold"));
        assert_eq!(coerce("select", &o, &json!("")).unwrap(), None);
    }

    #[test]
    fn markers_are_read_from_stdout_lines() {
        let out = "starting\nRMM-FIELD warranty_end=2027-03-01\r\nRMM-FIELD Owner = Alice Smith \n  RMM-FIELD indented=1\nRMM-FIELD bad name=1\nRMM-FIELD =x\nRMM-FIELDS a=b\nnot RMM-FIELD a=b\nRMM-FIELD empty=\nRMM-FIELD noequals\n";
        assert_eq!(
            parse_markers(out),
            vec![("warranty_end".into(), "2027-03-01".into()), ("owner".into(), "Alice Smith".into()), ("empty".into(), "".into())]
        );
        let many: String = (0..200).map(|i| format!("RMM-FIELD f{i}=1\n")).collect();
        assert_eq!(parse_markers(&many).len(), MARKER_MAX);
    }

    #[test]
    fn names() {
        for ok in ["a", "warranty_end", "x1", &"a".repeat(40)] {
            assert!(valid_name(ok), "{ok}");
        }
        for bad in ["", "1a", "_a", "A", "a-b", "a b", &"a".repeat(41)] {
            assert!(!valid_name(bad), "{bad}");
        }
    }
}
