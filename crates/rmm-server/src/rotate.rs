//! `rmm-server rotate-data-key`: re-encrypts everything sealed with `RMM_DATA_KEY` under a new
//! key, in one transaction.
//!
//! What `RMM_DATA_KEY` seals (every call site of `crypto.rs` — keep [`TABLES`] in step when
//! one is added; `every_sealed_flag_in_the_migrations_is_listed` below checks the schema):
//!
//! | table                   | columns                                        | flag                |
//! |-------------------------|------------------------------------------------|---------------------|
//! | `users`                 | `totp_secret`, `totp_pending`                  | `totp_sealed`       |
//! | `contact_credentials`   | `totp_secret`, `totp_pending`                  | `totp_sealed`       |
//! | `mailboxes`             | `graph_secret`                                 | `graph_secret_sealed` |
//! | `accounting_connections`| `client_secret`, `access_token`, `refresh_token` | `sealed`          |
//! | `security_detections`   | `context`                                      | `context_encrypted` |
//! | `sso_providers`         | `client_secret`                                | `secret_sealed`     |
//! | `webhook_subscriptions` | `secret`                                       | `secret_sealed`     |
//! | `mailboxes` (second row)| `imap_password_enc`                            | `imap_password_sealed` |
//! | `company_settings`      | `smtp_password_enc`                            | `smtp_password_sealed` |
//! | `notification_channels` | `secret` (webhook channel signing secret)      | `secret_sealed`     |
//! | `siem_destinations`     | `token`                                        | `token_sealed`      |
//! | `net_credentials`       | `secret` (SNMP community or passphrases)       | `secret_sealed`     |
//! | `vault_keys`            | `wrapped_key` (AAD `vault-key:<client id>`)    | always sealed       |
//!
//! The vault's items are sealed with the per-client keys, not with `RMM_DATA_KEY`, so
//! rewrapping `vault_keys` is all the vault needs: no item is touched.
//!
//! # Safe to repeat
//!
//! Each stored value is classified on its own:
//! - opens with the old key: resealed with the new one;
//! - doesn't, but opens with the new one: already rotated, left alone (a run that was
//!   interrupted and rolled back, or a server started with the new key meanwhile, writes
//!   such rows);
//! - flagged as not sealed (stored in the clear, before a key was set): sealed with the new key;
//! - none of these: the whole run stops with nothing written, naming the row. Wrong old key,
//!   or a row that was already unreadable.
//!
//! So the command can be run again after any failure, and running it twice does nothing the
//! second time. Everything happens in one transaction: either all rows move or none do. Rows
//! are locked while it runs, but a *running* server keeps the old key in memory and would
//! write new rows with it, so stop the server first (a row it wrote with the old key is
//! picked up by running this again).

use anyhow::{Context, Result, bail};
use serde_json::json;
use sqlx::Row;

use crate::crypto::DataKey;

/// Rows are read this many at a time (keyset order), so a large table isn't held in memory.
const PAGE: i64 = 500;

pub struct Table {
    pub name: &'static str,
    pub pk: &'static str,
    /// SQL type of the key column, for casting the value bound back from text.
    pub pk_type: &'static str,
    pub columns: &'static [&'static str],
    /// Boolean column saying whether the values are sealed; always sealed when `None`.
    pub flag: Option<&'static str>,
    /// Associated data of each ciphertext: a prefix, followed by the row's key.
    pub aad_prefix: Option<&'static str>,
}

pub const TABLES: &[Table] = &[
    Table { name: "users", pk: "id", pk_type: "uuid", columns: &["totp_secret", "totp_pending"], flag: Some("totp_sealed"), aad_prefix: None },
    Table {
        name: "contact_credentials",
        pk: "contact_id",
        pk_type: "uuid",
        columns: &["totp_secret", "totp_pending"],
        flag: Some("totp_sealed"),
        aad_prefix: None,
    },
    Table { name: "mailboxes", pk: "id", pk_type: "uuid", columns: &["graph_secret"], flag: Some("graph_secret_sealed"), aad_prefix: None },
    Table {
        name: "accounting_connections",
        pk: "provider",
        pk_type: "text",
        columns: &["client_secret", "access_token", "refresh_token"],
        flag: Some("sealed"),
        aad_prefix: None,
    },
    Table { name: "security_detections", pk: "id", pk_type: "uuid", columns: &["context"], flag: Some("context_encrypted"), aad_prefix: None },
    Table { name: "sso_providers", pk: "id", pk_type: "uuid", columns: &["client_secret"], flag: Some("secret_sealed"), aad_prefix: None },
    Table { name: "webhook_subscriptions", pk: "id", pk_type: "uuid", columns: &["secret"], flag: Some("secret_sealed"), aad_prefix: None },
    Table { name: "mailboxes", pk: "id", pk_type: "uuid", columns: &["imap_password_enc"], flag: Some("imap_password_sealed"), aad_prefix: None },
    Table {
        name: "company_settings",
        pk: "id",
        pk_type: "boolean",
        columns: &["smtp_password_enc"],
        flag: Some("smtp_password_sealed"),
        aad_prefix: None,
    },
    Table { name: "notification_channels", pk: "id", pk_type: "uuid", columns: &["secret"], flag: Some("secret_sealed"), aad_prefix: None },
    Table { name: "siem_destinations", pk: "id", pk_type: "uuid", columns: &["token"], flag: Some("token_sealed"), aad_prefix: None },
    Table { name: "net_credentials", pk: "id", pk_type: "uuid", columns: &["secret"], flag: Some("secret_sealed"), aad_prefix: None },
    Table { name: "vault_keys", pk: "client_id", pk_type: "uuid", columns: &["wrapped_key"], flag: None, aad_prefix: Some("vault-key:") },
];

#[derive(Debug, PartialEq, Eq)]
pub enum Rewrap {
    /// Sealed with the old key: here it is under the new one.
    Rotate(Vec<u8>),
    /// Already under the new key.
    Already,
    /// Was stored in the clear: here it is sealed with the new key.
    Seal(Vec<u8>),
}

/// What to do with one stored value. `sealed` is the row's flag. `old` is `None` when the
/// server never had a key (only values stored in the clear can then be handled).
pub fn rewrap(old: Option<&DataKey>, new: &DataKey, stored: &[u8], sealed: bool, aad: Option<&str>) -> Result<Rewrap, &'static str> {
    let open = |k: &DataKey| match aad {
        Some(a) => k.open_aad(stored, a),
        None => k.open(stored),
    };
    let seal = |plain: &[u8]| match aad {
        Some(a) => new.seal_aad(plain, a),
        None => new.seal(plain),
    };
    if !sealed {
        return Ok(Rewrap::Seal(seal(stored)));
    }
    if let Some(plain) = old.and_then(open) {
        return Ok(Rewrap::Rotate(seal(&plain)));
    }
    if open(new).is_some() {
        return Ok(Rewrap::Already);
    }
    Err(if old.is_some() { "opens with neither the old nor the new key" } else { "is sealed, and there is no old key" })
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    pub rotated: u64,
    pub already: u64,
    pub sealed_plain: u64,
}

#[derive(Debug)]
pub struct Report(pub Vec<(&'static str, Counts)>);

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (table, c) in &self.0 {
            writeln!(f, "  {table:<24} {} to rotate, {} stored in the clear to seal, {} already under the new key", c.rotated, c.sealed_plain, c.already)?;
        }
        Ok(())
    }
}

/// Reads the two keys: `RMM_DATA_KEY_OLD` (else the `RMM_DATA_KEY` the server runs with) and
/// `RMM_DATA_KEY_NEW`. Environment only: a key on the command line shows up in `ps` and in
/// shell history.
pub fn keys_from_env() -> Result<(Option<DataKey>, DataKey)> {
    let var = |k: &str| std::env::var(k).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    let old = match var("RMM_DATA_KEY_OLD").or_else(|| var("RMM_DATA_KEY")) {
        Some(k) => Some(DataKey::parse(&k).context("the old key (RMM_DATA_KEY_OLD or RMM_DATA_KEY)")?),
        None => None,
    };
    let new = var("RMM_DATA_KEY_NEW").context("set RMM_DATA_KEY_NEW to the new key (`openssl rand -hex 32`)")?;
    let new = DataKey::parse(&new).context("RMM_DATA_KEY_NEW")?;
    if let Some(o) = &old
        && o.open(&new.seal(b"probe")).is_some()
    {
        bail!("the old and new keys are the same");
    }
    Ok((old, new))
}

/// Rewraps and reseals everything. With `dry_run`, only counts (and still fails on a value
/// that nothing opens, so a wrong old key shows up before the real run).
pub async fn rotate(db: &sqlx::PgPool, old: Option<&DataKey>, new: &DataKey, dry_run: bool) -> Result<Report> {
    let mut tx = db.begin().await?;
    let mut report = Vec::new();
    for t in TABLES {
        let counts = rotate_table(&mut tx, t, old, new, dry_run).await.with_context(|| format!("table {}", t.name))?;
        report.push((t.name, counts));
    }
    if dry_run {
        tx.rollback().await?;
    } else {
        tx.commit().await?;
    }
    Ok(Report(report))
}

async fn rotate_table(tx: &mut sqlx::PgConnection, t: &Table, old: Option<&DataKey>, new: &DataKey, dry_run: bool) -> Result<Counts> {
    let cols = t.columns.join(", ");
    let flag_col = t.flag.map(|f| format!(", {f}")).unwrap_or_default();
    let any = t.columns.iter().map(|c| format!("{c} IS NOT NULL")).collect::<Vec<_>>().join(" OR ");
    let select = format!(
        "SELECT {pk}::text AS pk, {cols}{flag_col} FROM {table} WHERE ({any}) AND ($1::text IS NULL OR {pk} > $1::text::{ty}) ORDER BY {pk} LIMIT {PAGE} FOR UPDATE",
        pk = t.pk,
        table = t.name,
        ty = t.pk_type,
    );
    let set = t.columns.iter().enumerate().map(|(i, c)| format!("{c} = ${}", i + 2)).collect::<Vec<_>>().join(", ");
    let set_flag = t.flag.map(|f| format!(", {f} = true")).unwrap_or_default();
    let update = format!("UPDATE {table} SET {set}{set_flag} WHERE {pk} = $1::text::{ty}", table = t.name, pk = t.pk, ty = t.pk_type);

    let mut counts = Counts::default();
    let mut after: Option<String> = None;
    loop {
        let rows = sqlx::query(sqlx::AssertSqlSafe(select.clone())).bind(after.as_deref()).fetch_all(&mut *tx).await?;
        if rows.is_empty() {
            return Ok(counts);
        }
        for row in &rows {
            let pk: String = row.try_get("pk")?;
            let sealed = match t.flag {
                Some(_) => row.try_get::<bool, _>(t.columns.len() + 1)?,
                None => true,
            };
            let aad = t.aad_prefix.map(|p| format!("{p}{pk}"));
            let mut out: Vec<Option<Vec<u8>>> = Vec::new();
            let mut changed = false;
            for (i, col) in t.columns.iter().enumerate() {
                let Some(stored) = row.try_get::<Option<Vec<u8>>, _>(i + 1)? else {
                    out.push(None);
                    continue;
                };
                match rewrap(old, new, &stored, sealed, aad.as_deref()) {
                    Ok(Rewrap::Rotate(v)) => {
                        counts.rotated += 1;
                        changed = true;
                        out.push(Some(v));
                    }
                    Ok(Rewrap::Seal(v)) => {
                        counts.sealed_plain += 1;
                        changed = true;
                        out.push(Some(v));
                    }
                    Ok(Rewrap::Already) => {
                        counts.already += 1;
                        out.push(Some(stored));
                    }
                    Err(why) => bail!("{}.{col} of row {pk} {why}: is RMM_DATA_KEY_OLD the key the server was running with? Nothing was changed", t.name),
                }
            }
            // The whole row is written, with its flag set: it says "sealed" about every column.
            if changed && !dry_run {
                let mut q = sqlx::query(sqlx::AssertSqlSafe(update.clone())).bind(&pk);
                for v in &out {
                    q = q.bind(v.as_deref());
                }
                q.execute(&mut *tx).await?;
            }
        }
        after = rows.last().map(|r| r.get::<String, _>("pk"));
        if (rows.len() as i64) < PAGE {
            return Ok(counts);
        }
    }
}

/// The (table, flag) pairs of [`TABLES`] whose values the server seals at startup when a key is
/// set and they were stored in the clear (the credentials that were plaintext before 0031).
const SEALED_AT_STARTUP: &[(&str, &str)] = &[
    ("mailboxes", "imap_password_sealed"),
    ("company_settings", "smtp_password_sealed"),
    ("notification_channels", "secret_sealed"),
];

/// Seals what 0031 moved over in the clear. Without a key, values that are already sealed can't
/// be read: the server refuses to start rather than send mail with a garbage password.
pub async fn seal_plaintext_credentials(db: &sqlx::PgPool, key: Option<&DataKey>) -> Result<()> {
    for t in TABLES.iter().filter(|t| SEALED_AT_STARTUP.iter().any(|(n, f)| *n == t.name && Some(*f) == t.flag)) {
        let flag = t.flag.expect("filtered on the flag");
        let any = t.columns.iter().map(|c| format!("{c} IS NOT NULL")).collect::<Vec<_>>().join(" OR ");
        let Some(key) = key else {
            let (n,): (i64,) = sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {} WHERE {flag} AND ({any})", t.name))).fetch_one(db).await?;
            anyhow::ensure!(
                n == 0,
                "{n} row(s) of {} hold credentials encrypted with RMM_DATA_KEY, but it isn't set; set it again",
                t.name
            );
            continue;
        };
        // One transaction per table: the row is locked while it is read, sealed and written.
        let mut tx = db.begin().await?;
        let counts = rotate_table_plain(&mut tx, t, key).await.with_context(|| format!("sealing {}", t.name))?;
        tx.commit().await?;
        if counts > 0 {
            tracing::info!(table = t.name, rows = counts, "encrypted credentials with RMM_DATA_KEY");
        }
    }
    Ok(())
}

/// Seals the rows of `t` flagged as not sealed; leaves the rest alone.
async fn rotate_table_plain(tx: &mut sqlx::PgConnection, t: &Table, key: &DataKey) -> Result<u64> {
    let flag = t.flag.expect("a flag");
    let cols = t.columns.join(", ");
    let any = t.columns.iter().map(|c| format!("{c} IS NOT NULL")).collect::<Vec<_>>().join(" OR ");
    let select = format!("SELECT {pk}::text AS pk, {cols} FROM {table} WHERE NOT {flag} AND ({any}) FOR UPDATE", pk = t.pk, table = t.name);
    let set = t.columns.iter().enumerate().map(|(i, c)| format!("{c} = ${}", i + 2)).collect::<Vec<_>>().join(", ");
    let update = format!("UPDATE {table} SET {set}, {flag} = true WHERE {pk} = $1::text::{ty}", table = t.name, pk = t.pk, ty = t.pk_type);
    let rows = sqlx::query(sqlx::AssertSqlSafe(select)).fetch_all(&mut *tx).await?;
    for row in &rows {
        let pk: String = row.try_get("pk")?;
        let mut q = sqlx::query(sqlx::AssertSqlSafe(update.clone())).bind(&pk);
        for i in 0..t.columns.len() {
            let stored: Option<Vec<u8>> = row.try_get(i + 1)?;
            q = q.bind(stored.map(|s| key.seal(&s)));
        }
        q.execute(&mut *tx).await?;
    }
    Ok(rows.len() as u64)
}

/// The audit-log entry of a finished (not dry) run.
pub fn audit_details(report: &Report) -> serde_json::Value {
    json!({ "via": "cli", "tables": report.0.iter().map(|(t, c)| json!({ "table": t, "rotated": c.rotated, "sealed_plain": c.sealed_plain, "already": c.already })).collect::<Vec<_>>() })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> DataKey {
        DataKey::from_bytes([b; 32])
    }

    #[test]
    fn rotates_what_the_old_key_opens() {
        let (old, new) = (key(1), key(2));
        let stored = old.seal(b"totp secret");
        let Ok(Rewrap::Rotate(v)) = rewrap(Some(&old), &new, &stored, true, None) else { panic!("expected a rotation") };
        assert_eq!(new.open(&v).unwrap(), b"totp secret");
        assert!(old.open(&v).is_none(), "the old key no longer opens it");
    }

    #[test]
    fn the_associated_data_survives() {
        let (old, new) = (key(1), key(2));
        let stored = old.seal_aad(&[7u8; 32], "vault-key:c1");
        let Ok(Rewrap::Rotate(v)) = rewrap(Some(&old), &new, &stored, true, Some("vault-key:c1")) else { panic!("expected a rotation") };
        assert_eq!(new.open_aad(&v, "vault-key:c1").unwrap(), [7u8; 32]);
        assert!(new.open_aad(&v, "vault-key:c2").is_none(), "still bound to its client");
        // Wrong AAD for the row: nothing opens it, so the run stops rather than guessing.
        assert!(rewrap(Some(&old), &new, &stored, true, Some("vault-key:c2")).is_err());
    }

    #[test]
    fn running_twice_changes_nothing() {
        let (old, new) = (key(1), key(2));
        let stored = old.seal(b"x");
        let Ok(Rewrap::Rotate(v)) = rewrap(Some(&old), &new, &stored, true, None) else { panic!() };
        assert_eq!(rewrap(Some(&old), &new, &v, true, None), Ok(Rewrap::Already));
    }

    #[test]
    fn values_in_the_clear_are_sealed() {
        let (old, new) = (key(1), key(2));
        let Ok(Rewrap::Seal(v)) = rewrap(Some(&old), &new, b"plain", false, None) else { panic!() };
        assert_eq!(new.open(&v).unwrap(), b"plain");
        // Even with no old key at all (a server that never had one).
        assert!(matches!(rewrap(None, &new, b"plain", false, None), Ok(Rewrap::Seal(_))));
    }

    #[test]
    fn a_wrong_old_key_is_an_error() {
        let (old, new, other) = (key(1), key(2), key(3));
        let stored = old.seal(b"x");
        assert!(rewrap(Some(&other), &new, &stored, true, None).is_err());
        assert!(rewrap(None, &new, &stored, true, None).is_err());
        assert!(rewrap(Some(&old), &new, b"short", true, None).is_err());
    }

    /// A migration that adds a `*sealed` / `*encrypted` flag column for a new sealed value has to
    /// add it to [`TABLES`] too, or its rows would silently stay under the old key.
    #[test]
    fn every_sealed_flag_in_the_migrations_is_listed() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
        let listed: Vec<&str> = TABLES.iter().filter_map(|t| t.flag).collect();
        let mut found = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let sql = std::fs::read_to_string(entry.unwrap().path()).unwrap();
            for line in sql.lines().filter(|l| !l.trim_start().starts_with("--")) {
                let words: Vec<&str> = line.split(|c: char| !(c.is_alphanumeric() || c == '_')).filter(|w| !w.is_empty()).collect();
                for pair in words.windows(2) {
                    if pair[1] == "boolean" && (pair[0].contains("sealed") || pair[0].contains("encrypted")) {
                        found.push(pair[0].to_string());
                    }
                }
            }
        }
        assert!(found.len() >= listed.len(), "the scan finds the flags: {found:?}");
        for f in &found {
            assert!(listed.contains(&f.as_str()), "sealed flag column {f} isn't rotated: add its table to rotate::TABLES");
        }
        for t in TABLES {
            assert!(t.columns.iter().all(|c| !c.is_empty()) && !t.pk.is_empty());
        }
    }

    #[test]
    fn keys_come_from_the_environment_only() {
        // (Process-wide, so this is the one test that touches these variables.)
        unsafe {
            std::env::remove_var("RMM_DATA_KEY_OLD");
            std::env::set_var("RMM_DATA_KEY", "ab".repeat(32));
            std::env::remove_var("RMM_DATA_KEY_NEW");
        }
        assert!(keys_from_env().is_err(), "the new key is required");
        unsafe { std::env::set_var("RMM_DATA_KEY_NEW", "ab".repeat(32)) };
        assert!(keys_from_env().is_err(), "the same key twice");
        unsafe { std::env::set_var("RMM_DATA_KEY_NEW", "cd".repeat(32)) };
        let (old, new) = keys_from_env().unwrap();
        let stored = DataKey::parse(&"ab".repeat(32)).unwrap().seal(b"x");
        assert!(old.unwrap().open(&stored).is_some(), "RMM_DATA_KEY is the old key by default");
        assert!(new.open(&stored).is_none());
        unsafe {
            std::env::set_var("RMM_DATA_KEY_OLD", "ef".repeat(32));
            std::env::set_var("RMM_DATA_KEY_NEW", "not a key");
        }
        assert!(keys_from_env().is_err());
        unsafe {
            std::env::remove_var("RMM_DATA_KEY_OLD");
            std::env::remove_var("RMM_DATA_KEY");
            std::env::remove_var("RMM_DATA_KEY_NEW");
        }
    }
}
