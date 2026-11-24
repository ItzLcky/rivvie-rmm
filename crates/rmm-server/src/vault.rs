//! The vault's sealing, and its **system write path** (docs/design/vault-managed.md).
//!
//! Envelope encryption (docs/design/documentation.md#password-vault): each client has a random
//! key, wrapped with `RMM_DATA_KEY` ("vault-key:<client id>" as associated data), that seals an
//! item's password, notes and TOTP secret ("<item id>:<column>"). The HTTP API over it is
//! `api/vault.rs`; this module is what both it and server features use.
//!
//! # Managed items
//!
//! Some credentials are kept by the server rather than typed in by a person: BitLocker recovery
//! passwords, rotated local admin passwords, passwords set by an identity reset. Those features
//! call [`put_managed`], which stores the secret in the device's client vault as a *managed*
//! item, identified by `(client, kind, reference)`:
//!
//! - the first call creates the item, later calls with the same key update it (an upsert);
//! - a changed password moves the previous one to the item's history (the last 10 are kept),
//!   exactly as a person's edit does; writing the same password again changes nothing there;
//! - every call is audited as `vault.system_write`, naming the fields that changed, never a value;
//! - people can reveal a managed item as any other (2FA, rate limit, `vault.reveal`), rename it,
//!   change its URL or notes, and delete it with `vault.manage`, but not change its password or
//!   username (`PUT /vault/{id}` answers 409): the feature that owns it does that.
//!
//! Without `RMM_DATA_KEY` nothing can be stored: [`put_managed`] answers
//! [`ApiError::Conflict`] with [`NEEDS_KEY`], and callers must report that and do nothing else
//! (LAPS must never rotate a password it can't keep).
//!
//! ```ignore
//! let id = vault::put_managed(
//!     &st,
//!     client_id,
//!     Managed {
//!         kind: ManagedKind::DiskRecovery,
//!         agent_id: Some(agent_id),
//!         reference: format!("{agent_id}:C:"),
//!         name: format!("BitLocker recovery: {hostname} C:"),
//!         username: protector_id,
//!         ..Default::default()
//!     },
//!     &recovery_password,
//!     Source::system("diskenc"),
//! )
//! .await?;
//! ```

use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth;
use crate::crypto::DataKey;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Earlier passwords kept per item.
pub const HISTORY_KEPT: i64 = 10;

/// What callers report when the server has no `RMM_DATA_KEY`.
pub const NEEDS_KEY: &str = "the vault needs RMM_DATA_KEY to be set on the server";

/// The longest password (or recovery key) an item holds, in characters.
pub const PASSWORD_MAX: usize = 1000;
/// The longest notes, in characters.
pub const NOTES_MAX: usize = 20_000;

/// The client's vault key, made on first use. Two first uses at once both end up with the one
/// that was stored.
pub async fn client_key(db: &PgPool, master: &DataKey, client: Uuid) -> ApiResult<DataKey> {
    let aad = format!("vault-key:{client}");
    let load = || sqlx::query_scalar::<_, Vec<u8>>("SELECT wrapped_key FROM vault_keys WHERE client_id = $1").bind(client).fetch_optional(db);
    let wrapped = match load().await? {
        Some(w) => w,
        None => {
            let mut raw = [0u8; 32];
            getrandom::fill(&mut raw).expect("OS RNG unavailable");
            sqlx::query("INSERT INTO vault_keys (client_id, wrapped_key) VALUES ($1, $2) ON CONFLICT (client_id) DO NOTHING")
                .bind(client)
                .bind(master.seal_aad(&raw, &aad))
                .execute(db)
                .await
                .map_err(|e| match e {
                    sqlx::Error::Database(d) if d.is_foreign_key_violation() => ApiError::NotFound("client"),
                    e => e.into(),
                })?;
            load().await?.ok_or(ApiError::NotFound("client"))?
        }
    };
    let raw: [u8; 32] = master
        .open_aad(&wrapped, &aad)
        .and_then(|k| k.try_into().ok())
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("can't unwrap the vault key of client {client}: RMM_DATA_KEY has changed")))?;
    Ok(DataKey::from_bytes(raw))
}

/// Seals one column of one item ("<item id>:<field>" as associated data).
pub fn seal(key: &DataKey, item: Uuid, field: &str, plain: &[u8]) -> Vec<u8> {
    key.seal_aad(plain, &format!("{item}:{field}"))
}

/// Opens what [`seal`] sealed for the same item and column.
pub fn open(key: &DataKey, item: Uuid, field: &str, sealed: &[u8]) -> ApiResult<Vec<u8>> {
    key.open_aad(sealed, &format!("{item}:{field}"))
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("vault item {item}: {field} doesn't decrypt")))
}

/// The current password of `item`, which must belong to `client` (else 404), for server
/// features that hand a stored secret to an agent (a script parameter taken from the vault,
/// LAPS retrying a rotation). `None` when the item has no password. Nothing is audited here:
/// the caller records why it read it (`vault.use`, ...).
pub async fn read_password(db: &PgPool, master: &DataKey, client: Uuid, item: Uuid) -> ApiResult<Option<String>> {
    let row: Option<Option<Vec<u8>>> = sqlx::query_scalar("SELECT password FROM vault_items WHERE id = $1 AND client_id = $2")
        .bind(item)
        .bind(client)
        .fetch_optional(db)
        .await?;
    let Some(sealed) = row.ok_or(ApiError::NotFound("credential"))? else { return Ok(None) };
    let key = client_key(db, master, client).await?;
    Ok(Some(String::from_utf8_lossy(&open(&key, item, "password", &sealed)?).into_owned()))
}

/// Collapses runs of whitespace; 1-200 characters.
pub fn clean_name(s: &str) -> ApiResult<String> {
    let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if s.is_empty() || s.chars().count() > 200 {
        return Err(ApiError::BadRequest("name must be 1-200 characters".into()));
    }
    Ok(s)
}

pub fn clean_username(s: &str) -> ApiResult<String> {
    let s = s.trim().to_string();
    if s.chars().count() > 200 {
        return Err(ApiError::BadRequest("the username is limited to 200 characters".into()));
    }
    Ok(s)
}

/// Shown as a link to open, so no script or data URLs.
pub fn clean_url(s: &str) -> ApiResult<String> {
    let s = s.trim().to_string();
    if s.chars().count() > 2000 {
        return Err(ApiError::BadRequest("the URL is limited to 2,000 characters".into()));
    }
    let lower = s.to_ascii_lowercase().replace(|c: char| c.is_ascii_whitespace() || c.is_ascii_control(), "");
    if ["javascript:", "data:", "vbscript:", "file:", "blob:"].iter().any(|p| lower.starts_with(p)) {
        return Err(ApiError::BadRequest("the URL must be a web address or host name".into()));
    }
    Ok(s)
}

/// What kind of managed item: which feature owns it. Stored in `vault_items.managed_kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ManagedKind {
    /// A BitLocker recovery password (`reference` = "<agent id>:<volume>").
    #[default]
    DiskRecovery,
    /// The rotated password of a device's managed local admin account (`reference` = agent id).
    LocalAdmin,
    /// A password set by an AD or Entra reset (`reference` = "<source>:<external id>").
    Identity,
}

impl ManagedKind {
    pub const ALL: &[ManagedKind] = &[ManagedKind::DiskRecovery, ManagedKind::LocalAdmin, ManagedKind::Identity];

    pub fn as_str(self) -> &'static str {
        match self {
            ManagedKind::DiskRecovery => "disk_recovery",
            ManagedKind::LocalAdmin => "local_admin",
            ManagedKind::Identity => "identity",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|k| k.as_str() == s)
    }
}

/// The non-secret part of a managed item. `name`, `username` and `url` are metadata in the clear
/// (lists and search show them); `notes` is sealed like a person's notes.
#[derive(Debug, Clone, Default)]
pub struct Managed {
    pub kind: ManagedKind,
    /// The device it belongs to, if any. `None` on an update leaves the stored one alone; the
    /// link is cleared (not the item) when the device is deleted.
    pub agent_id: Option<Uuid>,
    /// The caller's key for the item within `kind` and the client, 1-200 characters. The same
    /// reference always reaches the same item.
    pub reference: String,
    pub name: String,
    pub username: String,
    pub url: String,
    /// `None` on an update leaves the stored notes alone; `Some("")` clears them.
    pub notes: Option<String>,
    /// Feature-defined progress shown next to the item (`pending`, `ok`...), up to 40
    /// characters. `None` on an update leaves it alone. See also [`set_managed_state`].
    pub state: Option<String>,
}

/// Who wrote a managed item, for the audit log: the feature (`diskenc`, `local_admin`,
/// `identity`...) and, when a person's action caused it, that user.
#[derive(Debug, Clone, Copy)]
pub struct Source {
    pub feature: &'static str,
    pub user: Option<Uuid>,
}

impl Source {
    /// Written by the server on its own (an agent report, a schedule).
    pub fn system(feature: &'static str) -> Self {
        Self { feature, user: None }
    }

    /// Written because `user` asked for it (a reset they started).
    #[allow(dead_code)] // the API disk encryption, LAPS and identity build on
    pub fn user(feature: &'static str, user: Uuid) -> Self {
        Self { feature, user: Some(user) }
    }
}

/// Creates or updates the managed item `(client_id, m.kind, m.reference)` and stores `password`
/// in it, sealed with the client's key; returns the item's id. See the module docs for the
/// rules. Errors: [`ApiError::Conflict`] ([`NEEDS_KEY`]) without `RMM_DATA_KEY`,
/// [`ApiError::NotFound`] for an unknown client or agent, [`ApiError::BadRequest`] for a field
/// out of bounds (never echoing the password).
#[allow(dead_code)] // the API disk encryption, LAPS and identity build on
pub async fn put_managed(st: &AppState, client_id: Uuid, m: Managed, password: &str, source: Source) -> ApiResult<Uuid> {
    let master = st.cfg.data_key.as_ref().ok_or_else(|| ApiError::Conflict(NEEDS_KEY.into()))?;
    put_managed_with(&st.db, master, client_id, m, password, source).await
}

/// [`put_managed`] with the pool and key passed in (the CLI has no `AppState`).
pub async fn put_managed_with(db: &PgPool, master: &DataKey, client_id: Uuid, m: Managed, password: &str, source: Source) -> ApiResult<Uuid> {
    let reference = m.reference.trim();
    if reference.is_empty() || reference.chars().count() > 200 {
        return Err(ApiError::BadRequest("a managed item's reference must be 1-200 characters".into()));
    }
    let name = clean_name(&m.name)?;
    let username = clean_username(&m.username)?;
    let url = clean_url(&m.url)?;
    if password.is_empty() || password.chars().count() > PASSWORD_MAX {
        return Err(ApiError::BadRequest(format!("the password must be 1-{PASSWORD_MAX} characters")));
    }
    if m.notes.as_ref().is_some_and(|n| n.chars().count() > NOTES_MAX) {
        return Err(ApiError::BadRequest(format!("the notes are limited to {NOTES_MAX} characters")));
    }
    let state = m.state.as_deref().map(str::trim);
    if state.is_some_and(|s| s.is_empty() || s.chars().count() > 40) {
        return Err(ApiError::BadRequest("a managed state is 1-40 characters".into()));
    }
    let key = client_key(db, master, client_id).await?;
    let kind = m.kind.as_str();
    let fk = |e: sqlx::Error| match e {
        sqlx::Error::Database(d) if d.is_foreign_key_violation() => ApiError::NotFound("agent"),
        e => e.into(),
    };

    let mut tx = db.begin().await?;
    // Serializes writers of the same item, including two first writes.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('rmm.vault.managed:' || $1 || ':' || $2 || ':' || $3))")
        .bind(client_id.to_string())
        .bind(kind)
        .bind(reference)
        .execute(&mut *tx)
        .await?;
    type Cur = (Uuid, String, String, String, Option<Vec<u8>>, Option<Uuid>, Option<String>, bool);
    let cur: Option<Cur> = sqlx::query_as(
        "SELECT id, name, username, url, password, agent_id, managed_state, notes IS NOT NULL FROM vault_items
          WHERE client_id = $1 AND managed_kind = $2 AND managed_ref = $3 FOR UPDATE",
    )
    .bind(client_id)
    .bind(kind)
    .bind(reference)
    .fetch_optional(&mut *tx)
    .await?;
    let notes = m.notes.as_deref().map(|n| if n.is_empty() { None } else { Some(n) });

    let (id, created, fields) = match cur {
        None => {
            let id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO vault_items (id, client_id, name, username, url, password, notes, password_changed_at, created_by, updated_by,
                                          managed_kind, agent_id, managed_ref, managed_state)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, now(), $8, $8, $9, $10, $11, $12)",
            )
            .bind(id)
            .bind(client_id)
            .bind(&name)
            .bind(&username)
            .bind(&url)
            .bind(seal(&key, id, "password", password.as_bytes()))
            .bind(notes.flatten().map(|n| seal(&key, id, "notes", n.as_bytes())))
            .bind(source.user)
            .bind(kind)
            .bind(m.agent_id)
            .bind(reference)
            .bind(state)
            .execute(&mut *tx)
            .await
            .map_err(fk)?;
            let mut fields = vec!["password"];
            if notes.flatten().is_some() {
                fields.push("notes");
            }
            (id, true, fields)
        }
        Some((id, cur_name, cur_user, cur_url, cur_pw, cur_agent, cur_state, had_notes)) => {
            let old = cur_pw.as_deref().map(|c| open(&key, id, "password", c)).transpose()?;
            let pw_changed = old.as_deref() != Some(password.as_bytes());
            let mut fields = Vec::new();
            for (f, changed) in [
                ("name", name != cur_name),
                ("username", username != cur_user),
                ("url", url != cur_url),
                ("password", pw_changed),
                ("notes", notes.is_some_and(|n| n.is_some() || had_notes)),
                ("agent_id", m.agent_id.is_some_and(|a| Some(a) != cur_agent)),
                ("state", state.is_some_and(|s| Some(s) != cur_state.as_deref())),
            ] {
                if changed {
                    fields.push(f);
                }
            }
            if pw_changed && let Some(old) = &cur_pw {
                // Copied as sealed: still bound to "<item id>:password".
                sqlx::query("INSERT INTO vault_item_history (item_id, password, replaced_by) VALUES ($1, $2, $3)")
                    .bind(id)
                    .bind(old)
                    .bind(source.user)
                    .execute(&mut *tx)
                    .await?;
                sqlx::query(
                    "DELETE FROM vault_item_history WHERE item_id = $1
                       AND id NOT IN (SELECT id FROM vault_item_history WHERE item_id = $1 ORDER BY id DESC LIMIT $2)",
                )
                .bind(id)
                .bind(HISTORY_KEPT)
                .execute(&mut *tx)
                .await?;
            }
            if !fields.is_empty() {
                sqlx::query(
                    "UPDATE vault_items SET name = $2, username = $3, url = $4,
                            password = CASE WHEN $5 THEN $6 ELSE password END,
                            password_changed_at = CASE WHEN $5 THEN now() ELSE password_changed_at END,
                            notes = CASE WHEN $7 THEN $8 ELSE notes END,
                            agent_id = coalesce($9, agent_id), managed_state = coalesce($10, managed_state),
                            updated_by = $11, updated_at = now()
                      WHERE id = $1",
                )
                .bind(id)
                .bind(&name)
                .bind(&username)
                .bind(&url)
                .bind(pw_changed)
                .bind(seal(&key, id, "password", password.as_bytes()))
                .bind(notes.is_some())
                .bind(notes.flatten().map(|n| seal(&key, id, "notes", n.as_bytes())))
                .bind(m.agent_id)
                .bind(state)
                .bind(source.user)
                .execute(&mut *tx)
                .await
                .map_err(fk)?;
            }
            (id, false, fields)
        }
    };
    tx.commit().await?;
    if created || !fields.is_empty() {
        auth::audit(
            db,
            source.user,
            "vault.system_write",
            Some(("vault_item", id)),
            json!({
                "client_id": client_id, "kind": kind, "reference": reference, "name": name, "agent_id": m.agent_id,
                "feature": source.feature, "created": created, "fields": fields,
            }),
        )
        .await;
    }
    Ok(id)
}

/// Sets the managed state of item `id` (a managed item of `client`), e.g. `ok` once the agent
/// confirmed a rotated password. Not audited: the password didn't change.
#[allow(dead_code)] // the API disk encryption, LAPS and identity build on
pub async fn set_managed_state(db: &PgPool, client: Uuid, id: Uuid, state: &str) -> ApiResult<()> {
    let state = state.trim();
    if state.is_empty() || state.chars().count() > 40 {
        return Err(ApiError::BadRequest("a managed state is 1-40 characters".into()));
    }
    let n = sqlx::query("UPDATE vault_items SET managed_state = $3, updated_at = now() WHERE id = $1 AND client_id = $2 AND managed_kind IS NOT NULL")
        .bind(id)
        .bind(client)
        .bind(state)
        .execute(db)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound("managed credential"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_round_trip() {
        for k in ManagedKind::ALL {
            assert_eq!(ManagedKind::parse(k.as_str()), Some(*k));
        }
        assert_eq!(ManagedKind::parse("nope"), None);
        // The migration's CHECK lists exactly these.
        let sql = include_str!("../migrations/0037_vault_managed.sql");
        for k in ManagedKind::ALL {
            assert!(sql.contains(&format!("'{}'", k.as_str())), "{k:?} missing from 0037");
        }
    }

    #[test]
    fn sealing_is_bound_to_item_and_column() {
        let key = DataKey::from_bytes([9; 32]);
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let s = seal(&key, a, "password", b"hunter2");
        assert_eq!(open(&key, a, "password", &s).unwrap(), b"hunter2");
        assert!(open(&key, b, "password", &s).is_err(), "another item");
        assert!(open(&key, a, "notes", &s).is_err(), "another column");
        let e = open(&key, b, "password", &s).unwrap_err().to_string();
        assert!(!e.contains("hunter2"));
    }

    #[test]
    fn urls() {
        for ok in ["", "https://fw.acme.local:4443", "10.0.0.1", "rdp://server01", "ssh://root@host"] {
            assert!(clean_url(ok).is_ok(), "{ok}");
        }
        for bad in ["javascript:alert(1)", " JavaScript:alert(1)", "java\tscript:x", "data:text/html,x", "vbscript:x"] {
            assert!(clean_url(bad).is_err(), "{bad}");
        }
    }
}
