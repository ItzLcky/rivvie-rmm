//! Identity management (docs/design/identity.md): a client's directories, kept in step by a
//! sync loop, and the actions technicians take on their users.
//!
//! Two kinds of source:
//!
//! - **Active Directory**, through the agent on one of the domain's controllers. Directory
//!   operations go over dedicated messages ([`rmm_proto::identity`]), never script jobs: a
//!   job's body and output are stored, and a password must not be. Syncs are deltas by
//!   `uSNChanged`, with a full sync (which also reads group membership and notices deleted
//!   users) at least once a day.
//! - **Entra ID**, through Microsoft Graph with the client's own app registration
//!   ([`crate::entra`]): a full list every time. With `sync_devices` the same sync reads the
//!   tenant's Intune devices (docs/design/mdm.md).
//!
//! Users are matched to the client's contacts by email. A password reset either shows the
//! password once (the response, `Cache-Control: no-store`, and nowhere else) or saves it in the
//! client's vault as a managed item ([`crate::vault::put_managed`], kind `identity`): exactly
//! one of the two, as [`Delivered`] says.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::Duration;

use chrono::{DateTime, Utc};
use rmm_proto::identity::{Op, Reply, SyncPage, protected_sid, valid_sid};
use serde::Serialize;
use serde_json::json;
use sqlx::{PgConnection, PgPool};
use tracing::{info, warn};
use uuid::Uuid;

use crate::auth::{self, Role, User};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use crate::vault;

/// One directory operation (an unlock, a reset...).
const ACTION_TIMEOUT: Duration = Duration::from_secs(90);
/// One page of an AD sync.
const SYNC_PAGE_TIMEOUT: Duration = Duration::from_secs(300);
/// An AD source does a full sync when the last one is older than this.
const FULL_SYNC_HOURS: i64 = 24;
/// Generated passwords.
pub const GENERATED_LEN: usize = 16;

/// Sources being synced right now: a second request for the same one waits for nothing.
static SYNCING: Mutex<Option<HashSet<Uuid>>> = Mutex::new(None);

struct SyncGuard(Uuid);

impl SyncGuard {
    fn take(id: Uuid) -> Option<SyncGuard> {
        let mut s = SYNCING.lock().unwrap_or_else(|e| e.into_inner());
        s.get_or_insert_with(HashSet::new).insert(id).then_some(SyncGuard(id))
    }
}

impl Drop for SyncGuard {
    fn drop(&mut self) {
        if let Some(s) = SYNCING.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
            s.remove(&self.0);
        }
    }
}

#[derive(sqlx::FromRow, Clone)]
pub struct Source {
    pub id: Uuid,
    pub client_id: Uuid,
    pub kind: String,
    pub agent_id: Option<Uuid>,
    pub tenant_id: String,
    pub app_client_id: String,
    pub secret: Option<Vec<u8>>,
    pub secret_sealed: bool,
    pub sync_devices: bool,
    pub high_usn: i64,
    pub last_full_sync_at: Option<DateTime<Utc>>,
}

pub const SOURCE_COLS: &str =
    "id, client_id, kind, agent_id, tenant_id, app_client_id, secret, secret_sealed, sync_devices, high_usn, last_full_sync_at";

pub async fn source(db: &PgPool, id: Uuid) -> sqlx::Result<Option<Source>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT {SOURCE_COLS} FROM identity_sources WHERE id = $1"))).bind(id).fetch_optional(db).await
}

fn entra_secret(st: &AppState, s: &Source) -> Result<String, String> {
    let stored = s.secret.as_deref().ok_or("the connection has no client secret")?;
    let plain = crate::crypto::load(st.cfg.data_key.as_ref(), stored, s.secret_sealed)
        .ok_or("the client secret can't be decrypted (was RMM_DATA_KEY changed?)")?;
    String::from_utf8(plain).map_err(|_| "the client secret isn't text".to_string())
}

async fn entra_client<'a>(st: &'a AppState, s: &Source) -> Result<crate::entra::Client<'a>, String> {
    let secret = entra_secret(st, s)?;
    crate::entra::Client::connect(&st.http, &s.tenant_id, &s.app_client_id, &secret).await.map_err(|e| format!("{e:#}"))
}

/// Checks the source's agent can take directory operations.
async fn ad_agent(st: &AppState, s: &Source) -> Result<Uuid, String> {
    let agent = s.agent_id.ok_or("no domain controller agent is set for this directory")?;
    let capable: Option<bool> = sqlx::query_scalar("SELECT $2 = ANY(capabilities) FROM agents WHERE id = $1")
        .bind(agent)
        .bind(rmm_proto::identity::CAPABILITY)
        .fetch_optional(&st.db)
        .await
        .map_err(|e| e.to_string())?;
    match capable {
        None => Err("the domain controller's agent was deleted".into()),
        Some(false) => Err("the agent doesn't manage Active Directory: it must run on a domain controller, and be up to date".into()),
        Some(true) if !st.hub.is_online(agent) => Err("the domain controller's agent is offline".into()),
        Some(true) => Ok(agent),
    }
}

// ---------------------------------------------------------------------------------------------
// Sync
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Default, Serialize)]
pub struct SyncStats {
    pub users: usize,
    pub groups: usize,
    /// Intune devices, when the source reads them.
    pub devices: Option<usize>,
    /// A full AD sync (rather than a delta).
    pub full: bool,
    /// Devices couldn't be read (the users still were).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub devices_error: Option<String>,
}

/// Syncs every enabled source when it's due.
pub async fn run(st: std::sync::Arc<AppState>) {
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    loop {
        tick.tick().await;
        let due: Vec<Uuid> = match sqlx::query_scalar(
            "SELECT id FROM identity_sources WHERE enabled
                AND (last_sync_at IS NULL OR last_sync_at < now() - make_interval(mins => sync_minutes))
              ORDER BY last_sync_at NULLS FIRST LIMIT 20",
        )
        .fetch_all(&st.db)
        .await
        {
            Ok(d) => d,
            Err(e) => {
                warn!("listing identity sources: {e}");
                continue;
            }
        };
        for id in due {
            if let Err(e) = sync(&st, id).await {
                info!(source = %id, "directory sync: {e}");
            }
        }
    }
}

/// Syncs one source now, recording the outcome on it.
pub async fn sync(st: &AppState, id: Uuid) -> Result<SyncStats, String> {
    let _guard = SyncGuard::take(id).ok_or("a sync of this directory is already running")?;
    let s = source(&st.db, id).await.map_err(|e| e.to_string())?.ok_or("no such directory")?;
    let res = match s.kind.as_str() {
        "ad" => sync_ad(st, &s).await,
        _ => sync_entra(st, &s).await,
    };
    let err = match &res {
        Ok(stats) => stats.devices_error.as_ref().map(|e| format!("Intune devices: {e}")),
        Err(e) => Some(e.clone()),
    };
    let full = res.as_ref().is_ok_and(|r| r.full);
    if let Err(e) = sqlx::query(
        "UPDATE identity_sources SET last_sync_at = now(), last_error = $2,
                last_full_sync_at = CASE WHEN $3 THEN now() ELSE last_full_sync_at END WHERE id = $1",
    )
    .bind(id)
    .bind(err.as_deref().map(|e| e.chars().take(1000).collect::<String>()))
    .bind(full)
    .execute(&st.db)
    .await
    {
        warn!(source = %id, "recording sync: {e}");
    }
    if res.is_ok() {
        match_contacts(&st.db, id).await.map_err(|e| e.to_string())?;
    }
    res
}

/// Checks a source can be reached, changing nothing: Entra signs in and reads one user; AD
/// asks the domain controller for its groups. Returns what was found.
pub async fn test(st: &AppState, id: Uuid) -> Result<String, String> {
    let s = source(&st.db, id).await.map_err(|e| e.to_string())?.ok_or("no such directory")?;
    if s.kind == "ad" {
        let agent = ad_agent(st, &s).await?;
        // No user has changed after the last possible USN: this lists only the groups.
        match st.hub.identity(agent, Op::Sync { since_usn: i64::MAX - 1, page: 0 }, SYNC_PAGE_TIMEOUT).await? {
            Reply::Sync(p) => Ok(format!("the domain controller answered: {} groups", p.groups.len())),
            Reply::Error(e) => Err(format!("the domain controller: {e}")),
            Reply::Done => Err("the domain controller sent no listing".into()),
        }
    } else {
        let c = entra_client(st, &s).await?;
        c.test().await.map_err(|e| format!("{e:#}"))?;
        if s.sync_devices {
            c.devices().await.map_err(|e| format!("signed in and read users, but not Intune devices: {e:#}"))?;
        }
        Ok("signed in and read users".into())
    }
}

/// A user as stored, from either kind of directory.
#[derive(Debug, Clone, Default)]
struct UserIn {
    external_id: String,
    username: String,
    upn: String,
    display_name: String,
    email: String,
    enabled: bool,
    locked: bool,
    privileged: bool,
    synced_from_ad: bool,
    last_logon_at: Option<DateTime<Utc>>,
    password_last_set: Option<DateTime<Utc>>,
    password_expires_at: Option<DateTime<Utc>>,
    mfa_registered: Option<bool>,
    department: String,
    title: String,
}

fn clip(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

async fn upsert_user(db: &mut PgConnection, source: Uuid, u: &UserIn) -> sqlx::Result<Uuid> {
    sqlx::query_scalar(
        "INSERT INTO identity_users (id, source_id, external_id, username, upn, display_name, email, enabled, locked, privileged, synced_from_ad,
                                     last_logon_at, password_last_set, password_expires_at, mfa_registered, department, title)
         VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
         ON CONFLICT (source_id, external_id) DO UPDATE SET username = $3, upn = $4, display_name = $5, email = $6, enabled = $7, locked = $8,
                privileged = $9, synced_from_ad = $10, last_logon_at = coalesce($11, identity_users.last_logon_at), password_last_set = $12,
                password_expires_at = $13, mfa_registered = $14, department = $15, title = $16, deleted_at = NULL, synced_at = now()
         RETURNING id",
    )
    .bind(source)
    .bind(&u.external_id)
    .bind(clip(&u.username, 256))
    .bind(clip(&u.upn, 256))
    .bind(clip(&u.display_name, 256))
    .bind(clip(&u.email, 320))
    .bind(u.enabled)
    .bind(u.locked)
    .bind(u.privileged)
    .bind(u.synced_from_ad)
    .bind(u.last_logon_at)
    .bind(u.password_last_set)
    .bind(u.password_expires_at)
    .bind(u.mfa_registered)
    .bind(clip(&u.department, 256))
    .bind(clip(&u.title, 256))
    .fetch_one(db)
    .await
}

async fn upsert_group(db: &mut PgConnection, source: Uuid, external: &str, name: &str, description: &str, privileged: bool) -> sqlx::Result<Uuid> {
    sqlx::query_scalar(
        "INSERT INTO identity_groups (id, source_id, external_id, name, description, privileged)
         VALUES (gen_random_uuid(), $1, $2, $3, $4, $5)
         ON CONFLICT (source_id, external_id) DO UPDATE SET name = $3, description = $4, privileged = $5, deleted_at = NULL, synced_at = now()
         RETURNING id",
    )
    .bind(source)
    .bind(external)
    .bind(clip(name, 256))
    .bind(clip(description, 1000))
    .bind(privileged)
    .fetch_one(db)
    .await
}

/// Marks what isn't in `present` as deleted.
async fn mark_deleted(db: &mut PgConnection, table: &str, source: Uuid, present: &[String]) -> sqlx::Result<()> {
    let table = match table {
        "identity_users" => "identity_users",
        _ => "identity_groups",
    };
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE {table} SET deleted_at = now() WHERE source_id = $1 AND deleted_at IS NULL AND NOT (external_id = ANY($2))"
    )))
    .bind(source)
    .bind(present)
    .execute(db)
    .await?;
    Ok(())
}

async fn sync_ad(st: &AppState, s: &Source) -> Result<SyncStats, String> {
    let agent = ad_agent(st, s).await?;
    let full = s.high_usn == 0 || s.last_full_sync_at.is_none_or(|t| t < Utc::now() - chrono::Duration::hours(FULL_SYNC_HOURS));
    let since = if full { 0 } else { s.high_usn };
    let mut pages: Vec<SyncPage> = Vec::new();
    for page in 0..10_000u32 {
        let reply = st.hub.identity(agent, Op::Sync { since_usn: since, page }, SYNC_PAGE_TIMEOUT).await?;
        let p = match reply {
            Reply::Sync(p) => p,
            Reply::Error(e) => return Err(format!("the domain controller: {e}")),
            Reply::Done => return Err("the domain controller sent no listing".into()),
        };
        let more = p.more;
        pages.push(p);
        if !more {
            break;
        }
    }
    let high = pages.first().map_or(s.high_usn, |p| p.high_usn);
    let (n_users, n_groups) = store_ad(&st.db, s.id, &pages, full).await.map_err(|e| format!("storing the directory: {e}"))?;
    sqlx::query("UPDATE identity_sources SET high_usn = $2 WHERE id = $1").bind(s.id).bind(high).execute(&st.db).await.map_err(|e| e.to_string())?;
    Ok(SyncStats { users: n_users, groups: n_groups, devices: None, full, devices_error: None })
}

/// Stores an AD listing; `full` also marks users missing from it deleted.
async fn store_ad(db: &PgPool, source: Uuid, pages: &[SyncPage], full: bool) -> sqlx::Result<(usize, usize)> {
    let mut tx = db.begin().await?;
    let groups = pages.first().map(|p| p.groups.as_slice()).unwrap_or_default();
    let mut group_ids: HashMap<String, (Uuid, bool)> = HashMap::new();
    for g in groups.iter().filter(|g| valid_sid(&g.sid)) {
        let id = upsert_group(&mut tx, source, &g.sid, &g.name, &g.description, g.admin_count).await?;
        group_ids.insert(g.sid.clone(), (id, g.admin_count));
    }
    if !groups.is_empty() {
        mark_deleted(&mut tx, "identity_groups", source, &groups.iter().map(|g| g.sid.clone()).collect::<Vec<_>>()).await?;
    }
    let mut n = 0;
    for u in pages.iter().flat_map(|p| &p.users).filter(|u| valid_sid(&u.sid)) {
        let privileged = u.admin_count || u.member_of.iter().any(|g| group_ids.get(g).is_some_and(|(_, p)| *p));
        let id = upsert_user(
            &mut tx,
            source,
            &UserIn {
                external_id: u.sid.clone(),
                username: u.username.clone(),
                upn: u.upn.clone(),
                display_name: u.display_name.clone(),
                email: u.email.clone(),
                enabled: u.enabled,
                locked: u.locked,
                privileged,
                synced_from_ad: false,
                last_logon_at: u.last_logon_at,
                password_last_set: u.password_last_set,
                password_expires_at: u.password_expires_at,
                mfa_registered: None,
                department: u.department.clone(),
                title: u.title.clone(),
            },
        )
        .await?;
        // Membership lives on the groups, so a delta (user changes) only has it for the users
        // it lists; the daily full sync has everyone's.
        sqlx::query("DELETE FROM identity_group_members WHERE user_id = $1").bind(id).execute(&mut *tx).await?;
        let gids: Vec<Uuid> = u.member_of.iter().filter_map(|g| group_ids.get(g).map(|x| x.0)).collect();
        if !gids.is_empty() {
            sqlx::query("INSERT INTO identity_group_members (group_id, user_id) SELECT unnest($1::uuid[]), $2 ON CONFLICT DO NOTHING")
                .bind(&gids)
                .bind(id)
                .execute(&mut *tx)
                .await?;
        }
        n += 1;
    }
    if full && let Some(last) = pages.last().filter(|p| !p.all_user_sids.is_empty()) {
        mark_deleted(&mut tx, "identity_users", source, &last.all_user_sids).await?;
    }
    tx.commit().await?;
    Ok((n, groups.len()))
}

async fn sync_entra(st: &AppState, s: &Source) -> Result<SyncStats, String> {
    let c = entra_client(st, s).await?;
    let e = |e: anyhow::Error| format!("{e:#}");
    let users = c.users().await.map_err(e)?;
    let groups = c.groups().await.map_err(e)?;
    // Privileged detection needs RoleManagement.Read.Directory; without it nobody is marked,
    // and the sync says why.
    let (privileged, role_err) = match c.privileged().await {
        Ok(p) => (p, None),
        Err(err) => (HashSet::new(), Some(format!("{err:#}"))),
    };
    let mfa = c.mfa().await;
    let mut members: Vec<(String, Vec<String>)> = Vec::with_capacity(groups.len());
    for g in &groups {
        members.push((g.id.clone(), c.group_members(&g.id).await.map_err(e)?));
    }
    let mut tx = st.db.begin().await.map_err(|e| e.to_string())?;
    let db = async {
        let mut user_ids: HashMap<&str, Uuid> = HashMap::new();
        for u in &users {
            let id = upsert_user(
                &mut tx,
                s.id,
                &UserIn {
                    external_id: u.id.clone(),
                    username: u.upn.split('@').next().unwrap_or_default().to_string(),
                    upn: u.upn.clone(),
                    display_name: u.display_name.clone(),
                    email: u.mail.clone(),
                    enabled: u.enabled,
                    locked: false,
                    privileged: privileged.contains(&u.id),
                    synced_from_ad: u.synced_from_ad,
                    password_last_set: u.password_last_set,
                    mfa_registered: mfa.as_ref().and_then(|m| m.get(&u.id).copied()),
                    department: u.department.clone(),
                    title: u.title.clone(),
                    ..Default::default()
                },
            )
            .await?;
            user_ids.insert(u.id.as_str(), id);
        }
        mark_deleted(&mut tx, "identity_users", s.id, &users.iter().map(|u| u.id.clone()).collect::<Vec<_>>()).await?;
        sqlx::query("DELETE FROM identity_group_members m USING identity_groups g WHERE g.id = m.group_id AND g.source_id = $1")
            .bind(s.id)
            .execute(&mut *tx)
            .await?;
        for (g, (gid, ms)) in groups.iter().zip(&members) {
            debug_assert_eq!(&g.id, gid);
            let id = upsert_group(&mut tx, s.id, &g.id, &g.name, &g.description, false).await?;
            let uids: Vec<Uuid> = ms.iter().filter_map(|m| user_ids.get(m.as_str()).copied()).collect();
            if !uids.is_empty() {
                sqlx::query("INSERT INTO identity_group_members (group_id, user_id) SELECT $1, unnest($2::uuid[]) ON CONFLICT DO NOTHING")
                    .bind(id)
                    .bind(&uids)
                    .execute(&mut *tx)
                    .await?;
            }
        }
        mark_deleted(&mut tx, "identity_groups", s.id, &groups.iter().map(|g| g.id.clone()).collect::<Vec<_>>()).await?;
        Ok::<(), sqlx::Error>(())
    };
    db.await.map_err(|e| format!("storing the directory: {e}"))?;
    tx.commit().await.map_err(|e| e.to_string())?;
    let mut stats = SyncStats { users: users.len(), groups: groups.len(), devices: None, full: true, devices_error: role_err.map(|r| format!("(not Intune) directory roles: {r}")) };
    if s.sync_devices {
        match c.devices().await {
            Ok(d) => {
                crate::mdm::store(&st.db, s, &d).await.map_err(|e| format!("storing Intune devices: {e}"))?;
                stats.devices = Some(d.len());
            }
            Err(err) => stats.devices_error = Some(format!("{err:#}")),
        }
    }
    Ok(stats)
}

/// Links users to the client's contacts with the same email (or UPN).
async fn match_contacts(db: &PgPool, source: Uuid) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE identity_users iu SET contact_id = (
                SELECT c.id FROM contacts c JOIN identity_sources s ON s.client_id = c.client_id
                 WHERE s.id = iu.source_id AND c.email <> ''
                   AND lower(c.email) IN (lower(nullif(iu.email, '')), lower(nullif(iu.upn, '')))
                 ORDER BY c.is_primary DESC, c.created_at LIMIT 1)
          WHERE iu.source_id = $1",
    )
    .bind(source)
    .execute(db)
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------------------------

/// Where a reset password goes: shown once, or into the vault. Never both, never neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Delivery {
    Show,
    Vault,
}

#[derive(Debug, Clone)]
pub enum Action {
    Unlock,
    Reset { password: Option<String>, must_change: bool, delivery: Delivery },
    SetEnabled(bool),
    RevokeSessions,
    /// These groups (ids of `identity_groups`), or every group the user is in.
    RemoveGroups(Option<Vec<Uuid>>),
}

impl Action {
    pub fn audit_name(&self) -> &'static str {
        match self {
            Action::Unlock => "identity.unlock",
            Action::Reset { .. } => "identity.reset_password",
            Action::SetEnabled(true) => "identity.enable",
            Action::SetEnabled(false) => "identity.disable",
            Action::RevokeSessions => "identity.revoke_sessions",
            Action::RemoveGroups(_) => "identity.remove_groups",
        }
    }
}

/// What a reset produced: the password for the person who asked, or the vault item holding it.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "delivered", rename_all = "snake_case")]
pub enum Delivered {
    Shown { password: String },
    Vault { item_id: Uuid },
}

#[derive(Debug, Serialize)]
pub struct Outcome {
    pub ok: bool,
    #[serde(flatten)]
    pub delivered: Option<Delivered>,
}

/// The user an action is about, with what the checks need.
#[derive(sqlx::FromRow, Debug, Clone)]
pub struct Target {
    pub id: Uuid,
    pub source_id: Uuid,
    pub client_id: Uuid,
    pub kind: String,
    pub source_name: String,
    pub external_id: String,
    pub username: String,
    pub upn: String,
    pub display_name: String,
    pub privileged: bool,
    pub synced_from_ad: bool,
    pub deleted: bool,
}

pub async fn target(db: &PgPool, id: Uuid) -> sqlx::Result<Option<Target>> {
    sqlx::query_as(
        "SELECT u.id, u.source_id, s.client_id, s.kind, s.name AS source_name, u.external_id, u.username, u.upn, u.display_name,
                u.privileged, u.synced_from_ad, u.deleted_at IS NOT NULL AS deleted
           FROM identity_users u JOIN identity_sources s ON s.id = u.source_id WHERE u.id = $1",
    )
    .bind(id)
    .fetch_optional(db)
    .await
}

/// The rules every action follows, whoever starts it (the Users tab, a checklist). The caller
/// has already checked the client is visible, `identity.manage` and the second factor.
pub fn check(u: &User, t: &Target, action: &Action) -> ApiResult<()> {
    if t.deleted {
        return Err(ApiError::Conflict("the account is no longer in the directory".into()));
    }
    if t.privileged && u.role() < Role::Admin {
        return Err(ApiError::Denied("this is a privileged account: only an admin can change it".into()));
    }
    match t.kind.as_str() {
        "ad" => {
            if !valid_sid(&t.external_id) {
                return Err(ApiError::BadRequest("not a domain account".into()));
            }
            if protected_sid(&t.external_id) {
                return Err(ApiError::BadRequest("the built-in Administrator and krbtgt accounts are never changed".into()));
            }
            if matches!(action, Action::RevokeSessions) {
                return Err(ApiError::BadRequest("revoking sessions is an Entra ID action; Active Directory has no sessions to revoke".into()));
            }
        }
        _ => {
            if t.synced_from_ad {
                return Err(ApiError::Conflict(
                    "this account is synced from on-premises Active Directory: make the change there (add the client's AD as a directory) and it syncs up".into(),
                ));
            }
            if matches!(action, Action::Unlock) {
                return Err(ApiError::BadRequest("Entra ID locks sign-ins for a while on its own and has no unlock; reset the password instead".into()));
            }
        }
    }
    if let Action::Reset { password: Some(p), .. } = action
        && (p.chars().count() < 8 || p.chars().count() > 256)
    {
        return Err(ApiError::BadRequest("the password must be 8-256 characters".into()));
    }
    Ok(())
}

/// A random password: [`GENERATED_LEN`] characters with upper and lower case letters, digits
/// and a symbol, none easily confused (no `0O1lI`).
pub fn generate_password() -> String {
    const UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
    const LOWER: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
    const DIGIT: &[u8] = b"23456789";
    const SYMBOL: &[u8] = b"!#%+-=?@";
    let all: Vec<u8> = [UPPER, LOWER, DIGIT, SYMBOL].concat();
    // Uniform picks by rejection.
    let pick = |set: &[u8]| -> u8 {
        loop {
            let mut b = [0u8; 1];
            getrandom::fill(&mut b).expect("OS RNG unavailable");
            let limit = 256 - 256 % set.len();
            if (b[0] as usize) < limit {
                return set[b[0] as usize % set.len()];
            }
        }
    };
    loop {
        let pw: Vec<u8> = (0..GENERATED_LEN).map(|_| pick(&all)).collect();
        if [UPPER, LOWER, DIGIT, SYMBOL].iter().all(|set| pw.iter().any(|c| set.contains(c))) {
            return String::from_utf8(pw).expect("ascii");
        }
    }
}

/// Carries out `action` on `t` for `u` (after [`check`]), records it on the stored user and
/// in the audit log. `via` says where it was started (`users`, `checklist`).
pub async fn act(st: &AppState, u: &User, t: &Target, action: Action, via: &str) -> ApiResult<Outcome> {
    check(u, t, &action)?;
    // Without the key the vault can't take the password: refuse before changing anything.
    if matches!(action, Action::Reset { delivery: Delivery::Vault, .. }) && st.cfg.data_key.is_none() {
        return Err(ApiError::Conflict(vault::NEEDS_KEY.into()));
    }
    let s = source(&st.db, t.source_id).await?.ok_or(ApiError::NotFound("directory"))?;
    let mut generated = false;
    let password = match &action {
        Action::Reset { password: Some(p), .. } => Some(p.clone()),
        Action::Reset { password: None, .. } => {
            generated = true;
            Some(generate_password())
        }
        _ => None,
    };
    let groups: Vec<(Uuid, String)> = match &action {
        Action::RemoveGroups(which) => sqlx::query_as(
            "SELECT g.id, g.external_id FROM identity_group_members m JOIN identity_groups g ON g.id = m.group_id
              WHERE m.user_id = $1 AND ($2::uuid[] IS NULL OR g.id = ANY($2)) ORDER BY g.name",
        )
        .bind(t.id)
        .bind(which.as_deref())
        .fetch_all(&st.db)
        .await?,
        _ => vec![],
    };
    let failed = |e: String| ApiError::Conflict(e);
    match s.kind.as_str() {
        "ad" => {
            let agent = ad_agent(st, &s).await.map_err(failed)?;
            let sid = t.external_id.clone();
            let op = match &action {
                Action::Unlock => Op::Unlock { sid },
                Action::Reset { must_change, .. } => Op::ResetPassword { sid, password: password.clone().unwrap_or_default(), must_change: *must_change },
                Action::SetEnabled(enabled) => Op::SetEnabled { sid, enabled: *enabled },
                Action::RemoveGroups(_) => Op::RemoveFromGroups { sid, group_sids: groups.iter().map(|g| g.1.clone()).collect() },
                Action::RevokeSessions => unreachable!("refused by check"),
            };
            match st.hub.identity(agent, op, ACTION_TIMEOUT).await.map_err(failed)? {
                Reply::Done => {}
                Reply::Error(e) => return Err(failed(format!("the domain controller: {e}"))),
                Reply::Sync(_) => return Err(failed("the domain controller answered something else".into())),
            }
        }
        _ => {
            let c = entra_client(st, &s).await.map_err(failed)?;
            let id = &t.external_id;
            let r = match &action {
                Action::Reset { must_change, .. } => c.reset_password(id, password.as_deref().unwrap_or_default(), *must_change).await,
                Action::SetEnabled(enabled) => c.set_enabled(id, *enabled).await,
                Action::RevokeSessions => c.revoke_sessions(id).await,
                Action::RemoveGroups(_) => {
                    let mut r = Ok(());
                    for g in &groups {
                        r = c.remove_from_group(&g.1, id).await;
                        if r.is_err() {
                            break;
                        }
                    }
                    r
                }
                Action::Unlock => unreachable!("refused by check"),
            };
            r.map_err(|e| failed(format!("{e:#}")))?;
        }
    }

    // The directory changed: show it now rather than at the next sync.
    match &action {
        Action::Unlock => {
            sqlx::query("UPDATE identity_users SET locked = false WHERE id = $1").bind(t.id).execute(&st.db).await?;
        }
        Action::SetEnabled(e) => {
            sqlx::query("UPDATE identity_users SET enabled = $2 WHERE id = $1").bind(t.id).bind(e).execute(&st.db).await?;
        }
        Action::Reset { .. } => {
            sqlx::query("UPDATE identity_users SET password_last_set = now() WHERE id = $1").bind(t.id).execute(&st.db).await?;
        }
        Action::RemoveGroups(_) => {
            sqlx::query("DELETE FROM identity_group_members WHERE user_id = $1 AND group_id = ANY($2)")
                .bind(t.id)
                .bind(groups.iter().map(|g| g.0).collect::<Vec<_>>())
                .execute(&st.db)
                .await?;
        }
        Action::RevokeSessions => {}
    }

    let mut details = json!({
        "client_id": t.client_id, "source_id": t.source_id, "source": t.source_name, "kind": t.kind,
        "user": if t.upn.is_empty() { &t.username } else { &t.upn }, "via": via,
    });
    let delivered = match (&action, password) {
        (Action::Reset { delivery, must_change, .. }, Some(pw)) => {
            details["must_change"] = json!(must_change);
            details["generated"] = json!(generated);
            let d = deliver(st, u, t, *delivery, pw).await;
            details["delivery"] = json!(match &d {
                Ok(Delivered::Shown { .. }) => "shown",
                Ok(Delivered::Vault { .. }) => "vault",
                Err(_) => "vault_failed",
            });
            if let Ok(Delivered::Vault { item_id }) = &d {
                details["vault_item_id"] = json!(item_id);
            }
            auth::audit(&st.db, Some(u.id), action.audit_name(), Some(("identity_user", t.id)), details).await;
            Some(d.map_err(|e| ApiError::Internal(anyhow::anyhow!("the password was reset but couldn't be stored in the vault ({e}): reset it again"))))
                .transpose()?
        }
        _ => {
            if let Action::RemoveGroups(_) = &action {
                details["groups"] = json!(groups.iter().map(|g| g.1.clone()).collect::<Vec<_>>());
            }
            auth::audit(&st.db, Some(u.id), action.audit_name(), Some(("identity_user", t.id)), details).await;
            None
        }
    };
    Ok(Outcome { ok: true, delivered })
}

async fn deliver(st: &AppState, u: &User, t: &Target, delivery: Delivery, password: String) -> Result<Delivered, String> {
    match delivery {
        Delivery::Show => Ok(Delivered::Shown { password }),
        Delivery::Vault => {
            let who = if t.display_name.is_empty() { t.username.as_str() } else { t.display_name.as_str() };
            let item_id = vault::put_managed(
                st,
                t.client_id,
                vault::Managed {
                    kind: vault::ManagedKind::Identity,
                    reference: format!("{}:{}", t.source_id, t.external_id),
                    name: clip(&format!("{who} ({})", t.source_name), 200),
                    username: clip(if t.upn.is_empty() { &t.username } else { &t.upn }, 200),
                    state: Some("ok".into()),
                    ..Default::default()
                },
                &password,
                vault::Source::user("identity", u.id),
            )
            .await
            .map_err(|e| e.to_string())?;
            Ok(Delivered::Vault { item_id })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(role: Role) -> User {
        User {
            id: Uuid::new_v4(),
            email: "t@x".into(),
            name: "t".into(),
            role: match role {
                Role::Admin => "admin",
                Role::Technician => "technician",
                Role::Readonly => "readonly",
            }
            .into(),
            totp_enabled: true,
            mfa_enabled: true,
            mfa_setup_required: false,
            sso_session: false,
            sso_only: false,
            client_ids: None,
            permissions: None,
            session_id: Uuid::nil(),
            api_key: None,
        }
    }

    fn target(kind: &str, sid: &str) -> Target {
        Target {
            id: Uuid::nil(),
            source_id: Uuid::nil(),
            client_id: Uuid::nil(),
            kind: kind.into(),
            source_name: "Corp".into(),
            external_id: sid.into(),
            username: "jdoe".into(),
            upn: String::new(),
            display_name: "Jane".into(),
            privileged: false,
            synced_from_ad: false,
            deleted: false,
        }
    }

    #[test]
    fn generated_passwords() {
        let mut seen = HashSet::new();
        for _ in 0..200 {
            let p = generate_password();
            assert_eq!(p.len(), GENERATED_LEN);
            assert!(p.chars().any(|c| c.is_ascii_uppercase()) && p.chars().any(|c| c.is_ascii_lowercase()));
            assert!(p.chars().any(|c| c.is_ascii_digit()) && p.chars().any(|c| !c.is_ascii_alphanumeric()));
            assert!(!p.contains(['0', 'O', '1', 'l', 'I']));
            seen.insert(p);
        }
        assert_eq!(seen.len(), 200);
    }

    #[test]
    fn rules() {
        let tech = user(Role::Technician);
        let admin = user(Role::Admin);
        let ad = target("ad", "S-1-5-21-1-2-3-1104");
        assert!(check(&tech, &ad, &Action::Unlock).is_ok());
        assert!(check(&tech, &ad, &Action::RevokeSessions).is_err(), "AD has no sessions");
        assert!(check(&admin, &target("ad", "S-1-5-21-1-2-3-500"), &Action::SetEnabled(false)).is_err(), "RID 500 never");
        assert!(check(&admin, &target("ad", "S-1-5-21-1-2-3-502"), &Action::Unlock).is_err(), "krbtgt never");
        let privileged = Target { privileged: true, ..ad.clone() };
        assert!(matches!(check(&tech, &privileged, &Action::Unlock), Err(ApiError::Denied(_))));
        assert!(check(&admin, &privileged, &Action::Unlock).is_ok());
        let synced = Target { synced_from_ad: true, ..target("entra", "8d4c1f1e-0000-4000-8000-000000000003") };
        assert!(matches!(check(&admin, &synced, &Action::SetEnabled(false)), Err(ApiError::Conflict(_))));
        let entra = target("entra", "8d4c1f1e-0000-4000-8000-000000000001");
        assert!(check(&tech, &entra, &Action::Unlock).is_err(), "no unlock in Entra");
        assert!(check(&tech, &entra, &Action::RevokeSessions).is_ok());
        let short = Action::Reset { password: Some("short".into()), must_change: true, delivery: Delivery::Show };
        assert!(check(&tech, &entra, &short).is_err());
        let gone = Target { deleted: true, ..entra };
        assert!(check(&admin, &gone, &Action::RevokeSessions).is_err());
    }

    #[test]
    fn a_reset_is_delivered_exactly_once() {
        // Shown: the password is in the response...
        let shown = serde_json::to_value(Outcome { ok: true, delivered: Some(Delivered::Shown { password: "Pw-123456789".into() }) }).unwrap();
        assert_eq!(shown, json!({ "ok": true, "delivered": "shown", "password": "Pw-123456789" }));
        // ...saved: only the vault item's id is.
        let id = Uuid::new_v4();
        let saved = serde_json::to_value(Outcome { ok: true, delivered: Some(Delivered::Vault { item_id: id }) }).unwrap();
        assert_eq!(saved, json!({ "ok": true, "delivered": "vault", "item_id": id }));
        assert!(!saved.to_string().contains("password"));
        // Delivery is one value, so a request is one or the other.
        assert!(serde_json::from_value::<Delivery>(json!(["show", "vault"])).is_err());
        assert_eq!(serde_json::from_value::<Delivery>(json!("vault")).unwrap(), Delivery::Vault);
    }
}
