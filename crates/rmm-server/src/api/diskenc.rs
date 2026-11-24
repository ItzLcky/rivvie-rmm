//! Disk encryption as the agents last reported it: one device's volumes, the fleet list
//! (paged), a refresh and a recovery password rotation. Keys themselves are only reachable
//! through the vault. See [`crate::diskenc`] and docs/design/disk-encryption.md.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::AssertSqlSafe;
use uuid::Uuid;

use crate::auth::{self, Perm, Role, User};
use crate::error::{ApiError, ApiResult};
use crate::paging::{self, Page, PageQuery, Plan, SortKey};
use crate::state::AppState;

#[derive(Serialize, sqlx::FromRow)]
pub struct VolumeRow {
    agent_id: Uuid,
    hostname: String,
    online: bool,
    client_id: Uuid,
    client_name: String,
    site_name: String,
    volume_id: String,
    mount: String,
    device: String,
    /// `bitlocker`, `filevault`, `luks` or `none`.
    kind: String,
    /// `os` or `data`.
    role: String,
    /// `encrypted`, `encrypting`, `decrypting`, `unencrypted`, `suspended` or `unknown`.
    status: String,
    percent: Option<f32>,
    method: Option<String>,
    protectors: Vec<String>,
    protection_on: bool,
    locked: bool,
    recovery_protector_id: Option<String>,
    /// The vault holds the current recovery password.
    escrowed: bool,
    escrowed_at: Option<DateTime<Utc>>,
    escrow_error: Option<String>,
    /// The managed vault item with the recovery password (for those who may see the vault).
    vault_item_id: Option<Uuid>,
    suspended_since: Option<DateTime<Utc>>,
    updated_at: DateTime<Utc>,
    /// A disk encryption alert is open for this volume.
    alerting: bool,
    #[sqlx(default)]
    #[serde(skip)]
    sort_key: String,
    #[sqlx(default)]
    #[serde(skip)]
    row_id: String,
}

const COLS: &str = "v.agent_id, a.hostname, a.online, s.client_id, c.name AS client_name, s.name AS site_name, v.volume_id, v.mount, v.device, v.kind,
       v.role, v.status, v.percent, v.method, v.protectors, v.protection_on, v.locked, v.recovery_protector_id,
       (v.recovery_protector_id IS NOT NULL AND v.recovery_protector_id = v.escrowed_protector_id) AS escrowed, v.escrowed_at, v.escrow_error,
       v.vault_item_id, v.suspended_since, v.updated_at,
       EXISTS (SELECT 1 FROM alerts al WHERE al.agent_id = v.agent_id AND al.kind = 'disk_encryption' AND al.resolved_at IS NULL
                  AND al.key = 'vol:' || v.volume_id) AS alerting,
       (v.agent_id::text || '/' || v.volume_id) AS row_id";
const FROM: &str = "FROM disk_volumes v JOIN agents a ON a.id = v.agent_id JOIN sites s ON s.id = a.site_id JOIN clients c ON c.id = s.client_id";
const STATUSES: &[&str] = &["encrypted", "encrypting", "decrypting", "unencrypted", "suspended", "unknown"];

const SORT_KEYS: &[SortKey] = &[
    SortKey {
        name: "status",
        expr: "(CASE v.status WHEN 'unencrypted' THEN 0 WHEN 'suspended' THEN 1 WHEN 'decrypting' THEN 2 WHEN 'unknown' THEN 3 WHEN 'encrypting' THEN 4 ELSE 5 END)",
        ty: "int",
    },
    SortKey { name: "hostname", expr: "lower(a.hostname)", ty: "text" },
    SortKey { name: "volume", expr: "lower(v.volume_id)", ty: "text" },
    SortKey { name: "updated", expr: "v.updated_at", ty: "timestamptz" },
];

/// The vault item id only for people who may open the vault.
fn redact(u: &User, rows: &mut [VolumeRow]) {
    if !super::vault::can_read(u) {
        for r in rows {
            r.vault_item_id = None;
        }
    }
}

#[derive(Deserialize)]
pub struct ListQuery {
    client_id: Option<Uuid>,
    /// Comma-separated statuses.
    status: Option<String>,
    /// Only BitLocker volumes whose recovery password is (or isn't) in the vault.
    escrowed: Option<bool>,
    /// Only the system volumes.
    os_only: Option<bool>,
    /// Only volumes with an open alert.
    alerting: Option<bool>,
    /// Hostname.
    q: Option<String>,
}

pub async fn list(State(st): State<Arc<AppState>>, u: User, Query(q): Query<ListQuery>, Query(page): Query<PageQuery>) -> ApiResult<Json<Page<VolumeRow>>> {
    if let Some(c) = q.client_id {
        super::access::client(&u, c)?;
    }
    let plan = Plan::new(SORT_KEYS, ("status", false), &page, "(v.agent_id::text || '/' || v.volume_id)", "text", 9)?;
    let statuses: Option<Vec<String>> = q.status.as_deref().filter(|s| !s.is_empty()).map(|s| s.split(',').map(|r| r.trim().to_string()).collect());
    if let Some(bad) = statuses.iter().flatten().find(|r| !STATUSES.contains(&r.as_str())) {
        return Err(ApiError::BadRequest(format!("unknown status {bad}")));
    }
    let search = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(String::from);
    let filters = format!(
        "{FROM} WHERE ($1::uuid[] IS NULL OR s.client_id = ANY($1)) AND ($2::uuid IS NULL OR s.client_id = $2)
           AND ($3::text[] IS NULL OR v.status = ANY($3))
           AND ($4::bool IS NULL OR (v.kind = 'bitlocker' AND $4 = (v.recovery_protector_id IS NOT NULL AND v.recovery_protector_id = v.escrowed_protector_id)))
           AND ($5::bool IS NOT TRUE OR v.role = 'os')
           AND ($6::bool IS NULL OR $6 = EXISTS (SELECT 1 FROM alerts al WHERE al.agent_id = v.agent_id AND al.kind = 'disk_encryption'
                                                   AND al.resolved_at IS NULL AND al.key = 'vol:' || v.volume_id))
           AND ($7::text IS NULL OR a.hostname ILIKE '%' || $7 || '%')"
    );
    macro_rules! bind_filters {
        ($query:expr) => {
            $query.bind(u.scope()).bind(q.client_id).bind(&statuses).bind(q.escrowed).bind(q.os_only).bind(q.alerting).bind(&search)
        };
    }
    let sql = format!("SELECT {COLS}, {} {filters} {} {} {}", plan.key_select, plan.keyset, plan.order, plan.limit_sql());
    let mut rows = bind_filters!(sqlx::query_as::<_, VolumeRow>(AssertSqlSafe(sql)));
    if let Some((k, id)) = &plan.cursor {
        rows = rows.bind(k).bind(id);
    }
    let mut rows = rows.fetch_all(&st.db).await?;
    redact(&u, &mut rows);
    let total: i64 = bind_filters!(sqlx::query_scalar(AssertSqlSafe(paging::count_sql(&filters)))).fetch_one(&st.db).await?;
    Ok(Json(plan.finish(rows, |r| (r.sort_key.clone(), r.row_id.clone()), total)))
}

#[derive(Serialize)]
pub struct AgentDiskEncryption {
    /// When the agent last reported (None: never, or it predates disk encryption).
    reported_at: Option<DateTime<Utc>>,
    error: Option<String>,
    tpm: Option<Value>,
    /// `encrypted`, `partial` or `none`.
    summary: Option<String>,
    /// The device's policy: whether recovery passwords are escrowed.
    escrow_recovery_keys: bool,
    add_recovery_protector: bool,
    volumes: Vec<VolumeRow>,
}

pub async fn for_agent(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<AgentDiskEncryption>> {
    super::access::agent(&st, &u, id).await?;
    let (reported_at, error, tpm, summary): (Option<DateTime<Utc>>, Option<String>, Option<Value>, Option<String>) =
        sqlx::query_as("SELECT diskenc_at, diskenc_error, tpm, diskenc_status FROM agents WHERE id = $1").bind(id).fetch_one(&st.db).await?;
    let mut volumes: Vec<VolumeRow> = sqlx::query_as(AssertSqlSafe(format!("SELECT {COLS} {FROM} WHERE v.agent_id = $1 ORDER BY v.role <> 'os', v.volume_id")))
        .bind(id)
        .fetch_all(&st.db)
        .await?;
    redact(&u, &mut volumes);
    let policy = crate::policy::disk_encryption(&st, id).await?;
    Ok(Json(AgentDiskEncryption {
        reported_at,
        error,
        tpm,
        summary,
        escrow_recovery_keys: policy.escrow_recovery_keys,
        add_recovery_protector: policy.add_recovery_protector,
        volumes,
    }))
}

pub async fn refresh(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    super::access::agent(&st, &u, id).await?;
    crate::diskenc::refresh(&st, id).await?;
    Ok(Json(json!({ "ok": true })))
}

/// Replaces the volume's BitLocker recovery password (adds one if it has none). The new one is
/// escrowed from the report that follows.
pub async fn rotate(State(st): State<Arc<AppState>>, u: User, Path((id, volume)): Path<(Uuid, String)>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    u.need(Perm::SecurityRespond)?;
    super::access::agent(&st, &u, id).await?;
    let res = crate::diskenc::rotate(&st, id, &volume).await;
    let (ok, message) = match &res {
        Ok(m) => (true, m.clone()),
        Err(e) => (false, e.to_string()),
    };
    auth::audit(&st.db, Some(u.id), "diskenc.rotate", Some(("agent", id)), json!({ "volume": volume, "ok": ok, "message": message })).await;
    res?;
    Ok(Json(json!({ "ok": true, "message": message })))
}
