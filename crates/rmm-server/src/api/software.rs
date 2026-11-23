//! Software deployment API: the catalog (MSP-wide and per client, with uploaded installers),
//! deploying packages to agents, per-device status, runs and the third-party updates view.
//! The desired state itself (these packages must be present, kept current or absent) is the
//! `software` module of the policy sets (`api::policies`). Everything is limited to the clients
//! the user can see. See docs/design/software.md.

use std::collections::HashMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Multipart, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use chrono::{DateTime, Utc};
use rmm_proto::software::{Op, valid_token};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::AssertSqlSafe;
use uuid::Uuid;

use crate::auth::{self, Role, User};
use crate::error::{ApiError, ApiResult};
use crate::software::{self as core, Facts, PACKAGE_COLS, PackageRow, Trigger, Want};
use crate::state::AppState;

fn bad(m: impl Into<String>) -> ApiError {
    ApiError::BadRequest(m.into())
}

// ---------------------------------------------------------------------------
// Catalog
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct PackageOut {
    id: Uuid,
    client_id: Option<Uuid>,
    client_name: Option<String>,
    name: String,
    description: String,
    publisher: Option<String>,
    winget_id: Option<String>,
    choco_id: Option<String>,
    apt_name: Option<String>,
    dnf_name: Option<String>,
    version: Option<String>,
    installer: Option<InstallerOut>,
    silent_args: String,
    uninstall_cmd: Option<String>,
    product_code: Option<String>,
    detect_name: Option<String>,
    /// Which platforms it can be deployed to (`windows`, `linux`); empty: no source yet.
    platforms: Vec<&'static str>,
    /// Devices it's installed on, from the last scans.
    installed_on: i64,
    /// Devices with a newer version on offer.
    updates: i64,
    /// Policy requirements naming it.
    policies: i64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct InstallerOut {
    name: String,
    kind: String,
    size: i64,
    sha256: String,
}

#[derive(sqlx::FromRow)]
struct PackageStats {
    #[sqlx(flatten)]
    p: PackageRow,
    client_name: Option<String>,
    installed_on: i64,
    updates: i64,
    policies: i64,
}

impl From<PackageStats> for PackageOut {
    fn from(s: PackageStats) -> Self {
        let p = s.p;
        let mut platforms = Vec::new();
        if core::usable_on(&p, "windows") {
            platforms.push("windows");
        }
        if core::usable_on(&p, "linux") {
            platforms.push("linux");
        }
        let installer = match (&p.installer_name, &p.installer_kind, p.installer_size, &p.installer_sha256) {
            (Some(name), Some(kind), Some(size), Some(sha)) if p.installer_key.is_some() => {
                Some(InstallerOut { name: name.clone(), kind: kind.clone(), size, sha256: sha.clone() })
            }
            _ => None,
        };
        PackageOut {
            id: p.id,
            client_id: p.client_id,
            client_name: s.client_name,
            name: p.name,
            description: p.description,
            publisher: p.publisher,
            winget_id: p.winget_id,
            choco_id: p.choco_id,
            apt_name: p.apt_name,
            dnf_name: p.dnf_name,
            version: p.version,
            installer,
            silent_args: p.silent_args,
            uninstall_cmd: p.uninstall_cmd,
            product_code: p.product_code,
            detect_name: p.detect_name,
            platforms,
            installed_on: s.installed_on,
            updates: s.updates,
            policies: s.policies,
            created_at: p.created_at,
            updated_at: p.updated_at,
        }
    }
}

/// The catalog row visible to the user ($1: the user's client scope, NULL = all).
const VISIBLE: &str = "(p.client_id IS NULL OR $1::uuid[] IS NULL OR p.client_id = ANY($1))";

fn stats_sql(filter: &str) -> String {
    format!(
        "SELECT {PACKAGE_COLS}, c.name AS client_name,
                (SELECT count(*) FROM software_state ss WHERE ss.package_id = p.id AND ss.installed_version IS NOT NULL) AS installed_on,
                (SELECT count(*) FROM software_state ss WHERE ss.package_id = p.id AND ss.installed_version IS NOT NULL
                    AND ss.available_version IS NOT NULL AND ss.available_version IS DISTINCT FROM ss.ignored_version) AS updates,
                (SELECT count(*) FROM policy_items i WHERE i.module = 'software' AND i.config ->> 'package_id' = p.id::text) AS policies
           FROM software_packages p LEFT JOIN clients c ON c.id = p.client_id
          WHERE {VISIBLE} {filter}"
    )
}

#[derive(Deserialize)]
pub struct ListQuery {
    client_id: Option<Uuid>,
    q: Option<String>,
    /// `windows` or `linux`: only packages deployable there.
    platform: Option<String>,
}

pub async fn list(State(st): State<Arc<AppState>>, u: User, Query(q): Query<ListQuery>) -> ApiResult<Json<Vec<PackageOut>>> {
    let search = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let rows: Vec<PackageStats> = sqlx::query_as(AssertSqlSafe(stats_sql(
        "AND ($2::uuid IS NULL OR p.client_id = $2 OR p.client_id IS NULL)
         AND ($3::text IS NULL OR p.name ILIKE '%' || $3 || '%' OR p.winget_id ILIKE '%' || $3 || '%' OR p.choco_id ILIKE '%' || $3 || '%'
              OR p.apt_name ILIKE '%' || $3 || '%' OR p.dnf_name ILIKE '%' || $3 || '%' OR p.publisher ILIKE '%' || $3 || '%')
         ORDER BY lower(p.name) LIMIT 1000",
    )))
    .bind(u.scope())
    .bind(q.client_id)
    .bind(search)
    .fetch_all(&st.db)
    .await?;
    let want = q.platform.as_deref();
    Ok(Json(rows.into_iter().map(PackageOut::from).filter(|p| want.is_none_or(|w| p.platforms.contains(&w))).collect()))
}

async fn fetch_package(st: &AppState, u: &User, id: Uuid) -> ApiResult<PackageStats> {
    sqlx::query_as(AssertSqlSafe(stats_sql("AND p.id = $2")))
        .bind(u.scope())
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("package"))
}

pub async fn get(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<PackageOut>> {
    Ok(Json(fetch_package(&st, &u, id).await?.into()))
}

#[derive(Deserialize)]
pub struct PackageIn {
    /// Create only: the client that owns it; none for an MSP-wide package.
    #[serde(default)]
    client_id: Option<Uuid>,
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    publisher: Option<String>,
    #[serde(default)]
    winget_id: Option<String>,
    #[serde(default)]
    choco_id: Option<String>,
    #[serde(default)]
    apt_name: Option<String>,
    #[serde(default)]
    dnf_name: Option<String>,
    /// Pinned version; none installs and keeps the latest.
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    silent_args: String,
    #[serde(default)]
    uninstall_cmd: Option<String>,
    #[serde(default)]
    product_code: Option<String>,
    #[serde(default)]
    detect_name: Option<String>,
}

fn opt(s: &Option<String>) -> Option<String> {
    s.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string)
}

fn check_token(what: &str, v: &Option<String>) -> ApiResult<Option<String>> {
    match opt(v) {
        Some(t) if !valid_token(&t) => Err(bad(format!("{what} {t:?} has characters a package id doesn't (letters, digits and . _ + - : ~ only, not starting with -)"))),
        t => Ok(t),
    }
}

fn check_line(what: &str, v: &str) -> ApiResult<()> {
    if v.chars().count() > 1000 || v.chars().any(char::is_control) {
        return Err(bad(format!("{what} must be one line of at most 1000 characters")));
    }
    if !v.matches('"').count().is_multiple_of(2) {
        return Err(bad(format!("{what} has an unclosed double quote")));
    }
    Ok(())
}

/// `{8-4-4-4-12 hex}`, the form of an MSI product code.
pub fn valid_product_code(s: &str) -> bool {
    let Some(inner) = s.strip_prefix('{').and_then(|r| r.strip_suffix('}')) else { return false };
    let parts: Vec<&str> = inner.split('-').collect();
    parts.len() == 5 && [8, 4, 4, 4, 12].iter().zip(&parts).all(|(n, p)| p.len() == *n && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

struct Clean {
    name: String,
    description: String,
    publisher: Option<String>,
    winget: Option<String>,
    choco: Option<String>,
    apt: Option<String>,
    dnf: Option<String>,
    version: Option<String>,
    silent_args: String,
    uninstall_cmd: Option<String>,
    product_code: Option<String>,
    detect_name: Option<String>,
}

fn clean(b: &PackageIn) -> ApiResult<Clean> {
    let name = b.name.trim().to_string();
    if name.is_empty() || name.chars().count() > 200 {
        return Err(bad("name must be 1-200 characters"));
    }
    if b.description.chars().count() > 4000 {
        return Err(bad("the description is too long"));
    }
    check_line("silent arguments", &b.silent_args)?;
    let uninstall_cmd = opt(&b.uninstall_cmd);
    if let Some(c) = &uninstall_cmd {
        check_line("the uninstall command", c)?;
    }
    let product_code = opt(&b.product_code);
    if product_code.as_deref().is_some_and(|c| !valid_product_code(c)) {
        return Err(bad("the product code looks like {00000000-0000-0000-0000-000000000000}"));
    }
    let detect_name = opt(&b.detect_name);
    if detect_name.as_deref().is_some_and(|n| n.chars().count() > 200) {
        return Err(bad("the detection name is too long"));
    }
    Ok(Clean {
        name,
        description: b.description.trim().to_string(),
        publisher: opt(&b.publisher).map(|p| p.chars().take(200).collect()),
        winget: check_token("winget id", &b.winget_id)?,
        choco: check_token("Chocolatey id", &b.choco_id)?,
        apt: check_token("apt package", &b.apt_name)?,
        dnf: check_token("dnf package", &b.dnf_name)?,
        version: check_token("version", &b.version)?,
        silent_args: b.silent_args.trim().to_string(),
        uninstall_cmd,
        product_code,
        detect_name,
    })
}

fn name_taken(e: sqlx::Error) -> ApiError {
    match &e {
        sqlx::Error::Database(d) if d.is_unique_violation() => ApiError::Conflict("the catalog already has a package with that name".into()),
        _ => e.into(),
    }
}

pub async fn create(State(st): State<Arc<AppState>>, u: User, Json(b): Json<PackageIn>) -> ApiResult<Json<PackageOut>> {
    super::scripts::may_edit(&u, b.client_id)?;
    let c = clean(&b)?;
    if let Some(client) = b.client_id {
        let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM clients WHERE id = $1)").bind(client).fetch_one(&st.db).await?;
        if !exists {
            return Err(ApiError::NotFound("client"));
        }
    }
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO software_packages (id, client_id, name, description, publisher, winget_id, choco_id, apt_name, dnf_name, version,
                silent_args, uninstall_cmd, product_code, detect_name, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
    )
    .bind(id)
    .bind(b.client_id)
    .bind(&c.name)
    .bind(&c.description)
    .bind(&c.publisher)
    .bind(&c.winget)
    .bind(&c.choco)
    .bind(&c.apt)
    .bind(&c.dnf)
    .bind(&c.version)
    .bind(&c.silent_args)
    .bind(&c.uninstall_cmd)
    .bind(&c.product_code)
    .bind(&c.detect_name)
    .bind(u.id)
    .execute(&st.db)
    .await
    .map_err(name_taken)?;
    auth::audit(&st.db, Some(u.id), "software.package_create", Some(("software_package", id)), json!({ "name": c.name, "client_id": b.client_id })).await;
    Ok(Json(fetch_package(&st, &u, id).await?.into()))
}

/// An installed package from an uploaded file needs a version (what "newer" means) and, for an
/// EXE, silent arguments.
fn installer_ready(kind: Option<&str>, version: &Option<String>, silent_args: &str) -> ApiResult<()> {
    let Some(kind) = kind else { return Ok(()) };
    if version.is_none() {
        return Err(bad("a package with an uploaded installer needs its version (the version the file installs)"));
    }
    if kind == "exe" && silent_args.is_empty() {
        return Err(bad("an EXE installer needs silent arguments (like /S or /VERYSILENT)"));
    }
    Ok(())
}

pub async fn update(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<PackageIn>) -> ApiResult<Json<PackageOut>> {
    let cur = fetch_package(&st, &u, id).await?.p;
    super::scripts::may_edit(&u, cur.client_id)?;
    let c = clean(&b)?;
    installer_ready(cur.installer_kind.as_deref().filter(|_| cur.installer_key.is_some()), &c.version, &c.silent_args)?;
    sqlx::query(
        "UPDATE software_packages SET name = $2, description = $3, publisher = $4, winget_id = $5, choco_id = $6, apt_name = $7, dnf_name = $8,
                version = $9, silent_args = $10, uninstall_cmd = $11, product_code = $12, detect_name = $13, updated_at = now()
          WHERE id = $1",
    )
    .bind(id)
    .bind(&c.name)
    .bind(&c.description)
    .bind(&c.publisher)
    .bind(&c.winget)
    .bind(&c.choco)
    .bind(&c.apt)
    .bind(&c.dnf)
    .bind(&c.version)
    .bind(&c.silent_args)
    .bind(&c.uninstall_cmd)
    .bind(&c.product_code)
    .bind(&c.detect_name)
    .execute(&st.db)
    .await
    .map_err(name_taken)?;
    auth::audit(&st.db, Some(u.id), "software.package_update", Some(("software_package", id)), json!({ "name": c.name })).await;
    catalog_changed(&st, id).await;
    Ok(Json(fetch_package(&st, &u, id).await?.into()))
}

/// A package changed: forget earlier failures (it may work now) and enforce again where policies
/// ask for it.
async fn catalog_changed(st: &Arc<AppState>, package_id: Uuid) {
    let st = st.clone();
    tokio::spawn(async move {
        let res: sqlx::Result<()> = async {
            sqlx::query("UPDATE software_state SET fail_count = 0 WHERE package_id = $1").bind(package_id).execute(&st.db).await?;
            let agents: Vec<Uuid> = sqlx::query_scalar(
                "SELECT DISTINCT agent_id FROM agent_policy WHERE module = 'software' AND config ->> 'package_id' = $1",
            )
            .bind(package_id.to_string())
            .fetch_all(&st.db)
            .await?;
            if !agents.is_empty() {
                core::policy_changed(&st, Some(&agents)).await;
            }
            Ok(())
        }
        .await;
        if let Err(e) = res {
            tracing::warn!("software catalog change: {e}");
        }
    });
}

pub async fn delete(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let cur = fetch_package(&st, &u, id).await?.p;
    super::scripts::may_edit(&u, cur.client_id)?;
    let using: Vec<String> = sqlx::query_scalar(
        "SELECT ps.name FROM policy_items i JOIN policy_sets ps ON ps.id = i.set_id
          WHERE i.module = 'software' AND i.config ->> 'package_id' = $1 ORDER BY ps.name LIMIT 5",
    )
    .bind(id.to_string())
    .fetch_all(&st.db)
    .await?;
    if !using.is_empty() {
        return Err(ApiError::Conflict(format!("policy sets still require this package: {}. Remove those policies first.", using.join(", "))));
    }
    sqlx::query("DELETE FROM software_packages WHERE id = $1").bind(id).execute(&st.db).await?;
    if let Some(key) = &cur.installer_key
        && let Err(e) = st.storage.delete(key).await
    {
        tracing::warn!(%key, "removing a package's installer: {e:#}");
    }
    auth::audit(&st.db, Some(u.id), "software.package_delete", Some(("software_package", id)), json!({ "name": cur.name })).await;
    Ok(Json(json!({ "ok": true })))
}

/// Which kind an uploaded file is, from its name and its first bytes.
pub fn installer_kind(name: &str, head: &[u8]) -> Result<&'static str, String> {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".msi") {
        // OLE compound file.
        if head.starts_with(&[0xD0, 0xCF, 0x11, 0xE0]) { Ok("msi") } else { Err("that file isn't a Windows Installer package (.msi)".into()) }
    } else if lower.ends_with(".exe") {
        if head.starts_with(b"MZ") { Ok("exe") } else { Err("that file isn't a Windows program (.exe)".into()) }
    } else {
        Err("installers are .msi or .exe files".into())
    }
}

/// `POST /software/packages/{id}/installer`: the file as a multipart `file` field. Replaces
/// an earlier upload. Limited by RMM_ATTACHMENT_MAX_MB.
pub async fn upload_installer(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, mut mp: Multipart) -> ApiResult<Json<PackageOut>> {
    let cur = fetch_package(&st, &u, id).await?.p;
    super::scripts::may_edit(&u, cur.client_id)?;
    let mut saved = None;
    while let Some(field) = mp.next_field().await.map_err(|e| super::attachments::multipart_error(&st, e))? {
        if field.name() == Some("file") {
            saved = super::attachments::save(&st, field).await?;
            break;
        }
    }
    let saved = saved.ok_or_else(|| bad("send the installer as a `file` field"))?;
    let head = {
        use futures_util::StreamExt;
        let mut s = st.storage.read(&saved.key, 0, 8).await?;
        let mut head = Vec::new();
        while let Some(Ok(chunk)) = s.next().await {
            head.extend_from_slice(&chunk);
        }
        head
    };
    let kind = match installer_kind(&saved.name, &head) {
        Ok(k) => k,
        Err(m) => {
            super::attachments::discard(&st, &[saved]).await;
            return Err(bad(m));
        }
    };
    if let Err(e) = installer_ready(Some(kind), &cur.version, &cur.silent_args) {
        // The upload itself is fine; what's missing is on the package. Keep the file and say so.
        tracing::debug!("installer saved without deployable settings: {e}");
    }
    sqlx::query(
        "UPDATE software_packages SET installer_key = $2, installer_name = $3, installer_size = $4, installer_sha256 = $5, installer_kind = $6, updated_at = now()
          WHERE id = $1",
    )
    .bind(id)
    .bind(&saved.key)
    .bind(&saved.name)
    .bind(saved.size)
    .bind(hex::encode(&saved.sha256))
    .bind(kind)
    .execute(&st.db)
    .await?;
    if let Some(old) = &cur.installer_key
        && let Err(e) = st.storage.delete(old).await
    {
        tracing::warn!(key = %old, "removing a replaced installer: {e:#}");
    }
    auth::audit(
        &st.db,
        Some(u.id),
        "software.installer_upload",
        Some(("software_package", id)),
        json!({ "name": cur.name, "file": saved.name, "size": saved.size, "sha256": hex::encode(&saved.sha256), "kind": kind }),
    )
    .await;
    catalog_changed(&st, id).await;
    Ok(Json(fetch_package(&st, &u, id).await?.into()))
}

pub async fn delete_installer(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<PackageOut>> {
    let cur = fetch_package(&st, &u, id).await?.p;
    super::scripts::may_edit(&u, cur.client_id)?;
    let Some(key) = cur.installer_key.clone() else { return Err(ApiError::NotFound("installer")) };
    sqlx::query(
        "UPDATE software_packages SET installer_key = NULL, installer_name = NULL, installer_size = NULL, installer_sha256 = NULL,
                installer_kind = NULL, updated_at = now() WHERE id = $1",
    )
    .bind(id)
    .execute(&st.db)
    .await?;
    if let Err(e) = st.storage.delete(&key).await {
        tracing::warn!(%key, "removing an installer: {e:#}");
    }
    auth::audit(&st.db, Some(u.id), "software.installer_delete", Some(("software_package", id)), json!({ "name": cur.name })).await;
    Ok(Json(fetch_package(&st, &u, id).await?.into()))
}

/// `GET /agent/software/{id}/installer`: the file, for an agent (its id in `X-Rmm-Agent`, its
/// secret as the bearer token), with `Range` so an interrupted download resumes. Only for
/// packages its client may use.
pub async fn agent_installer(State(st): State<Arc<AppState>>, Path(id): Path<Uuid>, headers: HeaderMap) -> ApiResult<Response> {
    let agent_id = headers.get("x-rmm-agent").and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<Uuid>().ok());
    let secret = headers.get(axum::http::header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer "));
    let (Some(agent_id), Some(secret)) = (agent_id, secret) else { return Err(ApiError::Unauthorized) };
    if !crate::agent_ws::authenticate(&st, agent_id, secret).await? {
        return Err(ApiError::Unauthorized);
    }
    let row: Option<(String, i64, String)> = sqlx::query_as(
        "SELECT p.installer_key, p.installer_size, coalesce(p.installer_name, 'installer') FROM software_packages p, agents a JOIN sites s ON s.id = a.site_id
          WHERE p.id = $1 AND a.id = $2 AND p.installer_key IS NOT NULL AND (p.client_id IS NULL OR p.client_id = s.client_id)",
    )
    .bind(id)
    .bind(agent_id)
    .fetch_optional(&st.db)
    .await?;
    let (key, size, name) = row.ok_or(ApiError::NotFound("installer"))?;
    super::attachments::serve(&st, &headers, &key, size, &name, "application/octet-stream", false).await
}

// ---------------------------------------------------------------------------
// Per-device status
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct DeviceStatus {
    agent_id: Uuid,
    hostname: String,
    os_family: String,
    online: bool,
    client_id: Uuid,
    client_name: String,
    site_name: String,
    package_id: Uuid,
    package_name: String,
    pin: Option<String>,
    installed: Option<String>,
    available: Option<String>,
    ignored: Option<String>,
    /// The provider that looked; none: nothing on the device could.
    provider: Option<String>,
    checked_at: Option<DateTime<Utc>>,
    /// What the device's policies ask for (the strictest), if anything.
    desired: Option<Want>,
    /// Policy items asking.
    policy_items: Vec<Uuid>,
    /// Meets what the policies ask for; none when nothing is asked or it isn't known yet.
    compliant: Option<bool>,
    /// What happened last: a run's status, op and error.
    last_run: Option<Value>,
    fail_count: i32,
    last_error: Option<String>,
}

#[derive(sqlx::FromRow)]
struct DeviceRow {
    agent_id: Uuid,
    hostname: String,
    os_family: String,
    online: bool,
    client_id: Uuid,
    client_name: String,
    site_name: String,
    package_id: Uuid,
    package_name: String,
    pin: Option<String>,
    installed: Option<String>,
    available: Option<String>,
    ignored: Option<String>,
    provider: Option<String>,
    checked_at: Option<DateTime<Utc>>,
    wants: Vec<String>,
    items: Vec<Uuid>,
    in_window: bool,
    fail_count: Option<i32>,
    last_error: Option<String>,
    last_run: Option<Value>,
}

impl From<DeviceRow> for DeviceStatus {
    fn from(r: DeviceRow) -> Self {
        let wants: Vec<Want> = r.wants.iter().filter_map(|w| serde_json::from_value(Value::String(w.clone())).ok()).collect();
        let desired = core::strictest(wants);
        // Not scanned (or no provider could look): nothing to compare.
        let known = r.checked_at.is_some() && r.provider.is_some();
        let compliant = desired.filter(|_| known).map(|w| {
            core::compliant(w, Facts { installed: r.installed.as_deref(), available: r.available.as_deref(), ignored: r.ignored.as_deref(), pin: r.pin.as_deref(), in_window: r.in_window })
        });
        DeviceStatus {
            agent_id: r.agent_id,
            hostname: r.hostname,
            os_family: r.os_family,
            online: r.online,
            client_id: r.client_id,
            client_name: r.client_name,
            site_name: r.site_name,
            package_id: r.package_id,
            package_name: r.package_name,
            pin: r.pin,
            installed: r.installed,
            available: r.available,
            ignored: r.ignored,
            provider: r.provider,
            checked_at: r.checked_at,
            desired,
            policy_items: r.items,
            compliant,
            last_run: r.last_run,
            fail_count: r.fail_count.unwrap_or(0),
            last_error: r.last_error,
        }
    }
}

/// One row per agent and package, with what the agent's policies ask. `$1` scope, `$2` client,
/// `$3` agent, `$4` package, `$5` search.
const DEVICE_SELECT: &str = "SELECT a.id AS agent_id, a.hostname, a.os_family, a.online, s.client_id, c.name AS client_name, s.name AS site_name,
        p.id AS package_id, p.name AS package_name, p.version AS pin,
        ss.installed_version AS installed, ss.available_version AS available, ss.ignored_version AS ignored, ss.provider, ss.checked_at,
        coalesce(w.wants, '{}') AS wants, coalesce(w.items, '{}') AS items, coalesce(w.in_window, true) AS in_window,
        ss.fail_count, ss.last_error,
        (SELECT jsonb_build_object('id', r.id, 'op', r.op, 'status', r.status, 'trigger', r.trigger, 'at', coalesce(r.finished_at, r.created_at), 'error', r.error)
           FROM software_runs r WHERE r.agent_id = a.id AND r.package_id = p.id ORDER BY r.created_at DESC LIMIT 1) AS last_run
   FROM agents a
   JOIN sites s ON s.id = a.site_id
   JOIN clients c ON c.id = s.client_id
   JOIN software_packages p ON (p.client_id IS NULL OR p.client_id = s.client_id)
   LEFT JOIN software_state ss ON ss.agent_id = a.id AND ss.package_id = p.id
   LEFT JOIN LATERAL (
        SELECT array_agg(ap.config ->> 'state') AS wants, array_agg(ap.item_id) AS items,
               bool_or(in_maintenance_window(
                    CASE WHEN jsonb_typeof(ap.config -> 'window') = 'object'
                         THEN ARRAY(SELECT d::smallint FROM jsonb_array_elements_text(ap.config -> 'window' -> 'days') d) ELSE s.maint_days END,
                    CASE WHEN jsonb_typeof(ap.config -> 'window') = 'object' THEN (ap.config -> 'window' ->> 'start')::time ELSE s.maint_start END,
                    CASE WHEN jsonb_typeof(ap.config -> 'window') = 'object' THEN (ap.config -> 'window' ->> 'minutes')::int ELSE s.maint_minutes END,
                    CASE WHEN jsonb_typeof(ap.config -> 'window') = 'object' AND ap.config -> 'window' ->> 'tz' <> 'site'
                         THEN ap.config -> 'window' ->> 'tz' ELSE s.maint_tz END, now())) AS in_window
          FROM agent_policy ap WHERE ap.agent_id = a.id AND ap.module = 'software' AND ap.enabled AND ap.config ->> 'package_id' = p.id::text) w ON true
  WHERE ($1::uuid[] IS NULL OR s.client_id = ANY($1))
    AND ($2::uuid IS NULL OR s.client_id = $2)
    AND ($3::uuid IS NULL OR a.id = $3)
    AND ($4::uuid IS NULL OR p.id = $4)
    AND ($5::text IS NULL OR a.hostname ILIKE '%' || $5 || '%' OR p.name ILIKE '%' || $5 || '%')";

#[derive(Deserialize)]
pub struct DevicesQuery {
    client_id: Option<Uuid>,
    q: Option<String>,
    /// `installed` (default), `missing` (not installed, though a policy asks), `noncompliant`, or `all`.
    show: Option<String>,
}

/// `GET /software/packages/{id}/devices`: where the package is installed, and where policies
/// ask for it.
pub async fn package_devices(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Query(q): Query<DevicesQuery>) -> ApiResult<Json<Value>> {
    let pkg = fetch_package(&st, &u, id).await?.p;
    let search = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let mut sql = String::from(DEVICE_SELECT);
    // A client's package belongs on that client's devices only (the join covers it); the OS
    // filter drops devices that can't use it at all.
    sql.push_str(" AND CASE a.os_family WHEN 'windows' THEN $6 WHEN 'linux' THEN $7 ELSE false END ORDER BY c.name, a.hostname LIMIT 2000");
    let rows: Vec<DeviceRow> = sqlx::query_as(AssertSqlSafe(sql))
        .bind(u.scope())
        .bind(q.client_id)
        .bind(None::<Uuid>)
        .bind(id)
        .bind(search)
        .bind(core::usable_on(&pkg, "windows"))
        .bind(core::usable_on(&pkg, "linux"))
        .fetch_all(&st.db)
        .await?;
    let show = q.show.as_deref().unwrap_or("installed");
    let items: Vec<DeviceStatus> = rows
        .into_iter()
        .map(DeviceStatus::from)
        .filter(|d| match show {
            "all" => true,
            "missing" => d.installed.is_none() && d.desired.is_some_and(|w| w != Want::Absent),
            "noncompliant" => d.compliant == Some(false),
            _ => d.installed.is_some() || d.desired.is_some(),
        })
        .collect();
    Ok(Json(json!({ "items": items })))
}

/// `GET /agents/{id}/software`: what the device has of the catalog, what its policies ask, and
/// its recent runs.
pub async fn for_agent(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Query(q): Query<AllQuery>) -> ApiResult<Json<Value>> {
    super::access::agent(&st, &u, id).await?;
    let mut sql = String::from(DEVICE_SELECT);
    sql.push_str(" AND CASE a.os_family WHEN 'windows' THEN (p.winget_id IS NOT NULL OR p.choco_id IS NOT NULL OR p.installer_key IS NOT NULL) WHEN 'linux' THEN (p.apt_name IS NOT NULL OR p.dnf_name IS NOT NULL) ELSE false END ORDER BY p.name");
    let rows: Vec<DeviceRow> = sqlx::query_as(AssertSqlSafe(sql))
        .bind(u.scope())
        .bind(None::<Uuid>)
        .bind(id)
        .bind(None::<Uuid>)
        .bind(None::<String>)
        .fetch_all(&st.db)
        .await?;
    let all = q.all.unwrap_or(false);
    let items: Vec<DeviceStatus> = rows.into_iter().map(DeviceStatus::from).filter(|d| all || d.installed.is_some() || d.desired.is_some()).collect();
    type StatusRow = (Vec<String>, Option<DateTime<Utc>>, Option<DateTime<Utc>>, Option<String>);
    let status: Option<StatusRow> =
        sqlx::query_as("SELECT providers, scanned_at, requested_at, error FROM software_agent_status WHERE agent_id = $1").bind(id).fetch_optional(&st.db).await?;
    let capable: bool = sqlx::query_scalar("SELECT $2 = ANY(capabilities) FROM agents WHERE id = $1").bind(id).bind(rmm_proto::software::CAPABILITY).fetch_one(&st.db).await?;
    let runs = runs_query(&st, &u, RunsQuery { agent_id: Some(id), package_id: None, client_id: None, status: None, limit: Some(50) }).await?;
    Ok(Json(json!({
        "capable": capable,
        "providers": status.as_ref().map(|s| s.0.clone()).unwrap_or_default(),
        "scanned_at": status.as_ref().and_then(|s| s.1),
        "scan_requested_at": status.as_ref().and_then(|s| s.2),
        "scan_error": status.and_then(|s| s.3),
        "items": items,
        "runs": runs,
    })))
}

#[derive(Deserialize)]
pub struct AllQuery {
    /// Every package the device could use, not only those installed or required.
    all: Option<bool>,
}

// ---------------------------------------------------------------------------
// Deploying
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct DeployBody {
    package_id: Uuid,
    /// `install`, `upgrade` or `uninstall`.
    op: String,
    agent_ids: Vec<Uuid>,
    /// Allow installing Chocolatey first if the package needs it.
    #[serde(default)]
    bootstrap_choco: bool,
}

pub async fn deploy(State(st): State<Arc<AppState>>, u: User, Json(b): Json<DeployBody>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    let op = Op::parse(&b.op).ok_or_else(|| bad("op must be install, upgrade or uninstall"))?;
    if b.agent_ids.is_empty() || b.agent_ids.len() > 5000 {
        return Err(bad("choose 1-5000 devices"));
    }
    let pkg = fetch_package(&st, &u, b.package_id).await?.p;
    let agents: Vec<(Uuid, String, String, Uuid, bool, bool)> = sqlx::query_as(
        "SELECT a.id, a.hostname, a.os_family, s.client_id, $3 = ANY(a.capabilities),
                EXISTS (SELECT 1 FROM software_runs r WHERE r.agent_id = a.id AND r.status IN ('queued', 'sent'))
           FROM agents a JOIN sites s ON s.id = a.site_id
          WHERE a.id = ANY($1) AND ($2::uuid[] IS NULL OR s.client_id = ANY($2))",
    )
    .bind(&b.agent_ids)
    .bind(u.scope())
    .bind(rmm_proto::software::CAPABILITY)
    .fetch_all(&st.db)
    .await?;
    if agents.is_empty() {
        return Err(ApiError::NotFound("agent"));
    }
    let mut runs = Vec::new();
    let mut skipped = Vec::new();
    for (agent_id, hostname, os, client_id, capable, busy) in agents {
        let skip = |reason: &str| json!({ "agent_id": agent_id, "hostname": hostname, "reason": reason });
        if pkg.client_id.is_some_and(|c| c != client_id) {
            skipped.push(skip("this package belongs to another client"));
        } else if !capable {
            skipped.push(skip("its agent version doesn't support software deployment; update the agent"));
        } else if !core::usable_on(&pkg, &os) {
            skipped.push(skip("the package has no id or installer for this kind of device"));
        } else if busy {
            skipped.push(skip("another software run is queued or running on it"));
        } else {
            let (run_id, sent) = core::start_run(&st, agent_id, &pkg, op, Trigger::Manual(u.id), b.bootstrap_choco).await?;
            runs.push(json!({ "run_id": run_id, "agent_id": agent_id, "hostname": hostname, "sent": sent }));
        }
    }
    auth::audit(
        &st.db,
        Some(u.id),
        "software.deploy",
        Some(("software_package", pkg.id)),
        json!({ "name": pkg.name, "op": op.as_str(), "runs": runs.len(), "skipped": skipped.len(), "bootstrap_choco": b.bootstrap_choco }),
    )
    .await;
    Ok(Json(json!({ "runs": runs, "skipped": skipped })))
}

#[derive(Deserialize)]
pub struct ScanBody {
    agent_ids: Vec<Uuid>,
}

/// `POST /software/scan`: ask devices what they have of the catalog, now.
pub async fn scan(State(st): State<Arc<AppState>>, u: User, Json(b): Json<ScanBody>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    if b.agent_ids.is_empty() || b.agent_ids.len() > 5000 {
        return Err(bad("choose 1-5000 devices"));
    }
    let allowed: Vec<Uuid> = sqlx::query_scalar(
        "SELECT a.id FROM agents a JOIN sites s ON s.id = a.site_id WHERE a.id = ANY($1) AND ($2::uuid[] IS NULL OR s.client_id = ANY($2))",
    )
    .bind(&b.agent_ids)
    .bind(u.scope())
    .fetch_all(&st.db)
    .await?;
    let asked = core::scan_now(&st, &allowed).await?;
    Ok(Json(json!({ "asked": asked, "devices": allowed.len() })))
}

// ---------------------------------------------------------------------------
// Runs
// ---------------------------------------------------------------------------

#[derive(Deserialize, Default)]
pub struct RunsQuery {
    agent_id: Option<Uuid>,
    package_id: Option<Uuid>,
    client_id: Option<Uuid>,
    /// Comma-separated statuses.
    status: Option<String>,
    limit: Option<i64>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct RunRow {
    id: Uuid,
    agent_id: Uuid,
    hostname: String,
    client_id: Uuid,
    client_name: String,
    package_id: Option<Uuid>,
    package_name: String,
    op: String,
    trigger: String,
    policy_item_id: Option<Uuid>,
    created_by_name: Option<String>,
    status: String,
    stage: Option<String>,
    progress: Option<String>,
    error: Option<String>,
    provider: Option<String>,
    from_version: Option<String>,
    to_version: Option<String>,
    reboot_required: bool,
    created_at: DateTime<Utc>,
    sent_at: Option<DateTime<Utc>>,
    finished_at: Option<DateTime<Utc>>,
    duration_ms: Option<i64>,
}

const RUN_COLS: &str = "r.id, r.agent_id, a.hostname, s.client_id, c.name AS client_name, r.package_id, r.package_name, r.op, r.trigger, r.policy_item_id,
    u.name AS created_by_name, r.status, r.stage, r.progress, r.error, r.provider, r.from_version, r.to_version, r.reboot_required,
    r.created_at, r.sent_at, r.finished_at, r.duration_ms";
const RUN_FROM: &str = "FROM software_runs r JOIN agents a ON a.id = r.agent_id JOIN sites s ON s.id = a.site_id JOIN clients c ON c.id = s.client_id
    LEFT JOIN users u ON u.id = r.created_by";

async fn runs_query(st: &AppState, u: &User, q: RunsQuery) -> ApiResult<Vec<RunRow>> {
    let status: Option<Vec<String>> = q.status.as_deref().filter(|s| !s.is_empty()).map(|s| s.split(',').map(|x| x.trim().to_string()).collect());
    Ok(sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {RUN_COLS} {RUN_FROM}
          WHERE ($1::uuid[] IS NULL OR s.client_id = ANY($1)) AND ($2::uuid IS NULL OR r.agent_id = $2) AND ($3::uuid IS NULL OR r.package_id = $3)
            AND ($4::uuid IS NULL OR s.client_id = $4) AND ($5::text[] IS NULL OR r.status = ANY($5))
          ORDER BY r.created_at DESC, r.id DESC LIMIT $6"
    )))
    .bind(u.scope())
    .bind(q.agent_id)
    .bind(q.package_id)
    .bind(q.client_id)
    .bind(status)
    .bind(q.limit.unwrap_or(200).clamp(1, 500))
    .fetch_all(&st.db)
    .await?)
}

pub async fn runs(State(st): State<Arc<AppState>>, u: User, Query(q): Query<RunsQuery>) -> ApiResult<Json<Vec<RunRow>>> {
    Ok(Json(runs_query(&st, &u, q).await?))
}

pub async fn run(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let row: RunRow = sqlx::query_as(AssertSqlSafe(format!("SELECT {RUN_COLS} {RUN_FROM} WHERE r.id = $2 AND ($1::uuid[] IS NULL OR s.client_id = ANY($1))")))
        .bind(u.scope())
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("run"))?;
    let output: String = sqlx::query_scalar("SELECT output FROM software_runs WHERE id = $1").bind(id).fetch_one(&st.db).await?;
    let mut v = serde_json::to_value(&row).map_err(anyhow::Error::from)?;
    v["output"] = Value::String(output);
    Ok(Json(v))
}

/// Cancels a run that hasn't been sent yet.
pub async fn cancel_run(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    let client: Option<Uuid> = sqlx::query_scalar("SELECT s.client_id FROM software_runs r JOIN agents a ON a.id = r.agent_id JOIN sites s ON s.id = a.site_id WHERE r.id = $1")
        .bind(id)
        .fetch_optional(&st.db)
        .await?;
    client.filter(|c| u.can_see_client(*c)).ok_or(ApiError::NotFound("run"))?;
    let n = sqlx::query("UPDATE software_runs SET status = 'cancelled', finished_at = now() WHERE id = $1 AND status = 'queued'").bind(id).execute(&st.db).await?.rows_affected();
    if n == 0 {
        return Err(ApiError::Conflict("only a run that hasn't been sent yet can be cancelled".into()));
    }
    auth::audit(&st.db, Some(u.id), "software.run_cancel", Some(("software_run", id)), json!({})).await;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Updates to third-party software
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct UpdatesQuery {
    client_id: Option<Uuid>,
    package_id: Option<Uuid>,
    q: Option<String>,
    /// Include versions people chose to ignore.
    ignored: Option<bool>,
}

/// `GET /software/updates`: installed catalog packages with a newer version on offer.
pub async fn updates(State(st): State<Arc<AppState>>, u: User, Query(q): Query<UpdatesQuery>) -> ApiResult<Json<Value>> {
    let search = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let mut sql = String::from(DEVICE_SELECT);
    sql.push_str(" AND ss.installed_version IS NOT NULL AND ss.available_version IS NOT NULL AND ($6 OR ss.available_version IS DISTINCT FROM ss.ignored_version)
         ORDER BY p.name, c.name, a.hostname LIMIT 1000");
    let rows: Vec<DeviceRow> = sqlx::query_as(AssertSqlSafe(sql))
        .bind(u.scope())
        .bind(q.client_id)
        .bind(None::<Uuid>)
        .bind(q.package_id)
        .bind(search)
        .bind(q.ignored.unwrap_or(false))
        .fetch_all(&st.db)
        .await?;
    let items: Vec<DeviceStatus> = rows.into_iter().map(DeviceStatus::from).collect();
    // Per package, for the summary.
    let mut by: HashMap<Uuid, (String, i64)> = HashMap::new();
    for d in &items {
        by.entry(d.package_id).or_insert_with(|| (d.package_name.clone(), 0)).1 += 1;
    }
    let mut packages: Vec<Value> = by.into_iter().map(|(id, (name, devices))| json!({ "package_id": id, "name": name, "devices": devices })).collect();
    packages.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    Ok(Json(json!({ "items": items, "packages": packages })))
}

#[derive(Deserialize)]
pub struct UpdateItem {
    agent_id: Uuid,
    package_id: Uuid,
}

#[derive(Deserialize)]
pub struct UpdatesBody {
    items: Vec<UpdateItem>,
    /// `ignore`: true skips the version on offer now (a newer one shows again); false undoes it.
    #[serde(default)]
    ignore: Option<bool>,
}

fn check_items(items: &[UpdateItem]) -> ApiResult<()> {
    if items.is_empty() || items.len() > 5000 {
        return Err(bad("choose 1-5000 updates"));
    }
    Ok(())
}

/// `POST /software/updates/install`: upgrades these package and device pairs now.
pub async fn install_updates(State(st): State<Arc<AppState>>, u: User, Json(b): Json<UpdatesBody>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    check_items(&b.items)?;
    let mut runs = Vec::new();
    let mut skipped = Vec::new();
    for it in &b.items {
        let row: Option<(String, bool, bool, Option<String>)> = sqlx::query_as(
            "SELECT a.hostname, $4 = ANY(a.capabilities), EXISTS (SELECT 1 FROM software_runs r WHERE r.agent_id = a.id AND r.status IN ('queued', 'sent')), ss.available_version
               FROM agents a JOIN sites s ON s.id = a.site_id
               LEFT JOIN software_state ss ON ss.agent_id = a.id AND ss.package_id = $2 AND ss.installed_version IS NOT NULL
              WHERE a.id = $1 AND ($3::uuid[] IS NULL OR s.client_id = ANY($3))",
        )
        .bind(it.agent_id)
        .bind(it.package_id)
        .bind(u.scope())
        .bind(rmm_proto::software::CAPABILITY)
        .fetch_optional(&st.db)
        .await?;
        let Some((hostname, capable, busy, available)) = row else { continue };
        let skip = |reason: &str| json!({ "agent_id": it.agent_id, "package_id": it.package_id, "hostname": hostname, "reason": reason });
        if available.is_none() {
            skipped.push(skip("no update is on offer for it"));
        } else if !capable {
            skipped.push(skip("its agent version doesn't support software deployment; update the agent"));
        } else if busy {
            skipped.push(skip("another software run is queued or running on it"));
        } else if let Some(pkg) = core::load_package(&st, it.package_id).await? {
            let (run_id, sent) = core::start_run(&st, it.agent_id, &pkg, Op::Upgrade, Trigger::Manual(u.id), false).await?;
            runs.push(json!({ "run_id": run_id, "agent_id": it.agent_id, "hostname": hostname, "sent": sent }));
        }
    }
    auth::audit(&st.db, Some(u.id), "software.updates_install", None, json!({ "requested": b.items.len(), "runs": runs.len(), "skipped": skipped.len() })).await;
    Ok(Json(json!({ "runs": runs, "skipped": skipped })))
}

/// `POST /software/updates/ignore`: skip (or stop skipping) the version on offer.
pub async fn ignore_updates(State(st): State<Arc<AppState>>, u: User, Json(b): Json<UpdatesBody>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    check_items(&b.items)?;
    let ignore = b.ignore.unwrap_or(true);
    let mut changed = 0;
    for it in &b.items {
        let n = sqlx::query(
            "UPDATE software_state ss SET ignored_version = CASE WHEN $3 THEN ss.available_version END
               FROM agents a JOIN sites s ON s.id = a.site_id
              WHERE ss.agent_id = a.id AND a.id = $1 AND ss.package_id = $2 AND ($4::uuid[] IS NULL OR s.client_id = ANY($4))",
        )
        .bind(it.agent_id)
        .bind(it.package_id)
        .bind(ignore)
        .bind(u.scope())
        .execute(&st.db)
        .await?
        .rows_affected();
        changed += n;
    }
    auth::audit(&st.db, Some(u.id), "software.updates_ignore", None, json!({ "ignore": ignore, "changed": changed })).await;
    if !ignore {
        let agents: Vec<Uuid> = b.items.iter().map(|i| i.agent_id).collect();
        core::policy_changed(&st, Some(&agents)).await;
    }
    Ok(Json(json!({ "changed": changed })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_codes() {
        assert!(valid_product_code("{11111111-2222-3333-4444-555555555555}"));
        assert!(valid_product_code("{ABCDEF01-2222-3333-4444-555555555555}"));
        for bad in ["11111111-2222-3333-4444-555555555555", "{1111-2222-3333-4444-555555555555}", "{1111111g-2222-3333-4444-555555555555}", "{}"] {
            assert!(!valid_product_code(bad), "{bad}");
        }
    }

    #[test]
    fn installer_kinds_need_matching_names_and_magic() {
        assert_eq!(installer_kind("App.MSI", &[0xD0, 0xCF, 0x11, 0xE0, 0, 0]), Ok("msi"));
        assert_eq!(installer_kind("setup.exe", b"MZ\x90\0"), Ok("exe"));
        assert!(installer_kind("setup.exe", b"#!/bin/sh").is_err());
        assert!(installer_kind("app.msi", b"MZ").is_err());
        assert!(installer_kind("archive.zip", b"PK").is_err());
    }

    #[test]
    fn package_input_is_checked() {
        let ok = PackageIn {
            client_id: None,
            name: " Firefox ".into(),
            description: String::new(),
            publisher: None,
            winget_id: Some("Mozilla.Firefox".into()),
            choco_id: Some("".into()),
            apt_name: Some("firefox".into()),
            dnf_name: None,
            version: None,
            silent_args: "/S".into(),
            uninstall_cmd: None,
            product_code: None,
            detect_name: None,
        };
        let c = clean(&ok).unwrap();
        assert_eq!((c.name.as_str(), c.choco), ("Firefox", None));
        for mutate in [
            |p: &mut PackageIn| p.winget_id = Some("--accept-all".into()),
            |p: &mut PackageIn| p.apt_name = Some("a b".into()),
            |p: &mut PackageIn| p.version = Some("1.0; rm".into()),
            |p: &mut PackageIn| p.name = "  ".into(),
            |p: &mut PackageIn| p.silent_args = "/S \"x".into(),
            |p: &mut PackageIn| p.product_code = Some("nope".into()),
        ] {
            let mut p = PackageIn { name: "x".into(), winget_id: None, apt_name: None, ..ok_clone(&ok) };
            mutate(&mut p);
            assert!(clean(&p).is_err());
        }
    }

    fn ok_clone(p: &PackageIn) -> PackageIn {
        PackageIn {
            client_id: p.client_id,
            name: p.name.clone(),
            description: p.description.clone(),
            publisher: p.publisher.clone(),
            winget_id: p.winget_id.clone(),
            choco_id: p.choco_id.clone(),
            apt_name: p.apt_name.clone(),
            dnf_name: p.dnf_name.clone(),
            version: p.version.clone(),
            silent_args: p.silent_args.clone(),
            uninstall_cmd: p.uninstall_cmd.clone(),
            product_code: p.product_code.clone(),
            detect_name: p.detect_name.clone(),
        }
    }

    #[test]
    fn exe_installers_need_arguments_and_a_version() {
        assert!(installer_ready(None, &None, "").is_ok());
        assert!(installer_ready(Some("msi"), &Some("1.0".into()), "").is_ok());
        assert!(installer_ready(Some("msi"), &None, "").is_err());
        assert!(installer_ready(Some("exe"), &Some("1.0".into()), "").is_err());
        assert!(installer_ready(Some("exe"), &Some("1.0".into()), "/S").is_ok());
    }
}
