//! Feed sync: downloads into Postgres, daily, only for the ecosystems present in the fleet.
//!
//! | Feed | Source (override) | How |
//! |---|---|---|
//! | `osv:<Ecosystem>` | `<RMM_VULN_OSV_URL>/<Ecosystem>/all.zip` | whole dump, streamed to a temp file, read entry by entry |
//! | `arch` | `RMM_VULN_ARCH_URL` | the tracker's JSON |
//! | `nvd` | `RMM_VULN_NVD_URL` (`RMM_NVD_API_KEY`) | per mapped product present in the fleet; incremental by `lastModStartDate` |
//! | `kev` | `RMM_VULN_KEV_URL` | CISA's catalogue |
//! | `epss` | `RMM_VULN_EPSS_URL` | FIRST's daily CSV (gzipped or not), CVEs we know only |
//!
//! Downloads are conditional (ETag, Last-Modified). After a full dump, the feed's advisories that
//! weren't in it are removed. Air-gapped installs load the same files with `vuln-import`.

use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use chrono::Utc;
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

use super::osv::Advisory;
use crate::state::AppState;

pub const OSV_FEEDS: &[&str] = &["Debian", "Ubuntu", "AlmaLinux", "Rocky Linux", "Red Hat", "SUSE", "openSUSE", "Alpine"];

const BATCH: usize = 500;
/// The largest download accepted (the biggest OSV dumps are a few hundred MB).
const MAX_DOWNLOAD: u64 = 4 << 30;

static RUNNING: AtomicBool = AtomicBool::new(false);

pub fn running() -> bool {
    RUNNING.load(Ordering::SeqCst)
}

fn env(key: &str, default: &str) -> String {
    std::env::var(key).ok().map(|v| v.trim().trim_end_matches('/').to_string()).filter(|v| !v.is_empty()).unwrap_or_else(|| default.to_string())
}

pub struct Urls {
    pub osv: String,
    pub arch: String,
    pub nvd: String,
    pub kev: String,
    pub epss: String,
    pub nvd_key: Option<String>,
}

impl Urls {
    pub fn from_env() -> Urls {
        Urls {
            osv: env("RMM_VULN_OSV_URL", "https://osv-vulnerabilities.storage.googleapis.com"),
            arch: env("RMM_VULN_ARCH_URL", "https://security.archlinux.org/issues/all.json"),
            nvd: env("RMM_VULN_NVD_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0"),
            kev: env("RMM_VULN_KEV_URL", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"),
            epss: env("RMM_VULN_EPSS_URL", "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"),
            nvd_key: std::env::var("RMM_NVD_API_KEY").ok().map(|k| k.trim().to_string()).filter(|k| !k.is_empty()),
        }
    }
}

fn client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .user_agent(concat!("rmm-server/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(3600))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()?)
}

/// Every hour: sync the feeds that are due. The first look is an hour after start, so a fresh
/// install has its inventory in first (and restarts don't hammer the feeds). `RMM_VULN_SYNC_HOURS`
/// (default 24) is how old a feed may get; 0 turns the automatic sync off.
pub async fn daily(st: Arc<AppState>) {
    let hours: i64 = std::env::var("RMM_VULN_SYNC_HOURS").ok().and_then(|v| v.trim().parse().ok()).unwrap_or(24);
    if hours <= 0 {
        info!("vulnerabilities: automatic feed sync is off (RMM_VULN_SYNC_HOURS=0)");
        return;
    }
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + Duration::from_secs(3600), Duration::from_secs(3600));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        match sync(&st.db, None, false, hours).await {
            Ok(r) if !r.is_empty() => info!("vulnerabilities: feeds synced: {}", summary(&r)),
            Ok(_) => {}
            Err(e) => warn!("vulnerabilities: feed sync: {e:#}"),
        }
    }
}

pub fn summary(r: &[(String, Result<usize, String>)]) -> String {
    r.iter()
        .map(|(f, x)| match x {
            Ok(n) => format!("{f}: {n}"),
            Err(e) => format!("{f}: failed ({e})"),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Feeds the fleet needs: those of the ecosystems devices are in, and KEV and EPSS once any is.
pub async fn relevant(db: &sqlx::PgPool) -> sqlx::Result<BTreeSet<String>> {
    let ecos: Vec<String> = sqlx::query_scalar("SELECT DISTINCT vuln_ecosystem FROM agents WHERE vuln_ecosystem IS NOT NULL").fetch_all(db).await?;
    let mut out: BTreeSet<String> = ecos.iter().map(|e| super::feed_for(e)).collect();
    if !out.is_empty() {
        out.insert("kev".into());
        out.insert("epss".into());
    }
    Ok(out)
}

struct Guard;

impl Drop for Guard {
    fn drop(&mut self) {
        RUNNING.store(false, Ordering::SeqCst);
    }
}

/// Syncs `only` (or every relevant feed), each if it is enabled and older than `max_age_hours`
/// (or always, with `force`). One sync at a time. Returns what each feed did.
pub async fn sync(db: &sqlx::PgPool, only: Option<Vec<String>>, force: bool, max_age_hours: i64) -> Result<Vec<(String, Result<usize, String>)>> {
    if RUNNING.swap(true, Ordering::SeqCst) {
        bail!("a sync is already running");
    }
    let _guard = Guard;
    let wanted: BTreeSet<String> = match only {
        Some(list) => list.into_iter().collect(),
        None => relevant(db).await?,
    };
    let rows: Vec<(String, bool, Option<chrono::DateTime<Utc>>)> = sqlx::query_as("SELECT name, enabled, last_sync_at FROM vuln_feeds").fetch_all(db).await?;
    let due: Vec<String> = rows
        .into_iter()
        .filter(|(n, enabled, last)| wanted.contains(n) && *enabled && (force || last.is_none_or(|t| t < Utc::now() - chrono::Duration::hours(max_age_hours) + chrono::Duration::minutes(30))))
        .map(|r| r.0)
        .collect();
    if due.is_empty() {
        return Ok(vec![]);
    }
    let urls = Urls::from_env();
    let http = client()?;
    let mut report = Vec::new();
    let mut changed = false;
    // Advisories before scores: KEV and EPSS are copied onto what is there.
    let order = |f: &String| match f.as_str() {
        "kev" => 2,
        "epss" => 3,
        _ => 1,
    };
    let mut due = due;
    due.sort_by_key(order);
    for feed in due {
        sqlx::query("UPDATE vuln_feeds SET last_attempt_at = now(), progress = 'starting' WHERE name = $1").bind(&feed).execute(db).await?;
        let res = match feed.as_str() {
            "arch" => sync_arch(db, &http, &urls).await,
            "nvd" => sync_nvd(db, &http, &urls).await,
            "kev" => sync_kev(db, &http, &urls).await,
            "epss" => sync_epss(db, &http, &urls).await,
            f if f.starts_with("osv:") => sync_osv(db, &http, &urls, f).await,
            f => Err(anyhow!("unknown feed {f}")),
        };
        let res = match res {
            Ok(Some(n)) => {
                changed = true;
                finish(db, &feed, Ok(Some(n))).await?;
                Ok(n)
            }
            Ok(None) => {
                finish(db, &feed, Ok(None)).await?;
                Ok(0)
            }
            Err(e) => {
                warn!(feed, "vulnerability feed: {e:#}");
                let msg = format!("{e:#}");
                finish(db, &feed, Err(&msg)).await?;
                Err(msg)
            }
        };
        report.push((feed, res));
    }
    if changed {
        apply_scores(db).await?;
        super::requeue(db, None).await?;
    }
    Ok(report)
}

/// Records the outcome: `Ok(Some(n))` stored n records, `Ok(None)` unchanged upstream.
async fn finish(db: &sqlx::PgPool, feed: &str, res: Result<Option<usize>, &str>) -> sqlx::Result<()> {
    match res {
        Ok(n) => {
            sqlx::query(
                "UPDATE vuln_feeds SET last_sync_at = now(), error = NULL, progress = NULL,
                        records = coalesce($2, records) WHERE name = $1",
            )
            .bind(feed)
            .bind(n.map(|n| n as i32))
            .execute(db)
            .await?;
        }
        Err(e) => {
            sqlx::query("UPDATE vuln_feeds SET error = left($2, 1000), progress = NULL WHERE name = $1").bind(feed).bind(e).execute(db).await?;
        }
    }
    Ok(())
}

async fn progress(db: &sqlx::PgPool, feed: &str, text: &str) {
    let _ = sqlx::query("UPDATE vuln_feeds SET progress = $2 WHERE name = $1").bind(feed).bind(text).execute(db).await;
}

/// A conditional GET. None: not modified since the last sync.
async fn get(db: &sqlx::PgPool, http: &reqwest::Client, feed: &str, url: &str) -> Result<Option<reqwest::Response>> {
    let (etag, modified): (Option<String>, Option<String>) =
        sqlx::query_as("SELECT etag, last_modified FROM vuln_feeds WHERE name = $1").bind(feed).fetch_optional(db).await?.unwrap_or_default();
    let mut req = http.get(url);
    if let Some(e) = &etag {
        req = req.header(reqwest::header::IF_NONE_MATCH, e);
    }
    if let Some(m) = &modified {
        req = req.header(reqwest::header::IF_MODIFIED_SINCE, m);
    }
    let res = req.send().await.with_context(|| format!("GET {url}"))?;
    if res.status() == reqwest::StatusCode::NOT_MODIFIED {
        return Ok(None);
    }
    if !res.status().is_success() {
        bail!("GET {url}: {}", res.status());
    }
    let h = |k: reqwest::header::HeaderName| res.headers().get(k).and_then(|v| v.to_str().ok()).map(str::to_string);
    sqlx::query("UPDATE vuln_feeds SET etag = $2, last_modified = $3 WHERE name = $1")
        .bind(feed)
        .bind(h(reqwest::header::ETAG))
        .bind(h(reqwest::header::LAST_MODIFIED))
        .execute(db)
        .await?;
    Ok(Some(res))
}

/// Streams a response body to a temporary file.
async fn to_file(res: reqwest::Response, db: &sqlx::PgPool, feed: &str) -> Result<TempFile> {
    let path = std::env::temp_dir().join(format!("rmm-vuln-{}.download", uuid::Uuid::new_v4()));
    let tmp = TempFile(path.clone());
    let mut f = tokio::fs::File::create(&path).await?;
    let mut n: u64 = 0;
    let mut last = 0u64;
    let mut body = res.bytes_stream();
    while let Some(chunk) = body.next().await {
        let chunk = chunk?;
        n += chunk.len() as u64;
        if n > MAX_DOWNLOAD {
            bail!("download larger than {} MB", MAX_DOWNLOAD >> 20);
        }
        f.write_all(&chunk).await?;
        if n - last > 16 << 20 {
            last = n;
            progress(db, feed, &format!("downloading: {} MB", n >> 20)).await;
        }
    }
    f.flush().await?;
    Ok(tmp)
}

/// Deleted when dropped.
struct TempFile(PathBuf);

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

async fn sync_osv(db: &sqlx::PgPool, http: &reqwest::Client, urls: &Urls, feed: &str) -> Result<Option<usize>> {
    let eco = feed.trim_start_matches("osv:");
    // Path segments are escaped (`Rocky Linux` -> `Rocky%20Linux`).
    let mut url = reqwest::Url::parse(&format!("{}/", urls.osv)).context("RMM_VULN_OSV_URL")?;
    url.path_segments_mut().map_err(|_| anyhow!("RMM_VULN_OSV_URL can't take a path"))?.pop_if_empty().push(eco).push("all.zip");
    let Some(res) = get(db, http, feed, url.as_str()).await? else { return Ok(None) };
    let file = to_file(res, db, feed).await?;
    import_zip(db, &file.0, feed).await.map(Some)
}

/// Reads an OSV dump entry by entry (in a blocking thread) and stores it in batches; then
/// removes the feed's advisories that weren't in it.
pub async fn import_zip(db: &sqlx::PgPool, path: &Path, feed: &str) -> Result<usize> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(Vec<Advisory>, usize, usize)>(4);
    let path = path.to_path_buf();
    let feed_name = feed.to_string();
    let reader = tokio::task::spawn_blocking(move || -> Result<(usize, usize)> {
        let mut z = super::zip::Archive::open(&path)?;
        let total = z.entries.len();
        let (mut bad, mut batch) = (0usize, Vec::with_capacity(BATCH));
        for i in 0..total {
            if !z.entries[i].name.ends_with(".json") {
                continue;
            }
            match z.read(i).and_then(|b| super::osv::parse(&b, &feed_name)) {
                Ok(Some(a)) => batch.push(a),
                Ok(None) => {}
                Err(_) => bad += 1,
            }
            if batch.len() >= BATCH && tx.blocking_send((std::mem::take(&mut batch), i + 1, total)).is_err() {
                bail!("import stopped");
            }
        }
        if !batch.is_empty() {
            let _ = tx.blocking_send((batch, total, total));
        }
        Ok((total, bad))
    });
    let mut seen: Vec<String> = Vec::new();
    while let Some((batch, done, total)) = rx.recv().await {
        store(db, feed, &batch, None).await?;
        seen.extend(batch.into_iter().map(|a| a.id));
        progress(db, feed, &format!("{done} of {total} records")).await;
    }
    let (total, bad) = reader.await??;
    if bad > 0 {
        warn!(feed, bad, total, "vulnerability feed: records that didn't parse were skipped");
    }
    // A dump that mostly failed to parse is no reason to forget what we had.
    if bad * 10 <= total.max(1) {
        prune(db, feed, &seen).await?;
    }
    Ok(seen.len())
}

async fn sync_arch(db: &sqlx::PgPool, http: &reqwest::Client, urls: &Urls) -> Result<Option<usize>> {
    let Some(res) = get(db, http, "arch", &urls.arch).await? else { return Ok(None) };
    let body = res.bytes().await?;
    import_arch(db, &body).await.map(Some)
}

pub async fn import_arch(db: &sqlx::PgPool, json: &[u8]) -> Result<usize> {
    let all = super::arch::parse(json)?;
    for chunk in all.chunks(BATCH) {
        store(db, "arch", chunk, None).await?;
    }
    let seen: Vec<String> = all.iter().map(|a| a.id.clone()).collect();
    prune(db, "arch", &seen).await?;
    Ok(seen.len())
}

/// Mapped products some Windows device has installed: (id, vendor, product, last NVD sync).
async fn products_in_fleet(db: &sqlx::PgPool) -> sqlx::Result<Vec<(uuid::Uuid, String, String, Option<chrono::DateTime<Utc>>)>> {
    let titles: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT DISTINCT s ->> 'name', s ->> 'publisher'
           FROM agents a, jsonb_array_elements(coalesce(a.inventory -> 'software', '[]')) s
          WHERE a.os_family = 'windows' AND s ->> 'source' IN ('registry', 'msi')",
    )
    .fetch_all(db)
    .await?;
    let products: Vec<super::matcher::Product> = super::matcher::products(db).await?;
    let synced: Vec<(uuid::Uuid, Option<chrono::DateTime<Utc>>)> = sqlx::query_as("SELECT id, nvd_synced_at FROM vuln_products").fetch_all(db).await?;
    let mut out = Vec::new();
    for p in products {
        if titles.iter().any(|(n, publ)| p.matches(n, publ.as_deref())) {
            let at = synced.iter().find(|s| s.0 == p.id).and_then(|s| s.1);
            out.push((p.id, p.vendor, p.product, at));
        }
    }
    Ok(out)
}

async fn sync_nvd(db: &sqlx::PgPool, http: &reqwest::Client, urls: &Urls) -> Result<Option<usize>> {
    let products = products_in_fleet(db).await?;
    // NVD allows 5 requests in 30 seconds without a key, 50 with one.
    let pause = Duration::from_millis(if urls.nvd_key.is_some() { 700 } else { 6500 });
    let mut stored = 0usize;
    let mut first = true;
    for (k, (id, vendor, product, last)) in products.iter().enumerate() {
        progress(db, "nvd", &format!("{} of {} products", k + 1, products.len())).await;
        let started = Utc::now();
        // Incremental within NVD's 120-day window for lastModified ranges; otherwise in full.
        let since = last.filter(|t| *t > started - chrono::Duration::days(119)).map(|t| t - chrono::Duration::hours(1));
        let mut start = 0i64;
        loop {
            if !first {
                tokio::time::sleep(pause).await;
            }
            first = false;
            let mut q: Vec<(&str, String)> =
                vec![("virtualMatchString", format!("cpe:2.3:a:{vendor}:{product}")), ("resultsPerPage", "2000".into()), ("startIndex", start.to_string())];
            if let Some(s) = since {
                q.push(("lastModStartDate", s.format("%Y-%m-%dT%H:%M:%S%.3f+00:00").to_string()));
                q.push(("lastModEndDate", started.format("%Y-%m-%dT%H:%M:%S%.3f+00:00").to_string()));
            }
            let mut req = http.get(&urls.nvd).query(&q);
            if let Some(key) = &urls.nvd_key {
                req = req.header("apiKey", key);
            }
            let res = req.send().await.context("NVD")?;
            if !res.status().is_success() {
                bail!("NVD {vendor}:{product}: {}", res.status());
            }
            let page = super::nvd::parse_page(&res.bytes().await?)?;
            let advisories = page.advisories(vendor, product);
            for chunk in advisories.chunks(BATCH) {
                store(db, "nvd", chunk, Some(&format!("{vendor}:{product}"))).await?;
            }
            stored += advisories.len();
            start = page.start_index + page.results_per_page.max(1);
            if page.results_per_page == 0 || start >= page.total_results {
                break;
            }
        }
        sqlx::query("UPDATE vuln_products SET nvd_synced_at = $2 WHERE id = $1").bind(id).bind(started).execute(db).await?;
    }
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM vulns WHERE source = 'nvd'").fetch_one(db).await?;
    info!(products = products.len(), updated = stored, total, "vulnerabilities: NVD synced");
    Ok(Some(total as usize))
}

/// Imports saved NVD API pages; `vendor:product` comes from each CVE's own configurations.
pub async fn import_nvd(db: &sqlx::PgPool, json: &[u8]) -> Result<usize> {
    let page = super::nvd::parse_page(json)?;
    let products = super::matcher::products(db).await?;
    let mut n = 0;
    for p in &products {
        let advisories = page.advisories(&p.vendor, &p.product);
        for chunk in advisories.chunks(BATCH) {
            store(db, "nvd", chunk, Some(&format!("{}:{}", p.vendor, p.product))).await?;
        }
        n += advisories.len();
    }
    Ok(n)
}

#[derive(Deserialize)]
struct Kev {
    vulnerabilities: Vec<KevItem>,
}

#[derive(Deserialize)]
struct KevItem {
    #[serde(rename = "cveID")]
    cve: String,
    #[serde(default, rename = "dateAdded")]
    added: Option<chrono::NaiveDate>,
    #[serde(default, rename = "dueDate")]
    due: Option<chrono::NaiveDate>,
}

async fn sync_kev(db: &sqlx::PgPool, http: &reqwest::Client, urls: &Urls) -> Result<Option<usize>> {
    let Some(res) = get(db, http, "kev", &urls.kev).await? else { return Ok(None) };
    import_kev(db, &res.bytes().await?).await.map(Some)
}

pub async fn import_kev(db: &sqlx::PgPool, json: &[u8]) -> Result<usize> {
    let kev: Kev = serde_json::from_slice(json).context("KEV catalogue")?;
    let cves: Vec<String> = kev.vulnerabilities.iter().map(|k| k.cve.trim().to_string()).collect();
    let added: Vec<Option<chrono::NaiveDate>> = kev.vulnerabilities.iter().map(|k| k.added).collect();
    let due: Vec<Option<chrono::NaiveDate>> = kev.vulnerabilities.iter().map(|k| k.due).collect();
    let mut tx = db.begin().await?;
    sqlx::query("UPDATE vuln_cve_scores SET kev = false, kev_added = NULL, kev_due = NULL WHERE kev AND NOT (cve = ANY($1))")
        .bind(&cves)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO vuln_cve_scores (cve, kev, kev_added, kev_due)
         SELECT c, true, a, d FROM unnest($1::text[], $2::date[], $3::date[]) AS x(c, a, d)
         ON CONFLICT (cve) DO UPDATE SET kev = true, kev_added = EXCLUDED.kev_added, kev_due = EXCLUDED.kev_due",
    )
    .bind(&cves)
    .bind(&added)
    .bind(&due)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(cves.len())
}

async fn sync_epss(db: &sqlx::PgPool, http: &reqwest::Client, urls: &Urls) -> Result<Option<usize>> {
    let Some(res) = get(db, http, "epss", &urls.epss).await? else { return Ok(None) };
    import_epss(db, &res.bytes().await?).await.map(Some)
}

/// `cve,epss,percentile` lines (after a `#model_version` comment), plain or gzipped. Only CVEs
/// an advisory names are kept.
pub async fn import_epss(db: &sqlx::PgPool, data: &[u8]) -> Result<usize> {
    let text = if data.starts_with(&[0x1f, 0x8b]) {
        let mut s = String::new();
        std::io::Read::read_to_string(&mut flate2::read::GzDecoder::new(data), &mut s).context("EPSS: gzip")?;
        s
    } else {
        String::from_utf8_lossy(data).into_owned()
    };
    let known: HashSet<String> = sqlx::query_scalar::<_, String>("SELECT DISTINCT cve FROM vulns WHERE cve IS NOT NULL").fetch_all(db).await?.into_iter().collect();
    let (mut cves, mut scores, mut pct) = (Vec::new(), Vec::new(), Vec::new());
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("cve,") {
            continue;
        }
        let mut f = line.split(',');
        let (Some(c), Some(e)) = (f.next(), f.next()) else { continue };
        let Ok(e) = e.trim().parse::<f32>() else { continue };
        if !known.contains(c.trim()) {
            continue;
        }
        cves.push(c.trim().to_string());
        scores.push(e);
        pct.push(f.next().and_then(|p| p.trim().parse::<f32>().ok()));
    }
    for k in (0..cves.len()).step_by(5000) {
        let end = (k + 5000).min(cves.len());
        sqlx::query(
            "INSERT INTO vuln_cve_scores (cve, epss, epss_percentile)
             SELECT * FROM unnest($1::text[], $2::real[], $3::real[])
             ON CONFLICT (cve) DO UPDATE SET epss = EXCLUDED.epss, epss_percentile = EXCLUDED.epss_percentile",
        )
        .bind(&cves[k..end])
        .bind(&scores[k..end])
        .bind(&pct[k..end])
        .execute(db)
        .await?;
    }
    Ok(cves.len())
}

/// Copies KEV and EPSS onto the advisories.
pub async fn apply_scores(db: &sqlx::PgPool) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE vulns v SET epss = s.epss, kev = s.kev FROM vuln_cve_scores s
          WHERE s.cve = v.cve AND (v.epss IS DISTINCT FROM s.epss OR v.kev IS DISTINCT FROM s.kev)",
    )
    .execute(db)
    .await?;
    sqlx::query("UPDATE vulns v SET kev = false WHERE kev AND NOT EXISTS (SELECT 1 FROM vuln_cve_scores s WHERE s.cve = v.cve AND s.kev)").execute(db).await?;
    Ok(())
}

/// Upserts advisories and replaces their ranges (for NVD, only the ranges of `package`: one
/// CVE can name several mapped products, fetched separately).
pub async fn store(db: &sqlx::PgPool, feed: &str, batch: &[Advisory], package: Option<&str>) -> sqlx::Result<()> {
    if batch.is_empty() {
        return Ok(());
    }
    let rows: Vec<Value> = batch
        .iter()
        .map(|a| {
            json!({
                "id": a.id, "aliases": a.aliases, "cve": a.cve, "summary": a.summary, "details": a.details, "severity": a.severity,
                "cvss": a.cvss, "cvss_vector": a.cvss_vector, "published": a.published, "modified": a.modified, "url": a.url,
            })
        })
        .collect();
    let ranges: Vec<Value> = batch
        .iter()
        .flat_map(|a| {
            a.ranges.iter().map(move |r| {
                json!({
                    "vuln_id": a.id, "ecosystem": r.ecosystem, "package": r.package, "introduced": r.range.introduced,
                    "introduced_exclusive": r.range.introduced_exclusive, "fixed": r.range.fixed, "last_affected": r.range.last_affected,
                })
            })
        })
        .collect();
    let ids: Vec<&str> = batch.iter().map(|a| a.id.as_str()).collect();
    let mut tx = db.begin().await?;
    sqlx::query(
        "INSERT INTO vulns (id, aliases, cve, summary, details, severity, cvss, cvss_vector, published, modified, source, url)
         SELECT x.id, ARRAY(SELECT jsonb_array_elements_text(x.aliases)), x.cve, x.summary, x.details, x.severity, x.cvss, x.cvss_vector,
                x.published, x.modified, $2, x.url
           FROM jsonb_to_recordset($1) AS x(id text, aliases jsonb, cve text, summary text, details text, severity text, cvss real,
                                             cvss_vector text, published timestamptz, modified timestamptz, url text)
         ON CONFLICT (id) DO UPDATE SET aliases = EXCLUDED.aliases, cve = EXCLUDED.cve, summary = EXCLUDED.summary, details = EXCLUDED.details,
                severity = EXCLUDED.severity, cvss = EXCLUDED.cvss, cvss_vector = EXCLUDED.cvss_vector, published = EXCLUDED.published,
                modified = EXCLUDED.modified, source = EXCLUDED.source, url = EXCLUDED.url",
    )
    .bind(Value::Array(rows))
    .bind(feed)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM vuln_ranges WHERE vuln_id = ANY($1) AND ($2::text IS NULL OR package = $2)").bind(&ids).bind(package).execute(&mut *tx).await?;
    sqlx::query(
        "INSERT INTO vuln_ranges (vuln_id, ecosystem, package, introduced, introduced_exclusive, fixed, last_affected)
         SELECT * FROM jsonb_to_recordset($1) AS x(vuln_id text, ecosystem text, package text, introduced text, introduced_exclusive boolean,
                                                    fixed text, last_affected text)",
    )
    .bind(Value::Array(ranges))
    .execute(&mut *tx)
    .await?;
    tx.commit().await
}

/// Removes the feed's advisories that the latest full download no longer has.
async fn prune(db: &sqlx::PgPool, feed: &str, seen: &[String]) -> sqlx::Result<()> {
    let n = sqlx::query("DELETE FROM vulns WHERE source = $1 AND NOT (id = ANY($2))").bind(feed).bind(seen).execute(db).await?.rows_affected();
    if n > 0 {
        info!(feed, removed = n, "vulnerabilities: advisories withdrawn upstream removed");
    }
    Ok(())
}

/// `rmm-server vuln-import <dir>`: loads saved feed files, for servers that can't reach the
/// feeds. Every file under `dir` is looked at:
/// - `*.zip`: an OSV dump; the ecosystem is the file's directory (`Debian/all.zip`) or name
///   (`Debian.zip`);
/// - `*.json`: the Arch tracker (an array), the KEV catalogue, a saved NVD API page, or one
///   OSV record (told apart by their shape);
/// - `*.csv`, `*.csv.gz`: EPSS scores.
pub async fn import_dir(db: &sqlx::PgPool, dir: &Path) -> Result<String> {
    let mut files = Vec::new();
    walk(dir, &mut files, 0)?;
    files.sort();
    let mut lines = Vec::new();
    let mut osv_single: Vec<Advisory> = Vec::new();
    for f in files {
        let name = f.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let lower = name.to_ascii_lowercase();
        let res: Result<(String, usize)> = async {
            if lower.ends_with(".zip") {
                let eco = if lower == "all.zip" {
                    f.parent().and_then(|p| p.file_name()).map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
                } else {
                    name.trim_end_matches(".zip").trim_end_matches(".ZIP").to_string()
                };
                let Some(eco) = OSV_FEEDS.iter().find(|e| e.eq_ignore_ascii_case(&eco)) else {
                    bail!("{}: name the file after its OSV ecosystem ({})", f.display(), OSV_FEEDS.join(", "));
                };
                let feed = format!("osv:{eco}");
                let n = import_zip(db, &f, &feed).await?;
                Ok((feed, n))
            } else if lower.ends_with(".json") {
                let data = std::fs::read(&f)?;
                let v: Value = serde_json::from_slice(&data).with_context(|| format!("{}", f.display()))?;
                if v.is_array() {
                    Ok(("arch".into(), import_arch(db, &data).await?))
                } else if v.get("catalogVersion").is_some() || (v.get("vulnerabilities").is_some() && v.get("count").is_some()) {
                    Ok(("kev".into(), import_kev(db, &data).await?))
                } else if v.get("resultsPerPage").is_some() {
                    Ok(("nvd".into(), import_nvd(db, &data).await?))
                } else if v.get("affected").is_some() {
                    let feed = v["affected"][0]["package"]["ecosystem"].as_str().unwrap_or_default().split(':').next().unwrap_or_default().to_string();
                    let n = super::osv::parse(&data, &format!("osv:{feed}"))?.map(|a| osv_single.push(a)).map_or(0, |_| 1);
                    Ok((format!("osv:{feed} (records)"), n))
                } else {
                    bail!("{}: not a feed file this importer knows", f.display())
                }
            } else if lower.ends_with(".csv") || lower.ends_with(".csv.gz") {
                Ok(("epss".into(), import_epss(db, &std::fs::read(&f)?).await?))
            } else {
                Ok((String::new(), 0))
            }
        }
        .await;
        match res {
            Ok((feed, n)) if !feed.is_empty() => {
                let plain = feed.trim_end_matches(" (records)").to_string();
                if !feed.ends_with("(records)") {
                    finish(db, &plain, Ok(Some(n))).await?;
                }
                lines.push(format!("{}: {feed}, {n} records", f.display()));
            }
            Ok(_) => {}
            Err(e) => lines.push(format!("{}: {e:#}", f.display())),
        }
    }
    // Single OSV records go in by their own feed (no pruning: they aren't a whole dump).
    let mut by_feed: std::collections::BTreeMap<String, Vec<Advisory>> = Default::default();
    for a in osv_single {
        let feed = a.ranges.first().map(|r| super::feed_for(&r.ecosystem)).unwrap_or_else(|| "osv:import".into());
        by_feed.entry(feed).or_default().push(a);
    }
    for (feed, list) in by_feed {
        for chunk in list.chunks(BATCH) {
            store(db, &feed, chunk, None).await?;
        }
    }
    apply_scores(db).await?;
    let n = super::requeue(db, None).await?;
    lines.push(format!("{n} devices queued for re-evaluation (a running server picks them up within seconds)"));
    Ok(lines.join("\n"))
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>, depth: usize) -> Result<()> {
    if depth > 4 {
        return Ok(());
    }
    for e in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let e = e?;
        let p = e.path();
        if e.file_type()?.is_dir() {
            walk(&p, out, depth + 1)?;
        } else {
            out.push(p);
        }
    }
    Ok(())
}
