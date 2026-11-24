// Included by e2e.rs (`include!`): the vulnerabilities section, with a stand-in for every feed
// (OSV dumps, the Arch tracker, NVD, CISA KEV, EPSS) served from this process.

/// A request to the mock feed server: (path and query, apiKey header).
type Seen = (String, Option<String>);

/// What the mock feed server serves, and what it was asked.
#[derive(Clone, Default)]
struct FeedMock {
    /// Path (after the base) -> body.
    files: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>>,
    /// NVD answers by `virtualMatchString`.
    nvd: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, Value>>>,
    /// Every request: (path and query, apiKey header).
    seen: std::sync::Arc<std::sync::Mutex<Vec<Seen>>>,
}

async fn feed_mock() -> (String, FeedMock) {
    use axum::extract::{Query, State as S};
    use axum::http::{HeaderMap, StatusCode as Code, Uri};
    let mock = FeedMock::default();
    let app = axum::Router::new()
        .route(
            "/nvd",
            axum::routing::get(|S(m): S<FeedMock>, h: HeaderMap, uri: Uri, Query(q): Query<std::collections::HashMap<String, String>>| async move {
                m.seen.lock().unwrap().push((uri.to_string(), h.get("apikey").and_then(|v| v.to_str().ok()).map(String::from)));
                let key = q.get("virtualMatchString").cloned().unwrap_or_default();
                let empty = json!({ "resultsPerPage": 0, "startIndex": 0, "totalResults": 0, "vulnerabilities": [] });
                axum::Json(m.nvd.lock().unwrap().get(&key).cloned().unwrap_or(empty))
            }),
        )
        .fallback(|S(m): S<FeedMock>, uri: Uri| async move {
            m.seen.lock().unwrap().push((uri.to_string(), None));
            let path = percent_decode(uri.path());
            match m.files.lock().unwrap().get(&path) {
                Some(b) => (Code::OK, b.clone()),
                None => (Code::NOT_FOUND, b"not here".to_vec()),
            }
        })
        .with_state(mock.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, mock)
}

/// `/osv/Rocky%20Linux/all.zip` -> `/osv/Rocky Linux/all.zip`.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = (b[i] == b'%' && i + 2 < b.len()).then(|| std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok())).flatten();
        match hex {
            Some(v) => {
                out.push(v);
                i += 3;
            }
            None => {
                out.push(b[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

async fn vuln_alerts(db: &sqlx::PgPool, agent: &str) -> Vec<(uuid::Uuid, String, Value, bool)> {
    sqlx::query_as("SELECT id, title, details, resolved_at IS NULL FROM alerts WHERE agent_id = $1::uuid AND kind = 'vulnerability' ORDER BY opened_at")
        .bind(agent)
        .fetch_all(db)
        .await
        .unwrap()
}

async fn vuln_findings(admin: &Api, agent: &str) -> Value {
    admin.get(&format!("/agents/{agent}/vulnerabilities")).await
}

/// Vulnerabilities: a real package of this host's inventory, in its own ecosystem (Arch here,
/// Ubuntu in CI), served as affected by a mock feed; the finding, the alert, health, a record
/// fixed at the installed version (nothing), KEV and EPSS, accepting the risk and its expiry,
/// the Windows path through the product map and a mock NVD, the "not assessed" list, client
/// scoping, and `vuln-import`.
#[allow(clippy::too_many_arguments)]
async fn vulnerabilities(server: &mut Server, url: &str, admin: &Api, db: &sqlx::PgPool, id1: &str, id3: &str, a_id: &str, b_id: &str) {
    use reqwest::Method;
    let (mock_url, mock) = feed_mock().await;
    // The server reads the feed URLs from its environment, which it inherits from this process.
    // SAFETY: set before the restart below; nothing else in the test reads these variables.
    unsafe {
        std::env::set_var("RMM_VULN_OSV_URL", format!("{mock_url}/osv"));
        std::env::set_var("RMM_VULN_ARCH_URL", format!("{mock_url}/arch/all.json"));
        std::env::set_var("RMM_VULN_NVD_URL", format!("{mock_url}/nvd"));
        std::env::set_var("RMM_VULN_KEV_URL", format!("{mock_url}/kev.json"));
        std::env::set_var("RMM_VULN_EPSS_URL", format!("{mock_url}/epss.csv.gz"));
        std::env::set_var("RMM_NVD_API_KEY", "e2e-nvd-key");
    }
    server.restart().await;
    admin.wait_online(id1, true).await;

    // --- this host's ecosystem and a real package of it ------------------------------------------
    // Evaluated once its inventory is in (before that it reads "no inventory").
    let status = eventually(60, "the agent to be assessed", || async {
        let v = vuln_findings(admin, id1).await;
        (v["evaluated_at"].is_string() && v["unassessed"] != "no_inventory").then_some(v)
    })
    .await;
    let agent = admin.get(&format!("/agents/{id1}")).await;
    let software = agent["inventory"]["software"].as_array().cloned().unwrap_or_default();
    let eco = status["ecosystem"].as_str().map(String::from);
    println!("vulnerabilities: this host is assessed as {eco:?} ({} packages)", software.len());
    let Some(eco) = eco.filter(|e| e == "Arch" || e.starts_with("Ubuntu:") || e.starts_with("Debian:")) else {
        println!("vulnerabilities: neither Arch, Ubuntu nor Debian; the host package checks are skipped ({status})");
        return;
    };
    let source = if eco == "Arch" { "pacman" } else { "dpkg" };
    let pkg = software
        .iter()
        .filter(|s| s["source"] == source && s["version"].as_str().is_some_and(|v| !v.is_empty()))
        .find(|s| s["name"].as_str().is_some_and(|n| n.starts_with("lib")) || s["name"] == "bash")
        .or_else(|| software.iter().find(|s| s["source"] == source))
        .cloned()
        .expect("a package of the host's own package manager");
    let name = pkg["name"].as_str().unwrap().to_string();
    // Debian and Ubuntu advisories are by source package.
    let key = if source == "dpkg" { pkg["source_name"].as_str().unwrap_or(&name).to_string() } else { name.clone() };
    let installed = pkg["version"].as_str().unwrap().to_string();
    // ".1" sorts after the release in dpkg and pacman alike: the installed version is affected.
    let fixed_later = format!("{installed}.1");
    println!("vulnerabilities: testing with {name} ({key}) {installed}");
    let cve1 = "CVE-2099-0001";
    let cve_same = "CVE-2099-0002";
    let cve_kev = "CVE-2099-0003";
    if eco == "Arch" {
        let groups = json!([
            { "name": "AVG-9001", "packages": [key], "status": "Fixed", "severity": "Critical", "type": "arbitrary code execution", "affected": installed, "fixed": fixed_later, "issues": [cve1], "advisories": [] },
            { "name": "AVG-9002", "packages": [key], "status": "Fixed", "severity": "Critical", "type": "denial of service", "affected": installed, "fixed": installed, "issues": [cve_same], "advisories": [] },
            { "name": "AVG-9003", "packages": [key], "status": "Vulnerable", "severity": "Low", "type": "information disclosure", "affected": installed, "fixed": null, "issues": [cve_kev], "advisories": [] },
        ]);
        mock.files.lock().unwrap().insert("/arch/all.json".into(), serde_json::to_vec(&groups).unwrap());
    } else {
        let osv_eco = if let Some(v) = eco.strip_prefix("Ubuntu:") { format!("Ubuntu:{v}:LTS") } else { eco.clone() };
        let dir = eco.split(':').next().unwrap();
        let rec = |id: &str, cve: &str, events: Value, severity: Value| {
            serde_json::to_vec(&json!({
                "id": id, "upstream": [cve], "summary": format!("e2e advisory {id}"), "details": "Made up for the e2e test.",
                "published": "2099-01-01T00:00:00Z", "modified": "2099-01-02T00:00:00Z", "severity": severity,
                "affected": [{ "package": { "ecosystem": osv_eco, "name": key }, "ranges": [{ "type": "ECOSYSTEM", "events": events }] }],
            }))
            .unwrap()
        };
        let critical = json!([{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }]);
        let low = json!([{ "type": "Ubuntu", "score": "low" }]);
        let zip = stored_zip_many(&[
            ("E2E-0001.json", &rec("E2E-0001", cve1, json!([{ "introduced": "0" }, { "fixed": fixed_later }]), critical.clone())),
            ("E2E-0002.json", &rec("E2E-0002", cve_same, json!([{ "introduced": "0" }, { "fixed": installed }]), critical)),
            ("E2E-0003.json", &rec("E2E-0003", cve_kev, json!([{ "introduced": "0" }]), low)),
            ("README.txt", b"not an advisory"),
        ]);
        mock.files.lock().unwrap().insert(format!("/osv/{dir}/all.zip"), zip);
    }
    let kev = json!({ "catalogVersion": "2099.01.01", "count": 1, "vulnerabilities": [{ "cveID": cve_kev, "dateAdded": "2099-01-01", "dueDate": "2099-01-22" }] });
    mock.files.lock().unwrap().insert("/kev.json".into(), serde_json::to_vec(&kev).unwrap());
    let epss = format!("#model_version:v2099.01.01,score_date:2099-01-01T00:00:00+0000\ncve,epss,percentile\n{cve1},0.42000,0.97000\n{cve_kev},0.01000,0.20000\nCVE-1999-0001,0.5,0.5\n");
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut gz, epss.as_bytes()).unwrap();
    mock.files.lock().unwrap().insert("/epss.csv.gz".into(), gz.finish().unwrap());

    // --- the Windows path: a seeded inventory on the agent that never runs ------------------------
    let win_inventory = json!({
        "collected_at": chrono::Utc::now(), "system": { "hostname": "e2e-win", "os_family": "windows", "os_name": "Windows 11 Pro", "os_version": "10.0.26100",
            "kernel_version": "26100", "arch": "x86_64", "agent_version": "0.2.0", "machine_id": null },
        "cpu_brand": "", "cpu_cores_physical": null, "cpu_cores_logical": 4, "mem_total": 0, "disks": [], "network": [], "logged_in_users": [],
        "software": [
            { "name": "Google Chrome", "version": "127.0.6533.120", "publisher": "Google LLC", "source": "registry" },
            { "name": "Contoso Widget", "version": "1.0", "publisher": "Contoso Ltd", "source": "registry" },
        ],
    });
    let (old_family, old_name): (String, String) = sqlx::query_as("SELECT os_family, os_name FROM agents WHERE id = $1::uuid").bind(id3).fetch_one(db).await.unwrap();
    sqlx::query("UPDATE agents SET os_family = 'windows', os_name = 'Windows 11 Pro', inventory = $2, inventory_at = now(), vuln_evaluated_at = NULL WHERE id = $1::uuid")
        .bind(id3)
        .bind(&win_inventory)
        .execute(db)
        .await
        .unwrap();
    let chrome_page = json!({
        "resultsPerPage": 1, "startIndex": 0, "totalResults": 1, "format": "NVD_CVE", "version": "2.0",
        "vulnerabilities": [{ "cve": {
            "id": "CVE-2099-0100", "published": "2099-01-01T00:00:00.000", "lastModified": "2099-01-02T00:00:00.000", "vulnStatus": "Analyzed",
            "descriptions": [{ "lang": "en", "value": "Type confusion in V8 in Google Chrome prior to 128.0.6613.84 (made up for the e2e test)." }],
            "metrics": { "cvssMetricV31": [{ "type": "Primary", "cvssData": { "version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "baseScore": 8.8, "baseSeverity": "HIGH" } }] },
            "configurations": [{ "nodes": [{ "operator": "OR", "negate": false, "cpeMatch": [
                { "vulnerable": true, "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", "versionEndExcluding": "128.0.6613.84" }
            ] }] }],
        } }],
    });
    mock.nvd.lock().unwrap().insert("cpe:2.3:a:google:chrome".into(), chrome_page);
    eventually(30, "the Windows device to be assessed", || async {
        let v = vuln_findings(admin, id3).await;
        (v["ecosystem"] == "Windows").then_some(())
    })
    .await;
    let unassessed = admin.get("/vulnerabilities/unassessed").await;
    let titles: Vec<&str> = unassessed["titles"].as_array().unwrap().iter().filter_map(|t| t["title"].as_str()).collect();
    assert!(titles.contains(&"Contoso Widget") && !titles.contains(&"Google Chrome"), "Chrome is in the built-in map, the widget isn't: {unassessed}");

    // --- the alert item, then a sync ----------------------------------------------------------
    let (s, v) = admin.alert_policy_call(json!({ "name": "bad", "kind": "vulnerability", "params": { "min_severity": "urgent" }, "severity": "critical" })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let item = admin
        .alert_policy(json!({
            "name": "E2E vulnerabilities", "kind": "vulnerability", "client_id": a_id, "severity": "critical",
            "params": { "min_severity": "critical", "fix_available_only": true, "older_than_days": 0 },
        }))
        .await;
    let item_id = item["id"].as_str().unwrap().to_string();
    let tech = signed_in(url, admin, "vuln-tech@e2e.test", "technician", None, false).await;
    let (s, _) = tech.call(Method::POST, "/vulnerabilities/sync", Some(json!({}))).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "syncing needs security.manage");
    let (s, v) = admin.call(Method::POST, "/vulnerabilities/sync", Some(json!({ "feeds": ["osv:Nowhere"] }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let (s, v) = admin.call(Method::POST, "/vulnerabilities/sync", Some(json!({ "force": true }))).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    let host_feed = if eco == "Arch" { "arch".to_string() } else { format!("osv:{}", eco.split(':').next().unwrap()) };
    let feeds = eventually(120, "the sync to finish", || async {
        let f = admin.get("/vulnerabilities/feeds").await;
        let done = f["running"] == false
            && ["kev", "epss", "nvd", host_feed.as_str()].iter().all(|n| f["feeds"].as_array().unwrap().iter().any(|x| x["name"] == *n && x["last_sync_at"].is_string()));
        done.then_some(f)
    })
    .await;
    for f in feeds["feeds"].as_array().unwrap() {
        if [host_feed.as_str(), "kev", "epss", "nvd"].contains(&f["name"].as_str().unwrap()) {
            assert!(f["error"].is_null() && f["needed"] == true, "{f}");
        }
    }
    let host = feeds["feeds"].as_array().unwrap().iter().find(|f| f["name"] == host_feed.as_str()).unwrap();
    assert_eq!(host["records"], 3, "{host}");
    assert!(feeds["attribution"].as_array().unwrap().iter().any(|a| a.as_str().unwrap().contains("not endorsed or certified by the NVD")));
    let nvd_calls: Vec<(String, Option<String>)> = mock.seen.lock().unwrap().iter().filter(|(p, _)| p.starts_with("/nvd")).cloned().collect();
    assert!(!nvd_calls.is_empty() && nvd_calls.iter().all(|(p, k)| k.as_deref() == Some("e2e-nvd-key") && p.contains("virtualMatchString=cpe%3A2.3%3Aa%3A")), "{nvd_calls:?}");
    assert!(nvd_calls.iter().any(|(p, _)| p.contains("google%3Achrome")), "only products in the fleet are asked for: {nvd_calls:?}");
    assert!(!nvd_calls.iter().any(|(p, _)| p.contains("mozilla%3Afirefox")), "{nvd_calls:?}");

    // --- the finding, the alert, health ----------------------------------------------------------
    let found = eventually(60, "the host finding", || async {
        let v = vuln_findings(admin, id1).await;
        v["findings"].as_array().unwrap().iter().any(|f| f["key"] == cve1).then_some(v)
    })
    .await;
    let list = found["findings"].as_array().unwrap();
    let f1 = list.iter().find(|f| f["key"] == cve1).unwrap();
    assert_eq!((f1["fixed_version"].as_str(), f1["fix_available"].as_bool(), f1["severity"].as_str()), (Some(fixed_later.as_str()), Some(true), Some("critical")), "{f1}");
    assert_eq!(f1["installed_version"], installed.as_str());
    assert_eq!(f1["package"], key.as_str());
    assert!((f1["epss"].as_f64().unwrap() - 0.42).abs() < 1e-4, "EPSS applied: {f1}");
    assert!(!list.iter().any(|f| f["key"] == cve_same), "fixed at the installed version: nothing ({found})");
    let fk = list.iter().find(|f| f["key"] == cve_kev).expect("a low, unfixed CVE is kept when it is known exploited");
    assert_eq!((fk["kev"].as_bool(), fk["fix_available"].as_bool()), (Some(true), Some(false)), "{fk}");
    assert_eq!(found["critical"], 1, "{found}");
    let alert = eventually(30, "the vulnerability alert", || async {
        vuln_alerts(db, id1).await.into_iter().find(|a| a.3)
    })
    .await;
    assert_eq!(alert.1, "1 vulnerability to fix (1 critical)");
    assert_eq!(alert.2["top"][0]["cve"], cve1, "{}", alert.2);
    assert_eq!(alert.2["count"], 1, "the KEV one is unfixed, and the item wants fixes: {}", alert.2);
    eventually(30, "the agent to turn unhealthy", || async { (admin.get(&format!("/agents/{id1}")).await["health"] == "unhealthy").then_some(()) }).await;

    // Lists, filters, the CVE page.
    let by_cve = admin.get("/vulnerabilities?limit=50").await;
    let row = by_cve["items"].as_array().unwrap().iter().find(|r| r["key"] == cve1).cloned().unwrap_or_else(|| panic!("{by_cve}"));
    // Other sections may leave more agents on this machine, with the same real package.
    let devices = admin.get(&format!("/vulnerabilities/{cve1}/devices")).await;
    let devices = devices.as_array().unwrap();
    assert!(devices.iter().any(|d| d["agent_id"] == id1), "{devices:?}");
    let n_devices = devices.len() as u64;
    assert_eq!((row["devices"].as_u64(), row["severity"].as_str()), (Some(devices.len() as u64), Some("critical")), "{row}");
    let kev_only = admin.get("/vulnerabilities?kev=true").await;
    let keys: Vec<&str> = kev_only["items"].as_array().unwrap().iter().filter_map(|r| r["key"].as_str()).collect();
    assert_eq!(keys, [cve_kev], "{kev_only}");
    for sort in ["devices", "severity", "cvss", "epss", "published", "first_seen", "cve"] {
        admin.get(&format!("/vulnerabilities?sort={sort}&limit=1")).await;
    }
    let (s, _) = admin.call(Method::GET, "/vulnerabilities?severity=urgent", None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let detail = admin.get(&format!("/vulnerabilities/{cve1}")).await;
    assert!(detail["epss"].as_f64().is_some() && detail["kev"] == false && detail["advisories"].as_array().unwrap().len() == 1, "{detail}");
    assert_eq!(admin.get(&format!("/vulnerabilities/{cve_kev}")).await["kev"], true);
    let (s, _) = admin.call(Method::GET, "/vulnerabilities/CVE-2099-9999", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let summary = admin.get(&format!("/vulnerabilities/summary?client_id={a_id}")).await;
    assert!(summary["critical"].as_i64() >= Some(1) && summary["kev"].as_i64() >= Some(1), "{summary}");
    let soft = admin.get("/vulnerabilities/software").await;
    assert!(soft.as_array().unwrap().iter().any(|r| r["package"] == key.as_str()), "{soft}");
    assert!(admin.get("/vulnerabilities/agents").await.as_array().unwrap().iter().any(|r| r["agent_id"] == id1));

    // --- Windows: the mapped product through NVD ---------------------------------------------
    let win = eventually(60, "the Chrome finding", || async {
        let v = vuln_findings(admin, id3).await;
        v["findings"].as_array().unwrap().iter().find(|f| f["key"] == "CVE-2099-0100").cloned()
    })
    .await;
    assert_eq!((win["package"].as_str(), win["severity"].as_str(), win["fixed_version"].as_str()), (Some("google:chrome"), Some("high"), Some("128.0.6613.84")), "{win}");
    assert_eq!(win["remediation"]["kind"], "catalog", "mapped, not in the catalog: {win}");
    assert!(vuln_alerts(db, id3).await.is_empty(), "high is below the item's critical");
    // Mapping the widget assesses it (NVD has nothing for it here).
    let (s, v) = admin.call(Method::POST, "/vulnerabilities/products", Some(json!({ "vendor": "Contoso", "product": "widget", "name": "Widget", "name_patterns": ["Contoso Widget"] }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "CPE names are lowercase: {v}");
    let (s, product) = admin.call(Method::POST, "/vulnerabilities/products", Some(json!({ "vendor": "contoso", "product": "widget", "name": "Contoso Widget", "name_patterns": ["Contoso Widget"], "publisher_pattern": "Contoso*" }))).await;
    assert_eq!(s, StatusCode::CREATED, "{product}");
    let (s, _) = admin.call(Method::POST, "/vulnerabilities/products", Some(json!({ "vendor": "contoso", "product": "widget", "name": "Again", "name_patterns": ["x"] }))).await;
    assert_eq!(s, StatusCode::CONFLICT);
    let titles = admin.get("/vulnerabilities/unassessed").await;
    assert!(!titles["titles"].as_array().unwrap().iter().any(|t| t["title"] == "Contoso Widget"), "{titles}");
    eventually(60, "NVD to be asked about the new product", || async {
        mock.seen.lock().unwrap().iter().any(|(p, _)| p.contains("contoso%3Awidget")).then_some(())
    })
    .await;
    assert_eq!(audit_count(db, "vuln.product.create").await, 1);
    // A built-in mapping is hidden, not deleted.
    let chrome = admin.get("/vulnerabilities/products").await.as_array().unwrap().iter().find(|p| p["product"] == "chrome").cloned().unwrap();
    assert_eq!(chrome["builtin"], true);
    assert_eq!(chrome["devices"], 1, "{chrome}");

    // --- client scoping --------------------------------------------------------------------
    let other = signed_in(url, admin, "vuln-b@e2e.test", "technician", Some(b_id), false).await;
    let theirs = other.get("/vulnerabilities").await;
    assert_eq!(theirs["total"], 0, "client B sees none of client A's findings: {theirs}");
    assert!(other.get(&format!("/vulnerabilities/{cve1}/devices")).await.as_array().unwrap().is_empty());
    let (s, _) = other.call(Method::GET, &format!("/agents/{id1}/vulnerabilities"), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = other.call(Method::GET, &format!("/vulnerabilities?client_id={a_id}"), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = other.call(Method::POST, "/vulnerabilities/acceptances", Some(json!({ "vuln_id": cve1, "client_id": a_id }))).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(other.get("/vulnerabilities/summary").await["critical"], 0);

    // --- accepting the risk, and its expiry -----------------------------------------------------
    let (s, v) = admin.call(Method::POST, "/vulnerabilities/acceptances", Some(json!({ "vuln_id": cve1, "client_id": b_id, "agent_id": id1 }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "the device isn't client B's: {v}");
    let expires = chrono::Utc::now() + chrono::Duration::seconds(8);
    let acc = admin
        .post("/vulnerabilities/acceptances", json!({ "vuln_id": cve1, "client_id": a_id, "agent_id": id1, "note": "e2e: compensating control", "expires_at": expires }))
        .await;
    assert_eq!(acc["devices"], 1, "{acc}");
    let after = vuln_alerts(db, id1).await;
    assert!(after.iter().all(|a| !a.3), "accepting closes the alert: {after:?}");
    let v = vuln_findings(admin, id1).await;
    assert!(v["findings"].as_array().unwrap().iter().any(|f| f["key"] == cve1 && f["accepted"] == true), "{v}");
    assert_eq!(v["critical"], 0, "accepted findings don't count");
    let open = admin.get("/vulnerabilities").await;
    let still = open["items"].as_array().unwrap().iter().find(|r| r["key"] == cve1).map(|r| r["devices"].as_u64());
    if n_devices == 1 {
        assert!(still.is_none(), "accepted CVEs leave the list: {open}");
    } else {
        assert_eq!(still, Some(Some(n_devices - 1)), "only the other devices still count: {open}");
    }
    assert!(admin.get("/vulnerabilities?accepted=true").await["items"].as_array().unwrap().iter().any(|r| r["key"] == cve1 && r["accepted_devices"] == 1));
    assert_eq!(audit_count(db, "vuln.accept").await, 1);
    let reopened = eventually(40, "the alert to come back once the acceptance expires", || async {
        let all = vuln_alerts(db, id1).await;
        (all.len() >= 2 && all.last().unwrap().3).then_some(all)
    })
    .await;
    assert_ne!(reopened[0].0, reopened.last().unwrap().0, "a new alert");
    assert_eq!(vuln_findings(admin, id1).await["critical"], 1);
    // Removing an (expired) acceptance is allowed; an unknown one isn't there.
    admin.call(Method::DELETE, &format!("/vulnerabilities/acceptances/{}", acc["id"].as_str().unwrap()), None).await;
    let (s, _) = admin.call(Method::DELETE, &format!("/vulnerabilities/acceptances/{}", uuid::Uuid::new_v4()), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // --- the fix arrives upstream ------------------------------------------------------------
    // The feed now says the installed version is the fix: the finding resolves and the alert clears.
    if eco == "Arch" {
        let mut files = mock.files.lock().unwrap();
        let body = String::from_utf8(files["/arch/all.json"].clone()).unwrap().replace(&format!("\"fixed\":\"{fixed_later}\""), &format!("\"fixed\":\"{installed}\""));
        files.insert("/arch/all.json".into(), body.into_bytes());
    } else {
        let dir = eco.split(':').next().unwrap().to_string();
        let osv_eco = if let Some(v) = eco.strip_prefix("Ubuntu:") { format!("Ubuntu:{v}:LTS") } else { eco.clone() };
        let rec = serde_json::to_vec(&json!({ "id": "E2E-0001", "upstream": [cve1], "summary": "e2e advisory", "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
            "affected": [{ "package": { "ecosystem": osv_eco, "name": key }, "ranges": [{ "type": "ECOSYSTEM", "events": [{ "introduced": "0" }, { "fixed": installed }] }] }] })).unwrap();
        mock.files.lock().unwrap().insert(format!("/osv/{dir}/all.zip"), stored_zip_many(&[("E2E-0001.json", &rec)]));
    }
    admin.post("/vulnerabilities/sync", json!({ "feeds": [host_feed], "force": true })).await;
    eventually(60, "the finding to resolve", || async {
        let v = vuln_findings(admin, id1).await;
        (!v["findings"].as_array().unwrap().iter().any(|f| f["key"] == cve1)).then_some(())
    })
    .await;
    eventually(30, "the alert to clear", || async { vuln_alerts(db, id1).await.iter().all(|a| !a.3).then_some(()) }).await;
    if eco != "Arch" {
        // A full dump replaces the feed: what isn't in it any more is gone.
        assert!(!vuln_findings(admin, id1).await["findings"].as_array().unwrap().iter().any(|f| f["key"] == cve_kev));
    }

    // --- vuln-import: the same files from a directory ----------------------------------------
    let import_dir = server.dir.join("vuln-import");
    std::fs::create_dir_all(import_dir.join("Debian")).unwrap();
    let rec = serde_json::to_vec(&json!({ "id": "DEBIAN-CVE-2099-0200", "upstream": ["CVE-2099-0200"], "details": "Imported.",
        "affected": [{ "package": { "ecosystem": "Debian:12", "name": "e2e-imported" }, "ranges": [{ "type": "ECOSYSTEM", "events": [{ "introduced": "0" }, { "fixed": "1.1-1" }] }] }] })).unwrap();
    std::fs::write(import_dir.join("Debian/all.zip"), stored_zip_many(&[("DEBIAN-CVE-2099-0200.json", &rec)])).unwrap();
    std::fs::write(import_dir.join("kev.json"), serde_json::to_vec(&kev).unwrap()).unwrap();
    std::fs::write(import_dir.join("notes.txt"), b"ignored").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_rmm-server"))
        .env("DATABASE_URL", &server.db_url)
        .arg("vuln-import")
        .arg(&import_dir)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "vuln-import: {text} {}", String::from_utf8_lossy(&out.stderr));
    assert!(text.contains("osv:Debian, 1 records") && text.contains("kev, 1 records"), "{text}");
    assert_eq!(admin.get("/vulnerabilities/CVE-2099-0200").await["advisories"][0]["source"], "osv:Debian");
    assert!(audit_count(db, "vuln.sync").await >= 3);

    // --- tidy up for the sections that follow ---------------------------------------------------
    assert!(admin.delete_policy(&item_id).await.is_success());
    admin.call(Method::DELETE, &format!("/vulnerabilities/products/{}", product["id"].as_str().unwrap()), None).await;
    sqlx::query("UPDATE agents SET os_family = $2, os_name = $3, inventory = NULL, vuln_evaluated_at = NULL WHERE id = $1::uuid")
        .bind(id3)
        .bind(&old_family)
        .bind(&old_name)
        .execute(db)
        .await
        .unwrap();
}

/// A zip of stored (uncompressed) entries, as `stored_zip` makes one.
fn stored_zip_many(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cd = Vec::new();
    for (name, data) in entries {
        let crc = crc32(data);
        let offset = out.len() as u32;
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);
        cd.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        cd.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        cd.extend_from_slice(&crc.to_le_bytes());
        cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
        cd.extend_from_slice(&[0; 12]);
        cd.extend_from_slice(&offset.to_le_bytes());
        cd.extend_from_slice(name.as_bytes());
    }
    let cd_offset = out.len() as u32;
    out.extend_from_slice(&cd);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(cd.len() as u32).to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for b in data {
        c ^= *b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xEDB8_8320 } else { c >> 1 };
        }
    }
    !c
}
