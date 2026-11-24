// Included by e2e.rs (`include!`): identity management and Intune (docs/design/identity.md,
// docs/design/mdm.md). Kept in its own file so the parallel feature tracks don't all edit the
// same few thousand lines.

/// What the Entra side of the Graph stand-in holds and was asked to do.
#[derive(Default)]
struct EntraState {
    users: Vec<Value>,
    /// (group, member ids)
    groups: Vec<(Value, Vec<String>)>,
    roles: Vec<Value>,
    mfa: Vec<Value>,
    devices: Vec<Value>,
    /// (user id, PATCH body)
    patches: Vec<(String, Value)>,
    revoked: Vec<String>,
    /// (group id, user id)
    removed: Vec<(String, String)>,
}

#[derive(Clone, Default)]
struct EntraMock(std::sync::Arc<std::sync::Mutex<EntraState>>);

fn entra_mock() -> &'static EntraMock {
    static M: std::sync::OnceLock<EntraMock> = std::sync::OnceLock::new();
    M.get_or_init(EntraMock::default)
}

/// Users, groups, directory roles, MFA registration and Intune devices, merged into
/// `graph_mock()`'s router. The token comes from its token endpoint.
fn entra_routes() -> axum::Router<GraphMock> {
    use axum::extract::{Path as P, Query as Q, State as S};
    use axum::http::{HeaderMap, StatusCode as Code};
    use axum::routing::{delete, get, post};
    fn authed(h: &HeaderMap) -> bool {
        h.get("authorization").and_then(|v| v.to_str().ok()) == Some("Bearer graph-token")
    }
    fn denied() -> (Code, axum::Json<Value>) {
        (Code::UNAUTHORIZED, axum::Json(json!({ "error": { "code": "InvalidAuthenticationToken", "message": "no token" } })))
    }
    type Query = std::collections::HashMap<String, String>;
    axum::Router::new()
        .route(
            "/v1.0/users",
            get(|S(m): S<EntraMock>, h: HeaderMap, Q(q): Q<Query>| async move {
                if !authed(&h) {
                    return denied();
                }
                let users = m.0.lock().unwrap().users.clone();
                if q.get("$top").map(String::as_str) == Some("1") {
                    return (Code::OK, axum::Json(json!({ "value": users.into_iter().take(1).collect::<Vec<_>>() })));
                }
                // Two pages, the second through @odata.nextLink.
                assert!(q.get("$select").is_some_and(|s| s.contains("onPremisesSyncEnabled")) || q.contains_key("$skiptoken"), "{q:?}");
                if q.get("$skiptoken").map(String::as_str) == Some("page2") {
                    return (Code::OK, axum::Json(json!({ "value": users.into_iter().skip(2).collect::<Vec<_>>() })));
                }
                let next = format!("{}/v1.0/users?$skiptoken=page2", GRAPH_URL.get().unwrap());
                (Code::OK, axum::Json(json!({ "@odata.nextLink": next, "value": users.into_iter().take(2).collect::<Vec<_>>() })))
            }),
        )
        .route(
            "/v1.0/users/{user}",
            axum::routing::patch(|S(m): S<EntraMock>, h: HeaderMap, P(user): P<String>, axum::Json(b): axum::Json<Value>| async move {
                if !authed(&h) {
                    return denied();
                }
                let mut st = m.0.lock().unwrap();
                if let Some(e) = b["accountEnabled"].as_bool() {
                    for u in st.users.iter_mut().filter(|u| u["id"] == user) {
                        u["accountEnabled"] = json!(e);
                    }
                }
                st.patches.push((user, b));
                (Code::NO_CONTENT, axum::Json(json!(null)))
            }),
        )
        .route(
            "/v1.0/users/{user}/revokeSignInSessions",
            post(|S(m): S<EntraMock>, h: HeaderMap, P(user): P<String>| async move {
                if !authed(&h) {
                    return denied();
                }
                m.0.lock().unwrap().revoked.push(user);
                (Code::OK, axum::Json(json!({ "value": true })))
            }),
        )
        .route(
            "/v1.0/groups",
            get(|S(m): S<EntraMock>, h: HeaderMap| async move {
                if !authed(&h) {
                    return denied();
                }
                let g: Vec<Value> = m.0.lock().unwrap().groups.iter().map(|g| g.0.clone()).collect();
                (Code::OK, axum::Json(json!({ "value": g })))
            }),
        )
        .route(
            "/v1.0/groups/{group}/members",
            get(|S(m): S<EntraMock>, h: HeaderMap, P(group): P<String>| async move {
                if !authed(&h) {
                    return denied();
                }
                let st = m.0.lock().unwrap();
                let ms: Vec<Value> = st.groups.iter().filter(|g| g.0["id"] == group).flat_map(|g| g.1.iter().map(|id| json!({ "id": id }))).collect();
                (Code::OK, axum::Json(json!({ "value": ms })))
            }),
        )
        .route(
            "/v1.0/groups/{group}/members/{member}/$ref",
            delete(|S(m): S<EntraMock>, h: HeaderMap, P((group, member)): P<(String, String)>| async move {
                if !authed(&h) {
                    return denied();
                }
                let mut st = m.0.lock().unwrap();
                for g in st.groups.iter_mut().filter(|g| g.0["id"] == group) {
                    g.1.retain(|x| *x != member);
                }
                st.removed.push((group, member));
                (Code::NO_CONTENT, axum::Json(json!(null)))
            }),
        )
        .route(
            "/v1.0/directoryRoles",
            get(|S(m): S<EntraMock>, h: HeaderMap, Q(q): Q<Query>| async move {
                if !authed(&h) {
                    return denied();
                }
                assert!(q.get("$expand").is_some_and(|e| e.starts_with("members")), "{q:?}");
                (Code::OK, axum::Json(json!({ "value": m.0.lock().unwrap().roles.clone() })))
            }),
        )
        .route(
            "/v1.0/reports/authenticationMethods/userRegistrationDetails",
            get(|S(m): S<EntraMock>, h: HeaderMap| async move {
                if !authed(&h) {
                    return denied();
                }
                (Code::OK, axum::Json(json!({ "value": m.0.lock().unwrap().mfa.clone() })))
            }),
        )
        .route(
            "/v1.0/deviceManagement/managedDevices",
            get(|S(m): S<EntraMock>, h: HeaderMap| async move {
                if !authed(&h) {
                    return denied();
                }
                (Code::OK, axum::Json(json!({ "value": m.0.lock().unwrap().devices.clone() })))
            }),
        )
        .with_state(entra_mock().clone())
}

/// What the fake directory (`RMM_IDENTITY_FAKE`) was asked to do, oldest first.
fn directory_ops(dir: &Path) -> Vec<Value> {
    std::fs::read_to_string(dir.join("dc1-identity.json.ops.jsonl"))
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

/// Tables (and columns, as text) holding `needle` anywhere.
async fn tables_containing(db: &sqlx::PgPool, needle: &str) -> Vec<String> {
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT table_name::text FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY 1",
    )
    .fetch_all(db)
    .await
    .unwrap();
    let mut found = vec![];
    for t in tables {
        let n: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM \"{t}\" x WHERE x::text LIKE '%' || $1 || '%'")))
            .bind(needle)
            .fetch_one(db)
            .await
            .unwrap();
        if n > 0 {
            found.push(t);
        }
    }
    found
}

async fn identity_users(api: &Api, client: &str, query: &str) -> Vec<Value> {
    api.get(&format!("/clients/{client}/identity/users?limit=500{query}")).await["items"].as_array().unwrap().clone()
}

fn by_username<'a>(users: &'a [Value], name: &str) -> &'a Value {
    users.iter().find(|u| u["username"] == name).unwrap_or_else(|| panic!("{name} in {users:?}"))
}

const SID: &str = "S-1-5-21-1004336348-1177238915-682003330";

/// Identity management: Active Directory through a fake on a second agent, Entra ID and Intune
/// through the Graph stand-in, who may do what, where a reset password goes (and where it
/// doesn't), and the leaver template's checklist.
#[allow(clippy::too_many_arguments)]
async fn identity(url: &str, admin: &Api, db: &sqlx::PgPool, dir: &Path, token: &str, id1: &str, a_id: &str, b_id: &str) {
    use reqwest::Method;

    // --- a domain controller (the fake directory) ---------------------------------------
    let fake = dir.join("dc1-identity.json");
    let user = |rid: u32, name: &str, extra: Value| {
        let mut u = json!({ "sid": format!("{SID}-{rid}"), "username": name, "upn": format!("{name}@corp.example"), "display_name": name,
                            "enabled": true, "usn": 50 + rid as i64 % 50 });
        u.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        u
    };
    std::fs::write(
        &fake,
        json!({
            "high_usn": 100,
            "users": [
                user(1104, "jdoe", json!({ "display_name": "Jane Doe", "email": "jane.doe@corp.example", "locked": true,
                                           "member_of": [format!("{SID}-1105")], "last_logon_at": "2026-11-20T08:00:00Z" })),
                user(500, "Administrator", json!({ "admin_count": true })),
                user(1110, "it.admin", json!({ "admin_count": true, "locked": true, "member_of": [format!("{SID}-512")] })),
                user(1120, "old.temp", json!({})),
                user(1121, "bob.leaver", json!({ "display_name": "Bob Leaver", "member_of": [format!("{SID}-1105"), format!("{SID}-1106")] })),
            ],
            "groups": [
                { "sid": format!("{SID}-1105"), "name": "Finance" },
                { "sid": format!("{SID}-1106"), "name": "VPN Users" },
                { "sid": format!("{SID}-512"), "name": "Domain Admins", "admin_count": true },
            ],
        })
        .to_string(),
    )
    .unwrap();
    let mut dc = Agent::new(dir, "dc1");
    let dc_id = dc.enroll(url, token).unwrap();
    dc.run(dir);
    admin.wait_online(&dc_id, true).await;
    let contact = admin.post("/contacts", json!({ "client_id": a_id, "name": "Jane Doe", "email": "Jane.Doe@corp.example" })).await;

    // Sources are for admins.
    let tech = signed_in(url, admin, "identity-tech@e2e.test", "technician", Some(a_id), true).await;
    let (s, _) = tech.call(Method::POST, &format!("/clients/{a_id}/identity-sources"), Some(json!({ "kind": "ad", "name": "Corp AD", "agent_id": dc_id }))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, v) = admin.call(Method::POST, &format!("/clients/{b_id}/identity-sources"), Some(json!({ "kind": "ad", "name": "x", "agent_id": dc_id }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "another client's agent: {v}");
    let ad = admin.post(&format!("/clients/{a_id}/identity-sources"), json!({ "kind": "ad", "name": "Corp AD", "agent_id": dc_id })).await;
    let ad_id = ad["id"].as_str().unwrap().to_string();
    let t = admin.post(&format!("/identity-sources/{ad_id}/test"), json!({})).await;
    assert_eq!(t["ok"], true, "{t}");
    assert!(t["detail"].as_str().unwrap().contains("3 groups"), "{t}");
    let s1 = tech.post(&format!("/identity-sources/{ad_id}/sync"), json!({})).await;
    assert_eq!((s1["stats"]["users"].as_u64(), s1["stats"]["full"].as_bool()), (Some(5), Some(true)), "{s1}");

    let users = identity_users(&tech, a_id, "").await;
    assert_eq!(users.len(), 5);
    let jdoe = by_username(&users, "jdoe").clone();
    assert_eq!((jdoe["locked"].as_bool(), jdoe["privileged"].as_bool()), (Some(true), Some(false)));
    assert_eq!(jdoe["contact_id"], contact["id"], "matched to the contact by email, ignoring case");
    assert_eq!(jdoe["last_logon_at"], "2026-11-20T08:00:00Z");
    assert_eq!(by_username(&users, "it.admin")["privileged"], true);
    let locked = identity_users(&tech, a_id, "&filter=locked").await;
    assert_eq!(locked.len(), 2);
    assert_eq!(identity_users(&tech, a_id, &format!("&contact_id={}", contact["id"].as_str().unwrap())).await.len(), 1);
    let (s, _) = tech.call(Method::GET, &format!("/clients/{a_id}/identity/users?filter=bogus"), None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let detail = tech.get(&format!("/identity/users/{}", jdoe["id"].as_str().unwrap())).await;
    assert_eq!(detail["groups"][0]["name"], "Finance", "{detail}");
    assert_eq!(detail["can_manage"], true);
    let groups = tech.get(&format!("/clients/{a_id}/identity/groups")).await;
    assert_eq!(groups.as_array().unwrap().len(), 3);
    assert!(groups.as_array().unwrap().iter().any(|g| g["name"] == "Domain Admins" && g["privileged"] == true));

    // --- AD actions ----------------------------------------------------------------------
    let act = |api: &Api, user: &Value, action: &str, body: Value| {
        let path = format!("/identity/users/{}/{action}", user["id"].as_str().unwrap());
        async move { api.call(Method::POST, &path, Some(body)).await }
    };
    let (s, v) = act(&tech, &jdoe, "unlock", json!({})).await;
    assert!(s.is_success(), "{s} {v}");
    assert_eq!(directory_ops(dir).last().unwrap()["op"], "unlock");
    assert_eq!(tech.get(&format!("/identity/users/{}", jdoe["id"].as_str().unwrap())).await["locked"], false);

    // Reset into the vault: the vault holds exactly what the directory was given.
    let (s, v) = act(&tech, &jdoe, "reset-password", json!({ "delivery": "vault" })).await;
    assert!(s.is_success(), "{s} {v}");
    assert_eq!(v["delivered"], "vault");
    assert!(v.get("password").is_none(), "{v}");
    let op = directory_ops(dir).last().unwrap().clone();
    assert_eq!((op["op"].as_str(), op["must_change"].as_bool()), (Some("reset_password"), Some(true)));
    let given = op["password"].as_str().unwrap().to_string();
    assert_eq!(given.len(), 16);
    let item = v["item_id"].as_str().unwrap();
    let revealed = tech.post(&format!("/vault/{item}/reveal"), json!({ "field": "password" })).await;
    assert_eq!(revealed["value"], given.as_str());
    let vi = tech.get(&format!("/vault/{item}")).await;
    assert_eq!((vi["item"]["managed_kind"].as_str().or(vi["managed_kind"].as_str())), Some("identity"), "{vi}");
    let reset_audit = audit_detail(db, "identity.reset_password").await;
    assert_eq!(reset_audit["delivery"], "vault");
    assert!(!reset_audit.to_string().contains(&given));

    // Reset shown once: the response, and nowhere in the database (the audit log included).
    let res = tech
        .http
        .post(format!("{}/identity/users/{}/reset-password", tech.base, jdoe["id"].as_str().unwrap()))
        .json(&json!({ "delivery": "show", "password": "Chosen-by-tech-9271", "must_change": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.headers()["cache-control"], "no-store");
    let v: Value = res.json().await.unwrap();
    assert_eq!((v["delivered"].as_str(), v["password"].as_str()), (Some("shown"), Some("Chosen-by-tech-9271")), "{v}");
    let op = directory_ops(dir).last().unwrap().clone();
    assert_eq!((op["password"].as_str(), op["must_change"].as_bool()), (Some("Chosen-by-tech-9271"), Some(false)));
    assert_eq!(tables_containing(db, "Chosen-by-tech-9271").await, Vec::<String>::new(), "a shown password is stored nowhere");
    assert_eq!(tables_containing(db, &given).await, Vec::<String>::new(), "a vaulted one only sealed");
    assert_eq!(audit_detail(db, "identity.reset_password").await["delivery"], "shown");
    let (s, _) = act(&tech, &jdoe, "reset-password", json!({})).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "a delivery must be chosen");

    let old = by_username(&users, "old.temp").clone();
    let (s, v) = act(&tech, &old, "disable", json!({})).await;
    assert!(s.is_success(), "{s} {v}");
    assert_eq!(directory_ops(dir).last().unwrap()["enabled"], false);
    assert_eq!(identity_users(&tech, a_id, "&filter=disabled").await.len(), 1);

    // Never RID 500; privileged accounts need an admin; Entra-only actions are refused here.
    let rid500 = by_username(&users, "Administrator").clone();
    let n = directory_ops(dir).len();
    let (s, v) = act(admin, &rid500, "disable", json!({})).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let it = by_username(&users, "it.admin").clone();
    let (s, _) = act(&tech, &it, "unlock", json!({})).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "a privileged account needs an admin");
    assert_eq!(directory_ops(dir).len(), n, "nothing reached the directory");
    let (s, v) = act(admin, &it, "unlock", json!({})).await;
    assert!(s.is_success(), "{s} {v}");
    let (s, _) = act(&tech, &jdoe, "revoke-sessions", json!({})).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // Another client's technician sees nothing of it.
    let tech_b = signed_in(url, admin, "identity-tech-b@e2e.test", "technician", Some(b_id), true).await;
    let (s, _) = tech_b.call(Method::GET, &format!("/identity/users/{}", jdoe["id"].as_str().unwrap()), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = act(&tech_b, &jdoe, "unlock", json!({})).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    for path in [format!("/clients/{a_id}/identity/users"), format!("/clients/{a_id}/identity-sources"), format!("/clients/{a_id}/mdm/devices")] {
        let (s, _) = tech_b.call(Method::GET, &path, None).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{path}");
    }
    // A technician without a second factor can read but not act.
    let tech_no2fa = signed_in(url, admin, "identity-tech-no2fa@e2e.test", "technician", Some(a_id), false).await;
    assert_eq!(identity_users(&tech_no2fa, a_id, "").await.len(), 5);
    let (s, _) = act(&tech_no2fa, &jdoe, "unlock", json!({})).await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // A delta sync picks up what changed (the fake bumps a user's USN on every action).
    let s2 = tech.post(&format!("/identity-sources/{ad_id}/sync"), json!({})).await;
    assert_eq!(s2["stats"]["full"], false, "{s2}");
    assert!(s2["stats"]["users"].as_u64().unwrap() >= 3, "{s2}");
    assert_eq!(by_username(&identity_users(&tech, a_id, "").await, "jdoe")["locked"], false);

    // --- Entra ID and Intune -----------------------------------------------------------------
    let a1 = admin.get(&format!("/agents/{id1}")).await;
    let host = a1["hostname"].as_str().unwrap().to_string();
    {
        let mut m = entra_mock().0.lock().unwrap();
        let id = |n: u32| format!("8d4c1f1e-0000-4000-8000-{n:012}");
        m.users = vec![
            json!({ "id": id(1), "userPrincipalName": "adele@contoso.example", "displayName": "Adele Vance", "mail": "adele@contoso.example",
                    "accountEnabled": true, "onPremisesSyncEnabled": null, "department": "Retail", "jobTitle": "Manager" }),
            json!({ "id": id(2), "userPrincipalName": "synced@contoso.example", "displayName": "Synced User", "accountEnabled": true,
                    "onPremisesSyncEnabled": true }),
            json!({ "id": id(3), "userPrincipalName": "ga@contoso.example", "displayName": "Global Admin", "accountEnabled": true }),
        ];
        m.groups = vec![(json!({ "id": "9a000000-0000-4000-8000-000000000001", "displayName": "Sales" }), vec![id(1), id(3)])];
        m.roles = vec![json!({ "id": "r1", "displayName": "Global Administrator", "members": [{ "id": id(3) }] })];
        m.mfa = vec![json!({ "id": id(1), "isMfaRegistered": false }), json!({ "id": id(3), "isMfaRegistered": true })];
        m.devices = vec![
            json!({ "id": "d1", "deviceName": host.to_uppercase(), "userPrincipalName": "adele@contoso.example", "operatingSystem": "Windows",
                    "osVersion": "10.0.22631", "complianceState": "compliant", "isEncrypted": true, "managedDeviceOwnerType": "company",
                    "serialNumber": "SER-1", "lastSyncDateTime": "2026-11-23T10:00:00Z" }),
            json!({ "id": "d2", "deviceName": "Adele's iPhone", "userPrincipalName": "adele@contoso.example", "operatingSystem": "iOS",
                    "complianceState": "noncompliant", "isEncrypted": false, "managedDeviceOwnerType": "personal" }),
        ];
    }
    let (s, v) = admin
        .call(
            Method::POST,
            &format!("/clients/{a_id}/identity-sources"),
            Some(json!({ "kind": "entra", "name": "Contoso", "tenant_id": "e2e-tenant", "app_client_id": "not-a-guid", "secret": "graph-s3cret" })),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let entra = admin
        .post(
            &format!("/clients/{a_id}/identity-sources"),
            json!({ "kind": "entra", "name": "Contoso", "tenant_id": "e2e-tenant", "app_client_id": "11111111-2222-4333-8444-555555555555",
                    "secret": "graph-s3cret", "sync_devices": true }),
        )
        .await;
    assert_eq!(entra["has_secret"], true);
    assert!(entra.get("secret").is_none());
    let entra_id = entra["id"].as_str().unwrap().to_string();
    let (secret, sealed): (Vec<u8>, bool) =
        sqlx::query_as("SELECT secret, secret_sealed FROM identity_sources WHERE id = $1::uuid").bind(&entra_id).fetch_one(db).await.unwrap();
    assert!(sealed && !String::from_utf8_lossy(&secret).contains("graph-s3cret"), "the client secret is sealed at rest");
    assert_eq!(admin.post(&format!("/identity-sources/{entra_id}/test"), json!({})).await["ok"], true);
    let s3 = admin.post(&format!("/identity-sources/{entra_id}/sync"), json!({})).await;
    assert_eq!((s3["stats"]["users"].as_u64(), s3["stats"]["groups"].as_u64(), s3["stats"]["devices"].as_u64()), (Some(3), Some(1), Some(2)), "{s3}");

    let all = identity_users(&tech, a_id, &format!("&source_id={entra_id}")).await;
    assert_eq!(all.len(), 3, "both pages");
    let adele = all.iter().find(|u| u["upn"] == "adele@contoso.example").unwrap().clone();
    let synced = all.iter().find(|u| u["upn"] == "synced@contoso.example").unwrap().clone();
    let ga = all.iter().find(|u| u["upn"] == "ga@contoso.example").unwrap().clone();
    assert_eq!((ga["privileged"].as_bool(), synced["synced_from_ad"].as_bool()), (Some(true), Some(true)));
    let no_mfa = identity_users(&tech, a_id, "&filter=no_mfa").await;
    assert_eq!(no_mfa.iter().map(|u| u["upn"].as_str().unwrap()).collect::<Vec<_>>(), ["adele@contoso.example"]);

    let (s, v) = act(&tech, &adele, "disable", json!({})).await;
    assert!(s.is_success(), "{s} {v}");
    let (s, v) = act(&tech, &adele, "reset-password", json!({ "delivery": "show" })).await;
    assert!(s.is_success(), "{s} {v}");
    let shown = v["password"].as_str().unwrap().to_string();
    let (s, v) = act(&tech, &adele, "revoke-sessions", json!({})).await;
    assert!(s.is_success(), "{s} {v}");
    let (s, v) = act(&tech, &adele, "remove-groups", json!({})).await;
    assert!(s.is_success(), "{s} {v}");
    {
        let m = entra_mock().0.lock().unwrap();
        let adele_id = adele["external_id"].as_str().unwrap();
        assert_eq!(m.patches[0], (adele_id.to_string(), json!({ "accountEnabled": false })));
        assert_eq!(m.patches[1].1["passwordProfile"], json!({ "password": shown, "forceChangePasswordNextSignIn": true }));
        assert_eq!(m.revoked, [adele_id]);
        assert_eq!(m.removed, [("9a000000-0000-4000-8000-000000000001".to_string(), adele_id.to_string())]);
    }
    assert!(tables_containing(db, &shown).await.is_empty());
    let (s, v) = act(admin, &synced, "disable", json!({})).await;
    assert_eq!(s, StatusCode::CONFLICT, "synced from AD: changed there: {v}");
    let (s, _) = act(&tech, &ga, "revoke-sessions", json!({})).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "a directory role member needs an admin");
    let (s, _) = act(&tech, &adele, "unlock", json!({})).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "Entra has no unlock");

    // Intune: matched to the agent by host name; the gap lists; scoped to the client.
    let devices = tech.get(&format!("/clients/{a_id}/mdm/devices")).await;
    assert_eq!(devices["total"], 2, "{devices}");
    let d1 = devices["items"].as_array().unwrap().iter().find(|d| d["external_id"] == "d1").unwrap();
    assert_eq!(d1["agent_id"], id1, "{d1}");
    assert_eq!((d1["compliance"].as_str(), d1["encrypted"].as_bool()), (Some("compliant"), Some(true)));
    let unmatched = tech.get(&format!("/clients/{a_id}/mdm/devices?unmatched=true")).await;
    assert_eq!(unmatched["items"][0]["name"], "Adele's iPhone");
    assert_eq!(tech.get(&format!("/clients/{a_id}/mdm/devices?compliance=noncompliant")).await["total"], 1);
    let summary = tech.get(&format!("/clients/{a_id}/mdm/summary")).await;
    assert_eq!((summary["total"].as_i64(), summary["unmatched"].as_i64(), summary["by_compliance"]["compliant"].as_i64()), (Some(2), Some(1), Some(1)));
    let (s, _) = tech_b.call(Method::GET, &format!("/mdm/devices/{}", d1["id"].as_str().unwrap()), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // A device gone from Intune goes from here at the next sync.
    entra_mock().0.lock().unwrap().devices.truncate(1);
    admin.post(&format!("/identity-sources/{entra_id}/sync"), json!({})).await;
    assert_eq!(tech.get(&format!("/clients/{a_id}/mdm/devices")).await["total"], 1);

    // --- the leaver template ---------------------------------------------------------------------
    let templates = tech.get(&format!("/ticket-templates?client_id={a_id}")).await;
    let leaver_t = templates.as_array().unwrap().iter().find(|t| t["name"] == "Leaver").unwrap().clone();
    assert!(templates.as_array().unwrap().iter().any(|t| t["name"] == "New starter"));
    let bob = by_username(&users, "bob.leaver").clone();
    let (s, _) = tech_b
        .call(Method::POST, "/tickets/from-template", Some(json!({ "template_id": leaver_t["id"], "client_id": a_id, "identity_user_id": bob["id"] })))
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "another client's technician");
    let t = tech.post("/tickets/from-template", json!({ "template_id": leaver_t["id"], "client_id": a_id, "identity_user_id": bob["id"] })).await;
    let ticket = t["id"].as_str().unwrap().to_string();
    assert_eq!(tech.get(&format!("/tickets/{ticket}")).await["subject"], "Leaver: Bob Leaver");
    let cl = tech.get(&format!("/tickets/{ticket}/checklist")).await;
    assert_eq!(cl["identity_user"]["display_name"], "Bob Leaver");
    let items = cl["items"].as_array().unwrap();
    assert_eq!(items.len(), leaver_t["checklist"].as_array().unwrap().len());
    let item = |action: &str| items.iter().find(|i| i["action"] == action).unwrap()["id"].as_str().unwrap().to_string();
    let r = tech.post(&format!("/tickets/{ticket}/checklist/{}/run", item("identity.disable")), json!({})).await;
    let done = r["items"].as_array().unwrap().iter().find(|i| i["action"] == "identity.disable").unwrap();
    assert_eq!(done["action_state"], "done");
    assert!(done["done_at"].is_string());
    let op = directory_ops(dir).last().unwrap().clone();
    assert_eq!((op["op"].as_str(), op["sid"].as_str(), op["enabled"].as_bool()), (Some("set_enabled"), bob["external_id"].as_str(), Some(false)));
    let r = tech.post(&format!("/tickets/{ticket}/checklist/{}/run", item("identity.remove_groups")), json!({})).await;
    assert_eq!(r["outcome"]["ok"], true);
    assert_eq!(directory_ops(dir).last().unwrap()["group_sids"].as_array().unwrap().len(), 2);
    // AD has no sessions to revoke: the item records why.
    let (s, _) = tech.call(Method::POST, &format!("/tickets/{ticket}/checklist/{}/run", item("identity.revoke_sessions")), Some(json!({}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let cl = tech.get(&format!("/tickets/{ticket}/checklist")).await;
    let failed = cl["items"].as_array().unwrap().iter().find(|i| i["action"] == "identity.revoke_sessions").unwrap();
    assert!(failed["action_state"].as_str().unwrap().starts_with("failed"), "{failed}");
    assert!(failed["done_at"].is_null());
    let manual = items.iter().find(|i| i["action"].is_null()).unwrap()["id"].as_str().unwrap().to_string();
    tech.post(&format!("/tickets/{ticket}/checklist/{manual}"), json!({ "done": true })).await;
    let notes: Vec<String> = sqlx::query_scalar("SELECT body FROM ticket_events WHERE ticket_id = $1::uuid AND kind = 'note' AND NOT public ORDER BY id")
        .bind(&ticket)
        .fetch_all(db)
        .await
        .unwrap();
    assert!(notes.iter().any(|n| n.contains("identity.disable") && n.contains("Bob Leaver") && n.ends_with("done")), "{notes:?}");
    assert!(notes.iter().any(|n| n.starts_with("Checklist: done:")), "{notes:?}");
    assert_eq!(notes.len(), 4, "{notes:?}");
    // Editing the list keeps the state of what stays.
    let kept: Vec<Value> = cl["items"].as_array().unwrap().iter().take(2).map(|i| json!({ "id": i["id"], "text": i["text"], "action": i["action"] })).collect();
    let mut body = kept.clone();
    body.push(json!({ "text": "Archive the home folder" }));
    let cl = tech.put(&format!("/tickets/{ticket}/checklist"), json!({ "items": body })).await;
    let items = cl["items"].as_array().unwrap();
    assert_eq!(items.len(), 3);
    assert_eq!(items[1]["action_state"], "done", "{cl}");
    // Templates are admin-only to change.
    let (s, _) = tech.call(Method::POST, "/ticket-templates", Some(json!({ "name": "Mine", "checklist": [] }))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let mine = admin
        .post("/ticket-templates", json!({ "name": "Laptop swap", "client_id": a_id, "checklist": [{ "text": "Wipe the old one" }, { "text": "Sign out", "action": "identity.revoke_sessions" }] }))
        .await;
    assert_eq!(mine["checklist"].as_array().unwrap().len(), 2);
    let (s, _) = admin.call(Method::POST, "/ticket-templates", Some(json!({ "name": "Bad", "checklist": [{ "text": "x", "action": "identity.delete" }] }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(
        !tech_b.get(&format!("/ticket-templates?client_id={b_id}")).await.as_array().unwrap().iter().any(|t| t["name"] == "Laptop swap"),
        "another client's template"
    );
    let (s, _) = admin.call(Method::DELETE, &format!("/ticket-templates/{}", mine["id"].as_str().unwrap()), None).await;
    assert!(s.is_success());

    // Every action is audited, never with a password.
    for action in ["identity.unlock", "identity.disable", "identity.revoke_sessions", "identity.remove_groups", "identity.source.create", "identity.source.sync"] {
        assert!(audit_count(db, action).await > 0, "{action}");
    }
    let leaked: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE details::text LIKE '%Chosen-by-tech%' OR details::text LIKE '%' || $1 || '%'")
        .bind(&shown)
        .fetch_one(db)
        .await
        .unwrap();
    assert_eq!(leaked, 0);

    // Deleting a directory takes its users with it.
    let (s, _) = admin.call(Method::DELETE, &format!("/identity-sources/{entra_id}"), None).await;
    assert!(s.is_success());
    assert_eq!(identity_users(&tech, a_id, "").await.len(), 5);
    dc.kill();
}
