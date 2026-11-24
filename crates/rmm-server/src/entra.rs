//! Entra ID (Azure AD) through Microsoft Graph, for a client's identity source
//! (docs/design/identity.md), and Intune managed devices through the same connection
//! (docs/design/mdm.md).
//!
//! Each connection is an app registration in the customer's tenant, signed in with the
//! client-credentials flow ([`crate::graph::app_token`]). Reading needs `User.Read.All` and
//! `Group.Read.All` (plus `RoleManagement.Read.Directory` for privileged detection, and
//! `AuditLog.Read.All` for MFA registration, both optional); actions need `User.ReadWrite.All`,
//! `GroupMember.ReadWrite.All` and the User Administrator directory role on the app's service
//! principal (Graph won't reset passwords on application permissions alone); devices need
//! `DeviceManagementManagedDevices.Read.All`.
//!
//! Paged lists follow `@odata.nextLink`, but only to the Graph host the first request went to,
//! so the token is never sent anywhere else.

use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use crate::graph::{error_text, graph_base};

/// At most this many pages per list (999 users a page: about a million).
const MAX_PAGES: usize = 1000;

pub struct Client<'a> {
    http: &'a reqwest::Client,
    token: String,
    base: String,
}

impl<'a> Client<'a> {
    pub async fn connect(http: &'a reqwest::Client, tenant: &str, app_client_id: &str, secret: &str) -> Result<Client<'a>> {
        let token = crate::graph::app_token(http, tenant, app_client_id, secret).await?;
        Ok(Client { http, token, base: format!("{}/v1.0", graph_base()) })
    }

    /// `{base}/<segments...>` with each segment escaped.
    fn url(&self, segments: &[&str]) -> Result<reqwest::Url> {
        let mut u = reqwest::Url::parse(&self.base).context("Graph URL")?;
        {
            let mut p = u.path_segments_mut().map_err(|_| anyhow::anyhow!("Graph URL can't have a path"))?;
            p.pop_if_empty();
            for s in segments {
                p.push(s);
            }
        }
        Ok(u)
    }

    async fn check(res: reqwest::Response, what: &str) -> Result<reqwest::Response> {
        if res.status().is_success() {
            return Ok(res);
        }
        let status = res.status();
        bail!("{what}: {status}: {}", error_text(&res.text().await.unwrap_or_default()))
    }

    /// Every item of a paged list.
    async fn get_all(&self, what: &str, segments: &[&str], query: &[(&str, &str)]) -> Result<Vec<Value>> {
        let mut url = self.url(segments)?;
        url.query_pairs_mut().extend_pairs(query);
        let mut items = Vec::new();
        for _ in 0..MAX_PAGES {
            let res = self.http.get(url.clone()).bearer_auth(&self.token).header("ConsistencyLevel", "eventual").send().await.with_context(|| what.to_string())?;
            let page: Value = Self::check(res, what).await?.json().await.with_context(|| format!("{what}: response"))?;
            items.extend(page["value"].as_array().cloned().unwrap_or_default());
            match page["@odata.nextLink"].as_str() {
                Some(next) if next.starts_with(&self.base) => url = reqwest::Url::parse(next).context("next page link")?,
                Some(next) => bail!("{what}: the next page link points elsewhere ({})", next.chars().take(100).collect::<String>()),
                None => return Ok(items),
            }
        }
        bail!("{what}: more than {MAX_PAGES} pages")
    }

    pub async fn users(&self) -> Result<Vec<EntraUser>> {
        let v = self
            .get_all(
                "listing users",
                &["users"],
                &[
                    ("$select", "id,userPrincipalName,displayName,mail,accountEnabled,onPremisesSyncEnabled,department,jobTitle,lastPasswordChangeDateTime"),
                    ("$top", "999"),
                ],
            )
            .await?;
        Ok(v.iter().filter_map(parse_user).collect())
    }

    pub async fn groups(&self) -> Result<Vec<EntraGroup>> {
        let v = self.get_all("listing groups", &["groups"], &[("$select", "id,displayName,description"), ("$top", "999")]).await?;
        Ok(v.iter().filter_map(parse_group).collect())
    }

    /// Ids of the group's direct members.
    pub async fn group_members(&self, group: &str) -> Result<Vec<String>> {
        let v = self.get_all("listing group members", &["groups", group, "members"], &[("$select", "id"), ("$top", "999")]).await?;
        Ok(v.iter().filter_map(|m| m["id"].as_str().map(String::from)).collect())
    }

    /// Members of any activated directory role (Global Administrator, User Administrator...).
    pub async fn privileged(&self) -> Result<HashSet<String>> {
        let v = self.get_all("listing directory roles", &["directoryRoles"], &[("$select", "id,displayName"), ("$expand", "members($select=id)")]).await?;
        Ok(role_members(&v))
    }

    /// Whether each user has registered an MFA method. Needs `AuditLog.Read.All` and a premium
    /// licence; `None` when the tenant won't say.
    pub async fn mfa(&self) -> Option<HashMap<String, bool>> {
        let v = self
            .get_all("reading MFA registration", &["reports", "authenticationMethods", "userRegistrationDetails"], &[("$select", "id,isMfaRegistered")])
            .await
            .map_err(|e| tracing::debug!("{e:#}"))
            .ok()?;
        Some(v.iter().filter_map(|r| Some((r["id"].as_str()?.to_string(), r["isMfaRegistered"].as_bool()?))).collect())
    }

    pub async fn devices(&self) -> Result<Vec<MdmDevice>> {
        let v = self
            .get_all(
                "listing Intune devices",
                &["deviceManagement", "managedDevices"],
                &[(
                    "$select",
                    "id,deviceName,userPrincipalName,operatingSystem,osVersion,complianceState,isEncrypted,managedDeviceOwnerType,serialNumber,model,manufacturer,enrolledDateTime,lastSyncDateTime",
                )],
            )
            .await?;
        Ok(v.iter().filter_map(parse_device).collect())
    }

    async fn patch_user(&self, id: &str, body: Value, what: &str) -> Result<()> {
        let res = self.http.patch(self.url(&["users", id])?).bearer_auth(&self.token).json(&body).send().await.with_context(|| what.to_string())?;
        Self::check(res, what).await.map(|_| ())
    }

    /// Connectivity check: one user.
    pub async fn test(&self) -> Result<()> {
        let mut url = self.url(&["users"])?;
        url.query_pairs_mut().append_pair("$top", "1").append_pair("$select", "id");
        let res = self.http.get(url).bearer_auth(&self.token).send().await.context("reading users")?;
        Self::check(res, "reading users").await.map(|_| ())
    }

    pub async fn set_enabled(&self, id: &str, enabled: bool) -> Result<()> {
        self.patch_user(id, json!({ "accountEnabled": enabled }), if enabled { "enabling the user" } else { "disabling the user" }).await
    }

    pub async fn reset_password(&self, id: &str, password: &str, must_change: bool) -> Result<()> {
        self.patch_user(id, json!({ "passwordProfile": { "password": password, "forceChangePasswordNextSignIn": must_change } }), "resetting the password")
            .await
    }

    pub async fn revoke_sessions(&self, id: &str) -> Result<()> {
        let res = self.http.post(self.url(&["users", id, "revokeSignInSessions"])?).bearer_auth(&self.token).send().await.context("revoking sessions")?;
        Self::check(res, "revoking sessions").await.map(|_| ())
    }

    pub async fn remove_from_group(&self, group: &str, user: &str) -> Result<()> {
        let what = "removing from a group";
        let res = self.http.delete(self.url(&["groups", group, "members", user, "$ref"])?).bearer_auth(&self.token).send().await.context(what)?;
        if res.status() == reqwest::StatusCode::NOT_FOUND {
            // Not a member any more: the goal is reached.
            return Ok(());
        }
        Self::check(res, what).await.map(|_| ())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct EntraUser {
    pub id: String,
    pub upn: String,
    pub display_name: String,
    pub mail: String,
    pub enabled: bool,
    pub synced_from_ad: bool,
    pub department: String,
    pub title: String,
    pub password_last_set: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EntraGroup {
    pub id: String,
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MdmDevice {
    pub id: String,
    pub name: String,
    pub user_upn: String,
    pub os: String,
    pub os_version: String,
    pub compliance: String,
    pub encrypted: Option<bool>,
    pub ownership: String,
    pub serial: String,
    pub model: String,
    pub manufacturer: String,
    pub enrolled_at: Option<DateTime<Utc>>,
    pub last_sync_at: Option<DateTime<Utc>>,
}

fn text(v: &Value) -> String {
    v.as_str().unwrap_or_default().trim().to_string()
}

fn date(v: &Value) -> Option<DateTime<Utc>> {
    let t = DateTime::parse_from_rfc3339(v.as_str()?).ok()?.with_timezone(&Utc);
    // Intune's "never" is 0001-01-01.
    (t.timestamp() > 0).then_some(t)
}

pub fn parse_user(v: &Value) -> Option<EntraUser> {
    Some(EntraUser {
        id: v["id"].as_str()?.to_string(),
        upn: text(&v["userPrincipalName"]),
        display_name: text(&v["displayName"]),
        mail: text(&v["mail"]),
        enabled: v["accountEnabled"].as_bool().unwrap_or(true),
        synced_from_ad: v["onPremisesSyncEnabled"].as_bool().unwrap_or(false),
        department: text(&v["department"]),
        title: text(&v["jobTitle"]),
        password_last_set: date(&v["lastPasswordChangeDateTime"]),
    })
}

pub fn parse_group(v: &Value) -> Option<EntraGroup> {
    Some(EntraGroup { id: v["id"].as_str()?.to_string(), name: text(&v["displayName"]), description: text(&v["description"]) })
}

pub fn role_members(roles: &[Value]) -> HashSet<String> {
    roles.iter().flat_map(|r| r["members"].as_array().into_iter().flatten()).filter_map(|m| m["id"].as_str().map(String::from)).collect()
}

pub fn parse_device(v: &Value) -> Option<MdmDevice> {
    let ownership = match v["managedDeviceOwnerType"].as_str().unwrap_or("") {
        "company" => "company",
        "personal" => "personal",
        _ => "unknown",
    };
    let compliance = text(&v["complianceState"]);
    Some(MdmDevice {
        id: v["id"].as_str()?.to_string(),
        name: text(&v["deviceName"]),
        user_upn: text(&v["userPrincipalName"]),
        os: text(&v["operatingSystem"]),
        os_version: text(&v["osVersion"]),
        compliance: if compliance.is_empty() { "unknown".into() } else { compliance.chars().take(40).collect() },
        encrypted: v["isEncrypted"].as_bool(),
        ownership: ownership.into(),
        serial: text(&v["serialNumber"]),
        model: text(&v["model"]),
        manufacturer: text(&v["manufacturer"]),
        enrolled_at: date(&v["enrolledDateTime"]),
        last_sync_at: date(&v["lastSyncDateTime"]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorded_pages() {
        let users: Value = serde_json::from_str(include_str!("../tests/fixtures/graph-users.json")).unwrap();
        let u: Vec<EntraUser> = users["value"].as_array().unwrap().iter().filter_map(parse_user).collect();
        assert_eq!(u.len(), 3);
        assert_eq!(u[0].upn, "adele@contoso.example");
        assert!(u[0].enabled && !u[0].synced_from_ad);
        assert_eq!(u[0].password_last_set.unwrap().to_rfc3339(), "2026-10-01T09:30:00+00:00");
        assert!(!u[1].enabled && u[1].mail.is_empty() && u[1].title.is_empty());
        assert!(u[2].synced_from_ad);
        assert!(users["@odata.nextLink"].is_string());

        let roles: Value = serde_json::from_str(include_str!("../tests/fixtures/graph-directory-roles.json")).unwrap();
        let p = role_members(roles["value"].as_array().unwrap());
        assert!(p.contains("8d4c1f1e-0000-4000-8000-00000000000a") && p.len() == 2);

        let devices: Value = serde_json::from_str(include_str!("../tests/fixtures/graph-managed-devices.json")).unwrap();
        let d: Vec<MdmDevice> = devices["value"].as_array().unwrap().iter().filter_map(parse_device).collect();
        assert_eq!(d.len(), 2);
        assert_eq!((d[0].compliance.as_str(), d[0].ownership.as_str(), d[0].encrypted), ("compliant", "company", Some(true)));
        assert_eq!(d[0].serial, "5CD1234XYZ");
        assert_eq!((d[1].compliance.as_str(), d[1].ownership.as_str()), ("noncompliant", "personal"));
        assert_eq!(d[1].enrolled_at, None, "0001-01-01 is never");
    }
}
