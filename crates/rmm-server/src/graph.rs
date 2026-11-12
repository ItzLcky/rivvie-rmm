//! Microsoft 365 mailboxes over Microsoft Graph, for tenants where basic-auth IMAP and SMTP
//! are switched off.
//!
//! An app registration with the `Mail.ReadWrite` and `Mail.Send` application permissions
//! (ideally limited to the support mailbox with an application access policy) signs in with
//! the client-credentials flow. Polling lists unread messages in the folder, files each one's
//! MIME through [`crate::email::receive`] and marks it read; replies go out with `sendMail`
//! as MIME, so threading headers survive.
//!
//! `RMM_GRAPH_LOGIN_URL` and `RMM_GRAPH_URL` override the Microsoft endpoints (tests, national
//! clouds).

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::json;
use tracing::warn;

use crate::email::Mailbox;
use crate::state::AppState;

fn login_base() -> String {
    std::env::var("RMM_GRAPH_LOGIN_URL").unwrap_or_else(|_| "https://login.microsoftonline.com".into()).trim_end_matches('/').to_string()
}

fn graph_base() -> String {
    std::env::var("RMM_GRAPH_URL").unwrap_or_else(|_| "https://graph.microsoft.com".into()).trim_end_matches('/').to_string()
}

/// The app's client secret, unsealed.
fn secret(st: &AppState, mb: &Mailbox) -> Result<String> {
    let stored = mb.graph_secret.as_deref().context("the mailbox has no client secret")?;
    let plain = crate::crypto::load(st.cfg.data_key.as_ref(), stored, mb.graph_secret_sealed)
        .context("the client secret can't be decrypted (was RMM_DATA_KEY changed?)")?;
    String::from_utf8(plain).context("client secret")
}

async fn token(st: &AppState, mb: &Mailbox) -> Result<String> {
    #[derive(Deserialize)]
    struct Token {
        access_token: String,
    }
    let url = format!("{}/{}/oauth2/v2.0/token", login_base(), mb.graph_tenant);
    let scope = format!("{}/.default", graph_scope());
    let secret = secret(st, mb)?;
    let res = st
        .http
        .post(&url)
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", mb.graph_client_id.as_str()),
            ("client_secret", secret.as_str()),
            ("scope", scope.as_str()),
        ])
        .send()
        .await
        .context("signing in to Microsoft")?;
    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().await.unwrap_or_default();
        bail!("signing in to Microsoft: {status}: {}", error_text(&body));
    }
    Ok(res.json::<Token>().await.context("token response")?.access_token)
}

/// The resource the token is for: the real Graph host even when the URL is overridden for tests.
fn graph_scope() -> String {
    std::env::var("RMM_GRAPH_SCOPE").unwrap_or_else(|_| "https://graph.microsoft.com".into())
}

/// The useful part of a Graph or identity-platform error body.
fn error_text(body: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    v["error"]["message"]
        .as_str()
        .or(v["error_description"].as_str())
        .map(|s| s.lines().next().unwrap_or(s).to_string())
        .unwrap_or_else(|| body.chars().take(300).collect())
}

/// `{graph}/v1.0/users/{address}/<rest...>` with each segment escaped.
fn user_url(mb: &Mailbox, rest: &[&str]) -> Result<reqwest::Url> {
    let mut u = reqwest::Url::parse(&format!("{}/v1.0", graph_base())).context("Graph URL")?;
    {
        let mut segs = u.path_segments_mut().map_err(|_| anyhow::anyhow!("Graph URL can't have a path"))?;
        segs.push("users").push(&mb.address);
        for s in rest {
            segs.push(s);
        }
    }
    Ok(u)
}

/// Graph's name for the folder: the well-known `inbox` for IMAP's INBOX, else as given (a
/// well-known name or a folder id).
fn folder(mb: &Mailbox) -> String {
    let f = mb.imap_folder.trim();
    if f.is_empty() || f.eq_ignore_ascii_case("inbox") { "inbox".into() } else { f.to_string() }
}

/// Files unread messages (at most 50 per poll), marking each read once it's stored.
pub async fn poll(st: &AppState, mb: &Mailbox) -> Result<usize> {
    #[derive(Deserialize)]
    struct Msg {
        id: String,
    }
    #[derive(Deserialize)]
    struct List {
        value: Vec<Msg>,
    }
    let token = token(st, mb).await?;
    let mut url = user_url(mb, &["mailFolders", &folder(mb), "messages"])?;
    url.query_pairs_mut().append_pair("$filter", "isRead eq false").append_pair("$select", "id").append_pair("$top", "50");
    let res = st.http.get(url).bearer_auth(&token).send().await.context("listing messages")?;
    if !res.status().is_success() {
        let status = res.status();
        bail!("listing messages: {status}: {}", error_text(&res.text().await.unwrap_or_default()));
    }
    let list: List = res.json().await.context("message list")?;
    let mut filed = 0;
    for m in list.value {
        let raw = st.http.get(user_url(mb, &["messages", &m.id, "$value"])?).bearer_auth(&token).send().await?;
        if !raw.status().is_success() {
            warn!(mailbox = %mb.name, id = %m.id, status = %raw.status(), "fetching message MIME");
            continue;
        }
        let bytes = raw.bytes().await?;
        match crate::email::receive(st, mb, &bytes).await {
            Ok(_) => {
                filed += 1;
                let res = st
                    .http
                    .patch(user_url(mb, &["messages", &m.id])?)
                    .bearer_auth(&token)
                    .json(&json!({ "isRead": true }))
                    .send()
                    .await?;
                if !res.status().is_success() {
                    // Filed already; the Message-ID check makes the next poll a no-op for it.
                    warn!(mailbox = %mb.name, id = %m.id, status = %res.status(), "marking message read");
                }
            }
            // Left unread, so the next poll retries it.
            Err(e) => warn!(mailbox = %mb.name, id = %m.id, "filing message: {e:#}"),
        }
    }
    Ok(filed)
}

/// Sends a complete MIME message from the mailbox (`sendMail` with a base64 MIME body).
pub async fn send(st: &AppState, mb: &Mailbox, mime: &[u8]) -> Result<(), String> {
    let token = token(st, mb).await.map_err(|e| format!("{e:#}"))?;
    let url = user_url(mb, &["sendMail"]).map_err(|e| e.to_string())?;
    let res = st
        .http
        .post(url)
        .bearer_auth(&token)
        .header("content-type", "text/plain")
        .body(data_encoding::BASE64.encode(mime))
        .send()
        .await
        .map_err(|e| format!("Graph sendMail: {e}"))?;
    if res.status().is_success() {
        Ok(())
    } else {
        let status = res.status();
        Err(format!("Graph sendMail: {status}: {}", error_text(&res.text().await.unwrap_or_default())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mb(address: &str, folder: &str) -> Mailbox {
        Mailbox {
            id: uuid::Uuid::nil(),
            name: "m".into(),
            address: address.into(),
            kind: "graph".into(),
            imap_host: String::new(),
            imap_port: 993,
            imap_security: "tls".into(),
            imap_username: String::new(),
            imap_password: String::new(),
            imap_folder: folder.into(),
            board_id: uuid::Uuid::nil(),
            auto_reply: false,
            enabled: true,
            graph_tenant: "t".into(),
            graph_client_id: "c".into(),
            graph_secret: None,
            graph_secret_sealed: false,
        }
    }

    #[test]
    fn urls_and_folders() {
        let m = mb("help+it@msp.example", "INBOX");
        assert_eq!(folder(&m), "inbox");
        assert_eq!(folder(&mb("a@b.c", "Support Queue")), "Support Queue");
        let u = user_url(&m, &["messages", "AAMk/x=", "$value"]).unwrap();
        assert_eq!(u.as_str(), "https://graph.microsoft.com/v1.0/users/help+it@msp.example/messages/AAMk%2Fx=/$value");
    }

    #[test]
    fn error_messages() {
        assert_eq!(error_text(r#"{"error":{"code":"ErrorAccessDenied","message":"Access is denied.\nMore"}}"#), "Access is denied.");
        assert_eq!(error_text(r#"{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret."}"#), "AADSTS7000215: Invalid client secret.");
        assert_eq!(error_text("plain"), "plain");
    }
}
