//! Accounting sync: finalised invoices and credit notes go to QuickBooks Online or Xero, and
//! their payment status comes back. One provider is connected at a time, over OAuth 2.
//!
//! The app's client id and secret come from the provider's developer portal; the redirect
//! URI to register is `{RMM_PUBLIC_URL}/api/billing/accounting/{qbo|xero}/callback`. Tax is
//! left to the accounting system (its default tax for the item or account).
//!
//! Endpoints can be overridden (tests, the QuickBooks sandbox): `RMM_QBO_AUTH_URL`,
//! `RMM_QBO_TOKEN_URL`, `RMM_QBO_API_URL`, `RMM_XERO_AUTH_URL`, `RMM_XERO_TOKEN_URL`,
//! `RMM_XERO_API_URL`.

use std::sync::Arc;
use std::time::Duration as StdDuration;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use tracing::{info, warn};
use uuid::Uuid;

use crate::billing::minor_digits;
use crate::state::AppState;

pub const PROVIDERS: &[&str] = &["qbo", "xero"];

fn env_or(k: &str, d: &str) -> String {
    std::env::var(k).ok().filter(|v| !v.trim().is_empty()).unwrap_or_else(|| d.into()).trim_end_matches('/').to_string()
}

struct Urls {
    authorize: String,
    token: String,
    api: String,
    scope: &'static str,
}

fn urls(provider: &str) -> Urls {
    if provider == "qbo" {
        Urls {
            authorize: env_or("RMM_QBO_AUTH_URL", "https://appcenter.intuit.com/connect/oauth2"),
            token: env_or("RMM_QBO_TOKEN_URL", "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"),
            api: env_or("RMM_QBO_API_URL", "https://quickbooks.api.intuit.com"),
            scope: "com.intuit.quickbooks.accounting",
        }
    } else {
        Urls {
            authorize: env_or("RMM_XERO_AUTH_URL", "https://login.xero.com/identity/connect/authorize"),
            token: env_or("RMM_XERO_TOKEN_URL", "https://identity.xero.com/connect/token"),
            api: env_or("RMM_XERO_API_URL", "https://api.xero.com"),
            scope: "openid profile email accounting.transactions accounting.contacts offline_access",
        }
    }
}

pub fn redirect_uri(st: &AppState, provider: &str) -> String {
    format!("{}/api/billing/accounting/{provider}/callback", st.cfg.public_url)
}

#[derive(sqlx::FromRow)]
struct Conn {
    provider: String,
    client_id: String,
    client_secret: Option<Vec<u8>>,
    access_token: Option<Vec<u8>>,
    refresh_token: Option<Vec<u8>>,
    sealed: bool,
    token_expires_at: Option<DateTime<Utc>>,
    tenant_id: Option<String>,
    settings: Value,
}

const CONN_COLS: &str =
    "provider, client_id, client_secret, access_token, refresh_token, sealed, token_expires_at, tenant_id, settings";

fn open(st: &AppState, v: &Option<Vec<u8>>, sealed: bool) -> Result<String> {
    let b = v.as_deref().context("not connected")?;
    let plain = crate::crypto::load(st.cfg.data_key.as_ref(), b, sealed).context("can't decrypt the stored credentials (was RMM_DATA_KEY changed?)")?;
    String::from_utf8(plain).context("stored credential")
}

fn seal(st: &AppState, s: &str) -> (Vec<u8>, bool) {
    crate::crypto::store(st.cfg.data_key.as_ref(), s.as_bytes())
}

/// The connected provider, if any (one with a tenant).
async fn connected(st: &AppState) -> Result<Option<Conn>> {
    Ok(sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {CONN_COLS} FROM accounting_connections WHERE tenant_id IS NOT NULL AND refresh_token IS NOT NULL ORDER BY connected_at DESC LIMIT 1"
    )))
    .fetch_optional(&st.db)
    .await?)
}

/// Saves the app credentials for a provider (before connecting).
pub async fn save_app(st: &AppState, provider: &str, client_id: &str, secret: Option<&str>, settings: &Value) -> Result<()> {
    let sealed_secret = secret.map(|s| seal(st, s));
    sqlx::query(
        "INSERT INTO accounting_connections (provider, client_id, client_secret, sealed, settings) VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (provider) DO UPDATE SET client_id = $2, client_secret = coalesce($3, accounting_connections.client_secret),
                sealed = CASE WHEN $3::bytea IS NULL THEN accounting_connections.sealed ELSE $4 END, settings = $5",
    )
    .bind(provider)
    .bind(client_id)
    .bind(sealed_secret.as_ref().map(|s| s.0.clone()))
    .bind(sealed_secret.as_ref().is_some_and(|s| s.1))
    .bind(settings)
    .execute(&st.db)
    .await?;
    Ok(())
}

/// Where to send the admin to grant access. Remembers a one-time state for the callback.
pub async fn authorize_url(st: &AppState, provider: &str, user: Uuid) -> Result<String> {
    let client_id: Option<String> = sqlx::query_scalar("SELECT client_id FROM accounting_connections WHERE provider = $1 AND client_id <> ''")
        .bind(provider)
        .fetch_optional(&st.db)
        .await?;
    let client_id = client_id.context("save the app's client id and secret first")?;
    let state = crate::auth::random_token();
    sqlx::query("UPDATE accounting_connections SET oauth_state = $2, connected_by = $3 WHERE provider = $1")
        .bind(provider)
        .bind(format!("{}|{}", hex::encode(crate::auth::token_hash(&state)), (Utc::now() + Duration::minutes(15)).timestamp()))
        .bind(user)
        .execute(&st.db)
        .await?;
    let u = urls(provider);
    let mut url = reqwest::Url::parse(&u.authorize).context("authorize URL")?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &client_id)
        .append_pair("redirect_uri", &redirect_uri(st, provider))
        .append_pair("scope", u.scope)
        .append_pair("state", &state);
    Ok(url.to_string())
}

#[derive(Deserialize)]
struct Tokens {
    access_token: String,
    refresh_token: String,
    expires_in: Option<i64>,
}

async fn token_request(st: &AppState, provider: &str, client_id: &str, secret: &str, form: &[(&str, &str)]) -> Result<Tokens> {
    let res = st
        .http
        .post(urls(provider).token)
        .basic_auth(client_id, Some(secret))
        .header("accept", "application/json")
        .form(form)
        .send()
        .await
        .context("token request")?;
    if !res.status().is_success() {
        let status = res.status();
        bail!("token request: {status}: {}", res.text().await.unwrap_or_default().chars().take(300).collect::<String>());
    }
    res.json().await.context("token response")
}

/// The OAuth callback: checks the state, exchanges the code, finds the company / tenant.
pub async fn callback(st: &AppState, provider: &str, code: &str, state: &str, realm_id: Option<&str>) -> Result<()> {
    let row: Option<(String, String, Option<Vec<u8>>, bool)> =
        sqlx::query_as("SELECT coalesce(oauth_state, ''), client_id, client_secret, sealed FROM accounting_connections WHERE provider = $1")
            .bind(provider)
            .fetch_optional(&st.db)
            .await?;
    let (stored, client_id, secret, sealed) = row.context("unknown provider")?;
    let (hash, exp) = stored.split_once('|').context("no sign-in in progress")?;
    let fresh = exp.parse::<i64>().is_ok_and(|e| e > Utc::now().timestamp());
    if !fresh || !bool::from(subtle::ConstantTimeEq::ct_eq(hex::encode(crate::auth::token_hash(state)).as_bytes(), hash.as_bytes())) {
        bail!("the sign-in expired or didn't start here; try connecting again");
    }
    let secret = open(st, &secret, sealed)?;
    let redirect = redirect_uri(st, provider);
    let t = token_request(st, provider, &client_id, &secret, &[("grant_type", "authorization_code"), ("code", code), ("redirect_uri", &redirect)]).await?;
    let (tenant, name) = if provider == "qbo" {
        (realm_id.context("QuickBooks didn't say which company")?.to_string(), None)
    } else {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Connection {
            tenant_id: String,
            tenant_name: Option<String>,
        }
        let list: Vec<Connection> = st
            .http
            .get(format!("{}/connections", urls(provider).api))
            .bearer_auth(&t.access_token)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .context("Xero connections")?;
        let c = list.into_iter().next().context("no Xero organisation was authorised")?;
        (c.tenant_id, c.tenant_name)
    };
    let (access, s1) = seal(st, &t.access_token);
    let (refresh, _) = seal(st, &t.refresh_token);
    let mut tx = st.db.begin().await?;
    // One provider at a time.
    sqlx::query("UPDATE accounting_connections SET access_token = NULL, refresh_token = NULL, tenant_id = NULL, tenant_name = NULL WHERE provider <> $1")
        .bind(provider)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE accounting_connections SET access_token = $2, refresh_token = $3, sealed = $4, token_expires_at = $5, tenant_id = $6,
                tenant_name = $7, oauth_state = NULL, connected_at = now(), last_error = NULL WHERE provider = $1",
    )
    .bind(provider)
    .bind(access)
    .bind(refresh)
    .bind(s1)
    .bind(Utc::now() + Duration::seconds(t.expires_in.unwrap_or(1800)))
    .bind(&tenant)
    .bind(name)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    info!(provider, %tenant, "accounting connected");
    Ok(())
}

pub async fn disconnect(st: &AppState) -> Result<()> {
    sqlx::query("UPDATE accounting_connections SET access_token = NULL, refresh_token = NULL, tenant_id = NULL, tenant_name = NULL, token_expires_at = NULL")
        .execute(&st.db)
        .await?;
    Ok(())
}

/// A valid access token, refreshed when it's about to expire.
async fn token(st: &AppState, c: &Conn) -> Result<String> {
    if c.token_expires_at.is_some_and(|e| e > Utc::now() + Duration::seconds(60)) {
        return open(st, &c.access_token, c.sealed);
    }
    let secret = open(st, &c.client_secret, c.sealed)?;
    let refresh = open(st, &c.refresh_token, c.sealed)?;
    let t = token_request(st, &c.provider, &c.client_id, &secret, &[("grant_type", "refresh_token"), ("refresh_token", &refresh)]).await?;
    let (access, sealed) = seal(st, &t.access_token);
    let (refresh, _) = seal(st, &t.refresh_token);
    sqlx::query("UPDATE accounting_connections SET access_token = $2, refresh_token = $3, sealed = $4, token_expires_at = $5 WHERE provider = $1")
        .bind(&c.provider)
        .bind(access)
        .bind(refresh)
        .bind(sealed)
        .bind(Utc::now() + Duration::seconds(t.expires_in.unwrap_or(1800)))
        .execute(&st.db)
        .await?;
    Ok(t.access_token)
}

/// Minor units as a decimal number for JSON.
fn decimal(amount: i64, currency: &str) -> f64 {
    let scale = 10f64.powi(minor_digits(currency) as i32);
    (amount as f64 / scale * 1000.0).round() / 1000.0
}

#[derive(sqlx::FromRow)]
struct InvoiceCtx {
    number: Option<String>,
    kind: String,
    currency: String,
    issue_date: NaiveDate,
    due_date: NaiveDate,
    client_id: Uuid,
    client_name: String,
    accounting_ids: Value,
}

async fn api(st: &AppState, c: &Conn, method: reqwest::Method, path: &str, body: Option<Value>) -> Result<Value> {
    let tok = token(st, c).await?;
    let base = urls(&c.provider).api;
    let url = if c.provider == "qbo" {
        format!("{base}/v3/company/{}/{path}", c.tenant_id.as_deref().unwrap_or_default())
    } else {
        format!("{base}/api.xro/2.0/{path}")
    };
    let mut req = st.http.request(method, url).bearer_auth(tok).header("accept", "application/json");
    if c.provider == "xero" {
        req = req.header("xero-tenant-id", c.tenant_id.as_deref().unwrap_or_default());
    }
    if let Some(b) = body {
        req = req.json(&b);
    }
    let res = req.send().await.context("calling the accounting API")?;
    let status = res.status();
    let text = res.text().await.unwrap_or_default();
    if !status.is_success() {
        let v: Value = serde_json::from_str(&text).unwrap_or_default();
        let msg = v["Fault"]["Error"][0]["Detail"]
            .as_str()
            .or(v["Fault"]["Error"][0]["Message"].as_str())
            .or(v["Elements"][0]["ValidationErrors"][0]["Message"].as_str())
            .or(v["Message"].as_str())
            .map(str::to_string)
            .unwrap_or_else(|| text.chars().take(300).collect());
        bail!("{status}: {msg}");
    }
    serde_json::from_str(&text).context("accounting API response")
}

/// The client's customer / contact id in the accounting system, found by name or created.
async fn customer(st: &AppState, c: &Conn, inv: &InvoiceCtx) -> Result<String> {
    if let Some(id) = inv.accounting_ids[&c.provider].as_str() {
        return Ok(id.to_string());
    }
    let name = inv.client_name.replace(['\'', '"'], "");
    let id = if c.provider == "qbo" {
        let q = format!("query?query={}", urlencode(&format!("select Id from Customer where DisplayName = '{name}'")));
        let found = api(st, c, reqwest::Method::GET, &q, None).await?;
        match found["QueryResponse"]["Customer"][0]["Id"].as_str() {
            Some(id) => id.to_string(),
            None => api(st, c, reqwest::Method::POST, "customer", Some(json!({ "DisplayName": name }))).await?["Customer"]["Id"]
                .as_str()
                .context("QuickBooks returned no customer id")?
                .to_string(),
        }
    } else {
        let q = format!("Contacts?where={}", urlencode(&format!("Name==\"{name}\"")));
        let found = api(st, c, reqwest::Method::GET, &q, None).await?;
        match found["Contacts"][0]["ContactID"].as_str() {
            Some(id) => id.to_string(),
            None => api(st, c, reqwest::Method::POST, "Contacts", Some(json!({ "Contacts": [{ "Name": name }] }))).await?["Contacts"][0]["ContactID"]
                .as_str()
                .context("Xero returned no contact id")?
                .to_string(),
        }
    };
    sqlx::query("UPDATE clients SET accounting_ids = accounting_ids || jsonb_build_object($2::text, $3::text) WHERE id = $1")
        .bind(inv.client_id)
        .bind(&c.provider)
        .bind(&id)
        .execute(&st.db)
        .await?;
    Ok(id)
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

/// Pushes one finalised invoice or credit note. Returns its id in the accounting system.
pub async fn push(st: &AppState, invoice: Uuid) -> Result<String> {
    let c = connected(st).await?.context("no accounting system is connected")?;
    let inv: InvoiceCtx = sqlx::query_as(
        "SELECT i.number, i.kind, i.currency, i.issue_date, i.due_date, i.client_id, cl.name AS client_name, cl.accounting_ids
           FROM invoices i JOIN clients cl ON cl.id = i.client_id WHERE i.id = $1 AND i.status IN ('finalised', 'sent', 'paid')",
    )
    .bind(invoice)
    .fetch_optional(&st.db)
    .await?
    .context("only finalised invoices are synced")?;
    let lines: Vec<(String, i64, i64, i64)> =
        sqlx::query_as("SELECT description, quantity_milli, unit_price, amount FROM invoice_lines WHERE invoice_id = $1 ORDER BY position")
            .bind(invoice)
            .fetch_all(&st.db)
            .await?;
    let customer = customer(st, &c, &inv).await?;
    let credit = inv.kind == "credit_note";
    let number = inv.number.clone().unwrap_or_default();
    // Credit notes are positive documents of their own kind there.
    let sign = if credit { -1 } else { 1 };
    let id = if c.provider == "qbo" {
        let item = c.settings["item_id"].as_str().unwrap_or("1");
        let qbo_lines: Vec<Value> = lines
            .iter()
            .map(|(d, q, p, a)| {
                json!({
                    "DetailType": "SalesItemLineDetail",
                    "Amount": decimal(a * sign, &inv.currency),
                    "Description": d,
                    "SalesItemLineDetail": { "ItemRef": { "value": item }, "Qty": (*q * sign) as f64 / 1000.0, "UnitPrice": decimal(*p, &inv.currency) },
                })
            })
            .collect();
        let doc = json!({
            "CustomerRef": { "value": customer },
            "DocNumber": number.chars().take(21).collect::<String>(),
            "TxnDate": inv.issue_date.to_string(),
            "DueDate": inv.due_date.to_string(),
            "Line": qbo_lines,
        });
        let (path, key) = if credit { ("creditmemo", "CreditMemo") } else { ("invoice", "Invoice") };
        api(st, &c, reqwest::Method::POST, path, Some(doc)).await?[key]["Id"].as_str().context("QuickBooks returned no id")?.to_string()
    } else {
        let account = c.settings["account_code"].as_str().unwrap_or("200");
        let tax = c.settings["tax_type"].as_str().filter(|t| !t.is_empty());
        let xero_lines: Vec<Value> = lines
            .iter()
            .map(|(d, q, p, a)| {
                let mut l = json!({
                    "Description": d,
                    "Quantity": (*q * sign) as f64 / 1000.0,
                    "UnitAmount": decimal(*p, &inv.currency),
                    "LineAmount": decimal(a * sign, &inv.currency),
                    "AccountCode": account,
                });
                if let Some(t) = tax {
                    l["TaxType"] = t.into();
                }
                l
            })
            .collect();
        if credit {
            let doc = json!({ "CreditNotes": [{
                "Type": "ACCRECCREDIT", "Contact": { "ContactID": customer }, "CreditNoteNumber": number, "Date": inv.issue_date.to_string(),
                "CurrencyCode": inv.currency, "Status": "AUTHORISED", "LineAmountTypes": "Exclusive", "LineItems": xero_lines,
            }] });
            api(st, &c, reqwest::Method::POST, "CreditNotes", Some(doc)).await?["CreditNotes"][0]["CreditNoteID"]
                .as_str()
                .context("Xero returned no id")?
                .to_string()
        } else {
            let doc = json!({ "Invoices": [{
                "Type": "ACCREC", "Contact": { "ContactID": customer }, "InvoiceNumber": number, "Date": inv.issue_date.to_string(),
                "DueDate": inv.due_date.to_string(), "CurrencyCode": inv.currency, "Status": "AUTHORISED", "LineAmountTypes": "Exclusive",
                "LineItems": xero_lines,
            }] });
            api(st, &c, reqwest::Method::POST, "Invoices", Some(doc)).await?["Invoices"][0]["InvoiceID"].as_str().context("Xero returned no id")?.to_string()
        }
    };
    sqlx::query("UPDATE invoices SET external = jsonb_build_object('provider', $2::text, 'id', $3::text, 'synced_at', now()) WHERE id = $1")
        .bind(invoice)
        .bind(&c.provider)
        .bind(&id)
        .execute(&st.db)
        .await?;
    Ok(id)
}

/// Whether the accounting system has the invoice as paid.
async fn is_paid(st: &AppState, c: &Conn, external: &str) -> Result<bool> {
    if c.provider == "qbo" {
        let v = api(st, c, reqwest::Method::GET, &format!("invoice/{external}"), None).await?;
        Ok(v["Invoice"]["Balance"].as_f64().is_some_and(|b| b.abs() < 0.005))
    } else {
        let v = api(st, c, reqwest::Method::GET, &format!("Invoices/{external}"), None).await?;
        Ok(v["Invoices"][0]["Status"].as_str() == Some("PAID"))
    }
}

#[derive(Default, serde::Serialize)]
pub struct SyncResult {
    pub pushed: usize,
    pub paid: usize,
    pub errors: Vec<String>,
}

/// Pushes finalised documents that aren't there yet and pulls payment status for the rest.
pub async fn sync(st: &AppState) -> Result<SyncResult> {
    let Some(c) = connected(st).await? else { return Ok(SyncResult::default()) };
    let mut out = SyncResult::default();
    let unsynced: Vec<(Uuid, Option<String>)> = sqlx::query_as(
        "SELECT id, number FROM invoices WHERE status IN ('finalised', 'sent', 'paid') AND NOT (external ? 'id') ORDER BY finalised_at LIMIT 100",
    )
    .fetch_all(&st.db)
    .await?;
    for (id, number) in unsynced {
        match push(st, id).await {
            Ok(_) => out.pushed += 1,
            Err(e) => {
                let msg = format!("{}: {e:#}", number.unwrap_or_default());
                sqlx::query("UPDATE invoices SET external = external || jsonb_build_object('error', $2::text) WHERE id = $1")
                    .bind(id)
                    .bind(&msg)
                    .execute(&st.db)
                    .await?;
                out.errors.push(msg);
            }
        }
    }
    let open: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, external->>'id' FROM invoices WHERE status IN ('finalised', 'sent') AND kind = 'invoice' AND external->>'provider' = $1
            AND external ? 'id' LIMIT 200",
    )
    .bind(&c.provider)
    .fetch_all(&st.db)
    .await?;
    for (id, ext) in open {
        match is_paid(st, &c, &ext).await {
            Ok(true) => {
                sqlx::query("UPDATE invoices SET status = 'paid', paid_at = now(), updated_at = now() WHERE id = $1 AND status IN ('finalised', 'sent')")
                    .bind(id)
                    .execute(&st.db)
                    .await?;
                crate::auth::audit(&st.db, None, "invoice.paid", Some(("invoice", id)), json!({ "via": c.provider })).await;
                out.paid += 1;
            }
            Ok(false) => {}
            Err(e) => out.errors.push(format!("{ext}: {e:#}")),
        }
    }
    let err = (!out.errors.is_empty()).then(|| out.errors.join("; ").chars().take(1000).collect::<String>());
    sqlx::query("UPDATE accounting_connections SET last_sync_at = now(), last_error = $2 WHERE provider = $1")
        .bind(&c.provider)
        .bind(err)
        .execute(&st.db)
        .await?;
    Ok(out)
}

/// Every ten minutes while a provider is connected.
pub async fn run(st: Arc<AppState>) {
    let mut tick = tokio::time::interval(StdDuration::from_secs(600));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        match sync(&st).await {
            Ok(r) if r.pushed + r.paid > 0 => info!(pushed = r.pushed, paid = r.paid, "accounting sync"),
            Ok(_) => {}
            Err(e) => warn!("accounting sync: {e:#}"),
        }
    }
}

/// For error messages that name the provider.
pub fn label(provider: &str) -> &'static str {
    if provider == "qbo" { "QuickBooks Online" } else { "Xero" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimals_and_escaping() {
        assert_eq!(decimal(123456, "USD"), 1234.56);
        assert_eq!(decimal(-5, "EUR"), -0.05);
        assert_eq!(decimal(1500, "JPY"), 1500.0);
        assert_eq!(urlencode("Name==\"A B\""), "Name%3D%3D%22A%20B%22");
    }
}
