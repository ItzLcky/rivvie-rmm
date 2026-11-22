//! OpenID Connect relying party for technician sign-in: provider discovery, JWKS caching,
//! authorization-code exchange and ID token validation.
//!
//! The token checks are plain functions over a JWKS (see [`validate_id_token`]) so they are
//! unit-tested without a network. Signatures are verified with `ring`; only asymmetric
//! algorithms are accepted, so `none` and the HMAC family (which would let anyone who knows
//! the public key forge tokens) never verify.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use data_encoding::BASE64URL_NOPAD;
use reqwest::Url;
use ring::signature::{self, RsaPublicKeyComponents, UnparsedPublicKey, VerificationAlgorithm};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Seconds of clock skew tolerated on `exp`, `nbf` and `iat`.
pub const LEEWAY_SECS: i64 = 60;
const DISCOVERY_TTL: Duration = Duration::from_secs(3600);
const JWKS_TTL: Duration = Duration::from_secs(3600);
/// A key id nobody has seen refetches the key set, but not more often than this.
const JWKS_REFETCH_MIN: Duration = Duration::from_secs(60);
const MAX_BODY: usize = 1 << 20;

#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    #[error("malformed token: {0}")]
    Malformed(&'static str),
    #[error("unsupported signing algorithm {0}")]
    UnsupportedAlg(String),
    #[error("no matching signing key")]
    UnknownKey,
    #[error("bad signature")]
    BadSignature,
    #[error("wrong issuer")]
    Issuer,
    #[error("wrong audience")]
    Audience,
    #[error("token expired")]
    Expired,
    #[error("token not valid yet")]
    NotYetValid,
    #[error("nonce mismatch")]
    Nonce,
    #[error("tenant not allowed")]
    Tenant,
    #[error("{0}")]
    Provider(String),
}

impl OidcError {
    /// A short stable code for the audit log.
    pub fn code(&self) -> &'static str {
        match self {
            OidcError::Malformed(_) => "malformed_token",
            OidcError::UnsupportedAlg(_) => "unsupported_alg",
            OidcError::UnknownKey => "unknown_key",
            OidcError::BadSignature => "bad_signature",
            OidcError::Issuer => "bad_issuer",
            OidcError::Audience => "bad_audience",
            OidcError::Expired => "expired",
            OidcError::NotYetValid => "not_yet_valid",
            OidcError::Nonce => "bad_nonce",
            OidcError::Tenant => "tenant_not_allowed",
            OidcError::Provider(_) => "provider_error",
        }
    }
}

type Result<T, E = OidcError> = std::result::Result<T, E>;

// ---------------------------------------------------------------------------------------
// JWKS and signatures
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub kid: Option<String>,
    pub alg: Option<String>,
    #[serde(rename = "use")]
    pub use_: Option<String>,
    pub n: Option<String>,
    pub e: Option<String>,
    pub crv: Option<String>,
    pub x: Option<String>,
    pub y: Option<String>,
}

/// Parses a JWKS document, skipping keys of types we don't understand.
pub fn parse_jwks(doc: &Value) -> Vec<Jwk> {
    doc["keys"].as_array().map(|a| a.iter().filter_map(|k| serde_json::from_value(k.clone()).ok()).collect()).unwrap_or_default()
}

const ALGS: [&str; 9] = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA"];

fn kty_for(alg: &str) -> &'static str {
    match alg {
        "ES256" | "ES384" => "EC",
        "EdDSA" => "OKP",
        _ => "RSA",
    }
}

fn b64(s: &Option<String>) -> Result<Vec<u8>> {
    let s = s.as_deref().ok_or(OidcError::UnknownKey)?;
    BASE64URL_NOPAD.decode(s.trim_end_matches('=').as_bytes()).map_err(|_| OidcError::Malformed("bad key encoding"))
}

fn verify_signature(alg: &str, key: &Jwk, msg: &[u8], sig: &[u8]) -> Result<()> {
    let rsa = |p: &'static signature::RsaParameters| -> Result<()> {
        RsaPublicKeyComponents { n: b64(&key.n)?, e: b64(&key.e)? }.verify(p, msg, sig).map_err(|_| OidcError::BadSignature)
    };
    let plain = |p: &'static dyn VerificationAlgorithm, public: Vec<u8>| -> Result<()> {
        UnparsedPublicKey::new(p, public).verify(msg, sig).map_err(|_| OidcError::BadSignature)
    };
    let ec = |p: &'static dyn VerificationAlgorithm, crv: &str, len: usize| -> Result<()> {
        if key.crv.as_deref() != Some(crv) {
            return Err(OidcError::UnknownKey);
        }
        let (x, y) = (b64(&key.x)?, b64(&key.y)?);
        if x.len() != len || y.len() != len {
            return Err(OidcError::Malformed("bad EC key"));
        }
        // An uncompressed SEC1 point.
        plain(p, [&[4u8][..], &x, &y].concat())
    };
    match alg {
        "RS256" => rsa(&signature::RSA_PKCS1_2048_8192_SHA256),
        "RS384" => rsa(&signature::RSA_PKCS1_2048_8192_SHA384),
        "RS512" => rsa(&signature::RSA_PKCS1_2048_8192_SHA512),
        "PS256" => rsa(&signature::RSA_PSS_2048_8192_SHA256),
        "PS384" => rsa(&signature::RSA_PSS_2048_8192_SHA384),
        "PS512" => rsa(&signature::RSA_PSS_2048_8192_SHA512),
        "ES256" => ec(&signature::ECDSA_P256_SHA256_FIXED, "P-256", 32),
        "ES384" => ec(&signature::ECDSA_P384_SHA384_FIXED, "P-384", 48),
        "EdDSA" if key.crv.as_deref() == Some("Ed25519") => plain(&signature::ED25519, b64(&key.x)?),
        _ => Err(OidcError::UnsupportedAlg(alg.to_string())),
    }
}

/// Picks the key a token was signed with. A token naming a `kid` must find exactly that key;
/// without one, the key set must hold a single usable key for the algorithm.
fn select_key<'a>(keys: &'a [Jwk], alg: &str, kid: Option<&str>) -> Result<&'a Jwk> {
    let mut usable = keys
        .iter()
        .filter(|k| k.kty == kty_for(alg))
        .filter(|k| k.use_.as_deref().is_none_or(|u| u == "sig"))
        .filter(|k| k.alg.as_deref().is_none_or(|a| a == alg));
    match kid {
        Some(kid) => usable.find(|k| k.kid.as_deref() == Some(kid)).ok_or(OidcError::UnknownKey),
        None => {
            let first = usable.next().ok_or(OidcError::UnknownKey)?;
            if usable.next().is_some() { Err(OidcError::UnknownKey) } else { Ok(first) }
        }
    }
}

/// The signed payload's claims once the signature checks out. Nothing in the token is trusted
/// before this: the header only picks the key and algorithm, from a fixed list.
fn verified_claims(token: &str, keys: &[Jwk]) -> Result<Value> {
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(s), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err(OidcError::Malformed("not a compact JWT"));
    };
    let decode = |part: &str, what: &'static str| BASE64URL_NOPAD.decode(part.as_bytes()).map_err(|_| OidcError::Malformed(what));
    let header: Value = serde_json::from_slice(&decode(h, "header")?).map_err(|_| OidcError::Malformed("header"))?;
    let alg = header["alg"].as_str().ok_or(OidcError::Malformed("no alg"))?;
    if !ALGS.contains(&alg) {
        return Err(OidcError::UnsupportedAlg(alg.chars().take(20).collect()));
    }
    let key = select_key(keys, alg, header["kid"].as_str())?;
    verify_signature(alg, key, format!("{h}.{p}").as_bytes(), &decode(s, "signature")?)?;
    serde_json::from_slice(&decode(p, "payload")?).map_err(|_| OidcError::Malformed("payload"))
}

// ---------------------------------------------------------------------------------------
// ID token claims
// ---------------------------------------------------------------------------------------

pub struct Expect<'a> {
    /// The issuer the provider's discovery document names (Entra's multi-tenant one is a template).
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub nonce: &'a str,
    /// Unix seconds.
    pub now: i64,
    /// Entra tenant ids allowed to sign in (compared case-insensitively); empty = any the issuer admits.
    pub allowed_tenants: &'a [String],
}

const TENANT_TEMPLATE: &str = "{tenantid}";

/// Validates an ID token: signature against `keys`, then `iss`, `aud` (and `azp`), `exp`,
/// `nbf`, `iat`, `nonce` and the tenant. Returns the claims.
pub fn validate_id_token(token: &str, keys: &[Jwk], exp: &Expect) -> Result<Value> {
    let claims = verified_claims(token, keys)?;

    let tid = claims["tid"].as_str().map(str::to_lowercase);
    let iss = claims["iss"].as_str().ok_or(OidcError::Issuer)?;
    if exp.issuer.contains(TENANT_TEMPLATE) {
        // Entra's multi-tenant endpoints: the issuer carries the signing-in user's tenant, and
        // any tenant's users hold validly signed tokens, so the tenants allowed must be listed.
        let tid = tid.as_deref().filter(|t| is_tenant_id(t)).ok_or(OidcError::Tenant)?;
        if exp.allowed_tenants.is_empty() {
            return Err(OidcError::Tenant);
        }
        if iss != exp.issuer.replace(TENANT_TEMPLATE, tid) {
            return Err(OidcError::Issuer);
        }
    } else if iss != exp.issuer {
        return Err(OidcError::Issuer);
    }
    if !exp.allowed_tenants.is_empty() && !tid.as_deref().is_some_and(|t| exp.allowed_tenants.iter().any(|a| a.eq_ignore_ascii_case(t))) {
        return Err(OidcError::Tenant);
    }

    let aud_ok = match &claims["aud"] {
        Value::String(a) => a == exp.client_id,
        Value::Array(a) => a.iter().any(|a| a.as_str() == Some(exp.client_id)),
        _ => false,
    };
    if !aud_ok {
        return Err(OidcError::Audience);
    }
    if claims["aud"].as_array().is_some_and(|a| a.len() > 1) && claims["azp"].as_str() != Some(exp.client_id) {
        return Err(OidcError::Audience);
    }

    let num = |k: &str| claims[k].as_f64().map(|v| v as i64);
    if num("exp").ok_or(OidcError::Expired)? + LEEWAY_SECS < exp.now {
        return Err(OidcError::Expired);
    }
    if num("nbf").is_some_and(|n| n - LEEWAY_SECS > exp.now) || num("iat").is_some_and(|i| i - LEEWAY_SECS > exp.now) {
        return Err(OidcError::NotYetValid);
    }
    if claims["nonce"].as_str() != Some(exp.nonce) || exp.nonce.is_empty() {
        return Err(OidcError::Nonce);
    }
    if claims["sub"].as_str().is_none_or(str::is_empty) {
        return Err(OidcError::Malformed("no sub"));
    }
    Ok(claims)
}

/// A tenant id is a GUID; nothing else belongs in an issuer URL we build from a claim.
pub fn is_tenant_id(s: &str) -> bool {
    s.len() == 36 && s.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
}

/// Who the ID token says is signing in.
#[derive(Debug, Clone, PartialEq)]
pub struct Identity {
    pub subject: String,
    pub email: Option<String>,
    /// The provider vouches for `email`: `email_verified`, or a provider configured to be trusted.
    pub email_verified: bool,
    pub name: Option<String>,
    /// Group values, lowercased for comparison.
    pub groups: Vec<String>,
    pub tenant: Option<String>,
}

pub fn identity(claims: &Value, groups_claim: &str, trust_email: bool, entra: bool) -> Identity {
    let s = |k: &str| claims[k].as_str().map(str::trim).filter(|v| !v.is_empty()).map(str::to_string);
    let mut email = s("email");
    if email.is_none() && entra {
        // Entra ID often omits `email`; the sign-in name is the address for work accounts.
        email = s("preferred_username").or_else(|| s("upn")).filter(|e| e.contains('@'));
    }
    let verified_claim = match &claims["email_verified"] {
        Value::Bool(b) => *b,
        Value::String(v) => v.eq_ignore_ascii_case("true"),
        _ => false,
    };
    // Entra marks a guest (someone another tenant, or any address, was invited as) by an `idp`
    // that isn't the tenant itself; the address in `email` is whatever the inviter typed.
    let guest = entra && claims["idp"].as_str().is_some_and(|idp| claims["iss"].as_str() != Some(idp));
    Identity {
        subject: s("sub").unwrap_or_default(),
        email: email.map(|e| e.to_lowercase()),
        email_verified: verified_claim || (trust_email && !guest),
        name: s("name"),
        groups: groups(claims, groups_claim),
        tenant: s("tid"),
    }
}

/// The group values at `path` (dotted into nested objects); a single string counts as one group.
pub fn groups(claims: &Value, path: &str) -> Vec<String> {
    let mut v = claims;
    for part in path.split('.').filter(|p| !p.is_empty()) {
        v = &v[part];
    }
    match v {
        Value::String(s) => vec![s.trim().to_lowercase()],
        Value::Array(a) => a.iter().filter_map(Value::as_str).map(|s| s.trim().to_lowercase()).collect(),
        _ => Vec::new(),
    }
}

/// Entra ID sends only a pointer (`_claim_names`) instead of the groups when the user is in
/// too many to fit in a token.
pub fn groups_overage(claims: &Value) -> bool {
    claims["_claim_names"]["groups"].is_string() || claims["hasgroups"] == Value::Bool(true)
}

// ---------------------------------------------------------------------------------------
// Provider endpoints
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Discovery {
    /// As the document states it (Entra multi-tenant: with a `{tenantid}` placeholder).
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    /// The token endpoint takes the client secret in an `Authorization: Basic` header.
    pub basic_auth: bool,
}

/// Plain `http://` only for the machine itself (a provider on localhost, the tests).
pub fn url_allowed(u: &str) -> bool {
    let Ok(url) = Url::parse(u) else { return false };
    match url.scheme() {
        "https" => url.host_str().is_some(),
        "http" => matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")),
        _ => false,
    }
}

/// Whether a discovery document published under `configured` may name `discovered` as its issuer.
fn issuer_matches(configured: &str, discovered: &str) -> bool {
    discovered == configured
        || (discovered.contains(TENANT_TEMPLATE)
            && ["common", "organizations", "consumers"].iter().any(|t| discovered.replace(TENANT_TEMPLATE, t) == configured))
}

pub fn discovery_url(issuer: &str) -> String {
    format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'))
}

pub fn parse_discovery(configured: &str, doc: &Value) -> Result<Discovery> {
    let s = |k: &str| doc[k].as_str().map(str::to_string).ok_or_else(|| OidcError::Provider(format!("discovery document has no {k}")));
    let issuer = s("issuer")?;
    if !issuer_matches(configured.trim_end_matches('/'), issuer.trim_end_matches('/')) {
        return Err(OidcError::Provider(format!("the provider says its issuer is {issuer}, not {configured}")));
    }
    let d = Discovery {
        issuer,
        authorization_endpoint: s("authorization_endpoint")?,
        token_endpoint: s("token_endpoint")?,
        jwks_uri: s("jwks_uri")?,
        basic_auth: match doc["token_endpoint_auth_methods_supported"].as_array() {
            Some(m) => !m.iter().any(|m| m == "client_secret_post") && m.iter().any(|m| m == "client_secret_basic"),
            // The specification's default when the document doesn't say.
            None => true,
        },
    };
    // A provider served over https can't hand us an endpoint on this machine: the authorization
    // code and the client secret would go to whatever listens there.
    let secure = configured.starts_with("https://");
    for u in [&d.authorization_endpoint, &d.token_endpoint, &d.jwks_uri] {
        if !url_allowed(u) || (secure && !u.starts_with("https://")) {
            return Err(OidcError::Provider(format!("{u} must be an https URL")));
        }
    }
    Ok(d)
}

/// (verifier, S256 challenge) for PKCE.
pub fn pkce() -> (String, String) {
    let mut raw = [0u8; 32];
    getrandom::fill(&mut raw).expect("OS RNG unavailable");
    let verifier = BASE64URL_NOPAD.encode(&raw);
    let challenge = pkce_challenge(&verifier);
    (verifier, challenge)
}

pub fn pkce_challenge(verifier: &str) -> String {
    BASE64URL_NOPAD.encode(&Sha256::digest(verifier.as_bytes()))
}

pub struct AuthRequest<'a> {
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub scopes: &'a str,
    pub state: &'a str,
    pub nonce: &'a str,
    pub challenge: &'a str,
}

pub fn authorization_url(d: &Discovery, r: &AuthRequest) -> Result<String> {
    let mut url = Url::parse(&d.authorization_endpoint).map_err(|_| OidcError::Provider("bad authorization endpoint".into()))?;
    let scope = if r.scopes.split_whitespace().any(|s| s == "openid") { r.scopes.to_string() } else { format!("openid {}", r.scopes) };
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", r.client_id)
        .append_pair("redirect_uri", r.redirect_uri)
        .append_pair("scope", &scope)
        .append_pair("state", r.state)
        .append_pair("nonce", r.nonce)
        .append_pair("code_challenge", r.challenge)
        .append_pair("code_challenge_method", "S256");
    Ok(url.into())
}

/// Discovery documents and key sets of the configured providers, fetched on first use and kept
/// for an hour (a token signed with an unknown key refetches the keys, at most once a minute).
pub struct Cache {
    http: reqwest::Client,
    inner: Mutex<HashMap<String, Entry>>,
}

struct Entry {
    disc: Discovery,
    disc_at: Instant,
    jwks: Vec<Jwk>,
    jwks_at: Option<Instant>,
}

impl Default for Cache {
    fn default() -> Self {
        Self::new()
    }
}

impl Cache {
    pub fn new() -> Self {
        // Providers are admin-configured URLs the server fetches itself: no redirects, short timeout.
        let http = reqwest::Client::builder()
            .user_agent(concat!("rmm-server/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("building the OIDC HTTP client");
        Self { http, inner: Mutex::default() }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    async fn read_json(&self, req: reqwest::RequestBuilder) -> Result<Value> {
        let net = |e: reqwest::Error| OidcError::Provider(format!("can't reach the provider: {}", e.without_url()));
        let mut res = req.send().await.map_err(net)?;
        let status = res.status();
        let mut body = Vec::new();
        while let Some(chunk) = res.chunk().await.map_err(net)? {
            body.extend_from_slice(&chunk);
            if body.len() > MAX_BODY {
                return Err(OidcError::Provider("the provider's response is too large".into()));
            }
        }
        let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        if !status.is_success() {
            let detail = [v["error"].as_str(), v["error_description"].as_str()].into_iter().flatten().collect::<Vec<_>>().join(": ");
            let detail: String = detail.chars().take(200).collect();
            return Err(OidcError::Provider(format!("the provider answered {status}{}{detail}", if detail.is_empty() { "" } else { ": " })));
        }
        Ok(v)
    }

    async fn get_json(&self, url: &str) -> Result<Value> {
        if !url_allowed(url) {
            return Err(OidcError::Provider(format!("{url} must be an https URL")));
        }
        self.read_json(self.http.get(url)).await
    }

    /// The provider's endpoints, fetched when missing or older than an hour (`fresh` forces it).
    pub async fn discovery(&self, issuer: &str, fresh: bool) -> Result<Discovery> {
        if !fresh && let Some(e) = self.lock().get(issuer).filter(|e| e.disc_at.elapsed() < DISCOVERY_TTL) {
            return Ok(e.disc.clone());
        }
        let doc = self.get_json(&discovery_url(issuer)).await?;
        let disc = parse_discovery(issuer, &doc)?;
        let mut map = self.lock();
        match map.get_mut(issuer) {
            Some(e) => {
                e.disc = disc.clone();
                e.disc_at = Instant::now();
            }
            None => {
                map.insert(issuer.to_string(), Entry { disc: disc.clone(), disc_at: Instant::now(), jwks: Vec::new(), jwks_at: None });
            }
        }
        Ok(disc)
    }

    /// The signing keys; refetched when older than an hour, or when `unknown_kid` says a token
    /// used one we don't have (rate-limited).
    pub async fn keys(&self, issuer: &str, disc: &Discovery, unknown_kid: bool) -> Result<Vec<Jwk>> {
        {
            let map = self.lock();
            if let Some(e) = map.get(issuer)
                && let Some(at) = e.jwks_at
            {
                let stale = at.elapsed() >= JWKS_TTL || (unknown_kid && at.elapsed() >= JWKS_REFETCH_MIN);
                if !stale {
                    return Ok(e.jwks.clone());
                }
            }
        }
        let keys = parse_jwks(&self.get_json(&disc.jwks_uri).await?);
        if keys.is_empty() {
            return Err(OidcError::Provider("the provider published no signing keys".into()));
        }
        if let Some(e) = self.lock().get_mut(issuer) {
            e.jwks = keys.clone();
            e.jwks_at = Some(Instant::now());
        }
        Ok(keys)
    }

    /// Exchanges an authorization code for the ID token.
    pub async fn exchange_code(
        &self,
        disc: &Discovery,
        client_id: &str,
        client_secret: &str,
        redirect_uri: &str,
        code: &str,
        verifier: &str,
    ) -> Result<String> {
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", verifier),
        ];
        let mut req = self.http.post(&disc.token_endpoint);
        if disc.basic_auth {
            req = req.basic_auth(client_id, Some(client_secret));
        } else {
            form.push(("client_id", client_id));
            form.push(("client_secret", client_secret));
        }
        let v = self.read_json(req.form(&form)).await?;
        v["id_token"].as_str().map(str::to_string).ok_or_else(|| OidcError::Provider("the token response has no id_token".into()))
    }

    /// Validates `token`, refetching the keys once if it names one we haven't seen.
    pub async fn validate(&self, issuer: &str, disc: &Discovery, token: &str, exp: &Expect<'_>) -> Result<Value> {
        let keys = self.keys(issuer, disc, false).await?;
        match validate_id_token(token, &keys, exp) {
            Err(OidcError::UnknownKey) => {
                let keys = self.keys(issuer, disc, true).await?;
                validate_id_token(token, &keys, exp)
            }
            r => r,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, RsaKeyPair};
    use serde_json::json;

    const NOW: i64 = 1_800_000_000;
    const CLIENT: &str = "rmm-client";
    const ISSUER: &str = "https://idp.example.com";

    fn enc(v: &Value) -> String {
        BASE64URL_NOPAD.encode(v.to_string().as_bytes())
    }

    /// (n, e) of a DER `RSAPublicKey ::= SEQUENCE { n INTEGER, e INTEGER }`, without leading zeros.
    fn rsa_components(der: &[u8]) -> (Vec<u8>, Vec<u8>) {
        fn item(b: &[u8]) -> (u8, &[u8], &[u8]) {
            let len_bytes = if b[1] & 0x80 == 0 { 0 } else { (b[1] & 0x7f) as usize };
            let (len, head) = if len_bytes == 0 { (b[1] as usize, 2) } else { (b[2..2 + len_bytes].iter().fold(0usize, |a, v| a << 8 | *v as usize), 2 + len_bytes) };
            (b[0], &b[head..head + len], &b[head + len..])
        }
        let (tag, body, _) = item(der);
        assert_eq!(tag, 0x30);
        let (_, n, rest) = item(body);
        let (_, e, _) = item(rest);
        let strip = |v: &[u8]| v.iter().skip_while(|b| **b == 0).copied().collect::<Vec<u8>>();
        (strip(n), strip(e))
    }

    /// Test signing keys and the JWKS that publishes them.
    pub struct Keys {
        rsa: RsaKeyPair,
        ec: EcdsaKeyPair,
        pub jwks: Vec<Jwk>,
    }

    pub fn keys() -> Keys {
        let pk8 = data_encoding::BASE64.decode(include_str!("../tests/fixtures/rsa2048.pk8.b64").trim().as_bytes()).unwrap();
        let rsa = RsaKeyPair::from_pkcs8(&pk8).unwrap();
        let rng = SystemRandom::new();
        let ec_pk8 = EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let ec = EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, ec_pk8.as_ref(), &rng).unwrap();
        let point = ec.public_key().as_ref().to_vec();
        let (n, e) = rsa_components(rsa.public().as_ref());
        let jwks = parse_jwks(&json!({ "keys": [
            { "kty": "RSA", "kid": "rsa1", "use": "sig", "alg": "RS256",
              "n": BASE64URL_NOPAD.encode(&n), "e": BASE64URL_NOPAD.encode(&e) },
            { "kty": "EC", "kid": "ec1", "crv": "P-256",
              "x": BASE64URL_NOPAD.encode(&point[1..33]), "y": BASE64URL_NOPAD.encode(&point[33..]) },
        ]}));
        assert_eq!(jwks.len(), 2);
        Keys { rsa, ec, jwks }
    }

    impl Keys {
        pub fn sign_rs256(&self, kid: &str, claims: &Value) -> String {
            let input = format!("{}.{}", enc(&json!({ "alg": "RS256", "kid": kid })), enc(claims));
            let mut sig = vec![0u8; self.rsa.public().modulus_len()];
            self.rsa.sign(&signature::RSA_PKCS1_SHA256, &SystemRandom::new(), input.as_bytes(), &mut sig).unwrap();
            format!("{input}.{}", BASE64URL_NOPAD.encode(&sig))
        }

        pub fn sign_es256(&self, kid: &str, claims: &Value) -> String {
            let input = format!("{}.{}", enc(&json!({ "alg": "ES256", "kid": kid })), enc(claims));
            let sig = self.ec.sign(&SystemRandom::new(), input.as_bytes()).unwrap();
            format!("{input}.{}", BASE64URL_NOPAD.encode(sig.as_ref()))
        }
    }

    fn claims() -> Value {
        json!({ "iss": ISSUER, "aud": CLIENT, "sub": "u-1", "exp": NOW + 300, "iat": NOW - 5, "nonce": "n-1", "email": "Tech@Example.com", "email_verified": true })
    }

    fn expect<'a>() -> Expect<'a> {
        Expect { issuer: ISSUER, client_id: CLIENT, nonce: "n-1", now: NOW, allowed_tenants: &[] }
    }

    fn check(token: &str) -> Result<Value> {
        validate_id_token(token, &keys().jwks, &expect())
    }

    #[test]
    fn valid_tokens_verify_with_rsa_and_ec() {
        let k = keys();
        for t in [k.sign_rs256("rsa1", &claims()), k.sign_es256("ec1", &claims())] {
            let c = validate_id_token(&t, &k.jwks, &expect()).unwrap();
            assert_eq!(c["sub"], "u-1");
        }
    }

    #[test]
    fn rejects_tampered_and_unsigned_tokens() {
        let k = keys();
        let good = k.sign_rs256("rsa1", &claims());
        // Another payload under the same signature.
        let mut parts: Vec<&str> = good.split('.').collect();
        let forged = enc(&json!({ "iss": ISSUER, "aud": CLIENT, "sub": "admin", "exp": NOW + 300, "nonce": "n-1" }));
        parts[1] = &forged;
        assert!(matches!(check(&parts.join(".")), Err(OidcError::BadSignature)));
        // alg none, and an HMAC token keyed with the public modulus (the classic confusion attack).
        let none = format!("{}.{}.", enc(&json!({ "alg": "none" })), enc(&claims()));
        assert!(matches!(check(&none), Err(OidcError::UnsupportedAlg(_))));
        let hs = format!("{}.{}.AAAA", enc(&json!({ "alg": "HS256", "kid": "rsa1" })), enc(&claims()));
        assert!(matches!(check(&hs), Err(OidcError::UnsupportedAlg(_))));
        // An RS256 token can't be checked against the EC key, nor under a kid we don't have.
        assert!(matches!(check(&k.sign_rs256("ec1", &claims())), Err(OidcError::UnknownKey)));
        assert!(matches!(check(&k.sign_rs256("other", &claims())), Err(OidcError::UnknownKey)));
        assert!(matches!(check("a.b"), Err(OidcError::Malformed(_))));
        assert!(matches!(check("a.b.c.d"), Err(OidcError::Malformed(_))));
        // A signature made by a different key under the right kid.
        let rng = SystemRandom::new();
        let other = EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let other = EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, other.as_ref(), &rng).unwrap();
        let input = format!("{}.{}", enc(&json!({ "alg": "ES256", "kid": "ec1" })), enc(&claims()));
        let sig = other.sign(&rng, input.as_bytes()).unwrap();
        assert!(matches!(check(&format!("{input}.{}", BASE64URL_NOPAD.encode(sig.as_ref()))), Err(OidcError::BadSignature)));
    }

    #[test]
    fn rejects_wrong_claims() {
        let k = keys();
        let with = |f: &dyn Fn(&mut Value)| {
            let mut c = claims();
            f(&mut c);
            check(&k.sign_rs256("rsa1", &c))
        };
        assert!(matches!(with(&|c| c["iss"] = json!("https://evil.example.com")), Err(OidcError::Issuer)));
        assert!(matches!(with(&|c| c["aud"] = json!("another-client")), Err(OidcError::Audience)));
        assert!(matches!(with(&|c| c["aud"] = json!([CLIENT, "other"])), Err(OidcError::Audience)), "several audiences need azp");
        assert!(with(&|c| { c["aud"] = json!([CLIENT, "other"]); c["azp"] = json!(CLIENT) }).is_ok());
        assert!(matches!(with(&|c| c["exp"] = json!(NOW - 61)), Err(OidcError::Expired)));
        assert!(with(&|c| c["exp"] = json!(NOW - 30)).is_ok(), "within the leeway");
        assert!(matches!(with(&|c| { c.as_object_mut().unwrap().remove("exp"); }), Err(OidcError::Expired)));
        assert!(matches!(with(&|c| c["nbf"] = json!(NOW + 600)), Err(OidcError::NotYetValid)));
        assert!(matches!(with(&|c| c["iat"] = json!(NOW + 600)), Err(OidcError::NotYetValid)));
        assert!(matches!(with(&|c| c["nonce"] = json!("replayed")), Err(OidcError::Nonce)));
        assert!(matches!(with(&|c| { c.as_object_mut().unwrap().remove("nonce"); }), Err(OidcError::Nonce)));
        assert!(matches!(with(&|c| c["sub"] = json!("")), Err(OidcError::Malformed(_))));
    }

    #[test]
    fn entra_multi_tenant_issuer_and_tenant_allow_list() {
        let k = keys();
        let tenant = "11111111-2222-3333-4444-555555555555";
        let template = "https://login.microsoftonline.com/{tenantid}/v2.0";
        let c = json!({ "iss": format!("https://login.microsoftonline.com/{tenant}/v2.0"), "tid": tenant, "aud": CLIENT, "sub": "u", "exp": NOW + 60, "nonce": "n-1" });
        let t = k.sign_rs256("rsa1", &c);
        let allowed = vec![tenant.to_uppercase()];
        let ok = |issuer: &str, allowed: &[String], token: &str| {
            validate_id_token(token, &k.jwks, &Expect { issuer, client_id: CLIENT, nonce: "n-1", now: NOW, allowed_tenants: allowed })
        };
        assert!(ok(template, &allowed, &t).is_ok());
        // A template without an allow list would admit every Entra tenant.
        assert!(matches!(ok(template, &[], &t), Err(OidcError::Tenant)));
        assert!(matches!(ok(template, &["99999999-2222-3333-4444-555555555555".into()], &t), Err(OidcError::Tenant)));
        // The issuer must match the tenant the token says it is for.
        let mut bad = c.clone();
        bad["iss"] = json!("https://login.microsoftonline.com/99999999-2222-3333-4444-555555555555/v2.0");
        assert!(matches!(ok(template, &allowed, &k.sign_rs256("rsa1", &bad)), Err(OidcError::Issuer)));
        // A tid that isn't a GUID never reaches the issuer comparison.
        let mut weird = c.clone();
        weird["tid"] = json!("../evil");
        assert!(matches!(ok(template, &["../evil".into()], &k.sign_rs256("rsa1", &weird)), Err(OidcError::Tenant)));
        // A single-tenant issuer plus an allow list.
        let single = format!("https://login.microsoftonline.com/{tenant}/v2.0");
        assert!(ok(&single, &[], &t).is_ok());
        assert!(matches!(ok(&single, &["99999999-2222-3333-4444-555555555555".into()], &t), Err(OidcError::Tenant)));
    }

    #[test]
    fn identity_and_groups() {
        let c = json!({ "sub": "s", "email": "Tech@Example.com", "email_verified": "true", "name": " Tech ", "groups": ["Admins", "g-2"], "tid": "t" });
        let id = identity(&c, "groups", false, false);
        assert_eq!(id.email.as_deref(), Some("tech@example.com"));
        assert!(id.email_verified && id.groups == ["admins", "g-2"] && id.name.as_deref() == Some("Tech"));
        // Unverified unless the provider is trusted.
        let c2 = json!({ "sub": "s", "email": "a@b.c" });
        assert!(!identity(&c2, "groups", false, false).email_verified);
        assert!(identity(&c2, "groups", true, false).email_verified);
        // Entra falls back to the sign-in name.
        // An Entra guest's address is whatever the inviter typed: not believed.
        let guest = json!({ "sub": "s", "iss": "https://i/", "idp": "live.com", "email": "a@b.c" });
        assert!(!identity(&guest, "groups", true, true).email_verified);
        let member = json!({ "sub": "s", "iss": "https://i/", "email": "a@b.c" });
        assert!(identity(&member, "groups", true, true).email_verified);
        let c3 = json!({ "sub": "s", "preferred_username": "A@B.c" });
        assert_eq!(identity(&c3, "groups", true, true).email.as_deref(), Some("a@b.c"));
        assert_eq!(identity(&c3, "groups", true, false).email, None);
        // Nested claim paths and single-string claims.
        assert_eq!(groups(&json!({ "realm": { "roles": ["x"] } }), "realm.roles"), ["x"]);
        assert_eq!(groups(&json!({ "roles": "Solo" }), "roles"), ["solo"]);
        assert!(groups(&json!({}), "groups").is_empty());
        assert!(groups_overage(&json!({ "_claim_names": { "groups": "src1" } })));
    }

    #[test]
    fn discovery_documents() {
        let doc = |issuer: &str| json!({ "issuer": issuer, "authorization_endpoint": "https://i/auth", "token_endpoint": "https://i/token",
            "jwks_uri": "https://i/keys", "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"] });
        let d = parse_discovery("https://i", &doc("https://i")).unwrap();
        assert!(!d.basic_auth);
        assert!(parse_discovery("https://i", &doc("https://other")).is_err());
        // Entra's `common` endpoint names a template as its issuer.
        let t = "https://login.microsoftonline.com/{tenantid}/v2.0";
        assert!(parse_discovery("https://login.microsoftonline.com/common/v2.0", &doc(t)).is_ok());
        assert!(parse_discovery("https://login.microsoftonline.com/organizations/v2.0", &doc(t)).is_ok());
        assert!(parse_discovery("https://evil.example.com/v2.0", &doc(t)).is_err());
        let mut plain = doc("https://i");
        plain["token_endpoint"] = json!("http://i/token");
        assert!(parse_discovery("https://i", &plain).is_err(), "no plain http off the machine");
        let mut loopback = doc("https://i");
        loopback["token_endpoint"] = json!("http://127.0.0.1:9/token");
        assert!(parse_discovery("https://i", &loopback).is_err(), "an https provider can't point us at localhost");
        let mut local = doc("http://127.0.0.1:9");
        local["authorization_endpoint"] = json!("http://127.0.0.1:9/a");
        local["token_endpoint"] = json!("http://localhost:9/t");
        local["jwks_uri"] = json!("http://127.0.0.1:9/k");
        assert!(parse_discovery("http://127.0.0.1:9", &local).is_ok());
        assert!(!url_allowed("file:///etc/passwd") && !url_allowed("ftp://x/"));
        assert_eq!(discovery_url("https://i/"), "https://i/.well-known/openid-configuration");
    }

    #[test]
    fn pkce_challenge_is_s256_of_the_verifier() {
        // RFC 7636, appendix B.
        assert_eq!(pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        let (v, c) = pkce();
        assert_eq!(c, pkce_challenge(&v));
        assert!(v.len() >= 43);
    }

    #[test]
    fn authorization_url_carries_pkce_state_and_nonce() {
        let d = Discovery {
            issuer: "https://i".into(),
            authorization_endpoint: "https://i/auth?x=1".into(),
            token_endpoint: "https://i/token".into(),
            jwks_uri: "https://i/keys".into(),
            basic_auth: false,
        };
        let u = authorization_url(&d, &AuthRequest { client_id: "c", redirect_uri: "https://rmm/cb", scopes: "email", state: "S", nonce: "N", challenge: "C" }).unwrap();
        let url = Url::parse(&u).unwrap();
        let q: HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(q["x"], "1");
        assert_eq!(q["scope"], "openid email", "openid is always requested");
        assert_eq!((q["state"].as_str(), q["nonce"].as_str(), q["code_challenge"].as_str(), q["code_challenge_method"].as_str()), ("S", "N", "C", "S256"));
        assert_eq!(q["redirect_uri"], "https://rmm/cb");
    }
}
