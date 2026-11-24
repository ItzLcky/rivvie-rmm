//! Web Push to the dashboard installed as an app (docs/design/pwa.md).
//!
//! Messages are encrypted for the browser (RFC 8291, `aes128gcm` content coding) and the
//! request is signed with the server's VAPID key (RFC 8292, ES256), all with `ring`: P-256
//! ECDH, HKDF-SHA256, AES-128-GCM and ECDSA. The push service only ever sees ciphertext.
//!
//! A subscription's endpoint must be on a known push service ([`endpoint_allowed`]), or a user
//! could aim the server at any URL; `RMM_PUSH_ALLOW_HOSTS` (comma-separated host names, http
//! allowed) adds hosts for tests. A 404 or 410 from the service deletes the subscription.
//!
//! What is sent: alerts to people who can see the client and opted in ([`alert_opened`]),
//! pages (the `push` contact method, [`send_to_user`]), and the staff ticket mails
//! ([`ticket_event`]). Alerts and tickets go through `push_outbox`, so the alert engine never
//! waits on a push service; pages are sent by the on-call worker directly.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use data_encoding::BASE64URL_NOPAD;
use ring::rand::{SecureRandom, SystemRandom};
use ring::{aead, agreement, hkdf, signature};
use serde_json::{Value, json};
use tracing::{debug, warn};
use uuid::Uuid;

use crate::state::AppState;

/// Notification preferences: (event, label, push by default, email by default).
pub const EVENTS: &[(&str, &str, bool)] = &[
    ("page", "I'm paged", true),
    ("alert_critical", "Critical alerts", true),
    ("alert_warning", "Warnings", false),
    ("ticket_assigned", "A ticket is assigned to me", true),
    ("ticket_reply", "A client replies on my ticket", false),
    ("sla_warning", "SLA warnings and breaches on my tickets", false),
];

/// Push on by default for this event. Email is on by default for every event.
pub fn push_default(event: &str) -> bool {
    EVENTS.iter().find(|e| e.0 == event).is_some_and(|e| e.2)
}

static WAKE: tokio::sync::Notify = tokio::sync::Notify::const_new();

// ---------------------------------------------------------------------------
// RFC 8291: message encryption
// ---------------------------------------------------------------------------

/// Records are one per message here: 4096 bytes is the conventional size.
const RECORD_SIZE: u32 = 4096;
/// Plaintext room in one record: record size less the tag (16) and the delimiter (1).
pub const MAX_PAYLOAD: usize = RECORD_SIZE as usize - 17;

struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

fn hkdf_expand(prk: &hkdf::Prk, info: &[&[u8]], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    prk.expand(info, Len(len)).and_then(|okm| okm.fill(&mut out)).expect("HKDF output length is valid");
    out
}

/// The content-encryption key and nonce for one message, from the ECDH shared secret
/// (RFC 8291 §3.3-3.4 and RFC 8188 §2.2).
pub fn derive(ecdh_secret: &[u8], auth: &[u8], ua_public: &[u8], as_public: &[u8], salt: &[u8]) -> ([u8; 16], [u8; 12]) {
    let prk_key = hkdf::Salt::new(hkdf::HKDF_SHA256, auth).extract(ecdh_secret);
    let ikm = hkdf_expand(&prk_key, &[b"WebPush: info\0", ua_public, as_public], 32);
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(&ikm);
    let cek: [u8; 16] = hkdf_expand(&prk, &[b"Content-Encoding: aes128gcm\0"], 16).try_into().expect("16 bytes");
    let nonce: [u8; 12] = hkdf_expand(&prk, &[b"Content-Encoding: nonce\0"], 12).try_into().expect("12 bytes");
    (cek, nonce)
}

/// The `aes128gcm` body: header (salt, record size, key id = the sender's public key) and a
/// single record of `plaintext` with the last-record delimiter.
pub fn seal_record(cek: &[u8; 16], nonce: &[u8; 12], salt: &[u8; 16], as_public: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, cek).expect("16-byte key"));
    let mut record = plaintext.to_vec();
    record.push(2);
    key.seal_in_place_append_tag(aead::Nonce::assume_unique_for_key(*nonce), aead::Aad::empty(), &mut record).expect("record fits");
    let mut out = Vec::with_capacity(21 + as_public.len() + record.len());
    out.extend_from_slice(salt);
    out.extend_from_slice(&RECORD_SIZE.to_be_bytes());
    out.push(as_public.len() as u8);
    out.extend_from_slice(as_public);
    out.extend_from_slice(&record);
    out
}

/// Encrypts `plaintext` for a subscription (`p256dh`, `auth`) with a fresh key pair and salt.
pub fn encrypt(ua_public: &[u8], auth: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    if plaintext.len() > MAX_PAYLOAD {
        return Err("the notification is too large".into());
    }
    let rng = SystemRandom::new();
    let private = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).map_err(|_| "key generation failed")?;
    let as_public = private.compute_public_key().map_err(|_| "key generation failed")?.as_ref().to_vec();
    let peer = agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, ua_public);
    let secret = agreement::agree_ephemeral(private, &peer, |s| s.to_vec()).map_err(|_| "the subscription's key is not a P-256 point")?;
    let mut salt = [0u8; 16];
    rng.fill(&mut salt).map_err(|_| "no randomness")?;
    let (cek, nonce) = derive(&secret, auth, ua_public, &as_public, &salt);
    Ok(seal_record(&cek, &nonce, &salt, &as_public, plaintext))
}

// ---------------------------------------------------------------------------
// RFC 8292: VAPID
// ---------------------------------------------------------------------------

/// The server's VAPID key pair: the uncompressed public point and the PKCS#8 private key.
pub struct Vapid {
    pub public: Vec<u8>,
    pkcs8: Vec<u8>,
}

impl Vapid {
    pub fn generate() -> Result<Vapid, String> {
        let rng = SystemRandom::new();
        let doc = signature::EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng).map_err(|_| "key generation failed")?;
        let pkcs8 = doc.as_ref().to_vec();
        let pair = signature::EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8, &rng).map_err(|_| "bad key")?;
        Ok(Vapid { public: signature::KeyPair::public_key(&pair).as_ref().to_vec(), pkcs8 })
    }

    pub fn from_parts(public: Vec<u8>, pkcs8: Vec<u8>) -> Vapid {
        Vapid { public, pkcs8 }
    }

    /// A signed JWT for the push service at `audience` (its origin), valid until `exp`.
    pub fn jwt(&self, audience: &str, subject: &str, exp: i64) -> Result<String, String> {
        let rng = SystemRandom::new();
        let pair = signature::EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &self.pkcs8, &rng)
            .map_err(|_| "the VAPID key can't be read")?;
        let head = BASE64URL_NOPAD.encode(br#"{"typ":"JWT","alg":"ES256"}"#);
        let claims = BASE64URL_NOPAD.encode(json!({ "aud": audience, "exp": exp, "sub": subject }).to_string().as_bytes());
        let input = format!("{head}.{claims}");
        let sig = pair.sign(&rng, input.as_bytes()).map_err(|_| "signing failed")?;
        Ok(format!("{input}.{}", BASE64URL_NOPAD.encode(sig.as_ref())))
    }

    /// The `Authorization` header value for a request to `endpoint`.
    pub fn authorization(&self, endpoint: &reqwest::Url, subject: &str) -> Result<String, String> {
        let exp = chrono::Utc::now().timestamp() + 12 * 3600;
        let jwt = self.jwt(&endpoint.origin().ascii_serialization(), subject, exp)?;
        Ok(format!("vapid t={jwt}, k={}", BASE64URL_NOPAD.encode(&self.public)))
    }
}

/// The VAPID key pair, made on first use and kept in `push_keys`.
pub async fn keys(st: &AppState) -> Result<Vapid, String> {
    let load = || async {
        sqlx::query_as::<_, (Vec<u8>, Vec<u8>, bool)>("SELECT public, private, private_sealed FROM push_keys")
            .fetch_optional(&st.db)
            .await
            .map_err(|e| e.to_string())
    };
    let row = match load().await? {
        Some(r) => r,
        None => {
            let v = Vapid::generate()?;
            let (private, sealed) = crate::crypto::store(st.cfg.data_key.as_ref(), &v.pkcs8);
            sqlx::query("INSERT INTO push_keys (id, public, private, private_sealed) VALUES (true, $1, $2, $3) ON CONFLICT DO NOTHING")
                .bind(&v.public)
                .bind(private)
                .bind(sealed)
                .execute(&st.db)
                .await
                .map_err(|e| e.to_string())?;
            load().await?.ok_or("the push key wasn't stored")?
        }
    };
    let pkcs8 = crate::crypto::load(st.cfg.data_key.as_ref(), &row.1, row.2).ok_or("the push key can't be read: RMM_DATA_KEY is missing or changed")?;
    Ok(Vapid::from_parts(row.0, pkcs8))
}

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

fn extra_hosts() -> &'static [String] {
    static V: OnceLock<Vec<String>> = OnceLock::new();
    V.get_or_init(|| {
        std::env::var("RMM_PUSH_ALLOW_HOSTS")
            .unwrap_or_default()
            .split(',')
            .map(|h| h.trim().to_ascii_lowercase())
            .filter(|h| !h.is_empty())
            .collect()
    })
}

/// Whether the server may post to this endpoint: https on a known push service, or (any
/// scheme) a host in `extra`.
pub fn endpoint_allowed(endpoint: &str, extra: &[String]) -> Result<reqwest::Url, String> {
    let url = reqwest::Url::parse(endpoint).map_err(|_| "the subscription endpoint is not a URL".to_string())?;
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    if extra.iter().any(|h| *h == host) && matches!(url.scheme(), "http" | "https") {
        return Ok(url);
    }
    let known = host == "fcm.googleapis.com"
        || [".push.services.mozilla.com", ".notify.windows.com", ".push.apple.com"].iter().any(|s| host.ends_with(s));
    if url.scheme() != "https" || !known || url.port().is_some_and(|p| p != 443) {
        return Err(format!("{host} is not a known push service"));
    }
    Ok(url)
}

#[derive(sqlx::FromRow)]
struct Sub {
    id: Uuid,
    endpoint: String,
    p256dh: Vec<u8>,
    auth: Vec<u8>,
}

fn subject(st: &AppState) -> String {
    if st.cfg.public_url.starts_with("https://") {
        st.cfg.public_url.clone()
    } else {
        "mailto:rmm@localhost".into()
    }
}

/// Sends `payload` to one subscription. Ok(true): delivered; Ok(false): gone (deleted).
async fn send_one(st: &AppState, vapid: &Vapid, s: &Sub, body: &[u8], urgent: bool) -> Result<bool, String> {
    let url = endpoint_allowed(&s.endpoint, extra_hosts())?;
    let sealed = encrypt(&s.p256dh, &s.auth, body)?;
    let res = st
        .http
        .post(url.clone())
        .header("authorization", vapid.authorization(&url, &subject(st))?)
        .header("content-encoding", "aes128gcm")
        .header("content-type", "application/octet-stream")
        .header("ttl", if urgent { "3600" } else { "86400" })
        .header("urgency", if urgent { "high" } else { "normal" })
        .body(sealed)
        .timeout(Duration::from_secs(20))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    let status = res.status();
    if status.is_success() {
        sqlx::query("UPDATE push_subscriptions SET last_ok_at = now(), failures = 0 WHERE id = $1").bind(s.id).execute(&st.db).await.map_err(|e| e.to_string())?;
        return Ok(true);
    }
    if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::GONE {
        sqlx::query("DELETE FROM push_subscriptions WHERE id = $1").bind(s.id).execute(&st.db).await.map_err(|e| e.to_string())?;
        debug!(subscription = %s.id, %status, "push subscription expired");
        return Ok(false);
    }
    sqlx::query("UPDATE push_subscriptions SET failures = failures + 1 WHERE id = $1").bind(s.id).execute(&st.db).await.map_err(|e| e.to_string())?;
    let text = res.text().await.unwrap_or_default();
    Err(format!("HTTP {status}: {}", text.chars().take(200).collect::<String>()))
}

/// Sends to every device of the user. Returns how many accepted it.
pub async fn send_to_user(st: &AppState, user: Uuid, payload: &Value, urgent: bool) -> Result<usize, String> {
    let subs: Vec<Sub> = sqlx::query_as(
        "SELECT s.id, s.endpoint, s.p256dh, s.auth FROM push_subscriptions s JOIN users u ON u.id = s.user_id WHERE s.user_id = $1 AND NOT u.disabled",
    )
    .bind(user)
    .fetch_all(&st.db)
    .await
    .map_err(|e| e.to_string())?;
    if subs.is_empty() {
        return Ok(0);
    }
    let vapid = keys(st).await?;
    let body = serde_json::to_vec(payload).map_err(|e| e.to_string())?;
    let mut ok = 0;
    for s in &subs {
        match send_one(st, &vapid, s, &body, urgent).await {
            Ok(true) => ok += 1,
            Ok(false) => {}
            Err(e) => warn!(subscription = %s.id, "push failed: {e}"),
        }
    }
    Ok(ok)
}

// ---------------------------------------------------------------------------
// What is sent
// ---------------------------------------------------------------------------

async fn queue(st: &AppState, user: Uuid, payload: Value, urgent: bool) {
    let res = sqlx::query("INSERT INTO push_outbox (user_id, payload, urgent) VALUES ($1, $2, $3)").bind(user).bind(payload).bind(urgent).execute(&st.db).await;
    match res {
        Ok(_) => WAKE.notify_one(),
        Err(e) => warn!(%user, "queueing a push: {e}"),
    }
}

/// An alert opened: a push to everyone who can see its client, has a device and wants this
/// severity.
pub async fn alert_opened(st: &AppState, alert_id: Uuid) {
    let res: sqlx::Result<()> = async {
        let row: Option<(String, String, String, Uuid, String)> = sqlx::query_as(
            "SELECT al.severity, al.title, a.hostname, s.client_id, c.name FROM alerts al JOIN agents a ON a.id = al.agent_id
               JOIN sites s ON s.id = a.site_id JOIN clients c ON c.id = s.client_id WHERE al.id = $1",
        )
        .bind(alert_id)
        .fetch_optional(&st.db)
        .await?;
        let Some((severity, title, host, client_id, client)) = row else { return Ok(()) };
        let event = match severity.as_str() {
            "critical" => "alert_critical",
            "warning" => "alert_warning",
            _ => return Ok(()),
        };
        let users: Vec<(Uuid, bool)> = sqlx::query_as(
            "SELECT u.id, u.push_hide_details FROM users u
              WHERE NOT u.disabled AND EXISTS (SELECT 1 FROM push_subscriptions s WHERE s.user_id = u.id)
                AND (u.role = 'admin' OR u.all_clients OR EXISTS (SELECT 1 FROM user_clients uc WHERE uc.user_id = u.id AND uc.client_id = $1))
                AND coalesce((SELECT p.push FROM user_notification_prefs p WHERE p.user_id = u.id AND p.event = $2), $3)",
        )
        .bind(client_id)
        .bind(event)
        .bind(push_default(event))
        .fetch_all(&st.db)
        .await?;
        for (user, hide) in users {
            let (t, b) = if hide {
                (format!("New {severity} alert"), "Open the app to see it.".to_string())
            } else {
                (format!("{}: {title}", severity.to_uppercase()), format!("{host} · {client}"))
            };
            let payload = json!({ "title": t, "body": b, "url": format!("/alerts/{alert_id}"), "alert_id": alert_id, "tag": format!("alert-{alert_id}"), "kind": "alert" });
            queue(st, user, payload, severity == "critical").await;
        }
        Ok(())
    }
    .await;
    if let Err(e) = res {
        warn!(%alert_id, "alert push: {e}");
    }
}

/// A staff ticket mail point (`email.rs`): a push to that person when they want one. Returns
/// whether they still want the email.
pub async fn ticket_event(st: &AppState, user: Uuid, event: &str, ticket_id: Uuid, what: &str) -> bool {
    let row: Option<(Option<bool>, Option<bool>, bool, bool, i64, String)> = match sqlx::query_as(
        "SELECT p.push, p.email, u.push_hide_details, EXISTS (SELECT 1 FROM push_subscriptions s WHERE s.user_id = u.id), t.number, t.subject
           FROM users u CROSS JOIN tickets t LEFT JOIN user_notification_prefs p ON p.user_id = u.id AND p.event = $3
          WHERE u.id = $1 AND t.id = $2 AND NOT u.disabled",
    )
    .bind(user)
    .bind(ticket_id)
    .bind(event)
    .fetch_optional(&st.db)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!(%ticket_id, "ticket push: {e}");
            return true;
        }
    };
    let Some((push, email, hide, has_device, number, subject)) = row else { return true };
    if push.unwrap_or(push_default(event)) && has_device {
        let (t, b) = if hide { ("Ticket update".to_string(), "Open the app to see it.".to_string()) } else { (format!("T-{number} {what}"), subject) };
        queue(st, user, json!({ "title": t, "body": b, "url": format!("/tickets/{ticket_id}"), "tag": format!("ticket-{ticket_id}"), "kind": "ticket" }), false).await;
    }
    email.unwrap_or(true)
}

/// Drains `push_outbox`.
pub async fn run(st: Arc<AppState>) {
    loop {
        match drain(&st).await {
            Ok(n) if n >= 50 => continue,
            Ok(_) => {}
            Err(e) => warn!("push worker: {e}"),
        }
        tokio::select! {
            _ = WAKE.notified() => {}
            _ = tokio::time::sleep(Duration::from_secs(30)) => {}
        }
    }
}

async fn drain(st: &AppState) -> anyhow::Result<usize> {
    let mut tx = st.db.begin().await?;
    let rows: Vec<(i64, Uuid, Value, bool, i32)> = sqlx::query_as(
        "SELECT id, user_id, payload, urgent, attempts FROM push_outbox ORDER BY id LIMIT 50 FOR UPDATE SKIP LOCKED",
    )
    .fetch_all(&mut *tx)
    .await?;
    let n = rows.len();
    for (id, user, payload, urgent, attempts) in rows {
        match send_to_user(st, user, &payload, urgent).await {
            Err(e) if attempts < 2 => {
                warn!(push = id, "push failed, will retry: {e}");
                sqlx::query("UPDATE push_outbox SET attempts = attempts + 1 WHERE id = $1").bind(id).execute(&mut *tx).await?;
            }
            _ => {
                sqlx::query("DELETE FROM push_outbox WHERE id = $1").bind(id).execute(&mut *tx).await?;
            }
        }
    }
    // Rows that keep failing (a broken key) don't pile up.
    sqlx::query("DELETE FROM push_outbox WHERE created_at < now() - interval '1 day'").execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(s: &str) -> Vec<u8> {
        BASE64URL_NOPAD.decode(s.as_bytes()).unwrap()
    }

    /// RFC 8291 Appendix A, from the shared secret on (ring can't import the fixed ECDH
    /// private keys the appendix uses, so the agreement itself is covered by the round trip
    /// below and the e2e test).
    #[test]
    fn rfc8291_appendix_a() {
        let plaintext = b"When I grow up, I want to be a watermelon";
        let as_public = b64("BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8");
        let ua_public = b64("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4");
        let auth = b64("BTBZMqHH6r4Tts7J_aSIgg");
        let salt: [u8; 16] = b64("DGv6ra1nlYgDCS1FRnbzlw").try_into().unwrap();
        let ecdh = b64("kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs");
        let (cek, nonce) = derive(&ecdh, &auth, &ua_public, &as_public, &salt);
        assert_eq!(BASE64URL_NOPAD.encode(&cek), "oIhVW04MRdy2XN9CiKLxTg");
        assert_eq!(BASE64URL_NOPAD.encode(&nonce), "4h_95klXJ5E_qnoN");
        let body = seal_record(&cek, &nonce, &salt, &as_public, plaintext);
        assert_eq!(
            BASE64URL_NOPAD.encode(&body),
            "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"
        );
    }

    /// A receiver's view: decrypt what `encrypt` made, with the receiver's private key.
    #[test]
    fn encrypt_round_trip() {
        let rng = SystemRandom::new();
        let ua = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).unwrap();
        let ua_public = ua.compute_public_key().unwrap().as_ref().to_vec();
        let auth = [7u8; 16];
        let body = encrypt(&ua_public, &auth, b"{\"title\":\"hi\"}").unwrap();
        let (salt, rest) = body.split_at(16);
        assert_eq!(&rest[..4], &4096u32.to_be_bytes());
        let idlen = rest[4] as usize;
        let as_public = &rest[5..5 + idlen];
        let record = &rest[5 + idlen..];
        let secret = agreement::agree_ephemeral(ua, &agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, as_public), |s| s.to_vec()).unwrap();
        let (cek, nonce) = derive(&secret, &auth, &ua_public, as_public, salt);
        let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &cek).unwrap());
        let mut buf = record.to_vec();
        let plain = key.open_in_place(aead::Nonce::assume_unique_for_key(nonce), aead::Aad::empty(), &mut buf).unwrap();
        assert_eq!(plain, b"{\"title\":\"hi\"}\x02");
        assert!(encrypt(&ua_public, &auth, &vec![b'x'; MAX_PAYLOAD + 1]).is_err());
        assert!(encrypt(b"not a point", &auth, b"x").is_err());
    }

    #[test]
    fn vapid_jwt_verifies_with_the_public_key() {
        let v = Vapid::generate().unwrap();
        let url = reqwest::Url::parse("https://fcm.googleapis.com/fcm/send/abc").unwrap();
        let header = v.authorization(&url, "mailto:ops@example.com").unwrap();
        let (t, k) = header.strip_prefix("vapid t=").unwrap().split_once(", k=").unwrap();
        assert_eq!(b64(k), v.public);
        let (input, sig) = t.rsplit_once('.').unwrap();
        signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &v.public).verify(input.as_bytes(), &b64(sig)).unwrap();
        let claims: Value = serde_json::from_slice(&b64(input.split_once('.').unwrap().1)).unwrap();
        assert_eq!(claims["aud"], "https://fcm.googleapis.com");
        assert_eq!(claims["sub"], "mailto:ops@example.com");
        assert!(claims["exp"].as_i64().unwrap() > chrono::Utc::now().timestamp() + 11 * 3600);
        let head: Value = serde_json::from_slice(&b64(input.split_once('.').unwrap().0)).unwrap();
        assert_eq!(head["alg"], "ES256");
        let reloaded = Vapid::from_parts(v.public.clone(), v.pkcs8.clone());
        assert!(reloaded.jwt("https://x", "mailto:a@b", 1).is_ok());
    }

    #[test]
    fn only_known_push_services() {
        for ok in [
            "https://fcm.googleapis.com/fcm/send/x",
            "https://updates.push.services.mozilla.com/wpush/v2/x",
            "https://wns2-par02p.notify.windows.com/w/?token=x",
            "https://web.push.apple.com/QGx",
        ] {
            assert!(endpoint_allowed(ok, &[]).is_ok(), "{ok}");
        }
        for bad in [
            "http://fcm.googleapis.com/fcm/send/x",
            "https://evil.example/fcm.googleapis.com",
            "https://push.services.mozilla.com.evil.example/x",
            "https://fcm.googleapis.com:8443/x",
            "https://169.254.169.254/latest",
            "not a url",
        ] {
            assert!(endpoint_allowed(bad, &[]).is_err(), "{bad}");
        }
        let extra = vec!["127.0.0.1".to_string()];
        assert!(endpoint_allowed("http://127.0.0.1:9000/push/1", &extra).is_ok());
        assert!(endpoint_allowed("http://127.0.0.2:9000/push/1", &extra).is_err());
    }

    #[test]
    fn event_defaults() {
        assert!(push_default("page") && push_default("alert_critical") && !push_default("alert_warning") && !push_default("nope"));
    }
}
