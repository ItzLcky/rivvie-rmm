//! WebAuthn (passkeys) as a second factor: the relying party configuration and the short-lived
//! ceremony state that sits between "here is a challenge" and "here is the browser's answer".
//!
//! The relying party id is the host of `RMM_PUBLIC_URL` and the origin is that URL, so a
//! passkey only works where the dashboard is reached at its public address. State lives in
//! memory: a ceremony that spans a server restart simply has to be started again.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use uuid::Uuid;
use webauthn_rs::prelude::{PasskeyAuthentication, PasskeyRegistration, Url, Webauthn, WebauthnBuilder};

const TTL: Duration = Duration::from_secs(300);
const MAX_PENDING: usize = 5000;
/// A person can have this many ceremonies pending; starting more replaces the oldest, so one
/// account can't fill the table for everybody.
const MAX_PER_USER: usize = 5;

enum Kind {
    Register(Box<PasskeyRegistration>),
    Login(Box<PasskeyAuthentication>),
}

struct Ceremony {
    user_id: Uuid,
    at: Instant,
    kind: Kind,
}

pub struct Passkeys {
    /// `None` when `RMM_PUBLIC_URL` can't be a WebAuthn origin (an IP address).
    pub webauthn: Option<Webauthn>,
    pending: Mutex<HashMap<String, Ceremony>>,
}

impl Passkeys {
    pub fn new(public_url: &str) -> Passkeys {
        let built = Url::parse(public_url)
            .map_err(|e| e.to_string())
            .and_then(|origin| {
                let host = origin.host_str().ok_or("no host")?.to_string();
                WebauthnBuilder::new(&host, &origin)
                    .and_then(|b| b.rp_name("RMM").build())
                    .map_err(|e| e.to_string())
            });
        let webauthn = match built {
            Ok(w) => Some(w),
            Err(e) => {
                tracing::warn!("passkeys are unavailable: RMM_PUBLIC_URL {public_url} can't be a WebAuthn origin ({e}); use a host name, not an IP address");
                None
            }
        };
        Passkeys { webauthn, pending: Mutex::default() }
    }

    fn put(&self, user_id: Uuid, kind: Kind) -> Option<String> {
        let id = crate::auth::random_token();
        let mut map = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let mine: Vec<(Instant, String)> = map.iter().filter(|(_, c)| c.user_id == user_id).map(|(k, c)| (c.at, k.clone())).collect();
        if mine.len() >= MAX_PER_USER
            && let Some((_, oldest)) = mine.into_iter().min()
        {
            map.remove(&oldest);
        }
        if map.len() >= MAX_PENDING {
            map.retain(|_, c| c.at.elapsed() < TTL);
            if map.len() >= MAX_PENDING {
                return None;
            }
        }
        map.insert(id.clone(), Ceremony { user_id, at: Instant::now(), kind });
        Some(id)
    }

    /// Single use: a ceremony is consumed whether or not the answer turns out to be right.
    fn take(&self, id: &str, user_id: Uuid) -> Option<Kind> {
        let c = self.pending.lock().unwrap_or_else(|e| e.into_inner()).remove(id)?;
        (c.user_id == user_id && c.at.elapsed() < TTL).then_some(c.kind)
    }

    pub fn start_register(&self, user_id: Uuid, reg: PasskeyRegistration) -> Option<String> {
        self.put(user_id, Kind::Register(Box::new(reg)))
    }

    pub fn finish_register(&self, id: &str, user_id: Uuid) -> Option<PasskeyRegistration> {
        match self.take(id, user_id)? {
            Kind::Register(r) => Some(*r),
            Kind::Login(_) => None,
        }
    }

    pub fn start_login(&self, user_id: Uuid, auth: PasskeyAuthentication) -> Option<String> {
        self.put(user_id, Kind::Login(Box::new(auth)))
    }

    pub fn finish_login(&self, id: &str, user_id: Uuid) -> Option<PasskeyAuthentication> {
        match self.take(id, user_id)? {
            Kind::Login(a) => Some(*a),
            Kind::Register(_) => None,
        }
    }

    pub fn prune(&self) {
        self.pending.lock().unwrap_or_else(|e| e.into_inner()).retain(|_, c| c.at.elapsed() < TTL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;

    #[test]
    fn ip_addresses_cant_be_origins() {
        assert!(Passkeys::new("https://rmm.example.com").webauthn.is_some());
        assert!(Passkeys::new("http://localhost:8080").webauthn.is_some());
        assert!(Passkeys::new("https://10.0.0.5").webauthn.is_none());
        assert!(Passkeys::new("not a url").webauthn.is_none());
    }

    /// Register and authenticate with a software authenticator, and check what must be refused.
    #[test]
    fn register_and_authenticate_with_a_software_authenticator() {
        let pk = Passkeys::new("https://rmm.example.com");
        let wa = pk.webauthn.as_ref().unwrap();
        let origin = Url::parse("https://rmm.example.com").unwrap();
        let user = Uuid::new_v4();
        let mut device = SoftPasskey::new(true);

        let (ccr, reg) = wa.start_passkey_registration(user, "tech@example.com", "Tech", None).unwrap();
        let id = pk.start_register(user, reg).unwrap();
        let cred = device.do_registration(origin.clone(), ccr).unwrap();
        // Another user can't finish it, and it works once.
        assert!(pk.finish_register(&id, Uuid::new_v4()).is_none());
        assert!(pk.finish_register(&id, user).is_none(), "consumed by the failed attempt");
        let (ccr, reg) = wa.start_passkey_registration(user, "tech@example.com", "Tech", None).unwrap();
        let id = pk.start_register(user, reg).unwrap();
        let cred2 = device.do_registration(origin.clone(), ccr).unwrap();
        let passkey = wa.finish_passkey_registration(&cred2, &pk.finish_register(&id, user).unwrap()).unwrap();
        // The first registration's challenge doesn't verify against the second state.
        let (_, reg3) = wa.start_passkey_registration(user, "tech@example.com", "Tech", None).unwrap();
        assert!(wa.finish_passkey_registration(&cred, &reg3).is_err());

        // Stored as JSON and read back.
        let stored = serde_json::to_value(&passkey).unwrap();
        let mut passkey: webauthn_rs::prelude::Passkey = serde_json::from_value(stored).unwrap();

        let (rcr, auth) = wa.start_passkey_authentication(std::slice::from_ref(&passkey)).unwrap();
        let aid = pk.start_login(user, auth).unwrap();
        let assertion = device.do_authentication(origin.clone(), rcr).unwrap();
        let state = pk.finish_login(&aid, user).unwrap();
        let res = wa.finish_passkey_authentication(&assertion, &state).unwrap();
        assert_eq!(res.cred_id(), passkey.cred_id());
        assert!(passkey.update_credential(&res).is_some());

        // The same assertion doesn't verify under a fresh challenge.
        let (_, auth2) = wa.start_passkey_authentication(std::slice::from_ref(&passkey)).unwrap();
        assert!(wa.finish_passkey_authentication(&assertion, &auth2).is_err());
        // Nor does an assertion from a device that doesn't hold the credential.
        let (rcr, _) = wa.start_passkey_authentication(std::slice::from_ref(&passkey)).unwrap();
        assert!(SoftPasskey::new(true).do_authentication(origin, rcr).is_err());
    }

    #[test]
    fn one_user_cant_fill_the_table() {
        let pk = Passkeys::new("https://rmm.example.com");
        let wa = pk.webauthn.as_ref().unwrap();
        let (me, other) = (Uuid::new_v4(), Uuid::new_v4());
        let (_, reg) = wa.start_passkey_registration(other, "o@b.c", "O", None).unwrap();
        let theirs = pk.start_register(other, reg).unwrap();
        let first = {
            let (_, reg) = wa.start_passkey_registration(me, "a@b.c", "A", None).unwrap();
            pk.start_register(me, reg).unwrap()
        };
        for _ in 0..MAX_PER_USER {
            let (_, reg) = wa.start_passkey_registration(me, "a@b.c", "A", None).unwrap();
            pk.start_register(me, reg).unwrap();
        }
        assert!(pk.finish_register(&first, me).is_none(), "the oldest was replaced");
        assert!(pk.finish_register(&theirs, other).is_some(), "someone else's is untouched");
    }

    #[test]
    fn ceremonies_expire_and_are_kind_checked() {
        let pk = Passkeys::new("https://rmm.example.com");
        let wa = pk.webauthn.as_ref().unwrap();
        let user = Uuid::new_v4();
        let (_, reg) = wa.start_passkey_registration(user, "a@b.c", "A", None).unwrap();
        let id = pk.start_register(user, reg).unwrap();
        assert!(pk.finish_login(&id, user).is_none(), "a registration isn't a login");
        let (_, reg) = wa.start_passkey_registration(user, "a@b.c", "A", None).unwrap();
        let id = pk.start_register(user, reg).unwrap();
        pk.pending.lock().unwrap().get_mut(&id).unwrap().at = Instant::now() - TTL - Duration::from_secs(1);
        assert!(pk.finish_register(&id, user).is_none(), "expired");
    }
}
