//! Against a real net-snmp `snmpd`, which is what proves the v3 code (key localization,
//! signatures, DES and AES) agrees with an independent implementation.
//!
//! ```sh
//! cat > snmpd.conf <<'CONF'
//! agentAddress udp:161
//! rocommunity e2ecomm
//! createUser e2ev3 SHA e2eauthpass AES e2eprivpass
//! rouser e2ev3 priv
//! createUser e2emd5 MD5 e2emd5authpass DES e2edespass
//! rouser e2emd5 priv
//! createUser e2eauthonly SHA256 e2eauthonly1
//! rouser e2eauthonly auth
//! sysName e2e-snmpd
//! CONF
//! docker run -d --name snmpd -v $PWD/snmpd.conf:/etc/snmp/snmpd.conf:ro alpine:3 sh -c \
//!   'apk add --no-cache net-snmp && exec snmpd -f -Lo -C -c /etc/snmp/snmpd.conf'
//! RMM_SNMP_TEST_HOST=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' snmpd) \
//!   cargo test -p rmm-snmp --test netsnmp -- --ignored --nocapture
//! ```

use std::net::SocketAddr;
use std::time::Duration;

use rmm_snmp::{AuthProto, Client, Creds, Error, Options, PrivProto, V3, mib};

fn target() -> SocketAddr {
    let host = std::env::var("RMM_SNMP_TEST_HOST").expect("set RMM_SNMP_TEST_HOST (see the module docs)");
    format!("{host}:161").parse().unwrap()
}

fn opts() -> Options {
    Options { timeout: Duration::from_millis(2000), retries: 1, bulk: 20 }
}

fn v3(user: &str, auth: Option<(AuthProto, &str)>, privacy: Option<(PrivProto, &str)>) -> Creds {
    Creds::V3(V3 {
        user: user.into(),
        auth: auth.map(|(p, s)| (p, s.into())),
        privacy: privacy.map(|(p, s)| (p, s.into())),
        context: String::new(),
    })
}

#[tokio::test]
#[ignore = "needs a net-snmp snmpd: see the module docs"]
async fn every_version_and_security_level_reads_the_same_device() {
    let cases = [
        ("v2c", Creds::V2c { community: "e2ecomm".into() }),
        ("sha+aes", v3("e2ev3", Some((AuthProto::Sha1, "e2eauthpass")), Some((PrivProto::Aes128, "e2eprivpass")))),
        ("md5+des", v3("e2emd5", Some((AuthProto::Md5, "e2emd5authpass")), Some((PrivProto::Des, "e2edespass")))),
        ("sha256", v3("e2eauthonly", Some((AuthProto::Sha256, "e2eauthonly1")), None)),
    ];
    for (name, creds) in cases {
        let mut c = Client::connect(target(), creds, opts()).await.unwrap();
        let r = c.get(&[mib::sys_name(), mib::sys_descr(), mib::sys_object_id()]).await.unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(r[0].1.as_text().as_deref(), Some("e2e-snmpd"), "{name}");
        assert!(r[1].1.as_text().unwrap().contains("Linux"), "{name}: {:?}", r[1]);
        // A walk is many requests: the time window and message ids keep working.
        let ifs = c.column(&mib::if_descr(), 100).await.unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(!ifs.is_empty(), "{name}: the device has interfaces");
        assert!(ifs.iter().any(|(_, v)| v.as_text().as_deref() == Some("lo")), "{name}: {ifs:?}");
        println!("{name}: ok, {} interfaces", ifs.len());
    }
}

#[tokio::test]
#[ignore = "needs a net-snmp snmpd: see the module docs"]
async fn wrong_credentials_say_what_is_wrong() {
    let bad = [
        ("passphrase", v3("e2ev3", Some((AuthProto::Sha1, "not-the-pass")), Some((PrivProto::Aes128, "e2eprivpass")))),
        ("user", v3("nobody", Some((AuthProto::Sha1, "e2eauthpass")), None)),
        ("level", v3("e2eauthonly", Some((AuthProto::Sha256, "e2eauthonly1")), Some((PrivProto::Aes128, "whateverelse")))),
    ];
    for (name, creds) in bad {
        let mut c = Client::connect(target(), creds, opts()).await.unwrap();
        let r = c.get(&[mib::sys_name()]).await;
        assert!(matches!(r, Err(Error::Auth(_)) | Err(Error::Timeout)), "{name}: {r:?}");
        println!("{name}: {}", r.unwrap_err());
    }
    let mut c = Client::connect(target(), Creds::V2c { community: "wrong".into() }, opts()).await.unwrap();
    assert!(matches!(c.get(&[mib::sys_name()]).await, Err(Error::Timeout)));
}
