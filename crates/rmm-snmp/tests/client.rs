use std::time::Duration;

use rmm_snmp::sim::{self, Sim};
use rmm_snmp::{Client, Creds, Error, Oid, Options, Value, mib};

fn opts() -> Options {
    Options { timeout: Duration::from_millis(300), retries: 1, bulk: 10 }
}

async fn switch() -> Sim {
    let mut o = sim::system("Acme Switch 24", "1.3.6.1.4.1.9.1.516", "core-sw1", 123_456);
    for i in 1..=30 {
        o.extend(sim::interface(i, &format!("Gi0/{i}"), 1000, i % 2 == 1, u64::from(i) * 1000, u64::from(i) * 2000));
    }
    Sim::start("public", o).await.unwrap()
}

fn v2c(c: &str) -> Creds {
    Creds::V2c { community: c.into() }
}

#[tokio::test]
async fn get_walk_and_the_wrong_community() {
    let s = switch().await;
    let mut c = Client::connect(s.addr, v2c("public"), opts()).await.unwrap();
    let r = c.get(&[mib::sys_descr(), mib::sys_name(), mib::sys_uptime(), Oid::of("1.3.6.1.2.1.1.99.0")]).await.unwrap();
    assert_eq!(r[0].1.as_text().as_deref(), Some("Acme Switch 24"));
    assert_eq!(r[1].1.as_text().as_deref(), Some("core-sw1"));
    assert_eq!(r[2].1, Value::TimeTicks(123_456));
    assert_eq!(r[3].1, Value::NoSuchInstance);

    // 30 rows with 10 per request: three requests and a clean stop at the end of the column.
    let col = c.column(&mib::if_oper_status(), 1000).await.unwrap();
    assert_eq!(col.len(), 30);
    assert_eq!(col[0], (vec![1], Value::Integer(1)));
    assert_eq!(col[1], (vec![2], Value::Integer(2)));
    // The next column isn't included, and the table's end doesn't loop.
    let all = c.walk(&Oid::of("1.3.6.1.2.1.31"), 10_000).await.unwrap();
    assert_eq!(all.len(), 30 * 5);
    assert_eq!(c.walk(&Oid::of("1.3.6.1.2.1.1"), 3).await.unwrap().len(), 3, "the row cap holds");

    let mut bad = Client::connect(s.addr, v2c("secret"), opts()).await.unwrap();
    assert!(matches!(bad.get(&[mib::sys_descr()]).await, Err(Error::Timeout)));
}

#[tokio::test]
async fn a_counter_that_ticks_is_read_again() {
    let s = switch().await;
    let mut c = Client::connect(s.addr, v2c("public"), opts()).await.unwrap();
    let oid = Oid::of("1.3.6.1.2.1.31.1.1.1.6.1");
    assert_eq!(c.get(std::slice::from_ref(&oid)).await.unwrap()[0].1, Value::Counter64(1000));
    s.set("1.3.6.1.2.1.31.1.1.1.6.1", Value::Counter64(u64::MAX - 5));
    assert_eq!(c.get(std::slice::from_ref(&oid)).await.unwrap()[0].1, Value::Counter64(u64::MAX - 5));
}

#[tokio::test]
async fn nothing_listening_is_an_error_not_a_hang() {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    drop(sock);
    let mut c = Client::connect(addr, v2c("public"), opts()).await.unwrap();
    let r = tokio::time::timeout(Duration::from_secs(5), c.get(&[mib::sys_descr()])).await.expect("returns within the retry budget");
    assert!(matches!(r, Err(Error::Io(_) | Error::Timeout)), "{r:?}");
}

#[test]
fn credentials_are_checked_and_never_printed() {
    use rmm_snmp::{AuthProto, PrivProto, V3};
    let v3 = |auth: Option<&str>, privacy: Option<&str>| {
        Creds::V3(V3 {
            user: "u".into(),
            auth: auth.map(|p| (AuthProto::Sha1, p.to_string())),
            privacy: privacy.map(|p| (PrivProto::Aes128, p.to_string())),
            context: String::new(),
        })
    };
    assert!(v3(None, None).validate().is_ok());
    assert!(v3(Some("longenough"), Some("longenough")).validate().is_ok());
    assert!(v3(None, Some("longenough")).validate().is_err(), "privacy needs authentication");
    assert!(v3(Some("short"), None).validate().is_err());
    assert!(v2c("").validate().is_err());
    assert!(!format!("{:?}", v2c("hunter2hunter2")).contains("hunter2"));
    assert!(!format!("{:?}", v3(Some("authsecret1"), Some("privsecret1"))).contains("secret1"));
}
