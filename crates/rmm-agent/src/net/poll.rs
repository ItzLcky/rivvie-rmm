//! Reading a device over SNMP: identity, uptime, interfaces (IF-MIB), CPU and memory
//! (HOST-RESOURCES-MIB, UCD-SNMP where that's what the device has) and printer supplies
//! (Printer-MIB). Everything read-only, one device at a time per connection, and at most
//! [`CONCURRENCY`] devices at once.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rmm_proto::net::{Interface, MAX_INTERFACES, PollResult, PollTarget, SnmpCreds, Storage, Supply, SysInfo};
use rmm_snmp::{AuthProto, Client, Creds, Error, Oid, Options, PrivProto, V3, Value, mib};
use tokio::sync::Semaphore;

use super::addr::pollable;

/// Devices read at once.
pub const CONCURRENCY: usize = 8;
const OPTS: Options = Options { timeout: Duration::from_millis(2000), retries: 1, bulk: 20 };

pub fn creds(c: &SnmpCreds) -> Result<Creds, String> {
    let creds = match c {
        SnmpCreds::V2c { community } => Creds::V2c { community: community.clone() },
        SnmpCreds::V3 { user, auth_proto, auth_secret, priv_proto, priv_secret, context } => {
            let auth = match (auth_proto, auth_secret) {
                (Some(p), Some(s)) => Some((AuthProto::parse(p).ok_or_else(|| format!("unknown authentication protocol {p:?}"))?, s.clone())),
                (None, None) => None,
                _ => return Err("an authentication protocol needs a passphrase, and the other way round".into()),
            };
            let privacy = match (priv_proto, priv_secret) {
                (Some(p), Some(s)) => Some((PrivProto::parse(p).ok_or_else(|| format!("unknown privacy protocol {p:?}"))?, s.clone())),
                (None, None) => None,
                _ => return Err("a privacy protocol needs a passphrase, and the other way round".into()),
            };
            Creds::V3(V3 { user: user.clone(), auth, privacy, context: context.clone() })
        }
    };
    creds.validate()?;
    Ok(creds)
}

fn addr(host: &str, port: u16) -> Result<SocketAddr, String> {
    let ip: IpAddr = host.trim_matches(['[', ']']).parse().map_err(|_| format!("{host:?} isn't an IP address"))?;
    if !pollable(ip) {
        return Err(format!("{ip} isn't in private address space: devices are only read on the local network"));
    }
    if port == 0 {
        return Err("port 0".into());
    }
    Ok(SocketAddr::new(ip, port))
}

/// Reads the system group with these credentials; `None` when the host doesn't answer them.
pub async fn identify(ip: IpAddr, port: u16, c: &SnmpCreds) -> Option<SysInfo> {
    let creds = creds(c).ok()?;
    let opts = Options { timeout: Duration::from_millis(900), retries: 0, bulk: 10 };
    let mut client = Client::connect(SocketAddr::new(ip, port), creds, opts).await.ok()?;
    system(&mut client).await.ok().filter(|s| !(s.descr.is_empty() && s.name.is_empty() && s.object_id.is_empty()))
}

async fn system(c: &mut Client) -> Result<SysInfo, Error> {
    let r = c.get(&[mib::sys_descr(), mib::sys_object_id(), mib::sys_name(), mib::sys_location(), mib::sys_contact()]).await?;
    let text = |i: usize| r.get(i).and_then(|(_, v)| v.as_text()).unwrap_or_default().chars().take(512).collect::<String>();
    let object_id = match r.get(1) {
        Some((_, Value::ObjectId(o))) => o.to_string(),
        _ => String::new(),
    };
    Ok(SysInfo { descr: text(0), object_id, name: text(2), location: text(3), contact: text(4) })
}

/// Reads every target, a few at a time.
pub async fn poll(targets: Vec<PollTarget>) -> Vec<PollResult> {
    let sem = Arc::new(Semaphore::new(CONCURRENCY));
    let mut tasks = tokio::task::JoinSet::new();
    for (i, t) in targets.into_iter().enumerate() {
        let sem = sem.clone();
        tasks.spawn(async move {
            let _p = sem.acquire_owned().await;
            (i, read(&t).await)
        });
    }
    let mut out: Vec<(usize, PollResult)> = Vec::new();
    while let Some(Ok(r)) = tasks.join_next().await {
        out.push(r);
    }
    out.sort_by_key(|(i, _)| *i);
    out.into_iter().map(|(_, r)| r).collect()
}

async fn read(t: &PollTarget) -> PollResult {
    let mut r = PollResult { device_id: t.device_id, ..Default::default() };
    let fail = |mut r: PollResult, e: String| {
        r.error = Some(e);
        r
    };
    let (addr, creds) = match (addr(&t.host, t.port), creds(&t.creds)) {
        (Ok(a), Ok(c)) => (a, c),
        (Err(e), _) | (_, Err(e)) => return fail(r, e),
    };
    let mut c = match Client::connect(addr, creds, OPTS).await {
        Ok(c) => c,
        Err(e) => return fail(r, e.to_string()),
    };
    // The first request doubles as the reachability check and the round-trip measurement.
    let started = Instant::now();
    let first = c.get(&[mib::sys_uptime(), mib::sys_descr(), mib::sys_object_id(), mib::sys_name(), mib::sys_location(), mib::sys_contact()]).await;
    let first = match first {
        Ok(v) => v,
        Err(e) => return fail(r, e.to_string()),
    };
    r.rtt_ms = Some(started.elapsed().as_millis() as u32);
    r.ok = true;
    r.uptime_secs = first.first().and_then(|(_, v)| v.as_u64()).map(|t| t / 100);
    let text = |i: usize| first.get(i).and_then(|(_, v)| v.as_text()).unwrap_or_default().chars().take(512).collect::<String>();
    r.sys = Some(SysInfo {
        descr: text(1),
        object_id: match first.get(2) {
            Some((_, Value::ObjectId(o))) => o.to_string(),
            _ => String::new(),
        },
        name: text(3),
        location: text(4),
        contact: text(5),
    });

    let mut notes: Vec<String> = Vec::new();
    match interfaces(&mut c).await {
        Ok(i) => r.interfaces = i,
        Err(e) => notes.push(format!("interfaces: {e}")),
    }
    match host_resources(&mut c).await {
        Ok(h) => {
            r.cpu_percent = h.cpu;
            r.mem_total = h.mem.map(|m| m.0);
            r.mem_used = h.mem.map(|m| m.1);
            r.storage = h.storage;
        }
        Err(e) => notes.push(format!("host resources: {e}")),
    }
    // UCD-SNMP fills in what HOST-RESOURCES didn't (net-snmp based firewalls and NAS boxes).
    if (r.cpu_percent.is_none() || r.mem_total.is_none())
        && let Ok(u) = c.get(&[mib::ucd_cpu_idle(), mib::ucd_mem_total_real(), mib::ucd_mem_avail_real()]).await
    {
        if r.cpu_percent.is_none()
            && let Some(idle) = u[0].1.as_i64()
        {
            r.cpu_percent = Some((100 - idle).clamp(0, 100) as f32);
        }
        if r.mem_total.is_none()
            && let (Some(total), Some(avail)) = (u[1].1.as_u64(), u[2].1.as_u64())
            && total > 0
        {
            r.mem_total = Some(total * 1024);
            r.mem_used = Some(total.saturating_sub(avail) * 1024);
        }
    }
    if t.supplies {
        match supplies(&mut c).await {
            Ok(s) => r.supplies = s,
            Err(e) => notes.push(format!("printer supplies: {e}")),
        }
    }
    if !notes.is_empty() {
        r.error = Some(notes.join("; "));
    }
    r
}

type Column = BTreeMap<Vec<u32>, Value>;

async fn column(c: &mut Client, root: &Oid, max: usize) -> Result<Column, Error> {
    Ok(c.column(root, max).await?.into_iter().collect())
}

pub async fn interfaces(c: &mut Client) -> Result<Vec<Interface>, Error> {
    let max = MAX_INTERFACES;
    let oper = column(c, &mib::if_oper_status(), max).await?;
    let admin = column(c, &mib::if_admin_status(), max).await?;
    let descr = column(c, &mib::if_descr(), max).await?;
    let names = column(c, &mib::if_name(), max).await.unwrap_or_default();
    let alias = column(c, &mib::if_alias(), max).await.unwrap_or_default();
    let types = column(c, &mib::if_type(), max).await.unwrap_or_default();
    let speed = column(c, &mib::if_speed(), max).await.unwrap_or_default();
    let high_speed = column(c, &mib::if_high_speed(), max).await.unwrap_or_default();
    let in32 = column(c, &mib::if_in_octets(), max).await.unwrap_or_default();
    let out32 = column(c, &mib::if_out_octets(), max).await.unwrap_or_default();
    let in64 = column(c, &mib::if_hc_in_octets(), max).await.unwrap_or_default();
    let out64 = column(c, &mib::if_hc_out_octets(), max).await.unwrap_or_default();
    let in_err = column(c, &mib::if_in_errors(), max).await.unwrap_or_default();
    let out_err = column(c, &mib::if_out_errors(), max).await.unwrap_or_default();
    let in_disc = column(c, &mib::if_in_discards(), max).await.unwrap_or_default();
    let out_disc = column(c, &mib::if_out_discards(), max).await.unwrap_or_default();

    let num = |col: &Column, k: &Vec<u32>| col.get(k).and_then(Value::as_u64).unwrap_or(0);
    let text = |col: &Column, k: &Vec<u32>| col.get(k).and_then(Value::as_text).unwrap_or_default();
    let mut out = Vec::new();
    for (k, o) in &oper {
        let [index] = k[..] else { continue };
        let hc = in64.contains_key(k) && out64.contains_key(k);
        let speed_bps = match high_speed.get(k).and_then(Value::as_u64) {
            Some(m) if m > 0 => m.saturating_mul(1_000_000),
            _ => num(&speed, k),
        };
        let d = text(&descr, k);
        let name = Some(text(&names, k)).filter(|n| !n.is_empty()).unwrap_or_else(|| d.clone());
        out.push(Interface {
            index,
            name: name.chars().take(128).collect(),
            descr: d.chars().take(256).collect(),
            alias: text(&alias, k).chars().take(256).collect(),
            if_type: types.get(k).and_then(Value::as_i64).unwrap_or(0) as i32,
            speed_bps,
            admin_status: admin.get(k).and_then(Value::as_i64).unwrap_or(1) as i32,
            oper_status: o.as_i64().unwrap_or(4) as i32,
            in_octets: if hc { num(&in64, k) } else { num(&in32, k) },
            out_octets: if hc { num(&out64, k) } else { num(&out32, k) },
            in_errors: num(&in_err, k),
            out_errors: num(&out_err, k),
            in_discards: num(&in_disc, k),
            out_discards: num(&out_disc, k),
            hc,
        });
    }
    Ok(out)
}

#[derive(Default)]
pub struct HostResources {
    pub cpu: Option<f32>,
    pub mem: Option<(u64, u64)>,
    pub storage: Vec<Storage>,
}

pub async fn host_resources(c: &mut Client) -> Result<HostResources, Error> {
    let mut h = HostResources::default();
    let load = column(c, &mib::hr_processor_load(), 256).await?;
    let loads: Vec<i64> = load.values().filter_map(Value::as_i64).collect();
    if !loads.is_empty() {
        h.cpu = Some(loads.iter().sum::<i64>() as f32 / loads.len() as f32);
    }
    let kinds = column(c, &mib::hr_storage_type(), 64).await?;
    if kinds.is_empty() {
        return Ok(h);
    }
    let descr = column(c, &mib::hr_storage_descr(), 64).await?;
    let units = column(c, &mib::hr_storage_units(), 64).await?;
    let size = column(c, &mib::hr_storage_size(), 64).await?;
    let used = column(c, &mib::hr_storage_used(), 64).await?;
    for (k, kind) in &kinds {
        let Value::ObjectId(kind) = kind else { continue };
        let which = if *kind == mib::hr_storage_ram() {
            "ram"
        } else if *kind == mib::hr_storage_fixed_disk() {
            "disk"
        } else {
            continue;
        };
        let unit = units.get(k).and_then(Value::as_u64).unwrap_or(1);
        let total = size.get(k).and_then(Value::as_u64).unwrap_or(0).saturating_mul(unit);
        let used = used.get(k).and_then(Value::as_u64).unwrap_or(0).saturating_mul(unit);
        if total == 0 {
            continue;
        }
        if which == "ram" && h.mem.is_none() {
            h.mem = Some((total, used.min(total)));
        }
        if h.storage.len() < 16 {
            h.storage.push(Storage { descr: descr.get(k).and_then(Value::as_text).unwrap_or_default().chars().take(128).collect(), kind: which.into(), total, used: used.min(total) });
        }
    }
    Ok(h)
}

pub async fn supplies(c: &mut Client) -> Result<Vec<Supply>, Error> {
    let desc = column(c, &mib::prt_supply_description(), 64).await?;
    if desc.is_empty() {
        return Ok(Vec::new());
    }
    let class = column(c, &mib::prt_supply_class(), 64).await?;
    let kind = column(c, &mib::prt_supply_type(), 64).await?;
    let max = column(c, &mib::prt_supply_max(), 64).await?;
    let level = column(c, &mib::prt_supply_level(), 64).await?;
    let mut out = Vec::new();
    for (k, d) in &desc {
        let lvl = level.get(k).and_then(Value::as_i64);
        let cap = max.get(k).and_then(Value::as_i64);
        out.push(Supply {
            index: k.last().copied().unwrap_or(0),
            description: d.as_text().unwrap_or_default().chars().take(128).collect(),
            class: class.get(k).and_then(Value::as_i64).unwrap_or(0) as i32,
            kind: kind.get(k).and_then(Value::as_i64).unwrap_or(0) as i32,
            percent: supply_percent(lvl, cap),
        });
    }
    Ok(out)
}

/// Level against capacity as a percentage. `-1` means no restriction, `-2` unknown and `-3`
/// "some remains": none of them is a number.
pub fn supply_percent(level: Option<i64>, max: Option<i64>) -> Option<u8> {
    let (level, max) = (level?, max?);
    if level < 0 || max <= 0 {
        return None;
    }
    Some((level * 100 / max).clamp(0, 100) as u8)
}

#[cfg(test)]
mod tests {
    use rmm_snmp::sim::{self, Sim};
    use uuid::Uuid;

    use super::*;

    #[test]
    fn supply_levels() {
        assert_eq!(supply_percent(Some(50), Some(100)), Some(50));
        assert_eq!(supply_percent(Some(1500), Some(6000)), Some(25));
        assert_eq!(supply_percent(Some(0), Some(100)), Some(0));
        assert_eq!(supply_percent(Some(-3), Some(100)), None);
        assert_eq!(supply_percent(Some(-2), Some(100)), None);
        assert_eq!(supply_percent(Some(5), Some(-2)), None);
        assert_eq!(supply_percent(Some(500), Some(100)), Some(100));
    }

    #[test]
    fn credentials_convert_and_refuse_nonsense() {
        let v3 = |ap: Option<&str>, a: Option<&str>, pp: Option<&str>, p: Option<&str>| SnmpCreds::V3 {
            user: "u".into(),
            auth_proto: ap.map(Into::into),
            auth_secret: a.map(Into::into),
            priv_proto: pp.map(Into::into),
            priv_secret: p.map(Into::into),
            context: String::new(),
        };
        assert!(creds(&v3(Some("sha256"), Some("longenough"), Some("aes128"), Some("longenough"))).is_ok());
        assert!(creds(&v3(Some("rot13"), Some("longenough"), None, None)).is_err());
        assert!(creds(&v3(Some("sha1"), None, None, None)).is_err());
        assert!(creds(&v3(None, None, Some("aes128"), Some("longenough"))).is_err(), "privacy needs authentication");
        assert!(creds(&SnmpCreds::V2c { community: String::new() }).is_err());
    }

    #[test]
    fn devices_outside_private_space_are_refused() {
        assert!(addr("10.0.0.2", 161).is_ok() && addr("127.0.0.1", 161).is_ok() && addr("fd12::1", 161).is_ok());
        assert!(addr("8.8.8.8", 161).is_err() && addr("example.com", 161).is_err() && addr("10.0.0.2", 0).is_err());
    }

    #[tokio::test]
    async fn a_switch_and_a_printer_are_read() {
        let mut o = sim::system("Acme 24-port switch", "1.3.6.1.4.1.9.1.516", "core-sw1", 8_640_000);
        o.extend(sim::interface(1, "Gi0/1", 1000, true, 5_000_000_000, 7_000_000_000));
        o.extend(sim::interface(2, "Gi0/2", 1000, false, 0, 0));
        o.push((Oid::of("1.3.6.1.2.1.25.3.3.1.2.196608"), Value::Integer(30)));
        o.push((Oid::of("1.3.6.1.2.1.25.3.3.1.2.196609"), Value::Integer(50)));
        o.push((Oid::of("1.3.6.1.2.1.25.2.3.1.2.1"), Value::ObjectId(mib::hr_storage_ram())));
        o.push((Oid::of("1.3.6.1.2.1.25.2.3.1.3.1"), Value::OctetString(b"Physical memory".to_vec())));
        o.push((Oid::of("1.3.6.1.2.1.25.2.3.1.4.1"), Value::Integer(1024)));
        o.push((Oid::of("1.3.6.1.2.1.25.2.3.1.5.1"), Value::Integer(1000)));
        o.push((Oid::of("1.3.6.1.2.1.25.2.3.1.6.1"), Value::Integer(250)));
        o.extend(sim::supply(1, "Black Toner", 3, 40, 100));
        o.extend(sim::supply(2, "Waste Toner Box", 4, -3, 100));
        let s = Sim::start("public", o).await.unwrap();
        let target = |supplies| PollTarget {
            device_id: Uuid::new_v4(),
            host: "127.0.0.1".into(),
            port: s.addr.port(),
            creds: SnmpCreds::V2c { community: "public".into() },
            supplies,
        };
        let dead = PollTarget { device_id: Uuid::new_v4(), host: "8.8.8.8".into(), port: 161, creds: SnmpCreds::V2c { community: "x".into() }, supplies: false };
        let results = poll(vec![target(true), dead.clone(), target(false)]).await;
        assert_eq!(results.len(), 3);

        let r = &results[0];
        assert!(r.ok, "{:?}", r.error);
        assert_eq!(r.uptime_secs, Some(86_400));
        assert_eq!(r.sys.as_ref().unwrap().name, "core-sw1");
        assert_eq!(r.sys.as_ref().unwrap().object_id, "1.3.6.1.4.1.9.1.516");
        assert_eq!(r.interfaces.len(), 2);
        let (i1, i2) = (&r.interfaces[0], &r.interfaces[1]);
        assert_eq!((i1.index, i1.name.as_str(), i1.oper_status, i1.hc, i1.speed_bps), (1, "Gi0/1", 1, true, 1_000_000_000));
        assert_eq!((i1.in_octets, i1.out_octets), (5_000_000_000, 7_000_000_000), "64-bit counters past 4 GB");
        assert_eq!((i2.oper_status, i2.alias.as_str()), (2, "uplink 2"));
        assert_eq!(r.cpu_percent, Some(40.0));
        assert_eq!((r.mem_total, r.mem_used), (Some(1_024_000), Some(256_000)));
        assert_eq!(r.supplies.len(), 2);
        assert_eq!((r.supplies[0].description.as_str(), r.supplies[0].percent, r.supplies[0].kind), ("Black Toner", Some(40), 3));
        assert_eq!(r.supplies[1].percent, None, "'some remains' isn't a number");

        assert_eq!(results[1].device_id, dead.device_id);
        assert!(!results[1].ok && results[1].error.as_deref().unwrap().contains("private"), "{:?}", results[1].error);
        assert!(results[2].ok && results[2].supplies.is_empty(), "supplies only when asked");
    }

    #[tokio::test]
    async fn a_silent_device_is_down_not_an_error_of_ours() {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = sock.local_addr().unwrap().port();
        let t = PollTarget { device_id: Uuid::new_v4(), host: "127.0.0.1".into(), port, creds: SnmpCreds::V2c { community: "public".into() }, supplies: false };
        let r = poll(vec![t]).await.remove(0);
        assert!(!r.ok && r.error.is_some() && r.interfaces.is_empty());
        drop(sock);
    }

    #[tokio::test]
    async fn identify_wants_the_right_community() {
        let s = Sim::start("public", sim::system("Printer", "1.3.6.1.4.1.11.2.3.9.1", "prn1", 1)).await.unwrap();
        let ip = "127.0.0.1".parse().unwrap();
        let ok = identify(ip, s.addr.port(), &SnmpCreds::V2c { community: "public".into() }).await.unwrap();
        assert_eq!((ok.name.as_str(), ok.descr.as_str()), ("prn1", "Printer"));
        assert!(identify(ip, s.addr.port(), &SnmpCreds::V2c { community: "private".into() }).await.is_none());
    }
}
