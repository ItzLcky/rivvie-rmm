//! A small SNMPv2c responder for tests: serves a table of objects over UDP on the loopback
//! address, answering `GET`, `GETNEXT` and `GETBULK` like a real agent (including
//! `endOfMibView`). The table can be changed while it runs, so counters can be made to tick.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

use crate::ber::{self, Oid, Reader, Value};

pub type Mib = Arc<Mutex<BTreeMap<Oid, Value>>>;

pub struct Sim {
    pub addr: SocketAddr,
    pub mib: Mib,
    task: JoinHandle<()>,
}

impl Drop for Sim {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Sim {
    /// Starts on `127.0.0.1` with a free port. Requests with another community are ignored,
    /// like a device does.
    pub async fn start(community: &str, objects: Vec<(Oid, Value)>) -> std::io::Result<Sim> {
        let sock = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = sock.local_addr()?;
        let mib: Mib = Arc::new(Mutex::new(objects.into_iter().collect()));
        let (m, community) = (mib.clone(), community.as_bytes().to_vec());
        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65507];
            loop {
                let Ok((n, from)) = sock.recv_from(&mut buf).await else { return };
                let reply = answer(&buf[..n], &community, &m.lock().unwrap());
                if let Some(reply) = reply {
                    let _ = sock.send_to(&reply, from).await;
                }
            }
        });
        Ok(Sim { addr, mib, task })
    }

    pub fn set(&self, oid: &str, v: Value) {
        self.mib.lock().unwrap().insert(Oid::of(oid), v);
    }
}

fn answer(req: &[u8], community: &[u8], mib: &BTreeMap<Oid, Value>) -> Option<Vec<u8>> {
    let mut r = Reader::new(req);
    let mut m = r.sequence().ok()?;
    let version = m.int().ok()?;
    if version != 1 || m.octets().ok()? != community {
        return None;
    }
    let (tag, body) = m.read().ok()?;
    let mut p = Reader::new(body);
    let id = p.int().ok()?;
    let (a, b) = (p.int().ok()?, p.int().ok()?);
    let mut list = p.sequence().ok()?;
    let mut oids = Vec::new();
    while !list.is_empty() {
        oids.push(list.sequence().ok()?.oid().ok()?);
    }
    let next = |from: &Oid| mib.range((std::ops::Bound::Excluded(from.clone()), std::ops::Bound::Unbounded)).next().map(|(o, v)| (o.clone(), v.clone()));
    let mut out: Vec<(Oid, Value)> = Vec::new();
    match tag {
        0xa0 => {
            for o in &oids {
                out.push((o.clone(), mib.get(o).cloned().unwrap_or(Value::NoSuchInstance)));
            }
        }
        0xa1 => {
            for o in &oids {
                out.push(next(o).unwrap_or((o.clone(), Value::EndOfMibView)));
            }
        }
        0xa5 => {
            let (nr, mr) = (a.max(0) as usize, b.clamp(0, 100) as usize);
            for o in oids.iter().take(nr) {
                out.push(next(o).unwrap_or((o.clone(), Value::EndOfMibView)));
            }
            let mut cur: Vec<Oid> = oids.iter().skip(nr).cloned().collect();
            for _ in 0..mr {
                for c in cur.iter_mut() {
                    let (o, v) = next(c).unwrap_or((c.clone(), Value::EndOfMibView));
                    *c = o.clone();
                    out.push((o, v));
                }
            }
        }
        _ => return None,
    }
    let binds: Vec<Vec<u8>> = out.iter().map(|(o, v)| ber::sequence(&[ber::oid(o), ber::value(v)])).collect();
    let pdu = ber::tlv(0xa2, &[ber::int(id), ber::int(0), ber::int(0), ber::sequence(&binds)].concat());
    Some(ber::sequence(&[ber::int(1), ber::octets(community), pdu]))
}

fn s(v: &str) -> Value {
    Value::OctetString(v.as_bytes().to_vec())
}

/// The system group of a device.
pub fn system(descr: &str, object_id: &str, name: &str, uptime_ticks: u32) -> Vec<(Oid, Value)> {
    vec![
        (Oid::of("1.3.6.1.2.1.1.1.0"), s(descr)),
        (Oid::of("1.3.6.1.2.1.1.2.0"), Value::ObjectId(Oid::of(object_id))),
        (Oid::of("1.3.6.1.2.1.1.3.0"), Value::TimeTicks(uptime_ticks)),
        (Oid::of("1.3.6.1.2.1.1.5.0"), s(name)),
    ]
}

/// One interface: IF-MIB ifTable and ifXTable rows (64-bit counters).
pub fn interface(index: u32, name: &str, speed_mbps: u32, oper_up: bool, in_octets: u64, out_octets: u64) -> Vec<(Oid, Value)> {
    let row = |col: &str| Oid::of(&format!("{col}.{index}"));
    vec![
        (row("1.3.6.1.2.1.2.2.1.2"), s(name)),
        (row("1.3.6.1.2.1.2.2.1.3"), Value::Integer(6)),
        (row("1.3.6.1.2.1.2.2.1.5"), Value::Gauge32(speed_mbps.saturating_mul(1_000_000))),
        (row("1.3.6.1.2.1.2.2.1.7"), Value::Integer(1)),
        (row("1.3.6.1.2.1.2.2.1.8"), Value::Integer(if oper_up { 1 } else { 2 })),
        (row("1.3.6.1.2.1.2.2.1.10"), Value::Counter32(in_octets as u32)),
        (row("1.3.6.1.2.1.2.2.1.13"), Value::Counter32(0)),
        (row("1.3.6.1.2.1.2.2.1.14"), Value::Counter32(0)),
        (row("1.3.6.1.2.1.2.2.1.16"), Value::Counter32(out_octets as u32)),
        (row("1.3.6.1.2.1.2.2.1.19"), Value::Counter32(0)),
        (row("1.3.6.1.2.1.2.2.1.20"), Value::Counter32(0)),
        (row("1.3.6.1.2.1.31.1.1.1.1"), s(name)),
        (row("1.3.6.1.2.1.31.1.1.1.6"), Value::Counter64(in_octets)),
        (row("1.3.6.1.2.1.31.1.1.1.10"), Value::Counter64(out_octets)),
        (row("1.3.6.1.2.1.31.1.1.1.15"), Value::Gauge32(speed_mbps)),
        (row("1.3.6.1.2.1.31.1.1.1.18"), s(&format!("uplink {index}"))),
    ]
}

/// One Printer-MIB supply: class 3 is "supplyThatIsConsumed", 1 is "other" (a waste container).
/// `level` is in the supply's own units (percent here, with a maximum of 100).
pub fn supply(index: u32, description: &str, kind: i64, level: i64, max: i64) -> Vec<(Oid, Value)> {
    let row = |col: &str| Oid::of(&format!("1.3.6.1.2.1.43.11.1.1.{col}.1.{index}"));
    vec![
        (row("4"), Value::Integer(3)),
        (row("5"), Value::Integer(kind)),
        (row("6"), s(description)),
        (row("7"), Value::Integer(19)),
        (row("8"), Value::Integer(max)),
        (row("9"), Value::Integer(level)),
    ]
}
