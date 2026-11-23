//! A client for one device: v2c, or v3 with engine discovery and time synchronisation.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;

use crate::ber::{self, Oid, Reader, Value};
use crate::usm::{self, AuthProto, PrivProto};
use crate::{Creds, Error, V3, mib};

const GET: u8 = 0xa0;
const GET_NEXT: u8 = 0xa1;
const RESPONSE: u8 = 0xa2;
const GET_BULK: u8 = 0xa5;
const REPORT: u8 = 0xa8;

/// What an answer may carry at most: a UDP datagram.
const MAX_MSG: usize = 65507;
/// Rows a walk collects at most, whatever the device says.
pub const WALK_MAX: usize = 20_000;

#[derive(Clone, Debug)]
pub struct Options {
    /// Per attempt.
    pub timeout: Duration,
    /// Attempts after the first.
    pub retries: u32,
    /// `max-repetitions` of GETBULK: rows asked for per request.
    pub bulk: u32,
}

impl Default for Options {
    fn default() -> Self {
        Options { timeout: Duration::from_millis(1500), retries: 1, bulk: 20 }
    }
}

type VarBinds = Vec<(Oid, Value)>;

/// What is known of the device's SNMP engine (v3).
struct Engine {
    id: Vec<u8>,
    boots: u32,
    /// The device's clock when we last heard it, and when that was.
    time: u32,
    synced: Instant,
    auth_key: Option<Vec<u8>>,
    priv_key: Option<Vec<u8>>,
}

impl Engine {
    fn now(&self) -> u32 {
        self.time.saturating_add(self.synced.elapsed().as_secs() as u32)
    }
}

pub struct Client {
    sock: UdpSocket,
    creds: Creds,
    opts: Options,
    next_id: i32,
    engine: Option<Engine>,
    salt: u64,
}

impl Client {
    pub async fn connect(addr: SocketAddr, creds: Creds, opts: Options) -> Result<Client, Error> {
        creds.validate().map_err(Error::Config)?;
        let bind: SocketAddr = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse().expect("literal address");
        let sock = UdpSocket::bind(bind).await?;
        sock.connect(addr).await?;
        let mut seed = [0u8; 12];
        let _ = getrandom::fill(&mut seed);
        let next_id = i32::from_be_bytes(seed[..4].try_into().expect("4 bytes")) & 0x3fff_ffff;
        // Salts only need to not repeat for one engine; the counter's low half is what DES uses.
        let salt = u64::from(u32::from_be_bytes(seed[4..8].try_into().expect("4 bytes"))) << 32 | u64::from(u32::from_be_bytes(seed[8..].try_into().expect("4 bytes")));
        Ok(Client { sock, creds, opts, next_id, engine: None, salt })
    }

    fn id(&mut self) -> i32 {
        self.next_id = self.next_id.wrapping_add(1) & 0x3fff_ffff;
        self.next_id
    }

    pub async fn get(&mut self, oids: &[Oid]) -> Result<VarBinds, Error> {
        self.request(GET, oids, 0, 0).await
    }

    pub async fn get_next(&mut self, oids: &[Oid]) -> Result<VarBinds, Error> {
        self.request(GET_NEXT, oids, 0, 0).await
    }

    pub async fn get_bulk(&mut self, oids: &[Oid], non_repeaters: u32, max_repetitions: u32) -> Result<VarBinds, Error> {
        self.request(GET_BULK, oids, non_repeaters, max_repetitions).await
    }

    /// Everything under `root`, in order, at most `max` rows.
    pub async fn walk(&mut self, root: &Oid, max: usize) -> Result<VarBinds, Error> {
        let mut out: VarBinds = Vec::new();
        let mut at = root.clone();
        'outer: loop {
            let rows = self.get_bulk(std::slice::from_ref(&at), 0, self.opts.bulk.clamp(1, 50)).await?;
            if rows.is_empty() {
                break;
            }
            for (oid, v) in rows {
                if v == Value::EndOfMibView || !oid.starts_with(root) {
                    break 'outer;
                }
                // A device that walks backwards or in circles would never let us finish.
                if oid <= at {
                    break 'outer;
                }
                at = oid.clone();
                out.push((oid, v));
                if out.len() >= max.min(WALK_MAX) {
                    break 'outer;
                }
            }
        }
        Ok(out)
    }

    /// Like [`walk`](Self::walk), keyed by the instance part of each OID.
    pub async fn column(&mut self, root: &Oid, max: usize) -> Result<Vec<(Vec<u32>, Value)>, Error> {
        Ok(self.walk(root, max).await?.into_iter().filter_map(|(o, v)| o.suffix(root).map(|s| (s.to_vec(), v))).collect())
    }

    async fn request(&mut self, pdu_type: u8, oids: &[Oid], a: u32, b: u32) -> Result<VarBinds, Error> {
        match self.creds.clone() {
            Creds::V2c { community } => self.request_v2c(&community, pdu_type, oids, a, b).await,
            Creds::V3(v3) => self.request_v3(&v3, pdu_type, oids, a, b).await,
        }
    }

    async fn exchange(&self, msg: &[u8], matches: impl Fn(&[u8]) -> bool) -> Result<Vec<u8>, Error> {
        let mut buf = vec![0u8; MAX_MSG];
        for _ in 0..=self.opts.retries {
            self.sock.send(msg).await?;
            let deadline = tokio::time::Instant::now() + self.opts.timeout;
            loop {
                match tokio::time::timeout_at(deadline, self.sock.recv(&mut buf)).await {
                    Err(_) => break,
                    // An ICMP port unreachable surfaces as a refused connection on a connected socket.
                    Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => return Err(Error::Io(e)),
                    Ok(Err(e)) => return Err(e.into()),
                    Ok(Ok(n)) => {
                        if matches(&buf[..n]) {
                            return Ok(buf[..n].to_vec());
                        }
                    }
                }
            }
        }
        Err(Error::Timeout)
    }

    async fn request_v2c(&mut self, community: &str, pdu_type: u8, oids: &[Oid], a: u32, b: u32) -> Result<VarBinds, Error> {
        let id = self.id();
        let pdu = pdu(pdu_type, id, a, b, oids);
        let msg = ber::sequence(&[ber::int(1), ber::octets(community.as_bytes()), pdu]);
        let reply = self.exchange(&msg, |m| v2c_request_id(m) == Some(id)).await?;
        let mut r = Reader::new(&reply);
        let mut m = r.sequence()?;
        m.int()?;
        m.octets()?;
        let (tag, body) = m.read()?;
        parse_pdu(tag, body)?.into_result()
    }

    // ---- v3 ---------------------------------------------------------------------------

    async fn request_v3(&mut self, v3: &V3, pdu_type: u8, oids: &[Oid], a: u32, b: u32) -> Result<VarBinds, Error> {
        for attempt in 0..3 {
            if self.engine.is_none() {
                self.discover(v3).await?;
            }
            let id = self.id();
            let pdu = pdu(pdu_type, id, a, b, oids);
            let msg_id = self.id();
            let (msg, reply_key) = self.build_v3(v3, msg_id, &pdu)?;
            let reply = self.exchange(&msg, |m| v3_msg_id(m) == Some(reply_key)).await?;
            match self.parse_v3(v3, &reply)? {
                V3Reply::Pdu(p) => return p.into_result(),
                V3Reply::Report(oid) => {
                    // The device's clock moved (or ours drifted): the report carries the current one, already noted.
                    if oid == mib::usm_not_in_time_windows() && attempt < 2 {
                        continue;
                    }
                    if oid == mib::usm_unknown_engine_ids() && attempt < 2 {
                        self.engine = None;
                        continue;
                    }
                    return Err(Error::Auth(report_reason(&oid)));
                }
            }
        }
        Err(Error::Auth("the device's clock keeps disagreeing with ours".into()))
    }

    /// Learns the device's engine id and clock with an unauthenticated request for nothing.
    async fn discover(&mut self, v3: &V3) -> Result<(), Error> {
        let msg_id = self.id();
        let pdu = pdu(GET, self.id(), 0, 0, &[]);
        let scoped = ber::sequence(&[ber::octets(&[]), ber::octets(&[]), pdu]);
        let sec = ber::sequence(&[ber::octets(&[]), ber::int(0), ber::int(0), ber::octets(&[]), ber::octets(&[]), ber::octets(&[])]);
        let msg = v3_message(msg_id, 0x04, &sec, &scoped);
        let reply = self.exchange(&msg, |m| v3_msg_id(m) == Some(msg_id)).await?;
        let (engine_id, boots, time) = sec_params(&reply)?;
        if engine_id.is_empty() {
            return Err(Error::Auth("the device didn't say who it is".into()));
        }
        self.engine = Some(engine_for(v3, engine_id, boots, time));
        Ok(())
    }

    fn build_v3(&mut self, v3: &V3, msg_id: i32, pdu: &[u8]) -> Result<(Vec<u8>, i32), Error> {
        self.salt = self.salt.wrapping_add(1);
        let salt = self.salt;
        let e = self.engine.as_ref().expect("discovered");
        let (boots, time) = (e.boots, e.now());
        let mut flags = 0x04u8;
        let scoped = ber::sequence(&[ber::octets(&e.id), ber::octets(v3.context.as_bytes()), pdu.to_vec()]);
        let mut priv_params = Vec::new();
        let data = match (&v3.privacy, &e.priv_key) {
            (Some((proto, _)), Some(key)) => {
                flags |= 0x03;
                let (ct, params) = usm::encrypt(*proto, key, boots, time, salt, &scoped);
                priv_params = params;
                ber::octets(&ct)
            }
            _ => {
                if v3.auth.is_some() {
                    flags |= 0x01;
                }
                scoped
            }
        };
        let mac_len = v3.auth.as_ref().map_or(0, |(p, _)| p.mac_len());
        let sec = |mac: &[u8]| {
            ber::sequence(&[
                ber::octets(&e.id),
                ber::int(i64::from(boots)),
                ber::int(i64::from(time)),
                ber::octets(v3.user.as_bytes()),
                ber::octets(mac),
                ber::octets(&priv_params),
            ])
        };
        let mut msg = v3_message_raw(msg_id, flags, &sec(&vec![0u8; mac_len]), &data);
        if let (Some((proto, _)), Some(key)) = (&v3.auth, &e.auth_key) {
            let mac = proto.sign(key, &msg);
            msg = v3_message_raw(msg_id, flags, &sec(&mac), &data);
        }
        Ok((msg, msg_id))
    }

    fn parse_v3(&mut self, v3: &V3, raw: &[u8]) -> Result<V3Reply, Error> {
        let mut r = Reader::new(raw);
        let mut m = r.sequence()?;
        m.int()?;
        let mut global = m.sequence()?;
        global.int()?;
        global.int()?;
        let flags = global.octets()?.first().copied().unwrap_or(0);
        let model = global.int()?;
        if model != 3 {
            return Err(Error::Decode("not a USM message"));
        }
        let sec_bytes = m.octets()?;
        let mut sp = Reader::new(sec_bytes).sequence()?;
        let engine_id = sp.octets()?.to_vec();
        let boots = sp.int()? as u32;
        let time = sp.int()? as u32;
        let user = sp.octets()?;
        let auth_params = sp.octets()?;
        let priv_params = sp.octets()?;
        let is_report = flags & 0x04 == 0 && flags & 0x03 == 0;
        let _ = user;

        if flags & 0x01 != 0 {
            let (Some((proto, _)), Some(e)) = (&v3.auth, &self.engine) else {
                return Err(Error::Auth("the device authenticated a reply we didn't ask it to".into()));
            };
            let key = e.auth_key.as_ref().ok_or_else(|| Error::Auth("no key".into()))?;
            if auth_params.len() != proto.mac_len() {
                return Err(Error::Auth("the reply's authentication parameters have the wrong length".into()));
            }
            // The offset of the parameters within the datagram: they're a slice of it.
            let start = auth_params.as_ptr() as usize - raw.as_ptr() as usize;
            let mut zeroed = raw.to_vec();
            zeroed[start..start + auth_params.len()].fill(0);
            let want = proto.sign(key, &zeroed);
            if !constant_eq(&want, auth_params) {
                return Err(Error::Auth("the reply's signature is wrong: check the authentication passphrase and protocol".into()));
            }
        }

        let (tag, body) = m.read()?;
        let scoped = if tag == ber::OCTET_STRING {
            let (Some((_, _)), Some(e)) = (&v3.privacy, &self.engine) else {
                return Err(Error::Auth("the device encrypted a reply we didn't ask it to".into()));
            };
            let proto = v3.privacy.as_ref().map(|p| p.0).expect("checked");
            let key = e.priv_key.as_ref().ok_or_else(|| Error::Auth("no key".into()))?;
            usm::decrypt(proto, key, boots, time, priv_params, body)?
        } else {
            // Re-wrap so the one path below reads a SEQUENCE.
            ber::tlv(tag, body)
        };
        let mut sr = Reader::new(&scoped);
        let mut sc = sr.sequence().map_err(|_| Error::Auth("the reply couldn't be decrypted: check the privacy passphrase and protocol".into()))?;
        sc.octets()?;
        sc.octets()?;
        let (ptag, pbody) = sc.read()?;
        let parsed = parse_pdu(ptag, pbody)?;
        if ptag == REPORT || is_report {
            // Remember the clock the report gives so the retry lands in the time window.
            if !engine_id.is_empty() {
                let keep = self.engine.take();
                let fresh = engine_for(v3, engine_id, boots, time);
                self.engine = Some(match keep {
                    Some(old) if old.id == fresh.id => Engine { boots, time, synced: Instant::now(), ..old },
                    _ => fresh,
                });
            }
            let oid = parsed.binds.first().map(|b| b.0.clone()).unwrap_or_default();
            return Ok(V3Reply::Report(oid));
        }
        // An authenticated answer is also the freshest clock we have.
        if flags & 0x01 != 0
            && let Some(e) = self.engine.as_mut()
            && e.id == engine_id
        {
            e.boots = boots;
            e.time = time;
            e.synced = Instant::now();
        }
        Ok(V3Reply::Pdu(parsed))
    }
}

enum V3Reply {
    Pdu(Pdu),
    Report(Oid),
}

fn engine_for(v3: &V3, id: Vec<u8>, boots: u32, time: u32) -> Engine {
    let auth_key = v3.auth.as_ref().map(|(p, pass)| p.localize(pass, &id));
    // The privacy key is derived with the authentication protocol's hash.
    let priv_key = match (&v3.auth, &v3.privacy) {
        (Some((p, _)), Some((_, pass))) => Some(p.localize(pass, &id)),
        _ => None,
    };
    Engine { id, boots, time, synced: Instant::now(), auth_key, priv_key }
}

fn report_reason(oid: &Oid) -> String {
    if *oid == mib::usm_unknown_user_names() {
        "the device doesn't know this SNMPv3 user".into()
    } else if *oid == mib::usm_wrong_digests() {
        "the device rejected the signature: check the authentication passphrase and protocol".into()
    } else if *oid == mib::usm_unsupported_sec_levels() {
        "the user isn't allowed this security level (authentication and privacy)".into()
    } else if *oid == mib::usm_decryption_errors() {
        "the device couldn't decrypt the request: check the privacy passphrase and protocol".into()
    } else if *oid == mib::usm_not_in_time_windows() {
        "the device's clock keeps disagreeing with ours".into()
    } else {
        format!("the device sent a report we don't know ({oid})")
    }
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// A request or response PDU.
fn pdu(kind: u8, id: i32, a: u32, b: u32, oids: &[Oid]) -> Vec<u8> {
    let binds: Vec<Vec<u8>> = oids.iter().map(|o| ber::sequence(&[ber::oid(o), ber::value(&Value::Null)])).collect();
    ber::tlv(kind, &[ber::int(i64::from(id)), ber::int(i64::from(a)), ber::int(i64::from(b)), ber::sequence(&binds)].concat())
}

struct Pdu {
    status: i64,
    index: i64,
    binds: VarBinds,
}

impl Pdu {
    fn into_result(self) -> Result<VarBinds, Error> {
        if self.status != 0 {
            let name = match self.status {
                1 => "the answer was too big",
                2 => "no such name",
                3 => "bad value",
                4 => "read-only",
                5 => "generic error",
                6 | 16 => "access denied",
                _ => "error",
            };
            return Err(Error::Status(format!("{name} (status {}, at {})", self.status, self.index)));
        }
        Ok(self.binds)
    }
}

fn parse_pdu(tag: u8, body: &[u8]) -> Result<Pdu, Error> {
    if tag != RESPONSE && tag != REPORT {
        return Err(Error::Decode("not a response"));
    }
    let mut r = Reader::new(body);
    r.int()?;
    let status = r.int()?;
    let index = r.int()?;
    let mut list = r.sequence()?;
    let mut binds = Vec::new();
    while !list.is_empty() {
        let mut b = list.sequence()?;
        binds.push((b.oid()?, b.value()?));
    }
    Ok(Pdu { status, index, binds })
}

fn v2c_request_id(m: &[u8]) -> Option<i32> {
    let mut r = Reader::new(m);
    let mut m = r.sequence().ok()?;
    m.int().ok()?;
    m.octets().ok()?;
    let (_, body) = m.read().ok()?;
    Reader::new(body).int().ok().map(|i| i as i32)
}

fn v3_msg_id(m: &[u8]) -> Option<i32> {
    let mut r = Reader::new(m);
    let mut m = r.sequence().ok()?;
    m.int().ok()?;
    let mut g = m.sequence().ok()?;
    g.int().ok().map(|i| i as i32)
}

fn v3_message(msg_id: i32, flags: u8, sec: &[u8], data: &[u8]) -> Vec<u8> {
    v3_message_raw(msg_id, flags, sec, data)
}

fn v3_message_raw(msg_id: i32, flags: u8, sec: &[u8], data: &[u8]) -> Vec<u8> {
    ber::sequence(&[
        ber::int(3),
        ber::sequence(&[ber::int(i64::from(msg_id)), ber::int(MAX_MSG as i64), ber::octets(&[flags]), ber::int(3)]),
        ber::octets(sec),
        data.to_vec(),
    ])
}

/// The engine id, boots and time in a v3 message's security parameters.
fn sec_params(raw: &[u8]) -> Result<(Vec<u8>, u32, u32), Error> {
    let mut r = Reader::new(raw);
    let mut m = r.sequence()?;
    m.int()?;
    m.sequence()?;
    let mut sp = Reader::new(m.octets()?).sequence()?;
    Ok((sp.octets()?.to_vec(), sp.int()? as u32, sp.int()? as u32))
}

pub fn proto_names() -> (&'static [AuthProto], &'static [PrivProto]) {
    (
        &[AuthProto::Md5, AuthProto::Sha1, AuthProto::Sha224, AuthProto::Sha256, AuthProto::Sha384, AuthProto::Sha512],
        &[PrivProto::Des, PrivProto::Aes128],
    )
}
