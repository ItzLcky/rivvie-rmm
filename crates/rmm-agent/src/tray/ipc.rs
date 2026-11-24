//! The tray's local socket: frames of a u32 little-endian length and a MessagePack message,
//! [`TrayToAgent`] one way and [`AgentToTray`] the other.
//!
//! The service end reads from any local user, so the decoder is deliberately small: a length
//! over the cap ends the connection before anything is allocated for it, and a frame that
//! doesn't decode as one of the few messages below is an error, never a panic.

use anyhow::{Result, bail};
use rmm_proto::tray::{Config, MAX_SCREENSHOT};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

/// The largest frame either side accepts: a help request with the biggest screenshot, plus the
/// text and some slack.
pub const MAX_FRAME: usize = MAX_SCREENSHOT + 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum TrayToAgent {
    /// First message. `link`: a long-lived tray that shows consent prompts and notices for its
    /// session (the Windows icon, the Linux background process); otherwise a one-off.
    Hello {
        version: String,
        #[serde(default)]
        link: bool,
    },
    GetConfig,
    HelpRequest {
        subject: String,
        body: String,
        /// JPEG or PNG; empty for none.
        #[serde(default, with = "serde_bytes")]
        screenshot: Vec<u8>,
    },
    /// Answer to [`AgentToTray::Consent`].
    ConsentAnswer { id: Uuid, allow: bool },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum AgentToTray {
    /// `None` until the agent has heard from the server once.
    Config { config: Option<Config> },
    /// Answer to [`TrayToAgent::HelpRequest`]. `queued`: kept on the machine and sent when the
    /// server can be reached (no ticket number yet).
    HelpResult {
        request_id: Option<Uuid>,
        #[serde(default)]
        ticket_number: Option<i64>,
        #[serde(default)]
        queued: bool,
        #[serde(default)]
        error: Option<String>,
    },
    /// Ask the person in this session whether a technician may connect.
    Consent { id: Uuid, title: String, text: String, timeout_secs: u32 },
    /// A technician's remote session started (`active`) or ended.
    Notice { text: String, active: bool },
    /// The agent was updated: start again from the (new) binary.
    Restart,
    Error { message: String },
}

/// Accumulates bytes and splits off whole frames. Used by both ends; the async helpers below
/// are thin wrappers over it.
#[derive(Default)]
pub struct Decoder {
    buf: Vec<u8>,
}

impl Decoder {
    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// The next whole frame's payload, `None` if more bytes are needed, an error for a length
    /// over `max` (the connection should be dropped).
    pub fn next(&mut self, max: usize) -> Result<Option<Vec<u8>>> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_le_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
        if len > max {
            bail!("frame of {len} bytes is over the {max}-byte limit");
        }
        if self.buf.len() < 4 + len {
            return Ok(None);
        }
        let frame = self.buf[4..4 + len].to_vec();
        self.buf.drain(..4 + len);
        Ok(Some(frame))
    }

    /// Bytes still waiting for the rest of their frame.
    pub fn pending(&self) -> usize {
        self.buf.len()
    }
}

pub fn encode<T: Serialize>(msg: &T) -> Result<Vec<u8>> {
    let body = rmm_proto::encode(msg)?;
    if body.len() > MAX_FRAME {
        bail!("message of {} bytes is too large", body.len());
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

pub fn decode<T: for<'a> Deserialize<'a>>(frame: &[u8]) -> Result<T> {
    Ok(rmm_proto::decode(frame)?)
}

pub async fn write<T: Serialize>(w: &mut (impl AsyncWrite + Unpin), msg: &T) -> Result<()> {
    w.write_all(&encode(msg)?).await?;
    w.flush().await?;
    Ok(())
}

/// The next message, `None` at a clean end of stream.
pub async fn read<T: for<'a> Deserialize<'a>>(r: &mut (impl AsyncRead + Unpin), dec: &mut Decoder) -> Result<Option<T>> {
    let mut chunk = [0u8; 16 * 1024];
    loop {
        if let Some(frame) = dec.next(MAX_FRAME)? {
            return decode(&frame).map(Some);
        }
        let n = r.read(&mut chunk).await?;
        if n == 0 {
            if dec.pending() > 0 {
                bail!("connection closed in the middle of a message");
            }
            return Ok(None);
        }
        dec.push(&chunk[..n]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_split_and_join() {
        let a = TrayToAgent::Hello { version: "1".into(), link: true };
        let b = TrayToAgent::HelpRequest { subject: "Printer".into(), body: "jammed".into(), screenshot: vec![0xff, 0xd8, 1, 2] };
        let mut bytes = encode(&a).unwrap();
        bytes.extend(encode(&b).unwrap());
        // One byte at a time: nothing until a frame is whole.
        let mut d = Decoder::default();
        let mut got = vec![];
        for byte in &bytes {
            d.push(std::slice::from_ref(byte));
            while let Some(f) = d.next(MAX_FRAME).unwrap() {
                got.push(decode::<TrayToAgent>(&f).unwrap());
            }
        }
        assert_eq!(got, [a, b]);
        assert_eq!(d.pending(), 0);
    }

    #[test]
    fn oversized_and_malformed_frames_are_errors() {
        let mut d = Decoder::default();
        d.push(&(MAX_FRAME as u32 + 1).to_le_bytes());
        assert!(d.next(MAX_FRAME).is_err(), "over the cap before any payload arrives");
        let mut d = Decoder::default();
        d.push(&u32::MAX.to_le_bytes());
        assert!(d.next(MAX_FRAME).is_err());
        // A well-framed payload that isn't a message.
        for junk in [&b""[..], b"\xc1", b"\x81\xa1t\xa4nope", b"\x81\xa1t\xa8get_config\xc0", b"\xdd\xff\xff\xff\xff"] {
            assert!(decode::<TrayToAgent>(junk).is_err(), "{junk:?}");
        }
        assert!(decode::<TrayToAgent>(&rmm_proto::encode(&TrayToAgent::GetConfig).unwrap()).is_ok());
    }

    /// Random bytes through the decoder never panic, never yield a frame over the cap, and the
    /// frames that come out either decode or are rejected.
    #[test]
    fn fuzz_random_bytes() {
        // xorshift: deterministic, no dependency.
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mut decoded = 0;
        for round in 0..3000 {
            let len = (next() % 600) as usize;
            let mut bytes: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            // Often give it a plausible small length prefix so payloads reach the MessagePack decoder.
            if round % 2 == 0 && bytes.len() >= 4 {
                let n = ((next() % 64) as u32).min(bytes.len() as u32 - 4);
                bytes[..4].copy_from_slice(&n.to_le_bytes());
                // And sometimes a map with the tag key, so the enum's variant lookup runs.
                if round % 4 == 0 && n >= 4 {
                    bytes[4..8].copy_from_slice(b"\x82\xa1t\xab");
                }
            }
            let mut d = Decoder::default();
            let mut offset = 0;
            while offset < bytes.len() {
                let step = 1 + (next() % 97) as usize;
                let end = (offset + step).min(bytes.len());
                d.push(&bytes[offset..end]);
                offset = end;
                loop {
                    match d.next(4096) {
                        Ok(Some(f)) => {
                            assert!(f.len() <= 4096);
                            if decode::<TrayToAgent>(&f).is_ok() {
                                decoded += 1;
                            }
                            let _ = decode::<AgentToTray>(&f);
                        }
                        Ok(None) => break,
                        Err(_) => {
                            offset = bytes.len();
                            break;
                        }
                    }
                }
            }
        }
        // Not a requirement, but random input should essentially never be a valid message.
        assert!(decoded < 30, "{decoded}");
    }

    #[tokio::test]
    async fn async_read_write() {
        let (mut a, mut b) = tokio::io::duplex(64);
        let msg = AgentToTray::HelpResult { request_id: Some(Uuid::nil()), ticket_number: Some(42), queued: false, error: None };
        let m2 = msg.clone();
        let w = tokio::spawn(async move {
            write(&mut a, &m2).await.unwrap();
            write(&mut a, &AgentToTray::Restart).await.unwrap();
        });
        let mut d = Decoder::default();
        assert_eq!(read::<AgentToTray>(&mut b, &mut d).await.unwrap(), Some(msg));
        assert_eq!(read::<AgentToTray>(&mut b, &mut d).await.unwrap(), Some(AgentToTray::Restart));
        w.await.unwrap();
        assert_eq!(read::<AgentToTray>(&mut b, &mut d).await.unwrap(), None);
    }
}
