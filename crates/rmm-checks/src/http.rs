//! A minimal HTTP/1.1 client for monitors: one GET or HEAD, `Connection: close`, at most
//! [`MAX_BODY`] bytes read and [`MAX_REDIRECTS`] redirects followed. The body is only searched
//! for a keyword, never returned.

use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::Guard;
use crate::tls::Seen;

pub const MAX_BODY: usize = 256 * 1024;
pub const MAX_REDIRECTS: usize = 5;
const MAX_HEAD: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub tls: bool,
    pub host: String,
    pub port: u16,
    /// Path and query, starting with `/`.
    pub path: String,
}

impl Url {
    /// `http://` or `https://` only; credentials in the URL are refused (they would end up in
    /// logs and the database).
    pub fn parse(s: &str) -> Result<Url, String> {
        let s = s.trim();
        let (tls, rest) = if let Some(r) = s.get(..8).filter(|p| p.eq_ignore_ascii_case("https://")).map(|_| &s[8..]) {
            (true, r)
        } else if let Some(r) = s.get(..7).filter(|p| p.eq_ignore_ascii_case("http://")).map(|_| &s[7..]) {
            (false, r)
        } else {
            return Err("the URL must start with http:// or https://".into());
        };
        let rest = rest.split('#').next().unwrap_or("");
        let end = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, path) = (&rest[..end], &rest[end..]);
        if authority.contains('@') {
            return Err("URLs with a user name or password are refused".into());
        }
        if authority.is_empty() || authority.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err("the URL has no valid host".into());
        }
        let default = if tls { 443 } else { 80 };
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let (h, after) = v6.split_once(']').ok_or("unclosed [ in the URL")?;
            let port = match after.strip_prefix(':') {
                Some(p) => p.parse().map_err(|_| "bad port")?,
                None if after.is_empty() => default,
                None => return Err("bad host".into()),
            };
            (h.to_string(), port)
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), p.parse::<u16>().map_err(|_| "bad port")?),
                None => (authority.to_string(), default),
            }
        };
        if host.is_empty() || port == 0 {
            return Err("the URL has no valid host".into());
        }
        if path.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err("the URL's path has spaces or control characters".into());
        }
        let path = if path.is_empty() { "/".to_string() } else if path.starts_with('?') { format!("/{path}") } else { path.to_string() };
        Ok(Url { tls, host: host.to_ascii_lowercase(), port, path })
    }

    fn default_port(&self) -> bool {
        self.port == if self.tls { 443 } else { 80 }
    }

    /// The `Host` header.
    fn authority(&self) -> String {
        let h = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        if self.default_port() { h } else { format!("{h}:{}", self.port) }
    }

    /// A `Location` relative to this URL.
    pub fn join(&self, location: &str) -> Result<Url, String> {
        let l = location.trim();
        if l.len() > 7 && (l[..7].eq_ignore_ascii_case("http://") || l.get(..8).is_some_and(|p| p.eq_ignore_ascii_case("https://"))) {
            return Url::parse(l);
        }
        if let Some(rest) = l.strip_prefix("//") {
            return Url::parse(&format!("{}://{rest}", if self.tls { "https" } else { "http" }));
        }
        let path = if l.starts_with('/') {
            l.to_string()
        } else {
            let base = self.path.split('?').next().unwrap_or("/");
            format!("{}{l}", &base[..base.rfind('/').map_or(0, |i| i + 1)])
        };
        let path = if path.starts_with('/') { path } else { format!("/{path}") };
        Ok(Url { path: path.split('#').next().unwrap_or("/").to_string(), ..self.clone() })
    }
}

impl std::fmt::Display for Url {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://{}{}", if self.tls { "https" } else { "http" }, self.authority(), self.path)
    }
}

/// The head of a response: status and the headers we look at.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Head {
    pub status: u16,
    pub content_length: Option<usize>,
    pub chunked: bool,
    pub location: Option<String>,
    /// Bytes the head took, including the blank line.
    pub len: usize,
}

/// `HTTP/1.1 200 OK` → 200.
pub fn parse_status_line(line: &str) -> Option<u16> {
    let mut w = line.split_whitespace();
    let v = w.next()?;
    if !v.starts_with("HTTP/") {
        return None;
    }
    let code = w.next()?;
    if code.len() != 3 {
        return None;
    }
    code.parse().ok().filter(|c| (100..=599).contains(c))
}

/// Parses the head if `buf` holds all of it. `Err` for something that isn't HTTP.
pub fn parse_head(buf: &[u8]) -> Result<Option<Head>, String> {
    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return if buf.len() > MAX_HEAD { Err("the response headers are too large".into()) } else { Ok(None) };
    };
    let text = String::from_utf8_lossy(&buf[..end]);
    let mut lines = text.split("\r\n");
    let status = parse_status_line(lines.next().unwrap_or("")).ok_or("not an HTTP response")?;
    let mut h = Head { status, len: end + 4, ..Head::default() };
    for line in lines {
        let Some((k, v)) = line.split_once(':') else { continue };
        let v = v.trim();
        match k.trim().to_ascii_lowercase().as_str() {
            "content-length" => h.content_length = v.parse().ok(),
            "transfer-encoding" => h.chunked = v.to_ascii_lowercase().contains("chunked"),
            "location" => h.location = Some(v.to_string()),
            _ => {}
        }
    }
    Ok(Some(h))
}

/// Decodes a chunked body. Returns the data so far and whether the last chunk was seen.
pub fn dechunk(mut buf: &[u8]) -> Result<(Vec<u8>, bool), String> {
    let mut out = Vec::new();
    loop {
        let Some(eol) = buf.windows(2).position(|w| w == b"\r\n") else { return Ok((out, false)) };
        let line = std::str::from_utf8(&buf[..eol]).map_err(|_| "bad chunk size")?;
        let size = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16).map_err(|_| format!("bad chunk size {line:?}"))?;
        let data = &buf[eol + 2..];
        if size == 0 {
            return Ok((out, true));
        }
        if data.len() < size {
            out.extend_from_slice(data);
            return Ok((out, false));
        }
        out.extend_from_slice(&data[..size]);
        buf = data.get(size..).unwrap_or(&[]);
        buf = buf.strip_prefix(b"\r\n").unwrap_or(buf);
    }
}

/// Case-insensitive substring search, over the text of the body.
pub fn keyword_found(body: &[u8], keyword: &str) -> bool {
    let k = keyword.trim().to_lowercase();
    !k.is_empty() && String::from_utf8_lossy(body).to_lowercase().contains(&k)
}

#[derive(Debug, Clone)]
pub struct Request {
    pub url: String,
    pub head: bool,
    pub timeout: Duration,
}

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    /// Until the head of the final response arrived, redirects included.
    pub latency_ms: u32,
    pub redirects: usize,
    /// Where it ended up.
    pub url: String,
    /// The body (at most [`MAX_BODY`]); for keyword matching, not for reporting.
    pub body: Vec<u8>,
    /// The final hop's TLS handshake, for `https://`.
    pub tls: Option<Seen>,
}

trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// Fetches the URL, following redirects. Every hop's address goes past `guard`.
pub async fn fetch(req: &Request, guard: Guard) -> Result<Response, String> {
    let started = Instant::now();
    let deadline = started + req.timeout;
    let mut url = Url::parse(&req.url)?;
    for hop in 0..=MAX_REDIRECTS {
        let (head, body, tls) = one(&url, req.head, guard, deadline).await?;
        if matches!(head.status, 301 | 302 | 303 | 307 | 308)
            && let Some(loc) = head.location.as_deref()
        {
            if hop == MAX_REDIRECTS {
                return Err(format!("more than {MAX_REDIRECTS} redirects"));
            }
            url = url.join(loc)?;
            continue;
        }
        return Ok(Response { status: head.status, latency_ms: crate::millis(started.elapsed()), redirects: hop, url: url.to_string(), body, tls });
    }
    Err(format!("more than {MAX_REDIRECTS} redirects"))
}

async fn one(url: &Url, head_only: bool, guard: Guard, deadline: Instant) -> Result<(Head, Vec<u8>, Option<Seen>), String> {
    let left = deadline.saturating_duration_since(Instant::now());
    let addrs = crate::resolve(&url.host, url.port, guard, left).await?;
    let (tcp, _) = crate::tcp::connect_any(&addrs, deadline).await?;
    let (mut s, seen): (Box<dyn Stream>, Option<Seen>) = if url.tls {
        let (t, seen) = crate::tls::handshake(tcp, crate::tls::server_name(&url.host)?, true, deadline).await?;
        (Box::new(t), Some(seen))
    } else {
        (Box::new(tcp), None)
    };
    let req = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: rmm-uptime/{}\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        if head_only { "HEAD" } else { "GET" },
        url.path,
        url.authority(),
        env!("CARGO_PKG_VERSION"),
    );
    let io = |what: &'static str| move |e: std::io::Error| format!("{what}: {}", crate::tcp::describe(&e));
    let left = deadline.saturating_duration_since(Instant::now());
    tokio::time::timeout(left, s.write_all(req.as_bytes())).await.map_err(|_| "timed out sending the request".to_string())?.map_err(io("sending the request"))?;
    let mut buf = Vec::with_capacity(8192);
    let mut chunk = vec![0u8; 16 * 1024];
    let mut head: Option<Head> = None;
    loop {
        if let Some(h) = &head {
            let body = &buf[h.len..];
            let no_body = head_only || h.status < 200 || matches!(h.status, 204 | 304);
            let done = no_body
                || body.len() >= MAX_BODY
                || h.content_length.is_some_and(|n| body.len() >= n)
                || (h.chunked && dechunk(body).is_ok_and(|(_, last)| last));
            if done {
                break;
            }
        }
        let left = deadline.saturating_duration_since(Instant::now());
        let n = match tokio::time::timeout(left, s.read(&mut chunk)).await {
            Err(_) if head.is_some() => break, // a slow body doesn't fail a check whose status is in
            Err(_) => return Err("timed out waiting for the response".into()),
            Ok(Err(e)) if head.is_some() => {
                let _ = e;
                break;
            }
            Ok(Err(e)) => return Err(io("reading the response")(e)),
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
        };
        buf.extend_from_slice(&chunk[..n]);
        if head.is_none() {
            head = parse_head(&buf)?;
        }
    }
    let h = match head {
        Some(h) => h,
        None => return Err(if buf.is_empty() { "the server closed the connection without answering".into() } else { "incomplete response".into() }),
    };
    let raw = &buf[h.len.min(buf.len())..];
    let mut body = if h.chunked { dechunk(raw).map(|(b, _)| b).unwrap_or_default() } else { raw.to_vec() };
    if let Some(n) = h.content_length {
        body.truncate(n);
    }
    body.truncate(MAX_BODY);
    Ok((h, body, seen))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn urls() {
        let u = Url::parse("https://Example.com/a/b?q=1#frag").unwrap();
        assert_eq!(u, Url { tls: true, host: "example.com".into(), port: 443, path: "/a/b?q=1".into() });
        assert_eq!(u.to_string(), "https://example.com/a/b?q=1");
        let u = Url::parse("http://10.0.0.5:8080").unwrap();
        assert_eq!((u.port, u.path.as_str(), u.authority().as_str()), (8080, "/", "10.0.0.5:8080"));
        let u = Url::parse("http://[::1]:81/x").unwrap();
        assert_eq!((u.host.as_str(), u.port, u.authority().as_str()), ("::1", 81, "[::1]:81"));
        assert_eq!(Url::parse("http://h?x=1").unwrap().path, "/?x=1");
        for bad in ["ftp://x", "http://", "http://user:pw@host/", "http://a@b", "http://h:99999/", "http://h/a b", "example.com"] {
            assert!(Url::parse(bad).is_err(), "{bad}");
        }
        assert!(Url::parse("https://u:p@h/").unwrap_err().contains("password"));
        let base = Url::parse("http://h/dir/page?x").unwrap();
        assert_eq!(base.join("/top").unwrap().to_string(), "http://h/top");
        assert_eq!(base.join("other").unwrap().to_string(), "http://h/dir/other");
        assert_eq!(base.join("https://elsewhere:8443/z").unwrap().to_string(), "https://elsewhere:8443/z");
        assert_eq!(base.join("//cdn.example/p").unwrap().to_string(), "http://cdn.example/p");
        assert!(base.join("http://me:secret@evil/").is_err(), "credentials in a redirect too");
    }

    #[test]
    fn status_lines_and_heads() {
        assert_eq!(parse_status_line("HTTP/1.1 200 OK"), Some(200));
        assert_eq!(parse_status_line("HTTP/1.0 404"), Some(404));
        assert_eq!(parse_status_line("HTTP/2 503 Service Unavailable"), Some(503));
        for bad in ["", "SSH-2.0-OpenSSH", "HTTP/1.1 20 OK", "HTTP/1.1 abc", "HTTP/1.1 999 x"] {
            assert_eq!(parse_status_line(bad), None, "{bad:?}");
        }
        let raw = b"HTTP/1.1 301 Moved\r\nLocation: /new\r\nContent-Length: 0\r\nX: y\r\n\r\nrest";
        let h = parse_head(raw).unwrap().unwrap();
        assert_eq!(h, Head { status: 301, content_length: Some(0), chunked: false, location: Some("/new".into()), len: raw.len() - 4 });
        assert_eq!(parse_head(b"HTTP/1.1 200 OK\r\nContent-").unwrap(), None, "not all there yet");
        assert!(parse_head(b"garbage\r\n\r\n").is_err());
        let h = parse_head(b"HTTP/1.1 200 OK\r\ntransfer-encoding: Chunked\r\n\r\n").unwrap().unwrap();
        assert!(h.chunked && h.content_length.is_none());
    }

    #[test]
    fn chunked_bodies() {
        assert_eq!(dechunk(b"5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\n\r\n").unwrap(), (b"hello world".to_vec(), true));
        assert_eq!(dechunk(b"5\r\nhel").unwrap(), (b"hel".to_vec(), false), "a chunk cut short");
        assert_eq!(dechunk(b"a\r\n0123456789\r\n").unwrap(), (b"0123456789".to_vec(), false), "no last chunk yet");
        assert_eq!(dechunk(b"").unwrap(), (vec![], false));
        assert!(dechunk(b"zz\r\nhi\r\n").is_err());
    }

    #[test]
    fn keywords() {
        assert!(keyword_found(b"<h1>All systems Operational</h1>", "operational"));
        assert!(!keyword_found(b"<h1>Degraded</h1>", "operational"));
        assert!(!keyword_found(b"anything", "  "), "an empty keyword matches nothing");
        assert!(keyword_found("Ärger im Büro".as_bytes(), "ÄRGER"), "case folding beyond ASCII");
    }

    /// Answers each connection with the next of `replies` (the last one repeats).
    async fn serve(replies: Vec<Vec<u8>>) -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut i = 0;
            loop {
                let (mut s, _) = l.accept().await.unwrap();
                let mut req = vec![0u8; 4096];
                let _ = s.read(&mut req).await;
                let r = replies[i.min(replies.len() - 1)].clone();
                i += 1;
                let _ = s.write_all(&r).await;
            }
        });
        port
    }

    #[tokio::test]
    async fn fetches_follows_redirects_and_limits() {
        let port = serve(vec![
            b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nall \r\n2\r\nok\r\n0\r\n\r\n".to_vec(),
        ])
        .await;
        let r = fetch(&Request { url: format!("http://127.0.0.1:{port}/"), head: false, timeout: Duration::from_secs(5) }, crate::allow_all).await.unwrap();
        assert_eq!((r.status, r.redirects, r.body.as_slice()), (200, 1, &b"all ok"[..]));
        assert!(r.url.ends_with("/next") && r.tls.is_none());

        let looping = serve(vec![b"HTTP/1.1 301 Moved\r\nLocation: /again\r\n\r\n".to_vec()]).await;
        let e = fetch(&Request { url: format!("http://127.0.0.1:{looping}/"), head: false, timeout: Duration::from_secs(5) }, crate::allow_all).await.unwrap_err();
        assert!(e.contains("redirects"), "{e}");

        let big = vec![b'x'; MAX_BODY * 2];
        let mut reply = format!("HTTP/1.1 503 Busy\r\nContent-Length: {}\r\n\r\n", big.len()).into_bytes();
        reply.extend_from_slice(&big);
        let port = serve(vec![reply]).await;
        let r = fetch(&Request { url: format!("http://127.0.0.1:{port}/"), head: false, timeout: Duration::from_secs(5) }, crate::allow_all).await.unwrap();
        assert_eq!((r.status, r.body.len()), (503, MAX_BODY), "the body stops at the limit");

        let e = fetch(&Request { url: format!("http://127.0.0.1:{port}/"), head: true, timeout: Duration::from_secs(5) }, crate::addr::public_only).await.unwrap_err();
        assert!(e.contains("loopback"), "{e}");
        let silent = serve(vec![vec![]]).await;
        let e = fetch(&Request { url: format!("http://127.0.0.1:{silent}/"), head: true, timeout: Duration::from_secs(5) }, crate::allow_all).await.unwrap_err();
        assert!(e.contains("without answering"), "{e}");
    }
}
