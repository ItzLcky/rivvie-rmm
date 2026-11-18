//! A small HTTP/1.1 client for downloads from our own server (signature databases): one GET,
//! resumable with `Range`, over the same rustls stack and native roots the agent socket uses,
//! so it adds no TLS library of its own. Integrity is the caller's business: what arrives is
//! checked against the hash and signature it was offered with.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

/// Nothing from the server for this long: give up (the caller retries, resuming).
const IDLE: Duration = Duration::from_secs(60);

trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

struct Url {
    tls: bool,
    host: String,
    port: u16,
    path: String,
}

fn parse(url: &str) -> Result<Url> {
    let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        bail!("not an http(s) URL: {url}");
    };
    let (authority, path) = rest.find('/').map_or((rest, "/"), |i| (&rest[..i], &rest[i..]));
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.ends_with(']') || authority.starts_with('[') => (h.to_string(), p.parse().context("port")?),
        _ => (authority.to_string(), if tls { 443 } else { 80 }),
    };
    Ok(Url { tls, host: host.trim_matches(['[', ']']).to_string(), port, path: path.to_string() })
}

fn tls_config() -> Result<Arc<rustls::ClientConfig>> {
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(c);
    }
    if roots.is_empty() {
        bail!("no trusted root certificates found on this machine");
    }
    // The provider named here, not the process default: no default means a panic otherwise.
    let c = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .context("TLS setup")?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(c))
}

async fn connect(u: &Url) -> Result<Box<dyn Stream>> {
    let tcp = tokio::time::timeout(IDLE, tokio::net::TcpStream::connect((u.host.as_str(), u.port))).await.map_err(|_| anyhow!("timed out connecting"))??;
    if !u.tls {
        return Ok(Box::new(tcp));
    }
    let name = rustls::pki_types::ServerName::try_from(u.host.clone()).context("server name")?;
    let tls = tokio_rustls::TlsConnector::from(tls_config()?).connect(name, tcp).await.context("TLS handshake")?;
    Ok(Box::new(tls))
}

async fn idle<T>(f: impl std::future::Future<Output = std::io::Result<T>>) -> Result<T> {
    Ok(tokio::time::timeout(IDLE, f).await.map_err(|_| anyhow!("the download stalled"))??)
}

/// Downloads `url` to `dest`, resuming a partial `dest` (it must be at most `size` bytes).
/// Stops at `size` bytes. `headers` are sent as given (authentication).
pub async fn download(url: &str, headers: &[(&str, String)], dest: &Path, size: u64) -> Result<()> {
    let u = parse(url)?;
    let have = std::fs::metadata(dest).map(|m| m.len()).unwrap_or(0);
    if have > size {
        std::fs::remove_file(dest)?;
    } else if have == size && size > 0 {
        return Ok(());
    }
    let have = std::fs::metadata(dest).map(|m| m.len()).unwrap_or(0);
    let mut s = connect(&u).await?;
    let mut req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: rmm-agent/{}\r\nAccept-Encoding: identity\r\nConnection: close\r\n",
        u.path,
        u.host,
        crate::collect::AGENT_VERSION
    );
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if have > 0 {
        req.push_str(&format!("Range: bytes={have}-\r\n"));
    }
    req.push_str("\r\n");
    idle(s.write_all(req.as_bytes())).await?;
    let mut r = BufReader::new(s);
    let mut status = String::new();
    idle(r.read_line(&mut status)).await?;
    let code: u16 = status.split_whitespace().nth(1).and_then(|c| c.parse().ok()).ok_or_else(|| anyhow!("bad response: {}", status.trim()))?;
    let (mut length, mut chunked) = (None, false);
    for _ in 0..100 {
        let mut line = String::new();
        idle(r.read_line(&mut line)).await?;
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            match k.trim().to_ascii_lowercase().as_str() {
                "content-length" => length = v.trim().parse::<u64>().ok(),
                "transfer-encoding" => chunked = v.to_ascii_lowercase().contains("chunked"),
                _ => {}
            }
        }
    }
    let append = match code {
        206 if have > 0 => true,
        200 => false,
        416 if have > 0 => {
            // What we hold doesn't fit what's there: start over next time.
            let _ = std::fs::remove_file(dest);
            bail!("the server refused the resume range");
        }
        c => bail!("the server answered {c}"),
    };
    let mut f = tokio::fs::OpenOptions::new().create(true).write(true).append(append).truncate(!append).open(dest).await?;
    let mut got = if append { have } else { 0 };
    let mut buf = vec![0u8; 64 * 1024];
    let mut left_in_chunk = if chunked { 0 } else { length.unwrap_or(u64::MAX) };
    loop {
        if chunked && left_in_chunk == 0 {
            let mut line = String::new();
            idle(r.read_line(&mut line)).await?;
            if line.trim().is_empty() {
                // The CRLF after the previous chunk.
                line.clear();
                idle(r.read_line(&mut line)).await?;
            }
            left_in_chunk = u64::from_str_radix(line.trim().split(';').next().unwrap_or("").trim(), 16).context("bad chunk size")?;
            if left_in_chunk == 0 {
                break;
            }
        }
        if left_in_chunk == 0 {
            break;
        }
        let want = (buf.len() as u64).min(left_in_chunk) as usize;
        let n = idle(r.read(&mut buf[..want])).await?;
        if n == 0 {
            break;
        }
        got += n as u64;
        if got > size {
            bail!("the server sent more than the {size} bytes offered");
        }
        f.write_all(&buf[..n]).await?;
        left_in_chunk -= n as u64;
    }
    f.flush().await?;
    if got != size {
        bail!("download ended at {got} of {size} bytes");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn urls() {
        let u = parse("https://rmm.example.com/api/agent/databases/v1").unwrap();
        assert_eq!((u.tls, u.host.as_str(), u.port, u.path.as_str()), (true, "rmm.example.com", 443, "/api/agent/databases/v1"));
        let u = parse("http://127.0.0.1:8080").unwrap();
        assert_eq!((u.tls, u.host.as_str(), u.port, u.path.as_str()), (false, "127.0.0.1", 8080, "/"));
        assert!(parse("ftp://x").is_err());
    }

    /// Serves `body` once per connection, honouring `Range`, optionally chunked.
    async fn server(body: Vec<u8>, chunked: bool) -> String {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = l.accept().await.unwrap();
                let mut req = vec![0u8; 4096];
                let n = s.read(&mut req).await.unwrap();
                let req = String::from_utf8_lossy(&req[..n]).to_string();
                assert!(req.contains("X-Test: yes"));
                let from = req.lines().find_map(|l| l.strip_prefix("Range: bytes=")).and_then(|r| r.trim_end_matches('-').parse::<usize>().ok());
                let part = &body[from.unwrap_or(0)..];
                let status = if from.is_some() { "206 Partial Content" } else { "200 OK" };
                if chunked {
                    let mut out = format!("HTTP/1.1 {status}\r\nTransfer-Encoding: chunked\r\n\r\n").into_bytes();
                    for c in part.chunks(7) {
                        out.extend(format!("{:x}\r\n", c.len()).bytes());
                        out.extend_from_slice(c);
                        out.extend_from_slice(b"\r\n");
                    }
                    out.extend_from_slice(b"0\r\n\r\n");
                    s.write_all(&out).await.unwrap();
                } else {
                    s.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\n\r\n", part.len()).as_bytes()).await.unwrap();
                    s.write_all(part).await.unwrap();
                }
            }
        });
        format!("http://{addr}/db")
    }

    #[tokio::test]
    async fn downloads_and_resumes() {
        let body: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let dir = std::env::temp_dir().join(format!("rmm-fetch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let h = [("X-Test", "yes".to_string())];
        for chunked in [false, true] {
            let url = server(body.clone(), chunked).await;
            let dest = dir.join(format!("db-{chunked}"));
            download(&url, &h, &dest, body.len() as u64).await.unwrap();
            assert_eq!(std::fs::read(&dest).unwrap(), body);
            // Half there from an interrupted run: only the rest is fetched.
            std::fs::write(&dest, &body[..40_000]).unwrap();
            download(&url, &h, &dest, body.len() as u64).await.unwrap();
            assert_eq!(std::fs::read(&dest).unwrap(), body);
            assert!(download(&url, &h, &dir.join("short"), 10).await.is_err(), "more than offered is refused");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
