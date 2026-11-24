//! A TLS handshake that reads the server's certificate. The verifier records what it was shown
//! and whether the chain is trusted by the machine's roots, and never rejects: an expired or
//! self-signed certificate is exactly what a certificate monitor wants to see. Signatures over
//! the handshake are still checked, so the server proved it holds the certificate's key.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use rustls::DigitallySignedStruct;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use crate::Guard;
use crate::x509::Cert;

/// What a handshake showed.
#[derive(Debug, Clone)]
pub struct Seen {
    pub cert: Option<Cert>,
    /// Why the machine's roots don't trust the chain (or the name doesn't match); None when they do.
    pub untrusted: Option<String>,
    pub protocol: Option<String>,
}

fn provider() -> Arc<CryptoProvider> {
    static P: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    P.get_or_init(|| Arc::new(rustls::crypto::ring::default_provider())).clone()
}

/// The machine's roots, loaded once.
fn webpki() -> Option<Arc<WebPkiServerVerifier>> {
    static V: OnceLock<Option<Arc<WebPkiServerVerifier>>> = OnceLock::new();
    V.get_or_init(|| {
        let mut roots = rustls::RootCertStore::empty();
        for c in rustls_native_certs::load_native_certs().certs {
            let _ = roots.add(c);
        }
        if roots.is_empty() {
            return None;
        }
        WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider()).build().ok()
    })
    .clone()
}

#[derive(Debug)]
struct Recorder {
    inner: Option<Arc<WebPkiServerVerifier>>,
    provider: Arc<CryptoProvider>,
    seen: Mutex<Option<(Vec<u8>, Option<String>)>>,
}

impl ServerCertVerifier for Recorder {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let untrusted = match &self.inner {
            Some(v) => v.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now).err().map(|e| e.to_string()),
            None => Some("no trusted root certificates on this machine".into()),
        };
        *self.seen.lock().unwrap_or_else(|e| e.into_inner()) = Some((end_entity.to_vec(), untrusted));
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// `host` as the name to present (SNI) and check the certificate against.
pub(crate) fn server_name(host: &str) -> Result<ServerName<'static>, String> {
    let h = host.trim_matches(['[', ']']);
    match h.parse::<std::net::IpAddr>() {
        Ok(ip) => Ok(ServerName::IpAddress(ip.into())),
        Err(_) => ServerName::try_from(h.to_string()).map_err(|_| format!("{h:?} isn't a valid server name")),
    }
}

/// Runs a handshake over `tcp`, returning the stream and what was seen.
pub(crate) async fn handshake(tcp: TcpStream, name: ServerName<'static>, alpn_http1: bool, deadline: Instant) -> Result<(TlsStream<TcpStream>, Seen), String> {
    let rec = Arc::new(Recorder { inner: webpki(), provider: provider(), seen: Mutex::new(None) });
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(rec.clone())
        .with_no_client_auth();
    if alpn_http1 {
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    }
    let left = deadline.saturating_duration_since(Instant::now());
    let stream = match tokio::time::timeout(left, tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(name, tcp)).await {
        Err(_) => return Err("timed out during the TLS handshake".into()),
        Ok(Err(e)) => return Err(format!("TLS handshake failed: {e}")),
        Ok(Ok(s)) => s,
    };
    let protocol = stream.get_ref().1.protocol_version().map(|v| format!("{v:?}").replace('_', "."));
    let (cert, untrusted) = match rec.seen.lock().unwrap_or_else(|e| e.into_inner()).take() {
        Some((der, untrusted)) => (crate::x509::parse(&der).ok(), untrusted),
        None => (None, Some("the server sent no certificate".into())),
    };
    Ok((stream, Seen { cert, untrusted, protocol }))
}

/// Connects to `host:port` and shakes hands, presenting `sni` (or `host`).
pub async fn inspect(host: &str, port: u16, sni: Option<&str>, guard: Guard, timeout: Duration) -> Result<(u32, Seen), String> {
    let deadline = Instant::now() + timeout;
    let addrs = crate::resolve(host, port, guard, timeout).await?;
    let started = Instant::now();
    let (tcp, _) = crate::tcp::connect_any(&addrs, deadline).await?;
    let name = server_name(sni.filter(|s| !s.is_empty()).unwrap_or(host))?;
    let (_stream, seen) = handshake(tcp, name, false, deadline).await?;
    Ok((crate::millis(started.elapsed()), seen))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A TLS server with a self-signed certificate for `localhost`, valid until `not_after`
    /// (y, m, d); answers HTTP requests with 200 and `body`.
    async fn server(not_after: (i32, u8, u8), body: &'static str) -> u16 {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(not_after.0, not_after.1, not_after.2);
        params.distinguished_name.push(rcgen::DnType::CommonName, "rmm-checks test");
        let cert = params.self_signed(&key).unwrap();
        let cfg = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()))
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (s, _) = l.accept().await.unwrap();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut t) = acceptor.accept(s).await else { return };
                    let mut buf = [0u8; 2048];
                    if t.read(&mut buf).await.unwrap_or(0) > 0 {
                        let _ = t.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes()).await;
                    }
                    let _ = t.shutdown().await;
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn reads_the_certificate_without_trusting_it() {
        let port = server((2041, 3, 4), "hello").await;
        let (ms, seen) = inspect("127.0.0.1", port, Some("localhost"), crate::allow_all, Duration::from_secs(5)).await.unwrap();
        assert!(ms < 5000);
        let cert = seen.cert.expect("the certificate");
        assert_eq!(cert.not_after.to_rfc3339(), "2041-03-04T00:00:00+00:00");
        assert_eq!(cert.subject, "CN=rmm-checks test");
        assert_eq!(cert.sans, ["localhost"]);
        assert!(seen.untrusted.is_some(), "self-signed: recorded as untrusted, not refused");
        assert!(seen.protocol.as_deref().is_some_and(|p| p.starts_with("TLS")), "{:?}", seen.protocol);

        // Over HTTPS the same: the response, and the certificate with it.
        let r = crate::http::fetch(&crate::http::Request { url: format!("https://localhost:{port}/"), head: false, timeout: Duration::from_secs(5) }, crate::allow_all).await.unwrap();
        assert_eq!((r.status, r.body.as_slice()), (200, &b"hello"[..]));
        let t = r.tls.unwrap();
        assert!(t.untrusted.is_some() && t.cert.is_some_and(|c| c.sans == ["localhost"]));

        // An expired one is read just the same.
        let old = server((2021, 1, 1), "").await;
        let (_, seen) = inspect("127.0.0.1", old, Some("localhost"), crate::allow_all, Duration::from_secs(5)).await.unwrap();
        assert!(seen.cert.unwrap().days_left(chrono::Utc::now()) < 0);
        // Nothing listening: a connection error, not a hang.
        let e = inspect("127.0.0.1", 1, None, crate::allow_all, Duration::from_secs(3)).await.unwrap_err();
        assert!(e.contains("refused"), "{e}");
    }
}
