//! TLS for the syslog listener (RFC 5425) and for the HTTPS listener of the web UI and API, with
//! optional client-certificate verification.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use rustls::RootCertStore;
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::server::WebPkiClientVerifier;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

use crate::live::Reloadable;
use crate::metrics::Metrics;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Handshakes in progress at once; a connection beyond that is closed, so a flood of half-open
/// connections cannot pile up tasks.
const MAX_HANDSHAKES: usize = 256;
/// Finished handshakes waiting for the server to pick them up.
const READY_QUEUE: usize = 64;

fn load_certs(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let certs: Vec<_> = CertificateDer::pem_file_iter(path)
        .with_context(|| format!("cannot read certificates from {}", path.display()))?
        .collect::<Result<_, _>>()
        .with_context(|| format!("invalid certificate in {}", path.display()))?;
    if certs.is_empty() {
        bail!("{} contains no certificate", path.display());
    }
    Ok(certs)
}

/// Builds the server side of TLS 1.2/1.3 from PEM files: `cert` (the leaf first, then any
/// intermediates) and its private `key`. With `client_ca`, clients must present a certificate
/// issued by one of the CAs in that PEM file; without it any client may connect.
pub fn build_acceptor(
    cert: &Path,
    key: &Path,
    client_ca: Option<&Path>,
) -> anyhow::Result<TlsAcceptor> {
    let certs = load_certs(cert)?;
    let key = PrivateKeyDer::from_pem_file(key)
        .with_context(|| format!("cannot read a private key from {}", key.display()))?;
    let provider = Arc::new(default_provider());
    let builder = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .context("unsupported TLS protocol versions")?;
    let builder = match client_ca {
        Some(ca) => {
            let mut roots = RootCertStore::empty();
            for cert in load_certs(ca)? {
                roots
                    .add(cert)
                    .with_context(|| format!("invalid CA certificate in {}", ca.display()))?;
            }
            let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .context("cannot build the client certificate verifier")?;
            builder.with_client_cert_verifier(verifier)
        }
        None => builder.with_no_client_auth(),
    };
    let mut config = builder
        .with_single_cert(certs, key)
        .context("the certificate and private key do not match or are unusable")?;
    // The HTTPS listener speaks HTTP/2 too (gRPC needs it); other users ignore the negotiation.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// The HTTPS listener: accepts TCP connections and finishes their TLS handshakes concurrently
/// (a client that stalls halfway never delays the others), handing only completed connections to
/// `axum::serve`. The certificate is read from `acceptor` for each connection, so a reload takes
/// effect for the next one.
pub struct HttpsListener {
    ready: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    local: SocketAddr,
}

impl HttpsListener {
    pub fn new(
        tcp: TcpListener,
        acceptor: Arc<Reloadable<TlsAcceptor>>,
        metrics: Arc<Metrics>,
    ) -> std::io::Result<Self> {
        let local = tcp.local_addr()?;
        let (tx, ready) = mpsc::channel(READY_QUEUE);
        let slots = Arc::new(Semaphore::new(MAX_HANDSHAKES));
        tokio::spawn(async move {
            loop {
                let (stream, peer) = match tcp.accept().await {
                    Ok(c) => c,
                    Err(e) => {
                        // Out of file descriptors and the like: back off instead of spinning.
                        tracing::warn!("HTTPS accept failed: {e}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let Ok(permit) = slots.clone().try_acquire_owned() else {
                    Metrics::inc(&metrics.tls_failures, 1);
                    continue;
                };
                let (tx, acceptor, metrics) = (tx.clone(), acceptor.get(), metrics.clone());
                tokio::spawn(async move {
                    let _permit = permit;
                    match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                        Ok(Ok(tls)) => {
                            let _ = tx.send((tls, peer)).await;
                        }
                        // A probe, a plain-HTTP client or a refused client certificate.
                        _ => Metrics::inc(&metrics.tls_failures, 1),
                    }
                });
            }
        });
        Ok(Self { ready, local })
    }
}

/// The address of the peer of an HTTPS connection, as request extension (`ConnectInfo`): axum
/// only knows how to provide `SocketAddr` for its own plain TCP listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerAddr(pub SocketAddr);

impl axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, HttpsListener>>
    for PeerAddr
{
    fn connect_info(stream: axum::serve::IncomingStream<'_, HttpsListener>) -> Self {
        PeerAddr(*stream.remote_addr())
    }
}

impl axum::serve::Listener for HttpsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.ready.recv().await {
            Some(conn) => conn,
            // The accept task only ends with the runtime.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.local)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::{Receiver, sync_channel};
    use std::time::Duration;

    use rcgen::KeyPair;
    use rustls::pki_types::ServerName;
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsConnector;

    use super::testpki::pki;
    use super::*;
    use crate::ingest::{Sink, serve_tls};
    use crate::metrics::Metrics;
    use crate::model::LogEntry;
    use crate::silence::Tracker;

    /// Starts a TLS listener on a free port with a sink whose entries are returned on `Receiver`.
    async fn start(acceptor: TlsAcceptor) -> (u16, Receiver<LogEntry>, Arc<Metrics>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = sync_channel(100);
        let metrics = Arc::new(Metrics::default());
        let sink = Sink::new(
            tx,
            metrics.clone(),
            16 * 1024,
            Arc::new(Tracker::new(false)),
        );
        tokio::spawn(serve_tls(
            listener,
            sink,
            Arc::new(crate::live::Reloadable::new(acceptor)),
        ));
        (port, rx, metrics)
    }

    fn connector(trust_pem: &str, client: Option<(&str, &str)>) -> TlsConnector {
        let mut roots = RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(trust_pem.as_bytes()) {
            roots.add(cert.unwrap()).unwrap();
        }
        let builder = rustls::ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots);
        let config = match client {
            Some((cert, key)) => builder
                .with_client_auth_cert(
                    CertificateDer::pem_slice_iter(cert.as_bytes())
                        .collect::<Result<_, _>>()
                        .unwrap(),
                    PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap(),
                )
                .unwrap(),
            None => builder.with_no_client_auth(),
        };
        TlsConnector::from(Arc::new(config))
    }

    async fn send(port: u16, conn: &TlsConnector, payload: &[u8]) -> std::io::Result<()> {
        let tcp = TcpStream::connect(("127.0.0.1", port)).await?;
        let mut tls = conn
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await?;
        tls.write_all(payload).await?;
        tls.flush().await?;
        // Wait for the server to act on it (and, for a rejected client certificate, to alert us).
        let mut buf = [0u8; 1];
        let _ = tokio::time::timeout(
            Duration::from_millis(300),
            tokio::io::AsyncReadExt::read(&mut tls, &mut buf),
        )
        .await;
        tls.shutdown().await
    }

    async fn next(rx: Receiver<LogEntry>) -> (Option<LogEntry>, Receiver<LogEntry>) {
        tokio::task::spawn_blocking(move || (rx.recv_timeout(Duration::from_secs(3)).ok(), rx))
            .await
            .unwrap()
    }

    const MSG_A: &str = "<14>1 2026-10-03T12:00:00Z myhost app 1 - - first over tls";
    const MSG_B: &str = "<14>1 2026-10-03T12:00:01Z myhost app 1 - - second over tls";

    #[tokio::test]
    async fn accepts_octet_counted_and_newline_framing_over_tls() {
        let pki = pki("plain");
        let acceptor = build_acceptor(&pki.server_cert, &pki.server_key, None).unwrap();
        let (port, rx, _) = start(acceptor).await;
        let conn = connector(&pki.ca_pem, None);

        let payload = format!("{} {MSG_A}{MSG_B}\n", MSG_A.len());
        send(port, &conn, payload.as_bytes()).await.unwrap();
        let (first, rx) = next(rx).await;
        let (second, _) = next(rx).await;
        assert!(first.unwrap().message.contains("first over tls"));
        assert!(second.unwrap().message.contains("second over tls"));
        std::fs::remove_dir_all(&pki.dir).ok();
    }

    #[tokio::test]
    async fn clients_that_do_not_trust_the_server_cannot_send() {
        let pki = pki("untrusted");
        let acceptor = build_acceptor(&pki.server_cert, &pki.server_key, None).unwrap();
        let (port, rx, metrics) = start(acceptor).await;
        // A client with an empty trust store refuses the server certificate.
        let conn = connector("", None);
        assert!(
            send(port, &conn, format!("{MSG_A}\n").as_bytes())
                .await
                .is_err()
        );
        let (got, _) = next(rx).await;
        assert!(got.is_none());
        // The failed handshake is counted on the server side.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            metrics
                .tls_failures
                .load(std::sync::atomic::Ordering::Relaxed)
                >= 1
        );
        std::fs::remove_dir_all(&pki.dir).ok();
    }

    #[tokio::test]
    async fn client_certificates_are_required_when_a_client_ca_is_set() {
        let pki = pki("mtls");
        let acceptor =
            build_acceptor(&pki.server_cert, &pki.server_key, Some(&pki.ca_file)).unwrap();
        let (port, rx, _) = start(acceptor).await;
        let line = format!("{MSG_A}\n");

        // Without a client certificate nothing gets through.
        let anonymous = connector(&pki.ca_pem, None);
        let _ = send(port, &anonymous, line.as_bytes()).await;
        let (got, rx) = next(rx).await;
        assert!(got.is_none(), "an anonymous client must be refused");

        // With a certificate issued by the configured CA the message is accepted.
        let authenticated = connector(
            &pki.ca_pem,
            Some((&pki.client_cert_pem, &pki.client_key_pem)),
        );
        send(port, &authenticated, line.as_bytes()).await.unwrap();
        let (got, _) = next(rx).await;
        assert!(got.unwrap().message.contains("first over tls"));
        std::fs::remove_dir_all(&pki.dir).ok();
    }

    #[test]
    fn bad_certificate_files_are_reported() {
        let pki = pki("bad");
        let missing = pki.dir.join("missing.pem");
        assert!(build_acceptor(&missing, &pki.server_key, None).is_err());
        assert!(build_acceptor(&pki.server_cert, &missing, None).is_err());
        // A key file that holds a certificate, and a certificate file that holds a key.
        assert!(build_acceptor(&pki.server_cert, &pki.server_cert, None).is_err());
        assert!(build_acceptor(&pki.server_key, &pki.server_key, None).is_err());
        assert!(build_acceptor(&pki.server_cert, &pki.server_key, Some(&missing)).is_err());
        // A key that does not belong to the certificate.
        let other = KeyPair::generate().unwrap();
        let other_key = pki.dir.join("other.key");
        std::fs::write(&other_key, other.serialize_pem()).unwrap();
        assert!(build_acceptor(&pki.server_cert, &other_key, None).is_err());
        // The matching pair works.
        assert!(build_acceptor(&pki.server_cert, &pki.server_key, None).is_ok());
        std::fs::remove_dir_all(&pki.dir).ok();
    }
}

/// Throwaway certificates for tests: a CA, a `localhost` server certificate and a client certificate.
#[cfg(test)]
pub(crate) mod testpki {
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;

    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        SanType,
    };

    pub struct Pki {
        pub dir: PathBuf,
        pub ca_pem: String,
        pub server_cert: PathBuf,
        pub server_key: PathBuf,
        pub ca_file: PathBuf,
        pub client_cert_pem: String,
        pub client_key_pem: String,
    }

    fn name(cn: &str) -> rcgen::DistinguishedName {
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        dn
    }

    /// A throwaway CA with a `localhost` server certificate and a client certificate.
    pub fn pki(tag: &str) -> Pki {
        let dir = std::env::temp_dir().join(format!("logpit-tls-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.distinguished_name = name("test ca");
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(ca_params, ca_key);

        let server_key = KeyPair::generate().unwrap();
        let mut server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        server_params
            .subject_alt_names
            .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server = server_params.signed_by(&server_key, &issuer).unwrap();

        let client_key = KeyPair::generate().unwrap();
        let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        client_params.distinguished_name = name("test client");
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client = client_params.signed_by(&client_key, &issuer).unwrap();

        let write = |file: &str, text: String| {
            let path = dir.join(file);
            std::fs::write(&path, text).unwrap();
            path
        };
        Pki {
            ca_pem: ca.pem(),
            server_cert: write("server.pem", server.pem()),
            server_key: write("server.key", server_key.serialize_pem()),
            ca_file: write("ca.pem", ca.pem()),
            client_cert_pem: client.pem(),
            client_key_pem: client_key.serialize_pem(),
            dir,
        }
    }
}

#[cfg(test)]
mod https_tests {
    use std::time::Duration;

    use axum::Router;
    use axum::extract::ConnectInfo;
    use axum::routing::get;
    use rustls::pki_types::ServerName;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::TlsConnector;

    use super::testpki::{Pki, pki};
    use super::*;

    struct Https {
        port: u16,
        acceptor: Arc<Reloadable<TlsAcceptor>>,
        metrics: Arc<Metrics>,
    }

    async fn start(p: &Pki, client_ca: bool) -> Https {
        let acceptor = build_acceptor(
            &p.server_cert,
            &p.server_key,
            client_ca.then_some(p.ca_file.as_path()),
        )
        .unwrap();
        let acceptor = Arc::new(Reloadable::new(acceptor));
        let metrics = Arc::new(Metrics::default());
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = tcp.local_addr().unwrap().port();
        let listener = HttpsListener::new(tcp, acceptor.clone(), metrics.clone()).unwrap();
        let app =
            Router::new()
                .route("/healthz", get(|| async { "ok" }))
                .route(
                    "/peer",
                    get(
                        |ConnectInfo(PeerAddr(a)): ConnectInfo<PeerAddr>| async move {
                            a.ip().to_string()
                        },
                    ),
                );
        let service = app.into_make_service_with_connect_info::<PeerAddr>();
        tokio::spawn(async move {
            let _ = axum::serve(listener, service).await;
        });
        Https {
            port,
            acceptor,
            metrics,
        }
    }

    fn connector(trust_pem: &str, client: Option<(&str, &str)>) -> TlsConnector {
        let mut roots = RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(trust_pem.as_bytes()) {
            roots.add(cert.unwrap()).unwrap();
        }
        let builder = rustls::ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots);
        let config = match client {
            Some((cert, key)) => builder
                .with_client_auth_cert(
                    CertificateDer::pem_slice_iter(cert.as_bytes())
                        .collect::<Result<_, _>>()
                        .unwrap(),
                    PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap(),
                )
                .unwrap(),
            None => builder.with_no_client_auth(),
        };
        TlsConnector::from(Arc::new(config))
    }

    /// Waits until at least `n` handshake failures are counted (the server notices them after the
    /// client has already given up).
    async fn failures_reach(metrics: &Metrics, n: u64) {
        for _ in 0..200 {
            if metrics
                .tls_failures
                .load(std::sync::atomic::Ordering::Relaxed)
                >= n
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("no handshake failure was counted");
    }

    /// `GET path` over TLS; returns the body, and the certificate the server showed.
    async fn get_body(
        port: u16,
        conn: &TlsConnector,
        path: &str,
    ) -> std::io::Result<(String, Vec<u8>)> {
        let tcp = TcpStream::connect(("127.0.0.1", port)).await?;
        let mut tls = conn
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await?;
        let cert = tls.get_ref().1.peer_certificates().unwrap()[0]
            .as_ref()
            .to_vec();
        tls.write_all(format!("GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n").as_bytes())
            .await?;
        let mut raw = Vec::new();
        // With client certificates (TLS 1.3) a refusal only shows up when reading.
        tls.read_to_end(&mut raw).await?;
        let text = String::from_utf8_lossy(&raw).to_string();
        Ok((
            text.split_once("\r\n\r\n")
                .map_or(String::new(), |(_, b)| b.to_string()),
            cert,
        ))
    }

    #[tokio::test]
    async fn http2_is_negotiated_over_tls_for_clients_that_ask_for_it() {
        let p = pki("https-h2");
        let s = start(&p, false).await;
        let mut roots = RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(p.ca_pem.as_bytes()) {
            roots.add(cert.unwrap()).unwrap();
        }
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let tcp = TcpStream::connect(("127.0.0.1", s.port)).await.unwrap();
        let tls = TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
        let (mut client, connection) = h2::client::handshake(tls).await.unwrap();
        tokio::spawn(connection);
        let req = axum::http::Request::builder()
            .uri("https://localhost/peer")
            .body(())
            .unwrap();
        let (response, _) = client.send_request(req, true).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), 200);
        let mut body = response.into_body();
        let chunk = body.data().await.unwrap().unwrap();
        assert_eq!(&chunk[..], b"127.0.0.1");
        let _ = std::fs::remove_dir_all(&p.dir);
    }

    #[tokio::test]
    async fn requests_are_served_over_tls_with_the_peer_address() {
        let p = pki("https-basic");
        let s = start(&p, false).await;
        let c = connector(&p.ca_pem, None);
        let (body, _) = get_body(s.port, &c, "/healthz").await.unwrap();
        assert_eq!(body, "ok");
        let (peer, _) = get_body(s.port, &c, "/peer").await.unwrap();
        assert_eq!(peer, "127.0.0.1");
        // A client that does not trust the certificate cannot talk to it.
        let stranger = connector(&pki("https-stranger").ca_pem, None);
        assert!(get_body(s.port, &stranger, "/healthz").await.is_err());
        failures_reach(&s.metrics, 1).await;
        let _ = std::fs::remove_dir_all(&p.dir);
    }

    #[tokio::test]
    async fn plain_http_and_stalled_clients_do_not_block_the_others() {
        let p = pki("https-stall");
        let s = start(&p, false).await;
        // A client that connects and says nothing keeps its handshake open...
        let _stalled = TcpStream::connect(("127.0.0.1", s.port)).await.unwrap();
        // ...and one that speaks plain HTTP is turned away, without holding anyone up.
        let mut plain = TcpStream::connect(("127.0.0.1", s.port)).await.unwrap();
        plain
            .write_all(b"GET /healthz HTTP/1.0\r\n\r\n")
            .await
            .unwrap();
        let c = connector(&p.ca_pem, None);
        let started = std::time::Instant::now();
        let (body, _) = get_body(s.port, &c, "/healthz").await.unwrap();
        assert_eq!(body, "ok");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "served while another handshake hung"
        );
        let mut sink = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), plain.read_to_end(&mut sink)).await;
        assert!(
            !String::from_utf8_lossy(&sink).contains("ok"),
            "plain HTTP got an answer"
        );
        failures_reach(&s.metrics, 1).await;
        let _ = std::fs::remove_dir_all(&p.dir);
    }

    #[tokio::test]
    async fn client_certificates_are_required_when_a_ca_is_given() {
        let p = pki("https-mtls");
        let s = start(&p, true).await;
        let without = connector(&p.ca_pem, None);
        assert!(get_body(s.port, &without, "/healthz").await.is_err());
        let with = connector(&p.ca_pem, Some((&p.client_cert_pem, &p.client_key_pem)));
        assert_eq!(get_body(s.port, &with, "/healthz").await.unwrap().0, "ok");
        let _ = std::fs::remove_dir_all(&p.dir);
    }

    #[tokio::test]
    async fn a_reloaded_certificate_is_used_by_the_next_connection() {
        let first = pki("https-reload-a");
        let second = pki("https-reload-b");
        let s = start(&first, false).await;
        let (_, cert_a) = get_body(s.port, &connector(&first.ca_pem, None), "/healthz")
            .await
            .unwrap();
        // Replace the acceptor, as a reload does after the files changed.
        s.acceptor.set(Arc::new(
            build_acceptor(&second.server_cert, &second.server_key, None).unwrap(),
        ));
        let (_, cert_b) = get_body(s.port, &connector(&second.ca_pem, None), "/healthz")
            .await
            .unwrap();
        assert_ne!(cert_a, cert_b);
        // The old CA no longer vouches for what the server presents.
        assert!(
            get_body(s.port, &connector(&first.ca_pem, None), "/healthz")
                .await
                .is_err()
        );
        let _ = std::fs::remove_dir_all(&first.dir);
        let _ = std::fs::remove_dir_all(&second.dir);
    }

    #[tokio::test]
    async fn the_health_probe_works_over_tls_and_with_client_certificates() {
        let p = pki("https-health");
        let s = start(&p, false).await;
        let addr: SocketAddr = ([127, 0, 0, 1], s.port).into();
        // The probe runs on a blocking thread: it uses plain std sockets.
        let r = tokio::task::spawn_blocking(move || {
            (
                crate::health::check_tls(addr),
                crate::health::check(addr),
                crate::health::check_connect(addr),
            )
        })
        .await
        .unwrap();
        assert!(r.0.is_ok(), "{:?}", r.0);
        assert!(r.1.is_err(), "a plain probe cannot read a TLS server");
        assert!(r.2.is_ok());
        let mtls = start(&p, true).await;
        let addr: SocketAddr = ([127, 0, 0, 1], mtls.port).into();
        let r = tokio::task::spawn_blocking(move || {
            (
                crate::health::check_tls(addr),
                crate::health::check_connect(addr),
            )
        })
        .await
        .unwrap();
        assert!(r.0.is_err(), "it has no certificate to show");
        assert!(r.1.is_ok());
        let _ = std::fs::remove_dir_all(&p.dir);
    }
}
