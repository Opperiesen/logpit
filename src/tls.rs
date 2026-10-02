//! TLS for the syslog listener (RFC 5425), with optional client-certificate verification.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, bail};
use rustls::RootCertStore;
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::server::WebPkiClientVerifier;
use tokio_rustls::TlsAcceptor;

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
    let config = builder
        .with_single_cert(certs, key)
        .context("the certificate and private key do not match or are unusable")?;
    Ok(TlsAcceptor::from(Arc::new(config)))
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
        tokio::spawn(serve_tls(listener, sink, acceptor));
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
