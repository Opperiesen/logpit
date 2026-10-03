//! Minimal HTTP health probe, used by `logpit --healthcheck` (the container image
//! has no shell or curl to run a probe with).

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::time::Duration;

use std::sync::Arc;

use anyhow::{Context, bail};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, ring::default_provider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

const TIMEOUT: Duration = Duration::from_secs(3);

/// Turns a listen address into one that can be connected to (0.0.0.0 -> loopback).
pub fn probe_target(listen: SocketAddr) -> SocketAddr {
    let ip = match listen.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    SocketAddr::new(ip, listen.port())
}

fn connect(addr: SocketAddr) -> anyhow::Result<TcpStream> {
    let stream = TcpStream::connect_timeout(&addr, TIMEOUT).context("connect failed")?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    Ok(stream)
}

fn probe<S: Read + Write>(stream: &mut S) -> anyhow::Result<()> {
    stream.write_all(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n")?;
    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).context("no response")?;
    let head = String::from_utf8_lossy(&buf[..n]);
    if head.starts_with("HTTP/1.1 200") || head.starts_with("HTTP/1.0 200") {
        Ok(())
    } else {
        bail!("unhealthy: {}", head.lines().next().unwrap_or(""))
    }
}

/// Succeeds if `GET /healthz` on `addr` answers with a 200.
pub fn check(addr: SocketAddr) -> anyhow::Result<()> {
    probe(&mut connect(addr)?)
}

/// Succeeds if the server at `addr` accepts a connection: for a server that demands client
/// certificates, which the probe does not have.
pub fn check_connect(addr: SocketAddr) -> anyhow::Result<()> {
    connect(addr).map(|_| ())
}

/// Accepts whatever certificate the server shows: the probe asks its own server about liveness,
/// and the certificate is issued for a public name, not for `localhost`.
#[derive(Debug)]
struct AcceptAnyCertificate(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Like [`check`] for a server that speaks TLS, without checking its certificate.
pub fn check_tls(addr: SocketAddr) -> anyhow::Result<()> {
    let provider = Arc::new(default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .context("unsupported TLS protocol versions")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate(provider)))
        .with_no_client_auth();
    let conn = rustls::ClientConnection::new(Arc::new(config), ServerName::try_from("localhost")?)
        .context("cannot start the TLS handshake")?;
    let mut stream = rustls::StreamOwned::new(conn, connect(addr)?);
    probe(&mut stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn serve_once(reply: &'static [u8]) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 256];
                let _ = s.read(&mut buf);
                let _ = s.write_all(reply);
            }
        });
        addr
    }

    #[test]
    fn healthy_and_unhealthy_responses() {
        assert!(
            check(serve_once(
                b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok"
            ))
            .is_ok()
        );
        assert!(check(serve_once(b"HTTP/1.1 500 Internal Server Error\r\n\r\n")).is_err());
    }

    #[test]
    fn closed_port_is_unhealthy() {
        let addr = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap()
        };
        assert!(check(addr).is_err());
    }

    #[test]
    fn unspecified_addresses_probe_loopback() {
        let t = probe_target("0.0.0.0:8080".parse().unwrap());
        assert_eq!(t, "127.0.0.1:8080".parse().unwrap());
        let t = probe_target("[::]:8080".parse().unwrap());
        assert_eq!(t, "[::1]:8080".parse().unwrap());
        let keep: SocketAddr = "192.168.1.5:9".parse().unwrap();
        assert_eq!(probe_target(keep), keep);
    }
}
