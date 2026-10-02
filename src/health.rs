//! Minimal HTTP health probe, used by `logpit --healthcheck` (the container image
//! has no shell or curl to run a probe with).

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::time::Duration;

use anyhow::{Context, bail};

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

/// Succeeds if `GET /healthz` on `addr` answers with a 200.
pub fn check(addr: SocketAddr) -> anyhow::Result<()> {
    let mut stream = TcpStream::connect_timeout(&addr, TIMEOUT).context("connect failed")?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
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
