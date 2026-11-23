//! Shared policy for Ramparts' network-facing modes (`ramparts server`,
//! `ramparts mcp-http` / `mcp-sse`), where scan requests may come from
//! remote callers.
//!
//! - Private destinations (loopback, RFC 1918) may be scanned: internal MCP
//!   servers are a normal target. Only cloud metadata addresses are refused,
//!   since they hand out the host's cloud credentials and are never an MCP
//!   server.
//! - Remote mode makes the scanner refuse local-process (`stdio:`) targets
//!   at its own dispatch, whatever entry point a request came through.
//! - Startup helpers (token, bind address, Host check) are shared by both
//!   modes.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use axum::{
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use serde_json::json;
use tracing::warn;

static REMOTE_MODE: AtomicBool = AtomicBool::new(false);

/// Called by the network-facing modes at startup.
pub fn enter_remote_mode() {
    REMOTE_MODE.store(true, Ordering::SeqCst);
}

/// True once a network-facing mode has started: scan targets come from
/// callers who must not be able to start local processes.
pub fn remote_mode() -> bool {
    REMOTE_MODE.load(Ordering::SeqCst)
}

/// Cloud metadata / link-local addresses (169.254.0.0/16, fe80::/10, AWS's
/// fd00:ec2::254), including IPv4 written in IPv6 form (mapped, compatible,
/// NAT64 and 6to4), which a dual-stack socket reaches over IPv4.
pub fn is_metadata_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => {
            if let Some(v4) = embedded_v4(v6) {
                return v4.is_link_local();
            }
            (v6.segments()[0] & 0xffc0) == 0xfe80
                || v6 == Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254)
        }
    }
}

/// The IPv4 address inside an IPv4-mapped (`::ffff:a.b.c.d`), IPv4-compatible
/// (`::a.b.c.d`), NAT64 (`64:ff9b::a.b.c.d`) or 6to4 (`2002:aabb:ccdd::`)
/// IPv6 address.
fn embedded_v4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = v6.to_ipv4_mapped() {
        return Some(v4);
    }
    let s = v6.segments();
    let o = v6.octets();
    let tail = Ipv4Addr::new(o[12], o[13], o[14], o[15]);
    if s[..6] == [0, 0, 0, 0, 0, 0] && !v6.is_loopback() && !v6.is_unspecified() {
        return Some(tail); // IPv4-compatible (deprecated)
    }
    if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return Some(tail); // NAT64
    }
    if s[0] == 0x2002 {
        return Some(Ipv4Addr::new(o[2], o[3], o[4], o[5])); // 6to4
    }
    None
}

/// `host` without IPv6 brackets (`[::1]` -> `::1`).
pub fn bare_host(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

pub fn is_loopback_host(host: &str) -> bool {
    let host = bare_host(host).trim_end_matches('.');
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Socket address for `--host` / `--port`, accepting IPv6 with or without
/// brackets and host names.
pub async fn resolve_bind(host: &str, port: u16) -> std::io::Result<SocketAddr> {
    let bare = bare_host(host);
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    tokio::net::lookup_host((bare, port))
        .await?
        .next()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("could not resolve {host}"),
            )
        })
}

/// `RAMPARTS_API_TOKEN`, if set. Warns when the listener is reachable beyond
/// loopback without one.
pub fn api_token(bind_host: &str, mode: &str) -> Option<Arc<str>> {
    let token: Option<Arc<str>> = std::env::var("RAMPARTS_API_TOKEN")
        .ok()
        .filter(|t| !t.is_empty())
        .map(Into::into);
    if token.is_none() && !is_loopback_host(bind_host) {
        warn!(
            "RAMPARTS_API_TOKEN is not set and {mode} binds {bind_host}: it is \
             unauthenticated. Set a token or bind 127.0.0.1."
        );
    }
    token
}

/// Bearer-token check when a token is configured. The scheme name is
/// case-insensitive (RFC 7235); the token is compared in constant time.
pub async fn require_token(token: Option<Arc<str>>, request: Request, next: Next) -> Response {
    let Some(token) = token else {
        return next.run(request).await;
    };
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
        .map(|(_, t)| t.trim());
    if presented.is_some_and(|p| constant_time_eq(p.as_bytes(), token.as_bytes())) {
        next.run(request).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "success": false, "error": "Missing or invalid bearer token" })),
        )
            .into_response()
    }
}

/// For a loopback listener without a token: only accept requests addressed
/// to a loopback host. A web page can't then reach the API by rebinding its
/// own domain to 127.0.0.1 (the browser sends that domain as Host).
pub async fn require_loopback_host(request: Request, next: Next) -> Response {
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(strip_port);
    if host.is_some_and(is_loopback_host) {
        next.run(request).await
    } else {
        (
            StatusCode::FORBIDDEN,
            Json(json!({
                "success": false,
                "error": "Host must be a loopback address; set RAMPARTS_API_TOKEN to serve other hosts"
            })),
        )
            .into_response()
    }
}

/// `localhost:3000` -> `localhost`, `[::1]:3000` -> `[::1]`.
fn strip_port(host: &str) -> &str {
    if let Some(end) = host.starts_with('[').then(|| host.find(']')).flatten() {
        return &host[..=end];
    }
    match host.rsplit_once(':') {
        Some((h, port)) if port.chars().all(|c| c.is_ascii_digit()) => h,
        _ => host,
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_addresses_in_every_form() {
        for ip in [
            "169.254.169.254",
            "169.254.0.1",
            "fe80::1",
            "fd00:ec2::254",
            "::ffff:169.254.169.254",
            "::169.254.169.254",
            "64:ff9b::a9fe:a9fe",
            "2002:a9fe:a9fe::",
        ] {
            assert!(is_metadata_ip(ip.parse().unwrap()), "should refuse {ip}");
        }
        // Private and loopback destinations are allowed.
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.1.1",
            "::1",
            "fd12::1",
            "93.184.216.34",
        ] {
            assert!(!is_metadata_ip(ip.parse().unwrap()), "should allow {ip}");
        }
    }

    #[test]
    fn loopback_hosts_ports_and_tokens() {
        for host in [
            "127.0.0.1",
            "127.0.0.2",
            "::1",
            "[::1]",
            "localhost",
            "localhost.",
        ] {
            assert!(is_loopback_host(host), "{host}");
        }
        assert!(!is_loopback_host("0.0.0.0"));
        assert!(!is_loopback_host("attacker.example"));
        assert_eq!(strip_port("localhost:3000"), "localhost");
        assert_eq!(strip_port("[::1]:3000"), "[::1]");
        assert_eq!(strip_port("127.0.0.1"), "127.0.0.1");
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secreT"));
        assert!(!constant_time_eq(b"secret", b"secret2"));
    }
}
