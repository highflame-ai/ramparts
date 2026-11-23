//! Outbound network policy for scans requested by remote callers (server
//! mode). A caller-supplied URL must not reach the host itself, private
//! networks or cloud metadata services. Checking the URL string once is not
//! enough: a public name can resolve to a private address and a public URL
//! can redirect to one. So the policy is enforced in three places:
//!
//! - `is_forbidden_ip`: the single definition of "private", used by the
//!   server's URL check for IP literals;
//! - `GuardedResolver`: DNS answers with private addresses are dropped
//!   before the HTTP client connects;
//! - `redirect_policy`: every redirect hop is re-checked.
//!
//! The policy is off by default (the CLI scans whatever the operator points
//! it at, including internal servers) and switched on by `ramparts server`
//! unless `RAMPARTS_ALLOW_PRIVATE_TARGETS=1`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};

static BLOCK_PRIVATE_TARGETS: AtomicBool = AtomicBool::new(false);

/// Turn the policy on for every HTTP client built from now on.
pub fn block_private_targets() {
    BLOCK_PRIVATE_TARGETS.store(true, Ordering::SeqCst);
}

pub fn private_targets_blocked() -> bool {
    BLOCK_PRIVATE_TARGETS.load(Ordering::SeqCst)
}

/// Loopback, private, link-local, CGNAT, unspecified and similar addresses,
/// including IPv4 addresses written in IPv6 form (`::ffff:a.b.c.d`, NAT64
/// `64:ff9b::a.b.c.d`), which a dual-stack socket connects to over IPv4.
pub fn is_forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_forbidden_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = embedded_v4(v6) {
                return is_forbidden_v4(v4);
            }
            let first = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || (first & 0xffc0) == 0xfe80 // link-local fe80::/10
                || (first & 0xfe00) == 0xfc00 // unique local fc00::/7
                || v6.is_multicast()
        }
    }
}

fn is_forbidden_v4(v4: Ipv4Addr) -> bool {
    let [a, b, ..] = v4.octets();
    v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_unspecified()
        || v4.is_multicast()
        || a == 0 // 0.0.0.0/8
        || (a == 100 && (64..128).contains(&b)) // CGNAT 100.64.0.0/10
        || (a == 198 && (b == 18 || b == 19)) // benchmarking 198.18.0.0/15
}

/// The IPv4 address inside an IPv4-mapped (`::ffff:0:0/96`) or NAT64
/// (`64:ff9b::/96`) IPv6 address.
fn embedded_v4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = v6.to_ipv4_mapped() {
        return Some(v4);
    }
    let s = v6.segments();
    if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        let o = v6.octets();
        return Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
    }
    None
}

/// DNS resolver that drops private addresses from every answer, so a public
/// name pointing at `127.0.0.1` or `169.254.169.254` never gets connected to.
pub struct GuardedResolver;

impl reqwest::dns::Resolve for GuardedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await?
                .filter(|a| !is_forbidden_ip(a.ip()))
                .collect();
            if addrs.is_empty() {
                return Err(format!(
                    "{host} resolves only to loopback, private or link-local addresses"
                )
                .into());
            }
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Redirect policy for guarded clients: follow at most 5 hops, only to
/// http(s), and never to a private IP literal (names are covered by the
/// resolver).
pub fn redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        let url = attempt.url();
        if attempt.previous().len() >= 5 {
            return attempt.error("too many redirects");
        }
        if !matches!(url.scheme(), "http" | "https") {
            let msg = format!("refusing redirect to non-http URL {url}");
            return attempt.error(msg);
        }
        let ip = match url.host() {
            Some(url::Host::Ipv4(v4)) => Some(IpAddr::V4(v4)),
            Some(url::Host::Ipv6(v6)) => Some(IpAddr::V6(v6)),
            _ => None,
        };
        if ip.is_some_and(is_forbidden_ip) {
            let msg = format!("refusing redirect to private address {url}");
            return attempt.error(msg);
        }
        attempt.follow()
    })
}

/// Apply the policy to a client builder when it is switched on.
pub fn guard(builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    if private_targets_blocked() {
        builder
            .dns_resolver(GuardedResolver)
            .redirect(redirect_policy())
    } else {
        builder
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_ranges_and_embedded_v4_are_forbidden() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "100.127.255.254",
            "0.0.0.0",
            "0.1.2.3",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "fd12:3456::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "64:ff9b::a9fe:a9fe",
        ] {
            assert!(is_forbidden_ip(ip.parse().unwrap()), "should forbid {ip}");
        }
        for ip in [
            "93.184.216.34",
            "100.128.0.1",
            "2606:4700::1111",
            "::ffff:8.8.8.8",
        ] {
            assert!(!is_forbidden_ip(ip.parse().unwrap()), "should allow {ip}");
        }
    }

    #[tokio::test]
    async fn resolver_drops_private_answers() {
        use reqwest::dns::Resolve;
        let err = GuardedResolver
            .resolve("localhost".parse().unwrap())
            .await
            .err()
            .expect("localhost resolves only to loopback");
        assert!(err.to_string().contains("loopback"), "{err}");
    }

    /// A guarded client must not follow a redirect to a private address,
    /// whether it's an IP literal or a name that resolves to one. (The first
    /// hop here is a loopback literal, which the server's URL check would
    /// refuse; it stands in for a public redirector.)
    #[tokio::test]
    async fn redirects_to_private_targets_are_not_followed() {
        use std::io::{Read, Write};
        use std::sync::atomic::AtomicUsize;
        use std::sync::Arc;

        let bait = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let bait_port = bait.local_addr().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        bait.set_nonblocking(false).unwrap();
        std::thread::spawn(move || {
            for stream in bait.incoming().flatten() {
                h.fetch_add(1, Ordering::SeqCst);
                drop(stream);
            }
        });

        for target in [
            format!("http://127.0.0.1:{bait_port}/"),
            format!("http://127.0.0.1.nip.io:{bait_port}/"),
        ] {
            let redirector = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = redirector.local_addr().unwrap().port();
            let location = target.clone();
            std::thread::spawn(move || {
                if let Ok((mut s, _)) = redirector.accept() {
                    let mut buf = [0u8; 1024];
                    let _ = s.read(&mut buf);
                    let _ = write!(
                        s,
                        "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n"
                    );
                }
            });
            let client = reqwest::Client::builder()
                .dns_resolver(GuardedResolver)
                .redirect(redirect_policy())
                .build()
                .unwrap();
            let res = client.get(format!("http://127.0.0.1:{port}/")).send().await;
            assert!(res.is_err(), "redirect to {target} was followed");
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert_eq!(hits.load(Ordering::SeqCst), 0, "bait was reached");
    }
}
