//! Small shared helpers without a natural home elsewhere.

use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

/// The current Unix timestamp in seconds.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// HMAC-SHA256 (RFC 2104), implemented locally to avoid extra dependencies.
/// Shared by the LiveKit JWT signing and the S3/R2 (SigV4) request signing.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    const BLOCK: usize = 64;
    let mut key = key.to_vec();
    if key.len() > BLOCK {
        key = Sha256::digest(&key).to_vec();
    }
    key.resize(BLOCK, 0);
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for (i, b) in key.iter().enumerate() {
        ipad[i] ^= b;
        opad[i] ^= b;
    }
    let inner = Sha256::digest([ipad.as_slice(), data].concat());
    let outer = Sha256::digest([opad.as_slice(), inner.as_slice()].concat());
    outer.into()
}

/// Normalizes an IP address for blocking and per-IP accounting: a
/// dual-stack listener reports IPv4 peers as `::ffff:a.b.c.d`, which
/// would otherwise never equal a `blockip "a.b.c.d"` entry.
pub fn normalize_ip(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip {
        std::net::IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(std::net::IpAddr::V4)
            .unwrap_or(std::net::IpAddr::V6(v6)),
        other => other,
    }
}

/// The address a client is *accounted under* by the per-IP caps and the
/// per-IP connection rate limiter. IPv6 clients are aggregated by their
/// /64 prefix: a single host is routinely delegated a /64 and can rotate
/// the low 64 bits at will, so counting full addresses would let one host
/// bypass the cap with a new suffix per connection. IPv4 addresses are
/// unchanged (a /32 is the natural host unit).
pub fn accounting_ip(ip: std::net::IpAddr) -> std::net::IpAddr {
    match normalize_ip(ip) {
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            octets[8..].fill(0);
            IpAddr::V6(std::net::Ipv6Addr::from(octets))
        }
        v4 => v4,
    }
}

/// A trusted reverse proxy: an IP address or CIDR range (e.g.
/// `127.0.0.1/32`, `::1`, `10.0.0.0/8`). Only peers matching one of these
/// may name the client address in `X-Forwarded-For`; for every other peer
/// the header is attacker-controlled and ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedProxy {
    addr: IpAddr,
    prefix: u8,
}

impl TrustedProxy {
    /// Parses an IP or CIDR value. Returns `None` for malformed input, an
    /// out-of-range prefix or a `/0` range (trusting every peer would let
    /// any client spoof `X-Forwarded-For`).
    pub fn parse(value: &str) -> Option<TrustedProxy> {
        let value = value.trim();
        let (addr, prefix) = match value.split_once('/') {
            Some((addr, prefix)) => (
                addr.trim().parse::<IpAddr>().ok()?,
                prefix.trim().parse::<u8>().ok()?,
            ),
            None => {
                let addr = value.parse::<IpAddr>().ok()?;
                // Default the prefix from the normalized family: a dual-stack
                // listener reports IPv4 peers as `::ffff:a.b.c.d`, and such a
                // bare value names the IPv4 host (`/32`), not a `/128` that
                // would overflow the V4 mask in `contains`.
                let prefix = if normalize_ip(addr).is_ipv4() {
                    32
                } else {
                    128
                };
                (addr, prefix)
            }
        };
        // Validate against the normalized family: an IPv4-mapped address
        // with a prefix above 32 (e.g. `::ffff:10.0.0.0/96`) can never match
        // (the V4 mask shifts by `32 - prefix`), so reject it instead of
        // storing an unusable range.
        let addr = normalize_ip(addr);
        let bits = if addr.is_ipv4() { 32 } else { 128 };
        if prefix == 0 || prefix > bits {
            return None;
        }
        Some(TrustedProxy { addr, prefix })
    }

    /// Whether `ip` falls inside this proxy's range.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = normalize_ip(ip);
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX << (32 - self.prefix);
                (u32::from(net) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX << (128 - self.prefix);
                (u128::from(net) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}

/// Derives the client address for a TCP peer. For an untrusted peer the
/// peer itself is the client. When the peer is a configured trusted proxy,
/// the right-most `X-Forwarded-For` entry that is not itself a trusted
/// proxy is returned: the header is appended per hop, so the right-most
/// untrusted entry is the address that connected to the nearest trusted
/// hop; anything to its left is client-controlled. An absent, empty or
/// malformed header falls back to the peer (fail closed).
pub fn client_ip(peer: IpAddr, forwarded_for: Option<&str>, trusted: &[TrustedProxy]) -> IpAddr {
    let peer = normalize_ip(peer);
    if trusted.is_empty() || !trusted.iter().any(|proxy| proxy.contains(peer)) {
        return peer;
    }
    let Some(value) = forwarded_for.map(str::trim) else {
        return peer;
    };
    if value.is_empty() {
        return peer;
    }
    let mut client = None;
    for entry in value.split(',') {
        let entry = entry.trim();
        let Some(ip) = parse_forwarded_entry(entry) else {
            return peer;
        };
        let ip = normalize_ip(ip);
        if !trusted.iter().any(|proxy| proxy.contains(ip)) {
            client = Some(ip);
        }
    }
    client.unwrap_or(peer)
}

/// Parses one `X-Forwarded-For` entry: a bare IP, `host:port` or
/// `[v6]:port` (proxies differ in whether they append a port).
fn parse_forwarded_entry(entry: &str) -> Option<IpAddr> {
    if let Ok(ip) = entry.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Some(rest) = entry.strip_prefix('[') {
        let (ip, tail) = rest.split_once(']')?;
        // Like the `host:port` branch below, anything after the bracket
        // must be empty or a numeric port: `[::1]garbage` is malformed and
        // fails the whole chain closed (falls back to the peer) instead of
        // parsing as the bracketed address.
        let tail_ok = tail.is_empty()
            || tail
                .strip_prefix(':')
                .is_some_and(|port| !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()));
        if !tail_ok {
            return None;
        }
        return ip.parse().ok();
    }
    let (ip, port) = entry.rsplit_once(':')?;
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    ip.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_ip_maps_v4_mapped_addresses() {
        assert_eq!(
            normalize_ip("::ffff:127.0.0.1".parse().unwrap()),
            "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(
            normalize_ip("::1".parse().unwrap()),
            "::1".parse::<std::net::IpAddr>().unwrap()
        );
    }

    #[test]
    fn accounting_ip_aggregates_ipv6_by_64() {
        // One host rotating addresses inside its /64 must land on one key.
        assert_eq!(
            accounting_ip("2001:db8:1:2::1".parse().unwrap()),
            accounting_ip("2001:db8:1:2:ffff:ffff:ffff:ffff".parse().unwrap())
        );
        assert_eq!(
            accounting_ip("2001:db8:1:2::1".parse().unwrap()),
            "2001:db8:1:2::".parse::<IpAddr>().unwrap()
        );
        // Different /64s stay distinct, and IPv4 is untouched.
        assert_ne!(
            accounting_ip("2001:db8:1:3::1".parse().unwrap()),
            accounting_ip("2001:db8:1:2::1".parse().unwrap())
        );
        assert_eq!(
            accounting_ip("203.0.113.7".parse().unwrap()),
            "203.0.113.7".parse::<IpAddr>().unwrap()
        );
        // A v4-mapped peer aggregates to the plain IPv4 address.
        assert_eq!(
            accounting_ip("::ffff:203.0.113.7".parse().unwrap()),
            "203.0.113.7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn trusted_proxy_parses_ips_and_cidrs() {
        assert!(
            TrustedProxy::parse("127.0.0.1")
                .unwrap()
                .contains("127.0.0.1".parse().unwrap())
        );
        assert!(
            TrustedProxy::parse("10.0.0.0/8")
                .unwrap()
                .contains("10.9.8.7".parse().unwrap())
        );
        assert!(
            !TrustedProxy::parse("10.0.0.0/8")
                .unwrap()
                .contains("11.0.0.1".parse().unwrap())
        );
        assert!(
            TrustedProxy::parse("::1")
                .unwrap()
                .contains("::1".parse().unwrap())
        );
        assert!(
            TrustedProxy::parse("2001:db8::/32")
                .unwrap()
                .contains("2001:db8:1:2::1".parse().unwrap())
        );
        assert!(
            !TrustedProxy::parse("2001:db8::/32")
                .unwrap()
                .contains("2001:db9::1".parse().unwrap())
        );
        // A v4-mapped peer matches its plain IPv4 spelling.
        assert!(
            TrustedProxy::parse("127.0.0.1/32")
                .unwrap()
                .contains("::ffff:127.0.0.1".parse().unwrap())
        );
        // Malformed values and trusting everyone are rejected.
        assert!(TrustedProxy::parse("").is_none());
        assert!(TrustedProxy::parse("not-an-ip").is_none());
        assert!(TrustedProxy::parse("10.0.0.0/33").is_none());
        assert!(TrustedProxy::parse("2001:db8::/129").is_none());
        assert!(TrustedProxy::parse("0.0.0.0/0").is_none());
        assert!(TrustedProxy::parse("::/0").is_none());
    }

    #[test]
    fn trusted_proxy_v4_mapped_prefix_checked_after_normalization() {
        // A bare IPv4-mapped address names the IPv4 host: it must parse as
        // an exact `/32` and match the peer (previously it stored a `/128`
        // against a V4 address, overflowing the mask in `contains`).
        let mapped = TrustedProxy::parse("::ffff:127.0.0.1").expect("bare mapped must parse");
        assert!(mapped.contains("127.0.0.1".parse().unwrap()));
        assert!(mapped.contains("::ffff:127.0.0.1".parse().unwrap()));
        assert!(!mapped.contains("127.0.0.2".parse().unwrap()));
        // A mapped CIDR with a prefix above 32 is unrepresentable and must
        // be rejected instead of stored as a broken range.
        assert!(TrustedProxy::parse("::ffff:10.0.0.0/96").is_none());
        // A mapped CIDR within the V4 width works as the IPv4 range.
        let range = TrustedProxy::parse("::ffff:10.0.0.0/24").expect("mapped /24 must parse");
        assert!(range.contains("10.0.0.5".parse().unwrap()));
        assert!(!range.contains("10.0.1.5".parse().unwrap()));
    }

    #[test]
    fn client_ip_ignores_forwarded_for_from_untrusted_peers() {
        let trusted = [TrustedProxy::parse("127.0.0.1").unwrap()];
        // A direct client cannot spoof its address.
        assert_eq!(
            client_ip("203.0.113.9".parse().unwrap(), Some("10.0.0.1"), &trusted),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
        // Without any trusted proxies the header never matters.
        assert_eq!(
            client_ip("203.0.113.9".parse().unwrap(), Some("10.0.0.1"), &[]),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn client_ip_uses_the_right_most_untrusted_forwarded_entry() {
        let trusted = [TrustedProxy::parse("127.0.0.1").unwrap()];
        // The proxy appended the real client: the leftmost entry is
        // client-controlled and must not win.
        assert_eq!(
            client_ip(
                "127.0.0.1".parse().unwrap(),
                Some("6.6.6.6, 203.0.113.9"),
                &trusted
            ),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
        // A chain through further trusted hops skips them right-to-left.
        let chain = [
            TrustedProxy::parse("127.0.0.1").unwrap(),
            TrustedProxy::parse("10.0.1.0/24").unwrap(),
        ];
        assert_eq!(
            client_ip(
                "127.0.0.1".parse().unwrap(),
                Some("198.51.100.7, 10.0.1.5"),
                &chain
            ),
            "198.51.100.7".parse::<IpAddr>().unwrap()
        );
        // A host:port form is accepted.
        assert_eq!(
            client_ip(
                "127.0.0.1".parse().unwrap(),
                Some("203.0.113.9:4321"),
                &trusted
            ),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            client_ip(
                "127.0.0.1".parse().unwrap(),
                Some("[2001:db8::7]:443"),
                &trusted
            ),
            "2001:db8::7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn client_ip_falls_back_on_absent_or_malformed_headers() {
        let trusted = [TrustedProxy::parse("127.0.0.1").unwrap()];
        let peer = "127.0.0.1".parse::<IpAddr>().unwrap();
        assert_eq!(client_ip(peer, None, &trusted), peer);
        assert_eq!(client_ip(peer, Some(""), &trusted), peer);
        assert_eq!(client_ip(peer, Some("   "), &trusted), peer);
        assert_eq!(client_ip(peer, Some("not-an-ip"), &trusted), peer);
        // One malformed entry poisons the whole chain (fail closed).
        assert_eq!(
            client_ip(peer, Some("203.0.113.9, garbage"), &trusted),
            peer
        );
        // Garbage after a bracketed address is malformed too, like a
        // non-numeric `host:port` suffix.
        assert_eq!(
            client_ip(peer, Some("[203.0.113.9]garbage"), &trusted),
            peer
        );
        assert_eq!(client_ip(peer, Some("[::1]x"), &trusted), peer);
        // Bare brackets and a numeric bracketed port stay accepted.
        assert_eq!(
            client_ip(peer, Some("[203.0.113.9]"), &trusted),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
        // An all-trusted chain names no client: fall back to the peer.
        assert_eq!(
            client_ip(peer, Some("127.0.0.1, 127.0.0.1"), &trusted),
            peer
        );
    }
}
