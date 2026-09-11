//! Small shared helpers without a natural home elsewhere.

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

/// Whether `peer` is covered by a blocked-IP list. Both sides are parsed and
/// normalized, so an operator-written or legacy spelling (`::ffff:127.0.0.1`
/// versus `127.0.0.1`, `0:0:0:0:0:0:0:1` versus `::1`) still matches.
pub fn ip_blocked(blocked: &[(String, String)], peer: std::net::IpAddr) -> bool {
    let peer = normalize_ip(peer);
    blocked.iter().any(|(entry, _)| {
        entry
            .parse::<std::net::IpAddr>()
            .map(normalize_ip)
            .is_ok_and(|b| b == peer)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_blocked_normalizes_both_sides() {
        let v4_mapped = vec![("::ffff:127.0.0.1".to_string(), "x".to_string())];
        assert!(ip_blocked(&v4_mapped, "127.0.0.1".parse().unwrap()));
        let expanded = vec![("0:0:0:0:0:0:0:1".to_string(), "x".to_string())];
        assert!(ip_blocked(&expanded, "::1".parse().unwrap()));
        let v4 = vec![("127.0.0.1".to_string(), "x".to_string())];
        assert!(!ip_blocked(&v4, "127.0.0.2".parse().unwrap()));
        assert!(!ip_blocked(&[], "127.0.0.1".parse().unwrap()));
    }
}
