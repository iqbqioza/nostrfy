//! NIP-66: Relay Liveness Monitoring.
//!
//! The relay publishes its own kind 30166 relay-discovery event: an
//! addressable event (`d` = the relay's normalized URL) documenting the
//! characteristics advertised in the NIP-11 document — the supported NIP
//! numbers as repeated `N` tags, the NIP-11 `limitation` requirements as
//! `R` tags, and the stringified NIP-11 document in the content.
//! Publishing requires `relay.private_key`; without it the relay still
//! stores and serves 30166/10166 events published by clients and monitors.

use crate::config::{AccessControl, Config};
use crate::event::Event;
use crate::nips::nip11::relay_info;
use crate::stats::Stats;

/// How often the relay re-publishes its discovery event, so `created_at`
/// stays recent for clients and monitors.
pub(crate) const REFRESH_SECS: u64 = 12 * 3600;

/// The relay's normalized URL (NIP-66 requires the `d` tag to be the
/// normalized URL): `relay.public_url` when set, otherwise
/// `wss://host:port/`. IPv6 literals are bracketed to form a valid
/// authority (the same convention as the NIP-42/62/98 relay identity).
pub(crate) fn normalized_url(cfg: &Config) -> String {
    let url = cfg.relay.public_url.trim();
    let url = if url.is_empty() {
        let host = if cfg.server.host.contains(':') {
            format!("[{}]", cfg.server.host)
        } else {
            cfg.server.host.clone()
        };
        format!("wss://{host}:{}/", cfg.server.port)
    } else {
        url.to_string()
    };
    normalize_url(&url)
}

/// RFC 3986 §6 normalization: the scheme and host are lowercased and a
/// default port for the scheme is dropped, so `WSS://Relay.Example.Com:443/`
/// and `wss://relay.example.com/` publish the same `d` tag.
fn normalize_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    let scheme = scheme.to_ascii_lowercase();
    // `find`+`split_at` keep the delimiter, so the path keeps its leading
    // "/" ("host:8080/path" -> authority "host:8080", tail "/path").
    let (authority, tail) = match rest.find(['/', '?', '#']) {
        Some(i) => {
            let (a, t) = rest.split_at(i);
            (a, t)
        }
        None => (rest, ""),
    };
    // RFC 3986 §6.2.3: a hierarchical URI with an empty path is
    // normalized to "/".
    let tail = if tail.is_empty() && matches!(scheme.as_str(), "ws" | "wss" | "http" | "https") {
        "/"
    } else {
        tail
    };
    // IPv6 literals keep their brackets: only a trailing `:<digits>` is a
    // port ("[::1]:8080" -> host "[::1]", port "8080"; "[::1]" -> host).
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => (h, Some(p)),
        _ => (authority, None),
    };
    let host = host.to_ascii_lowercase();
    let port = port.filter(|p| {
        let default = match scheme.as_str() {
            "wss" | "https" => Some("443"),
            "ws" | "http" => Some("80"),
            _ => None,
        };
        default.is_none_or(|d| d != *p)
    });
    match port {
        Some(p) => format!("{scheme}://{host}:{p}{tail}"),
        None => format!("{scheme}://{host}{tail}"),
    }
}

/// Builds the relay's kind 30166 discovery event (unsigned — the publisher
/// signs it through `Relay::store_relay_event`).
pub(crate) fn relay_discovery_event(
    cfg: &Config,
    access: &AccessControl,
    relay_pubkey: &str,
    stats: &Stats,
    now: u64,
) -> Event {
    let mut tags: Vec<Vec<String>> = vec![vec!["d".into(), normalized_url(cfg)]];
    // NIP-66: repeated single-value tags (one `N` per supported NIP).
    for nip in cfg.effective_supported_nips(access) {
        tags.push(vec!["N".into(), nip.to_string()]);
    }
    // NIP-66: requirements per the NIP-11 `limitation` object, with `!`
    // prefixing false values.
    if cfg.relay.require_auth {
        tags.push(vec!["R".into(), "auth".into()]);
    } else {
        tags.push(vec!["R".into(), "!auth".into()]);
    }
    tags.push(vec!["R".into(), "!payment".into()]);
    // NIP-66's `R` keys cover auth, writes, pow and payment: when
    // `restrict_relay` narrows writes to the allowlist, the requirement
    // is asserted; otherwise it is negated.
    if access.restrict_relay {
        tags.push(vec!["R".into(), "writes".into()]);
    } else {
        tags.push(vec!["R".into(), "!writes".into()]);
    }
    if cfg.nip_enabled(13) && cfg.relay.require_pow > 0 {
        tags.push(vec!["R".into(), "pow".into()]);
    } else {
        tags.push(vec!["R".into(), "!pow".into()]);
    }
    // NIP-66: the content MAY carry the stringified NIP-11 document.
    let content = relay_info(cfg, access, stats, Some(relay_pubkey)).to_string();
    Event {
        id: String::new(),
        pubkey: relay_pubkey.to_string(),
        created_at: now,
        kind: 30166,
        tags,
        content,
        sig: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AccessControl;

    #[test]
    fn discovery_event_describes_the_relay() {
        let cfg = Config::default();
        let access = AccessControl::default();
        let stats = Stats::new();
        let pubkey = "bb".repeat(32);
        let ev = relay_discovery_event(&cfg, &access, &pubkey, &stats, 1_700_000_000);
        assert_eq!(ev.kind, 30166);
        assert_eq!(ev.pubkey, pubkey);
        // The `d` tag is the normalized relay URL.
        assert_eq!(ev.tags[0], vec!["d", "wss://127.0.0.1:8080/"]);
        // One `N` tag per advertised NIP.
        let nips: Vec<u16> = ev
            .tags
            .iter()
            .filter(|t| t[0] == "N")
            .map(|t| t[1].parse().unwrap())
            .collect();
        assert_eq!(nips, cfg.effective_supported_nips(&access));
        // Requirements are described with `!` prefixes for false values.
        let reqs: Vec<&str> = ev
            .tags
            .iter()
            .filter(|t| t[0] == "R")
            .map(|t| t[1].as_str())
            .collect();
        assert!(reqs.contains(&"!payment"));
        assert!(reqs.contains(&"!auth"));
        assert!(reqs.contains(&"!writes"));
        assert!(reqs.contains(&"!pow"));
        // The content is the stringified NIP-11 document.
        let doc: serde_json::Value = serde_json::from_str(&ev.content).unwrap();
        assert_eq!(doc["supported_nips"], serde_json::to_value(&nips).unwrap());
        assert_eq!(doc["name"], cfg.relay.name);
    }

    #[test]
    fn normalized_url_prefers_public_url() {
        let mut cfg = Config::default();
        assert_eq!(normalized_url(&cfg), "wss://127.0.0.1:8080/");
        cfg.relay.public_url = "wss://relay.example.com/".into();
        assert_eq!(normalized_url(&cfg), "wss://relay.example.com/");
        // IPv6 literals must be bracketed to form a valid URL.
        let mut cfg = Config::default();
        cfg.server.host = "::1".into();
        assert_eq!(normalized_url(&cfg), "wss://[::1]:8080/");
    }

    #[test]
    fn normalized_url_lowercases_and_drops_default_ports() {
        let mut cfg = Config::default();
        cfg.relay.public_url = "WSS://Relay.Example.Com:443/".into();
        assert_eq!(normalized_url(&cfg), "wss://relay.example.com/");
        cfg.relay.public_url = "wss://relay.example.com:8443/".into();
        assert_eq!(normalized_url(&cfg), "wss://relay.example.com:8443/");
        cfg.relay.public_url = "ws://Relay.Example.Com:80/path".into();
        assert_eq!(normalized_url(&cfg), "ws://relay.example.com/path");
        cfg.relay.public_url = "wss://[::1]:443/".into();
        assert_eq!(normalized_url(&cfg), "wss://[::1]/");
    }
}
