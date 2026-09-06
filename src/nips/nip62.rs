//! NIP-62: Request to Vanish.
//!
//! A kind-62 event requests the complete deletion of every event authored by
//! the event's pubkey. The relay must also make sure those events can never
//! be re-published afterwards.
//!
//! This module also hosts [`RelayIdentity`], the relay's own URL identity
//! used to validate `relay` and `u` tags (NIP-42/62/98).

use crate::event::Event;

/// The relay's own URL identity: the bound host:port plus the optional
/// public URL, which overrides them when set. Shared by the NIP-42/62/98
/// tag validations.
#[derive(Debug, Clone, Copy)]
pub struct RelayIdentity<'a> {
    host: &'a str,
    port: u16,
    public_url: &'a str,
}

impl<'a> RelayIdentity<'a> {
    pub fn new(host: &'a str, port: u16, public_url: &'a str) -> Self {
        RelayIdentity {
            host,
            port,
            public_url,
        }
    }
}

pub const VANISH_KIND: u64 = 62;
pub const RELAY_TAG: &str = "relay";
pub const ALL_RELAYS: &str = "ALL_RELAYS";
/// Kind of NIP-59 gift wraps (deleted as a courtesy when they p-tag the
/// vanished pubkey).
pub const GIFT_WRAP_KIND: u64 = 1059;

/// Returns `true` when the event is a request to vanish.
pub fn is_vanish(event: &Event) -> bool {
    event.kind == VANISH_KIND
        && event
            .tags
            .iter()
            .any(|t| t.first().map(String::as_str) == Some(RELAY_TAG))
}

/// Returns `true` when the request targets this relay, either because its
/// `relay` tag equals `ALL_RELAYS` or because it names our own URL.
pub fn targets_us(event: &Event, identity: &RelayIdentity<'_>) -> bool {
    event
        .tags
        .iter()
        .filter(|t| t.len() >= 2 && t[0] == RELAY_TAG)
        .any(|t| tag_matches(&t[1], identity))
}

/// Compares a relay URL tag value against this relay's host:port (or
/// `public_url` when set), tolerating different schemes and paths. Also used
/// by NIP-42 to validate the `relay` tag of auth events.
pub fn tag_matches(tag: &str, identity: &RelayIdentity<'_>) -> bool {
    if tag == ALL_RELAYS {
        return true;
    }
    // Compare host:port, tolerating different schemes, paths and the
    // hostname variants (localhost vs 127.0.0.1 are intentionally not
    // normalized further). The scheme and the hostname are both
    // case-insensitive (RFC 3986 / DNS).
    let tag_scheme = tag.split_once("://").map(|(s, _)| s.to_ascii_lowercase());
    let authority = scheme_authority(tag);
    let (tag_host, tag_port) = split_host_port(authority);
    let authority = authority_of(identity);
    let (our_host, our_port) = split_host_port(&authority);
    if !tag_host.eq_ignore_ascii_case(our_host) {
        return false;
    }
    match (tag_port, our_port) {
        (Some(tp), Some(op)) => tp == op,
        // An omitted port means the default port of the scheme: a
        // `wss://host` tag must not match a relay on a non-standard port.
        // A bare host (no scheme) has no default port: keep the lenient
        // any-port behavior.
        (None, Some(op)) => scheme_default_port(tag_scheme.as_deref()).is_none_or(|dp| dp == op),
        // Mirror case: a tag with an explicit port matches a portless
        // relay identity when the port is the scheme's default (`wss://
        // host:443` ≡ the relay's portless `wss://host`). Without this a
        // NIP-62 vanish / NIP-42 auth / NIP-98 admin event tagging an
        // explicit default port would be ignored whenever the operator
        // left the port off `relay.public_url`.
        (Some(tp), None) => scheme_default_port(tag_scheme.as_deref()).is_none_or(|dp| dp == tp),
        (None, None) => true,
    }
}

pub(crate) fn scheme_default_port(scheme: Option<&str>) -> Option<u16> {
    match scheme {
        Some(s) if s == "wss" || s == "https" => Some(443),
        Some(s) if s == "ws" || s == "http" => Some(80),
        // Unknown or absent scheme: no default to compare against, which
        // keeps the old lenient behavior for bare-host tags.
        _ => None,
    }
}

/// The authority part of a URL behind a known scheme (case-insensitive),
/// or the whole input when the scheme is unknown or absent: "WSS://HOST/p"
/// and "wss://HOST/p" both yield "HOST/p".
fn scheme_authority(url: &str) -> &str {
    match url.split_once("://") {
        Some((scheme, rest)) if is_known_scheme(scheme) => {
            rest.split(['/', '?', '#']).next().unwrap_or(rest)
        }
        _ => url,
    }
}

fn is_known_scheme(scheme: &str) -> bool {
    matches!(
        scheme.to_ascii_lowercase().as_str(),
        "wss" | "ws" | "https" | "http"
    )
}

pub(crate) fn authority_of(identity: &RelayIdentity<'_>) -> String {
    if !identity.public_url.is_empty() {
        let authority = scheme_authority(identity.public_url);
        if authority != identity.public_url {
            return authority.to_string();
        }
    }
    // IPv6 literals must be bracketed to form a valid authority.
    if identity.host.contains(':') {
        format!("[{}]:{}", identity.host, identity.port)
    } else {
        format!("{}:{}", identity.host, identity.port)
    }
}

/// Splits an authority into its host (brackets stripped) and optional port.
/// Handles IPv6 literals (`[::1]`, `[::1]:8080`), DNS names and IPv4. An
/// unparseable port suffix leaves the whole authority as the host (so a
/// garbage tail never degrades to "no port", which would match any port).
pub(crate) fn split_host_port(authority: &str) -> (&str, Option<u16>) {
    if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 literal: the host ends at the closing bracket, optionally
        // followed by a `:port`.
        match rest.split_once(']') {
            Some((host, "")) => (host, None),
            Some((host, tail)) => {
                let port = tail.strip_prefix(':').and_then(|p| p.parse::<u16>().ok());
                match port {
                    Some(port) => (host, Some(port)),
                    // `[::1]:garbage` or `[::1]junk`: unparseable tail.
                    None => (authority, None),
                }
            }
            None => (rest, None),
        }
    } else if let Some((host, port)) = authority.rsplit_once(':')
        && let Ok(port) = port.parse::<u16>()
    {
        (host, Some(port))
    } else {
        (authority, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(relay: &str) -> Event {
        Event {
            id: "a".repeat(64),
            pubkey: "b".repeat(64),
            created_at: 1,
            kind: VANISH_KIND,
            tags: vec![vec![RELAY_TAG.into(), relay.into()]],
            content: String::new(),
            sig: "c".repeat(128),
        }
    }

    #[test]
    fn detection() {
        assert!(is_vanish(&event("wss://relay.example.com")));
        let mut no_relay = event("x");
        no_relay.tags.clear();
        assert!(!is_vanish(&no_relay));
        let mut wrong_kind = event("x");
        wrong_kind.kind = 5;
        assert!(!is_vanish(&wrong_kind));
    }

    #[test]
    fn url_matching() {
        let identity = RelayIdentity::new("relay.example.com", 8080, "");
        assert!(targets_us(&event("ALL_RELAYS"), &identity));
        assert!(targets_us(&event("ws://relay.example.com:8080"), &identity));
        assert!(targets_us(
            &event("wss://relay.example.com:8080/some/path"),
            &identity
        ));
        assert!(!targets_us(
            &event("ws://other.example.com:8080"),
            &identity
        ));
        assert!(!targets_us(
            &event("ws://relay.example.com:9999"),
            &identity
        ));
        // public_url overrides the configured host/port.
        let public = RelayIdentity::new("127.0.0.1", 8080, "wss://public.example.net");
        assert!(targets_us(&event("wss://public.example.net"), &public));
    }

    #[test]
    fn omitted_port_means_the_scheme_default() {
        // `wss://host` (no port) matches a relay on 443, not on a
        // non-standard port; `ws://host` matches 80.
        let on_443 = RelayIdentity::new("relay.example.com", 443, "");
        assert!(tag_matches("wss://relay.example.com", &on_443));
        assert!(tag_matches("https://relay.example.com", &on_443));
        assert!(!tag_matches("ws://relay.example.com", &on_443));

        let on_80 = RelayIdentity::new("relay.example.com", 80, "");
        assert!(tag_matches("ws://relay.example.com", &on_80));
        assert!(tag_matches("http://relay.example.com", &on_80));
        assert!(!tag_matches("wss://relay.example.com", &on_80));

        let on_8080 = RelayIdentity::new("relay.example.com", 8080, "");
        assert!(
            !tag_matches("wss://relay.example.com", &on_8080),
            "a scheme-default port must not match a non-standard port"
        );
        assert!(tag_matches("wss://relay.example.com:8080", &on_8080));

        // A bare host (no scheme) keeps the lenient any-port behavior.
        assert!(tag_matches("relay.example.com", &on_8080));
    }

    #[test]
    fn ipv6_authorities_are_bracketed() {
        let identity = RelayIdentity::new("::1", 80, "");
        assert_eq!(authority_of(&identity), "[::1]:80");
        let ipv6 = RelayIdentity::new("fe80::1%eth0", 443, "");
        assert_eq!(authority_of(&ipv6), "[fe80::1%eth0]:443");
    }

    #[test]
    fn split_host_port_handles_ipv6() {
        assert_eq!(split_host_port("[::1]:8080"), ("::1", Some(8080)));
        assert_eq!(split_host_port("[::1]"), ("::1", None));
        assert_eq!(
            split_host_port("relay.example.com:8080"),
            ("relay.example.com", Some(8080))
        );
        assert_eq!(
            split_host_port("relay.example.com"),
            ("relay.example.com", None)
        );
        assert_eq!(split_host_port("192.0.2.1:80"), ("192.0.2.1", Some(80)));
    }
    #[test]
    fn url_matching_is_case_insensitive() {
        // DNS hostnames are case-insensitive: a differently-cased relay URL
        // must still match.
        let identity = RelayIdentity::new("relay.example.com", 8080, "");
        assert!(targets_us(
            &event("WSS://RELAY.EXAMPLE.COM:8080"),
            &identity
        ));
        assert!(targets_us(
            &event("wss://Relay.Example.Com:8080/path"),
            &identity
        ));
        // A different host still fails.
        assert!(!targets_us(
            &event("wss://OTHER.EXAMPLE.COM:8080"),
            &identity
        ));
    }
}
