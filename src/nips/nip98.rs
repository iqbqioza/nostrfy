//! NIP-98: HTTP Auth.
//!
//! Verifies NIP-98 HTTP auth events (`kind:27235` events sent in the
//! `Authorization: Nostr <base64 event>` header), shared by the NIP-86
//! management API and the NIP-29 LiveKit token endpoint.

use base64::Engine;
use secp256k1::Secp256k1;

use crate::event::Event;
use crate::nips::nip01;
use crate::util::unix_now;

pub const AUTH_KIND: u64 = 27235;
pub const PAYLOAD_TAG: &str = "payload";
pub const URL_TAG: &str = "u";
pub const METHOD_TAG: &str = "method";

/// Verifies an encoded NIP-98 event. When `expected_pubkey` is given the
/// event must be authored by it; when `require_payload` is set the event
/// must carry a `payload` tag (NIP-86 requires it); when
/// `expected_payload_hash` is given the tag value must additionally equal
/// the sha256 hex of the request body — presence alone would let a captured
/// authorization be replayed against a different body. The `u` tag value is
/// checked with `url_matches` and the `method` tag must equal the HTTP
/// method of the request (NIP-98 requirement 4).
pub async fn verify(
    encoded: &str,
    expected_pubkey: Option<&str>,
    secp: &Secp256k1<secp256k1::All>,
    require_payload: bool,
    expected_payload_hash: Option<&str>,
    method: &str,
    url_matches: impl Fn(&str) -> bool,
) -> Option<String> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let event: Event = serde_json::from_slice(&raw).ok()?;
    if event.kind != AUTH_KIND {
        return None;
    }
    if let Some(expected) = expected_pubkey
        && event.pubkey != expected
    {
        return None;
    }
    let now = unix_now();
    if event.created_at.abs_diff(now) > 60 {
        return None;
    }
    let url_ok = event
        .tags
        .iter()
        .any(|t| t.len() >= 2 && t[0] == URL_TAG && url_matches(&t[1]));
    if !url_ok {
        return None;
    }
    let method_ok = event
        .tags
        .iter()
        .any(|t| t.len() >= 2 && t[0] == METHOD_TAG && t[1] == method);
    if !method_ok {
        return None;
    }
    if require_payload {
        let payload_ok = event.tags.iter().any(|t| {
            t.len() >= 2
                && t[0] == PAYLOAD_TAG
                && expected_payload_hash.is_none_or(|want| t[1].eq_ignore_ascii_case(want))
        });
        if !payload_ok {
            return None;
        }
    }
    if nip01::verify(&event, secp).is_err() {
        return None;
    }
    Some(event.pubkey)
}

/// sha256 hex of HTTP request bytes, for the NIP-98 `payload` tag
/// comparison (NIP-98: the tag is the sha256 of the request body).
pub fn payload_sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

/// NIP-98: the `u` tag MUST be the absolute request URL. The scheme is
/// normalized (`wss`/`https` and `ws`/`http`, including the `nostr+`
/// variants) so that clients behind TLS-terminating proxies that sign
/// with the `wss` form still work; the host, port, path and query must
/// match exactly.
pub fn matches_request_url(
    tag: &str,
    identity: &crate::nips::nip62::RelayIdentity<'_>,
    request_path: &str,
    request_query: Option<&str>,
) -> bool {
    // `nostr+https`/`nostr+http` sign with the same TLS semantics as
    // `https`/`http` (the `nostr+` prefix is a relay-information marker),
    // so their default port follows the underlying scheme.
    let scheme = tag
        .split_once("://")
        .map(|(s, _)| s.to_ascii_lowercase())
        .map(|s| s.strip_prefix("nostr+").unwrap_or(&s).to_string());
    let Some(rest) = tag
        .strip_prefix("wss://")
        .or_else(|| tag.strip_prefix("https://"))
        .or_else(|| tag.strip_prefix("nostr+https://"))
        .or_else(|| tag.strip_prefix("ws://"))
        .or_else(|| tag.strip_prefix("http://"))
        .or_else(|| tag.strip_prefix("nostr+http://"))
    else {
        return false;
    };
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, format!("/{p}")),
        // A bare host is equivalent to the "/" path.
        None => (rest, "/".to_string()),
    };
    let (tag_path, tag_query) = match path.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path.as_str(), None),
    };
    if tag_path != request_path || tag_query.unwrap_or("") != request_query.unwrap_or("") {
        return false;
    }
    authority_matches(authority, scheme.as_deref(), identity)
}

fn authority_matches(
    authority: &str,
    scheme: Option<&str>,
    identity: &crate::nips::nip62::RelayIdentity<'_>,
) -> bool {
    let our_authority = crate::nips::nip62::authority_of(identity);
    let (our_host, our_port) = crate::nips::nip62::split_host_port(&our_authority);
    let (tag_host, tag_port) = crate::nips::nip62::split_host_port(authority);
    if !tag_host.eq_ignore_ascii_case(our_host) {
        return false;
    }
    match (tag_port, our_port) {
        (Some(tp), Some(op)) => tp == op,
        // An omitted port means the default port of the scheme (the same
        // rule as the NIP-62/NIP-42 relay-tag matching).
        (None, Some(op)) => {
            crate::nips::nip62::scheme_default_port(scheme).is_none_or(|dp| dp == op)
        }
        // Mirror case: a tag with the scheme's default port matches a
        // portless relay identity (`wss://host:443` ≡ portless `wss://host`).
        (Some(tp), None) => {
            crate::nips::nip62::scheme_default_port(scheme).is_none_or(|dp| dp == tp)
        }
        (None, None) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nips::nip01::compute_id;
    use crate::nips::nip62::RelayIdentity;
    use secp256k1::{Keypair, XOnlyPublicKey};

    fn signed_event(method: Option<&str>, url: &str, created: u64) -> Event {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_seckey_slice(&secp, &[5u8; 32]).unwrap();
        let pubkey = XOnlyPublicKey::from_keypair(&keypair).0.to_string();
        let mut tags = vec![vec![URL_TAG.into(), url.into()]];
        if let Some(m) = method {
            tags.push(vec![METHOD_TAG.into(), m.into()]);
        }
        let mut ev = Event {
            id: String::new(),
            pubkey,
            created_at: created,
            kind: AUTH_KIND,
            tags,
            content: String::new(),
            sig: String::new(),
        };
        ev.id = compute_id(&ev);
        let id = ev.id_bytes().unwrap();
        ev.sig = secp.sign_schnorr_no_aux_rand(&id, &keypair).to_string();
        ev
    }

    fn encode(ev: &Event) -> String {
        base64::engine::general_purpose::STANDARD.encode(serde_json::to_string(ev).unwrap())
    }

    #[test]
    fn method_tag_must_match() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let secp = Secp256k1::new();
        let now = unix_now();
        rt.block_on(async {
            // Correct method and url: accepted.
            let ev = signed_event(Some("POST"), "https://relay.example.com/", now);
            assert!(
                verify(&encode(&ev), None, &secp, false, None, "POST", |u| u
                    == "https://relay.example.com/",)
                .await
                .is_some()
            );
            // Wrong method: rejected (NIP-98 requirement 4).
            assert!(
                verify(&encode(&ev), None, &secp, false, None, "GET", |u| u
                    == "https://relay.example.com/",)
                .await
                .is_none()
            );
            // Missing method tag: rejected.
            let bare = signed_event(None, "https://relay.example.com/", now);
            assert!(
                verify(&encode(&bare), None, &secp, false, None, "POST", |u| u
                    == "https://relay.example.com/",)
                .await
                .is_none()
            );
        });
    }

    #[test]
    fn payload_tag_must_match_body_hash() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let secp = Secp256k1::new();
        let now = unix_now();
        let body = br#"{"method":"banpubkey","params":[]}"#;
        let want = payload_sha256_hex(body);
        let mut ev = signed_event(Some("POST"), "https://relay.example.com/", now);
        ev.tags.push(vec![PAYLOAD_TAG.into(), want.clone()]);
        // Re-sign after adding the tag (the id commits to the tags).
        ev.id = compute_id(&ev);
        let id = ev.id_bytes().unwrap();
        let keypair = Keypair::from_seckey_slice(&secp, &[5u8; 32]).unwrap();
        ev.sig = secp.sign_schnorr_no_aux_rand(&id, &keypair).to_string();
        let encoded = encode(&ev);
        rt.block_on(async {
            // Matching hash: accepted.
            assert!(
                verify(&encoded, None, &secp, true, Some(&want), "POST", |u| u
                    == "https://relay.example.com/",)
                .await
                .is_some()
            );
            // A captured authorization replayed against another body: rejected.
            let other = payload_sha256_hex(br#"{"method":"allowpubkey","params":[]}"#);
            assert!(
                verify(&encoded, None, &secp, true, Some(&other), "POST", |u| u
                    == "https://relay.example.com/",)
                .await
                .is_none()
            );
            // Missing tag when required: rejected.
            let bare = signed_event(Some("POST"), "https://relay.example.com/", now);
            assert!(
                verify(
                    &encode(&bare),
                    None,
                    &secp,
                    true,
                    Some(&want),
                    "POST",
                    |u| u == "https://relay.example.com/",
                )
                .await
                .is_none()
            );
        });
    }

    #[test]
    fn request_url_matches_exactly() {
        let identity = RelayIdentity::new("relay.example.com", 8080, "");
        // Exact match.
        assert!(matches_request_url(
            "https://relay.example.com:8080/ws",
            &identity,
            "/ws",
            None
        ));
        // Scheme normalization: wss and http are accepted too.
        assert!(matches_request_url(
            "wss://relay.example.com:8080/ws",
            &identity,
            "/ws",
            None
        ));
        assert!(matches_request_url(
            "nostr+https://relay.example.com:8080/ws",
            &identity,
            "/ws",
            None
        ));
        // The query must match exactly, including parameter order.
        assert!(matches_request_url(
            "https://relay.example.com:8080/ws?a=1&b=2",
            &identity,
            "/ws",
            Some("a=1&b=2")
        ));
        assert!(!matches_request_url(
            "https://relay.example.com:8080/ws?a=1&b=2",
            &identity,
            "/ws",
            Some("b=2&a=1")
        ));
        // A query on one side but not the other is a mismatch.
        assert!(!matches_request_url(
            "https://relay.example.com:8080/ws?a=1",
            &identity,
            "/ws",
            None
        ));
        assert!(!matches_request_url(
            "https://relay.example.com:8080/ws",
            &identity,
            "/ws",
            Some("a=1")
        ));
        // The path must match exactly.
        assert!(!matches_request_url(
            "https://relay.example.com:8080/ws/",
            &identity,
            "/ws",
            None
        ));
        assert!(!matches_request_url(
            "https://relay.example.com:8080/other",
            &identity,
            "/ws",
            None
        ));
        // Host and port must match; a non-default port may not be omitted.
        assert!(!matches_request_url(
            "https://evil.example.com:8080/ws",
            &identity,
            "/ws",
            None
        ));
        assert!(!matches_request_url(
            "https://relay.example.com:9999/ws",
            &identity,
            "/ws",
            None
        ));
        assert!(!matches_request_url(
            "https://relay.example.com/ws",
            &identity,
            "/ws",
            None
        ));
        // Unsupported schemes are rejected.
        assert!(!matches_request_url(
            "ftp://relay.example.com:8080/ws",
            &identity,
            "/ws",
            None
        ));
        // A bare host matches the "/" path.
        assert!(matches_request_url(
            "https://relay.example.com:8080",
            &identity,
            "/",
            None
        ));
    }

    #[test]
    fn request_url_default_port_and_public_url() {
        // Default ports may be omitted from the tag.
        let identity = RelayIdentity::new("relay.example.com", 443, "");
        assert!(matches_request_url(
            "wss://relay.example.com/ws",
            &identity,
            "/ws",
            None
        ));
        let identity = RelayIdentity::new("relay.example.com", 80, "");
        assert!(matches_request_url(
            "ws://relay.example.com/",
            &identity,
            "/",
            None
        ));
        // public_url overrides the configured host:port.
        let identity = RelayIdentity::new("127.0.0.1", 8080, "wss://public.example.net");
        assert!(matches_request_url(
            "wss://public.example.net/ws",
            &identity,
            "/ws",
            None
        ));
        assert!(!matches_request_url(
            "wss://public.example.net:8443/ws",
            &identity,
            "/ws",
            None
        ));
    }
}
