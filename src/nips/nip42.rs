//! NIP-42: Authentication of Clients to Relays.
//!
//! The relay sends `["AUTH", <challenge>]`; the client responds with
//! `["AUTH", <event>]` where the event is kind 22242 signed with the client
//! key, carrying `relay` and `challenge` tags.

use getrandom::getrandom;
use secp256k1::Secp256k1;
use serde_json::{Value, json};

use crate::event::Event;
use crate::nips::nip01;

pub const AUTH_KIND: u64 = 22242;
pub const CHALLENGE_TAG: &str = "challenge";
pub const RELAY_TAG: &str = "relay";

pub fn auth_message(challenge: &str) -> Value {
    json!(["AUTH", challenge])
}

pub fn generate_challenge() -> String {
    let mut bytes = [0u8; 16];
    let _ = getrandom(&mut bytes);
    hex::encode(bytes)
}

/// Verifies an AUTH event against the challenge this connection issued.
///
/// Per NIP-42 the `relay` tag must match the relay's own URL; `host`, `port`
/// and `public_url` identify this relay.
pub fn verify(
    event: &Event,
    challenge: &str,
    secp: &Secp256k1<secp256k1::All>,
    now: u64,
    identity: &crate::nips::nip62::RelayIdentity<'_>,
) -> bool {
    if event.kind != AUTH_KIND {
        return false;
    }
    if nip01::verify(event, secp).is_err() {
        return false;
    }
    if event.created_at.abs_diff(now) > 600 {
        return false;
    }
    let has_challenge = event
        .tags
        .iter()
        .any(|t| t.len() >= 2 && t[0] == CHALLENGE_TAG && t[1] == challenge);
    // `ALL_RELAYS` is a NIP-62 vanish scope, not a relay URL: it must not
    // authenticate a connection on its own (the per-connection challenge
    // would still bind it, but the spec requires the relay URL).
    let has_relay = event.tags.iter().any(|t| {
        t.len() >= 2
            && t[0] == RELAY_TAG
            && t[1] != crate::nips::nip62::ALL_RELAYS
            && crate::nips::nip62::tag_matches(&t[1], identity)
    });
    has_challenge && has_relay
}

pub fn ok(id: &str, accepted: bool) -> Value {
    if accepted {
        json!(["OK", id, true, ""])
    } else {
        json!(["OK", id, false, "error: invalid auth event"])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nips::nip01::compute_id;
    use crate::nips::nip62::RelayIdentity;
    use secp256k1::{Keypair, XOnlyPublicKey};

    fn event(created: u64, tags: Vec<Vec<String>>) -> Event {
        let mut ev = Event {
            id: String::new(),
            pubkey: "0000000000000000000000000000000000000000000000000000000000000000".into(),
            created_at: created,
            kind: AUTH_KIND,
            tags,
            content: String::new(),
            sig: "00".repeat(64),
        };
        ev.id = compute_id(&ev);
        ev
    }

    /// Builds an auth event with a valid signature so the relay-tag check is
    /// exercised in isolation.
    fn signed_event(created: u64, tags: Vec<Vec<String>>) -> Event {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_seckey_slice(&secp, &[1u8; 32]).unwrap();
        let pubkey = XOnlyPublicKey::from_keypair(&keypair).0.to_string();
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

    #[test]
    fn challenge_generation() {
        let a = generate_challenge();
        let b = generate_challenge();
        assert_eq!(a.len(), 32);
        assert_ne!(a, b);
    }

    #[test]
    fn requires_matching_challenge() {
        let secp = Secp256k1::new();
        let ev = event(
            1_700_000_000,
            vec![
                vec!["relay".into(), "ws://localhost:8080".into()],
                vec!["challenge".into(), "wrong".into()],
            ],
        );
        assert!(!verify(
            &ev,
            "right",
            &secp,
            1_700_000_000,
            &RelayIdentity::new("localhost", 8080, "")
        ));
    }

    #[test]
    fn wrong_kind_rejected() {
        let secp = Secp256k1::new();
        let mut ev = event(
            1_700_000_000,
            vec![
                vec!["relay".into(), "ws://localhost:8080".into()],
                vec!["challenge".into(), "abc".into()],
            ],
        );
        ev.kind = 1;
        assert!(!verify(
            &ev,
            "abc",
            &secp,
            1_700_000_000,
            &RelayIdentity::new("localhost", 8080, "")
        ));
    }

    #[test]
    fn relay_tag_must_match_our_url() {
        let secp = Secp256k1::new();
        let now = 1_700_000_000;
        // A wrong host is rejected even with a valid signature.
        let ev = signed_event(
            now,
            vec![
                vec!["relay".into(), "ws://other.example.com:8080".into()],
                vec!["challenge".into(), "abc".into()],
            ],
        );
        assert!(!verify(
            &ev,
            "abc",
            &secp,
            now,
            &RelayIdentity::new("localhost", 8080, "")
        ));
        // Wrong port is also rejected.
        let ev = signed_event(
            now,
            vec![
                vec!["relay".into(), "ws://localhost:9999".into()],
                vec!["challenge".into(), "abc".into()],
            ],
        );
        assert!(!verify(
            &ev,
            "abc",
            &secp,
            now,
            &RelayIdentity::new("localhost", 8080, "")
        ));
        // A matching URL passes the relay check.
        let ev = signed_event(
            now,
            vec![
                vec!["relay".into(), "ws://localhost:8080".into()],
                vec!["challenge".into(), "abc".into()],
            ],
        );
        assert!(verify(
            &ev,
            "abc",
            &secp,
            now,
            &RelayIdentity::new("localhost", 8080, "")
        ));
        // public_url takes precedence over host:port.
        let ev = signed_event(
            now,
            vec![
                vec!["relay".into(), "wss://public.example.net/some/path".into()],
                vec!["challenge".into(), "abc".into()],
            ],
        );
        assert!(verify(
            &ev,
            "abc",
            &secp,
            now,
            &RelayIdentity::new("127.0.0.1", 8080, "wss://public.example.net")
        ));
    }

    #[test]
    fn all_relays_does_not_authenticate() {
        // `ALL_RELAYS` is a NIP-62 vanish scope, not a relay URL.
        let secp = Secp256k1::new();
        let now = 1_700_000_000;
        let ev = signed_event(
            now,
            vec![
                vec!["relay".into(), crate::nips::nip62::ALL_RELAYS.into()],
                vec!["challenge".into(), "abc".into()],
            ],
        );
        assert!(
            !verify(
                &ev,
                "abc",
                &secp,
                now,
                &RelayIdentity::new("localhost", 8080, "")
            ),
            "ALL_RELAYS must not satisfy the NIP-42 relay tag"
        );
    }
}
