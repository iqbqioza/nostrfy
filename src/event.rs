//! The wire representation of a Nostr event.

use serde::{Deserialize, Serialize};

use crate::nips::nip01;

/// A Nostr event as defined by NIP-01. NIP-specific behaviour lives in the
/// `nips` modules; this struct only holds the data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Event {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u64,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

impl Event {
    pub fn id_bytes(&self) -> Option<[u8; nip01::ID_BYTES]> {
        hex::decode(&self.id).ok()?.try_into().ok()
    }

    pub fn pubkey_bytes(&self) -> Option<[u8; nip01::PK_BYTES]> {
        hex::decode(&self.pubkey).ok()?.try_into().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::fuzz_tests::{Rng, random_event, random_json};

    fn event() -> Event {
        Event {
            id: "a".repeat(64),
            pubkey: "b".repeat(64),
            created_at: 1,
            kind: 1,
            tags: vec![vec!["t".into(), "rust".into()]],
            content: "hello".into(),
            sig: "c".repeat(128),
        }
    }

    #[test]
    fn id_bytes_validates_length() {
        let ev = event();
        assert_eq!(ev.id_bytes().unwrap().len(), 32);
        let bad = Event {
            id: "abc".into(),
            ..event()
        };
        assert!(bad.id_bytes().is_none());
    }

    // ----- deterministic fuzzing (see crate::fuzz_tests) -----

    #[test]
    fn fuzz_random_events_roundtrip_and_never_panic_the_helpers() {
        // Structurally valid events with random contents survive a JSON
        // round-trip, and the helpers reachable without a database
        // (id_bytes, pubkey_bytes, the canonical id) never panic on them.
        let mut rng = Rng::new(0x5eed_e001);
        for _ in 0..4_000 {
            let original = random_event(&mut rng);
            let text = serde_json::to_string(&original).unwrap();
            let decoded: Event = serde_json::from_str(&text).unwrap();
            assert_eq!(decoded, original, "a serialized event must round-trip");
            // The helpers decode hex: exactly 64 hex characters yield
            // bytes, anything else (wrong length or non-hex) yields None.
            let is_hex64 = |s: &str| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit());
            assert_eq!(decoded.id_bytes().is_some(), is_hex64(&decoded.id));
            assert_eq!(decoded.pubkey_bytes().is_some(), is_hex64(&decoded.pubkey));
            assert_eq!(crate::nips::nip01::compute_id(&decoded).len(), 64);
        }

        // Random JSON text through the wire parser must never panic; only
        // the rare structurally complete object parses.
        for _ in 0..4_000 {
            let value = random_json(&mut rng, 4);
            let text = serde_json::to_string(&value).unwrap();
            if let Ok(decoded) = serde_json::from_str::<Event>(&text) {
                let _ = decoded.id_bytes();
                let _ = decoded.pubkey_bytes();
                let _ = crate::nips::nip01::compute_id(&decoded);
            }
        }
    }

    #[test]
    fn fuzz_event_hex_length_checks_never_panic() {
        // Random hex-ish field lengths around 64/128 characters: the
        // length checks must return None instead of panicking.
        let mut rng = Rng::new(0x5eed_e002);
        for _ in 0..2_000 {
            let id_len = rng.below(80);
            let pk_len = rng.below(80);
            let sig_len = rng.below(160);
            let tag_count = rng.below(3);
            let ev = Event {
                id: rng.hex(id_len),
                pubkey: rng.hex(pk_len),
                created_at: rng.next_u64(),
                kind: rng.next_u64(),
                tags: (0..tag_count)
                    .map(|_| {
                        let value_count = rng.below(3);
                        (0..value_count).map(|_| rng.hex(4)).collect()
                    })
                    .collect(),
                content: crate::fuzz_tests::random_string(&mut rng, 20),
                sig: rng.hex(sig_len),
            };
            assert_eq!(ev.id_bytes().is_some(), ev.id.len() == 64);
            assert_eq!(ev.pubkey_bytes().is_some(), ev.pubkey.len() == 64);
        }
    }
}
