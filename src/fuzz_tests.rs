//! Deterministic, dependency-free fuzz/property tests for the parsers that
//! face untrusted input.
//!
//! `proptest`/`quickcheck` are not available (the build must work offline),
//! so the drivers run on a tiny xorshift64 PRNG with fixed seeds: a failure
//! reproduces exactly (same seed, same iteration, same bytes). Each test
//! stays in the tens of milliseconds so the module is CI-fast.

use serde_json::{Map, Value};

use crate::event::Event;

/// xorshift64 (Marsaglia): three shifts and xors, no allocation, no
/// dependency.
pub(crate) struct Rng(u64);

impl Rng {
    /// A fixed-seed generator. Zero is a fixed point of xorshift64, so it
    /// is remapped to a non-zero constant.
    pub(crate) fn new(seed: u64) -> Self {
        Self(if seed == 0 {
            0x9e37_79b9_7f4a_7c15
        } else {
            seed
        })
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// A value in `0..bound` (`bound` must be non-zero).
    pub(crate) fn below(&mut self, bound: usize) -> usize {
        (self.next_u64() % bound as u64) as usize
    }

    pub(crate) fn bool(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }

    pub(crate) fn fill(&mut self, buf: &mut [u8]) {
        for byte in buf {
            *byte = self.next_u64() as u8;
        }
    }

    /// A random lowercase-hex string of exactly `len` characters.
    pub(crate) fn hex(&mut self, len: usize) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        (0..len).map(|_| DIGITS[self.below(16)] as char).collect()
    }
}

/// Random text mixing quotes, backslashes, control bytes and multi-byte
/// UTF-8, so JSON escaping and the text tokenizers are exercised.
pub(crate) fn random_string(rng: &mut Rng, max_chars: usize) -> String {
    const ALPHABET: &[char] = &[
        'a', 'b', '1', ' ', '"', '\\', '\n', '\t', '\u{7f}', 'é', '日', '𝄞', '#', 'e', 'p',
    ];
    let len = rng.below(max_chars + 1);
    (0..len)
        .map(|_| ALPHABET[rng.below(ALPHABET.len())])
        .collect()
}

/// A random JSON value with bounded depth. Object keys frequently use the
/// names the filter parser treats specially (`ids`, `#e`, `inbox`, ...) so
/// the generated documents reach the interesting type checks.
pub(crate) fn random_json(rng: &mut Rng, depth: usize) -> Value {
    let choice = if depth == 0 {
        rng.below(4)
    } else {
        rng.below(8)
    };
    match choice {
        0 => Value::Null,
        1 => Value::Bool(rng.bool()),
        2 => Value::Number(rng.next_u64().into()),
        3 => Value::String(random_string(rng, 12)),
        4 | 5 => {
            let len = rng.below(8);
            Value::Array((0..len).map(|_| random_json(rng, depth - 1)).collect())
        }
        _ => {
            const KEYS: &[&str] = &[
                "ids", "authors", "kinds", "since", "until", "limit", "search", "#e", "#p", "#t",
                "inbox", "outbox",
            ];
            let len = rng.below(6);
            let mut map = Map::new();
            for _ in 0..len {
                let key = if rng.bool() {
                    KEYS[rng.below(KEYS.len())].to_string()
                } else {
                    random_string(rng, 8)
                };
                map.insert(key, random_json(rng, depth - 1));
            }
            Value::Object(map)
        }
    }
}

/// A structurally valid event with random contents: the field types are
/// right, the values (lengths, hex-ness, control bytes, timestamps) are
/// not.
pub(crate) fn random_event(rng: &mut Rng) -> Event {
    let tags = (0..rng.below(4))
        .map(|_| {
            (0..rng.below(4))
                .map(|_| random_string(rng, 8))
                .collect::<Vec<String>>()
        })
        .collect();
    Event {
        id: random_string(rng, 70),
        pubkey: random_string(rng, 70),
        created_at: rng.next_u64(),
        kind: rng.next_u64(),
        tags,
        content: random_string(rng, 40),
        sig: random_string(rng, 140),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deeply_nested_and_huge_json_never_panics_the_parsers() {
        // Arrays nested past serde_json's recursion limit are rejected
        // (an error, not a panic or stack overflow) by both parsers.
        let deep = format!("{}{}", "[".repeat(300), "]".repeat(300));
        assert!(serde_json::from_str::<crate::filter::Filter>(&deep).is_err());
        assert!(serde_json::from_str::<Event>(&deep).is_err());

        // A huge tag-constraint array (bounded to a test size) parses and
        // is flagged over the cap without walking the whole array.
        let large = format!(
            r##"{{"#e": [{}]}}"##,
            vec!["\"x\"".to_string(); 10_000].join(",")
        );
        let filter: crate::filter::Filter = serde_json::from_str(&large).unwrap();
        assert!(filter.too_many_members());

        // A large event body parses without any allocation surprise.
        let event = format!(
            r#"{{"id":"{}","pubkey":"{}","created_at":0,"kind":0,"tags":[],"content":"{}","sig":"{}"}}"#,
            "0".repeat(64),
            "0".repeat(64),
            "x".repeat(10_000),
            "0".repeat(128)
        );
        let parsed: Event = serde_json::from_str(&event).unwrap();
        assert_eq!(parsed.content.len(), 10_000);
    }

    #[test]
    fn random_events_never_panic_signature_verification() {
        // `nip01::verify` is reachable without a database (it is the first
        // gate of the accept path): random field contents must fail closed
        // with an error, never panic. Half the events get a consistent id
        // so the Schnorr verification itself runs on random signatures.
        let secp = secp256k1::Secp256k1::new();
        let mut rng = Rng::new(0x5eed_0007);
        let mut reached_signature = 0usize;
        for _ in 0..600 {
            let mut event = random_event(&mut rng);
            if rng.bool() {
                event.pubkey = rng.hex(64);
                event.sig = rng.hex(128);
                event.id = crate::nips::nip01::compute_id(&event);
                if secp256k1::XOnlyPublicKey::from_slice(&hex::decode(&event.pubkey).unwrap())
                    .is_ok()
                {
                    reached_signature += 1;
                }
            }
            assert!(
                crate::nips::nip01::verify(&event, &secp).is_err(),
                "random events must never verify"
            );
        }
        assert!(
            reached_signature > 0,
            "the Schnorr path itself must be exercised"
        );
    }
}
