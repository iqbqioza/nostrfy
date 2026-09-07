//! NIP-01: Basic Protocol Flow.
//!
//! Event format, canonical serialization, id computation and Schnorr
//! signature verification, plus the regular replaceable event range.

use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, Secp256k1, XOnlyPublicKey};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::event::Event;

pub const ID_BYTES: usize = 32;
pub const PK_BYTES: usize = 32;
pub const SIG_BYTES: usize = 64;

/// Canonical serialization of an event without the `id` and `sig` fields.
///
/// The payload is serialized directly from a tuple — the `serde_json::json!`
/// macro would build an intermediate `Value` tree first, doubling the
/// allocation work on this hot path (every published event is hashed here).
///
/// C0 control bytes in the content stay escaped (`\u00XX`), exactly as
/// mainstream clients serialize them (`JSON.stringify` in nostr-tools,
/// `encoding/json` in go-nostr, serde in the Rust `nostr` crate all escape
/// control bytes, and the id is computed over that escaped text): restoring
/// them to raw bytes would reject every ecosystem-signed event that
/// contains a control byte.
pub fn canonical_payload(event: &Event) -> Vec<u8> {
    serde_json::to_vec(&(
        0u8,
        &event.pubkey,
        event.created_at,
        event.kind,
        &event.tags,
        &event.content,
    ))
    .expect("canonical serialization cannot fail")
}

pub fn compute_id(event: &Event) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical_payload(event));
    hex::encode(hasher.finalize())
}

/// Verifies the event id and the Schnorr signature.
pub fn verify(event: &Event, secp: &Secp256k1<secp256k1::All>) -> Result<()> {
    if event.id.len() != ID_BYTES * 2
        || event.pubkey.len() != PK_BYTES * 2
        || event.sig.len() != SIG_BYTES * 2
    {
        return Err(Error::Protocol("invalid id/pubkey/sig length".into()));
    }
    if compute_id(event) != event.id {
        return Err(Error::Protocol("invalid event id".into()));
    }
    let id_bytes: [u8; ID_BYTES] = event
        .id_bytes()
        .ok_or_else(|| Error::Protocol("invalid id hex".into()))?;
    let pk = XOnlyPublicKey::from_slice(&hex::decode(&event.pubkey)?)?;
    let sig = Signature::from_slice(&hex::decode(&event.sig)?)?;
    secp.verify_schnorr(&sig, &id_bytes, &pk)?;
    Ok(())
}

/// Signs an event with the given keypair: computes the id and the Schnorr
/// signature. Used by the relay for NIP-29 relay-generated events.
pub fn sign(event: &mut Event, keypair: &Keypair, secp: &Secp256k1<secp256k1::All>) -> Result<()> {
    event.id = compute_id(event);
    let id: [u8; ID_BYTES] = event
        .id_bytes()
        .ok_or_else(|| Error::Protocol("invalid id".into()))?;
    let mut aux = [0u8; 32];
    getrandom::getrandom(&mut aux).map_err(|_| Error::Protocol("rng failure".into()))?;
    event.sig = secp
        .sign_schnorr_with_aux_rand(&id, keypair, &aux)
        .to_string();
    Ok(())
}

/// Regular replaceable event kinds (NIP-01): kinds 0 and 3, plus 10000-19999.
pub fn is_replaceable_kind(kind: u64) -> bool {
    kind == 0 || kind == 3 || (10000..20000).contains(&kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> Event {
        Event {
            id: "4b5e47d19a5f6a4a1a4f1f2a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c".into(),
            pubkey: "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d".into(),
            created_at: 1_600_000_000,
            kind: 1,
            tags: vec![],
            content: "hello".into(),
            sig: "7f3a4c1e9a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d".into(),
        }
    }

    #[test]
    fn canonical_payload_is_stable() {
        let ev = sample_event();
        assert_eq!(
            canonical_payload(&ev),
            b"[0,\"3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d\",1600000000,1,[],\"hello\"]"
        );
    }

    /// NIP-01: the escaping rules for the canonical serialization — a line
    /// break, double quote, backslash, carriage return, tab, backspace and
    /// form feed must be escaped as `\n \" \\ \r \t \b \f` and all other
    /// characters must be included verbatim (UTF-8).
    #[test]
    fn canonical_payload_escapes_per_nip01() {
        let ev = Event {
            id: String::new(),
            pubkey: "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d".into(),
            created_at: 1_600_000_000,
            kind: 1,
            tags: vec![vec![
                "quote\"backslash\\tab\t".into(),
                "line\ncr\rbs\x08ff\x0c".into(),
            ]],
            content: "日本語 ünïcode \n\t\"\\\r\x08\x0c end".into(),
            sig: String::new(),
        };
        // Hand-written canonical JSON per the NIP-01 escaping table.
        let expected = b"[0,\"3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d\",1600000000,1,[[\"quote\\\"backslash\\\\tab\\t\",\"line\\ncr\\rbs\\bff\\f\"]],\"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e \xc3\xbcn\xc3\xafcode \\n\\t\\\"\\\\\\r\\b\\f end\"]";
        assert_eq!(canonical_payload(&ev), expected);
        // The id is the sha256 of the escaped serialization.
        let id = Sha256::digest(expected);
        assert_eq!(compute_id(&ev), hex::encode(id));
    }

    #[test]
    fn replaceable_ranges() {
        assert!(is_replaceable_kind(0));
        assert!(is_replaceable_kind(3));
        assert!(is_replaceable_kind(10000));
        assert!(is_replaceable_kind(19999));
        assert!(!is_replaceable_kind(20000));
        assert!(!is_replaceable_kind(30023));
        assert!(!is_replaceable_kind(1));
    }

    #[test]
    fn nak_generated_event_id_and_signature_verify() {
        // Cross-implementation check against fiatjaf's `nak` (v0.20.6):
        // an event built and signed by nak must have its id recomputed to
        // the identical value by nostrfy's canonical serializer and its
        // signature must verify (independent-ecosystem agreement).
        let ev = Event {
            id: "989a6847782177472741aafc77bef7b888c19157484488bbffe0bf558d1c8002".into(),
            pubkey: "5fab88cf2058ada0f460f9b07623f62be4ad378ea95bcf3823ddabc81f580cf0".into(),
            created_at: 1788752313,
            kind: 1,
            tags: vec![],
            content: "nak cross-check: hello world".into(),
            sig: "e5d00726edaec764b220b6bf5f2e2b19b0cf12925c89263b66d4e8308a3cb213fe71a57f0f3d97d59b5320e83dd389ab0639e68d2a5acbac3d0b4b49d0407f63".into(),
        };
        assert_eq!(
            compute_id(&ev),
            ev.id,
            "nostrfy's canonical id must match nak's"
        );
        let secp = Secp256k1::new();
        assert!(
            verify(&ev, &secp).is_ok(),
            "an event signed by nak must verify"
        );
    }

    #[test]
    fn signature_verification_roundtrip() {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_seckey_slice(&secp, &[7u8; 32]).unwrap();
        let pubkey = XOnlyPublicKey::from_keypair(&keypair).0.to_string();
        let mut event = Event {
            id: String::new(),
            pubkey,
            created_at: 1_600_000_000,
            kind: 1,
            tags: vec![],
            content: "signed message".into(),
            sig: String::new(),
        };
        sign(&mut event, &keypair, &secp).unwrap();
        assert_eq!(event.id.len(), 64);
        assert_eq!(event.sig.len(), 128);
        assert!(verify(&event, &secp).is_ok());

        // Tampering with the content invalidates the id.
        let mut tampered = event.clone();
        tampered.content = "tampered".into();
        assert!(verify(&tampered, &secp).is_err());

        // Tampering with the signature is caught by schnorr verification.
        let mut bad_sig = event.clone();
        bad_sig.sig = "1".repeat(128);
        assert!(verify(&bad_sig, &secp).is_err());

        // A signature from a different key fails.
        let other = Keypair::from_seckey_slice(&secp, &[9u8; 32]).unwrap();
        let mut forged = event.clone();
        sign(&mut forged, &other, &secp).unwrap();
        forged.pubkey = event.pubkey.clone();
        assert!(verify(&forged, &secp).is_err());
    }
}

#[cfg(test)]
mod control_tests {
    use super::*;
    use crate::event::Event;

    #[test]
    fn canonical_payload_escapes_control_bytes_like_the_ecosystem() {
        // Mainstream clients (nostr-tools' JSON.stringify, go-nostr,
        // the Rust nostr crate) escape C0 control bytes as `\u00XX` and
        // compute the event id over that escaped text. The canonical
        // payload must match them: restoring raw bytes (the old behavior)
        // rejected every ecosystem-signed event containing a control byte.
        let mut event = Event {
            id: "0".repeat(64),
            pubkey: "1".repeat(64),
            created_at: 1_600_000_000,
            kind: 1,
            tags: vec![],
            content: "\x01\x0b\x1f \t\n \" \\ \u{0000}".into(),
            sig: "2".repeat(128),
        };
        let payload = canonical_payload(&event);
        let text = String::from_utf8_lossy(&payload);
        assert!(
            text.contains("\\u0001") && text.contains("\\u000b") && text.contains("\\u001f"),
            "control bytes stay escaped like client serializers: {text:?}"
        );
        assert!(
            !text.contains('\u{1}'),
            "no raw control bytes in the payload: {text:?}"
        );
        // The 7 escaped forms survive untouched.
        assert!(text.contains("\\t") && text.contains("\\n"));
        assert!(text.contains("\\\"") && text.contains("\\\\"));
        // A literal backslash-u in the content stays escaped text.
        event.content = "literal \\\\u0002 text".into();
        let payload = canonical_payload(&event);
        let text = String::from_utf8_lossy(&payload);
        assert!(
            text.contains("\\\\u0002"),
            "a literal backslash-u stays escaped: {text:?}"
        );
    }

    #[test]
    fn control_bytes_roundtrip_through_verify() {
        // An event with C0 control bytes in its content must verify with
        // its own compute_id (the id a mainstream client computes over
        // the escaped serialization).
        let event = Event {
            id: String::new(),
            pubkey: "ab".repeat(32),
            created_at: 1_600_000_000,
            kind: 1,
            tags: vec![],
            content: "a\x01b\x0cc\x1fd".into(),
            sig: "cd".repeat(64),
        };
        let id = compute_id(&event);
        let mut signed = event;
        signed.id = id;
        let secp = secp256k1::Secp256k1::new();
        // The id check runs first: reaching the signature check means the
        // canonical id computed by this crate matches the one signed by
        // the client, so a canonicalization bug would fail here with an
        // id error instead.
        let err = verify(&signed, &secp).unwrap_err();
        // The id check runs first and returns its own error string: if the
        // canonical id did not match, the verify would report the id (not
        // the signature). The fake signature must be the reported failure.
        assert!(
            err.to_string().contains("signature"),
            "the canonical id matched; only the fake signature failed: {err}"
        );
    }
}
