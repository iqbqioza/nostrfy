//! NIP-26: Delegated Event Signing.
//!
//! A `delegation` tag `["delegation", <pubkey>, <conditions>, <sig>]` lets a
//! delegator authorize another key to publish events matching the conditions.

use secp256k1::Secp256k1;
use sha2::{Digest, Sha256};

use crate::event::Event;

pub const DELEGATION_TAG: &str = "delegation";

/// Returns `[delegator_pubkey, conditions, sig]` when a delegation tag exists.
pub fn delegation(event: &Event) -> Option<[&str; 3]> {
    event.tags.iter().find_map(|t| {
        if t.len() == 4 && t[0] == DELEGATION_TAG {
            Some([t[1].as_str(), t[2].as_str(), t[3].as_str()])
        } else {
            None
        }
    })
}

/// Evaluates delegation conditions such as
/// `kind=1&kind=2&created_at>1682500000&created_at<1690000000`.
///
/// Per NIP-26, "multiple conditions can be used in a single query string,
/// including on the same field": conditions sharing a field and operator
/// are OR-combined (`kind=0&kind=1` allows either kind), while distinct
/// field/operator groups are AND-combined (`created_at>X&created_at<Y`
/// requires both bounds, i.e. a window).
pub fn conditions_allow(conditions: &str, kind: u64, created_at: u64) -> bool {
    // (field, operator) -> whether some condition of that group passed.
    let mut results: Vec<((&str, &str), bool)> = Vec::new();
    for cond in conditions.split('&') {
        let cond = cond.trim();
        if cond.is_empty() {
            continue;
        }
        let (key, result) = if let Some(value) = cond.strip_prefix("kind=") {
            // The `|` pipe is a nostrfy extension kept for compatibility;
            // the spec form is repeated `kind=` conditions.
            (
                ("kind", "="),
                value
                    .split('|')
                    .any(|k| k.parse::<u64>().map(|k| k == kind).unwrap_or(false)),
            )
        } else if let Some(value) = cond.strip_prefix("created_at>=") {
            (
                ("created_at", ">="),
                value
                    .parse::<u64>()
                    .map(|v| created_at >= v)
                    .unwrap_or(false),
            )
        } else if let Some(value) = cond.strip_prefix("created_at<=") {
            (
                ("created_at", "<="),
                value
                    .parse::<u64>()
                    .map(|v| created_at <= v)
                    .unwrap_or(false),
            )
        } else if let Some(value) = cond.strip_prefix("created_at>") {
            (
                ("created_at", ">"),
                value
                    .parse::<u64>()
                    .map(|v| created_at > v)
                    .unwrap_or(false),
            )
        } else if let Some(value) = cond.strip_prefix("created_at<") {
            (
                ("created_at", "<"),
                value
                    .parse::<u64>()
                    .map(|v| created_at < v)
                    .unwrap_or(false),
            )
        } else {
            // An unknown or malformed condition never allows the event.
            (("", ""), false)
        };
        results.push((key, result));
    }
    if results.is_empty() {
        return true;
    }
    if results
        .iter()
        .any(|((f, o), _)| f.is_empty() && o.is_empty())
    {
        return false;
    }
    // AND across distinct (field, operator) groups; OR within a group.
    results
        .iter()
        .all(|(key, _)| results.iter().any(|(k, r)| k == key && *r))
}

/// Verifies a delegation tag when present. Events without a delegation tag
/// are always accepted (they are signed by their own key).
pub fn verify(event: &Event, secp: &Secp256k1<secp256k1::All>) -> bool {
    let Some([delegator, conditions, sig]) = delegation(event) else {
        return true;
    };
    let Ok(delegator_pk) = hex::decode(delegator) else {
        return false;
    };
    let Ok(sig) = hex::decode(sig) else {
        return false;
    };
    if sig.len() != 64 {
        return false;
    }
    // NIP-26: the token is a signature over the *delegatee's* pubkey, i.e.
    // the pubkey of the event being published (the event's own author).
    let payload = format!("nostr:delegation:{}:{conditions}", event.pubkey);
    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    let message: [u8; 32] = hasher.finalize().into();
    let Ok(pk) = secp256k1::XOnlyPublicKey::from_slice(&delegator_pk) else {
        return false;
    };
    let Ok(sig) = secp256k1::schnorr::Signature::from_slice(&sig) else {
        return false;
    };
    secp.verify_schnorr(&sig, &message, &pk).is_ok()
        && conditions_allow(conditions, event.kind, event.created_at)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conditions() {
        assert!(conditions_allow("kind=1", 1, 1_600_000_000));
        assert!(!conditions_allow("kind=1", 2, 1_600_000_000));
        assert!(conditions_allow("kind=1|2", 2, 1_600_000_000));
        // NIP-26: same-field conditions are OR-combined (the spec's own
        // example `kind=0&kind=1` must allow either kind).
        assert!(conditions_allow("kind=0&kind=1", 0, 1_600_000_000));
        assert!(conditions_allow("kind=0&kind=1", 1, 1_600_000_000));
        assert!(!conditions_allow("kind=0&kind=1", 2, 1_600_000_000));
        assert!(conditions_allow("created_at<1700000000", 1, 1_600_000_000));
        assert!(!conditions_allow("created_at<1600000000", 1, 1_600_000_000));
        // Different operators on the same field are AND-combined (a window).
        assert!(conditions_allow(
            "created_at>1500000000&created_at<1700000000",
            1,
            1_600_000_000
        ));
        assert!(!conditions_allow(
            "created_at>1700000000&created_at<1800000000",
            1,
            1_600_000_000
        ));
        // Mixed same-field OR across fields AND.
        assert!(conditions_allow(
            "kind=1&kind=2&created_at>1500000000&created_at<1700000000",
            2,
            1_600_000_000
        ));
        assert!(!conditions_allow(
            "kind=1&kind=2&created_at>1700000000",
            1,
            1_600_000_000
        ));
        assert!(conditions_allow(
            "kind=1&created_at>1500000000",
            1,
            1_600_000_000
        ));
    }

    #[test]
    fn no_delegation_tag_accepted() {
        let ev = Event {
            id: "a".repeat(64),
            pubkey: "b".repeat(64),
            created_at: 1,
            kind: 1,
            tags: vec![],
            content: String::new(),
            sig: "c".repeat(128),
        };
        let secp = Secp256k1::new();
        assert!(verify(&ev, &secp));
    }

    #[test]
    fn spec_example_delegation_verifies() {
        // The NIP-26 spec example: delegator 8e0d3d3e... grants the
        // delegatee 477318cf... permission with
        // "kind=1&created_at>1674834236&created_at<1677426236".
        let secp = Secp256k1::new();
        let delegator =
            "8e0d3d3eb2881ec137a11debe736a9086715a8c8beeeda615780064d68bc25dd".to_string();
        let delegatee =
            "477318cfb5427b9cfc66a9fa376150c1ddbc62115ae27cef72417eb959691396".to_string();
        let conditions = "kind=1&created_at>1674834236&created_at<1677426236";
        // The token is signed over the DELEGATEE's pubkey, per the spec.
        let payload = format!("nostr:delegation:{delegatee}:{conditions}");
        let mut hasher = Sha256::new();
        hasher.update(payload.as_bytes());
        let message: [u8; 32] = hasher.finalize().into();
        let delegator_key = secp256k1::Keypair::from_seckey_slice(
            &secp,
            &hex::decode("ee35e8bb71131c02c1d7e73231daa48e9953d329a4b701f7133c8f46dd21139c")
                .unwrap(),
        )
        .unwrap();
        let token = secp
            .sign_schnorr_no_aux_rand(&message, &delegator_key)
            .to_string();

        let ev = Event {
            id: String::new(),
            pubkey: delegatee,
            created_at: 1_677_000_000,
            kind: 1,
            tags: vec![vec![
                DELEGATION_TAG.into(),
                delegator,
                conditions.into(),
                token,
            ]],
            content: "Hello, world!".into(),
            sig: String::new(),
        };
        assert!(verify(&ev, &secp));

        // A token signed over the delegator's own pubkey (the previous,
        // incorrect behavior) must fail.
        let bad_token = {
            let payload = format!("nostr:delegation:{}:{conditions}", ev.tags[0][1]);
            let mut hasher = Sha256::new();
            hasher.update(payload.as_bytes());
            let message: [u8; 32] = hasher.finalize().into();
            secp.sign_schnorr_no_aux_rand(&message, &delegator_key)
                .to_string()
        };
        let mut bad_ev = ev.clone();
        bad_ev.tags[0][3] = bad_token;
        assert!(!verify(&bad_ev, &secp));
    }
}
