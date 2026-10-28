//! NIP-IA: Identity Archival (Buzz draft).
//!
//! The relay keeps a relay-scoped set of archived pubkeys and publishes the
//! NIP-IA snapshot and deltas. Archive state is visibility metadata only; it
//! never deletes history or grants/denies access.

use std::collections::BTreeSet;

use secp256k1::schnorr::Signature;
use sha2::{Digest, Sha256};

use crate::event::Event;

/// NIP-IA current archived-identities snapshot (replaceable).
pub const ARCHIVED_IDENTITIES: u64 = 13535;
pub const ARCHIVED_DELTA: u64 = 8002;
pub const UNARCHIVED_DELTA: u64 = 8003;

/// Bound on the relay-scoped archived-identities set. The snapshot is
/// relay-signed and grows one `p` tag per identity, so accepting unbounded
/// self-archive requests would make every 13535 publish arbitrarily large.
pub(crate) const MAX_ARCHIVED_IDENTITIES: usize = 10_000;

/// The relay's NIP-IA archived-identities snapshot. The NIP-70 `-` tag marks
/// it as relay state; one bare `p` tag names each archived identity.
pub fn snapshot(relay_pubkey: &str, now: u64, archived: &BTreeSet<String>) -> Event {
    let mut tags = vec![vec!["-".to_string()]];
    tags.extend(
        archived
            .iter()
            .take(MAX_ARCHIVED_IDENTITIES)
            .map(|pubkey| vec!["p".to_string(), pubkey.clone()]),
    );
    base(ARCHIVED_IDENTITIES, relay_pubkey, now, tags, "")
}

/// One NIP-IA archive/unarchive delta.
#[allow(clippy::too_many_arguments)]
pub fn delta(
    relay_pubkey: &str,
    now: u64,
    target: &str,
    archived: bool,
    consent: &str,
    consent_pubkey: Option<&str>,
    request_id: &str,
    reason: Option<&str>,
    replaced_by: Option<&str>,
    content: &str,
) -> Event {
    let mut tags = vec![
        vec!["-".to_string()],
        vec!["p".to_string(), target.to_string()],
    ];
    let mut consent_tag = vec!["consent".to_string(), consent.to_string()];
    if let Some(pubkey) = consent_pubkey {
        consent_tag.push(pubkey.to_string());
    }
    tags.push(consent_tag);
    tags.push(vec!["e".to_string(), request_id.to_string()]);
    if let Some(reason) = reason.filter(|reason| !reason.is_empty()) {
        tags.push(vec!["reason".to_string(), reason.to_string()]);
    }
    if let Some(replaced_by) = replaced_by.filter(|pubkey| !pubkey.is_empty()) {
        tags.push(vec!["replaced-by".to_string(), replaced_by.to_string()]);
    }
    base(
        if archived {
            ARCHIVED_DELTA
        } else {
            UNARCHIVED_DELTA
        },
        relay_pubkey,
        now,
        tags,
        content,
    )
}

/// Verifies the request-borne NIP-OA owner-of-agent path. Returns the owner
/// pubkey that consented when the single `auth` tag is valid.
pub(crate) fn verify_owner_agent_request(event: &Event, target: &str) -> Option<String> {
    let (owner, conditions, signature) = auth_tag(event)?;
    if !owner.eq_ignore_ascii_case(&event.pubkey)
        || target.eq_ignore_ascii_case(&owner)
        || !owner_conditions_allow(conditions, event.created_at)
    {
        return None;
    }
    verify_owner_signature(&owner, target, conditions, signature).then_some(owner)
}

/// Verifies the published-profile NIP-OA attestation path: the target's
/// latest kind:0 carries a standing owner authorization. Conditions are
/// syntax-checked but deliberately not evaluated (they describe the profile,
/// not the archive request).
pub(crate) fn verify_owner_agent_profile(
    profile: &Event,
    target: &str,
    expected_owner: &str,
) -> Option<String> {
    if profile.kind != 0
        || !profile.pubkey.eq_ignore_ascii_case(target)
        || crate::nips::nip01::verify(profile).is_err()
    {
        return None;
    }
    let (owner, conditions, signature) = auth_tag(profile)?;
    if !owner.eq_ignore_ascii_case(expected_owner)
        || target.eq_ignore_ascii_case(&owner)
        || !owner_conditions_syntax(conditions)
    {
        return None;
    }
    verify_owner_signature(&owner, target, conditions, signature).then_some(owner)
}

fn auth_tag(event: &Event) -> Option<(String, &str, &str)> {
    let mut auth = event
        .tags
        .iter()
        .filter(|tag| tag.len() == 4 && tag[0] == "auth");
    let tag = auth.next()?;
    if auth.next().is_some() {
        return None;
    }
    let owner = tag[1].to_ascii_lowercase();
    if owner.len() != 64 || !owner.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some((owner, tag[2].as_str(), tag[3].as_str()))
}

fn verify_owner_signature(owner: &str, target: &str, conditions: &str, signature: &str) -> bool {
    let Ok(owner_bytes) = hex::decode(owner) else {
        return false;
    };
    let Ok(owner_bytes): Result<[u8; 32], _> = owner_bytes.try_into() else {
        return false;
    };
    let Ok(sig_bytes) = hex::decode(signature) else {
        return false;
    };
    let Ok(sig_bytes): Result<[u8; 64], _> = sig_bytes.try_into() else {
        return false;
    };
    let Ok(pk) = secp256k1::XOnlyPublicKey::from_byte_array(owner_bytes) else {
        return false;
    };
    let signature = Signature::from_byte_array(sig_bytes);
    let preimage = format!("nostr:agent-auth:{target}:{conditions}");
    let message: [u8; 32] = Sha256::digest(preimage.as_bytes()).into();
    secp256k1::schnorr::verify(&signature, &message, &pk).is_ok()
}

fn owner_conditions_syntax(conditions: &str) -> bool {
    for clause in conditions.split('&').filter(|clause| !clause.is_empty()) {
        if let Some(kind) = clause.strip_prefix("kind=") {
            if kind.is_empty() || !kind.bytes().all(|byte| byte.is_ascii_digit()) {
                return false;
            }
        } else if let Some(value) = clause.strip_prefix("created_at<") {
            if value.parse::<u64>().is_err() {
                return false;
            }
        } else if let Some(value) = clause.strip_prefix("created_at>") {
            if value.parse::<u64>().is_err() {
                return false;
            }
        } else {
            return false;
        }
    }
    true
}

/// NIP-OA time clauses for the request-borne path. `kind=` is syntax-checked
/// but does not restrict an NIP-IA identity binding.
fn owner_conditions_allow(conditions: &str, created_at: u64) -> bool {
    if !owner_conditions_syntax(conditions) {
        return false;
    }
    for clause in conditions.split('&').filter(|clause| !clause.is_empty()) {
        if let Some(value) = clause.strip_prefix("created_at<") {
            let Ok(value) = value.parse::<u64>() else {
                return false;
            };
            if created_at >= value {
                return false;
            }
        } else if let Some(value) = clause.strip_prefix("created_at>") {
            let Ok(value) = value.parse::<u64>() else {
                return false;
            };
            if created_at <= value {
                return false;
            }
        }
    }
    true
}

fn base(kind: u64, relay_pubkey: &str, now: u64, tags: Vec<Vec<String>>, content: &str) -> Event {
    Event {
        id: String::new(),
        pubkey: relay_pubkey.to_string(),
        created_at: now,
        kind,
        tags,
        content: content.to_string(),
        sig: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_snapshot_has_the_required_shape() {
        let event = snapshot("relaypub", 1, &BTreeSet::new());
        assert_eq!(event.kind, ARCHIVED_IDENTITIES);
        assert_eq!(event.pubkey, "relaypub");
        assert_eq!(event.created_at, 1);
        assert_eq!(event.tags, vec![vec!["-".to_string()]]);
        assert!(event.content.is_empty());
    }

    #[test]
    fn owner_agent_request_vector_verifies() {
        // NIP-IA test vector 1's NIP-OA auth tag and request timestamp.
        let event = Event {
            id: String::new(),
            pubkey: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .into(),
            created_at: 1_713_956_400,
            kind: 9035,
            tags: vec![
                vec!["-".into()],
                vec![
                    "p".into(),
                    "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
                        .into(),
                ],
                vec![
                    "auth".into(),
                    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into(),
                    "kind=1&created_at<1713957000".into(),
                    "8b7df2575caf0a108374f8471722b233c53f9ff827a8b0f91861966c3b9dd5cb2e189eae9f49d72187674c2f5bd244145e10ff86c9f257ffe65a1ee5f108b369".into(),
                ],
            ],
            content: String::new(),
            sig: String::new(),
        };
        assert_eq!(
            verify_owner_agent_request(
                &event,
                "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
            ),
            Some("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into())
        );
    }

    #[test]
    fn snapshot_contains_archived_pubkeys() {
        let mut archived = BTreeSet::new();
        archived.insert("aa".repeat(32));
        let event = snapshot("relaypub", 1, &archived);
        assert!(event.tags.contains(&vec!["-".into()]));
        assert!(event.tags.contains(&vec!["p".into(), "aa".repeat(32)]));
    }
}
