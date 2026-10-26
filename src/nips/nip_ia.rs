//! NIP-IA: Identity Archival (Buzz draft).
//!
//! The relay keeps a relay-scoped set of archived pubkeys and publishes the
//! NIP-IA snapshot and deltas. Archive state is visibility metadata only; it
//! never deletes history or grants/denies access.

use std::collections::BTreeSet;

use crate::event::Event;

/// NIP-IA current archived-identities snapshot (replaceable).
pub const ARCHIVED_IDENTITIES: u64 = 13535;
pub const ARCHIVED_DELTA: u64 = 8002;
pub const UNARCHIVED_DELTA: u64 = 8003;

/// The relay's NIP-IA archived-identities snapshot. The NIP-70 `-` tag marks
/// it as relay state; one bare `p` tag names each archived identity.
pub fn snapshot(relay_pubkey: &str, now: u64, archived: &BTreeSet<String>) -> Event {
    let mut tags = vec![vec!["-".to_string()]];
    tags.extend(
        archived
            .iter()
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
    fn snapshot_contains_archived_pubkeys() {
        let mut archived = BTreeSet::new();
        archived.insert("aa".repeat(32));
        let event = snapshot("relaypub", 1, &archived);
        assert!(event.tags.contains(&vec!["-".into()]));
        assert!(event.tags.contains(&vec!["p".into(), "aa".repeat(32)]));
    }
}
