//! NIP-IA: Identity Archival (Buzz draft).
//!
//! nostrfy does not yet accept archive/unarchive requests, but NIP-IA-aware
//! clients query the relay-signed `kind:13535` snapshot and some report an
//! "archived identities could not be checked" error when it is missing. The
//! relay therefore publishes an empty snapshot: it truthfully says "nothing
//! is archived here" and gives clients a verifiable current state.

use crate::event::Event;

/// NIP-IA current archived-identities snapshot (replaceable).
pub const ARCHIVED_IDENTITIES: u64 = 13535;

/// The relay's empty archived-identities snapshot. The NIP-70 `-` tag marks
/// it as relay state; there are no `p` tags because this relay has no
/// archive store yet.
pub fn empty_snapshot(relay_pubkey: &str, now: u64) -> Event {
    Event {
        id: String::new(),
        pubkey: relay_pubkey.to_string(),
        created_at: now,
        kind: ARCHIVED_IDENTITIES,
        tags: vec![vec!["-".to_string()]],
        content: String::new(),
        sig: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_snapshot_has_the_required_shape() {
        let event = empty_snapshot("relaypub", 1);
        assert_eq!(event.kind, ARCHIVED_IDENTITIES);
        assert_eq!(event.pubkey, "relaypub");
        assert_eq!(event.created_at, 1);
        assert_eq!(event.tags, vec![vec!["-".to_string()]]);
        assert!(event.content.is_empty());
    }
}
