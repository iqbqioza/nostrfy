//! NIP-70: Protected Events.
//!
//! Events carrying a `["-"]` tag must come from authenticated clients and are
//! only delivered to authenticated subscribers.

use crate::event::Event;

pub const PROTECTED_TAG: &str = "-";

/// NIP-70: the tag is "a simple tag with a single item: `["-"]`". A tag
/// with extra elements is not a protected-event marker (other relays
/// would treat the event as unprotected), so only the exact one-element
/// form counts.
pub fn is_protected(event: &Event) -> bool {
    event
        .tags
        .iter()
        .any(|t| t.len() == 1 && t[0] == PROTECTED_TAG)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(tags: Vec<Vec<String>>) -> Event {
        Event {
            id: "a".repeat(64),
            pubkey: "b".repeat(64),
            created_at: 1,
            kind: 1,
            tags,
            content: String::new(),
            sig: "c".repeat(128),
        }
    }

    #[test]
    fn protected_detection() {
        assert!(is_protected(&event(vec![vec!["-".into()]])));
        assert!(!is_protected(&event(vec![vec!["p".into(), "x".into()]])));
        assert!(!is_protected(&event(vec![])));
        // The tag is exactly `["-"]`: extra elements are not protected.
        assert!(!is_protected(&event(vec![vec!["-".into(), "x".into()]])));
    }
}
