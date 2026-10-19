//! NIP-70: Protected Events.
//!
//! Events carrying a `["-"]` tag must come from authenticated clients and are
//! only delivered to authenticated subscribers — except the relay's own
//! relay-signed events: their protected advertisement stays publicly
//! readable (see [`hidden_from_anonymous`]).

use crate::event::Event;

pub const PROTECTED_TAG: &str = "-";

/// NIP-70: "When the `"-"` tag is present, that means the event is
/// 'protected'." The canonical marker is the one-element `["-"]`, but the
/// rule keys off the tag *name*, so any tag named `-` marks the event.
///
/// Requiring exactly one element failed open. `["-", "reason"]` — a client
/// adding a note, a version stamping itself, a stray value — read as
/// unprotected, so `validate_base` accepted it from an unauthenticated
/// client and `ws/handler`'s delivery check served it to every subscriber,
/// permanently, retrievable by id. The author's intent was explicit and the
/// relay published it anyway.
///
/// The two ways to be wrong are not symmetric, and that decides the
/// tie-break. Requiring one element leaks: the author asked for protection
/// and got publication. Matching on the name can only withhold an event some
/// other relay would have published — an availability cost, and one the
/// author can undo by removing the tag. A relay that cannot serve the event
/// to its author is an annoyance; one that publishes it to the world is the
/// failure NIP-70 exists to prevent.
pub fn is_protected(event: &Event) -> bool {
    tags_protected(&event.tags)
}

/// Tag-list variant of [`is_protected`] for paths that only carry the tags
/// (the negentropy light record has no content or signature to build an
/// [`Event`] from). Same rule: any tag *named* `-` marks the event,
/// regardless of extra values.
pub fn tags_protected(tags: &[Vec<String>]) -> bool {
    tags.iter()
        .any(|t| t.first().is_some_and(|name| name == PROTECTED_TAG))
}

/// Whether `pubkey` is the relay's own identity. The relay's relay-signed
/// events carry the `-` tag by spec (NIP-43's role state) but remain the
/// relay's advertisement: the read-side policy must not hide them (see
/// [`hidden_from_anonymous`]).
pub fn relay_authored(pubkey: &str, relay_pubkey: Option<&str>) -> bool {
    relay_pubkey.is_some_and(|pk| pubkey.eq_ignore_ascii_case(pk))
}

/// Whether a protected event is withheld from an anonymous reader.
///
/// The `-` tag constrains *publication* (author-only, enforced on the write
/// path) and re-publication, not the reads; withholding protected events
/// from anonymous clients is a closed-access policy. It must not apply to
/// the relay's own events: NIP-43's role state carries the tag by spec
/// while being the relay's advertisement, and hiding it would leave
/// anonymous clients with a silently empty role/membership view.
pub fn hidden_from_anonymous(event: &Event, relay_pubkey: Option<&str>) -> bool {
    is_protected(event) && !relay_authored(&event.pubkey, relay_pubkey)
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
        // A tag *named* `-` marks the event however many values it carries:
        // `["-", "reason"]` used to read as unprotected, so the event was
        // accepted unauthenticated and served to every subscriber.
        assert!(is_protected(&event(vec![vec!["-".into(), "x".into()]])));
        assert!(is_protected(&event(vec![
            vec!["e".into(), "a".repeat(64)],
            vec!["-".into(), "why".into(), "more".into()],
        ])));
        // An empty tag carries no name and marks nothing; `-` must be the
        // whole first element, not a prefix of it.
        assert!(!is_protected(&event(vec![vec![String::new(), "x".into()]])));
        assert!(!is_protected(&event(vec![vec!["--".into()]])));
        assert!(!is_protected(&event(vec![vec!["-x".into()]])));
    }

    /// The leak this rule closes, seen from the predicate both gates
    /// consult. `relay::validate` pins the write path end to end
    /// (`a_multi_value_dash_tag_needs_authentication`).
    #[test]
    fn a_multi_value_dash_tag_is_classified_as_protected() {
        // The exact leak: a `-` tag carrying a value read as unprotected, so
        // the write path accepted it unauthenticated and the delivery path
        // served it to every subscriber.
        assert!(
            is_protected(&event(vec![vec!["-".into(), "reason".into()]])),
            "`[-, reason]` is a NIP-70 marker by tag name"
        );
        // The canonical one-element form still works.
        assert!(is_protected(&event(vec![vec!["-".into()]])));
    }
}
