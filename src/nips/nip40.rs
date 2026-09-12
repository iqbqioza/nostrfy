//! NIP-40: Expiration Timestamp.
//!
//! An `expiration` tag carries a unix timestamp after which the event should
//! be removed from storage and queries.

use crate::event::Event;

pub const EXPIRATION_TAG: &str = "expiration";

/// Expiration timestamp of an event, if present.
///
/// When several `expiration` tags are present the earliest well-formed value
/// wins: the author asked for expiry, so the relay must honor the strictest
/// claim rather than a later (or missing) one. Malformed siblings are
/// reported by [`has_malformed_expiration`] and rejected at intake.
pub fn expiry(event: &Event) -> Option<u64> {
    expiry_fields(event)
}

/// Expiration timestamp for any event-like value with NIP-40 tags.
pub fn expiry_fields<E: crate::filter::EventFields>(event: &E) -> Option<u64> {
    event
        .tags()
        .iter()
        .filter(|t| t.len() >= 2 && t[0] == EXPIRATION_TAG)
        .filter_map(|t| t[1].parse().ok())
        .min()
}

/// Whether any `expiration` tag of the event is malformed: it has no value
/// (NIP-40 requires the timestamp) or its value does not parse as a unix
/// timestamp. A single malformed tag must reject the event even when another
/// tag parses, or a client could smuggle one valid tag past intake while a
/// bare sibling is ignored by the store/scan.
pub fn has_malformed_expiration(event: &Event) -> bool {
    event
        .tags
        .iter()
        .filter(|t| t.first().is_some_and(|n| n == EXPIRATION_TAG))
        .any(|t| t.len() < 2 || t[1].parse::<u64>().is_err())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event_with(tag: Option<&str>) -> Event {
        let tags = tag
            .map(|v| vec![vec![EXPIRATION_TAG.into(), v.into()]])
            .unwrap_or_default();
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
    fn expiry_parsing() {
        assert_eq!(expiry(&event_with(Some("1700000000"))), Some(1_700_000_000));
        assert_eq!(expiry(&event_with(Some("not-a-number"))), None);
        assert_eq!(expiry(&event_with(None)), None);
        // Several tags: the earliest well-formed value wins, and any
        // malformed sibling is reported.
        let multi = Event {
            tags: vec![
                vec![EXPIRATION_TAG.into(), "1800000000".into()],
                vec![EXPIRATION_TAG.into(), "1700000000".into()],
            ],
            ..event_with(None)
        };
        assert_eq!(expiry(&multi), Some(1_700_000_000));
        assert!(!has_malformed_expiration(&multi));
        let mixed = Event {
            tags: vec![
                vec![EXPIRATION_TAG.into(), "1700000000".into()],
                vec![EXPIRATION_TAG.into(), "bogus".into()],
            ],
            ..event_with(None)
        };
        assert!(has_malformed_expiration(&mixed));
        assert!(!has_malformed_expiration(&event_with(None)));
        // A bare `["expiration"]` sibling is malformed even when another tag
        // parses: the valid value must not mask the missing one.
        let bare_mixed = Event {
            tags: vec![
                vec![EXPIRATION_TAG.into(), "1700000000".into()],
                vec![EXPIRATION_TAG.into()],
            ],
            ..event_with(None)
        };
        assert!(has_malformed_expiration(&bare_mixed));
    }
}
