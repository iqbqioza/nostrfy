//! NIP-33: Parameterized Replaceable Events.
//!
//! Events of kind 30000-39999 are replaceable by the pair
//! `(pubkey, d-tag)`: the newest event with the same kind, author and `d`
//! value supersedes the previous one.

use crate::event::Event;

pub const PARAM_REPLACEABLE_MIN: u64 = 30000;
pub const PARAM_REPLACEABLE_MAX: u64 = 39999;

pub fn is_param_replaceable_kind(kind: u64) -> bool {
    (PARAM_REPLACEABLE_MIN..=PARAM_REPLACEABLE_MAX).contains(&kind)
}

/// Value of the first `d` tag, or `""` when absent. Borrowed: this runs on
/// every replaceable put/remove and the caller only needs the value.
pub fn dtag(event: &Event) -> &str {
    event
        .tags
        .iter()
        .find(|t| t.len() >= 2 && t[0] == "d")
        .map(|t| t[1].as_str())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(kind: u64, d: Option<&str>) -> Event {
        let tags = d
            .map(|d| vec![vec!["d".into(), d.into()]])
            .unwrap_or_default();
        Event {
            id: "a".repeat(64),
            pubkey: "b".repeat(64),
            created_at: 1,
            kind,
            tags,
            content: String::new(),
            sig: "c".repeat(128),
        }
    }

    #[test]
    fn ranges() {
        assert!(is_param_replaceable_kind(30000));
        assert!(is_param_replaceable_kind(39999));
        assert!(!is_param_replaceable_kind(29999));
        assert!(!is_param_replaceable_kind(40000));
    }

    #[test]
    fn dtag_value() {
        assert_eq!(dtag(&event(30023, Some("my-post"))), "my-post");
        assert_eq!(dtag(&event(30023, None)), "");
    }
}
