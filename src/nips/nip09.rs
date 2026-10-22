//! NIP-09: Event Deletion.
//!
//! Deletion requests are kind-5 events whose `e` tags reference event ids
//! and whose `a` tags reference addressable events
//! (`<kind>:<pubkey>:<d-identifier>`) to delete. Relays delete referenced
//! events authored by the same pubkey as the deletion request; deletion
//! requests themselves can never be deleted.

use crate::event::Event;

pub const DELETION_KIND: u64 = 5;

/// Upper bound on the distinct `a` targets a single deletion may carry.
/// Each address costs at least one tombstone and one replaceable-slot
/// lookup on the single writer; without a bound one event could stall
/// every other put/delete. Live intake rejects a request above this;
/// replay paths (migration, a pre-existing stored event) process at most
/// this many distinct addresses.
pub const MAX_DELETION_ADDRESSES: usize = 512;

/// An `a`-tag address of an addressable (replaceable) event.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Address {
    pub kind: u64,
    pub pubkey: String,
    pub d: String,
}

/// Event ids referenced by `e` tags of a deletion request.
pub fn deletion_targets(event: &Event) -> Vec<String> {
    event
        .tags
        .iter()
        .filter(|t| t.first().map(String::as_str) == Some("e") && t.len() >= 2)
        .map(|t| t[1].clone())
        .collect()
}

/// Addressable events referenced by `a` tags of a deletion request.
///
/// Duplicate addresses are collapsed and the result is capped at
/// [`MAX_DELETION_ADDRESSES`]; see its docs for why the walk must be
/// bounded and why live intake rejects rather than silently truncates.
pub fn deletion_addresses(event: &Event) -> Vec<Address> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for tag in &event.tags {
        if tag.first().map(String::as_str) != Some("a") || tag.len() < 2 {
            continue;
        }
        let Some(address) = parse_address(&tag[1]) else {
            continue;
        };
        if out.len() >= MAX_DELETION_ADDRESSES {
            break;
        }
        if seen.insert(address.clone()) {
            out.push(address);
        }
    }
    out
}

/// Every distinct `a` target, without the live-intake cap. Migration is an
/// explicit offline replay of a pre-cap export: silently dropping targets
/// left addressable events and their tombstones behind. The unbounded walk
/// is acceptable there because the operator chose the import; live intake
/// keeps using [`deletion_addresses`] and [`deletion_addresses_exceed_cap`].
pub fn deletion_addresses_all(event: &Event) -> Vec<Address> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for tag in &event.tags {
        if tag.first().map(String::as_str) != Some("a") || tag.len() < 2 {
            continue;
        }
        let Some(address) = parse_address(&tag[1]) else {
            continue;
        };
        if seen.insert(address.clone()) {
            out.push(address);
        }
    }
    out
}

/// Whether a deletion request has more distinct `a` targets than
/// [`MAX_DELETION_ADDRESSES`]. Checked at live intake before the event is
/// stored, so the replay paths never silently truncate a request this
/// relay accepted.
pub fn deletion_addresses_exceed_cap(event: &Event) -> bool {
    let mut seen = std::collections::HashSet::new();
    for tag in &event.tags {
        if tag.first().map(String::as_str) != Some("a") || tag.len() < 2 {
            continue;
        }
        let Some(address) = parse_address(&tag[1]) else {
            continue;
        };
        if seen.insert(address) && seen.len() > MAX_DELETION_ADDRESSES {
            return true;
        }
    }
    false
}

fn parse_address(value: &str) -> Option<Address> {
    let mut parts = value.splitn(3, ':');
    let kind = parts.next()?.parse().ok()?;
    let pubkey = parts.next()?.to_string();
    let d = parts.next()?.to_string();
    Some(Address { kind, pubkey, d })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(tags: Vec<Vec<String>>) -> Event {
        Event {
            id: "a".repeat(64),
            pubkey: "b".repeat(64),
            created_at: 1_600_000_000,
            kind: DELETION_KIND,
            tags,
            content: String::new(),
            sig: "c".repeat(128),
        }
    }

    #[test]
    fn targets_from_e_tags() {
        let ev = event(vec![
            vec!["e".into(), "abc".into()],
            vec!["e".into(), "def".into()],
        ]);
        assert_eq!(deletion_targets(&ev), vec!["abc", "def"]);
        let ev = event(vec![vec!["p".into(), "abc".into()]]);
        assert!(deletion_targets(&ev).is_empty());
    }

    #[test]
    fn duplicate_addresses_are_collapsed_and_capped() {
        let pk = "a".repeat(64);
        let mut tags = Vec::new();
        for i in 0..(MAX_DELETION_ADDRESSES + 10) {
            tags.push(vec!["a".into(), format!("30023:{pk}:d{i}")]);
        }
        let ev = event(tags.clone());
        assert_eq!(
            deletion_addresses(&ev).len(),
            MAX_DELETION_ADDRESSES,
            "the replay path must not materialize more than the cap"
        );
        assert!(deletion_addresses_exceed_cap(&ev));
        assert_eq!(
            deletion_addresses_all(&ev).len(),
            MAX_DELETION_ADDRESSES + 10,
            "migration must process every pre-cap address instead of truncating"
        );

        let exact = event(tags[..MAX_DELETION_ADDRESSES].to_vec());
        assert!(!deletion_addresses_exceed_cap(&exact));

        let mut duplicate = tags[..1].to_vec();
        duplicate.extend(tags[..1].to_vec());
        let ev = event(duplicate);
        assert_eq!(deletion_addresses(&ev).len(), 1);
        assert!(!deletion_addresses_exceed_cap(&ev));
    }

    #[test]
    fn addresses_from_a_tags() {
        let ev = event(vec![
            vec!["a".into(), "30023:abcd:post-1".into()],
            vec!["a".into(), "garbage".into()],
        ]);
        assert_eq!(
            deletion_addresses(&ev),
            vec![Address {
                kind: 30023,
                pubkey: "abcd".into(),
                d: "post-1".into(),
            }]
        );
    }
}
