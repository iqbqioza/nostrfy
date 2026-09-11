//! The live-delivery subscription index.
//!
//! Each connection registers the filter components of its subscriptions
//! (kinds, authors, tag constraints, and the "match everything" `{}`
//! case) with a connection id. When the live bus produces a batch, it
//! looks up the candidate connections for each event and delivers only
//! to them — an event wakes the connections that *can* match it instead
//! of every subscriber. The per-connection filter match remains the
//! final check, so the index only narrows the delivery set; it never
//! loosens it.

use std::collections::{HashMap, HashSet};

use crate::event::Event;

/// The filter components → connection ids.
#[derive(Default)]
pub(crate) struct SubscriptionIndex {
    kinds: HashMap<u64, HashSet<u64>>,
    authors: HashMap<[u8; 32], HashSet<u64>>,
    tags: HashMap<(String, String), HashSet<u64>>,
    /// Connections with at least one `{}`-style filter (match anything).
    all: HashSet<u64>,
}

/// The components of a filter that can be indexed ahead of the full
/// in-memory match.
pub(crate) enum FilterComponents {
    /// The filter matches every event.
    All,
    /// The indexed components (kinds, authors, tags). An empty set means
    /// "no indexed component": the filter still matches via `since`/
    /// `until`/`ids`, which the index cannot narrow.
    Indexed {
        kinds: Vec<u64>,
        authors: Vec<[u8; 32]>,
        tags: Vec<(String, String)>,
    },
}

impl FilterComponents {
    /// Derives the indexable components of a filter.
    pub(crate) fn of(filter: &crate::filter::Filter) -> FilterComponents {
        if filter.kinds.is_none()
            && filter.authors.is_none()
            && filter.tags.is_empty()
            && filter.ids.is_none()
            && filter.since.is_none()
            && filter.until.is_none()
            && !filter.has_search()
        {
            return FilterComponents::All;
        }
        let kinds: Vec<u64> = filter.kinds.clone().unwrap_or_default();
        let authors: Vec<[u8; 32]> = filter
            .authors
            .as_ref()
            .map(|authors| {
                authors
                    .iter()
                    .filter_map(|a| hex::decode(a).ok())
                    .filter(|b| b.len() == 32)
                    .map(|b| {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&b);
                        arr
                    })
                    .collect()
            })
            .unwrap_or_default();
        let tags: Vec<(String, String)> = filter
            .tags
            .iter()
            .filter(|(name, _)| name.starts_with('#'))
            .flat_map(|(name, value)| {
                let tag_name = name.strip_prefix('#').unwrap_or(name).to_string();
                crate::filter::tag_values(value).map(move |v| (tag_name.clone(), v.to_string()))
            })
            .collect();
        if kinds.is_empty() && authors.is_empty() && tags.is_empty() {
            // The filter constrains only ids/since/until/search, which the
            // index cannot narrow: treat it as match-everything so its
            // live delivery is not lost. The per-connection filter match
            // remains the final check, so widening the candidate set here
            // is always safe.
            return FilterComponents::All;
        }
        FilterComponents::Indexed {
            kinds,
            authors,
            tags,
        }
    }
}

impl SubscriptionIndex {
    /// Registers a connection's filter components.
    pub(crate) fn register(&mut self, conn: u64, components: &[FilterComponents]) {
        for component in components {
            match component {
                FilterComponents::All => {
                    self.all.insert(conn);
                }
                FilterComponents::Indexed {
                    kinds,
                    authors,
                    tags,
                } => {
                    for kind in kinds {
                        self.kinds.entry(*kind).or_default().insert(conn);
                    }
                    for author in authors {
                        self.authors.entry(*author).or_default().insert(conn);
                    }
                    for tag in tags {
                        self.tags.entry(tag.clone()).or_default().insert(conn);
                    }
                }
            }
        }
    }

    /// Removes a connection from every entry.
    pub(crate) fn unregister(&mut self, conn: u64) {
        self.all.remove(&conn);
        self.kinds.retain(|_, set| {
            set.remove(&conn);
            !set.is_empty()
        });
        self.authors.retain(|_, set| {
            set.remove(&conn);
            !set.is_empty()
        });
        self.tags.retain(|_, set| {
            set.remove(&conn);
            !set.is_empty()
        });
    }

    /// The candidate connections for an event (the union of the index
    /// entries its components hit). The per-connection filter match is
    /// the final check.
    pub(crate) fn candidates(&self, event: &Event) -> HashSet<u64> {
        let mut out: HashSet<u64> = self.all.clone();
        if let Some(set) = self.kinds.get(&event.kind) {
            out.extend(set.iter().copied());
        }
        if let Some(pubkey) = event.pubkey_bytes()
            && let Some(set) = self.authors.get(&pubkey)
        {
            out.extend(set.iter().copied());
        }
        // NIP-26: an event published under a valid delegation tag matches
        // filters on the delegator's pubkey too (see `Filter::matches`), so
        // those connections must be woken as well. Only the first well-formed
        // delegation tag (exactly 4 elements, see `nip26::delegation`)
        // counts: a malformed tag of any other length, or a second tag after
        // the honored one, must not wake the delegator's subscriptions.
        if let Some(tag) = event
            .tags
            .iter()
            .find(|tag| tag.len() == 4 && tag[0] == "delegation")
            && let Ok(bytes) = hex::decode(&tag[1])
            && bytes.len() == 32
        {
            let mut delegator = [0u8; 32];
            delegator.copy_from_slice(&bytes);
            if let Some(set) = self.authors.get(&delegator) {
                out.extend(set.iter().copied());
            }
        }
        // The index stores every `#`-prefixed tag constraint, single-letter
        // or not (NIP-01 tags are usually one letter, but `#emoji`,
        // `#subject` etc. are valid too): the lookup must not restrict the
        // tag name length, or multi-letter-tag-only subscriptions would
        // never be woken.
        for tag in &event.tags {
            if tag.len() >= 2
                && !tag[0].is_empty()
                && let Some(set) = self.tags.get(&(tag[0].clone(), tag[1].clone()))
            {
                out.extend(set.iter().copied());
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(kind: u64, tags: Vec<Vec<String>>) -> Event {
        Event {
            id: "0".repeat(64),
            pubkey: "ab".repeat(32),
            created_at: 1_600_000_000,
            kind,
            tags,
            content: String::new(),
            sig: "0".repeat(128),
        }
    }

    #[test]
    fn candidates_union_kinds_authors_and_tags() {
        let mut index = SubscriptionIndex::default();
        index.register(
            1,
            &[FilterComponents::Indexed {
                kinds: vec![1],
                authors: vec![],
                tags: vec![],
            }],
        );
        index.register(
            2,
            &[FilterComponents::Indexed {
                kinds: vec![],
                authors: vec![],
                tags: vec![("p".into(), "aa".repeat(32))],
            }],
        );
        index.register(3, &[FilterComponents::All]);
        let e = ev(1, vec![vec!["p".into(), "aa".repeat(32)]]);
        let candidates = index.candidates(&e);
        assert!(candidates.contains(&1), "kind match");
        assert!(candidates.contains(&2), "tag match");
        assert!(candidates.contains(&3), "match-everything filter");
        assert_eq!(candidates.len(), 3);
        // A non-matching event hits only the match-everything connection.
        let e = ev(30001, vec![]);
        let candidates = index.candidates(&e);
        assert_eq!(candidates, HashSet::from([3]));
    }

    #[test]
    fn unregister_removes_every_entry() {
        let mut index = SubscriptionIndex::default();
        index.register(
            1,
            &[FilterComponents::Indexed {
                kinds: vec![1, 2],
                authors: vec![[7u8; 32]],
                tags: vec![("p".into(), "x".into())],
            }],
        );
        index.unregister(1);
        assert!(index.candidates(&ev(1, vec![])).is_empty());
        assert!(index.candidates(&ev(2, vec![])).is_empty());
    }

    #[test]
    fn candidates_skip_malformed_delegation_and_unknown_delegators() {
        let mut index = SubscriptionIndex::default();
        index.register(
            7,
            &[FilterComponents::Indexed {
                kinds: vec![],
                authors: vec![[0xaa; 32]],
                tags: vec![],
            }],
        );
        // A delegation tag of the wrong length must not wake the
        // delegator's subscribers.
        let mut e = ev(
            1,
            vec![vec!["delegation".into(), "aa".repeat(32), "kind=1".into()]],
        );
        e.pubkey = "bb".repeat(32);
        assert!(
            index.candidates(&e).is_empty(),
            "a 3-element delegation tag is malformed and must not wake"
        );
        // A well-formed delegation to a delegator with no subscribers
        // wakes nobody.
        let mut e = ev(
            1,
            vec![vec![
                "delegation".into(),
                "cc".repeat(32),
                "kind=1".into(),
                "sig".into(),
            ]],
        );
        e.pubkey = "bb".repeat(32);
        assert!(index.candidates(&e).is_empty());
        // Only the first well-formed delegation tag is honored: a second tag
        // naming the subscribed delegator must not wake it.
        let mut e = ev(
            1,
            vec![
                vec![
                    "delegation".into(),
                    "cc".repeat(32),
                    "kind=1".into(),
                    "sig".into(),
                ],
                vec![
                    "delegation".into(),
                    "aa".repeat(32),
                    "kind=1".into(),
                    "sig".into(),
                ],
            ],
        );
        e.pubkey = "bb".repeat(32);
        assert!(
            index.candidates(&e).is_empty(),
            "a second delegation tag must stay inert"
        );
    }

    #[test]
    fn filter_components_derivation() {
        let filter: crate::filter::Filter =
            serde_json::from_value(serde_json::json!({"kinds": [1], "authors": ["ab".repeat(32)]}))
                .unwrap();
        match FilterComponents::of(&filter) {
            FilterComponents::Indexed {
                kinds,
                authors,
                tags,
            } => {
                assert_eq!(kinds, vec![1]);
                assert_eq!(authors, vec![[0xab; 32]]);
                assert!(tags.is_empty());
            }
            _ => panic!("indexed expected"),
        }
        let empty: crate::filter::Filter = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(matches!(
            FilterComponents::of(&empty),
            FilterComponents::All
        ));
    }

    #[test]
    fn filter_with_only_unindexable_constraints_is_all() {
        // Regression: a filter constraining only ids/since/until/search
        // used to register nothing in the index, so its live delivery was
        // silently lost. Such filters must be treated as match-everything
        // (the per-connection filter match is the final check).
        let f: crate::filter::Filter =
            serde_json::from_value(serde_json::json!({"since": 1_600_000_000})).unwrap();
        assert!(matches!(FilterComponents::of(&f), FilterComponents::All));
        let f: crate::filter::Filter =
            serde_json::from_value(serde_json::json!({"ids": ["ab".repeat(32)]})).unwrap();
        assert!(matches!(FilterComponents::of(&f), FilterComponents::All));
        let f: crate::filter::Filter =
            serde_json::from_value(serde_json::json!({"search": "nostr"})).unwrap();
        assert!(matches!(FilterComponents::of(&f), FilterComponents::All));
        // An actually indexable constraint stays indexed.
        let f: crate::filter::Filter =
            serde_json::from_value(serde_json::json!({"since": 1_600_000_000, "kinds": [1]}))
                .unwrap();
        assert!(matches!(
            FilterComponents::of(&f),
            FilterComponents::Indexed { .. }
        ));
    }

    #[test]
    fn candidates_wake_delegation_subscribers() {
        // NIP-26: a delegated event matches filters on the delegator's
        // pubkey, so the delegator's subscribers must be woken.
        let mut index = SubscriptionIndex::default();
        index.register(
            7,
            &[FilterComponents::Indexed {
                kinds: vec![],
                authors: vec![[0xaa; 32]],
                tags: vec![],
            }],
        );
        let mut e = ev(
            1,
            vec![vec![
                "delegation".into(),
                "aa".repeat(32),
                "kind=1".into(),
                "sig".into(),
            ]],
        );
        e.pubkey = "bb".repeat(32);
        let candidates = index.candidates(&e);
        assert!(
            candidates.contains(&7),
            "a delegated event wakes the delegator's subscribers"
        );
        // An event without a delegation tag does not.
        let e = ev(1, vec![]);
        assert!(index.candidates(&e).is_empty());
    }

    #[test]
    fn malformed_delegation_tags_do_not_wake_delegator_subscribers() {
        // NIP-26 delegation tags have exactly 4 elements; a shorter tag is
        // not a delegation and must not let the event match (or wake) the
        // delegator's author feed.
        let mut index = SubscriptionIndex::default();
        index.register(
            7,
            &[FilterComponents::Indexed {
                kinds: vec![],
                authors: vec![[0xaa; 32]],
                tags: vec![],
            }],
        );
        for tag in [
            vec!["delegation".into(), "aa".repeat(32)],
            vec!["delegation".into(), "aa".repeat(32), "sig".into()],
        ] {
            let mut e = ev(1, vec![tag]);
            e.pubkey = "bb".repeat(32);
            assert!(
                !index.candidates(&e).contains(&7),
                "a malformed delegation tag must not wake the delegator's subscribers"
            );
        }
    }
}
