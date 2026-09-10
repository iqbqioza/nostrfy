//! NIP-01 subscription filters and the in-memory match.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::event::Event;

/// Maximum number of `ids`/`authors` entries a filter may carry. The
/// in-memory per-candidate match is linear in these arrays, so an
/// unauthenticated REQ listing thousands of real ids or pubkeys could force
/// quadratic work on the shared reader thread; filters beyond this bound are
/// rejected with a clear error. No legitimate client lists this many ids or
/// authors in a single filter.
pub const MAX_FILTER_MEMBERS: usize = 512;

/// The event fields the in-memory filter matching reads. `Event`
/// implements it directly; the negentropy path uses a lightweight
/// deserialization that skips the content (the dominant field) and the
/// signature.
pub(crate) trait EventFields {
    fn id(&self) -> &str;
    fn pubkey(&self) -> &str;
    fn kind(&self) -> u64;
    fn created_at(&self) -> u64;
    fn tags(&self) -> &[Vec<String>];
    fn content(&self) -> &str;
}

impl EventFields for Event {
    fn id(&self) -> &str {
        &self.id
    }
    fn pubkey(&self) -> &str {
        &self.pubkey
    }
    fn kind(&self) -> u64 {
        self.kind
    }
    fn created_at(&self) -> u64 {
        self.created_at
    }
    fn tags(&self) -> &[Vec<String>] {
        &self.tags
    }
    fn content(&self) -> &str {
        &self.content
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Filter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authors: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search: Option<String>,
    #[serde(flatten)]
    pub tags: BTreeMap<String, Value>,
    /// Cached tokenized search terms (the `search` string is immutable
    /// after parsing, so the terms are computed once per filter and shared
    /// across the filter's clones; the live delivery path matches every
    /// event against them).
    #[serde(skip)]
    pub search_terms: std::sync::Arc<std::sync::OnceLock<Vec<String>>>,
}

impl Filter {
    /// Whether the filter exceeds the [`MAX_FILTER_MEMBERS`] bound on
    /// `ids`, `authors` or `kinds`, which would make the in-memory match
    /// quadratic (`kinds.contains` is linear per live event per
    /// subscription, and the scan fans out per kind).
    pub fn too_many_members(&self) -> bool {
        self.ids
            .as_ref()
            .is_some_and(|v| v.len() > MAX_FILTER_MEMBERS)
            || self
                .authors
                .as_ref()
                .is_some_and(|v| v.len() > MAX_FILTER_MEMBERS)
            || self
                .kinds
                .as_ref()
                .is_some_and(|v| v.len() > MAX_FILTER_MEMBERS)
    }

    /// Case-insensitive hex equality: stored events are lowercase hex while
    /// filters may carry uppercase hex. The historical scan decodes hex
    /// (case-insensitive), so the live match must compare the same way or a
    /// filter like `{"authors": ["AA.."]}` hits history but misses live.
    fn hex_eq(a: &str, b: &str) -> bool {
        a.len() == b.len()
            && a.bytes()
                .zip(b.bytes())
                .all(|(x, y)| x.eq_ignore_ascii_case(&y))
    }

    /// Case-insensitive prefix check for `ids` prefixes (same reason).
    fn hex_starts_with(haystack: &str, needle: &str) -> bool {
        haystack.len() >= needle.len()
            && haystack
                .bytes()
                .zip(needle.bytes())
                .all(|(x, y)| x.eq_ignore_ascii_case(&y))
    }

    /// Performs an in-memory match (used for live events and final checks).
    pub fn matches<E: EventFields>(&self, ev: &E) -> bool {
        if let Some(ids) = &self.ids {
            // `ids` entries may be full ids or prefixes: strict NIP-01
            // requires exact 64-char lowercase hex, but prefixes are an
            // ecosystem-wide convention, so they are accepted here. Only
            // even-length, non-empty prefixes are matched, mirroring the
            // historical scan (which decodes hex) so live and stored results
            // agree; an empty or odd-length entry matches nothing.
            // Comparison is ASCII case-insensitive like the scan's hex
            // decode, so uppercase filters agree on both paths.
            let id_str = ev.id();
            let matches = ids.iter().any(|id| {
                !id.is_empty()
                    && id.len() % 2 == 0
                    && (Self::hex_eq(id, id_str)
                        || (id.len() < id_str.len() && Self::hex_starts_with(id_str, id)))
            });
            if !matches {
                return false;
            }
        }
        // NIP-26: events published under a valid delegation tag match filters
        // on the delegator's pubkey as well as on the event's own author.
        // Only a well-formed delegation (`delegation` tags have exactly 4
        // elements, see `nip26::delegation`) counts: a malformed tag of
        // any other length must not let an attacker's event match filters
        // on somebody else's pubkey. Pubkey comparison is case-insensitive
        // for the same stored/live agreement reason as `ids` above.
        // Note: the tag's signature and conditions are NOT re-verified here
        // (trusted input — every caller feeds events that passed
        // `nip26::verify` at intake before store/broadcast); future callers
        // with unvalidated events must verify first.
        if let Some(authors) = &self.authors
            && !authors.iter().any(|a| Self::hex_eq(a, ev.pubkey()))
            && !ev.tags().iter().any(|t| {
                t.len() == 4
                    && t[0] == "delegation"
                    && authors.iter().any(|a| Self::hex_eq(a, &t[1]))
            })
        {
            return false;
        }
        if let Some(kinds) = &self.kinds
            && !kinds.contains(&ev.kind())
        {
            return false;
        }
        if let Some(since) = self.since
            && ev.created_at() < since
        {
            return false;
        }
        if let Some(until) = self.until
            && ev.created_at() > until
        {
            return false;
        }
        // NIP-50: an event matches when at least one search term appears in the
        // content as a whole word; the database scan ranks full matches
        // first and the word index and the non-indexed fallback agree.
        if let Some(search) = self.search.as_deref()
            && !search.trim().is_empty()
        {
            let terms = self.search_terms.get_or_init(|| {
                // Cap the terms like the scan path does: the live
                // delivery applies them to every event, so an
                // uncapped search string would force O(terms × event
                // words) comparisons per event (a CPU-DoS vector
                // against every live event on the relay).
                crate::nips::nip50::terms(search)
                    .into_iter()
                    .take(crate::db::SEARCH_MAX_TERMS)
                    .collect()
            });
            if !crate::nips::nip50::matches_terms(ev.content(), terms) {
                return false;
            }
        }
        self.tags.iter().all(|(name, value)| {
            // NIP-01: tag constraints are `#`-prefixed; any other key is an
            // unknown filter field and is ignored (a typo like `"kind"` must
            // not silently turn the whole filter into an impossible query).
            if !name.starts_with('#') {
                return true;
            }
            // Note: tag values compare exactly (case-sensitive), unlike
            // `ids`/`authors` which decode hex case-insensitively. An
            // uppercase `#e`/`#p` value therefore matches nothing on either
            // path — consistent, but clients should send lowercase hex.
            // NIP-01: only the first value of a tag is indexed (`tag[1]`);
            // further elements are metadata (relay hints, markers) and never
            // match a filter on their own.
            let tag_name = name.strip_prefix('#').unwrap_or(name);
            tag_values(value).any(|v| {
                ev.tags()
                    .iter()
                    .any(|t| t.len() >= 2 && t[0] == tag_name && t.get(1).is_some_and(|x| x == v))
            })
        })
    }

    pub fn has_search(&self) -> bool {
        self.search.as_deref().is_some_and(|s| !s.trim().is_empty())
    }

    /// Whether any `#`-prefixed tag constraint carries a value that is
    /// neither a string nor an array of strings. NIP-01 only defines those
    /// two forms; anything else would silently match nothing (the live
    /// match and the scan both skip non-string values), so such a filter
    /// is rejected at parse time instead.
    pub(crate) fn invalid_tag_values(&self) -> bool {
        // Only `#`-prefixed keys are tag constraints (NIP-01); any other
        // key is an unknown filter field and is ignored, so its value type
        // must not reject the filter.
        self.tags.iter().any(|(name, v)| {
            name.starts_with('#')
                && !v.is_string()
                && !v
                    .as_array()
                    .is_some_and(|a| a.iter().all(serde_json::Value::is_string))
        })
    }
}

/// The string values of a filter tag attribute (a single string or an
/// array of strings), borrowed — no per-event allocation: the live
/// delivery path iterates these for every event × tag constraint, so
/// cloning the values into `Vec<String>` was a hot-path allocation.
pub(crate) fn tag_values(value: &Value) -> impl Iterator<Item = &str> {
    value.as_str().into_iter().chain(
        value
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str),
    )
}

/// nostrfy extension: the `inbox` and `outbox` filter keys expand into the
/// standard constraints before the filter is parsed — `inbox` to `#p`
/// (events addressed to the pubkey: mentions, replies, zaps, DMs) and
/// `outbox` to `authors` (events authored by the pubkey). Each value is a
/// pubkey as 64-hex or an `npub1...` code, or an array of those; existing
/// `#p`/`authors` entries are merged. The keys make the inbox/outbox
/// routing model expressible in a single subscription while remaining
/// plain NIP-01 filters on the wire.
pub(crate) fn rewrite_inbox_outbox(value: &mut Value) -> Result<(), String> {
    let Value::Object(map) = value else {
        return Ok(());
    };
    for (key, dst) in [("inbox", "#p"), ("outbox", "authors")] {
        let Some(raw) = map.remove(key) else {
            continue;
        };
        let items = match raw {
            Value::String(s) => vec![s],
            Value::Array(items) => items
                .into_iter()
                .map(|v| {
                    v.as_str()
                        .map(str::to_string)
                        .ok_or_else(|| format!("invalid {key} filter value"))
                })
                .collect::<Result<Vec<_>, _>>()?,
            _ => return Err(format!("invalid {key} filter value")),
        };
        let mut pubkeys = Vec::new();
        for item in items {
            let valid_hex = item.len() == 64 && item.chars().all(|c| c.is_ascii_hexdigit());
            let hex_pk = if valid_hex {
                // Normalize to lowercase: the stored index is byte-based
                // (case-insensitive) while the live match is string-based, so
                // an uppercase filter would hit history but miss live events.
                item.to_ascii_lowercase()
            } else if let Ok(crate::nips::nip19::Nip19Entity::Pubkey(pk)) =
                crate::nips::nip19::parse_nip19(&item)
            {
                hex::encode(pk)
            } else {
                return Err(format!("invalid {key} pubkey"));
            };
            pubkeys.push(hex_pk);
        }
        let entry = map.entry(dst.to_string()).or_insert_with(|| json!([]));
        // A single-string `#p`/`authors` is valid NIP-01 (`tag_values` and
        // `invalid_tag_values` accept it): promote it to an array instead of
        // rejecting the subscription.
        if entry.is_string() {
            let s = entry.as_str().unwrap_or_default().to_string();
            *entry = json!([s]);
        }
        if let Some(arr) = entry.as_array_mut() {
            for pk in pubkeys {
                if !arr.iter().any(|v| v == &json!(pk)) {
                    arr.push(json!(pk));
                }
            }
        } else {
            return Err(format!("invalid existing {dst} filter value"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_values_borrows_without_allocating() {
        let single = serde_json::json!("abc");
        let values: Vec<&str> = tag_values(&single).collect();
        assert_eq!(values, vec!["abc"]);
        let array = serde_json::json!(["a", "b", 3]);
        let values: Vec<&str> = tag_values(&array).collect();
        assert_eq!(values, vec!["a", "b"]);
        let other = serde_json::json!(7);
        assert_eq!(tag_values(&other).count(), 0);
        let empty: serde_json::Value = serde_json::json!([]);
        assert_eq!(tag_values(&empty).count(), 0);
    }

    #[test]
    fn search_terms_are_cached_and_shared() {
        let filter: Filter =
            serde_json::from_value(serde_json::json!({"search": "rust nostr"})).unwrap();
        assert!(
            filter.search_terms.get().is_none(),
            "not computed before first use"
        );
        let mut ev = ev(1, vec![]);
        ev.content = "I like rust".into();
        assert!(filter.matches(&ev));
        assert!(
            filter.search_terms.get().is_some(),
            "the terms must be computed once and cached"
        );
        // The cached terms are shared with clones (the hot live path
        // clones filters into subscriptions).
        let clone = filter.clone();
        assert!(clone.search_terms.get().is_some());
        let mut other = super::tests::ev(1, vec![]);
        other.content = "nothing relevant".into();
        assert!(!clone.matches(&other));
    }

    fn ev(kind: u64, tags: Vec<Vec<String>>) -> Event {
        Event {
            id: "a".repeat(64),
            pubkey: "b".repeat(64),
            created_at: 1_600_000_000,
            kind,
            tags,
            content: "hello world".into(),
            sig: "c".repeat(128),
        }
    }

    #[test]
    fn basic_match() {
        let e = ev(1, vec![vec!["t".into(), "rust".into()]]);
        let f = Filter {
            kinds: Some(vec![1, 2]),
            ..Default::default()
        };
        assert!(f.matches(&e));
        let f = Filter {
            kinds: Some(vec![3]),
            ..Default::default()
        };
        assert!(!f.matches(&e));
    }

    #[test]
    fn tag_match_uses_only_the_first_tag_value() {
        // NIP-01: "Only the first value in any given tag is indexed." The
        // elements after the first are metadata (relay hints, markers), so a
        // filter value equal to `tag[2]` matches nothing on either path (see
        // the `only_first_value_of_a_single_letter_tag_is_indexed` db test).
        let e = ev(1, vec![vec!["e".into(), "aa".repeat(32), "bb".repeat(32)]]);
        let f: Filter =
            serde_json::from_value(serde_json::json!({"#e": ["aa".repeat(32)]})).unwrap();
        assert!(f.matches(&e), "the first tag value must match");
        let f: Filter =
            serde_json::from_value(serde_json::json!({"#e": ["bb".repeat(32)]})).unwrap();
        assert!(!f.matches(&e), "the second tag value must not match");
        let f: Filter =
            serde_json::from_value(serde_json::json!({"#e": ["cc".repeat(32)]})).unwrap();
        assert!(!f.matches(&e), "a value present in no tag must not match");
        // The filter value can match any one of several values (the first
        // value of any same-name tag).
        let f: Filter =
            serde_json::from_value(serde_json::json!({"#e": ["cc".repeat(32), "aa".repeat(32)]}))
                .unwrap();
        assert!(f.matches(&e));
        // Several same-name tags: every tag contributes its own first value.
        let multi = ev(
            1,
            vec![
                vec!["e".into(), "aa".repeat(32), "bb".repeat(32)],
                vec!["e".into(), "dd".repeat(32)],
            ],
        );
        let f: Filter =
            serde_json::from_value(serde_json::json!({"#e": ["dd".repeat(32)]})).unwrap();
        assert!(f.matches(&multi), "the second tag's first value must match");
    }

    #[test]
    fn tag_match() {
        let e = ev(1, vec![vec!["t".into(), "rust".into()]]);
        let f: Filter = serde_json::from_value(serde_json::json!({"#t": ["rust"]})).unwrap();
        assert!(f.matches(&e));
        let f: Filter = serde_json::from_value(serde_json::json!({"#t": ["go"]})).unwrap();
        assert!(!f.matches(&e));
    }

    #[test]
    fn time_match() {
        let e = ev(1, vec![]);
        let f: Filter =
            serde_json::from_value(serde_json::json!({"since": 1_700_000_000})).unwrap();
        assert!(!f.matches(&e));
    }

    #[test]
    fn search_match() {
        let e = ev(1, vec![]);
        let mut hit = e.clone();
        hit.content = "Rust Nostr Relay".into();
        let f: Filter = serde_json::from_value(serde_json::json!({"search": "nostr"})).unwrap();
        assert!(f.matches(&hit));
        assert!(!f.matches(&e));
        // At least one term must be present; partial matches pass.
        let f: Filter =
            serde_json::from_value(serde_json::json!({"search": "nostr bitcoin"})).unwrap();
        assert!(f.matches(&hit));
        let miss: Filter =
            serde_json::from_value(serde_json::json!({"search": "bitcoin only"})).unwrap();
        assert!(!miss.matches(&hit));
        // Empty search strings are ignored.
        let f: Filter = serde_json::from_value(serde_json::json!({"search": "  "})).unwrap();
        assert!(f.matches(&hit));
    }

    #[test]
    fn ids_match_full_and_prefix() {
        let e = ev(1, vec![]);
        // Full id matches.
        let f: Filter = serde_json::from_value(serde_json::json!({"ids": [e.id]})).unwrap();
        assert!(f.matches(&e));
        // Even-length prefix matches.
        let f: Filter = serde_json::from_value(serde_json::json!({"ids": ["aa"]})).unwrap();
        assert!(f.matches(&e));
        // Odd-length and empty entries match nothing (consistent with the
        // historical scan, which decodes hex).
        let f: Filter = serde_json::from_value(serde_json::json!({"ids": ["a"]})).unwrap();
        assert!(!f.matches(&e));
        let f: Filter = serde_json::from_value(serde_json::json!({"ids": [""]})).unwrap();
        assert!(!f.matches(&e));
        let f: Filter = serde_json::from_value(serde_json::json!({"ids": ["bb"]})).unwrap();
        assert!(!f.matches(&e));
    }

    #[test]
    fn ids_and_authors_match_uppercase_like_the_scan() {
        // The stored scan decodes hex (case-insensitive): the live match
        // must agree, so uppercase filters hit both paths.
        let e = ev(1, vec![]);
        let upper_id = e.id.to_ascii_uppercase();
        let f: Filter = serde_json::from_value(serde_json::json!({"ids": [upper_id]})).unwrap();
        assert!(f.matches(&e), "uppercase ids must match live");
        let upper_pk = e.pubkey.to_ascii_uppercase();
        let f: Filter = serde_json::from_value(serde_json::json!({"authors": [upper_pk]})).unwrap();
        assert!(f.matches(&e), "uppercase authors must match live");
    }

    #[test]
    fn too_many_members_flagged() {
        let mut f = Filter::default();
        assert!(!f.too_many_members());
        f.ids = Some(vec!["a".repeat(64); MAX_FILTER_MEMBERS]);
        assert!(!f.too_many_members(), "exactly at the bound is allowed");
        f.ids = Some(vec!["a".repeat(64); MAX_FILTER_MEMBERS + 1]);
        assert!(f.too_many_members());
        f.ids = None;
        f.authors = Some(vec!["a".repeat(64); MAX_FILTER_MEMBERS + 1]);
        assert!(f.too_many_members());
        f.authors = None;
        f.kinds = Some(vec![1; MAX_FILTER_MEMBERS + 1]);
        assert!(f.too_many_members(), "oversized kinds must be rejected too");
    }

    #[test]
    fn unknown_non_tag_filter_keys_are_ignored() {
        // NIP-01: tag constraints are `#`-prefixed; a typo like `"kind"`
        // must not turn the filter into an impossible query (0 results) —
        // it is ignored, so the filter matches by its other constraints.
        let e = ev(1, vec![vec!["t".into(), "rust".into()]]);
        let f: Filter =
            serde_json::from_value(serde_json::json!({"kind": [1], "kinds": [1]})).unwrap();
        assert!(f.matches(&e), "the unknown `kind` key must be ignored");
        let f: Filter = serde_json::from_value(serde_json::json!({"foo": "bar"})).unwrap();
        assert!(
            f.matches(&e),
            "an unknown non-tag key matches everything else"
        );
        // `#`-prefixed keys still constrain.
        let f: Filter = serde_json::from_value(serde_json::json!({"#t": ["go"]})).unwrap();
        assert!(!f.matches(&e));
    }

    #[test]
    fn inbox_outbox_rewrite() {
        let pk = "aa".repeat(32);
        let npub = "npub1424242424242424242424242424242424242424242424242424qamrcaj";
        let mut v = serde_json::json!({"inbox": pk});
        rewrite_inbox_outbox(&mut v).unwrap();
        assert_eq!(v, serde_json::json!({"#p": [pk]}));

        let mut v = serde_json::json!({"outbox": npub});
        rewrite_inbox_outbox(&mut v).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"authors": [pk]}),
            "npub decodes to the pubkey"
        );
    }

    #[test]
    fn inbox_outbox_merge_and_array() {
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        let mut v = serde_json::json!({"inbox": [a, b], "#p": ["cc".repeat(32)]});
        rewrite_inbox_outbox(&mut v).unwrap();
        let f: Filter = serde_json::from_value(v).unwrap();
        assert_eq!(
            f.tags["#p"].as_array().unwrap().len(),
            3,
            "inbox values merge with existing #p"
        );
    }

    #[test]
    fn inbox_merges_with_single_string_tag_and_lowercases() {
        // A single-string `#p` is valid NIP-01: promote, don't reject.
        let pk = "aa".repeat(32);
        let mut v = serde_json::json!({"inbox": pk, "#p": "bb".repeat(32)});
        rewrite_inbox_outbox(&mut v).unwrap();
        let arr = v["#p"].as_array().expect("promoted to array");
        assert_eq!(arr.len(), 2, "single-string #p merges with inbox");

        // Uppercase hex is normalized so live (string) and stored (byte)
        // matches agree.
        let upper = "AA".repeat(32);
        let mut v = serde_json::json!({"inbox": upper});
        rewrite_inbox_outbox(&mut v).unwrap();
        assert_eq!(v, serde_json::json!({"#p": ["aa".repeat(32)]}));
    }

    #[test]
    fn delegation_tag_does_not_match_other_authors() {
        // NIP-26: a delegation tag only extends the match to the DELEGATOR
        // named in the tag; filters on an unrelated pubkey must not match.
        let e = ev(
            1,
            vec![vec![
                "delegation".into(),
                "aa".repeat(32),
                "sig".into(),
                "kind".into(),
            ]],
        );
        let mut f: Filter = serde_json::from_value(serde_json::json!({})).unwrap();
        f.authors = Some(vec!["cc".repeat(32)]);
        assert!(!f.matches(&e));
        f.authors = Some(vec!["aa".repeat(32)]);
        assert!(f.matches(&e), "the delegator named in the tag matches");
    }

    #[test]
    fn until_rejects_younger_events() {
        let e = ev(1, vec![]);
        let mut f: Filter = serde_json::from_value(serde_json::json!({"kinds": [1]})).unwrap();
        f.until = Some(e.created_at - 1);
        assert!(!f.matches(&e), "an event newer than `until` must not match");
        f.until = Some(e.created_at);
        assert!(f.matches(&e));
    }

    #[test]
    fn inbox_outbox_dedupes_and_rejects_bad_shapes() {
        let pk = "aa".repeat(32);
        // A value already present in the target entry is not duplicated.
        let mut v = serde_json::json!({"inbox": pk, "#p": [pk]});
        rewrite_inbox_outbox(&mut v).unwrap();
        assert_eq!(v["#p"].as_array().unwrap().len(), 1);
        // Non-object input is left untouched.
        let mut v = serde_json::json!(42);
        rewrite_inbox_outbox(&mut v).unwrap();
        assert_eq!(v, serde_json::json!(42));
        // An array with a non-string element is invalid.
        let mut v = serde_json::json!({"inbox": [1]});
        assert!(rewrite_inbox_outbox(&mut v).is_err());
        // A pre-existing `#p`/`authors` entry of the wrong shape is invalid.
        let mut v = serde_json::json!({"inbox": pk, "#p": 42});
        assert!(rewrite_inbox_outbox(&mut v).is_err());
    }

    #[test]
    fn inbox_outbox_rejects_invalid() {
        let mut v = serde_json::json!({"inbox": 42});
        assert!(rewrite_inbox_outbox(&mut v).is_err());
        let mut v = serde_json::json!({"outbox": "not-a-pubkey"});
        assert!(rewrite_inbox_outbox(&mut v).is_err());
        let mut v = serde_json::json!({"outbox": "ff".repeat(32)});
        assert!(rewrite_inbox_outbox(&mut v).is_ok());
        // Unknown keys are left untouched.
        let mut v = serde_json::json!({"kinds": [1]});
        rewrite_inbox_outbox(&mut v).unwrap();
        assert_eq!(v, serde_json::json!({"kinds": [1]}));
    }
}
