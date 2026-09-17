//! NIP-01 subscription filters and the in-memory match.

use anyhow::{Result, anyhow};
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

/// Maximum combined number of tag constraint values (`#e`, `#p`, ...) across
/// every tag attribute of a filter. Each value becomes one scan range (the
/// merged walk compares all range heads per emitted candidate) and one
/// in-memory comparison per event, so an unbounded list is a CPU and memory
/// amplification vector; filters beyond this bound are rejected like
/// oversized `ids`/`authors`/`kinds`.
pub const MAX_FILTER_TAG_VALUES: usize = MAX_FILTER_MEMBERS;

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

/// A precomputed index over a filter's `#`-prefixed tag constraints: the
/// value set of each constraint, so matching an event is
/// `O(event tags + filter values)` instead of the quadratic
/// `O(filter values × event tags)` of a per-value linear scan. An
/// unauthenticated REQ may carry `MAX_FILTER_TAG_VALUES` (512) values and
/// a stored event up to `max_tags` (2000) tags, which measured ~0.85 s of
/// reader CPU per frame with the linear scan; the plan turns that into one
/// pass over the event's tags.
#[derive(Debug, Default)]
pub struct TagMatchPlan {
    /// The value set of each `#name` constraint, in first-seen order.
    constraints: Vec<(String, std::collections::HashSet<String>)>,
    /// Constraint index by tag name (without the leading `#`); one entry
    /// per constraint (the tag map's keys are unique).
    by_name: std::collections::HashMap<String, usize>,
    /// A constraint with no values (`[]`, or a non-string attribute) can
    /// never be satisfied — the same result the linear scan's `any` over
    /// an empty iterator produces — so the whole filter matches nothing.
    impossible: bool,
}

impl TagMatchPlan {
    /// Builds the plan from a filter's tag attribute map. Unknown
    /// (non-`#`) keys are ignored, like [`Filter::matches`].
    fn new(tags: &serde_json::Map<String, Value>) -> Self {
        let mut plan = TagMatchPlan::default();
        for (name, value) in tags {
            let Some(tag_name) = name.strip_prefix('#') else {
                continue;
            };
            let values: std::collections::HashSet<String> =
                tag_values(value).map(str::to_string).collect();
            if values.is_empty() {
                plan.impossible = true;
                return plan;
            }
            plan.by_name
                .insert(tag_name.to_string(), plan.constraints.len());
            plan.constraints.push((tag_name.to_string(), values));
        }
        plan
    }

    /// Whether an event satisfies every tag constraint of the filter.
    /// One pass over the event's tags marks the constraints they satisfy
    /// (the constraint index is looked up by tag name), so the old
    /// `values × tags` product is gone.
    pub fn matches<E: EventFields>(&self, ev: &E) -> bool {
        if self.impossible {
            return false;
        }
        if self.constraints.is_empty() {
            return true;
        }
        // A filter that passed `too_many_members` has at most
        // `MAX_FILTER_TAG_VALUES` non-empty constraints; a
        // caller-constructed filter beyond that bound falls back to the
        // linear scan (correct for any size) rather than overflow the
        // fixed-size satisfaction bitmap below.
        if self.constraints.len() > MAX_FILTER_TAG_VALUES {
            return self.matches_linear(ev);
        }
        let mut satisfied = [0u64; MAX_FILTER_TAG_VALUES.div_ceil(64)];
        let mut remaining = self.constraints.len();
        for tag in ev.tags() {
            // NIP-01: only the first value of a tag is indexed (`tag[1]`).
            if tag.len() < 2 {
                continue;
            }
            let Some(&index) = self.by_name.get(tag[0].as_str()) else {
                continue;
            };
            let (_, values) = &self.constraints[index];
            if satisfied[index / 64] & (1 << (index % 64)) == 0 && values.contains(tag[1].as_str())
            {
                satisfied[index / 64] |= 1 << (index % 64);
                remaining -= 1;
                if remaining == 0 {
                    return true;
                }
            }
        }
        false
    }

    /// The pre-plan matcher: `O(values × event tags)`, used only for
    /// unvalidated filters beyond the tracked-constraint bound.
    fn matches_linear<E: EventFields>(&self, ev: &E) -> bool {
        self.constraints.iter().all(|(name, values)| {
            ev.tags()
                .iter()
                .any(|t| t.len() >= 2 && t[0] == *name && values.contains(t[1].as_str()))
        })
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
    /// Tag constraints (`#`-prefixed keys) plus any unknown filter fields.
    /// A `serde_json::Map` preserves the client's JSON attribute order
    /// (`preserve_order`), which NIP-45's HLL offset derivation needs: it
    /// is defined over the *first* tag attribute in the filter.
    pub tags: serde_json::Map<String, Value>,
    /// Cached tokenized search terms (the `search` string is immutable
    /// after parsing, so the terms are computed once per filter and shared
    /// across the filter's clones; the live delivery path matches every
    /// event against them).
    #[serde(skip)]
    pub search_terms: std::sync::Arc<std::sync::OnceLock<Vec<String>>>,
    /// Lazily built tag-constraint index (see [`TagMatchPlan`]): the
    /// linear tag scan was `O(filter values × event tags)`, a CPU-DoS
    /// vector on the live path. Built on first match and shared with the
    /// filter's clones, on the same immutable-after-parse contract as
    /// `search` above.
    #[serde(skip)]
    pub(crate) tag_plan: std::sync::Arc<std::sync::OnceLock<TagMatchPlan>>,
}

impl Filter {
    /// Whether the filter exceeds the [`MAX_FILTER_MEMBERS`] bound on
    /// `ids`, `authors` or `kinds`, or the [`MAX_FILTER_TAG_VALUES`] bound
    /// on the combined tag constraint values, which would make the
    /// in-memory match quadratic (`kinds.contains` is linear per live event
    /// per subscription) and the scan fan out per kind/tag value.
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
            || {
                // The count stops at the cap: the check never walks a
                // hostile array to its end, and saturates so many oversized
                // attributes cannot overflow the sum.
                let values = self
                    .tags
                    .iter()
                    .filter(|(name, _)| name.starts_with('#'))
                    .map(|(_, value)| tag_values(value).take(MAX_FILTER_TAG_VALUES + 1).count())
                    .fold(0usize, usize::saturating_add);
                values > MAX_FILTER_TAG_VALUES
            }
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
    /// The tag constraints are matched through the precomputed
    /// [`TagMatchPlan`] (see [`Filter::matches_with`] to pass one in).
    pub fn matches<E: EventFields>(&self, ev: &E) -> bool {
        self.matches_with(ev, self.tag_plan())
    }

    /// The precomputed tag-constraint index of this filter, built on first
    /// match and shared with every clone (`tags` is immutable after the
    /// filter is put to use, like `search`). A caller matching many events
    /// against one filter holds the reference and reuses it through
    /// [`Filter::matches_with`] instead of re-reading the cache per event.
    pub fn tag_plan(&self) -> &TagMatchPlan {
        self.tag_plan.get_or_init(|| TagMatchPlan::new(&self.tags))
    }

    /// [`Filter::matches`] with an explicitly supplied tag plan: identical
    /// semantics, but the hot live path can hoist the plan out of its
    /// per-event loop. `plan` must have been built from this filter's
    /// `tags` (see [`Filter::tag_plan`]).
    pub fn matches_with<E: EventFields>(&self, ev: &E, plan: &TagMatchPlan) -> bool {
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
        // NIP-26: an event published under a valid delegation tag matches
        // filters on the delegator's pubkey as well as on the event's own
        // author. Only the first well-formed delegation tag is honored (the
        // one `nip26::verify` validated at intake): a second tag is inert and
        // must not let the event match another pubkey's feed, and a malformed
        // tag of any other length is skipped like `nip26::delegation` does.
        // Pubkey comparison is case-insensitive for the same stored/live
        // agreement reason as `ids` above.
        // Note: the tag's signature and conditions are NOT re-verified here
        // (trusted input — every caller feeds events that passed
        // `nip26::verify` at intake before store/broadcast); future callers
        // with unvalidated events must verify first.
        if let Some(authors) = &self.authors
            && !authors.iter().any(|a| Self::hex_eq(a, ev.pubkey()))
        {
            let delegated = ev
                .tags()
                .iter()
                .find(|t| t.len() == 4 && t[0] == "delegation")
                .map(|t| t[1].as_str());
            if !delegated
                .is_some_and(|delegator| authors.iter().any(|a| Self::hex_eq(a, delegator)))
            {
                return false;
            }
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
        // NIP-01: tag constraints are `#`-prefixed; any other key is an
        // unknown filter field and is ignored (a typo like `"kind"` must
        // not silently turn the whole filter into an impossible query).
        // Tag values compare exactly (case-sensitive), unlike
        // `ids`/`authors` which decode hex case-insensitively. An
        // uppercase `#e`/`#p` value therefore matches nothing on either
        // path — consistent, but clients should send lowercase hex.
        plan.matches(ev)
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
pub(crate) fn rewrite_inbox_outbox(value: &mut Value) -> Result<()> {
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
                        .ok_or_else(|| anyhow!("invalid {key} filter value"))
                })
                .collect::<Result<Vec<_>>>()?,
            _ => return Err(anyhow!("invalid {key} filter value")),
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
                return Err(anyhow!("invalid {key} pubkey"));
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
            // Dedup against a set of the existing strings: the previous
            // `arr.iter().any(|v| v == &json!(pk))` allocated a Value per
            // candidate and rescanned the whole array (O(n²)).
            let mut existing: std::collections::HashSet<String> = arr
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_string)
                .collect();
            for pk in pubkeys {
                if !existing.contains(&pk) {
                    existing.insert(pk.clone());
                    arr.push(json!(pk));
                }
            }
        } else {
            return Err(anyhow!("invalid existing {dst} filter value"));
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

    /// An [`EventFields`] wrapper that counts how often the event's tags
    /// are walked, so the tag-match complexity is asserted deterministically
    /// (a work counter, not a wall-clock measurement).
    struct CountedTags<'a> {
        event: &'a Event,
        tag_calls: std::cell::Cell<usize>,
    }

    impl EventFields for CountedTags<'_> {
        fn id(&self) -> &str {
            &self.event.id
        }
        fn pubkey(&self) -> &str {
            &self.event.pubkey
        }
        fn kind(&self) -> u64 {
            self.event.kind
        }
        fn created_at(&self) -> u64 {
            self.event.created_at
        }
        fn tags(&self) -> &[Vec<String>] {
            self.tag_calls.set(self.tag_calls.get() + 1);
            &self.event.tags
        }
        fn content(&self) -> &str {
            &self.event.content
        }
    }

    #[test]
    fn tag_match_walks_event_tags_once_for_many_filter_values() {
        // Regression (CPU DoS): the tag scan was O(filter values × event
        // tags) — 512 values against a 2000-tag event did ~1M comparisons
        // per event. The precomputed plan walks the event's tags once; the
        // old code called `tags()` once per filter value, so the work
        // counter here fails deterministically without timing.
        let event = ev(
            1,
            (0..2000)
                .map(|i| vec![format!("t{i}"), "value".into()])
                .collect(),
        );
        let values: Vec<String> = (0..MAX_FILTER_TAG_VALUES)
            .map(|i| format!("{i:064x}"))
            .collect();
        let f: Filter = serde_json::from_value(serde_json::json!({"#e": values})).unwrap();
        let counted = CountedTags {
            event: &event,
            tag_calls: std::cell::Cell::new(0),
        };
        assert!(!f.matches(&counted), "no `e` tag matches");
        assert!(
            counted.tag_calls.get() <= 2,
            "the event's tags must be walked once, not once per filter value \
             (walked {} times)",
            counted.tag_calls.get()
        );
        // The plan is shared with clones (the live path clones filters into
        // subscriptions) and still matches a hit.
        let clone = f.clone();
        let hit = ev(
            1,
            vec![vec![
                "e".into(),
                format!("{:064x}", MAX_FILTER_TAG_VALUES - 1),
            ]],
        );
        assert!(clone.matches(&hit));
    }

    #[test]
    fn tag_match_plan_covers_all_constraint_shapes() {
        // The plan must agree with the linear semantics: multiple
        // constraints, later tag values ignored, empty attributes
        // unsatisfiable, non-tag keys ignored.
        let e = ev(
            1,
            vec![
                vec!["e".into(), "aa".into(), "bb".into()],
                vec!["p".into(), "cc".into()],
            ],
        );
        let hit: Filter =
            serde_json::from_value(serde_json::json!({"#e": ["aa"], "#p": ["cc"], "foo": ["bar"]}))
                .unwrap();
        assert!(hit.matches(&e));
        let miss_p: Filter =
            serde_json::from_value(serde_json::json!({"#e": ["aa"], "#p": ["dd"]})).unwrap();
        assert!(!miss_p.matches(&e));
        let second_value: Filter =
            serde_json::from_value(serde_json::json!({"#e": ["bb"]})).unwrap();
        assert!(!second_value.matches(&e), "only tag[1] is indexed");
        let empty: Filter = serde_json::from_value(serde_json::json!({"#e": []})).unwrap();
        assert!(!empty.matches(&e), "an empty attribute matches nothing");
        let unknown: Filter =
            serde_json::from_value(serde_json::json!({"unknown": ["aa"]})).unwrap();
        assert!(unknown.matches(&e), "unknown non-tag keys are ignored");
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
        f.kinds = None;

        // Tag constraint values are bounded across all attributes combined:
        // each value is one scan range and one live comparison.
        f.tags.insert(
            "#e".into(),
            json!(vec!["a".repeat(64); MAX_FILTER_TAG_VALUES]),
        );
        assert!(!f.too_many_members(), "exactly at the bound is allowed");
        f.tags.insert(
            "#e".into(),
            json!(vec!["a".repeat(64); MAX_FILTER_TAG_VALUES + 1]),
        );
        assert!(
            f.too_many_members(),
            "an oversized tag attribute is rejected"
        );
        f.tags.clear();
        f.tags.insert(
            "#e".into(),
            json!(vec!["a".repeat(64); MAX_FILTER_TAG_VALUES / 2 + 1]),
        );
        f.tags.insert(
            "#p".into(),
            json!(vec!["b".repeat(64); MAX_FILTER_TAG_VALUES / 2]),
        );
        assert!(
            f.too_many_members(),
            "the bound is the combined total, not per attribute"
        );
        // Unknown non-tag keys are ignored and carry no tag values.
        f.tags.clear();
        f.tags.insert(
            "unknown".into(),
            json!(vec!["a".repeat(64); MAX_FILTER_TAG_VALUES + 1]),
        );
        assert!(!f.too_many_members());
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
        // Only the first well-formed delegation tag is honored: a second tag
        // must not let the event match another pubkey's feed.
        let e = ev(
            1,
            vec![
                vec![
                    "delegation".into(),
                    "aa".repeat(32),
                    "sig".into(),
                    "kind".into(),
                ],
                vec![
                    "delegation".into(),
                    "cc".repeat(32),
                    "sig".into(),
                    "kind".into(),
                ],
            ],
        );
        f.authors = Some(vec!["cc".repeat(32)]);
        assert!(
            !f.matches(&e),
            "a forged second delegation tag must not match"
        );
        f.authors = Some(vec!["aa".repeat(32)]);
        assert!(f.matches(&e), "the first delegation tag still matches");
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

    #[test]
    fn tag_attribute_order_is_preserved() {
        // NIP-45 derives the HLL offset from the *first* tag attribute, so
        // the parsed filter must keep the client's JSON attribute order.
        let f: Filter =
            serde_json::from_value(serde_json::json!({"#b": ["x"], "#a": ["y"]})).unwrap();
        let keys: Vec<&str> = f.tags.keys().map(String::as_str).collect();
        assert_eq!(keys, vec!["#b", "#a"]);
    }
}
