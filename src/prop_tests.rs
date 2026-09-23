//! Randomized, dependency-free property tests for the database's derived
//! state.
//!
//! `proptest`/`quickcheck` are not available (the build must work offline),
//! so the drivers run on the tiny xorshift64 PRNG of [`crate::fuzz_tests`]
//! with fixed seeds: a failure reproduces exactly (same seed, same operation
//! index). Two properties are checked:
//!
//! 1. A random sequence of writes (plain/replaceable/addressable/ephemeral
//!    events, NIP-09 deletions, NIP-29 group deletions/purges, NIP-40
//!    expiry, NIP-62 vanishes) is mirrored by a small in-memory model; after
//!    every batch of operations the visible set served by `query` /
//!    `query_req` must equal the model's. The sequence closes and reopens
//!    the database periodically, so snapshot/pending/index recovery
//!    regressions surface too.
//! 2. Random filters (kinds/authors/since/until/limit/tags/ids/search)
//!    must return exactly the model-filtered set (per-filter limit
//!    semantics included) and `COUNT` must equal the filtered cardinality,
//!    bounded by the count request's own limit (a count stops at the
//!    requested total, never invents events past it).
//!
//! The helpers are local to this file (the temp-`DatabaseConfig` pattern is
//! copied from `src/db/tests.rs`), so no other test module has to change.
//! Every generated `created_at` is globally unique: the scan's
//! same-timestamp boundary continuation then never fires, so the model can
//! use plain NIP-01 top-`limit` ordering; ties are exercised only inside a
//! replaceable slot, where they can never leave two stored events with the
//! same timestamp behind.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::config::DatabaseConfig;
use crate::db::{DbClient, PutOutcome};
use crate::event::Event;
use crate::filter::Filter;
use crate::fuzz_tests::Rng;
use crate::nips::{nip01, nip09, nip29, nip33, nip40};

/// Fixed seeds for the write-sequence property (three independent runs).
const SEEDS: [u64; 3] = [0x9e37_1001, 0x9e37_1002, 0x9e37_1003];
/// Operations per seed: a few seconds in total.
const OPS_PER_SEED: usize = 200;
/// Visible-set comparison cadence.
const CHECK_EVERY: usize = 10;
/// Close/reopen cadence: same path, fresh `DbClient`.
const RESTART_EVERY: usize = 50;
/// Fixed seeds for the filter/COUNT property.
const FILTER_SEEDS: [u64; 2] = [0xf117_2001, 0xf117_2002];
/// State-building operations per filter seed.
const FILTER_OPS: usize = 120;
/// Random filter/COUNT checks per filter seed.
const FILTER_CHECKS: usize = 250;
/// Request limit used by the visibility and filter queries. Larger than any
/// population the suite can build, so the global scan limit never bites.
const QUERY_LIMIT: usize = 500;
/// Base wall-clock for the deterministic logical clock.
const BASE_TIME: u64 = 1_700_000_000;

const REPLACEABLE_KINDS: [u64; 6] = [0, 3, 10_000, 10_001, 12_345, 19_999];
const ADDRESSABLE_KINDS: [u64; 4] = [30_000, 30_001, 30_023, 39_999];
const EPHEMERAL_KINDS: [u64; 4] = [20_000, 20_001, 21_059, 29_999];
const EXPIRING_KINDS: [u64; 6] = [1, 0, 3, 10_000, 30_000, 30_001];
/// Kind pool for the random filters: every kind the generator can store,
/// plus a kind that is never stored so impossible filters are covered too.
const FILTER_KINDS: [u64; 17] = [
    0, 1, 2, 3, 4, 5, 11, 10_000, 10_001, 12_345, 19_999, 30_000, 30_023, 39_000, 39_999, 9005,
    999_999,
];
const GROUP_KINDS: [u64; 8] = [
    11,
    nip29::JOIN,
    nip29::CREATE_GROUP,
    nip29::DELETE_GROUP,
    9000,
    nip29::GROUP_META,
    nip29::GROUP_ADMINS,
    nip29::GROUP_PINS,
];
const GROUP_IDS: [&str; 2] = ["group-a", "group-b"];
const D_TAGS: [&str; 4] = ["", "alpha", "beta", "gamma"];

/// The replaceable slot key: `(kind, pubkey, d)` with `d` always empty for
/// non-addressable kinds (`put_event_in`'s `dtag`).
type Slot = (u64, String, String);

/// The put outcome the model expects, stripped of the human-readable reason
/// so equal variants with different messages still compare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expected {
    Stored,
    Duplicate,
    Replaced,
    Expired,
    PreviouslyDeleted,
    Ephemeral,
    Invalid,
}

fn expected(outcome: &PutOutcome) -> Expected {
    match outcome {
        PutOutcome::Stored => Expected::Stored,
        PutOutcome::Duplicate(_) => Expected::Duplicate,
        PutOutcome::Replaced => Expected::Replaced,
        PutOutcome::Expired => Expected::Expired,
        PutOutcome::PreviouslyDeleted => Expected::PreviouslyDeleted,
        PutOutcome::Ephemeral => Expected::Ephemeral,
        PutOutcome::Invalid(_) => Expected::Invalid,
    }
}

/// A temp database directory, unique per call, small maps for parallel test
/// runs (mirrors `src/db/tests.rs::config`). `disabled_fsync` keeps the
/// hundreds of writes in the suite fast; an in-process close/reopen still
/// observes every commit (LMDB reads through the same mapping).
fn config() -> DatabaseConfig {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir()
        .join("nostrfy-prop-test")
        .join(format!("{:x}-{id}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    DatabaseConfig {
        path,
        map_size: 16 * 1024 * 1024,
        max_map_size: 64 * 1024 * 1024,
        disabled_fsync: true,
        ..Default::default()
    }
}

fn open_db(cfg: &DatabaseConfig) -> DbClient {
    DbClient::open(
        cfg,
        true,
        Arc::new(Default::default()),
        0,
        128,
        4096,
        262_144,
    )
    .expect("test database must open")
}

/// The fixed author pool: valid 32-byte hex pubkeys, all lowercase.
fn author_pool() -> Vec<String> {
    (1..=6u8).map(|n| format!("{n:02x}").repeat(32)).collect()
}

/// A structurally valid event with a unique id: the sequence number is baked
/// into the content, so two events never collide even when a test reuses a
/// `created_at` to exercise the replaceable tie-break.
fn mk_event(seq: u64, author: &str, kind: u64, created_at: u64, tags: Vec<Vec<String>>) -> Event {
    let mut event = Event {
        id: String::new(),
        pubkey: author.to_string(),
        created_at,
        kind,
        tags,
        content: format!("prop test event {seq}"),
        sig: "00".repeat(64),
    };
    event.id = nip01::compute_id(&event);
    event
}

fn slot_of(event: &Event) -> Option<Slot> {
    let replaceable = nip01::is_replaceable_kind(event.kind);
    let addressable = nip33::is_param_replaceable_kind(event.kind);
    if !replaceable && !addressable {
        return None;
    }
    let d = if addressable {
        nip33::dtag(event).to_string()
    } else {
        String::new()
    };
    Some((event.kind, event.pubkey.clone(), d))
}

fn expired(event: &Event, now: u64) -> bool {
    nip40::expiry(event).is_some_and(|exp| exp <= now)
}

/// The in-memory mirror of the database's derived state. It replays the
/// exact check order of `Store::put_event_in` / the removal walkers.
#[derive(Default)]
struct Model {
    /// Currently stored events (expired-but-not-purged ones included: they
    /// only disappear on `purge_expired`, exactly like the real store).
    stored: BTreeMap<String, Event>,
    /// Replaceable/addressable slot -> current event id.
    slots: BTreeMap<Slot, String>,
    /// NIP-09 id tombstones: a re-published id must stay deleted.
    deleted_ids: BTreeSet<String>,
    /// NIP-09 address tombstones: `(kind, pubkey, d) -> created_at cut`.
    address_tombstones: BTreeMap<Slot, u64>,
    /// NIP-62 vanished pubkeys -> the furthest `until_created` honored. Any
    /// later put from the pubkey is refused, whatever its timestamp.
    vanished: BTreeMap<String, u64>,
    /// NIP-29 purged groups -> `(purge_now, cut)`.
    purged_groups: BTreeMap<String, (u64, u64)>,
}

impl Model {
    fn visible_events(&self, now: u64) -> Vec<&Event> {
        self.stored
            .values()
            .filter(|event| !expired(event, now))
            .collect()
    }

    fn visible_ids(&self, now: u64) -> BTreeSet<String> {
        self.visible_events(now)
            .into_iter()
            .map(|event| event.id.clone())
            .collect()
    }

    fn is_visible(&self, id: &str, now: u64) -> bool {
        self.stored
            .get(id)
            .is_some_and(|event| !expired(event, now))
    }

    fn remove_stored(&mut self, id: &str) {
        if let Some(event) = self.stored.remove(id)
            && let Some(slot) = slot_of(&event)
            && self.slots.get(&slot).is_some_and(|current| current == id)
        {
            self.slots.remove(&slot);
        }
    }

    /// NIP-09 `a`-tag tombstones also survive a later replacement, so a
    /// version is judged by the event's `created_at` against the cut.
    fn address_blocked(&self, slot: &Slot, created_at: u64) -> bool {
        self.address_tombstones
            .get(slot)
            .is_some_and(|cut| created_at <= *cut)
    }

    fn purged_blocks(&self, event: &Event) -> bool {
        event.tags.iter().any(|tag| {
            tag.len() >= 2
                && tag[0] == "h"
                && self
                    .purged_groups
                    .get(&tag[1])
                    .is_some_and(|&(purge_now, cut)| {
                        if event.kind == nip29::CREATE_GROUP {
                            event.created_at < purge_now
                        } else {
                            event.created_at <= cut
                        }
                    })
        })
    }

    fn put(&mut self, event: &Event, now: u64) -> Expected {
        if self.vanished.contains_key(&event.pubkey) {
            return Expected::Invalid;
        }
        if self.deleted_ids.contains(&event.id) {
            return Expected::PreviouslyDeleted;
        }
        if self.purged_blocks(event) {
            return Expected::PreviouslyDeleted;
        }
        if (20_000..30_000).contains(&event.kind) {
            return Expected::Ephemeral;
        }
        if expired(event, now) {
            return Expected::Expired;
        }
        if let Some(slot) = slot_of(event) {
            if self.address_blocked(&slot, event.created_at) {
                return Expected::PreviouslyDeleted;
            }
            if let Some(old_id) = self.slots.get(&slot).cloned() {
                let old = self
                    .stored
                    .get(&old_id)
                    .expect("a slot must point at a stored event");
                let newer = event.created_at > old.created_at
                    || (event.created_at == old.created_at && event.id < old.id);
                if !newer {
                    return Expected::Duplicate;
                }
                self.remove_stored(&old_id);
                self.stored.insert(event.id.clone(), event.clone());
                self.slots.insert(slot, event.id.clone());
                return Expected::Replaced;
            }
            self.stored.insert(event.id.clone(), event.clone());
            self.slots.insert(slot, event.id.clone());
            return Expected::Stored;
        }
        match self.stored.entry(event.id.clone()) {
            Entry::Vacant(entry) => {
                entry.insert(event.clone());
                Expected::Stored
            }
            Entry::Occupied(_) => Expected::Duplicate,
        }
    }

    /// NIP-40 purge: removes every stored event whose expiration arrived.
    fn purge_expired(&mut self, now: u64) -> usize {
        let doomed: Vec<String> = self
            .stored
            .iter()
            .filter(|(_, event)| expired(event, now))
            .map(|(id, _)| id.clone())
            .collect();
        for id in &doomed {
            self.remove_stored(id);
        }
        doomed.len()
    }

    /// NIP-09: `e` targets delete same-author events (deletion requests stay);
    /// `a` targets tombstone the address up to the request's `created_at` and
    /// remove every version at or below the cut. An address of another author
    /// is inert (delegations are not exercised).
    fn delete(
        &mut self,
        requester: &str,
        targets: &[String],
        addresses: &[nip09::Address],
        request_created: u64,
    ) -> usize {
        let mut removed = 0;
        for id in targets {
            let Some(event) = self.stored.get(id) else {
                continue;
            };
            if event.kind == nip09::DELETION_KIND {
                continue;
            }
            if !event.pubkey.eq_ignore_ascii_case(requester) {
                continue;
            }
            self.remove_stored(id);
            self.deleted_ids.insert(id.clone());
            removed += 1;
        }
        for address in addresses {
            if !address.pubkey.eq_ignore_ascii_case(requester) {
                continue;
            }
            let slot = (address.kind, address.pubkey.clone(), address.d.clone());
            let cut = self.address_tombstones.entry(slot.clone()).or_insert(0);
            *cut = (*cut).max(request_created);
            if let Some(id) = self.slots.get(&slot).cloned() {
                let created = self.stored.get(&id).map_or(u64::MAX, |e| e.created_at);
                if created <= request_created {
                    self.remove_stored(&id);
                    self.deleted_ids.insert(id);
                    removed += 1;
                }
            }
        }
        removed
    }

    /// NIP-29 `kind:9005`: deletes `e` targets scoped to one group, leaving
    /// the relay-signed metadata kinds alone.
    fn group_delete(&mut self, targets: &[String], group: &str) -> usize {
        let mut removed = 0;
        for id in targets {
            let Some(event) = self.stored.get(id) else {
                continue;
            };
            if event.kind == nip09::DELETION_KIND {
                continue;
            }
            if nip29::group_id_any(event) != Some(group) {
                continue;
            }
            if (nip29::GROUP_META..=nip29::GROUP_PINS).contains(&event.kind) {
                continue;
            }
            self.remove_stored(id);
            self.deleted_ids.insert(id.clone());
            removed += 1;
        }
        removed
    }

    /// NIP-29 `kind:9008`: removes the group's `h`-tagged history and records
    /// the purge cut (the furthest purge time and the newest removed event).
    fn purge_group(&mut self, group: &str, now: u64) -> usize {
        let doomed: Vec<String> = self
            .stored
            .iter()
            .filter(|(_, event)| h_tagged(event, group))
            .map(|(id, _)| id.clone())
            .collect();
        let max_created = doomed
            .iter()
            .filter_map(|id| self.stored.get(id))
            .map(|event| event.created_at)
            .max()
            .unwrap_or(0);
        for id in &doomed {
            self.remove_stored(id);
        }
        let old = self.purged_groups.get(group).copied().unwrap_or((0, 0));
        let purge_now = old.0.max(now);
        let cut = old.1.max(now).max(max_created);
        self.purged_groups
            .insert(group.to_string(), (purge_now, cut));
        doomed.len()
    }

    /// NIP-62: removes the pubkey's authored history up to `until_created`
    /// and blocks every later put from the pubkey. A replay covered by the
    /// completed marker is a no-op (the store short-circuits it).
    fn vanish(&mut self, pubkey: &str, until_created: u64) -> usize {
        if self
            .vanished
            .get(pubkey)
            .is_some_and(|covered| *covered >= until_created)
        {
            return 0;
        }
        let effective = self
            .vanished
            .get(pubkey)
            .copied()
            .unwrap_or(0)
            .max(until_created);
        self.vanished.insert(pubkey.to_string(), effective);
        let doomed: Vec<String> = self
            .stored
            .iter()
            .filter(|(_, event)| {
                event.pubkey.eq_ignore_ascii_case(pubkey) && event.created_at <= effective
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in &doomed {
            self.remove_stored(id);
        }
        doomed.len()
    }
}

fn h_tagged(event: &Event, group: &str) -> bool {
    event
        .tags
        .iter()
        .any(|tag| tag.len() >= 2 && tag[0] == "h" && tag[1] == group)
}

/// The bounded top-`k` result of one filter, including the scan's
/// same-timestamp boundary continuation (all events tied at the boundary
/// timestamp are kept even past `k`; the generated timestamps are unique, so
/// this only matters as a safety net).
fn limited_ids(matching: &[&Event], k: usize) -> BTreeSet<String> {
    if k == 0 {
        return BTreeSet::new();
    }
    let mut out = BTreeSet::new();
    let mut boundary = None;
    for event in matching {
        if out.len() >= k {
            match boundary {
                Some(bound) if bound == event.created_at => {
                    out.insert(event.id.clone());
                }
                _ => break,
            }
        } else {
            if out.len() + 1 == k {
                boundary = Some(event.created_at);
            }
            out.insert(event.id.clone());
        }
    }
    out
}

fn random_filter(rng: &mut Rng, authors: &[String], history: &[Event]) -> Filter {
    let mut filter = Filter::default();
    if rng.bool() {
        let mut kinds = Vec::new();
        for _ in 0..1 + rng.below(3) {
            kinds.push(FILTER_KINDS[rng.below(FILTER_KINDS.len())]);
        }
        filter.kinds = Some(kinds);
    }
    if rng.bool() {
        let mut picked = Vec::new();
        for _ in 0..1 + rng.below(3) {
            picked.push(authors[rng.below(authors.len())].clone());
        }
        picked.push("ff".repeat(32));
        filter.authors = Some(picked);
    }
    if rng.bool() {
        filter.since = Some(BASE_TIME.saturating_sub(10) + rng.below(400) as u64);
    }
    if rng.bool() {
        filter.until = Some(BASE_TIME.saturating_sub(10) + rng.below(400) as u64);
    }
    if rng.bool() {
        filter.limit = Some(rng.below(6));
    }
    // Tag filters from the generator's vocabulary (hits) mixed with
    // never-stored values (misses): cross-checks the tag index against
    // `Filter::matches`, the class behind the first-value-only-indexing
    // regression. Tag values compare exactly (case-sensitive) on both
    // paths.
    if rng.bool() {
        let name = ["t", "d", "h", "e", "a"][rng.below(5)];
        let mut values = Vec::new();
        for _ in 0..1 + rng.below(3) {
            let value = match rng.below(3) {
                // A value some submitted event carries (a hit while that
                // event stays visible).
                0 => history_tag_value(rng, history, name).unwrap_or_else(|| rng.hex(8)),
                // A vocabulary constant the generator emits (`e`/`a`
                // carry ids/addresses, not constants).
                1 => match name {
                    "t" => "prop".to_string(),
                    "d" => D_TAGS[rng.below(D_TAGS.len())].to_string(),
                    "h" => GROUP_IDS[rng.below(GROUP_IDS.len())].to_string(),
                    _ => rng.hex(64),
                },
                // A never-stored value (a miss): hex can never spell the
                // word constants above, and a random 64-hex id is unique.
                _ => {
                    let len = 1 + rng.below(64);
                    rng.hex(len)
                }
            };
            values.push(serde_json::Value::String(value));
        }
        filter
            .tags
            .insert(format!("#{name}"), serde_json::Value::Array(values));
    }
    // `ids`: full ids and even-length prefixes from history (hits while
    // visible), random hex (usually a miss) and odd-length entries (match
    // nothing by design, mirroring the historical scan). Comparison is
    // ASCII case-insensitive on both paths, so uppercase spellings are
    // covered too.
    if rng.bool() {
        let mut ids = Vec::new();
        for _ in 0..1 + rng.below(3) {
            let mut id = if !history.is_empty() && rng.below(2) == 0 {
                let full = history[rng.below(history.len())].id.clone();
                match rng.below(3) {
                    // An even-length prefix (a hit while visible).
                    0 => full[..2 * (1 + rng.below(31))].to_string(),
                    // Odd length: matches nothing by design.
                    1 => full[..2 * rng.below(32) + 1].to_string(),
                    _ => full,
                }
            } else {
                rng.hex(64)
            };
            if rng.below(4) == 0 {
                id = id.to_ascii_uppercase();
            }
            ids.push(id);
        }
        filter.ids = Some(ids);
    }
    // NIP-50 search: the generator's content vocabulary (hits) and a
    // never-occurring term (misses), cross-checking the word index
    // against the in-memory term match.
    if rng.bool() {
        filter.search = Some(if rng.bool() {
            "prop".to_string()
        } else {
            "zzz-no-such-term-zzz".to_string()
        });
    }
    filter
}

/// A tag value sampled from the submitted history (a hit while the event
/// stays visible): tries a few random events for one carrying `name`.
fn history_tag_value(rng: &mut Rng, history: &[Event], name: &str) -> Option<String> {
    for _ in 0..8 {
        if history.is_empty() {
            return None;
        }
        let event = &history[rng.below(history.len())];
        let values: Vec<&String> = event
            .tags
            .iter()
            .filter(|tag| tag.len() >= 2 && tag[0] == name)
            .map(|tag| &tag[1])
            .collect();
        if !values.is_empty() {
            return Some(values[rng.below(values.len())].clone());
        }
    }
    None
}

/// One write-sequence run: random operations against a real `DbClient` with
/// a fresh `DbClient` over the same path every [`RESTART_EVERY`] ops, and a
/// full visible-set comparison every [`CHECK_EVERY`] ops.
#[test]
fn random_operations_preserve_visible_set() {
    for seed in SEEDS {
        run_visible_set_sequence(seed);
    }
}

#[test]
fn random_filters_match_model_filtered_set() {
    for seed in FILTER_SEEDS {
        run_filter_sequence(seed);
    }
}

struct Harness {
    db: DbClient,
    model: Model,
    rng: Rng,
    authors: Vec<String>,
    /// Every event ever submitted (including deletion requests), so re-puts
    /// can replay deleted/replaced/expired versions.
    history: Vec<Event>,
    /// Strictly increasing `created_at` allocator: stored timestamps stay
    /// unique, which keeps the limit model exact.
    created: u64,
    /// Logical wall clock (drives expiry visibility and purge cuts).
    now: u64,
    seed: u64,
}

impl Harness {
    fn new(cfg: &DatabaseConfig, seed: u64) -> Self {
        Self {
            db: open_db(cfg),
            model: Model::default(),
            rng: Rng::new(seed),
            authors: author_pool(),
            history: Vec::new(),
            created: BASE_TIME,
            now: BASE_TIME + 5_000,
            seed,
        }
    }

    fn ctx(&self, op: usize) -> String {
        format!("seed={:#x} op={op}", self.seed)
    }

    fn next_created(&mut self) -> u64 {
        self.created += 1;
        self.created
    }

    fn author(&mut self) -> String {
        self.authors[self.rng.below(self.authors.len())].clone()
    }

    fn slot_created(&self, slot: &Slot) -> Option<u64> {
        self.model
            .slots
            .get(slot)
            .and_then(|id| self.model.stored.get(id))
            .map(|event| event.created_at)
    }

    fn random_slot(&mut self) -> Option<Slot> {
        let len = self.model.slots.len();
        if len == 0 {
            return None;
        }
        let index = self.rng.below(len);
        self.model.slots.keys().nth(index).cloned()
    }

    fn random_history(&mut self) -> Option<Event> {
        if self.history.is_empty() {
            return None;
        }
        let index = self.rng.below(self.history.len());
        Some(self.history[index].clone())
    }

    /// A historical event that is no longer stored: a deletion tombstone,
    /// a replaced version, an expired event or a vanished author's post.
    /// Replaying it must re-run the exact acceptance rules (and usually be
    /// refused), which a pick from the live set can never check.
    fn random_gone(&mut self) -> Option<Event> {
        let gone: Vec<Event> = self
            .history
            .iter()
            .filter(|event| !self.model.stored.contains_key(&event.id))
            .cloned()
            .collect();
        if gone.is_empty() {
            return None;
        }
        let index = self.rng.below(gone.len());
        Some(gone[index].clone())
    }

    fn submit(&mut self, rt: &tokio::runtime::Runtime, event: Event, now: u64, ctx: &str) {
        self.history.push(event.clone());
        let wanted = self.model.put(&event, now);
        let got = expected(&rt.block_on(self.db.put(event, now)));
        assert_eq!(got, wanted, "{ctx}: put outcome");
    }

    fn step(&mut self, rt: &tokio::runtime::Runtime, op: usize) {
        let ctx = self.ctx(op);
        self.now = self.now.saturating_add(self.rng.below(4) as u64);
        match self.rng.below(100) {
            // Plain kind-1 events.
            0..=14 => {
                let author = self.author();
                let created = self.next_created();
                let tags = if self.rng.bool() {
                    vec![vec!["t".to_string(), "prop".to_string()]]
                } else {
                    Vec::new()
                };
                let event = mk_event(created, &author, 1, created, tags);
                self.submit(rt, event, self.now, &ctx);
            }
            // Replaceable (0/3/10000-19999): the `d` tag must be ignored. A
            // quarter of them reuse the slot's timestamp to exercise the
            // lowest-id tie-break.
            15..=28 => {
                let author = self.author();
                let kind = REPLACEABLE_KINDS[self.rng.below(REPLACEABLE_KINDS.len())];
                let slot = (kind, author.clone(), String::new());
                let created = if self.rng.below(4) == 0 {
                    self.slot_created(&slot)
                } else {
                    None
                }
                .unwrap_or_else(|| self.next_created());
                let mut tags = Vec::new();
                if self.rng.bool() {
                    tags.push(vec![
                        "d".to_string(),
                        D_TAGS[self.rng.below(D_TAGS.len())].into(),
                    ]);
                }
                let event = mk_event(created, &author, kind, created, tags);
                self.submit(rt, event, self.now, &ctx);
            }
            // Addressable (30000-39999), keyed on `(kind, pubkey, d)`.
            29..=40 => {
                let author = self.author();
                let kind = ADDRESSABLE_KINDS[self.rng.below(ADDRESSABLE_KINDS.len())];
                let d = D_TAGS[self.rng.below(D_TAGS.len())].to_string();
                let slot = (kind, author.clone(), d.clone());
                let created = if self.rng.below(4) == 0 {
                    self.slot_created(&slot)
                } else {
                    None
                }
                .unwrap_or_else(|| self.next_created());
                let tags = vec![vec!["d".to_string(), d]];
                let event = mk_event(created, &author, kind, created, tags);
                self.submit(rt, event, self.now, &ctx);
            }
            // Ephemeral (20000-29999): never stored.
            41..=46 => {
                let author = self.author();
                let kind = EPHEMERAL_KINDS[self.rng.below(EPHEMERAL_KINDS.len())];
                let created = self.next_created();
                let event = mk_event(created, &author, kind, created, Vec::new());
                self.submit(rt, event, self.now, &ctx);
            }
            // NIP-40: a past expiration is rejected at put time, a future
            // one becomes invisible (and purgeable) once the clock passes it.
            47..=60 => {
                let author = self.author();
                let kind = EXPIRING_KINDS[self.rng.below(EXPIRING_KINDS.len())];
                let created = self.next_created();
                let mut tags = Vec::new();
                if nip33::is_param_replaceable_kind(kind) {
                    tags.push(vec![
                        "d".to_string(),
                        D_TAGS[self.rng.below(D_TAGS.len())].into(),
                    ]);
                }
                let exp = if self.rng.bool() {
                    self.now.saturating_sub(self.rng.below(10) as u64)
                } else {
                    self.now + 1 + self.rng.below(20) as u64
                };
                tags.push(vec!["expiration".to_string(), exp.to_string()]);
                let event = mk_event(created, &author, kind, created, tags);
                self.submit(rt, event, self.now, &ctx);
            }
            // NIP-29 user/moderation/metadata events. Metadata kinds are
            // keyed by `d`, everything else by `h`.
            61..=68 => {
                let author = self.author();
                let kind = GROUP_KINDS[self.rng.below(GROUP_KINDS.len())];
                let group = GROUP_IDS[self.rng.below(GROUP_IDS.len())];
                let tags = if (nip29::GROUP_META..=nip29::GROUP_PINS).contains(&kind) {
                    vec![vec!["d".to_string(), group.into()]]
                } else {
                    vec![vec!["h".to_string(), group.into()]]
                };
                let created = self.next_created();
                let event = mk_event(created, &author, kind, created, tags);
                self.submit(rt, event, self.now, &ctx);
            }
            // Replay any historical event: deleted ids, replaced versions,
            // expired events and vanished authors must all be judged again.
            69..=73 => {
                if let Some(event) = self.random_gone() {
                    self.submit(rt, event, self.now, &ctx);
                }
            }
            // NIP-09 deletion request: the kind-5 event is stored first, then
            // its `e`/`a` targets are applied. `request_created` is
            // occasionally older than the current clock to exercise the
            // address cut (a version above the cut survives).
            74..=85 => {
                let requester = self.author();
                let mut targets = Vec::new();
                for _ in 0..self.rng.below(4) {
                    if let Some(event) = self.random_history() {
                        targets.push(event.id);
                    }
                }
                let mut addresses = Vec::new();
                for _ in 0..self.rng.below(3) {
                    let (kind, pubkey, d) = if self.rng.bool() {
                        self.random_slot().unwrap_or_else(|| {
                            (ADDRESSABLE_KINDS[0], requester.clone(), String::new())
                        })
                    } else {
                        let kind = ADDRESSABLE_KINDS[self.rng.below(ADDRESSABLE_KINDS.len())];
                        let pubkey = self.author();
                        let d = D_TAGS[self.rng.below(D_TAGS.len())].to_string();
                        (kind, pubkey, d)
                    };
                    addresses.push(nip09::Address { kind, pubkey, d });
                }
                let created = self.next_created();
                let request_created = if self.rng.below(3) == 0 {
                    self.created.saturating_sub(self.rng.below(150) as u64)
                } else {
                    created
                };
                let mut tags: Vec<Vec<String>> = targets
                    .iter()
                    .map(|id| vec!["e".to_string(), id.clone()])
                    .collect();
                tags.extend(addresses.iter().map(|address| {
                    vec![
                        "a".to_string(),
                        format!("{}:{}:{}", address.kind, address.pubkey, address.d),
                    ]
                }));
                let request = mk_event(request_created, &requester, 5, created, tags);
                self.history.push(request.clone());
                let wanted = self.model.put(&request, self.now);
                let got = expected(&rt.block_on(self.db.put(request, self.now)));
                assert_eq!(got, wanted, "{ctx}: deletion request put outcome");
                if matches!(wanted, Expected::Stored | Expected::Replaced) {
                    let removed =
                        self.model
                            .delete(&requester, &targets, &addresses, request_created);
                    let got_removed = rt.block_on(self.db.apply_deletion_checked(
                        targets.clone(),
                        addresses,
                        Some(requester),
                        request_created,
                    ));
                    assert_eq!(
                        got_removed.0,
                        Some(removed),
                        "{ctx}: NIP-09 deletion removed count"
                    );
                    // Replay one targeted version right after the deletion:
                    // the id tombstone must report it as previously deleted
                    // (or the address cut must refuse it) instead of letting
                    // it back in.
                    if let Some(event) = self
                        .history
                        .iter()
                        .find(|event| targets.contains(&event.id))
                        .cloned()
                    {
                        self.submit(rt, event, self.now, &ctx);
                    }
                }
            }
            // NIP-62 vanish. Half the requests cut near the current clock
            // (the usual "erase everything"), half cut somewhere in the
            // history so older versions survive the removal.
            86..=89 => {
                let pubkey = self.author();
                let until = if self.rng.bool() {
                    self.created.saturating_sub(self.rng.below(120) as u64)
                } else {
                    BASE_TIME + self.rng.below((self.created - BASE_TIME).max(1) as usize) as u64
                };
                let wanted = self.model.vanish(&pubkey, until);
                let key: [u8; 32] = hex::decode(&pubkey).unwrap().try_into().unwrap();
                let got = rt.block_on(self.db.apply_vanish_checked(key, until));
                assert_eq!(
                    got.map(|(removed, _)| removed),
                    Some(wanted),
                    "{ctx}: NIP-62 vanish removed count"
                );
            }
            // NIP-29 group-scoped deletion (kind:9005 side effect).
            90..=93 => {
                let group = GROUP_IDS[self.rng.below(GROUP_IDS.len())].to_string();
                let mut targets = Vec::new();
                for _ in 0..self.rng.below(4) {
                    if let Some(event) = self.random_history() {
                        targets.push(event.id);
                    }
                }
                let wanted = self.model.group_delete(&targets, &group);
                let got = rt.block_on(self.db.apply_group_deletion_checked(targets, group));
                assert_eq!(
                    got.0,
                    Some(wanted),
                    "{ctx}: NIP-29 group deletion removed count"
                );
            }
            // NIP-29 group purge (kind:9008 side effect).
            94..=95 => {
                let group = GROUP_IDS[self.rng.below(GROUP_IDS.len())].to_string();
                let wanted = self.model.purge_group(&group, self.now);
                let got = rt.block_on(self.db.group_purge(group, self.now));
                assert_eq!(got, Some(wanted), "{ctx}: NIP-29 group purge removed count");
            }
            // NIP-40 periodic purge: expired events leave storage.
            _ => {
                let wanted = self.model.purge_expired(self.now);
                let got = rt.block_on(self.db.purge_expired(self.now, 0));
                assert_eq!(got.0, wanted, "{ctx}: NIP-40 expiry purge removed count");
            }
        }
    }
}

fn check_visible(rt: &tokio::runtime::Runtime, harness: &Harness, op: usize, stage: &str) {
    let now = harness.now;
    let wanted = harness.model.visible_ids(now);
    let ctx = format!("seed={:#x} op={op} ({stage})", harness.seed);
    let filter = Filter::default();
    let (events, _) = rt.block_on(harness.db.query_req(vec![filter.clone()], QUERY_LIMIT, now));
    let got: BTreeSet<String> = events.iter().map(|event| event.id.clone()).collect();
    assert_eq!(got, wanted, "{ctx}: query_req visible set");
    for event in &events {
        assert!(
            wanted.contains(&event.id),
            "{ctx}: hidden event {} was served",
            event.id
        );
    }
    let (events, _) = rt.block_on(harness.db.query(vec![filter], QUERY_LIMIT, now));
    let got: BTreeSet<String> = events.iter().map(|event| event.id.clone()).collect();
    assert_eq!(got, wanted, "{ctx}: query visible set");
}

fn run_visible_set_sequence(seed: u64) {
    let cfg = config();
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let mut harness = Harness::new(&cfg, seed);
    for op in 0..OPS_PER_SEED {
        if op > 0 && op % RESTART_EVERY == 0 {
            harness.db.shutdown();
            harness.db = open_db(&cfg);
            check_visible(&rt, &harness, op, "after restart");
        }
        harness.step(&rt, op);
        if op % CHECK_EVERY == CHECK_EVERY - 1 {
            check_visible(&rt, &harness, op, "periodic");
        }
    }
    check_visible(&rt, &harness, OPS_PER_SEED, "final");
    assert_eq!(
        harness.db.take_errors(),
        0,
        "seed={:#x}: database errors",
        seed
    );
    assert_eq!(
        harness.db.take_overloads(),
        0,
        "seed={:#x}: overload fail-fast",
        seed
    );
    harness.db.shutdown();
}

fn check_random_filter(rt: &tokio::runtime::Runtime, harness: &mut Harness, check: usize) {
    let filter = random_filter(&mut harness.rng, &harness.authors, &harness.history);
    let now = harness.now;
    let ctx = format!("seed={:#x} filter-check={check} now={now}", harness.seed);
    let mut matching: Vec<&Event> = harness
        .model
        .visible_events(now)
        .into_iter()
        .filter(|event| filter.matches(*event))
        .collect();
    // NIP-01 newest first, lowest id first on a tie (the scan's sort key).
    matching.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
            .then_with(|| a.id.cmp(&b.id))
    });
    let limit = filter
        .limit
        .map_or(QUERY_LIMIT, |limit| limit.min(QUERY_LIMIT));
    let wanted = limited_ids(&matching, limit);
    let (events, _) = rt.block_on(harness.db.query(vec![filter.clone()], QUERY_LIMIT, now));
    let got: BTreeSet<String> = events.iter().map(|event| event.id.clone()).collect();
    assert_eq!(got, wanted, "{ctx}: filtered query");
    for event in &events {
        assert!(
            harness.model.is_visible(&event.id, now),
            "{ctx}: hidden event {} was served",
            event.id
        );
        assert!(
            filter.matches(event),
            "{ctx}: served event {} does not match the filter",
            event.id
        );
    }
    // COUNT ignores the filter's own `limit` and counts up to the request's
    // limit. The count is exact up to that cap; hitting the cap reports the
    // result as approximate (`more`) — but only when the walk was actually
    // cut short. A walk that exhausts exactly at the cap is complete, so
    // an exact count is not approximate.
    let count_limit = 1 + harness.rng.below(QUERY_LIMIT);
    let (counted, more) = rt
        .block_on(harness.db.count_reported(vec![filter], count_limit, now))
        .expect("count_reported must not fail");
    assert_eq!(
        counted.len(),
        matching.len().min(count_limit),
        "{ctx}: COUNT must equal the filtered cardinality up to the count limit"
    );
    assert_eq!(
        more,
        matching.len() > count_limit,
        "{ctx}: COUNT completeness flag (exact cap hit is complete, not approximate)"
    );
}

fn run_filter_sequence(seed: u64) {
    let cfg = config();
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let mut harness = Harness::new(&cfg, seed);
    for op in 0..FILTER_OPS {
        harness.step(&rt, op);
    }
    for check in 0..FILTER_CHECKS {
        harness.now = harness.now.saturating_add(harness.rng.below(2) as u64);
        check_random_filter(&rt, &mut harness, check);
    }
    assert_eq!(
        harness.db.take_errors(),
        0,
        "seed={:#x}: database errors",
        seed
    );
    assert_eq!(
        harness.db.take_overloads(),
        0,
        "seed={:#x}: overload fail-fast",
        seed
    );
    harness.db.shutdown();
}
