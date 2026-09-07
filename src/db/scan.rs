//! Query engine.
//!
//! Applies filters through index-selected range walks and collects the
//! matches for REQ (full events), COUNT (counts) and NIP-77 negentropy
//! (`(created_at, id)` records). Every scan shares the same collector
//! machinery, the NIP-01 ordering rules and the NIP-67 completeness flag.

use std::collections::HashSet;

use heed::types::Bytes;
use heed::{Database, RoTxn};

use super::store::{
    ID_LEN, Store, TAG_INDEX_VALUE_MAX, WORD_INDEX_MAX, created_key, kind_key, pubkey_key,
    tag_range,
};
use crate::error::Result;
use crate::event::Event;
use crate::filter::{EventFields, Filter};
use crate::nips::nip50;

/// A single NIP-77 negentropy record returned by a negentropy query. The
/// visibility flags let the connection layer withhold NIP-70 protected
/// events from unauthenticated peers, NIP-29 private/hidden group content
/// from non-members and NIP-59 gift wraps from anyone but their
/// recipients, mirroring the REQ path.
pub(crate) struct NegItem {
    pub created: u64,
    pub id: [u8; 32],
    /// Author pubkey (hex), so the connection layer can serve NIP-78
    /// application-specific events only to their authenticated owner.
    pub pubkey: String,
    pub protected: bool,
    /// Whether this record is a NIP-78 application-specific event (kinds
    /// 78/30078), served only to the authenticated owner when the AUTH
    /// gate is on.
    pub app_specific: bool,
    pub gid: Option<String>,
    pub meta: bool,
    /// p-tag recipients of a NIP-59 gift wrap (kind 1059), `None` for every
    /// other kind. Kept so the connection layer can serve wraps only to
    /// their recipients without loading the full events back.
    pub wrap_recipients: Option<Vec<String>>,
}

pub(crate) type NegItems = Vec<NegItem>;

/// The database handles and transaction of one scan, bundled so the
/// per-candidate checks stay readable.
struct ScanContext<'tx> {
    events: Database<Bytes, Bytes>,
    event_meta: Option<Database<Bytes, Bytes>>,
    deleted: Database<Bytes, Bytes>,
    banned: Database<Bytes, Bytes>,
    expiry_enabled: bool,
    rtxn: &'tx RoTxn<'tx>,
}

/// The per-filter parameters of one scan pass.
struct FilterScan<'a> {
    filter: &'a Filter,
    terms: &'a [String],
    now: u64,
    limit: usize,
    ascending: bool,
}

/// The mutable collection state shared by the candidates of a scan pass.
struct Collect<'a, C: ScanCollector> {
    seen: &'a mut HashSet<Vec<u8>>,
    out: &'a mut C,
}

/// NIP-50 search collection budget: the scan gathers up to this many
/// candidates (instead of the response limit) so that the relevance
/// ordering can pick the best matches before the limit is applied.
const SEARCH_BUDGET_MULTIPLIER: usize = 8;
const SEARCH_BUDGET_MAX: usize = 100_000;

/// Upper bound on the number of query terms used for a search: the word
/// index walk and the relevance ranking both stop here, so a pathological
/// query (e.g. a 1000-byte search string) cannot fan out into hundreds of
/// index ranges.
pub(crate) const SEARCH_MAX_TERMS: usize = 32;

/// How many word-index keys are counted per term to estimate its document
/// frequency for the IDF weight: beyond this the term is "common" and its
/// weight is negligible, so the count stops early to keep search instant.
const DF_SAMPLE: u64 = 4096;

/// Upper bound on the number of index candidates examined by one scan pass
/// before it gives up. A filter matching nothing (e.g. a popular `#p` value
/// combined with an impossible kind) would otherwise walk the whole range
/// and stall the reader thread for seconds. The cap is large enough that
/// legitimate subscriptions are never truncated in practice.
pub(crate) const SCAN_BUDGET: usize = 200_000;

/// Budget used by the startup rebuilds (NIP-29 group state, NIP-43 role
/// store): they must read the whole history, so they may walk far more
/// candidates than a client-driven subscription.
pub(crate) const FULL_SCAN_BUDGET: usize = 4_000_000;

/// Output collector for a scan: either full events (REQ/COUNT) or
/// `(created_at, id)` records (NIP-77 negentropy, memory-efficient).
trait ScanCollector {
    fn len(&self) -> usize;
    /// Whether the scan must stop: the hard collection cap is reached and
    /// no created_at boundary is being completed.
    fn full(&self) -> bool;
    /// The hard collection cap of this collector.
    fn cap(&self) -> usize;
    /// Starts the per-filter limit accounting over (the boundary timestamp
    /// belongs to one filter's limit, not the next one's).
    fn reset_boundary(&mut self);
    /// Pushes a matched event; returns `false` when the per-filter limit is
    /// reached and the event is strictly older than the boundary timestamp,
    /// so the scan stops. Events at the boundary timestamp are still
    /// collected: a page never splits a created_at tie across responses
    /// (NIP-01 ordering, NIP-67 boundary cursor).
    fn push(&mut self, event: Event, id: [u8; 32], limit: usize) -> bool;

    /// Lightweight push for the negentropy collector: the candidate was
    /// deserialized without its content. The event collectors never use
    /// this path.
    fn push_light(&mut self, event: &NegLight, id: [u8; 32], limit: usize) -> bool {
        let _ = (event, id, limit);
        unreachable!("push_light is only implemented by the negentropy collector")
    }
    /// Sorts the collected records by the NIP-01 ordering (newest first,
    /// lowest id first on equal timestamps).
    fn sort_key(&mut self);
    /// Sorts the collected records oldest first, lowest id first on equal
    /// timestamps (ascending variant of the NIP-01 ordering).
    fn sort_asc(&mut self);
    /// Sorts by NIP-50 search relevance (most matching terms first, weighted
    /// by the inverse document frequency of each term), then by the NIP-01
    /// ordering.
    fn sort_relevance(&mut self, terms: &[String], weights: &[f64]);
    /// Keeps only the first `take` records.
    fn truncate_to(&mut self, take: usize);
}

struct EventCollector {
    events: Vec<Event>,
    /// Hard stop for the whole scan.
    cap: usize,
    /// Whether the created_at boundary continuation applies (REQ/NEG
    /// delivery, NIP-67) or the limit must cut exactly (COUNT, NIP-45).
    boundary_ok: bool,
    /// created_at of the event that filled a per-filter limit; events at
    /// the same timestamp keep being collected (see [`ScanCollector::push`]).
    boundary: Option<u64>,
}

impl EventCollector {
    fn new(cap: usize, boundary_ok: bool) -> Self {
        EventCollector {
            events: Vec::new(),
            cap,
            boundary_ok,
            boundary: None,
        }
    }
}

/// The NIP-50 relevance score of an event: the sum of the weights of the
/// query terms present in its content *as whole words*. Weights are the
/// inverse document frequency of each term (`1 / (1 + ln df)`), so rarer
/// terms dominate. Whole-word matching keeps the ranking consistent with
/// the matching itself (a term present only as a substring of a longer
/// word, e.g. "ru" inside "rust", contributes nothing).
fn score(event: &Event, terms: &[String], weights: &[f64]) -> f64 {
    let words = crate::nips::nip50::tokenize(&event.content);
    terms
        .iter()
        .zip(weights)
        .filter(|(t, _)| words.iter().any(|w| w == *t))
        .map(|(_, w)| w)
        .sum()
}

impl ScanCollector for EventCollector {
    fn len(&self) -> usize {
        self.events.len()
    }
    fn full(&self) -> bool {
        self.events.len() >= self.cap && self.boundary.is_none()
    }
    fn cap(&self) -> usize {
        self.cap
    }
    fn reset_boundary(&mut self) {
        self.boundary = None;
    }
    fn push(&mut self, event: Event, _id: [u8; 32], limit: usize) -> bool {
        if self.events.len() >= limit {
            if !self.boundary_ok {
                return false;
            }
            match self.boundary {
                Some(b) if b == event.created_at => {}
                _ => return false,
            }
        } else if self.events.len() + 1 == limit {
            self.boundary = Some(event.created_at);
        }
        self.events.push(event);
        true
    }
    fn sort_key(&mut self) {
        self.events.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
    }
    fn sort_asc(&mut self) {
        self.events.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
    }
    fn sort_relevance(&mut self, terms: &[String], weights: &[f64]) {
        // Score every event exactly once (the per-event tokenization is the
        // expensive part; a comparator would re-tokenize each event on every
        // comparison), then sort by the precomputed scores.
        let mut scored: Vec<(f64, Event)> = std::mem::take(&mut self.events)
            .into_iter()
            .map(|event| (score(&event, terms, weights), event))
            .collect();
        scored.sort_by(|(sa, a), (sb, b)| {
            sb.partial_cmp(sa)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.created_at.cmp(&a.created_at))
                .then_with(|| a.id.cmp(&b.id))
        });
        self.events = scored.into_iter().map(|(_, event)| event).collect();
    }
    fn truncate_to(&mut self, take: usize) {
        self.events.truncate(take);
    }
}

struct ItemCollector {
    items: NegItems,
    cap: usize,
    boundary: Option<u64>,
}

impl ItemCollector {
    fn new(cap: usize) -> Self {
        ItemCollector {
            items: Vec::new(),
            cap,
            boundary: None,
        }
    }
}

impl ScanCollector for ItemCollector {
    fn len(&self) -> usize {
        self.items.len()
    }
    fn full(&self) -> bool {
        self.items.len() >= self.cap && self.boundary.is_none()
    }
    fn cap(&self) -> usize {
        self.cap
    }
    fn reset_boundary(&mut self) {
        self.boundary = None;
    }
    fn push(&mut self, event: Event, id: [u8; 32], limit: usize) -> bool {
        if self.items.len() >= limit {
            match self.boundary {
                Some(b) if b == event.created_at => {}
                _ => return false,
            }
        } else if self.items.len() + 1 == limit {
            self.boundary = Some(event.created_at);
        }
        let protected = crate::nips::nip70::is_protected(&event);
        let (gid, meta) = match crate::nips::nip29::group_id_any(&event) {
            Some(gid) => {
                let meta = (crate::nips::nip29::GROUP_META..=crate::nips::nip29::GROUP_PINS)
                    .contains(&event.kind);
                (Some(gid.to_string()), meta)
            }
            None => (None, false),
        };
        let wrap_recipients = if event.kind == crate::nips::nip62::GIFT_WRAP_KIND {
            Some(
                event
                    .tags
                    .iter()
                    .filter(|t| t.len() >= 2 && t[0] == "p")
                    .map(|t| t[1].clone())
                    .collect(),
            )
        } else {
            None
        };
        self.items.push(NegItem {
            created: event.created_at,
            id,
            pubkey: event.pubkey.clone(),
            protected,
            app_specific: crate::nips::nip78::is_app_specific(&event),
            gid,
            meta,
            wrap_recipients,
        });
        true
    }
    fn push_light(&mut self, event: &NegLight, id: [u8; 32], limit: usize) -> bool {
        if self.items.len() >= limit {
            match self.boundary {
                Some(b) if b == event.created_at => {}
                _ => return false,
            }
        } else if self.items.len() + 1 == limit {
            self.boundary = Some(event.created_at());
        }
        let protected = event
            .tags()
            .iter()
            .any(|t| t.first().map(String::as_str) == Some(crate::nips::nip70::PROTECTED_TAG));
        let (gid, meta) = match crate::nips::nip29::group_id_any_light(event) {
            Some(gid) => {
                let meta = (crate::nips::nip29::GROUP_META..=crate::nips::nip29::GROUP_PINS)
                    .contains(&event.kind());
                (Some(gid.to_string()), meta)
            }
            None => (None, false),
        };
        let wrap_recipients = if event.kind() == crate::nips::nip62::GIFT_WRAP_KIND {
            Some(
                event
                    .tags()
                    .iter()
                    .filter(|t| t.len() >= 2 && t[0] == "p")
                    .map(|t| t[1].clone())
                    .collect(),
            )
        } else {
            None
        };
        self.items.push(NegItem {
            created: event.created_at(),
            id,
            pubkey: event.pubkey().to_string(),
            protected,
            app_specific: crate::nips::nip78::is_app_specific_kind(event.kind()),
            gid,
            meta,
            wrap_recipients,
        });
        true
    }
    fn sort_key(&mut self) {
        self.items
            .sort_by(|a, b| b.created.cmp(&a.created).then_with(|| a.id.cmp(&b.id)));
    }
    fn sort_asc(&mut self) {
        self.items
            .sort_by(|a, b| a.created.cmp(&b.created).then_with(|| a.id.cmp(&b.id)));
    }
    fn sort_relevance(&mut self, terms: &[String], weights: &[f64]) {
        // Negentropy items are re-sorted by the protocol anyway; keep the
        // relevance path a no-op for the same ordering as sort_key.
        let _ = (terms, weights);
        self.sort_key();
    }
    fn truncate_to(&mut self, take: usize) {
        self.items.truncate(take);
    }
}
/// What a scan is collecting: full events for REQ, plain counts for
/// NIP-45 COUNT, or `(created_at, id)` records for NIP-77 negentropy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScanKind {
    Query,
    Count,
    Negentropy,
}

/// Parses the sort tail `(created_at, id)` from an index key
/// (`(prefix..., created_at, id)`). A key shorter than 40 bytes is
/// corruption (a truncated or hand-crafted index entry): the scan fails
/// loudly instead of panicking on the slice.
fn index_tail(key: &[u8]) -> std::result::Result<([u8; 8], [u8; 32]), String> {
    if key.len() < 40 {
        return Err(format!("corrupt index key ({} bytes)", key.len()));
    }
    let created: [u8; 8] = key[key.len() - 40..key.len() - 32]
        .try_into()
        .expect("slice length checked above");
    let id: [u8; 32] = key[key.len() - 32..]
        .try_into()
        .expect("slice length checked above");
    Ok((created, id))
}

impl Store {
    /// The document frequency of each search term, from the word index
    /// (counted up to [`DF_SAMPLE`]; a term reaching the cap is a "common
    /// term"). Terms are counted once per query and shared between the
    /// index-walk exclusion ([`Self::scan_filter`]) and the relevance
    /// weights, so a REQ does not pay the count twice.
    fn term_dfs(&self, rtxn: &RoTxn, terms: &[String]) -> Vec<u64> {
        let Some(by_word) = self.by_word else {
            return vec![0; terms.len()];
        };
        terms
            .iter()
            .map(|term| {
                if term.len() > WORD_INDEX_MAX {
                    return 0;
                }
                let mut start = term.as_bytes().to_vec();
                start.push(0x00);
                let mut end = term.as_bytes().to_vec();
                end.push(0x01);
                let range = (
                    std::ops::Bound::Included(start.as_slice()),
                    std::ops::Bound::Excluded(end.as_slice()),
                );
                let mut df = 0u64;
                if let Ok(iter) = by_word.range(rtxn, &range) {
                    for item in iter {
                        match item {
                            Ok(_) => {
                                df += 1;
                                if df >= DF_SAMPLE {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                }
                df
            })
            .collect()
    }

    /// The inverse document frequency weight of each search term from its
    /// document frequency. Rarer terms get a higher weight, so a query
    /// like "nostr bitcoin" ranks an event about both topics above one
    /// that merely mentions the common word "nostr". A missing word index
    /// leaves every term equally weighted.
    fn weights_from_dfs(dfs: &[u64]) -> Vec<f64> {
        dfs.iter()
            .map(|df| 1.0 / (1.0 + (*df.max(&1) as f64).ln()))
            .collect()
    }

    /// Collects events that match the filters, most recent first.
    ///
    /// `hidden_slack` lets a REQ over-fetch each filter's limit by a factor
    /// (`limit * (hidden_slack + 1)`, capped at `max_limit`) so that events
    /// hidden by the connection-level visibility rules (NIP-70 protected,
    /// NIP-59 gift wraps, NIP-29 private/hidden groups) do not consume the
    /// limit slots; the connection truncates the visible results back to the
    /// requested limits. Pass 0 for COUNT, negentropy and the API.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn scan(
        &self,
        filters: &[Filter],
        now: u64,
        max_limit: usize,
        count_mode: bool,
        ascending: bool,
        budget: usize,
        hidden_slack: usize,
    ) -> Result<(Vec<Event>, bool)> {
        let has_search = filters.iter().any(Filter::has_search);
        // NIP-50: relevance ordering needs more candidates than the response
        // limit, so the scan gathers up to the search budget.
        let collect_cap = if has_search {
            max_limit
                .saturating_mul(SEARCH_BUDGET_MULTIPLIER)
                .min(SEARCH_BUDGET_MAX)
        } else {
            max_limit
        };
        let kind = if count_mode {
            ScanKind::Count
        } else {
            ScanKind::Query
        };
        let mut out = EventCollector::new(collect_cap, !count_mode);
        let more = self.scan_collect(
            filters,
            now,
            max_limit,
            kind,
            ascending,
            budget,
            hidden_slack,
            &mut out,
            false,
        )?;
        Ok((out.events, more))
    }

    /// Collects only `(created_at, id)` records of the matching events
    /// (NIP-77 negentropy). Keeps the memory footprint small instead of
    /// materializing every full event.
    pub(crate) fn scan_neg(
        &self,
        filter: &Filter,
        now: u64,
        max_items: usize,
        budget: usize,
    ) -> Result<(NegItems, bool)> {
        let collect_cap = if filter.has_search() {
            max_items
                .saturating_mul(SEARCH_BUDGET_MULTIPLIER)
                .min(SEARCH_BUDGET_MAX)
        } else {
            max_items
        };
        let mut out = ItemCollector::new(collect_cap);
        let more = self.scan_collect(
            std::slice::from_ref(filter),
            now,
            max_items,
            ScanKind::Negentropy,
            false,
            budget,
            0,
            &mut out,
            // A search filter needs the content, which the light parse
            // skips: those NEG queries fall back to the full path.
            !filter.has_search(),
        )?;
        Ok((out.items, more))
    }

    /// Shared scan core: applies the filters through the index-selected
    /// candidate walks and collects into `out`. Returns `true` when the
    /// scan stopped at a limit instead of exhausting the matches
    /// (NIP-67 EOSE completeness hint).
    #[allow(clippy::too_many_arguments)]
    fn scan_collect<C: ScanCollector>(
        &self,
        filters: &[Filter],
        now: u64,
        max_limit: usize,
        kind: ScanKind,
        ascending: bool,
        budget: usize,
        hidden_slack: usize,
        out: &mut C,
        light: bool,
    ) -> Result<bool> {
        let count_mode = matches!(kind, ScanKind::Count);
        // NIP-50 relevance ordering only applies when *every* filter of the
        // REQ is a search filter. A REQ mixing search and plain filters
        // (e.g. `[{"search": "x", "limit": 5}, {"kinds": [1], "limit": 10}]`)
        // must return the union of both: truncating the whole response to
        // the search filters' limits would silently drop the plain
        // filters' results, and relevance-sorting would reorder them.
        let has_plain = filters.iter().any(|f| !f.has_search());
        let sort_search = matches!(kind, ScanKind::Query) && !has_plain;
        if max_limit == 0 {
            return Ok(false);
        }
        let rtxn = self.env.read_txn()?;
        let mut seen: HashSet<Vec<u8>> = HashSet::new();
        // Work budget shared by every filter of this REQ: an anti-DoS cap on
        // the candidates examined across all filters, so a REQ with many
        // filters cannot multiply the budget (e.g. 20 filters x 200k
        // examinations) and stall the reader thread.
        let mut examined = 0usize;
        // `more` is true when a scan stopped because of a limit instead of
        // exhausting the matching records (NIP-67 EOSE completeness hint).
        let mut more = false;
        // Union of every search filter's terms, for the relevance ordering,
        // and the response cap of the search results (min of the search
        // filters' limits, bounded by the relay's max_limit). Built once,
        // before the scan loop, so the document frequencies below cover
        // exactly the terms the walk exclusion and the ranking use.
        let mut all_terms: Vec<String> = Vec::new();
        for filter in filters {
            if let Some(search) = filter.search.as_deref()
                && !search.trim().is_empty()
            {
                for t in crate::nips::nip50::terms(search) {
                    if !all_terms.contains(&t) {
                        all_terms.push(t);
                        if all_terms.len() >= SEARCH_MAX_TERMS {
                            break;
                        }
                    }
                }
            }
        }
        let mut search_take = max_limit;
        // The document frequencies of the query's search terms are counted
        // once and shared between the index-walk exclusion (common terms
        // dropped from the walk) and the relevance weights.
        let all_dfs: Vec<u64> = if all_terms.is_empty() {
            Vec::new()
        } else {
            self.term_dfs(&rtxn, &all_terms)
        };

        for filter in filters {
            if out.full() {
                more = true;
                break;
            }
            let has_search = filter.has_search();
            let limit = if count_mode {
                max_limit
            } else if has_search && sort_search {
                // NIP-50 (pure-search REQ): the limit is applied after the
                // relevance sort, so candidates are gathered up to the
                // collection budget.
                out.cap()
            } else {
                let base = filter.limit.unwrap_or(max_limit).min(max_limit);
                // Hidden-event slack: events withheld by the connection's
                // visibility rules (NIP-70/59/29) must not consume the
                // per-filter limit slots, so a REQ over-fetches a little
                // and the connection truncates the visible results back to
                // the requested limits.
                base.saturating_mul(hidden_slack.saturating_add(1))
                    .min(max_limit)
            };
            let terms = if has_search {
                let terms = nip50::terms(filter.search.as_deref().unwrap_or(""));
                // Cap the terms used for the index walk and the ranking: a
                // pathological search string must not fan out into hundreds
                // of index ranges. Events matching only the truncated terms
                // are not candidates; the most common terms (last, in
                // token order) are dropped first.
                let terms: Vec<String> = terms.into_iter().take(SEARCH_MAX_TERMS).collect();
                if let Some(l) = filter.limit {
                    search_take = search_take.min(l);
                }
                terms
            } else {
                Vec::new()
            };
            out.reset_boundary();
            let scan = FilterScan {
                filter,
                terms: &terms,
                now,
                limit,
                ascending,
            };
            let mut collect = Collect {
                seen: &mut seen,
                out,
            };
            let stop = self.scan_filter(
                &rtxn,
                &scan,
                &mut collect,
                budget,
                &mut examined,
                &mut more,
                light,
                &all_dfs,
                &all_terms,
            )?;
            if stop {
                break;
            }
        }
        if !count_mode {
            if sort_search && !all_terms.is_empty() {
                // NIP-50: results are ordered by search relevance (weighted
                // by each term's inverse document frequency), not by
                // created_at, and the limit is applied after that ordering.
                let weights = Self::weights_from_dfs(&all_dfs);
                out.sort_relevance(&all_terms, &weights);
                let take = search_take.min(max_limit);
                if out.len() > take {
                    more = true;
                    out.truncate_to(take);
                }
            } else if ascending {
                // NIP-01 ascending: oldest events first; on equal created_at
                // the event with the lowest id comes first.
                ScanCollector::sort_asc(out);
            } else {
                // NIP-01: newest events first; on equal created_at the event
                // with the lowest id comes first.
                ScanCollector::sort_key(out);
            }
        }
        Ok(more)
    }

    /// Returns `true` when the global collection cap was reached.
    #[allow(clippy::too_many_arguments)]
    fn scan_filter<C: ScanCollector>(
        &self,
        rtxn: &RoTxn,
        scan: &FilterScan<'_>,
        collect: &mut Collect<'_, C>,
        budget: usize,
        examined: &mut usize,
        more: &mut bool,
        light: bool,
        all_dfs: &[u64],
        all_terms: &[String],
    ) -> Result<bool> {
        let FilterScan {
            filter,
            terms,
            now,
            limit,
            ascending,
        } = *scan;
        let seen = &mut *collect.seen;
        let out = &mut *collect.out;
        let ctx = ScanContext {
            events: self.events,
            event_meta: self.event_meta,
            deleted: self.deleted,
            banned: self.banned,
            expiry_enabled: self
                .expiry_enabled
                .load(std::sync::atomic::Ordering::Relaxed),
            rtxn,
        };
        let mut consider = |id: &[u8]| -> Result<bool> {
            consider_event(
                &ctx, id, filter, terms, now, seen, out, limit, budget, examined, light,
            )
        };

        if let Some(ids) = &filter.ids {
            // Every id is checked (each maps to at most one event): the
            // collection limit only bounds the results, not the number of
            // ids examined, so `{"ids": [A, B], "limit": 1}` must still find
            // B when A does not exist. The work budget bounds the walk.
            for id in ids {
                if let Ok(id) = hex::decode(id) {
                    if id.len() == ID_LEN {
                        if !consider(&id)? {
                            *more = true;
                            return Ok(false);
                        }
                    } else if !id.is_empty() {
                        // NIP-01: `ids` entries may be event-id *prefixes*.
                        // Walk the events range of that prefix (bounded by
                        // the work budget); the collection limit and the
                        // final created_at sort apply as usual.
                        let start = prefix_start(&id);
                        let end = prefix_end(&id);
                        if !self.walk_events_prefix(rtxn, &start, &end, &mut consider, more)? {
                            return Ok(false);
                        }
                    }
                }
            }
            return Ok(out.full());
        }

        if filter.has_search() && !terms.is_empty() {
            // With the word index available, scan the index of every term
            // and union the candidates in one merged walk (a note matching
            // only the second term must still be found, and the limit
            // applies to the union). Without the index, fall through to the
            // time-range scans, where the terms are checked per event.
            // `terms` may be empty when the query consisted only of
            // `key:value` extensions (NIP-50: unsupported extensions are
            // ignored); such a query matches everything, like an empty
            // search would.
            if let Some(by_word) = self.by_word {
                // A common term (df reaching the sampling cap) is dropped
                // from the index walk: its range is the flood source that
                // turns a one-word query into a seconds-long scan. The
                // term stays in the per-event matching, so an event that
                // contains it AND a rarer query term is still found via
                // the rarer term's range; an event matching only common
                // terms is not a candidate (such terms weigh ~0 in the
                // relevance order anyway).
                // The per-filter terms are normally a subset of `all_terms`
                // (the query-wide set), so their document frequencies come
                // from the shared count instead of a second index walk. A
                // pathological REQ with more than SEARCH_MAX_TERMS terms in
                // total falls back to df=0 (no common-term exclusion: the
                // walk widens but stays bounded by the work budget).
                let dfs: Vec<u64> = terms
                    .iter()
                    .map(|t| {
                        all_terms
                            .iter()
                            .position(|a| a == t)
                            .map(|i| all_dfs[i])
                            .unwrap_or(0)
                    })
                    .collect();
                let mut ranges: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(terms.len());
                for (word, df) in terms.iter().zip(dfs.iter()) {
                    // A common term (df reaching the sampling cap) is
                    // dropped from the walk. A term absent from the index
                    // (df == 0, e.g. numeric-only words) has an empty
                    // range, which walk_merged skips harmlessly — it must
                    // stay in the list, because `df == 0` also results
                    // from the query-wide term cap for multi-filter REQs,
                    // where the term *is* indexed and must still be
                    // walked.
                    if *df >= DF_SAMPLE || word.len() > WORD_INDEX_MAX {
                        continue;
                    }
                    let start = {
                        let mut v = word.as_bytes().to_vec();
                        v.push(0x00);
                        v
                    };
                    let end = {
                        let mut v = word.as_bytes().to_vec();
                        v.push(0x01);
                        v
                    };
                    ranges.push((start, end));
                }
                // Every term was common: the index walk has no range to
                // scan. Falling through to the time-range scan below
                // (which checks the terms per event) keeps the query
                // correct — a relay big enough for "nostr" to reach the
                // sampling cap must still find notes containing it.
                if !ranges.is_empty() {
                    if !self.walk_merged(rtxn, by_word, &ranges, ascending, &mut consider, more)? {
                        return Ok(false);
                    }
                    return Ok(out.full());
                }
            }
        }

        let since = filter.since.unwrap_or(0);
        let until = filter.until.unwrap_or(u64::MAX);

        if let Some(authors) = &filter.authors {
            let mut ranges: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(authors.len());
            for author in authors {
                let Ok(pk) = hex::decode(author) else {
                    continue;
                };
                if pk.len() != ID_LEN {
                    continue;
                }
                ranges.push((
                    pubkey_key(&pk, since, &[0u8; ID_LEN]),
                    pubkey_key(&pk, until, &[0xffu8; ID_LEN]),
                ));
            }
            if !ranges.is_empty()
                && !self.walk_merged(
                    rtxn,
                    self.by_pubkey,
                    &ranges,
                    ascending,
                    &mut consider,
                    more,
                )?
            {
                return Ok(false);
            }
            return Ok(out.full());
        }

        // Only `#`-prefixed keys are tag constraints (NIP-01); an unknown
        // non-`#` key (e.g. a typo like `"kind"`) is ignored by the scan
        // just like it is by the final in-memory match, so it cannot turn
        // the filter into an impossible query.
        if let Some((name, values)) = filter.tags.iter().find(|(n, _)| n.starts_with('#')) {
            let tag_name = name.strip_prefix('#').unwrap_or(name);
            if tag_name.len() == 1 {
                let name_byte = tag_name.as_bytes()[0];
                let mut ranges: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
                for value in crate::filter::tag_values(values) {
                    // A value beyond the index-key limit was never indexed
                    // (put skips it): a range boundary past LMDB's key
                    // limit would error the whole query.
                    if value.len() > TAG_INDEX_VALUE_MAX {
                        continue;
                    }
                    ranges.push(tag_range(name_byte, value.as_bytes(), since, until));
                }
                if !ranges.is_empty()
                    && !self.walk_merged(
                        rtxn,
                        self.by_tag,
                        &ranges,
                        ascending,
                        &mut consider,
                        more,
                    )?
                {
                    return Ok(false);
                }
                // A tag attribute with no string values (e.g. a numeric
                // `{"#a": 123}`) matches nothing: the final in-memory
                // `Filter::matches` requires every tag attribute to match,
                // so an empty value set yields zero results — consistent
                // with this index path.
                return Ok(out.full());
            }
            // Multi-letter tag names are not indexed (NIP-01 only requires
            // single-letter tags to be indexed): fall through to the
            // time-range scan, where the final in-memory match enforces the
            // tag filter.
        }

        if let Some(kinds) = &filter.kinds {
            let mut ranges: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(kinds.len());
            for kind in kinds {
                ranges.push((
                    kind_key(*kind, since, &[0u8; ID_LEN]),
                    kind_key(*kind, until, &[0xffu8; ID_LEN]),
                ));
            }
            if !ranges.is_empty()
                && !self.walk_merged(rtxn, self.by_kind, &ranges, ascending, &mut consider, more)?
            {
                return Ok(false);
            }
            return Ok(out.full());
        }

        let start = created_key(since, &[0u8; ID_LEN]);
        let end = created_key(until, &[0xffu8; ID_LEN]);
        // A per-filter limit/budget stop only ends this filter's walk, like
        // every other index path: the remaining filters still contribute
        // results. (Returning `true` here used to drop the rest of a
        // multi-filter REQ whenever the first filter hit its limit, e.g. a
        // `{"limit": 0}` filter killed the whole query.)
        if !self.walk_created_range(
            rtxn,
            self.by_created,
            &start,
            &end,
            ascending,
            &mut consider,
            more,
        )? {
            return Ok(false);
        }
        Ok(out.full())
    }

    #[allow(clippy::too_many_arguments)]
    fn walk_created_range(
        &self,
        rtxn: &RoTxn,
        db: Database<Bytes, Bytes>,
        start: &[u8],
        end: &[u8],
        ascending: bool,
        mut consider: impl FnMut(&[u8]) -> Result<bool>,
        more: &mut bool,
    ) -> Result<bool> {
        let range = (
            std::ops::Bound::Included(start),
            std::ops::Bound::Excluded(end),
        );
        type RangeIter<'a> = Box<dyn Iterator<Item = heed::Result<(&'a [u8], &'a [u8])>> + 'a>;
        let iter: RangeIter<'_> = if ascending {
            Box::new(db.range(rtxn, &range)?)
        } else {
            Box::new(db.rev_range(rtxn, &range)?)
        };
        for item in iter {
            let (key, _) = item?;
            let id = &key[key.len() - ID_LEN..];
            if !consider(id)? {
                *more = true;
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Walks the `events` database over the id range `[start, end]` (an
    /// id-prefix range from NIP-01 `ids` filters), handing every full id key
    /// to `consider`. The range is inclusive on both ends so the maximum id
    /// with the prefix is covered.
    fn walk_events_prefix(
        &self,
        rtxn: &RoTxn,
        start: &[u8],
        end: &[u8],
        mut consider: impl FnMut(&[u8]) -> Result<bool>,
        more: &mut bool,
    ) -> Result<bool> {
        let range = (
            std::ops::Bound::Included(start),
            std::ops::Bound::Included(end),
        );
        let iter = self.events.range(rtxn, &range)?;
        for item in iter {
            let (key, _) = item?;
            if !consider(key)? {
                *more = true;
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Walks several index ranges in parallel, handing ids to `consider` in
    /// global `(created_at, id)` descending order. A per-filter limit thus
    /// applies to the union of every range (NIP-01: "the last n events
    /// ordered by the created_at"): `{"authors": [A, B], "limit": 100}`
    /// returns the 100 newest events by either author instead of filling
    /// the limit from the first author only.
    fn walk_merged(
        &self,
        rtxn: &RoTxn,
        db: Database<Bytes, Bytes>,
        ranges: &[(Vec<u8>, Vec<u8>)],
        ascending: bool,
        consider: &mut impl FnMut(&[u8]) -> Result<bool>,
        more: &mut bool,
    ) -> Result<bool> {
        type RevIter<'a> = Box<dyn Iterator<Item = heed::Result<(&'a [u8], &'a [u8])>> + 'a>;
        struct Head<'a> {
            iter: RevIter<'a>,
            /// The next key with its parsed `(created_at, id)` tail: the
            /// tail is parsed once per refill instead of once per head per
            /// iteration.
            next_key: Option<(Vec<u8>, [u8; 8], [u8; 32])>,
        }
        let mut heads: Vec<Head<'_>> = Vec::with_capacity(ranges.len());
        for (start, end) in ranges {
            let range = (
                std::ops::Bound::Included(start.as_slice()),
                std::ops::Bound::Excluded(end.as_slice()),
            );
            heads.push(Head {
                iter: if ascending {
                    Box::new(db.range(rtxn, &range)?)
                } else {
                    Box::new(db.rev_range(rtxn, &range)?)
                },
                next_key: None,
            });
        }
        let mut last_emitted: Option<([u8; 8], [u8; 32])> = None;
        loop {
            // The index keys are `(prefix..., created_at, id)`, so the
            // newest head is the one with the largest (created_at, id)
            // pair, not the largest full key.
            let mut best: Option<(usize, [u8; 8], [u8; 32])> = None;
            for (i, head) in heads.iter_mut().enumerate() {
                if head.next_key.is_none() {
                    match head.iter.next() {
                        Some(Ok((key, _))) => {
                            let (created, id) =
                                index_tail(key).map_err(crate::error::Error::Other)?;
                            head.next_key = Some((key.to_vec(), created, id));
                        }
                        Some(Err(e)) => return Err(e.into()),
                        None => {}
                    }
                }
                if let Some((_, created, id)) = &head.next_key {
                    let better = if ascending {
                        best.as_ref()
                            .is_none_or(|(_, bc, bi)| (*created, *id) < (*bc, *bi))
                    } else {
                        best.as_ref()
                            .is_none_or(|(_, bc, bi)| (*created, *id) > (*bc, *bi))
                    };
                    if better {
                        best = Some((i, *created, *id));
                    }
                }
            }
            let Some((i, created, id)) = best else {
                return Ok(true);
            };
            let (key, _, _) = heads[i].next_key.as_ref().expect("head was picked");
            // The same event can appear in several ranges (e.g. a search
            // term union); the merged walk emits in global order, so a
            // repeat of the immediately previous id is the same event —
            // skip the second emission instead of handing it to
            // `consider` again (which would re-parse and re-check it).
            if let Some((last_created, last_id)) = last_emitted
                && last_created == created
                && last_id == id
            {
                heads[i].next_key = None;
                continue;
            }
            last_emitted = Some((created, id));
            let id = &key[key.len() - ID_LEN..];
            if !consider(id)? {
                *more = true;
                return Ok(false);
            }
            heads[i].next_key = None;
        }
    }
}

/// The smallest 32-byte id sharing `prefix` (for NIP-01 id-prefix ranges).
fn prefix_start(prefix: &[u8]) -> Vec<u8> {
    let mut v = prefix.to_vec();
    v.resize(ID_LEN, 0);
    v
}

/// The largest 32-byte id sharing `prefix`.
fn prefix_end(prefix: &[u8]) -> Vec<u8> {
    let mut v = prefix.to_vec();
    v.resize(ID_LEN, 0xff);
    v
}

/// A lightweight deserialization of a stored event for the negentropy
/// path: the content (the dominant field, up to 64 KiB) and the
/// signature are skipped entirely, leaving the fields the filter
/// matching needs.
#[derive(serde::Deserialize)]
struct NegLight {
    id: String,
    pubkey: String,
    created_at: u64,
    kind: u64,
    tags: Vec<Vec<String>>,
}

impl crate::filter::EventFields for NegLight {
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
        ""
    }
}

#[allow(clippy::too_many_arguments)]
fn consider_event<C: ScanCollector>(
    ctx: &ScanContext<'_>,
    id: &[u8],
    filter: &Filter,
    terms: &[String],
    now: u64,
    seen: &mut HashSet<Vec<u8>>,
    out: &mut C,
    limit: usize,
    budget: usize,
    examined: &mut usize,
    light: bool,
) -> Result<bool> {
    if out.full() {
        // The collection cap is reached: stop the scan (and any remaining
        // ranges of this filter) instead of walking them to completion.
        return Ok(false);
    }
    // Work budget: give up after examining `budget` candidates so a
    // filter matching nothing cannot walk an entire index range and stall
    // the reader thread (which also serves WebSocket REQ/COUNT/NEG).
    *examined += 1;
    if *examined > budget {
        return Ok(false);
    }
    if seen.contains(id) {
        return Ok(true);
    }
    let Some(raw) = ctx.events.get(ctx.rtxn, id)? else {
        return Ok(true);
    };
    let id = id.try_into().unwrap_or([0u8; 32]);
    // Header-first rejection: the metadata index carries the kind,
    // created_at, pubkey and expiration, so candidates failing those
    // checks are dropped before the full JSON is deserialized. A missing
    // header (a legacy event, or the index still being rebuilt) falls
    // through to the full parse.
    if let Some(meta) = ctx.event_meta
        && let Some(header) = meta.get(ctx.rtxn, &id)?
        && let Some((kind, created, _pubkey, exp)) = crate::db::store::decode_meta(header)
    {
        if let Some(kinds) = &filter.kinds
            && !kinds.contains(&kind)
        {
            return Ok(true);
        }
        if let Some(since) = filter.since
            && created < since
        {
            return Ok(true);
        }
        if let Some(until) = filter.until
            && created > until
        {
            return Ok(true);
        }
        if ctx.expiry_enabled && exp != 0 && exp < now {
            return Ok(true);
        }
    }
    if light {
        // The negentropy path deserializes the candidate without its
        // content (the dominant field) and its signature.
        let Ok(event) = serde_json::from_slice::<NegLight>(raw) else {
            return Ok(true);
        };
        if !is_deliverable(ctx, &event, filter, terms, now)? {
            return Ok(true);
        }
        if out.push_light(&event, id, limit) {
            seen.insert(id.to_vec());
        }
        return Ok(true);
    }
    let Ok(event) = serde_json::from_slice::<Event>(raw) else {
        return Ok(true);
    };
    if !is_deliverable(ctx, &event, filter, terms, now)? {
        return Ok(true);
    }
    // Only record the event as seen when it was actually collected: an event
    // that hit this filter's limit (push failed) must still be available to
    // a later filter of the same REQ, e.g. `[{"limit":0},{"kinds":[1]}]`.
    if out.push(event, id, limit) {
        seen.insert(id.to_vec());
        Ok(true)
    } else {
        Ok(false)
    }
}

fn is_deliverable<E: crate::filter::EventFields>(
    ctx: &ScanContext<'_>,
    event: &E,
    filter: &Filter,
    terms: &[String],
    now: u64,
) -> Result<bool> {
    let Some(id) = hex::decode(event.id()).ok() else {
        return Ok(false);
    };
    let Some(id): Option<[u8; 32]> = id.try_into().ok() else {
        return Ok(false);
    };
    if ctx.deleted.get(ctx.rtxn, &id)?.is_some() {
        return Ok(false);
    }
    if ctx.banned.get(ctx.rtxn, &id)?.is_some() {
        return Ok(false);
    }
    if ctx.expiry_enabled
        && let Some(exp) = event
            .tags()
            .iter()
            .find(|t| t.len() >= 2 && t[0] == crate::nips::nip40::EXPIRATION_TAG)
            .and_then(|t| t[1].parse::<u64>().ok())
        && exp < now
    {
        return Ok(false);
    }
    if !terms.is_empty() {
        // NIP-50: an event matches when at least one query term is present
        // as a whole word in its content; the relevance ordering ranks
        // events matching every term first. Whole-word matching keeps the
        // index walk, the non-indexed fallback and the live delivery
        // consistent (see `nip50::matches_terms`).
        if !crate::nips::nip50::matches_terms(event.content(), terms) {
            return Ok(false);
        }
    }
    Ok(filter.matches(event))
}

#[cfg(test)]
mod tests {
    use super::{index_tail, score};
    use crate::event::Event;

    #[test]
    fn index_tail_parses_and_rejects_corrupt_keys() {
        let mut key = vec![0xAAu8; 16]; // prefix
        key.extend_from_slice(&1u64.to_be_bytes());
        key.extend_from_slice(&[0xBBu8; 32]);
        let (created, id) = index_tail(&key).expect("a padded key parses");
        assert_eq!(created, 1u64.to_be_bytes());
        assert_eq!(id, [0xBBu8; 32]);
        // A bare 40-byte tail (no prefix) parses too.
        let bare: Vec<u8> = [2u64.to_be_bytes().as_slice(), &[0xCCu8; 32]].concat();
        assert_eq!(index_tail(&bare).unwrap().0, 2u64.to_be_bytes());
        // A truncated key is corruption: the scan must fail loudly, not
        // panic on the slice.
        assert!(index_tail(&bare[..39]).is_err());
        assert!(index_tail(&[]).is_err());
    }

    fn ev(content: &str, created: u64) -> Event {
        Event {
            id: "a".repeat(64),
            pubkey: "b".repeat(64),
            created_at: created,
            kind: 1,
            tags: vec![],
            content: content.into(),
            sig: "c".repeat(128),
        }
    }

    #[test]
    fn item_collector_boundary_giftwrap_groupmeta_and_sorts() {
        use super::{ItemCollector, NegLight, ScanCollector};
        use crate::nips::nip29::{GROUP_META, GROUP_PINS};
        use crate::nips::nip62::GIFT_WRAP_KIND;
        let mut c = ItemCollector::new(2);
        assert_eq!(c.cap(), 2);
        assert!(!c.full());
        // The first push at the limit sets the boundary timestamp.
        let e = ev("a", 1000);
        assert!(c.push(e.clone(), [0xAAu8; 32], 2));
        let e = ev("b", 999);
        assert!(c.push(e.clone(), [0xBBu8; 32], 2));
        assert_eq!(c.items[0].created, 1000);
        assert_eq!(c.items[0].id, [0xAAu8; 32]);
        assert!(!c.push(ev("c", 998), [0xCCu8; 32], 2), "limit reached");
        // Events at the boundary timestamp are still collected; older ones
        // are rejected.
        let e = ev("d", 999);
        assert!(c.push(e.clone(), [0xDDu8; 32], 2), "boundary tie collected");
        assert_eq!(c.items.len(), 3);
        // The light path shares the boundary semantics.
        let light = NegLight {
            id: "a".repeat(64),
            pubkey: "b".repeat(64),
            created_at: 999,
            kind: 1,
            tags: vec![],
        };
        assert!(
            c.push_light(&light, [0xEEu8; 32], 2),
            "light boundary tie collected"
        );
        let light2 = NegLight {
            created_at: 998,
            ..light
        };
        assert!(
            !c.push_light(&light2, [0xFFu8; 32], 2),
            "light limit reached"
        );
        c.reset_boundary();
        // A fresh collector (its own limit) for the per-kind tagging checks.
        let mut c = ItemCollector::new(8);
        // Gift wraps record their p-tag recipients; group metadata records
        // the meta flag; NIP-78 kinds record app_specific.
        let mut wrap = ev("w", 1);
        wrap.kind = GIFT_WRAP_KIND;
        wrap.tags = vec![
            vec!["p".into(), "aa".repeat(32)],
            vec!["p".into(), "bb".repeat(32)],
        ];
        assert!(c.push(wrap, [0x11u8; 32], 8));
        assert_eq!(
            c.items[0].wrap_recipients,
            Some(vec!["aa".repeat(32), "bb".repeat(32)])
        );
        let mut meta = ev("m", 1);
        meta.kind = GROUP_META;
        meta.tags = vec![vec!["d".into(), "g".into()]];
        assert!(c.push(meta, [0x22u8; 32], 8));
        assert_eq!(c.items[1].gid.as_deref(), Some("g"));
        assert!(c.items[1].meta);
        let mut pin = ev("p", 1);
        pin.kind = GROUP_PINS;
        pin.tags = vec![vec!["d".into(), "g".into()]];
        assert!(c.push(pin, [0x33u8; 32], 8));
        assert!(c.items[2].meta);
        let mut app = ev("x", 1);
        app.kind = crate::nips::nip78::APP_SPECIFIC_KIND;
        assert!(c.push(app, [0x44u8; 32], 8));
        assert!(c.items[3].app_specific);
        // Ordering helpers: newest-first by created then id, ascending by
        // created, relevance as a no-op and truncation to a count.
        c.sort_key();
        assert_eq!(c.items[0].created, 1);
        c.sort_asc();
        assert_eq!(c.items[0].created, 1);
        c.sort_relevance(&[], &[]);
        c.truncate_to(3);
        assert_eq!(c.items.len(), 3);
    }

    #[test]
    fn relevance_score_counts_whole_words_only() {
        let terms = vec!["ru".to_string(), "rust".to_string()];
        let weights = vec![1.0, 1.0];
        // "rust" is a whole word; "ru" is only a substring of "rust" and
        // must contribute nothing (matching itself is whole-word, so the
        // ranking must agree).
        assert_eq!(score(&ev("I like rust", 1), &terms, &weights), 1.0);
        // A content that actually contains "ru" as a word scores it.
        assert_eq!(score(&ev("ru matters", 1), &terms, &weights), 1.0);
        assert_eq!(score(&ev("ru and rust both", 1), &terms, &weights), 2.0);
    }
}
