//! WebSocket connection handling: the per-connection [`Conn`]
//! state, the connection loop and the live fan-out. The protocol
//! message handlers (REQ/EVENT/AUTH/COUNT/NEG) live in [`handler`].

mod handler;
mod negentropy;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};

use crate::event::Event;
use crate::filter::Filter;
use crate::nips::{nip29, nip42};
use crate::relay::Relay;
use crate::stats::Stats;

/// Secondary bound on the number of queued messages (a long tail of small
/// messages must not outgrow the VecDeque either).
const OUT_QUEUE_LIMIT: usize = 4096;
/// Events queued on a connection before they are accepted as one database
/// batch (the batch shares a single write commit).
pub(crate) const EVENT_BATCH: usize = 64;

/// Relay-wide byte budget for materialized REQ responses. The per-response
/// (`limits.max_req_response_bytes`) and per-connection (`pending_reqs`,
/// `max_out_queue_bytes`) caps alone still allow
/// `max_connections × MAX_PENDING_REQS × max_req_response_bytes` of pinned
/// memory (hundreds of GiB with the documented defaults); every response
/// reserves its materialized size here before it is queued for the pump,
/// and the reservation is released when the response completes, is
/// replaced/closed, or its connection drops (including a panic, through
/// [`PendingReq`]'s `Drop`). Responses that do not fit fail fast with a
/// retryable CLOSED instead of pinning the events.
pub(crate) struct PendingResponseBudget {
    /// Bytes currently reserved across the relay's connections.
    used: std::sync::atomic::AtomicU64,
}

impl PendingResponseBudget {
    fn new() -> Self {
        PendingResponseBudget {
            used: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// The bytes currently reserved (tests and diagnostics).
    #[cfg(test)]
    pub(crate) fn used(&self) -> u64 {
        self.used.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Reserves `bytes` against `limit` (`0` = unlimited), returning the
    /// amount actually reserved (`Some(0)` when nothing had to be
    /// accounted, e.g. an empty response or an unlimited budget). `None`
    /// means the reservation would exceed the relay-wide budget: the
    /// caller must refuse the response instead of materializing it. The
    /// caller stores the returned amount and passes it to [`Self::release`]
    /// on drop, so an unaccounted reservation is never subtracted from
    /// other connections' bytes.
    pub(crate) fn try_reserve(&self, bytes: u64, limit: u64) -> Option<u64> {
        if bytes == 0 || limit == 0 {
            return Some(0);
        }
        let mut current = self.used.load(std::sync::atomic::Ordering::Relaxed);
        loop {
            if current.saturating_add(bytes) > limit {
                return None;
            }
            match self.used.compare_exchange_weak(
                current,
                current + bytes,
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
            ) {
                Ok(_) => return Some(bytes),
                Err(actual) => current = actual,
            }
        }
    }

    /// Releases a reservation. Saturating, so a spurious extra release
    /// cannot wrap the counter and disable the budget.
    pub(crate) fn release(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        let _ = self.used.fetch_update(
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
            |current| Some(current.saturating_sub(bytes)),
        );
    }
}

/// Relay-wide pending-response budget as a multiple of the per-response
/// byte budget. The default (32 MiB × 16 = 512 MiB) bounds the relay-wide
/// pinned-response memory while leaving room for many concurrent
/// full-size responses; the previous per-connection caps had no global
/// bound at all.
pub(crate) const PENDING_RESPONSE_BUDGET_FACTOR: u64 = 16;

/// Sizes the relay-wide budget from `limits.max_req_response_bytes`; when
/// the per-response budget is disabled (`0` = unlimited) the documented
/// default is used, so the relay-wide bound still exists.
pub(crate) fn pending_response_budget_bytes(per_response: u64) -> u64 {
    /// The documented default of `limits.max_req_response_bytes`.
    const DEFAULT_PER_RESPONSE: u64 = 32 * 1024 * 1024;
    let per_response = if per_response == 0 {
        DEFAULT_PER_RESPONSE
    } else {
        per_response
    };
    per_response.saturating_mul(PENDING_RESPONSE_BUDGET_FACTOR)
}

/// Relay-wide NEG budget as a multiple of the per-query item cap, mirroring
/// [`PENDING_RESPONSE_BUDGET_FACTOR`]. The per-connection NEG caps alone
/// allow `max_connections × 2 × max_neg_items` held items (tens of GB with
/// the documented defaults); the default (100k items × 16 ≈ 122 MiB) bounds
/// the relay-wide held set while leaving room for many concurrent
/// full-size syncs.
pub(crate) const NEG_BUDGET_FACTOR: u64 = 16;

/// The estimated in-memory size of one held negentropy item: twice the
/// `(created_at, id)` tuple (40 bytes) because the collecting `Vec` may
/// hold up to twice its length in capacity. The deliberate overestimate is
/// what [`neg_budget_bytes`] charges per held item.
pub(crate) const NEG_ITEM_BYTES: u64 = std::mem::size_of::<crate::nips::nip77::Item>() as u64 * 2;

/// Sizes the relay-wide NEG budget from `limits.max_neg_items`; when the
/// per-query cap is `0` (no processable records) the documented default is
/// used, so the relay-wide bound still exists instead of `0` disabling the
/// budget entirely (`try_reserve` treats a `0` limit as unlimited).
pub(crate) fn neg_budget_bytes(per_query: usize) -> u64 {
    /// The documented default of `limits.max_neg_items`.
    const DEFAULT_MAX_NEG_ITEMS: u64 = 100_000;
    let per_query = if per_query == 0 {
        DEFAULT_MAX_NEG_ITEMS
    } else {
        per_query as u64
    };
    per_query
        .saturating_mul(NEG_ITEM_BYTES)
        .saturating_mul(NEG_BUDGET_FACTOR)
}

/// A per-relay budget registry, keyed by the relay allocation. `Arc::as_ptr`
/// identifies the relay (every `Conn` holds a clone of the same allocation),
/// so several relays in one process (tests) do not share a budget. The
/// registry holds a `Weak` reference: once every connection (and
/// reservation) of a relay is gone the counter is freed, so a later relay
/// allocated at the same address gets a fresh budget instead of a stale
/// counter, and the registry cannot keep budgets alive.
type BudgetRegistry =
    std::sync::OnceLock<std::sync::Mutex<HashMap<usize, std::sync::Weak<PendingResponseBudget>>>>;

fn relay_budget(registry: &BudgetRegistry, relay: &Arc<Relay>) -> Arc<PendingResponseBudget> {
    let key = Arc::as_ptr(relay) as usize;
    let mut budgets = registry
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if let Some(existing) = budgets.get(&key).and_then(std::sync::Weak::upgrade) {
        return existing;
    }
    let budget = Arc::new(PendingResponseBudget::new());
    budgets.insert(key, Arc::downgrade(&budget));
    budget
}

/// The pending-response budget of one relay (see [`relay_budget`] for the
/// registry rationale).
fn pending_response_budget(relay: &Arc<Relay>) -> Arc<PendingResponseBudget> {
    static BUDGETS: BudgetRegistry = std::sync::OnceLock::new();
    relay_budget(&BUDGETS, relay)
}

/// The relay-wide NEG budget of one relay (see [`relay_budget`] for the
/// registry rationale).
fn neg_budget(relay: &Arc<Relay>) -> Arc<PendingResponseBudget> {
    static BUDGETS: BudgetRegistry = std::sync::OnceLock::new();
    relay_budget(&BUDGETS, relay)
}

/// Relay-wide NEG CPU budget as a multiple of the per-query item cap,
/// mirroring [`NEG_BUDGET_FACTOR`]: one NEG-OPEN spends its per-query item
/// cap (the scan's worst case) and every NEG-MSG spends its held item
/// count (the bisection's worst case), so the whole relay processes at
/// most `max_neg_items × NEG_CPU_BUDGET_FACTOR` fingerprint units per
/// second. Without it the per-connection caps (`MAX_NEG_OPENS` ×
/// `MAX_NEG_MSG_ROUNDS` each) multiplied by `max_connections` let a
/// coordinated flood monopolize the CPU with reconciliation rounds.
pub(crate) const NEG_CPU_BUDGET_FACTOR: u64 = 16;

/// Sizes the relay-wide NEG CPU budget from `limits.max_neg_items`; when
/// the per-query cap is `0` the documented default is used, so the
/// relay-wide bound still exists instead of `0` disabling the budget.
pub(crate) fn neg_cpu_budget_units(per_query: usize) -> u64 {
    /// The documented default of `limits.max_neg_items`.
    const DEFAULT_MAX_NEG_ITEMS: u64 = 100_000;
    let per_query = if per_query == 0 {
        DEFAULT_MAX_NEG_ITEMS
    } else {
        per_query as u64
    };
    per_query.saturating_mul(NEG_CPU_BUDGET_FACTOR)
}

/// A relay-wide per-second work budget for NEG reconciliation. The
/// per-connection round and open budgets alone still allow
/// `max_connections × MAX_NEG_OPENS × MAX_NEG_MSG_ROUNDS` rounds over the
/// item budget's held sets; this shared counter caps the aggregate.
///
/// The window is packed into one `AtomicU64` (`unix second << 32 | units
/// used`) so the rollover is race-free without a lock: concurrent charges
/// in the same second add up, and the first charge of a new second (or
/// the first charge after the configured limit shrank below what was
/// already spent) resets the window.
pub(crate) struct NegCpuBudget {
    used: std::sync::atomic::AtomicU64,
    /// Test-only: pins the window so a test's charges cannot be reset by a
    /// wall-clock second tick (production always follows the clock).
    #[cfg(test)]
    frozen: std::sync::atomic::AtomicBool,
}

impl NegCpuBudget {
    fn new() -> Self {
        NegCpuBudget {
            used: std::sync::atomic::AtomicU64::new(0),
            #[cfg(test)]
            frozen: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// The current window's second: the wall clock, or the last charged
    /// second while frozen (test-only).
    fn window_second(&self) -> u32 {
        #[cfg(test)]
        if self.frozen.load(std::sync::atomic::Ordering::Relaxed) {
            return (self.used.load(std::sync::atomic::Ordering::Relaxed) >> 32) as u32;
        }
        (crate::util::unix_now() & 0xffff_ffff) as u32
    }

    /// Charges `units` against the per-second `limit` (`0` = unlimited).
    /// Returns `false` when the window is exhausted, so the caller refuses
    /// the work with a retryable NEG-ERR. A charge larger than the whole
    /// budget is refused without poisoning the fresh window for everyone
    /// else.
    fn try_charge(&self, units: u64, limit: u64) -> bool {
        if units == 0 {
            return true;
        }
        let limit = if limit == 0 {
            u64::from(u32::MAX)
        } else {
            limit.min(u64::from(u32::MAX))
        };
        let now = self.window_second();
        let mut current = self.used.load(std::sync::atomic::Ordering::Relaxed);
        loop {
            let second = (current >> 32) as u32;
            let used = current & 0xffff_ffff;
            // A new second, or a configured limit that shrank below what
            // this window already spent (a SIGHUP reload): opening a fresh
            // window would otherwise refuse every charge for the rest of
            // the second.
            if second != now || used > limit {
                if units > limit {
                    return false;
                }
                let next = (u64::from(now) << 32) | units;
                match self.used.compare_exchange_weak(
                    current,
                    next,
                    std::sync::atomic::Ordering::Relaxed,
                    std::sync::atomic::Ordering::Relaxed,
                ) {
                    Ok(_) => return true,
                    Err(actual) => current = actual,
                }
                continue;
            }
            if used + units > limit {
                return false;
            }
            let next = (u64::from(now) << 32) | (used + units);
            match self.used.compare_exchange_weak(
                current,
                next,
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    /// Test-only: disables the second rollover so the accounting is
    /// independent of the wall clock.
    #[cfg(test)]
    fn freeze(&self) {
        self.frozen
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// The relay-wide NEG CPU budget of one relay (see [`relay_budget`] for
/// the registry rationale).
fn neg_cpu_budget(relay: &Arc<Relay>) -> Arc<NegCpuBudget> {
    type CpuBudgetRegistry =
        std::sync::OnceLock<std::sync::Mutex<HashMap<usize, std::sync::Weak<NegCpuBudget>>>>;
    fn budget_for(registry: &CpuBudgetRegistry, relay: &Arc<Relay>) -> Arc<NegCpuBudget> {
        let key = Arc::as_ptr(relay) as usize;
        let mut budgets = registry
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if let Some(existing) = budgets.get(&key).and_then(std::sync::Weak::upgrade) {
            return existing;
        }
        let budget = Arc::new(NegCpuBudget::new());
        budgets.insert(key, Arc::downgrade(&budget));
        budget
    }
    static BUDGETS: CpuBudgetRegistry = std::sync::OnceLock::new();
    budget_for(&BUDGETS, relay)
}

/// A REQ response waiting to be pumped to the socket in bounded chunks:
/// the scan result is held here and moved into the capped outgoing queue
/// as the socket drains, instead of being queued all at once (which could
/// pin hundreds of MiB for a slow reader).
pub(crate) struct PendingReq {
    pub(crate) sub_id: String,
    pub(crate) events: std::collections::VecDeque<Event>,
    pub(crate) eose_hint: bool,
    pub(crate) truncated_or_more: bool,
    /// NIP-67 `"auth"` hint: more stored events match the filters if the
    /// client performs AUTH; the challenge is queued ahead of the EOSE.
    pub(crate) auth_hint: bool,
    /// Serialized bytes of the EVENT messages queued so far (against
    /// `limits.max_req_response_bytes`).
    pub(crate) sent_bytes: u64,
    /// Live EVENT messages that matched this subscription while its stored
    /// response was still pumping. NIP-01 defines EOSE as the boundary
    /// between stored and real-time events, so these wait here until the
    /// stored events and the EOSE have been queued.
    pub(crate) live: std::collections::VecDeque<String>,
    /// Serialized bytes held in `live`, against the outgoing byte cap.
    pub(crate) live_bytes: usize,
    /// Whether the EOSE (and any AUTH challenge before it) has been queued;
    /// afterwards the pump only drains `live`.
    pub(crate) eose_sent: bool,
    /// The relay-wide budget this response's materialized bytes were
    /// reserved against (`None` when no reservation was taken, e.g. test
    /// fixtures).
    pub(crate) budget: Option<Arc<PendingResponseBudget>>,
    /// The bytes reserved in `budget` for `events`; released on drop so
    /// every path (pump completion, live overflow, CLOSE/replacement,
    /// connection drop or panic) unaccounts exactly once.
    pub(crate) reserved: u64,
}

impl Drop for PendingReq {
    fn drop(&mut self) {
        if let Some(budget) = &self.budget {
            budget.release(self.reserved);
        }
    }
}

/// Upper bound on queued REQ responses per connection: beyond this the
/// oldest pending response is cut off (its EOSE is sent immediately) so a
/// client flooding REQs while reading slowly cannot pile up unbounded
/// scan results.
const MAX_PENDING_REQS: usize = 4;

/// One queued outgoing frame. EVENT frames carry a fingerprint of their
/// subscription so a re-REQ (which replaces the subscription, NIP-01) can
/// drop the old response's queued events before they reach the wire.
pub(crate) struct OutFrame {
    pub(crate) message: Message,
    event_sub: Option<u64>,
}

/// A stable-enough fingerprint of a subscription id: only equality between
/// ids of the same connection matters, so a hash collision would merely
/// drop an unrelated queued event (2^-64 chance with SipHash).
pub(crate) fn sub_fingerprint(sub_id: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    sub_id.hash(&mut hasher);
    hasher.finish()
}

pub struct Conn {
    pub(crate) relay: Arc<Relay>,
    /// The WebSocket endpoint path this connection was established on
    /// (`/`, `/inbox` or `/outbox`); drives the path-specific write policy.
    pub(crate) path: String,
    /// Outgoing messages awaiting a TCP write, drained by the connection
    /// loop after every select iteration. EVENT frames carry their
    /// subscription fingerprint so a re-REQ can purge stale queued events.
    pub(crate) outgoing: std::collections::VecDeque<OutFrame>,
    /// Bytes currently queued in `outgoing`; the byte cap decides whether a
    /// new message is queued or dropped.
    pub(crate) out_bytes: usize,
    /// Per-connection byte cap for the outgoing queue (`limits.max_out_queue_bytes`,
    /// cached once per connection; `0` = unset, in which case the safety
    /// ceiling of [`Conn::out_queue_cap`] applies instead).
    pub(crate) out_queue_bytes: usize,
    /// Byte budget for a single REQ response (`limits.max_req_response_bytes`,
    /// cached once per connection; 0 = unlimited).
    pub(crate) req_response_bytes: u64,
    /// Maximum inbound frame size (`limits.max_ws_message_bytes`, refreshed
    /// on SIGHUP like the queue budgets): an operator lowering the limit to
    /// shed oversized frames must not have to wait for every existing
    /// connection to reconnect.
    pub(crate) max_msg_size: usize,
    /// The relay-wide pending-response byte budget shared by every
    /// connection; each materialized response reserves its size against it
    /// and over-budget responses fail with a retryable CLOSED.
    pub(crate) pending_budget: Arc<PendingResponseBudget>,
    /// The relay-wide NEG item budget shared by every connection; each
    /// open NEG subscription reserves its held items against it, so the
    /// per-connection caps cannot pin GBs across many connections.
    /// Over-budget opens fail with a retryable NEG-ERR instead of pinning
    /// the items, and the reservation is released on NEG-CLOSE,
    /// replacement, connection drop or panic (RAII, like `PendingReq`).
    pub(crate) neg_budget: Arc<PendingResponseBudget>,
    /// The relay-wide NEG CPU budget shared by every connection: NEG-OPEN
    /// spends the scan's worst case and NEG-MSG spends the held item count,
    /// so a flood across many connections cannot monopolize the CPU with
    /// reconciliation rounds. Over-budget work fails with a retryable
    /// NEG-ERR (which per NIP-77 closes that subscription).
    pub(crate) neg_cpu_budget: Arc<NegCpuBudget>,
    /// REQ responses awaiting the pump: the scan results are moved into
    /// the capped outgoing queue in chunks as the socket drains.
    pub(crate) pending_reqs: std::collections::VecDeque<PendingReq>,
    /// Subscription id -> (filters, serialized filter bytes).
    subs: HashMap<String, (Vec<Filter>, usize, String)>,
    /// Bytes held by the filters of all active subscriptions.
    pub(crate) sub_bytes: usize,
    /// NIP-77 negentropy state per subscription id: the held items plus the
    /// remaining number of NEG-MSG rounds (a budget so a peer cannot drive
    /// unbounded CPU-bounded reconciliation work with tiny messages).
    neg: HashMap<String, negentropy::NegState>,
    /// Total number of negentropy items held across all open NEG-OPEN
    /// subscriptions, so that a connection cannot pin more than twice the
    /// configured per-query maximum in memory. This per-connection count is
    /// a second bound: the held items are also reserved against the
    /// relay-wide `neg_budget`.
    pub(crate) neg_total: usize,
    /// Total NEG-OPENs this connection has issued (including re-opens of
    /// closed subscriptions): caps how often the 128-round CPU budget can
    /// be renewed, independently of the per-subscription state.
    pub(crate) neg_opens_total: u32,
    pub(crate) challenge: String,
    /// Every pubkey authenticated on this connection (NIP-42: all of them
    /// are treated as authenticated).
    pub(crate) authed_pubkeys: Vec<String>,
    /// AUTH frames seen on this connection (bounded anti-bruteforce: each
    /// one costs a Schnorr verification).
    pub(crate) auth_attempts: u32,
    /// Events received but not yet accepted; flushed in batches so the
    /// database commit cost is amortized over many events.
    pub(crate) pending_events: Vec<Event>,
    /// Wire bytes of the events held in `pending_events`, so a burst of
    /// maximum-size frames cannot accumulate before the batch is flushed.
    pub(crate) pending_bytes: usize,
    /// Live-event receiver, created when the first REQ subscribes (before
    /// the query runs, so no stored event can fall into the gap between the
    /// query and the subscription) and kept for the rest of the
    /// connection's life: delivery is instead stopped by unregistering the
    /// connection from the relay's live subscription index when its last
    /// subscription closes (so idle connections are never woken by live
    /// events). A duplicate delivery of an event that is both in the query
    /// result and live is harmless (clients deduplicate by id).
    pub(crate) live: Option<tokio::sync::mpsc::Receiver<LiveBatch>>,
    /// The connection's id in the relay's live subscription index and
    /// delivery-queue map.
    pub(crate) conn_id: u64,
    /// This connection's open subscription count (REQ + negentropy),
    /// tracked so the connection guard can release `subscriptions_active`
    /// on panic as well as on the normal exit path.
    pub(crate) subscriptions_held: Arc<std::sync::atomic::AtomicUsize>,
    /// Whether this connection delivers NIP-40 expired events live. Cached
    /// from the config on connect and refreshed only after a SIGHUP
    /// reload (see `config_version`), so the per-batch live path avoids
    /// the shared config lock.
    pub(crate) expiry_enabled: bool,
    /// The relay's `config_version` when `expiry_enabled` /
    /// `giftwrap_restricted` were last refreshed.
    pub(crate) config_version: u64,
    /// Whether NIP-59 gift wraps are only served to their recipients
    /// (enforced with NIP-42 auth; false when NIP-42 is disabled).
    pub(crate) giftwrap_restricted: bool,
    /// Whether NIP-78 application-specific events (kinds 78/30078) are only
    /// served to the authenticated owner when the AUTH gate is on (cached
    /// from the config on connect and refreshed after a SIGHUP reload).
    pub(crate) nip78_restricted: bool,
    /// Whether anonymous subscriptions are refused (cached from the config
    /// on connect and refreshed after a SIGHUP reload): enabling
    /// `require_auth` mid-session must cut anonymous live streams, like
    /// the REQ/COUNT/NEG-OPEN paths already refuse them.
    pub(crate) require_auth: bool,
    /// Last verdict of the access-list read gate (see
    /// [`Conn::access_allows_read_sync`]): the non-blocking hot path falls
    /// back to this instead of failing open when the lists are contended.
    pub(crate) access_allowed_cache: bool,
    pub(crate) dropped: u64,
    /// Set when a pending live-response buffer overflows. The connection
    /// loop closes after the current batch so the client can resynchronize.
    pub(crate) live_overflowed: bool,
    /// Set when a completion-critical frame (OK/EOSE/CLOSED/NEG-*) had to
    /// be dropped at the last-resort control-queue cap. The peer may be
    /// waiting on it forever, so the connection loop closes the socket to
    /// force a clean resynchronization.
    pub(crate) control_overflowed: bool,
    /// Cached `/inbox`/`/outbox` write-policy values and the relay pubkey:
    /// the write policy is checked for every EVENT, so these must not be
    /// re-read (and cloned) from the config per event. Refreshed with the
    /// config version like the NIP flags.
    pub(crate) outbox_write_policy: String,
    pub(crate) inbox_write_policy: String,
    pub(crate) relay_pubkey: Option<String>,
    /// Per-connection message/byte counters, flushed into the shared stats
    /// once on disconnect so that a million connections do not hammer the
    /// same cache lines for every single message.
    pub(crate) in_msgs: u64,
    pub(crate) in_bytes: u64,
    pub(crate) out_msgs: u64,
    pub(crate) out_bytes_total: u64,
    /// Per-connection counter of received EVENT messages, flushed into the
    /// shared stats on disconnect like the other per-connection counters
    /// (an event-rate hot path must not touch a shared cache line).
    pub(crate) events_received_local: u64,
}

/// A live-delivery batch: the events (shared with the accepting path's
/// database write) plus their shared, pre-serialized JSON (encoded once by
/// the live bus task).
pub(crate) type LiveBatch = Arc<Vec<(Arc<crate::event::Event>, Arc<String>)>>;

impl Conn {
    pub(crate) fn send(&mut self, msg: Message) {
        self.send_tagged(msg, None);
    }

    /// Queues a message, tagged with the subscription fingerprint of the
    /// response it belongs to (if any). Returns `false` when the frame was
    /// dropped at the outgoing cap: a caller that cannot lose the frame
    /// (live delivery) must react instead of assuming it was queued.
    pub(crate) fn send_tagged(&mut self, msg: Message, event_sub: Option<u64>) -> bool {
        let size = message_size(&msg);
        // The configured cap, or the control ceiling when it is unset
        // (`0` = "no configured cap", not "no bound": without the ceiling
        // OUT_QUEUE_LIMIT frames of up to `max_ws_message_bytes` could pin
        // ~4 GiB per connection). The first frame of an empty queue is
        // never dropped, so a single frame above the cap is still
        // delivered; the queue then cannot grow past the cap again.
        let over_byte_cap =
            !self.outgoing.is_empty() && self.out_bytes.saturating_add(size) > self.out_queue_cap();
        if self.outgoing.len() >= OUT_QUEUE_LIMIT || over_byte_cap {
            self.dropped += 1;
            self.relay.stats.bump(&self.relay.stats.buffers_dropped, 1);
            return false;
        }
        self.out_bytes += size;
        self.out_msgs += 1;
        self.out_bytes_total += size as u64;
        self.outgoing.push_back(OutFrame {
            message: msg,
            event_sub,
        });
        true
    }

    pub(crate) fn send_json(&mut self, value: Value) {
        if let Ok(text) = serde_json::to_string(&value) {
            self.send(Message::Text(text.into()));
        }
    }

    /// Queues a completion-critical control message (EOSE / CLOSED /
    /// NEG-MSG / NEG-ERR) bypassing the byte cap: a dropped EOSE would
    /// leave the client hanging on a completed subscription, and a dropped
    /// NEG-MSG/NEG-ERR would hang a sync — worse than a dropped live event.
    /// The messages are tiny except for NEG-MSG id lists (bounded by
    /// `max_neg_items` and `max_req_response_bytes`, plus the NEG
    /// backpressure guard). As a last-resort OOM guard the queue length is
    /// still capped at twice `OUT_QUEUE_LIMIT`: legitimate clients drain
    /// far faster than control traffic arrives, so reaching it means an
    /// attacker flooding inbound frames on a stalled socket — drops are
    /// counted like any other queue drop.
    pub(crate) fn send_control(&mut self, value: Value) {
        self.send_control_tagged(value, None);
    }

    /// Like [`Conn::send_control`], but tags the frame with the
    /// subscription fingerprint of the response it ends (EOSE/CLOSED). A
    /// re-REQ or CLOSE under the same id purges the still-queued tagged
    /// frames, so the client can never receive an EOSE or CLOSED belonging
    /// to a replaced subscription (including a CLOSED queued by an earlier
    /// failed REQ). The control-queue caps and overflow accounting are
    /// unchanged.
    pub(crate) fn send_control_tagged(&mut self, value: Value, event_sub: Option<u64>) {
        if self.outgoing.len() >= OUT_QUEUE_LIMIT * 2 {
            self.dropped += 1;
            self.control_overflowed = true;
            self.relay.stats.bump(&self.relay.stats.buffers_dropped, 1);
            return;
        }
        if let Ok(text) = serde_json::to_string(&value) {
            let size = text.len();
            // An unset byte cap (`0` = unlimited) disables the normal
            // ceiling, but completion-critical frames still need one:
            // NEG-MSG id lists can be large, and without a bound a slow
            // reader could accumulate them up to the count cap.
            if self.out_queue_bytes == 0
                && self.out_bytes.saturating_add(size) > self.control_ceiling()
            {
                self.dropped += 1;
                self.control_overflowed = true;
                self.relay.stats.bump(&self.relay.stats.buffers_dropped, 1);
                return;
            }
            self.out_bytes += size;
            self.out_msgs += 1;
            self.out_bytes_total += size as u64;
            self.outgoing.push_back(OutFrame {
                message: Message::Text(text.into()),
                event_sub,
            });
        }
    }

    /// The absolute byte ceiling for control frames when the configured
    /// queue cap is disabled: twice the per-connection REQ budget (or a
    /// fixed 64 MiB when that is unlimited too).
    fn control_ceiling(&self) -> usize {
        if self.req_response_bytes > 0 {
            (self.req_response_bytes as usize).saturating_mul(2)
        } else {
            64 * 1024 * 1024
        }
    }

    /// The effective byte cap of the outgoing queue: the configured
    /// `limits.max_out_queue_bytes`, or [`Self::control_ceiling`] when
    /// that is unset (`0` = "no configured cap", not "no bound").
    fn out_queue_cap(&self) -> usize {
        if self.out_queue_bytes > 0 {
            self.out_queue_bytes
        } else {
            self.control_ceiling()
        }
    }

    pub(crate) fn send_notice(&mut self, text: &str) {
        self.send_json(json!(["NOTICE", text]));
    }

    /// NIP-01 CLOSED: a REQ was rejected or ended, with a machine-readable
    /// reason. Completion-critical: a dropped CLOSED would leave the
    /// client waiting on a subscription that will never deliver. Tagged
    /// with the subscription fingerprint so a re-REQ (or CLOSE) under the
    /// same id purges it before the client sees it.
    pub(crate) fn send_closed(&mut self, sub_id: &str, reason: &str) {
        self.send_control_tagged(
            json!(["CLOSED", sub_id, reason]),
            Some(sub_fingerprint(sub_id)),
        );
    }

    /// Notifies every active subscription before disconnecting after live
    /// backpressure. The client must reconnect and issue fresh REQs because
    /// events were dropped while its socket was not keeping up.
    pub(crate) fn close_for_live_overflow(&mut self) {
        let ids: Vec<String> = self.subs.keys().cloned().collect();
        for id in ids {
            self.send_closed(
                &id,
                "error: live delivery overflow; reconnect and resubscribe",
            );
        }
    }

    pub(crate) fn send_ok(&mut self, id: &str, accepted: bool, message: &str) {
        // NIP-01/NIP-42 completion acknowledgements must not compete with
        // live EVENT traffic for the byte budget: dropping one leaves the
        // publisher unable to determine whether its event or AUTH succeeded.
        self.send_control(json!(["OK", id, accepted, message]));
    }

    /// Whether the pending EVENT batch must be flushed before reading more
    /// frames: the documented count ([`EVENT_BATCH`], sharing one database
    /// commit) or the byte budget (one full frame, `max_msg_size`) is
    /// reached. Without the byte bound a burst of maximum-size frames
    /// accumulated up to the whole window before validation.
    pub(crate) fn pending_batch_full(&self, max_msg_size: usize) -> bool {
        self.pending_events.len() >= EVENT_BATCH || self.pending_bytes >= max_msg_size
    }

    /// Queues a REQ response for the pump. Responses are processed in
    /// order; when more than [`MAX_PENDING_REQS`] are queued (a client
    /// flooding REQs while reading slowly), the oldest is cut off — its
    /// EOSE is sent immediately so the client sees a completed
    /// subscription instead of a hanging one.
    pub(crate) fn enqueue_pending_req(&mut self, pending: PendingReq) {
        // A REQ replaces the subscription of the same id (NIP-01): drop
        // any still-pumping response for it so stale events are never
        // delivered for the replaced subscription.
        self.pending_reqs.retain(|p| p.sub_id != pending.sub_id);
        if self.pending_reqs.len() >= MAX_PENDING_REQS
            && let Some(mut dropped) = self.pending_reqs.pop_front()
        {
            // The dropped response was cut off before its remaining
            // events were sent: flag it so the EOSE carries the NIP-67
            // "more" hint instead of claiming a complete result (the
            // subscription itself stays open).
            dropped.truncated_or_more = true;
            // A CLOSEd subscription must not receive anything further (the
            // pump applies the same guard before its EOSE).
            if self.subs.contains_key(&dropped.sub_id) {
                if !dropped.live.is_empty() {
                    // Buffered live events can no longer be delivered
                    // (whether or not the EOSE went out), and the
                    // still-open subscription would look healthy while
                    // silently missing them — including ephemeral events
                    // that a re-REQ cannot recover. Close it so the client
                    // resubscribes (NIP-01 gives CLOSED the same closing
                    // semantics as a client CLOSE, so the subscription is
                    // released here).
                    self.send_closed(
                        &dropped.sub_id,
                        "error: live delivery overflow; resubscribe to resync",
                    );
                    self.remove_req_subscription(&dropped.sub_id);
                } else if !dropped.eose_sent {
                    // Only a response whose EOSE has not gone out needs the
                    // closing EOSE; one that already ended must not get a
                    // second one.
                    self.finish_pending_req(&dropped);
                }
            }
        }
        self.pending_reqs.push_back(pending);
    }

    /// Sends the closing EOSE (or the budget CLOSED) of a pending
    /// response. EOSE/CLOSED are tiny, so they take the uncapped path —
    /// the byte cap exists for large payloads, and a dropped EOSE would
    /// leave the client hanging on a completed subscription. The EOSE is
    /// tagged with the subscription fingerprint so a re-REQ or CLOSE
    /// purges a still-queued EOSE of the replaced incarnation.
    fn finish_pending_req(&mut self, pending: &PendingReq) {
        let eose = if pending.eose_hint {
            // NIP-67: `"auth"` advertises stored events that match the
            // filters but are withheld pending AUTH (protected events,
            // gift wraps, NIP-78 owner data, private groups). The spec
            // requires an AUTH challenge to be sent *before* the EOSE
            // that carries the hint, so it is queued ahead of it.
            if pending.auth_hint {
                self.send_control(nip42::auth_message(&self.challenge));
            }
            // `"finish"`/`"more"` describe the events servable without
            // AUTH; `"auth"` and either hint may coexist (e.g. the spec's
            // `["EOSE", sub, ["auth", "finish"]]`).
            let mut hints = Vec::with_capacity(2);
            if pending.auth_hint {
                hints.push("auth");
            }
            hints.push(if pending.truncated_or_more {
                "more"
            } else {
                "finish"
            });
            json!(["EOSE", pending.sub_id, hints])
        } else {
            json!(["EOSE", pending.sub_id])
        };
        self.send_control_tagged(eose, Some(sub_fingerprint(&pending.sub_id)));
    }

    /// Moves the pending REQ responses into the capped outgoing queue in
    /// bounded chunks: at most one pump per loop iteration, filling the
    /// queue up to the byte cap. A slow reader therefore pins at most the
    /// byte cap in the queue, and at most `req_response_bytes` per
    /// response — responses beyond the budget are closed with
    /// `CLOSED ... response too large` so the client can re-request with
    /// a narrower filter.
    pub(crate) fn pump_pending_reqs(&mut self) {
        // Cached for the whole pump: the fields only change on SIGHUP
        // (which is not applied mid-pump), and `front_mut` below borrows
        // `self` mutably.
        let out_queue_cap = self.out_queue_cap();
        loop {
            // The access lists gate the pump too: results queued before a
            // deny are dropped, so the restriction applies immediately
            // without disconnecting the connection. The subscriptions are
            // closed (CLOSED + unregistered), so the client does not hang
            // waiting for an EOSE that will never come.
            if !self.access_allows_read_sync() {
                let ids: Vec<String> = self.pending_reqs.iter().map(|p| p.sub_id.clone()).collect();
                self.pending_reqs.clear();
                for id in ids {
                    self.send_closed(&id, "restricted: you are not allowed to subscribe");
                    self.remove_req_subscription(&id);
                }
                break;
            }
            // A subscription closed while its response was still pumping
            // is dropped without an EOSE (the client already closed it).
            let closed = self
                .pending_reqs
                .front()
                .is_some_and(|f| !self.subs.contains_key(&f.sub_id));
            if closed {
                self.pending_reqs.pop_front();
                continue;
            }
            let Some(front) = self.pending_reqs.front_mut() else {
                break;
            };
            let mut budget_exceeded = false;
            while self.outgoing.len() < OUT_QUEUE_LIMIT {
                let Some(event) = front.events.front() else {
                    break;
                };
                // Hand-rolled framing: `["EVENT", <sub_id>, <event>]`
                // (the same one-pass construction `deliver_live` uses).
                // The `json!` macro would deep-clone the event into a
                // `Value` tree before serializing; serializing the
                // sub-id string and the event separately and concatenating
                // writes straight to the wire.
                let event_json = serde_json::to_string(event).unwrap_or_default();
                // The sub id's JSON form is cached at REQ time (third slot
                // of `subs`): reuse it instead of re-serializing it for
                // every event of the response.
                let sub_json = self
                    .subs
                    .get(&front.sub_id)
                    .map(|(_, _, sub_json)| sub_json.as_str())
                    .unwrap_or("\"\"");
                let mut text = String::with_capacity(event_json.len() + sub_json.len() + 16);
                text.push_str("[\"EVENT\",");
                text.push_str(sub_json);
                text.push(',');
                text.push_str(&event_json);
                text.push(']');
                let size = text.len();
                // Strict byte cap after the first message: a single
                // oversized event must still be delivered (dropping it
                // would lose data permanently), so the first push may
                // exceed the cap by one message; afterwards the queue
                // cannot grow past the cap. The effective cap applies
                // even when `max_out_queue_bytes` is unset (0 = no
                // configured cap): the pump used to skip this check
                // entirely then, letting a backlog fill the queue up to
                // the count limit.
                if self.out_bytes > 0 && self.out_bytes.saturating_add(size) > out_queue_cap {
                    break;
                }
                if self.req_response_bytes > 0
                    && front.sent_bytes.saturating_add(size as u64) > self.req_response_bytes
                {
                    budget_exceeded = true;
                    break;
                }
                front.events.pop_front();
                front.sent_bytes += size as u64;
                self.out_bytes += size;
                self.out_msgs += 1;
                self.out_bytes_total += size as u64;
                self.outgoing.push_back(OutFrame {
                    message: Message::Text(text.into()),
                    event_sub: Some(sub_fingerprint(&front.sub_id)),
                });
            }
            if budget_exceeded {
                let sub_id = front.sub_id.clone();
                self.send_closed(
                    &sub_id,
                    "blocked: response too large; narrow the filter or paginate",
                );
                // The CLOSED ends the subscription: release it exactly
                // like a client CLOSE (filter bytes, live slot, stats).
                // REQ namespace only (NIP-77 separate namespace). This
                // also removes this response from `pending_reqs`, so
                // popping the front again would silently discard the
                // *next* subscription's queued response (its events and
                // EOSE) and leave that client hanging.
                self.remove_req_subscription(&sub_id);
                continue;
            }
            if !front.events.is_empty() {
                // The queue is full or the count cap is reached: the next
                // loop iteration resumes the pump after the drain.
                break;
            }
            // All stored events are queued. Send the EOSE (with any AUTH
            // challenge ahead of it) before draining the live events that
            // arrived while the response was pumping: NIP-01 defines EOSE
            // as the boundary between stored and real-time events.
            let mut pending = self.pending_reqs.pop_front().expect("front exists");
            if !pending.eose_sent {
                pending.eose_sent = true;
                self.finish_pending_req(&pending);
            }
            self.drain_pending_live(&mut pending);
            if pending.live.is_empty() {
                continue;
            }
            // The queue filled up again with live events: keep the entry so
            // the next pump (after the socket drains) resumes in order.
            self.pending_reqs.push_front(pending);
            break;
        }
    }

    /// Moves the live events held for a pumped-out REQ response into the
    /// capped outgoing queue. The caller keeps the entry while a non-empty
    /// backlog remains, so the next pump (after the socket drains) resumes
    /// exactly where this one stopped.
    fn drain_pending_live(&mut self, pending: &mut PendingReq) {
        while self.outgoing.len() < OUT_QUEUE_LIMIT {
            let Some(text) = pending.live.front() else {
                return;
            };
            let size = text.len();
            // The same byte-cap rule as the stored events (including the
            // safety ceiling when `max_out_queue_bytes` is unset): the
            // first message may exceed the cap so a single event is never
            // lost.
            if self.out_bytes > 0 && self.out_bytes.saturating_add(size) > self.out_queue_cap() {
                return;
            }
            let text = pending.live.pop_front().expect("front checked");
            pending.live_bytes = pending.live_bytes.saturating_sub(size);
            self.out_bytes += size;
            self.out_msgs += 1;
            self.out_bytes_total += size as u64;
            self.outgoing.push_back(OutFrame {
                message: Message::Text(text.into()),
                event_sub: Some(sub_fingerprint(&pending.sub_id)),
            });
        }
    }

    /// Whether the connection is authenticated (with any pubkey).
    pub(crate) fn is_authed(&self) -> bool {
        !self.authed_pubkeys.is_empty()
    }

    pub(crate) async fn send_auth_challenge(&mut self) {
        let enabled = {
            let cfg = self.relay.config.read().await;
            cfg.nip_enabled(42) && cfg.relay.send_auth_challenge
        };
        if enabled {
            self.send_json(nip42::auth_message(&self.challenge));
        }
    }

    /// Whether this connection's source IP is blocked (NIP-86 `blockip`).
    /// Called when the blocked-IP list changes, so a read-only subscriber
    /// that never sends a frame is disconnected like any other.
    pub(crate) async fn source_ip_blocked(&self, peer_ip: std::net::IpAddr) -> bool {
        self.relay.access.read().await.is_ip_blocked(peer_ip)
    }
}

pub(crate) fn message_size(msg: &Message) -> usize {
    match msg {
        Message::Text(text) => text.len(),
        Message::Binary(data) | Message::Ping(data) | Message::Pong(data) => data.len(),
        Message::Close(_) => 0,
    }
}

/// Releases the connection's accounting when the connection task ends, no
/// matter how it ends. A panic anywhere in the connection handling would
/// otherwise skip the disconnect cleanup and leak the `connections_active`
/// counter, slowly refusing every new connection.
struct ConnectionGuard {
    relay: Arc<Relay>,
    stats: Arc<Stats>,
    /// The accept-layer slot handed over at the upgrade: the connection is
    /// already accounted for the global and per-IP caps, and the slot is
    /// released exactly once here (the shared counter replaces the old
    /// WS-layer per-IP map, so no connection is counted twice).
    conn_slot: Option<crate::conn::ConnSlotGuard>,
    /// The connection's live-index id, unregistered on drop so a panic in
    /// the connection handling cannot leave a dead entry (the bus would
    /// keep trying to deliver to a gone connection forever).
    conn_id: u64,
    /// The connection's open subscription count, released on drop so a
    /// panic cannot leak `subscriptions_active` (the normal exit path
    /// swaps it to zero first, so the drop only subtracts the rest).
    subscriptions_held: Arc<std::sync::atomic::AtomicUsize>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.stats
            .connections_active
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        // Releases the accept-layer slot inherited at the upgrade exactly
        // once, even when a panic unwinds through the connection loop.
        drop(self.conn_slot.take());
        self.relay
            .sub_index
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .unregister(self.conn_id);
        self.relay
            .conn_queues
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&self.conn_id);
        let held = self
            .subscriptions_held
            .swap(0, std::sync::atomic::Ordering::Relaxed);
        self.stats
            .subscriptions_active
            .fetch_sub(held as u64, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Conn {
    /// Refreshes the per-connection config caches after a reload: the
    /// caller only invokes this when `config_version` changed, so the hot
    /// paths never take the shared config lock. Besides the NIP-40/42/78
    /// flags this re-reads the queue budgets, which are otherwise cached
    /// at connect time (a reload must reach existing connections).
    pub(crate) async fn refresh_config_cache(&mut self) {
        {
            let cfg = self.relay.config.read().await;
            self.expiry_enabled = cfg.nip_enabled(40);
            self.giftwrap_restricted = cfg.nip_enabled(42);
            self.nip78_restricted = cfg.nip_enabled(78) && cfg.relay.enabled_nip78_auth;
            self.require_auth = cfg.relay.require_auth;
            self.out_queue_bytes = cfg.limits.max_out_queue_bytes;
            self.req_response_bytes = cfg.limits.max_req_response_bytes;
            self.max_msg_size = cfg.limits.max_ws_message_bytes;
            self.outbox_write_policy = cfg.server.outbox_write_policy.clone();
            self.inbox_write_policy = cfg.server.inbox_write_policy.clone();
        }
        self.relay_pubkey = self.relay.relay_pubkey();
    }

    /// Handles one inbound frame: bounds it against the message size
    /// limit, counts it and feeds it to the protocol handler. Returns
    /// `true` when the frame exceeded the limit and the connection must
    /// close.
    async fn handle_frame(&mut self, frame: Message, max_msg_size: usize) -> bool {
        // Borrow the text instead of copying it: the handler only reads
        // the frame, so the `Utf8Bytes` is passed by reference (the
        // per-frame allocation and memcpy of the old `to_string()` are
        // dropped entirely).
        let text = match &frame {
            Message::Text(text) => text.as_str(),
            Message::Binary(data) => return self.handle_binary(data, max_msg_size).await,
            // A Close inside the batch window must end the connection too
            // (RFC 6455: answer the close and stop reading), not be
            // swallowed until the next select iteration. (Pings are not
            // handled here: tungstenite already queues the pong.)
            Message::Close(_) => return true,
            // PONG frames are protocol keep-alive traffic: count them like
            // any other inbound frame (the old catch-all skipped them).
            Message::Pong(data) => {
                self.in_msgs += 1;
                self.in_bytes += data.len() as u64;
                return false;
            }
            _ => return false,
        };
        if text.len() > max_msg_size {
            self.send_notice("error: message too large");
            return true;
        }
        self.in_msgs += 1;
        self.in_bytes += text.len() as u64;
        self.handle_text(text).await;
        false
    }

    /// Decodes a binary frame (bytes with lossy UTF-8 fallback) and feeds
    /// it to the protocol handler. Returns `true` when the connection must
    /// close.
    async fn handle_binary(&mut self, data: &[u8], max_msg_size: usize) -> bool {
        if data.len() > max_msg_size {
            self.send_notice("error: message too large");
            return true;
        }
        let text = String::from_utf8_lossy(data);
        self.in_msgs += 1;
        // Count the wire length, not the lossy-decoded length: invalid
        // UTF-8 expands each bad byte to U+FFFD (up to three bytes), which
        // would inflate the inbound traffic statistic.
        self.in_bytes += data.len() as u64;
        self.handle_text(&text).await;
        false
    }
}

/// Why a drain attempt ended.
enum DrainOutcome {
    /// The queued messages were fed and flushed.
    Drained,
    /// The connection must close (the idle deadline expired or the relay's
    /// notification channel is gone).
    Stop,
    /// The blocked-IP list changed (the caller re-checks membership).
    IpChanged,
    /// The live-delivery queue overflowed.
    Overflow,
}

/// Feeds the queued outgoing messages and flushes once, while staying
/// responsive to the connection's liveness signals. A peer that stops
/// reading makes the socket unwritable: without racing the drain against
/// the idle deadline (and the IP-block/live-overflow notifications) the
/// task would sit in `feed` forever and the idle timeout could never reap
/// it. Backpressure is preserved: no inbound frame is read while draining.
/// A message that is already in flight when the race is lost is put back at
/// the front, so an IP-block notification that does not actually block the
/// peer cannot silently drop it.
async fn drain_outgoing<F>(
    conn: &mut Conn,
    sender: &mut F,
    idle_sleep: &mut Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
    ip_blocks_rx: &mut tokio::sync::watch::Receiver<u64>,
    overflow_rx: &mut tokio::sync::watch::Receiver<()>,
    drain_rx: &mut tokio::sync::watch::Receiver<bool>,
) -> DrainOutcome
where
    F: futures_util::Sink<Message, Error = axum::Error> + Unpin,
{
    let drain = async {
        while let Some(msg) = conn.outgoing.front() {
            // Feed a clone and pop only after the feed resolved: a drain
            // canceled by one of the races above (an IP-block notification
            // that does not actually block the peer) must leave the message
            // queued, not silently drop it.
            let msg = msg.message.clone();
            let size = message_size(&msg);
            if sender.feed(msg).await.is_err() {
                // A sink error means the socket is gone: report Stop so the
                // caller tears the connection down instead of treating the
                // queue as drained (which would leave the loop spinning on
                // a dead sink and the connection slot pinned).
                return false;
            }
            conn.outgoing.pop_front();
            conn.out_bytes = conn.out_bytes.saturating_sub(size);
        }
        let _ = sender.flush().await;
        true
    };
    let idle = async {
        match idle_sleep {
            Some(sleep) => sleep.as_mut().await,
            None => std::future::pending().await,
        }
    };
    let outcome = tokio::select! {
        drained = drain => {
            if drained {
                DrainOutcome::Drained
            } else {
                DrainOutcome::Stop
            }
        }
        _ = idle => DrainOutcome::Stop,
        changed = ip_blocks_rx.changed() => {
            if changed.is_err() {
                DrainOutcome::Stop
            } else {
                DrainOutcome::IpChanged
            }
        }
        changed = overflow_rx.changed() => {
            if changed.is_err() {
                DrainOutcome::Stop
            } else {
                DrainOutcome::Overflow
            }
        }
        changed = drain_rx.changed() => {
            // Graceful shutdown: stop draining so the caller can flush the
            // pending batch and close.
            let _ = changed;
            DrainOutcome::Stop
        }
    };
    outcome
}

/// Flushes the queued outgoing frames and closes the sink, bounded by
/// `grace`. A peer that stopped reading makes `send`/`close` park forever;
/// without the bound the connection task (and with it the connection slot,
/// live-index entry and subscription accounting) would never be released.
/// On expiry the remaining frames are abandoned and the caller still
/// releases its accounting; otherwise the flushing semantics are unchanged.
async fn flush_and_close<F>(conn: &mut Conn, sender: &mut F, grace: Duration)
where
    F: futures_util::Sink<Message, Error = axum::Error> + Unpin,
{
    let teardown = async {
        while let Some(frame) = conn.outgoing.pop_front() {
            let size = message_size(&frame.message);
            // Uncount on pop and re-count only on a delivered send:
            // whatever the teardown's fate (drained, send error, grace
            // expiry mid-send), a frame still queued or stuck in flight
            // is never reported as wire traffic, and a delivered frame
            // always is. The rest-uncount below then stays correct even
            // when the grace drops this future mid-send.
            conn.out_bytes = conn.out_bytes.saturating_sub(size);
            conn.out_msgs = conn.out_msgs.saturating_sub(1);
            conn.out_bytes_total = conn.out_bytes_total.saturating_sub(size as u64);
            if sender.send(frame.message).await.is_err() {
                break;
            }
            conn.out_msgs = conn.out_msgs.saturating_add(1);
            conn.out_bytes_total = conn.out_bytes_total.saturating_add(size as u64);
        }
        let _ = sender.close().await;
    };
    let _ = tokio::time::timeout(grace, teardown).await;
    // Grace expiry (or the send error above) abandons whatever is still
    // queued: those frames can never be received, so uncount them instead
    // of reporting phantom traffic. Runs unconditionally: the teardown
    // above may have been dropped mid-send, in which case this is what
    // releases the abandoned remainder.
    let mut rest_msgs = 0u64;
    let mut rest_bytes = 0usize;
    for frame in std::mem::take(&mut conn.outgoing) {
        rest_msgs += 1;
        rest_bytes = rest_bytes.saturating_add(message_size(&frame.message));
    }
    conn.out_bytes = conn.out_bytes.saturating_sub(rest_bytes);
    conn.out_msgs = conn.out_msgs.saturating_sub(rest_msgs);
    conn.out_bytes_total = conn.out_bytes_total.saturating_sub(rest_bytes as u64);
}

pub async fn handle_connection(
    mut socket: WebSocket,
    relay: Arc<Relay>,
    peer_ip: std::net::IpAddr,
    path: String,
    conn_slot: Option<crate::conn::ConnSlotGuard>,
) {
    // The global/per-IP caps were already enforced at the accept layer, and
    // the accept slot was handed over synchronously at the upgrade (the
    // HTTP task can no longer release it), so the connection cannot be
    // refused here: only the stats are accounted.
    relay
        .stats
        .connections_active
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    relay.stats.bump(&relay.stats.connections_total, 1);
    let conn_id = relay
        .next_conn_id
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let subscriptions_held = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let _guard = ConnectionGuard {
        relay: relay.clone(),
        stats: relay.stats.clone(),
        conn_slot,
        conn_id,
        subscriptions_held: Arc::clone(&subscriptions_held),
    };

    let challenge = match nip42::generate_challenge() {
        // RNG failure must fail the connection closed: a constant fallback
        // challenge would let one AUTH event replay across connections.
        // `_guard` releases the slot on return.
        None => {
            log::error!("RNG failure generating AUTH challenge; refusing connection");
            let _ = socket.close().await;
            return;
        }
        Some(challenge) => challenge,
    };

    let (mut sender, mut receiver) = socket.split();
    let (
        max_msg_size,
        out_queue_bytes,
        req_response_bytes,
        expiry_enabled,
        giftwrap_restricted,
        nip78_restricted,
        require_auth,
        idle_timeout,
        outbox_write_policy,
        inbox_write_policy,
    ) = {
        let cfg = relay.config.read().await;
        (
            cfg.limits.max_ws_message_bytes,
            cfg.limits.max_out_queue_bytes,
            cfg.limits.max_req_response_bytes,
            cfg.nip_enabled(40),
            cfg.nip_enabled(42),
            cfg.nip_enabled(78) && cfg.relay.enabled_nip78_auth,
            cfg.relay.require_auth,
            cfg.limits.ws_idle_timeout_secs,
            cfg.server.outbox_write_policy.clone(),
            cfg.server.inbox_write_policy.clone(),
        )
    };
    let relay_pubkey = relay.relay_pubkey();
    // Idle connections (no inbound frames) hold their slot forever; when the
    // operator enables the idle timeout the relay closes them, sending a
    // periodic PING so an alive-but-silent subscriber (which auto-responds
    // with a PONG, itself an inbound frame) stays connected while dead peers
    // are reaped. The deadline is measured from the *last inbound frame*, not
    // from the loop restart, so the keep-alive PING and live deliveries never
    // reset it (otherwise dead peers would never be reaped).
    let idle: Option<Duration> = if idle_timeout > 0 {
        Some(Duration::from_secs(idle_timeout))
    } else {
        None
    };
    // Bound for the final flush/close and the keep-alive PING send: a peer
    // that stopped reading must not park the task (and its connection slot,
    // live-index entry and subscription accounting) forever. It is never
    // longer than the operator's own idle deadline.
    let teardown_grace = idle.map_or(Duration::from_secs(2), |d| d.min(Duration::from_secs(5)));
    let mut last_activity = std::time::Instant::now();
    // A single persistent idle deadline (reset in place on every inbound
    // frame): the per-iteration `timeout(remaining)` of the old loop
    // created and destroyed a timer-wheel entry every pass — for live-
    // active connections that was dozens of times per second. The jitter
    // (derived from the connection id, so no RNG) spreads the deadlines
    // of a large simultaneous cohort instead of timing them all out in
    // the same instant.
    let mut ping: Option<tokio::time::Interval> = idle.map(|d| {
        let mut interval = tokio::time::interval(Duration::from_secs((d.as_secs() / 3).max(5)));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick of a fresh interval fires immediately: reset it so
        // a connect burst does not PING every connection at once.
        interval.reset();
        interval
    });

    // NIP-86 blockip: watch the blocked-IP list changes so this connection
    // is dropped when its source IP becomes blocked, even if it only
    // receives live events and never sends a frame.
    let mut ip_blocks_rx = relay.ip_blocks_tx.subscribe();
    // Graceful shutdown: the relay signals a drain so the loop flushes its
    // pending event batch and closes before the process exits (the upgraded
    // WebSocket task is detached from the HTTP connection, so the server's
    // HTTP-level drain cannot reach it).
    let mut drain_rx = relay.subscribe_drain();
    // A `watch` receiver treats the value present at subscription time as
    // already seen: when the drain was signaled before this connection
    // subscribed (a connection accepted during shutdown), `changed()` never
    // fires and the loop would run on instead of flushing. Read the current
    // value once so the loop takes the teardown path immediately.
    let drain_signaled = *drain_rx.borrow();

    let idle_jitter = Duration::from_millis(conn_id % 2000);
    let idle_sleep: Option<tokio::time::Sleep> =
        idle.map(|d| tokio::time::sleep_until(tokio::time::Instant::now() + d + idle_jitter));
    let mut idle_sleep = idle_sleep.map(Box::pin);
    let (live_tx, live_rx): (
        tokio::sync::mpsc::Sender<crate::ws::LiveBatch>,
        tokio::sync::mpsc::Receiver<crate::ws::LiveBatch>,
    ) = tokio::sync::mpsc::channel(crate::relay::LIVE_QUEUE_CAPACITY);
    let (overflow_tx, mut overflow_rx) = tokio::sync::watch::channel(());
    relay
        .conn_queues
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(
            conn_id,
            crate::relay::LiveQueue {
                sender: live_tx,
                overflow: overflow_tx,
            },
        );
    let mut conn = Conn {
        pending_budget: pending_response_budget(&relay),
        neg_budget: neg_budget(&relay),
        neg_cpu_budget: neg_cpu_budget(&relay),
        relay,
        conn_id,
        subscriptions_held,
        live: Some(live_rx),
        path,
        outgoing: std::collections::VecDeque::new(),
        control_overflowed: false,
        outbox_write_policy,
        inbox_write_policy,
        relay_pubkey,
        out_bytes: 0,
        out_queue_bytes,
        req_response_bytes,
        max_msg_size,
        subs: HashMap::new(),
        sub_bytes: 0,
        neg: HashMap::new(),
        neg_total: 0,
        neg_opens_total: 0,
        challenge,
        authed_pubkeys: Vec::new(),
        auth_attempts: 0,
        pending_events: Vec::new(),
        pending_bytes: 0,
        expiry_enabled,
        giftwrap_restricted,
        nip78_restricted,
        require_auth,
        access_allowed_cache: false,
        config_version: 0,
        dropped: 0,
        live_overflowed: false,
        in_msgs: 0,
        in_bytes: 0,
        out_msgs: 0,
        out_bytes_total: 0,
        events_received_local: 0,
        pending_reqs: std::collections::VecDeque::new(),
    };
    conn.send_auth_challenge().await;
    // Seed the access-read verdict cache with a genuinely computed value,
    // so the non-blocking live/pump checks never fall back to an
    // uninitialized (sentinel) verdict during the first contention window.
    conn.access_allows_read().await;

    // A single task per connection: incoming messages and live batches are
    // processed in the same loop, and outgoing messages are flushed to the
    // socket after every iteration. This halves the task count (no separate
    // writer task) and the per-connection channel.
    #[allow(unused_assignments)] // the initial value is overwritten before the first read
    let mut drain_stalled = !conn.outgoing.is_empty();
    'connection: loop {
        // The relay signaled the drain before this connection subscribed
        // (see `drain_signaled`): take the same teardown path as the
        // `drain_rx.changed()` branch so the pending batch is flushed.
        if drain_signaled {
            break;
        }
        // A completion-critical frame was dropped because the control queue
        // hit its last-resort cap: the peer could be waiting on that OK or
        // EOSE forever, so close the socket (a reconnect resynchronizes).
        if conn.control_overflowed {
            break;
        }
        // Drain pending outgoing messages. A slow reader stalls only its
        // own connection (outgoing is bounded, so new messages are dropped).
        // The drain races the connection's liveness signals: a peer that
        // stops reading makes the socket unwritable, and without the race
        // the idle timeout (and the IP-block/live-overflow notifications)
        // could never fire.
        match drain_outgoing(
            &mut conn,
            &mut sender,
            &mut idle_sleep,
            &mut ip_blocks_rx,
            &mut overflow_rx,
            &mut drain_rx,
        )
        .await
        {
            DrainOutcome::Drained => {}
            DrainOutcome::Stop => break,
            DrainOutcome::IpChanged => {
                if conn.source_ip_blocked(peer_ip).await {
                    break;
                }
            }
            DrainOutcome::Overflow => {
                conn.live_overflowed = true;
                conn.close_for_live_overflow();
                break;
            }
        }
        // Pump the queued REQ responses through the capped outgoing queue
        // in bounded chunks (see `pump_pending_reqs`).
        conn.pump_pending_reqs();
        // Remember whether anything is still queued *after* the pump
        // refilled the outgoing queue: the flush_wake branch retries
        // promptly only when there is more to send. (A tungstenite feed
        // never leaves a message queued on WouldBlock, so the queue's
        // emptiness is what decides whether the socket is the bottleneck.)
        drain_stalled = !conn.outgoing.is_empty();
        let live_fut = async {
            match conn.live.as_mut() {
                Some(rx) => rx.recv().await,
                None => std::future::pending().await,
            }
        };
        // Periodic keep-alive PING (when the idle timeout is enabled).
        let ping_fut = async {
            match ping.as_mut() {
                Some(interval) => interval.tick().await,
                None => std::future::pending().await,
            }
        };
        // Wakes the top-of-loop drain (which flushes the outgoing queue)
        // when the previous drain could not empty it: a client that is
        // blocked sending EVENTs cannot receive the OKs that unblock it
        // unless the relay actually sends them, and without this branch
        // the loop would wait for the next inbound frame (which never
        // comes while the peer is blocked). When the last drain emptied
        // the queue there is nothing to throttle, so the branch sleeps
        // only when the socket itself is the bottleneck.
        let flush_wake = async {
            if drain_stalled {
                tokio::time::sleep(tokio::time::Duration::from_millis(1)).await
            } else {
                std::future::pending().await
            }
        };
        let incoming_fut = async {
            match &mut idle_sleep {
                Some(sleep) => {
                    // The deadline is measured from the last inbound frame
                    // (only the incoming branch updates `last_activity`, so
                    // pings/live batches cannot mask a dead peer); a frame
                    // advanced the deadline, so reset the single Sleep in
                    // place.
                    let target = tokio::time::Instant::from_std(last_activity)
                        + idle.expect("idle_sleep is Some only when idle is Some")
                        + idle_jitter;
                    if sleep.as_mut().deadline() != target {
                        sleep.as_mut().reset(target);
                    }
                    tokio::select! {
                        biased;
                        _ = sleep.as_mut() => Err(()),
                        frame = receiver.next() => match frame {
                            Some(Ok(frame)) => Ok(frame),
                            _ => Err(()),
                        },
                    }
                }
                None => match receiver.next().await {
                    Some(Ok(frame)) => Ok(frame),
                    _ => Err(()),
                },
            }
        };
        tokio::select! {
            incoming = incoming_fut => {
                match incoming {
                    // Idle timeout (ws_idle_timeout_secs): no inbound frames.
                    Err(_) => break,
                    Ok(Message::Close(_)) => break,
                    Ok(frame) => {
                        last_activity = std::time::Instant::now();
                        // Refresh the cached flags and budgets *before*
                        // handling the frame, so a SIGHUP-lowered
                        // `max_ws_message_bytes` already applies to the
                        // first frame after the reload (the version bumps
                        // on every reload): the hot path never takes the
                        // shared config lock otherwise.
                        let version = conn
                            .relay
                            .config_version
                            .load(std::sync::atomic::Ordering::Relaxed);
                        if version != conn.config_version {
                            conn.config_version = version;
                            conn.refresh_config_cache().await;
                        }
                        if conn.handle_frame(frame, conn.max_msg_size).await {
                            break;
                        }
                    }
                }
                // Batch window: keep reading for a moment so consecutive
                // EVENT messages from a busy publisher share one database
                // commit, then flush the queue when the socket is idle. The
                // iteration cap bounds the window so a client flooding
                // frames cannot starve this connection's live delivery and
                // outgoing flush (which only run in the outer select).
                let mut too_large = false;
                // A single `Sleep` deadline covers the whole window: the
                // per-frame `timeout(1ms)` of the old loop created and
                // destroyed a timer-wheel entry for every frame (and taxed
                // every single-frame REQ/EVENT with a full millisecond).
                // The deadline is *sliding*: each frame resets it (1 ms
                // after the frame), so a continuous burst coalesces into
                // one window (and one database commit), while an idle
                // client still gets its OK within ~1 ms. The frame cap
                // bounds the window when a client floods faster than the
                // relay can drain; it is sized well above the receive
                // buffer so a full socket becomes one batch.
                let window_deadline = tokio::time::sleep_until(
                    tokio::time::Instant::now() + tokio::time::Duration::from_millis(1),
                );
                tokio::pin!(window_deadline);
                for _ in 0..EVENT_BATCH * 32 {
                    let frame = tokio::select! {
                        biased;
                        frame = receiver.next() => match frame {
                            Some(Ok(frame)) => frame,
                            _ => break,
                        },
                        _ = &mut window_deadline => break,
                    };
                    last_activity = std::time::Instant::now();
                    // A reload during the batch window (a SIGHUP handled
                    // between frames) must refresh before the next frame is
                    // size-checked, like the single-frame path above.
                    let version = conn
                        .relay
                        .config_version
                        .load(std::sync::atomic::Ordering::Relaxed);
                    if version != conn.config_version {
                        conn.config_version = version;
                        conn.refresh_config_cache().await;
                    }
                    if conn.handle_frame(frame, conn.max_msg_size).await {
                        too_large = true;
                        break;
                    }
                    // The pending batch is bounded by count and bytes: flush
                    // it through the post-window path instead of reading the
                    // rest of the window (which let a flood of maximum-size
                    // frames pile up parsed events before validation).
                    if conn.pending_batch_full(conn.max_msg_size) {
                        break;
                    }
                    // Slide the window: the next frame extends the batch
                    // instead of starting a new window (and a new commit).
                    window_deadline
                        .as_mut()
                        .reset(tokio::time::Instant::now() + tokio::time::Duration::from_millis(1));
                }
                if too_large {
                    break;
                }
                conn.flush_pending_events().await;
                // Deliver the REQ responses queued by the frames handled
                // in this iteration: without this, a client that sends one
                // REQ and waits would not receive the response until the
                // next select event (a further frame, the keep-alive PING
                // or a live batch) drives the top-of-loop drain.
                // The frames just handled moved `last_activity`: refresh the
                // idle deadline before the drain race, or a frame that
                // arrived close to the old deadline would be reaped as idle.
                if let (Some(sleep), Some(d)) = (idle_sleep.as_mut(), idle) {
                    let target = tokio::time::Instant::from_std(last_activity) + d + idle_jitter;
                    if sleep.as_mut().deadline() != target {
                        sleep.as_mut().reset(target);
                    }
                }
                match drain_outgoing(
                    &mut conn,
                    &mut sender,
                    &mut idle_sleep,
                    &mut ip_blocks_rx,
                    &mut overflow_rx,
                    &mut drain_rx,
                )
                .await
                {
                    DrainOutcome::Drained => {}
                    DrainOutcome::Stop => break,
                    DrainOutcome::IpChanged => {
                        if conn.source_ip_blocked(peer_ip).await {
                            break;
                        }
                    }
                    DrainOutcome::Overflow => {
                        conn.live_overflowed = true;
                        conn.close_for_live_overflow();
                        break;
                    }
                }
                conn.pump_pending_reqs();
            }
            _ = ping_fut => {
                // Keep-alive: a healthy client answers with a PONG (an
                // inbound frame, which resets the idle timeout), so an idle
                // subscriber stays connected while a dead peer is reaped.
                // Reap silent negentropy syncs here too: a PONG keeps the
                // connection alive but never touches NEG state, so without
                // this an idle sync would hold its items and budget share
                // forever.
                conn.reap_idle_negentropy();
                // The send is bounded: a peer that stopped reading parks
                // inside it, and the idle deadline (raced only by the
                // drain) could not fire here, so a stalled PING closes the
                // connection instead of pinning it.
                // Count the ping only when it actually goes out: a
                // failed send must not inflate the traffic counters.
                if tokio::time::timeout(
                    teardown_grace,
                    sender.send(Message::Ping(vec![].into())),
                )
                .await
                .is_ok()
                {
                    conn.out_msgs += 1;
                } else {
                    break;
                }
            }
            _ = flush_wake => {
                // The outgoing queue holds OKs (or REQ responses) that
                // must reach the peer for its send path to unblock: wake
                // the top-of-loop drain promptly instead of waiting for
                // the next inbound frame.
            }
            changed = ip_blocks_rx.changed() => {
                // NIP-86 blockip: wake on every blocked-IP list change so a
                // read-only subscriber (no inbound frames) is dropped too.
                // An `Err` means the relay (and its sender) is gone.
                if changed.is_err() || conn.source_ip_blocked(peer_ip).await {
                    break;
                }
            }
            changed = overflow_rx.changed() => {
                if changed.is_ok() {
                    conn.live_overflowed = true;
                    conn.close_for_live_overflow();
                    break;
                }
            }
            changed = drain_rx.changed() => {
                // Graceful shutdown: break so the teardown flushes the
                // pending event batch (and its OKs) before the process
                // exits.
                let _ = changed;
                break;
            }
            live_batch = live_fut => {
                match live_batch {
                    Some(batch) => {
                        // Refresh the cached NIP-40/NIP-42 flags only when
                        // the config actually changed (the version bumps on
                        // every SIGHUP reload): the hot live path never
                        // takes the shared config lock.
                        let version = conn
                            .relay
                            .config_version
                            .load(std::sync::atomic::Ordering::Relaxed);
                        if version != conn.config_version {
                            conn.config_version = version;
                            conn.refresh_config_cache().await;
                        }
                        // The group store lock and its Arc clone are only
                        // taken when the batch actually contains group
                        // events (rare); ordinary traffic skips the shared
                        // state entirely.
                        let has_group_events =
                            batch.iter().any(|(e, _)| nip29::is_group_event(e));
                        let store = if has_group_events {
                            Some(Arc::clone(&conn.relay.groups))
                        } else {
                            None
                        };
                        let guard = if let Some(store) = &store {
                            Some(store.read().await)
                        } else {
                            None
                        };
                        let groups = guard.as_deref();
                        let now = crate::util::unix_now();
                        for (event, json) in batch.iter() {
                            conn.deliver_live_at(event, json, groups, now);
                            if conn.live_overflowed {
                                conn.close_for_live_overflow();
                                break 'connection;
                            }
                        }
                    }
                    None => break,
                }
            }
        }
    }

    // Events received but not yet batched are accepted before closing, so
    // a client that disconnects without waiting for its OKs does not lose
    // them. The live broadcast of these events still reaches subscribers.
    // Bounded by the teardown grace like the close below: with the DB
    // timeout disabled (or a wedged writer) this wait would otherwise park
    // the task — and its connection slot and subscription accounting —
    // indefinitely. On expiry the connection closes without the final
    // batch; its events were never queued, so nothing partial commits.
    let _ = tokio::time::timeout(teardown_grace, conn.flush_pending_events()).await;

    // Final flush: deliver any queued messages (e.g. NOTICEs) before
    // closing the connection. Bounded by `teardown_grace`: a peer that
    // stopped reading must not park the task (and its connection slot and
    // subscription accounting) forever, so the remaining frames are
    // abandoned on expiry and the release below still runs.
    flush_and_close(&mut conn, &mut sender, teardown_grace).await;

    // Remove the connection from the live subscription index and the
    // delivery-queue map (the queue sender is dropped with the map entry;
    // the bus task's `send` then fails and the connection is skipped).
    conn.relay
        .sub_index
        .write()
        .unwrap_or_else(|p| p.into_inner())
        .unregister(conn.conn_id);
    conn.relay
        .conn_queues
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&conn.conn_id);

    // Flush the per-connection counters into the shared stats once, so the
    // hot per-message path never contends on the shared atomics.
    conn.relay
        .stats
        .bump(&conn.relay.stats.messages_in, conn.in_msgs);
    conn.relay
        .stats
        .bump(&conn.relay.stats.bytes_in, conn.in_bytes);
    conn.relay
        .stats
        .bump(&conn.relay.stats.messages_out, conn.out_msgs);
    conn.relay
        .stats
        .bump(&conn.relay.stats.bytes_out, conn.out_bytes_total);
    conn.relay.stats.bump(
        &conn.relay.stats.events_received,
        conn.events_received_local,
    );

    // Release the connection's accounting: any subscriptions still open at
    // disconnect were never CLOSE'd, so decrement them here (REQ
    // subscriptions and negentropy subscriptions both hold a slot). The
    // guard drops the remainder if a panic ever skips this path.
    let held = conn
        .subscriptions_held
        .swap(0, std::sync::atomic::Ordering::Relaxed);
    conn.relay
        .stats
        .subscriptions_active
        .fetch_sub(held as u64, std::sync::atomic::Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Keypair, Secp256k1, XOnlyPublicKey};
    use serde_json::Value;
    use tokio::sync::RwLock;

    use crate::config::Config;
    use crate::nips::nip01::{compute_id, sign};
    use crate::relay::LiveBusConfig;
    use crate::util::unix_now;

    fn temp_db_path() -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join("nostrfy-ws-test")
            .join(format!("{:x}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        path
    }

    fn signed_note(
        secp: &Secp256k1<secp256k1::All>,
        content: &str,
        created: u64,
        tags: Vec<Vec<String>>,
    ) -> Event {
        let keypair = Keypair::from_seckey_slice(secp, &[1u8; 32]).unwrap();
        let pubkey = XOnlyPublicKey::from_keypair(&keypair).0.to_string();
        let mut ev = Event {
            id: String::new(),
            pubkey,
            created_at: created,
            kind: 1,
            tags,
            content: content.into(),
            sig: String::new(),
        };
        sign(&mut ev, &keypair, secp).unwrap();
        ev
    }

    /// Like [`signed_note`] but with a distinct author per seed byte.
    fn signed_note_seeded(
        secp: &Secp256k1<secp256k1::All>,
        seed: u8,
        content: &str,
        created: u64,
        tags: Vec<Vec<String>>,
    ) -> Event {
        let keypair = Keypair::from_seckey_slice(secp, &[seed; 32]).unwrap();
        let pubkey = XOnlyPublicKey::from_keypair(&keypair).0.to_string();
        let mut ev = Event {
            id: String::new(),
            pubkey,
            created_at: created,
            kind: 1,
            tags,
            content: content.into(),
            sig: String::new(),
        };
        sign(&mut ev, &keypair, secp).unwrap();
        ev
    }

    fn signed_auth(secp: &Secp256k1<secp256k1::All>, challenge: &str, created: u64) -> Event {
        let keypair = Keypair::from_seckey_slice(secp, &[2u8; 32]).unwrap();
        let pubkey = XOnlyPublicKey::from_keypair(&keypair).0.to_string();
        let mut ev = Event {
            id: String::new(),
            pubkey,
            created_at: created,
            kind: 22242,
            tags: vec![
                vec!["challenge".into(), challenge.into()],
                vec!["relay".into(), "127.0.0.1:8080".into()],
            ],
            content: String::new(),
            sig: String::new(),
        };
        ev.id = compute_id(&ev);
        let id = ev.id_bytes().unwrap();
        ev.sig = secp.sign_schnorr_no_aux_rand(&id, &keypair).to_string();
        ev
    }

    /// Like [`signed_note_seeded`] but with an arbitrary kind and a valid
    /// signature over that kind (kind mutations after signing break the sig).
    fn signed_kind_note_seeded(
        secp: &Secp256k1<secp256k1::All>,
        seed: u8,
        kind: u64,
        content: &str,
        created: u64,
        tags: Vec<Vec<String>>,
    ) -> Event {
        let keypair = Keypair::from_seckey_slice(secp, &[seed; 32]).unwrap();
        let pubkey = XOnlyPublicKey::from_keypair(&keypair).0.to_string();
        let mut ev = Event {
            id: String::new(),
            pubkey,
            created_at: created,
            kind,
            tags,
            content: content.into(),
            sig: String::new(),
        };
        sign(&mut ev, &keypair, secp).unwrap();
        ev
    }

    /// AUTH event signed with a specific key seed (owner of the events it
    /// must reveal). Seed 2 matches [`signed_auth`]/[`signed_note_seeded`].
    fn signed_auth_seeded(
        secp: &Secp256k1<secp256k1::All>,
        seed: u8,
        challenge: &str,
        created: u64,
    ) -> Event {
        let keypair = Keypair::from_seckey_slice(secp, &[seed; 32]).unwrap();
        let pubkey = XOnlyPublicKey::from_keypair(&keypair).0.to_string();
        let mut ev = Event {
            id: String::new(),
            pubkey,
            created_at: created,
            kind: 22242,
            tags: vec![
                vec!["challenge".into(), challenge.into()],
                vec!["relay".into(), "127.0.0.1:8080".into()],
            ],
            content: String::new(),
            sig: String::new(),
        };
        ev.id = compute_id(&ev);
        let id = ev.id_bytes().unwrap();
        ev.sig = secp.sign_schnorr_no_aux_rand(&id, &keypair).to_string();
        ev
    }

    async fn build_conn() -> Conn {
        build_conn_with("").await
    }

    /// Builds a connection on a pre-built relay (for tests that need
    /// several connections sharing one relay + subscription index).
    async fn build_conn_on(relay: Arc<Relay>) -> Conn {
        let (
            out_queue_bytes,
            max_msg_size,
            expiry_enabled,
            giftwrap_restricted,
            nip78_restricted,
            require_auth,
        ) = {
            let cfg = relay.config.read().await;
            (
                cfg.limits.max_out_queue_bytes,
                cfg.limits.max_ws_message_bytes,
                cfg.nip_enabled(40),
                cfg.nip_enabled(42),
                cfg.nip_enabled(78) && cfg.relay.enabled_nip78_auth,
                cfg.relay.require_auth,
            )
        };
        let conn_id = relay
            .next_conn_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (live_tx, live_rx) = tokio::sync::mpsc::channel(crate::relay::LIVE_QUEUE_CAPACITY);
        let (overflow_tx, _overflow_rx) = tokio::sync::watch::channel(());
        relay
            .conn_queues
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(
                conn_id,
                crate::relay::LiveQueue {
                    sender: live_tx,
                    overflow: overflow_tx,
                },
            );
        Conn {
            pending_budget: pending_response_budget(&relay),
            neg_budget: neg_budget(&relay),
            neg_cpu_budget: neg_cpu_budget(&relay),
            relay,
            conn_id,
            subscriptions_held: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            live: Some(live_rx),
            path: "/".into(),
            outgoing: std::collections::VecDeque::new(),
            control_overflowed: false,
            outbox_write_policy: String::new(),
            inbox_write_policy: String::new(),
            relay_pubkey: None,
            out_bytes: 0,
            out_queue_bytes,
            req_response_bytes: 0,
            max_msg_size,
            pending_reqs: std::collections::VecDeque::new(),
            subs: HashMap::new(),
            sub_bytes: 0,
            neg: HashMap::new(),
            neg_total: 0,
            neg_opens_total: 0,
            challenge: "test-challenge".into(),
            authed_pubkeys: Vec::new(),
            auth_attempts: 0,
            pending_events: Vec::new(),
            pending_bytes: 0,
            expiry_enabled,
            giftwrap_restricted,
            nip78_restricted,
            require_auth,
            access_allowed_cache: false,
            config_version: 0,
            dropped: 0,
            live_overflowed: false,
            in_msgs: 0,
            in_bytes: 0,
            out_msgs: 0,
            out_bytes_total: 0,
            events_received_local: 0,
        }
    }

    async fn build_conn_with(private_key: &str) -> Conn {
        build_conn_on(build_relay_with(private_key).await).await
    }

    /// Builds a relay with the test memory-mapped database and its live bus
    /// running, for tests that need several connections sharing one relay.
    async fn build_relay_with(private_key: &str) -> Arc<Relay> {
        build_relay_with_limits(private_key, |_| {}).await
    }

    /// Like [`build_relay_with`], but lets the caller tune the test config
    /// (limits, idle timeout, database sizes) before the relay is created.
    async fn build_relay_with_limits(
        private_key: &str,
        tune: impl FnOnce(&mut Config),
    ) -> Arc<Relay> {
        let mut cfg = Config::default();
        cfg.database.path = temp_db_path();
        // Small memory map: the parallel tests each open a DB, and the
        // production 1 TiB reservation would exhaust the container's
        // memory under the concurrent load (sparse, but the mappings add
        // up). The tests store a handful of events.
        cfg.database.map_size = 16 * 1024 * 1024;
        cfg.database.max_map_size = 64 * 1024 * 1024;
        tune(&mut cfg);
        let db = crate::db::DbClient::open(
            &cfg.database,
            true,
            Arc::new(Default::default()),
            0,
            128,
            4096,
            262144,
        )
        .unwrap_or_else(|e| panic!("open test db at {}: {e}", cfg.database.path.display()));
        let config = Arc::new(RwLock::new(cfg));
        let stats = Stats::new();
        let mut relay = Relay::new(
            config,
            db,
            stats,
            private_key,
            LiveBusConfig {
                buffer: 1024,
                batch_interval_ms: 10,
                batch_size: 64,
            },
        )
        .await;
        relay.start_live_bus();
        Arc::new(relay)
    }

    /// Every queued outgoing text message parsed as JSON.
    fn outgoing_json(conn: &Conn) -> Vec<Value> {
        conn.outgoing
            .iter()
            .filter_map(|frame| match &frame.message {
                Message::Text(t) => serde_json::from_str(t).ok(),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn req_delivers_matching_events_then_eose() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            let e1 = signed_note(conn.relay.secp(), "hello", now, vec![]);
            let e2 = signed_note(conn.relay.secp(), "world", now - 1, vec![]);
            conn.relay.db.put(e1.clone(), now).await;
            conn.relay.db.put(e2.clone(), now).await;
            conn.handle_req(&[json!("sub"), json!({"kinds": [1]})])
                .await;
            conn.pump_pending_reqs();
            let msgs = outgoing_json(&conn);
            let events: Vec<&Value> = msgs.iter().filter(|m| m[0] == "EVENT").collect();
            assert_eq!(events.len(), 2);
            let ids: Vec<String> = events
                .iter()
                .map(|m| m[2]["id"].as_str().unwrap().to_string())
                .collect();
            assert!(ids.contains(&e1.id) && ids.contains(&e2.id));
            assert!(msgs.iter().any(|m| m[0] == "EOSE" && m[1] == "sub"));
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn req_response_is_bounded_by_the_byte_budget() {
        // A slow reader must not pin the whole scan result per pending
        // response: the materialized prefix is truncated to the response
        // byte budget, with the first over-budget event kept so the pump
        // still emits its exact-check CLOSED (never a silent drop).
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            for i in 0..10 {
                let ev = signed_note(
                    conn.relay.secp(),
                    &format!("e{i}-{}", "z".repeat(1_000)),
                    now - i as u64,
                    vec![],
                );
                conn.relay.db.put(ev, now).await;
            }
            // Each frame is well over 1 KiB; only a few fit in the budget.
            conn.req_response_bytes = 5_000;
            conn.handle_req(&[json!("sub"), json!({"kinds": [1]})])
                .await;
            let pending = conn.pending_reqs.front().expect("pending response");
            assert!(
                !pending.events.is_empty() && pending.events.len() < 10,
                "the response must be truncated to the byte budget, got {} events",
                pending.events.len()
            );
            conn.pump_pending_reqs();
            let msgs = outgoing_json(&conn);
            assert!(
                msgs.iter().any(|m| m[0] == "CLOSED"
                    && m[1] == "sub"
                    && m[2].as_str().unwrap_or("").contains("response too large")),
                "the truncated response must still end in the over-budget CLOSED"
            );
            assert!(
                !conn.subs.contains_key("sub"),
                "the over-budget response must release the subscription"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn byte_truncated_response_reports_more_after_a_budget_raise() {
        // Regression: the scan-time truncation against
        // `max_req_response_bytes` used to be invisible to the EOSE. A
        // SIGHUP raising the budget between the truncation and the pump
        // would then complete the response silently, losing the dropped
        // events; the EOSE must carry the NIP-67 "more" marker instead.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            for i in 0..10 {
                let ev = signed_note(
                    conn.relay.secp(),
                    &format!("e{i}-{}", "z".repeat(1_000)),
                    now - i as u64,
                    vec![],
                );
                conn.relay.db.put(ev, now).await;
            }
            conn.req_response_bytes = 5_000;
            conn.handle_req(&[json!("sub"), json!({"kinds": [1]})])
                .await;
            let kept = conn
                .pending_reqs
                .front()
                .expect("pending response")
                .events
                .len();
            assert!(
                kept < 10,
                "the response must be truncated to the byte budget, got {kept} events"
            );
            // The reload raises the budget before the pump: without the
            // truncation marker the response would complete as `finish`.
            conn.req_response_bytes = 1 << 20;
            conn.pump_pending_reqs();
            let msgs = outgoing_json(&conn);
            let eose = msgs
                .iter()
                .find(|m| m[0] == "EOSE" && m[1] == "sub")
                .expect("the response must end in an EOSE");
            assert_eq!(
                eose[2],
                json!(["more"]),
                "a byte-truncated response must not claim completion"
            );
            assert!(
                !msgs.iter().any(|m| m[0] == "CLOSED" && m[1] == "sub"),
                "the raised budget means no over-budget CLOSED"
            );
            assert!(
                conn.subs.contains_key("sub"),
                "the subscription stays open for pagination"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn req_timeout_closes_and_releases_the_subscription() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            let e1 = signed_note(conn.relay.secp(), "hello", now, vec![]);
            conn.relay.db.put(e1.clone(), now).await;
            // Killing the DB reader makes the REQ query fail deterministically
            // (`query_req_result` returns None), exactly like a timed-out or
            // errored scan: the CLOSED path must release the subscription it
            // had registered before the query, or the dead sub keeps
            // receiving live events under a closed id.
            conn.relay.db.shutdown();
            conn.handle_req(&[json!("sub"), json!({"kinds": [1]})])
                .await;
            conn.pump_pending_reqs();
            let msgs = outgoing_json(&conn);
            assert!(
                msgs.iter().any(|m| m[0] == "CLOSED"
                    && m[1] == "sub"
                    && m[2] == "error: database unavailable; retry"),
                "a failed REQ must be closed with a retryable reason"
            );
            assert!(
                !conn.subs.contains_key("sub"),
                "the subscription must be released on a timed-out query"
            );
            assert!(
                conn.pending_reqs.is_empty(),
                "the failed REQ's pending request must be released"
            );
            assert!(
                !msgs.iter().any(|m| m[0] == "EVENT" && m[1] == "sub"),
                "no events may be delivered for the closed subscription"
            );
            // A live event published afterwards must not reach the closed
            // sub (deliver_live reads `self.subs`).
            let e2 = signed_note(conn.relay.secp(), "late", now + 1, vec![]);
            conn.deliver_live(&e2, &serde_json::to_string(&e2).unwrap_or_default(), None);
            assert!(
                !outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "EVENT" && m[1] == "sub"),
                "live delivery must stop for the released subscription"
            );
        });
    }

    #[test]
    fn req_hides_protected_events_from_anonymous() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            let normal = signed_note(conn.relay.secp(), "public", now, vec![]);
            let protected = signed_note(conn.relay.secp(), "secret", now, vec![vec!["-".into()]]);
            conn.relay.db.put(normal.clone(), now).await;
            conn.relay.db.put(protected.clone(), now).await;
            conn.handle_req(&[json!("sub"), json!({"kinds": [1]})])
                .await;
            conn.pump_pending_reqs();
            let ids: Vec<String> = outgoing_json(&conn)
                .iter()
                .filter(|m| m[0] == "EVENT")
                .map(|m| m[2]["id"].as_str().unwrap().to_string())
                .collect();
            assert!(ids.contains(&normal.id));
            assert!(
                !ids.contains(&protected.id),
                "protected event must be hidden from anonymous"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn req_inbox_outbox_filters() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            let secp = conn.relay.secp();
            let alice_pk = XOnlyPublicKey::from_keypair(
                &Keypair::from_seckey_slice(secp, &[1u8; 32]).unwrap(),
            )
            .0
            .to_string();
            let bob_pk = XOnlyPublicKey::from_keypair(
                &Keypair::from_seckey_slice(secp, &[2u8; 32]).unwrap(),
            )
            .0
            .to_string();
            let alice_plain = signed_note_seeded(secp, 1, "alice plain", now, vec![]);
            let alice_to_bob = signed_note_seeded(
                secp,
                1,
                "alice to bob",
                now - 1,
                vec![vec!["p".into(), bob_pk.clone()]],
            );
            let bob_to_alice = signed_note_seeded(
                secp,
                2,
                "bob to alice",
                now - 2,
                vec![vec!["p".into(), alice_pk.clone()]],
            );
            for e in [&alice_plain, &alice_to_bob, &bob_to_alice] {
                conn.relay.db.put(e.clone(), now).await;
            }

            // outbox: only the events authored by the pubkey.
            conn.handle_req(&[json!("o"), json!({"outbox": alice_pk})])
                .await;
            conn.pump_pending_reqs();
            let contents: Vec<String> = outgoing_json(&conn)
                .iter()
                .filter(|m| m[0] == "EVENT" && m[1] == "o")
                .map(|m| m[2]["content"].as_str().unwrap().to_string())
                .collect();
            assert!(contents.contains(&"alice plain".to_string()));
            assert!(contents.contains(&"alice to bob".to_string()));
            assert!(
                !contents.contains(&"bob to alice".to_string()),
                "outbox must not return other authors"
            );

            // inbox: only the events addressed to the pubkey (#p tag).
            conn.handle_req(&[json!("i"), json!({"inbox": alice_pk})])
                .await;
            conn.pump_pending_reqs();
            let contents: Vec<String> = outgoing_json(&conn)
                .iter()
                .filter(|m| m[0] == "EVENT" && m[1] == "i")
                .map(|m| m[2]["content"].as_str().unwrap().to_string())
                .collect();
            assert_eq!(contents, vec!["bob to alice".to_string()]);

            // Combined: events by Bob addressed to Alice.
            conn.handle_req(&[json!("io"), json!({"outbox": bob_pk, "inbox": alice_pk})])
                .await;
            conn.pump_pending_reqs();
            let contents: Vec<String> = outgoing_json(&conn)
                .iter()
                .filter(|m| m[0] == "EVENT" && m[1] == "io")
                .map(|m| m[2]["content"].as_str().unwrap().to_string())
                .collect();
            assert_eq!(contents, vec!["bob to alice".to_string()]);

            // An invalid pubkey rejects the whole subscription.
            conn.handle_req(&[json!("bad"), json!({"outbox": "not-a-pubkey"})])
                .await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "CLOSED" && m[1] == "bad"),
                "an invalid outbox value must reject the subscription"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn auth_grants_protected_event_visibility() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            let protected = signed_note(conn.relay.secp(), "secret", now, vec![vec!["-".into()]]);
            conn.relay.db.put(protected.clone(), now).await;
            // AUTH with a valid event for this connection's challenge.
            let auth = signed_auth(conn.relay.secp(), "test-challenge", now);
            conn.handle_auth(&[serde_json::to_value(&auth).unwrap()])
                .await;
            assert!(conn.is_authed());
            conn.handle_req(&[json!("sub"), json!({"kinds": [1]})])
                .await;
            conn.pump_pending_reqs();
            let ids: Vec<String> = outgoing_json(&conn)
                .iter()
                .filter(|m| m[0] == "EVENT")
                .map(|m| m[2]["id"].as_str().unwrap().to_string())
                .collect();
            assert!(
                ids.contains(&protected.id),
                "authed client sees protected events"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn auth_disabled_still_answers_ok() {
        // NIP-42: client AUTH MUST be answered with OK even when the relay
        // has NIP-42 disabled.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            {
                let mut w = conn.relay.config.write().await;
                w.relay.disabled_nips.push(42);
            }
            let now = unix_now();
            let auth = signed_auth(conn.relay.secp(), "test-challenge", now);
            conn.handle_auth(&[serde_json::to_value(&auth).unwrap()])
                .await;
            let msgs = outgoing_json(&conn);
            assert!(
                msgs.iter()
                    .any(|m| m[0] == "OK" && m[1] == auth.id && m[2] == false),
                "disabled AUTH must still answer OK false: {msgs:?}"
            );
            assert!(!conn.is_authed(), "disabled AUTH must not authenticate");
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn close_and_neg_close_use_separate_namespaces() {
        // NIP-77: CLOSE releases only REQ, NEG-CLOSE only NEG.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            conn.handle_req(&[json!("s"), json!({"kinds": [1]})]).await;
            conn.handle_neg_open(&[json!("s"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            assert!(conn.subs.contains_key("s"));
            assert!(conn.neg.contains_key("s"));
            conn.handle_close(&[json!("s")]);
            assert!(
                !conn.subs.contains_key("s"),
                "CLOSE must release the REQ sub"
            );
            assert!(
                conn.neg.contains_key("s"),
                "CLOSE must leave NEG state untouched"
            );
            conn.handle_neg_close(&[json!("s")]);
            assert!(
                !conn.neg.contains_key("s"),
                "NEG-CLOSE must release the NEG state"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn count_applies_visibility_to_protected_events() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            conn.relay
                .db
                .put(signed_note(conn.relay.secp(), "public", now, vec![]), now)
                .await;
            conn.relay
                .db
                .put(
                    signed_note(conn.relay.secp(), "secret", now, vec![vec!["-".into()]]),
                    now,
                )
                .await;
            conn.handle_count(&[json!("c"), json!({"kinds": [1]})])
                .await;
            let msgs = outgoing_json(&conn);
            let count = msgs
                .iter()
                .find(|m| m[0] == "COUNT")
                .expect("a COUNT response is sent");
            assert_eq!(
                count[2]["count"].as_u64(),
                Some(1),
                "protected events are not counted for anonymous"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn count_ignores_filter_limit_zero() {
        // Documented NIP-45 divergence: COUNT counts the match set and has
        // no pagination, so `limit` (including `limit: 0`) does not bound
        // the count — unlike REQ, where `limit: 0` is an empty page.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            for i in 0..3 {
                let ev = signed_note(conn.relay.secp(), &format!("e{i}"), now - i, vec![]);
                conn.relay.db.put(ev, now).await;
            }
            conn.handle_count(&[json!("c"), json!({"kinds": [1], "limit": 0})])
                .await;
            let count = outgoing_json(&conn)
                .into_iter()
                .find(|m| m[0] == "COUNT")
                .expect("a COUNT response is sent");
            assert_eq!(
                count[2]["count"].as_u64(),
                Some(3),
                "COUNT ignores limit:0 and reports every match"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn count_database_failure_is_closed_not_zero() {
        // A failed scan must never be reported as `{"count": 0}`: the
        // client cannot distinguish that from an empty match set. NIP-45
        // refuses with a CLOSED, here retryable, and the same-id REQ
        // subscription (if any) is released with it.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            let ev = signed_note(conn.relay.secp(), "present", now, vec![]);
            conn.relay.db.put(ev, now).await;
            conn.relay.db.shutdown();
            conn.handle_count(&[json!("c"), json!({"kinds": [1]})])
                .await;
            let msgs = outgoing_json(&conn);
            let closed = msgs
                .iter()
                .find(|m| m[0] == "CLOSED" && m[1] == "c")
                .expect("a failed COUNT must be closed");
            assert_eq!(
                closed[2],
                json!("error: database unavailable; retry"),
                "the CLOSED must carry a retryable database reason"
            );
            assert!(
                !msgs.iter().any(|m| m[0] == "COUNT"),
                "a failed scan must not be answered as a zero count"
            );
            assert!(
                !conn.subs.contains_key("c"),
                "the CLOSED releases any same-id REQ subscription"
            );
        });
    }

    #[test]
    fn req_hides_nip78_events_from_anonymous_and_nonowners() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay_with("").await;
            let mut conn = build_conn_on(relay.clone()).await;
            let now = unix_now();
            let normal = signed_note(relay.secp(), "public", now, vec![]);
            // NIP-78 app-specific event authored by the seed-2 key (the key
            // that `signed_auth` authenticates as).
            let mut app = signed_note_seeded(
                relay.secp(),
                2,
                "app-specific",
                now,
                vec![vec!["d".into(), "profile".into()]],
            );
            app.kind = 30078;
            app.id = crate::nips::nip01::compute_id(&app);
            relay.db.put(normal.clone(), now).await;
            relay.db.put(app.clone(), now).await;

            conn.handle_req(&[json!("sub"), json!({"kinds": [1, 30078]})])
                .await;
            conn.pump_pending_reqs();
            let ids: Vec<String> = outgoing_json(&conn)
                .iter()
                .filter(|m| m[0] == "EVENT")
                .map(|m| m[2]["id"].as_str().unwrap().to_string())
                .collect();
            assert!(ids.contains(&normal.id));
            assert!(
                !ids.contains(&app.id),
                "NIP-78 event must be hidden from an anonymous client"
            );

            // The owner sees its own app-specific event.
            let mut owner = build_conn_on(relay.clone()).await;
            let auth = signed_auth(relay.secp(), "test-challenge", now);
            owner
                .handle_auth(&[serde_json::to_value(&auth).unwrap()])
                .await;
            assert!(owner.is_authed());
            owner
                .handle_req(&[json!("sub"), json!({"kinds": [30078]})])
                .await;
            owner.pump_pending_reqs();
            assert!(
                outgoing_json(&owner)
                    .iter()
                    .any(|m| m[0] == "EVENT" && m[2]["id"] == app.id),
                "the authenticated owner sees its own NIP-78 event"
            );

            // A third party authenticated with a different key does not.
            let mut other = build_conn_on(relay).await;
            let auth = signed_auth_seeded(other.relay.secp(), 3, "test-challenge", now);
            other
                .handle_auth(&[serde_json::to_value(&auth).unwrap()])
                .await;
            assert!(other.is_authed());
            other
                .handle_req(&[json!("sub"), json!({"kinds": [30078]})])
                .await;
            other.pump_pending_reqs();
            assert!(
                !outgoing_json(&other)
                    .iter()
                    .any(|m| m[0] == "EVENT" && m[2]["id"] == app.id),
                "an authenticated non-owner must not see the NIP-78 event"
            );

            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn count_applies_visibility_to_nip78_events() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            conn.relay
                .db
                .put(signed_note(conn.relay.secp(), "public", now, vec![]), now)
                .await;
            let mut app = signed_note(conn.relay.secp(), "app", now, vec![]);
            app.kind = 30078;
            app.id = crate::nips::nip01::compute_id(&app);
            conn.relay.db.put(app, now).await;
            conn.handle_count(&[json!("c"), json!({"kinds": [1, 30078]})])
                .await;
            let msgs = outgoing_json(&conn);
            let count = msgs
                .iter()
                .find(|m| m[0] == "COUNT")
                .expect("a COUNT response is sent");
            assert_eq!(
                count[2]["count"].as_u64(),
                Some(1),
                "NIP-78 events are not counted for anonymous"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn publish_requires_auth_for_nip78_events() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay_with("").await;
            let mut conn = build_conn_on(relay.clone()).await;
            let now = unix_now();
            for kind in [78, 30078] {
                let mut ev = signed_note(relay.secp(), "app", now, vec![]);
                ev.kind = kind;
                ev.id = crate::nips::nip01::compute_id(&ev);
                conn.queue_event_value(ev.clone()).await;
                conn.flush_pending_events().await;
                assert!(
                    !outgoing_json(&conn)
                        .iter()
                        .any(|m| m[0] == "OK" && m[1] == ev.id && m[2] == true),
                    "kind {kind} must be rejected on an anonymous connection"
                );
            }

            // The AUTH'd author can publish its own app-specific event.
            let mut owner = build_conn_on(relay).await;
            let auth = signed_auth(owner.relay.secp(), "test-challenge", now);
            owner
                .handle_auth(&[serde_json::to_value(&auth).unwrap()])
                .await;
            let app = signed_kind_note_seeded(
                owner.relay.secp(),
                2,
                78,
                "owner-app",
                now,
                vec![vec!["d".into(), "profile".into()]],
            );
            owner.queue_event_value(app.clone()).await;
            owner.flush_pending_events().await;
            assert!(
                outgoing_json(&owner)
                    .iter()
                    .any(|m| m[0] == "OK" && m[1] == app.id && m[2] == true),
                "an authenticated client may publish kind 78"
            );

            conn.relay.db.shutdown();
        });
    }

    /// Hex pubkey of a secret key (hex), for tests that act as the admin.
    fn pubkey_of_secret(secp: &Secp256k1<secp256k1::All>, secret_hex: &str) -> String {
        let secret = hex::decode(secret_hex).unwrap();
        let keypair = Keypair::from_seckey_slice(secp, &secret).unwrap();
        XOnlyPublicKey::from_keypair(&keypair).0.to_string()
    }

    /// A kind:1 event signed with an explicit secret key (hex), so a test
    /// can publish "as the admin" (relay.pubkey holder).
    fn signed_command_event(
        secp: &Secp256k1<secp256k1::All>,
        secret_hex: &str,
        content: &str,
        created: u64,
    ) -> Event {
        let secret = hex::decode(secret_hex).unwrap();
        let keypair = Keypair::from_seckey_slice(secp, &secret).unwrap();
        let pubkey = XOnlyPublicKey::from_keypair(&keypair).0.to_string();
        let mut ev = Event {
            id: String::new(),
            pubkey,
            created_at: created,
            kind: 1,
            tags: Vec::new(),
            content: content.into(),
            sig: String::new(),
        };
        sign(&mut ev, &keypair, secp).unwrap();
        ev
    }

    /// Stored kind:1111 events matching the `e` tag.
    async fn stored_replies(relay: &Arc<Relay>, e_tag: &str, now: u64) -> Vec<Event> {
        let f: Vec<crate::filter::Filter> = serde_json::from_value(serde_json::json!([
            { "kinds": [1111], "#e": [e_tag] }
        ]))
        .unwrap();
        let (events, _) = relay.db.query_req(f, 500, now).await;
        events
    }

    #[test]
    fn group_join_requires_a_stored_invite() {
        // On a CLOSED group, a JOIN with an invite code is only admitted
        // while a stored, undeleted 9009 backs the code: revoking the
        // 9009 (NIP-09) must take effect immediately, even though the
        // in-memory invite set still holds the code.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay_with("").await;
            let mut conn = build_conn_on(relay.clone()).await;
            let now = unix_now();
            let code = "abc123";

            // Create the group, close it, issue the invite, and join
            // with the code.
            let create = signed_kind_note_seeded(
                relay.secp(),
                1,
                crate::nips::nip29::CREATE_GROUP,
                "",
                now,
                vec![vec!["h".into(), "g1".into()]],
            );
            let close = signed_kind_note_seeded(
                relay.secp(),
                1,
                9002,
                "",
                now,
                vec![vec!["h".into(), "g1".into()], vec!["closed".into()]],
            );
            let invite = signed_kind_note_seeded(
                relay.secp(),
                1,
                9009,
                "",
                now,
                vec![
                    vec!["h".into(), "g1".into()],
                    vec!["code".into(), code.into()],
                ],
            );
            let join = signed_kind_note_seeded(
                relay.secp(),
                2,
                crate::nips::nip29::JOIN,
                "",
                now,
                vec![
                    vec!["h".into(), "g1".into()],
                    vec!["code".into(), code.into()],
                ],
            );
            for ev in [&create, &close, &invite, &join] {
                conn.queue_event_value(ev.clone()).await;
                conn.flush_pending_events().await;
                assert!(
                    outgoing_json(&conn)
                        .iter()
                        .any(|m| m[0] == "OK" && m[1] == ev.id && m[2] == true),
                    "the create/close/invite/join sequence is accepted"
                );
            }

            // Revoke the invite by deleting its 9009.
            let deletion = signed_kind_note_seeded(
                relay.secp(),
                1,
                crate::nips::nip09::DELETION_KIND,
                "",
                now + 1,
                vec![vec!["e".into(), invite.id.clone()]],
            );
            conn.queue_event_value(deletion.clone()).await;
            conn.flush_pending_events().await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "OK" && m[1] == deletion.id && m[2] == true),
                "the deletion is accepted"
            );

            // A different pubkey joining with the revoked code is refused,
            // even though the in-memory invite set still holds the code.
            let join2 = signed_kind_note_seeded(
                relay.secp(),
                3,
                crate::nips::nip29::JOIN,
                "",
                now,
                vec![
                    vec!["h".into(), "g1".into()],
                    vec!["code".into(), code.into()],
                ],
            );
            conn.queue_event_value(join2.clone()).await;
            conn.flush_pending_events().await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "OK" && m[1] == join2.id && m[2] == false),
                "a revoked invite code must not admit a join"
            );

            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn allowed_authors_posts_stay_readable_on_write_restricted_relays() {
        // End-to-end: with
        // `restrict_relay = true` + an allow list, the allowed author's
        // posts must remain readable by anonymous and non-listed readers
        // (the allow list is a write restriction, NIP-11
        // `restricted_writes`). Before the fix, anonymous readers were
        // refused entirely and the posts were unreadable.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay_with("").await;
            // The author of `signed_note` (seed 1) is the allowed pubkey.
            let author = {
                let keypair = Keypair::from_seckey_slice(relay.secp(), &[1u8; 32]).unwrap();
                XOnlyPublicKey::from_keypair(&keypair).0.to_string()
            };
            {
                let mut access = relay.access.write().await;
                access.restrict_relay = true;
                access.allowed_pubkeys.push((author.clone(), String::new()));
            }

            // The allowed author publishes.
            let mut author_conn = build_conn_on(relay.clone()).await;
            let note = signed_note(relay.secp(), "issue-61 note", unix_now(), vec![]);
            author_conn.queue_event_value(note.clone()).await;
            author_conn.flush_pending_events().await;
            assert!(
                outgoing_json(&author_conn)
                    .iter()
                    .any(|m| m[0] == "OK" && m[1] == note.id && m[2] == true),
                "the allowed author may publish"
            );

            // An anonymous reader sees the note (the reported symptom).
            let mut anon = build_conn_on(relay.clone()).await;
            anon.handle_req(&[json!("sub"), json!({"kinds": [1]})])
                .await;
            anon.pump_pending_reqs();
            let msgs = outgoing_json(&anon);
            assert!(
                !msgs.iter().any(|m| m[0] == "CLOSED"),
                "anonymous may subscribe on a write-restricted relay"
            );
            assert!(
                msgs.iter()
                    .any(|m| m[0] == "EVENT" && m[2]["id"] == note.id),
                "the anonymous reader receives the allowed author's post"
            );

            // A non-listed pubkey can read the post...
            let mut outsider = build_conn_on(relay.clone()).await;
            outsider
                .handle_req(&[json!("sub"), json!({"kinds": [1]})])
                .await;
            outsider.pump_pending_reqs();
            assert!(
                outgoing_json(&outsider)
                    .iter()
                    .any(|m| m[0] == "EVENT" && m[2]["id"] == note.id),
                "a non-listed pubkey can read the allowed author's post"
            );
            // ...but cannot publish (the write restriction stays).
            let outsider_note = signed_note_seeded(relay.secp(), 2, "outsider", unix_now(), vec![]);
            outsider.queue_event_value(outsider_note.clone()).await;
            outsider.flush_pending_events().await;
            assert!(
                !outgoing_json(&outsider)
                    .iter()
                    .any(|m| m[0] == "OK" && m[1] == outsider_note.id && m[2] == true),
                "a non-listed pubkey cannot publish (write restriction)"
            );

            relay.db.shutdown();
        });
    }

    #[test]
    fn command_events_edit_lists_and_reply_with_1111() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let secret = "aa".repeat(32);
            let relay = build_relay_with(&secret).await;
            relay.config.write().await.relay.pubkey = pubkey_of_secret(relay.secp(), &secret);
            relay.config.write().await.relay.enabled_command_events = true;
            let mut conn = build_conn_on(relay.clone()).await;
            let now = unix_now();
            let target = "bb".repeat(32);

            // relay allow: the access list changes immediately and the
            // change is persisted for the CLI/restart.
            let cmd = signed_command_event(
                relay.secp(),
                &secret,
                &format!("/relay allow {target}"),
                now,
            );
            conn.queue_event_value(cmd.clone()).await;
            conn.flush_pending_events().await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "OK" && m[1] == cmd.id && m[2] == true),
                "the command event is accepted"
            );
            assert!(
                relay
                    .access
                    .read()
                    .await
                    .allowed_pubkeys
                    .iter()
                    .any(|(p, _)| p == &target),
                "relay allow must add the pubkey to the allow list"
            );
            let (deny, allow) = relay.db.load_relay_pubkeys().await.unwrap_or_default();
            assert!(allow.iter().any(|(p, _)| p == &target));
            assert!(deny.is_empty());

            // The kind:1111 reply is stored, tagged to the command and
            // served publicly (no `-` tag): visible even without NIP-42.
            let replies = stored_replies(&relay, &cmd.id, now).await;
            assert_eq!(replies.len(), 1, "one reply per command");
            assert_eq!(replies[0].pubkey, relay.relay_pubkey().unwrap());
            assert!(
                replies[0]
                    .tags
                    .iter()
                    .all(|t| t.first().map(String::as_str) != Some("-")),
                "the reply must be public, not NIP-70 protected"
            );
            let admin = pubkey_of_secret(relay.secp(), &secret);
            assert!(
                replies[0]
                    .tags
                    .iter()
                    .any(|t| t == &vec!["p".into(), admin.clone()]),
                "the reply must mention the admin with a p tag"
            );
            assert!(
                replies[0]
                    .content
                    .contains(&format!("/relay allow {target}")),
                "reply content: {}",
                replies[0].content
            );

            // Re-dispatching the same accepted event must not repeat the
            // side effect or create a second response.
            relay.handle_command_event(&cmd).await;
            let replies = stored_replies(&relay, &cmd.id, now).await;
            assert_eq!(replies.len(), 1, "replayed command must stay idempotent");

            // relay deny: moves the pubkey from allow to deny (the `nostr:`
            // URI prefix is accepted on the operand).
            let cmd = signed_command_event(
                relay.secp(),
                &secret,
                &format!("/relay deny nostr:{target}"),
                now + 1,
            );
            conn.queue_event_value(cmd.clone()).await;
            conn.flush_pending_events().await;
            assert!(
                relay
                    .access
                    .read()
                    .await
                    .blocked_pubkeys
                    .iter()
                    .any(|(p, _)| p == &target),
                "relay deny must add the pubkey to the deny list"
            );
            assert!(
                !relay
                    .access
                    .read()
                    .await
                    .allowed_pubkeys
                    .iter()
                    .any(|(p, _)| p == &target),
                "relay deny must remove the pubkey from the allow list"
            );

            // blossom allow/deny edits the upload allowlist, persisted.
            let uploader = "cc".repeat(32);
            let cmd = signed_command_event(
                relay.secp(),
                &secret,
                &format!("/blossom allow {uploader}"),
                now + 2,
            );
            conn.queue_event_value(cmd.clone()).await;
            conn.flush_pending_events().await;
            assert!(
                relay
                    .blossom_allow
                    .read()
                    .await
                    .iter()
                    .any(|p| p == &uploader),
                "blossom allow must add the uploader"
            );
            assert!(
                relay
                    .db
                    .load_blossom_allow()
                    .await
                    .unwrap_or_default()
                    .contains(&uploader),
                "the blossom allowlist must be persisted"
            );
            let cmd = signed_command_event(
                relay.secp(),
                &secret,
                &format!("/blossom deny {uploader}"),
                now + 3,
            );
            conn.queue_event_value(cmd.clone()).await;
            conn.flush_pending_events().await;
            assert!(
                !relay.blossom_allow.read().await.contains(&uploader),
                "blossom deny must remove the uploader"
            );

            // An invalid operand gets an error reply, lists unchanged.
            let cmd = signed_command_event(relay.secp(), &secret, "/relay allow zzz", now + 4);
            conn.queue_event_value(cmd.clone()).await;
            conn.flush_pending_events().await;
            let replies = stored_replies(&relay, &cmd.id, now + 4).await;
            assert_eq!(replies.len(), 1);
            assert!(
                replies[0].content.starts_with("error: invalid pubkey"),
                "reply content: {}",
                replies[0].content
            );
            assert!(
                !relay
                    .access
                    .read()
                    .await
                    .allowed_pubkeys
                    .iter()
                    .any(|(p, _)| p == "zzz"),
                "an invalid command must not change the lists"
            );

            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn command_events_require_flag_and_owner_author() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let secret = "aa".repeat(32);
            let relay = build_relay_with(&secret).await; // flag defaults to false
            relay.config.write().await.relay.pubkey = pubkey_of_secret(relay.secp(), &secret);
            let mut conn = build_conn_on(relay.clone()).await;
            let now = unix_now();
            let target = "bb".repeat(32);

            // Flag off: the note is stored, but nothing is executed.
            let cmd = signed_command_event(
                relay.secp(),
                &secret,
                &format!("/relay allow {target}"),
                now,
            );
            conn.queue_event_value(cmd.clone()).await;
            conn.flush_pending_events().await;
            assert!(
                relay.access.read().await.allowed_pubkeys.is_empty(),
                "no list change while the flag is off"
            );
            assert!(stored_replies(&relay, &cmd.id, now).await.is_empty());

            // A different author cannot run commands even with the flag on.
            relay.config.write().await.relay.enabled_command_events = true;
            let impostor = signed_note(
                relay.secp(),
                &format!("/relay allow {target}"),
                now + 1,
                vec![],
            );
            conn.queue_event_value(impostor.clone()).await;
            conn.flush_pending_events().await;
            assert!(
                relay.access.read().await.allowed_pubkeys.is_empty(),
                "a non-owner cannot run commands"
            );
            assert!(
                stored_replies(&relay, &impostor.id, now + 1)
                    .await
                    .is_empty()
            );

            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn command_deny_applies_to_live_connections_immediately() {
        // A `/relay deny` command must take effect on an already-open
        // connection without disconnecting it: new REQs/COUNTs are refused
        // and live delivery stops, but the connection stays up.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let secret = "aa".repeat(32);
            let relay = build_relay_with(&secret).await;
            relay.config.write().await.relay.pubkey = pubkey_of_secret(relay.secp(), &secret);
            relay.config.write().await.relay.enabled_command_events = true;
            let mut operator = build_conn_on(relay.clone()).await;
            let victim = "cc".repeat(32);
            let mut victim_conn = build_conn_on(relay.clone()).await;
            victim_conn.authed_pubkeys = vec![victim.clone()];
            let now = unix_now();

            // The victim reads fine before the command...
            victim_conn
                .handle_req(&[json!("sub"), json!({"kinds": [1]})])
                .await;
            assert!(
                !outgoing_json(&victim_conn)
                    .iter()
                    .any(|m| m[0] == "CLOSED" && m[1] == "sub"),
                "the victim may subscribe before the deny"
            );

            // ...the operator runs /relay deny...
            let cmd =
                signed_command_event(relay.secp(), &secret, &format!("/relay deny {victim}"), now);
            operator.queue_event_value(cmd.clone()).await;
            operator.flush_pending_events().await;
            assert!(
                relay
                    .access
                    .read()
                    .await
                    .blocked_pubkeys
                    .iter()
                    .any(|(p, _)| p == &victim),
                "the deny is applied"
            );

            // Results queued before the deny are dropped by the pump...
            victim_conn.pump_pending_reqs();
            assert!(
                !outgoing_json(&victim_conn).iter().any(|m| m[0] == "EVENT"),
                "pre-deny REQ results are dropped after the deny"
            );

            // ...and the very same connection is refused new reads while
            // staying connected (no connection-level close is sent).
            victim_conn.outgoing.clear();
            victim_conn
                .handle_req(&[json!("sub2"), json!({"kinds": [1]})])
                .await;
            assert!(
                outgoing_json(&victim_conn).iter().any(|m| m[0] == "CLOSED"
                    && m[1] == "sub2"
                    && m[2].as_str().unwrap_or("").starts_with("restricted:")),
                "the new REQ is refused with restricted"
            );
            victim_conn
                .handle_count(&[json!("cnt"), json!({"kinds": [1]})])
                .await;
            assert!(
                outgoing_json(&victim_conn).iter().any(|m| m[0] == "CLOSED"
                    && m[1] == "cnt"
                    && m[2].as_str().unwrap_or("").starts_with("restricted:")),
                "the COUNT is refused with restricted"
            );
            victim_conn.outgoing.clear();
            let ev = signed_note(relay.secp(), "live", now + 1, vec![]);
            victim_conn.deliver_live(&ev, &serde_json::to_string(&ev).unwrap_or_default(), None);
            assert!(
                !outgoing_json(&victim_conn).iter().any(|m| m[0] == "EVENT"),
                "live delivery stops for the denied pubkey"
            );

            operator.relay.db.shutdown();
        });
    }

    #[test]
    fn restrict_relay_gates_writes_only() {
        // `restrict_relay` + the allow list gate WRITES only (NIP-11
        // `restricted_writes`): the allowed pubkey's posts stay readable
        // by everyone — anonymous connections, outsiders and the relay's
        // own key. Only a denied pubkey loses read access.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay_with(&"aa".repeat(32)).await;
            let allowed = "bb".repeat(32);
            let denied = "dd".repeat(32);
            {
                let mut access = relay.access.write().await;
                access.restrict_relay = true;
                access
                    .allowed_pubkeys
                    .push((allowed.clone(), String::new()));
                access.blocked_pubkeys.push((denied.clone(), String::new()));
            }

            // Anonymous readers are always admitted: the allow list is a
            // write restriction, not a read one.
            let mut anon = build_conn_on(relay.clone()).await;
            anon.handle_req(&[json!("sub"), json!({"kinds": [1]})])
                .await;
            anon.pump_pending_reqs();
            assert!(
                !outgoing_json(&anon).iter().any(|m| m[0] == "CLOSED"),
                "anonymous may read on a write-restricted relay"
            );

            // An authenticated outsider may read too.
            let mut outsider = build_conn_on(relay.clone()).await;
            outsider.authed_pubkeys = vec!["ee".repeat(32)];
            outsider
                .handle_req(&[json!("sub"), json!({"kinds": [1]})])
                .await;
            outsider.pump_pending_reqs();
            assert!(
                !outgoing_json(&outsider).iter().any(|m| m[0] == "CLOSED"),
                "an authenticated outsider may read on a write-restricted relay"
            );

            // A denied pubkey loses read access.
            let mut denier = build_conn_on(relay.clone()).await;
            denier.authed_pubkeys = vec![denied.clone()];
            denier
                .handle_req(&[json!("sub"), json!({"kinds": [1]})])
                .await;
            assert!(
                outgoing_json(&denier)
                    .iter()
                    .any(|m| m[0] == "CLOSED"
                        && m[2].as_str().unwrap_or("").starts_with("restricted:")),
                "a denied pubkey is refused reads"
            );

            // The relay's own pubkey is always admitted (the operator
            // reads command replies on restricted relays).
            let mut self_conn = build_conn_on(relay.clone()).await;
            self_conn.authed_pubkeys = vec![relay.relay_pubkey().unwrap()];
            self_conn
                .handle_req(&[json!("sub"), json!({"kinds": [1]})])
                .await;
            self_conn.pump_pending_reqs();
            assert!(
                !outgoing_json(&self_conn).iter().any(|m| m[0] == "CLOSED"),
                "the relay's own pubkey may subscribe on a restricted relay"
            );

            anon.relay.db.shutdown();
        });
    }

    #[test]
    fn command_events_work_on_restricted_relays() {
        // On a `restrict_relay` relay the allow list gates publishing only
        // (reading stays open) — and the relay's own pubkey is exempt
        // from the lists, so command events still run and the reply
        // stays readable.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let secret = "aa".repeat(32);
            let relay = build_relay_with(&secret).await;
            relay.config.write().await.relay.pubkey = pubkey_of_secret(relay.secp(), &secret);
            relay.config.write().await.relay.enabled_command_events = true;
            {
                let mut access = relay.access.write().await;
                access.restrict_relay = true;
            }
            let mut conn = build_conn_on(relay.clone()).await;
            conn.authed_pubkeys = vec![relay.relay_pubkey().unwrap()];
            let now = unix_now();
            let target = "bb".repeat(32);

            let cmd = signed_command_event(
                relay.secp(),
                &secret,
                &format!("/relay allow {target}"),
                now,
            );
            conn.queue_event_value(cmd.clone()).await;
            conn.flush_pending_events().await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "OK" && m[1] == cmd.id && m[2] == true),
                "the command event is accepted on a restricted relay"
            );
            assert!(
                relay
                    .access
                    .read()
                    .await
                    .allowed_pubkeys
                    .iter()
                    .any(|(p, _)| p == &target),
                "the allow is applied"
            );
            let replies = stored_replies(&relay, &cmd.id, now).await;
            assert_eq!(replies.len(), 1, "the reply is stored");
            assert!(
                replies[0]
                    .content
                    .contains(&format!("/relay allow {target}")),
                "reply content: {}",
                replies[0].content
            );

            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn live_delivery_hides_nip78_events() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay_with("").await;
            let mut conn = build_conn_on(relay.clone()).await;
            let now = unix_now();
            conn.handle_req(&[json!("sub"), json!({"kinds": [30078]})])
                .await;
            assert!(conn.live.is_some(), "REQ must subscribe to live events");

            let ev = signed_kind_note_seeded(relay.secp(), 2, 30078, "live-app", now, vec![]);
            assert!(relay.broadcast(ev.clone()).await.is_ok());
            let received = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                conn.live.as_mut().unwrap().recv(),
            )
            .await;
            match received {
                Ok(Some(_batch)) => {
                    conn.deliver_live(&ev, &serde_json::to_string(&ev).unwrap_or_default(), None);
                    assert!(
                        !outgoing_json(&conn)
                            .iter()
                            .any(|m| m[0] == "EVENT" && m[2]["id"] == ev.id),
                        "deliver_live must hide NIP-78 events from anonymous"
                    );
                }
                other => panic!("live bus did not deliver: {other:?}"),
            }

            // The authenticated owner receives its own live app-specific event.
            let mut owner = build_conn_on(relay.clone()).await;
            let auth = signed_auth(owner.relay.secp(), "test-challenge", now);
            owner
                .handle_auth(&[serde_json::to_value(&auth).unwrap()])
                .await;
            owner
                .handle_req(&[json!("sub"), json!({"kinds": [30078]})])
                .await;
            // The stored response (here empty) is pumped before any live
            // event: pulling it through the pump mirrors the connection loop
            // and leaves the subscription in its EOSE-sent state.
            owner.pump_pending_reqs();
            assert!(relay.broadcast(ev.clone()).await.is_ok());
            let received = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                owner.live.as_mut().unwrap().recv(),
            )
            .await;
            match received {
                Ok(Some(_batch)) => {
                    owner.deliver_live(&ev, &serde_json::to_string(&ev).unwrap_or_default(), None);
                    assert!(
                        outgoing_json(&owner)
                            .iter()
                            .any(|m| m[0] == "EVENT" && m[2]["id"] == ev.id),
                        "the owner receives its own live NIP-78 event"
                    );
                }
                other => panic!("live bus did not deliver: {other:?}"),
            }

            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn expired_ephemeral_events_are_not_delivered_live() {
        // NIP-40: an expiration tag means the event must not be relayed
        // after that time, ephemeral kind or not. The ephemeral exemption
        // only keeps such events out of storage.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            conn.subs
                .insert("s".into(), (vec![Filter::default()], 0, "\"s\"".into()));

            let expired = signed_kind_note_seeded(
                conn.relay.secp(),
                1,
                20001,
                "expired",
                now - 10,
                vec![vec!["expiration".into(), (now - 1).to_string()]],
            );
            // `deliver_live_at` takes the batch timestamp: pin it to the
            // test's `now` so the expiry boundary is deterministic rather
            // than sampled from the wall clock mid-test.
            conn.deliver_live_at(
                &expired,
                &serde_json::to_string(&expired).unwrap_or_default(),
                None,
                now,
            );
            assert!(
                !outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "EVENT" && m[2]["id"] == expired.id),
                "an expired ephemeral event must not be delivered live"
            );

            let alive = signed_kind_note_seeded(
                conn.relay.secp(),
                1,
                20001,
                "alive",
                now,
                vec![vec!["expiration".into(), (now + 3_600).to_string()]],
            );
            conn.deliver_live_at(
                &alive,
                &serde_json::to_string(&alive).unwrap_or_default(),
                None,
                now,
            );
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "EVENT" && m[2]["id"] == alive.id),
                "a not-yet-expired ephemeral event is still delivered"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn inbox_outbox_write_policies() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let now = unix_now();
            let some_pk = "cc".repeat(32);

            // /inbox with the default "any" policy: a p tag is required.
            let mut conn = build_conn().await;
            conn.path = "/inbox".into();
            let secp = conn.relay.secp();
            let addressed = signed_note_seeded(
                secp,
                1,
                "addressed",
                now,
                vec![vec!["p".into(), some_pk.clone()]],
            );
            let plain = signed_note_seeded(secp, 1, "plain", now - 1, vec![]);
            conn.queue_event_value(addressed.clone()).await;
            conn.queue_event_value(plain.clone()).await;
            conn.flush_pending_events().await;
            let msgs = outgoing_json(&conn);
            let ok_of = |id: &str| {
                msgs.iter()
                    .find(|m| m[0] == "OK" && m[1] == id)
                    .cloned()
                    .unwrap()
            };
            assert_eq!(
                ok_of(&addressed.id)[2],
                true,
                "a p-tagged event is accepted"
            );
            assert_eq!(ok_of(&plain.id)[2], false, "an untagged event is rejected");
            assert!(
                ok_of(&plain.id)[3]
                    .as_str()
                    .unwrap_or("")
                    .contains("restricted"),
                "the rejection is machine-readable"
            );
            conn.relay.db.shutdown();

            // /inbox with the "relay" policy: only events p-tagging the
            // relay's own pubkey are accepted.
            let mut conn = build_conn_with(&hex::encode([7u8; 32])).await;
            conn.path = "/inbox".into();
            conn.relay.config.write().await.server.inbox_write_policy = "relay".into();
            conn.refresh_config_cache().await;
            let relay_pk = conn.relay.relay_pubkey().unwrap();
            let secp = conn.relay.secp();
            let to_relay =
                signed_note_seeded(secp, 1, "to relay", now, vec![vec!["p".into(), relay_pk]]);
            let to_other = signed_note_seeded(
                secp,
                1,
                "to other",
                now - 1,
                vec![vec!["p".into(), some_pk]],
            );
            conn.queue_event_value(to_relay.clone()).await;
            conn.queue_event_value(to_other.clone()).await;
            conn.flush_pending_events().await;
            let msgs = outgoing_json(&conn);
            let ok_of = |id: &str| {
                msgs.iter()
                    .find(|m| m[0] == "OK" && m[1] == id)
                    .cloned()
                    .unwrap()
            };
            assert_eq!(ok_of(&to_relay.id)[2], true);
            assert_eq!(ok_of(&to_other.id)[2], false);
            conn.relay.db.shutdown();

            // /outbox: NIP-42 auth is required and the event must be the
            // authenticated user's own.
            let mut conn = build_conn().await;
            conn.path = "/outbox".into();
            let secp = conn.relay.secp().clone();
            let mine = signed_note_seeded(&secp, 2, "mine", now, vec![]);
            let others = signed_note_seeded(&secp, 1, "theirs", now - 1, vec![]);
            conn.queue_event_value(mine.clone()).await;
            conn.flush_pending_events().await;
            let msgs = outgoing_json(&conn);
            assert!(
                msgs.iter()
                    .any(|m| m[0] == "OK" && m[1] == mine.id && m[2] == false),
                "unauthenticated writes are rejected"
            );
            // Authenticate as the key-2 author and retry.
            conn.outgoing.clear();
            let auth = signed_auth(&secp, "test-challenge", now);
            conn.handle_auth(&[serde_json::to_value(&auth).unwrap()])
                .await;
            assert!(conn.is_authed());
            conn.queue_event_value(mine.clone()).await;
            conn.queue_event_value(others.clone()).await;
            conn.flush_pending_events().await;
            let msgs = outgoing_json(&conn);
            let ok_of = |id: &str| {
                msgs.iter()
                    .find(|m| m[0] == "OK" && m[1] == id)
                    .cloned()
                    .unwrap()
            };
            assert_eq!(ok_of(&mine.id)[2], true, "own authed events are accepted");
            assert_eq!(
                ok_of(&others.id)[2],
                false,
                "another author's event is rejected"
            );
            conn.relay.db.shutdown();

            // /outbox with the "relay" policy: only the relay's own events.
            let mut conn = build_conn_with(&hex::encode([7u8; 32])).await;
            conn.path = "/outbox".into();
            conn.relay.config.write().await.server.outbox_write_policy = "relay".into();
            conn.refresh_config_cache().await;
            let relay_pk = conn.relay.relay_pubkey().unwrap();
            let secp = conn.relay.secp().clone();
            let relay_event = signed_note_seeded(&secp, 7, "relay event", now, vec![]);
            let user_event = signed_note_seeded(&secp, 1, "user event", now - 1, vec![]);
            assert_eq!(relay_event.pubkey, relay_pk, "seed 7 is the relay key");
            conn.queue_event_value(relay_event.clone()).await;
            conn.queue_event_value(user_event.clone()).await;
            conn.flush_pending_events().await;
            let msgs = outgoing_json(&conn);
            let ok_of = |id: &str| {
                msgs.iter()
                    .find(|m| m[0] == "OK" && m[1] == id)
                    .cloned()
                    .unwrap()
            };
            assert_eq!(
                ok_of(&relay_event.id)[2],
                true,
                "the relay's own event is accepted without auth"
            );
            assert_eq!(
                ok_of(&user_event.id)[2],
                false,
                "another author's event is rejected in relay mode"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn ephemeral_events_rejected_via_ws_when_configured() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let now = unix_now();
            // Default config: ephemeral forwarded (accepted, not stored).
            let mut conn = build_conn().await;
            let ephemeral = signed_note_seeded(conn.relay.secp(), 1, "ephemeral", now, vec![]);
            let mut ev = ephemeral.clone();
            ev.kind = 20000;
            ev.id = crate::nips::nip01::compute_id(&ev);
            let id = ev.id_bytes().unwrap();
            ev.sig = conn
                .relay
                .secp()
                .sign_schnorr_no_aux_rand(
                    &id,
                    &Keypair::from_seckey_slice(conn.relay.secp(), &[1u8; 32]).unwrap(),
                )
                .to_string();
            conn.queue_event_value(ev.clone()).await;
            conn.flush_pending_events().await;
            let msgs = outgoing_json(&conn);
            let ok = msgs.iter().find(|m| m[0] == "OK" && m[1] == ev.id).unwrap();
            assert_eq!(ok[2], true, "ephemeral must be forwarded when not rejected");
            assert_eq!(
                ok[3].as_str().unwrap_or(""),
                "",
                "an accepted ephemeral must not carry the `mute:` prefix"
            );
            conn.relay.db.shutdown();

            // With reject_ephemeral = true via SIGHUP-like reload.
            let mut conn = build_conn().await;
            conn.relay.config.write().await.relay.reject_ephemeral = true;
            let ephemeral2 = {
                let mut e = signed_note_seeded(conn.relay.secp(), 1, "ephemeral2", now, vec![]);
                e.kind = 25000;
                e.id = crate::nips::nip01::compute_id(&e);
                let id = e.id_bytes().unwrap();
                e.sig = conn
                    .relay
                    .secp()
                    .sign_schnorr_no_aux_rand(
                        &id,
                        &Keypair::from_seckey_slice(conn.relay.secp(), &[1u8; 32]).unwrap(),
                    )
                    .to_string();
                e
            };
            let exempt = {
                let mut e = signed_note_seeded(conn.relay.secp(), 1, "exempt", now, vec![]);
                e.kind = 27235; // NIP-98 HTTP auth — must stay allowed
                e.id = crate::nips::nip01::compute_id(&e);
                let id = e.id_bytes().unwrap();
                e.sig = conn
                    .relay
                    .secp()
                    .sign_schnorr_no_aux_rand(
                        &id,
                        &Keypair::from_seckey_slice(conn.relay.secp(), &[1u8; 32]).unwrap(),
                    )
                    .to_string();
                e
            };
            conn.queue_event_value(ephemeral2.clone()).await;
            conn.queue_event_value(exempt.clone()).await;
            conn.flush_pending_events().await;
            let msgs = outgoing_json(&conn);
            let ok_ephem = msgs
                .iter()
                .find(|m| m[0] == "OK" && m[1] == ephemeral2.id)
                .unwrap();
            assert_eq!(ok_ephem[2], false);
            assert!(
                ok_ephem[3].as_str().unwrap_or("").contains("ephemeral"),
                "rejected ephemeral must mention ephemeral"
            );
            let ok_exempt = msgs
                .iter()
                .find(|m| m[0] == "OK" && m[1] == exempt.id)
                .unwrap();
            assert_eq!(
                ok_exempt[2], true,
                "NIPs-exempt ephemeral (27235) must not be blocked"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn flush_pending_events_acks_each_outcome() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            let valid = signed_note(conn.relay.secp(), "ok", now, vec![]);
            let mut invalid = signed_note(conn.relay.secp(), "bad", now, vec![]);
            invalid.sig = "00".repeat(64);
            conn.queue_event_value(valid.clone()).await;
            conn.queue_event_value(invalid.clone()).await;
            conn.flush_pending_events().await;
            let msgs = outgoing_json(&conn);
            let oks: Vec<&Value> = msgs.iter().filter(|m| m[0] == "OK").collect();
            assert_eq!(oks.len(), 2);
            let by_id = |id: &str| oks.iter().find(|m| m[1] == id).copied().unwrap();
            assert_eq!(by_id(&valid.id)[2], true);
            assert_eq!(by_id(&invalid.id)[2], false);
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn req_rejects_too_many_filters() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let mut args = vec![json!("sub")];
            for _ in 0..25 {
                args.push(json!({"kinds": [1]}));
            }
            conn.handle_req(&args).await;
            let msgs = outgoing_json(&conn);
            assert!(
                msgs.iter().any(|m| m[0] == "CLOSED"
                    && m[2].as_str().unwrap_or("").contains("too many filters")),
                "too many filters must be refused with CLOSED"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn req_rejects_too_many_tag_values() {
        // Each tag value becomes one scan range and one live-match
        // comparison, so an unbounded `#e`/`#p` list is a CPU and memory
        // amplification vector; oversized filters are refused like
        // oversized ids/authors/kinds.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let values: Vec<String> = (0..crate::filter::MAX_FILTER_TAG_VALUES + 1)
                .map(|_| "a".repeat(64))
                .collect();
            conn.handle_req(&[json!("sub"), json!({"#e": values})])
                .await;
            let msgs = outgoing_json(&conn);
            assert!(
                msgs.iter()
                    .any(|m| m[0] == "CLOSED" && m[2].as_str().unwrap_or("").contains("too many")),
                "an oversized tag filter must be refused with CLOSED"
            );
            assert!(
                !conn.subs.contains_key("sub"),
                "the refused subscription must not be registered"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn req_replacement_is_allowed_at_the_subscription_cap() {
        // NIP-01: re-REQ with an existing id replaces the subscription, so
        // it must work even when the connection already holds the maximum
        // number of subscriptions.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let max = conn.relay.config.read().await.limits.max_subscriptions;
            for i in 0..max {
                conn.handle_req(&[json!(format!("s{i}")), json!({"kinds": [1]})])
                    .await;
            }
            assert_eq!(conn.subs.len(), max, "the cap is reached");

            // Replacing an existing subscription is accepted...
            conn.handle_req(&[json!("s0"), json!({"kinds": [2]})]).await;
            assert!(
                !outgoing_json(&conn).iter().any(|m| m[0] == "CLOSED"),
                "re-REQ of an existing id must replace, not be refused"
            );
            assert_eq!(conn.subs.len(), max, "a replacement adds no subscription");

            // ...while a genuinely new id is refused at the cap.
            conn.handle_req(&[json!("s-extra"), json!({"kinds": [1]})])
                .await;
            assert!(
                outgoing_json(&conn).iter().any(|m| m[0] == "CLOSED"
                    && m[1] == "s-extra"
                    && m[2]
                        .as_str()
                        .unwrap_or("")
                        .contains("too many subscriptions")),
                "a new subscription is refused at the cap"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn neg_open_counts_towards_the_req_subscription_cap() {
        // REQ and NEG-OPEN share one connection-wide `max_subscriptions`
        // budget (both count as active subscriptions in NIP-11 and the
        // stats): with the cap at 1, the first subscription must leave no
        // room for the second, whichever namespace it is in.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            {
                let mut cfg = conn.relay.config.write().await;
                cfg.limits.max_subscriptions = 1;
            }
            conn.handle_req(&[json!("req"), json!({"kinds": [1]})])
                .await;
            assert!(conn.subs.contains_key("req"));
            conn.outgoing.clear();
            conn.handle_neg_open(&[json!("neg"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            assert!(
                outgoing_json(&conn).iter().any(|m| m[0] == "NEG-ERR"
                    && m[2]
                        .as_str()
                        .unwrap_or("")
                        .contains("too many subscriptions")),
                "NEG-OPEN must not double the advertised subscription cap"
            );
            assert!(conn.neg.is_empty(), "the refused NEG must not be stored");

            // The reverse order too: a held NEG subscription blocks a new
            // REQ.
            conn.remove_req_subscription("req");
            conn.outgoing.clear();
            conn.handle_neg_open(&[json!("neg2"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            assert!(conn.neg.contains_key("neg2"));
            conn.outgoing.clear();
            conn.handle_req(&[json!("req2"), json!({"kinds": [1]})])
                .await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "CLOSED" && m[1] == "req2"),
                "a new REQ must respect the NEG-held subscription budget"
            );
            assert!(!conn.subs.contains_key("req2"));
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn req_failed_replacement_releases_the_old_subscription() {
        // A failed re-REQ (CLOSED) must release the previous subscription
        // held under the same id: otherwise the ghost keeps receiving live
        // events for a client-considered-closed id.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            conn.handle_req(&[json!("ghost"), json!({"kinds": [1]})])
                .await;
            assert!(conn.subs.contains_key("ghost"));
            conn.outgoing.clear();

            let mut args = vec![json!("ghost")];
            for _ in 0..25 {
                args.push(json!({"kinds": [1]}));
            }
            conn.handle_req(&args).await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "CLOSED" && m[1] == "ghost"),
                "the failed re-REQ must close the id"
            );
            assert!(
                !conn.subs.contains_key("ghost"),
                "the old subscription must be released"
            );

            // No live delivery for the closed id.
            let now = unix_now();
            let ev = signed_note(conn.relay.secp(), "live", now, vec![]);
            conn.deliver_live(&ev, &serde_json::to_string(&ev).unwrap_or_default(), None);
            assert!(
                !outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "EVENT" && m[1] == "ghost"),
                "a closed id must not receive live events"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn text_ping_is_answered_with_pong() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            conn.handle_text("[\"PING\"]").await;
            let msgs = outgoing_json(&conn);
            assert!(
                msgs.iter().any(|m| m[0] == "PONG"),
                "a text PING must be answered with a PONG"
            );
            conn.relay.db.shutdown();
        });
    }
    #[test]
    fn first_token_extracts_the_verb_without_a_parse() {
        assert_eq!(Conn::first_token("[\"EVENT\",{}]"), Some("EVENT"));
        assert_eq!(Conn::first_token("[ \"REQ\", \"s\", {}]"), Some("REQ"));
        assert_eq!(Conn::first_token("[\"PING\"]"), Some("PING"));
        assert_eq!(Conn::first_token("[\"EVENT\""), Some("EVENT"));
        assert_eq!(Conn::first_token("[123]"), None);
        assert_eq!(Conn::first_token("\"REQ\""), None);
        assert_eq!(Conn::first_token("not json"), None);
        assert_eq!(Conn::first_token(""), None);
    }

    #[test]
    fn event_dispatch_parses_once_and_queues() {
        // The hot path parses the EVENT frame directly as a typed pair
        // (single JSON pass) and queues it for batched acceptance.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let event = crate::event::Event {
                id: "0".repeat(64),
                pubkey: "ab".repeat(32),
                created_at: unix_now(),
                kind: 1,
                tags: vec![],
                content: "hello".into(),
                sig: "0".repeat(128),
            };
            let payload = format!("[\"EVENT\",{}]", serde_json::to_string(&event).unwrap());
            conn.handle_text(&payload).await;
            assert_eq!(conn.pending_events.len(), 1, "the event must be queued");
            assert_eq!(conn.pending_events[0].content, "hello");
            assert_eq!(conn.events_received_local, 1, "the local counter must bump");
            // A malformed EVENT falls back to the generic path and gets a
            // NOTICE, not a crash.
            conn.pending_events.clear();
            conn.handle_text("[\"EVENT\",{\"id\":1}]").await;
            assert!(conn.pending_events.is_empty());
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NOTICE" || m[0] == "OK"),
                "a malformed event must produce a diagnostic"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn live_delivery_closes_subs_on_deny_and_auth_flip() {
        // A ban or a `require_auth` flip mid-session must close the
        // starving subscriptions with the same CLOSED the REQ path sends,
        // instead of leaving them silent post-EOSE.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay_with("").await;
            let mut conn = build_conn_on(relay.clone()).await;
            let now = unix_now();
            // Authenticated subscription in its post-EOSE state.
            let authed = "aa".repeat(32);
            conn.authed_pubkeys.push(authed.clone());
            conn.handle_req(&[json!("sub"), json!({"kinds": [1]})])
                .await;
            assert!(conn.subs.contains_key("sub"));
            conn.outgoing.clear();
            // Banning the key mid-session: the next live event closes the
            // subscription instead of dropping silently.
            conn.relay
                .access
                .write()
                .await
                .blocked_pubkeys
                .push((authed, String::new()));
            let ev = signed_kind_note_seeded(relay.secp(), 3, 1, "live", now, vec![]);
            conn.deliver_live(&ev, &serde_json::to_string(&ev).unwrap_or_default(), None);
            let msgs = outgoing_json(&conn);
            assert!(
                msgs.iter().any(|m| m[0] == "CLOSED"
                    && m[1] == "sub"
                    && m[2].as_str().is_some_and(|r| r.contains("restricted"))),
                "a denied live sub must be closed like a denied REQ: {msgs:?}"
            );
            assert!(
                !msgs.iter().any(|m| m[0] == "EVENT"),
                "no event may be delivered to a denied sub"
            );
            assert!(conn.subs.is_empty(), "the denied sub must be released");
            relay.db.shutdown();
        });
        rt.block_on(async {
            let relay = build_relay_with("").await;
            let mut conn = build_conn_on(relay.clone()).await;
            let now = unix_now();
            // Anonymous subscription while auth is not required.
            conn.handle_req(&[json!("sub"), json!({"kinds": [1]})])
                .await;
            assert!(conn.subs.contains_key("sub"));
            conn.outgoing.clear();
            // Enabling `require_auth` (SIGHUP) cuts the anonymous live
            // stream; the refresh propagates the flip to the connection.
            conn.relay.config.write().await.relay.require_auth = true;
            conn.refresh_config_cache().await;
            let ev = signed_kind_note_seeded(relay.secp(), 4, 1, "live", now, vec![]);
            conn.deliver_live(&ev, &serde_json::to_string(&ev).unwrap_or_default(), None);
            let msgs = outgoing_json(&conn);
            assert!(
                msgs.iter().any(|m| m[0] == "CLOSED"
                    && m[1] == "sub"
                    && m[2].as_str().is_some_and(|r| r.contains("auth-required"))),
                "an anonymous live sub must be closed on a require_auth flip: {msgs:?}"
            );
            assert!(conn.subs.is_empty());
            relay.db.shutdown();
        });
    }

    #[test]
    fn max_message_size_refreshes_on_reload() {
        // `limits.max_ws_message_bytes` is refreshed with the other cached
        // budgets: an operator lowering it to shed oversized frames must
        // not have to wait for every existing connection to reconnect.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay_with("").await;
            let mut conn = build_conn_on(relay.clone()).await;
            let initial = conn.max_msg_size;
            assert!(initial > 0);
            relay.config.write().await.limits.max_ws_message_bytes = initial / 2;
            conn.refresh_config_cache().await;
            assert_eq!(
                conn.max_msg_size,
                initial / 2,
                "the reload must refresh the inbound frame size limit"
            );
            // The refreshed limit is what the frame path enforces.
            let oversized = Message::Text("x".repeat(initial / 2 + 1).into());
            assert!(
                conn.handle_frame(oversized, conn.max_msg_size).await,
                "a frame over the refreshed limit must close the connection"
            );
            relay.db.shutdown();
        });
    }

    #[test]
    fn deeply_nested_json_is_rejected_without_abort() {
        // serde_json enforces a recursion limit (default 128): a deeply
        // nested frame must fail parsing with a NOTICE, never abort the
        // process with a stack overflow (which `catch_unwind` could not
        // contain and which would kill every connection).
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let deep = format!("[\"REQ\",\"s\",{}]", "[".repeat(5000));
            conn.handle_text(&deep).await;
            assert!(
                outgoing_json(&conn).iter().any(|m| m[0] == "NOTICE"),
                "deep nesting must be rejected with a NOTICE: {:?}",
                outgoing_json(&conn)
            );
            // The connection survives and still serves normal requests.
            conn.outgoing.clear();
            conn.handle_req(&[json!("alive"), json!({"kinds": [1]})])
                .await;
            assert!(
                conn.subs.contains_key("alive"),
                "the connection must stay usable after a hostile frame"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn live_delivery_uses_shared_json_and_cached_sub_json() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            conn.handle_req(&[json!("sub"), json!({"kinds": [30002]})])
                .await;
            // Finish the stored response first: a live event delivered while
            // the response is pumping waits for its EOSE (by design), so the
            // shared-JSON wrapping is asserted after the pump.
            conn.pump_pending_reqs();
            // The sub id JSON is cached at REQ time.
            let cached = conn.subs.get("sub").map(|(_, _, j)| j.clone()).unwrap();
            assert_eq!(cached, "\"sub\"");
            let mut ev = signed_note(conn.relay.secp(), "shared-json", now, vec![]);
            ev.kind = 30002;
            ev.id = crate::nips::nip01::compute_id(&ev);
            // Deliver with a pre-serialized JSON (as the bus provides):
            // the wrapped message must embed exactly those bytes.
            let event_json = serde_json::to_string(&ev).unwrap();
            conn.deliver_live(&ev, &event_json, None);
            let msg = outgoing_json(&conn);
            assert!(
                msg.iter().any(|m| {
                    m[0] == "EVENT"
                        && m[1] == "sub"
                        && serde_json::to_string(&m[2]).unwrap() == event_json
                }),
                "the shared JSON must be wrapped per subscription"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn live_index_delivers_only_to_candidate_connections() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            // Two connections on the *same* relay: the candidate
            // narrowing is a property of the shared subscription index,
            // so building separate relays would prove nothing.
            let mut shared = Relay::new(
                Arc::new(RwLock::new(Config::default())),
                crate::db::DbClient::open(
                    &{
                        let mut cfg = Config::default();
                        cfg.database.path = temp_db_path();
                        cfg.database.map_size = 16 * 1024 * 1024;
                        cfg.database.max_map_size = 64 * 1024 * 1024;
                        cfg.database
                    },
                    true,
                    Arc::new(Default::default()),
                    0,
                    128,
                    4096,
                    262144,
                )
                .unwrap(),
                Stats::new(),
                "",
                crate::relay::LiveBusConfig {
                    buffer: 1024,
                    batch_interval_ms: 10,
                    batch_size: 64,
                },
            )
            .await;
            shared.start_live_bus();
            let shared = Arc::new(shared);
            let mut conn_a = build_conn_on(Arc::clone(&shared)).await;
            let mut conn_b = build_conn_on(Arc::clone(&shared)).await;
            let now = unix_now();
            conn_a
                .handle_req(&[json!("a"), json!({"kinds": [30001]})])
                .await;
            conn_b
                .handle_req(&[json!("b"), json!({"kinds": [1]})])
                .await;
            // Both connections are in the index (their kinds), but a
            // kind-30001 event's candidate set contains only conn_a.
            let mut ev = signed_note(conn_a.relay.secp(), "candidate-check", now, vec![]);
            ev.kind = 30001;
            ev.id = crate::nips::nip01::compute_id(&ev);
            assert!(conn_a.relay.broadcast(ev.clone()).await.is_ok());
            let received_a = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                conn_a.live.as_mut().unwrap().recv(),
            )
            .await
            .expect("the matching connection receives the batch")
            .expect("the live channel stays open");
            assert!(
                received_a.iter().any(|(e, _)| e.id == ev.id),
                "the delivered batch must contain the broadcast event"
            );
            // conn_b is not a delivery candidate for this event at all
            // (its subscription indexes kind 1), so the bus cannot wake it.
            // Asserting the candidate set is deterministic; the old 300 ms
            // receive timeout could pass vacuously when a delivery was
            // merely slow.
            let candidates = conn_a
                .relay
                .sub_index
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .candidates(&ev);
            assert!(
                candidates.contains(&conn_a.conn_id),
                "the matching connection must be a delivery candidate"
            );
            assert!(
                !candidates.contains(&conn_b.conn_id),
                "a non-matching connection must not be a delivery candidate"
            );
            conn_a.relay.db.shutdown();
        });
    }

    #[test]
    fn live_flags_refresh_only_on_config_version_change() {
        // The caches are refreshed only when the config version changed:
        // without a bump the stale value must survive (the hot paths never
        // re-read the config), while a bumped version must pick the new
        // config up. This mirrors the connection loop's gate.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let v0 = conn.config_version;
            assert!(
                conn.expiry_enabled,
                "NIP-40 is enabled by the default config"
            );
            // The config changes without a version bump: the cached flag
            // stays put (a refresh here would silently re-read on every
            // frame).
            conn.relay.config.write().await.relay.disabled_nips.push(40);
            assert!(
                conn.expiry_enabled,
                "the cache must not change without a config version bump"
            );
            // A bumped version refreshes every cached value.
            conn.relay
                .config_version
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let version = conn
                .relay
                .config_version
                .load(std::sync::atomic::Ordering::Relaxed);
            assert_ne!(version, v0, "the version must have been bumped");
            if version != conn.config_version {
                conn.config_version = version;
                conn.refresh_config_cache().await;
            }
            assert_eq!(conn.config_version, v0 + 1);
            assert!(
                !conn.expiry_enabled,
                "a bumped version must refresh the cached NIP-40 flag"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn live_delivery_through_the_bus() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            conn.handle_req(&[json!("sub"), json!({"kinds": [30001]})])
                .await;
            assert!(conn.live.is_some(), "REQ must subscribe to live events");
            // Finish the (empty) stored response before the live event: a
            // live event delivered while a response is pumping is held for
            // its EOSE, so the queue assertion needs the subscription in its
            // EOSE-sent state.
            conn.pump_pending_reqs();

            let mut ev = signed_note(conn.relay.secp(), "live-check", now, vec![]);
            ev.kind = 30001;
            ev.id = crate::nips::nip01::compute_id(&ev);
            // The relay broadcast path: queue, bus task, receiver, deliver.
            assert!(conn.relay.broadcast(ev.clone()).await.is_ok());
            let received = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                conn.live.as_mut().unwrap().recv(),
            )
            .await;
            match received {
                Ok(Some(batch)) => {
                    assert!(
                        batch.iter().any(|(e, _)| e.id == ev.id),
                        "the broadcast event must arrive on the live receiver"
                    );
                    conn.deliver_live(&ev, &serde_json::to_string(&ev).unwrap_or_default(), None);
                    let msgs = outgoing_json(&conn);
                    assert!(
                        msgs.iter()
                            .any(|m| m[0] == "EVENT" && m[2]["content"] == "live-check"),
                        "deliver_live must queue the event for the subscriber"
                    );
                }
                other => panic!("live bus did not deliver: {other:?}"),
            }
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn neg_open_error_paths() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;

            // NIP-77 disabled: NEG-ERR with the id (NIP-77 error path),
            // not a NOTICE — the client can correlate the failure.
            {
                let mut w = conn.relay.config.write().await;
                w.relay.disabled_nips.push(77);
            }
            conn.handle_neg_open(&[json!("s"), json!({}), json!("61000000")])
                .await;
            assert!(
                outgoing_json(&conn).iter().any(|m| m[0] == "NEG-ERR"
                    && m[1] == "s"
                    && m[2].as_str().unwrap().contains("not enabled")),
                "a disabled NIP-77 must yield a NEG-ERR"
            );
            conn.outgoing.clear();
            // Without an id there is nothing to correlate: NOTICE.
            conn.handle_neg_open(&[]).await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NOTICE" && m[1].as_str().unwrap().contains("not enabled")),
                "a disabled NIP-77 without id must yield a NOTICE"
            );
            conn.outgoing.clear();
            {
                let mut w = conn.relay.config.write().await;
                w.relay.disabled_nips.retain(|n| *n != 77);
            }

            // Malformed NEG-OPEN frames with an id correlate via NEG-ERR.
            conn.handle_neg_open(&[json!("s"), json!({})]).await;
            assert!(
                outgoing_json(&conn).iter().any(|m| m[0] == "NEG-ERR"
                    && m[1] == "s"
                    && m[2].as_str().unwrap().contains("NEG-OPEN")),
                "a short NEG-OPEN must yield a NEG-ERR"
            );
            conn.outgoing.clear();
            conn.handle_neg_open(&[json!(""), json!({}), json!("61000000")])
                .await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NOTICE" && m[1].as_str().unwrap().contains("non-empty")),
                "an empty sub id must yield a NOTICE"
            );
            conn.outgoing.clear();
            let max_sub = conn.relay.config.read().await.limits.max_sub_id_len;
            conn.handle_neg_open(&[json!("x".repeat(max_sub + 1)), json!({}), json!("61000000")])
                .await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NEG-ERR" && m[2].as_str().unwrap().contains("too long")),
                "an over-long sub id must yield a NEG-ERR"
            );
            conn.outgoing.clear();
            conn.handle_neg_open(&[json!("s"), json!({"inbox": 42}), json!("61000000")])
                .await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NEG-ERR" && m[2].as_str().unwrap().contains("filter")),
                "an invalid inbox/outbox filter must yield a NEG-ERR"
            );
            conn.outgoing.clear();
            conn.handle_neg_open(&[json!("s"), json!("not-a-filter"), json!("61000000")])
                .await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NEG-ERR" && m[2].as_str().unwrap().contains("filter")),
                "a non-filter JSON must yield a NEG-ERR"
            );
            conn.outgoing.clear();
            conn.handle_neg_open(&[
                json!("s"),
                json!({"ids": vec![json!("a".repeat(64)); 513]}),
                json!("61000000"),
            ])
            .await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NEG-ERR" && m[2].as_str().unwrap().contains("too many")),
                "a filter over the member cap must yield a NEG-ERR"
            );
            conn.outgoing.clear();
            conn.handle_neg_open(&[json!("s"), json!({"#t": 42}), json!("61000000")])
                .await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NEG-ERR" && m[2].as_str().unwrap().contains("strings")),
                "a filter with non-string tag values must yield a NEG-ERR"
            );
            conn.outgoing.clear();
            conn.handle_neg_open(&[json!("s"), json!({}), json!(42)])
                .await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NEG-ERR" && m[2].as_str().unwrap().contains("hex")),
                "a non-string initial message must yield a NEG-ERR"
            );
            conn.outgoing.clear();
            conn.handle_neg_open(&[json!("s"), json!({}), json!("zzz")])
                .await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NEG-ERR" && m[2].as_str().unwrap().contains("hex")),
                "a non-hex initial message must yield a NEG-ERR"
            );
            conn.outgoing.clear();

            // AUTH-required relay: an unauthenticated NEG-OPEN is refused.
            {
                let mut w = conn.relay.config.write().await;
                w.relay.require_auth = true;
            }
            conn.handle_neg_open(&[json!("s"), json!({}), json!("61000000")])
                .await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NEG-ERR" && m[2].as_str().unwrap().contains("auth-required")),
                "an unauthenticated NEG-OPEN on an auth-requiring relay must be refused"
            );
            conn.outgoing.clear();
            {
                let mut w = conn.relay.config.write().await;
                w.relay.require_auth = false;
            }

            // A blocked (authed) pubkey is refused syncing.
            let blocked = "bb".repeat(32);
            conn.authed_pubkeys.push(blocked.clone());
            conn.relay
                .access
                .write()
                .await
                .blocked_pubkeys
                .push((blocked, String::new()));
            conn.handle_neg_open(&[json!("s"), json!({}), json!("61000000")])
                .await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NEG-ERR" && m[2].as_str().unwrap().contains("restricted")),
                "a blocked pubkey must be refused syncing"
            );
            conn.outgoing.clear();
            conn.authed_pubkeys.clear();
            conn.relay.access.write().await.blocked_pubkeys.clear();

            // The subscription cap applies to new ids only.
            {
                let mut w = conn.relay.config.write().await;
                w.limits.max_subscriptions = 1;
            }
            conn.handle_neg_open(&[json!("s1"), json!({}), json!("61000000")])
                .await;
            conn.outgoing.clear();
            conn.handle_neg_open(&[json!("s2"), json!({}), json!("61000000")])
                .await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NEG-ERR" && m[2].as_str().unwrap().contains("too many")),
                "a new NEG-OPEN over the subscription cap must be refused"
            );
            conn.outgoing.clear();
            {
                let mut w = conn.relay.config.write().await;
                w.limits.max_subscriptions = 100;
            }

            // A failed query (the reader is gone) closes with a retryable
            // NEG-ERR that never pretends the item set is empty (a peer
            // must not conclude its events are gone and delete them).
            conn.relay.db.shutdown();
            conn.handle_neg_open(&[json!("s"), json!({}), json!("61000000")])
                .await;
            let msgs = outgoing_json(&conn);
            assert!(
                msgs.iter().any(|m| m[0] == "NEG-ERR"
                    && m[1] == "s"
                    && m[2] == "error: database unavailable; retry"),
                "a failed sync must close with a retryable NEG-ERR: {msgs:?}"
            );
            assert!(
                !conn.neg.contains_key("s"),
                "the NEG-ERR must close the subscription"
            );
        });
    }

    #[test]
    fn neg_open_query_size_and_item_filters() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            for i in 0..5 {
                let e = signed_note(conn.relay.secp(), &format!("e{i}"), now - i, vec![]);
                let out = conn.relay.db.put(e.clone(), now).await;
                assert_eq!(out, crate::db::PutOutcome::Stored, "event {i} stored");
            }
            let f: crate::filter::Filter =
                serde_json::from_value(serde_json::json!({"kinds": [1]})).unwrap();
            let (stored, _) = conn.relay.db.query(vec![f.clone()], 10, now).await;
            assert_eq!(stored.len(), 5, "all five events are queryable");

            // The per-connection item cap is enforced across concurrent
            // subscriptions (cap = max_neg_items * 2). Use a max that covers
            // the five stored events so each query is complete (`more ==
            // false`); a smaller max would correctly reject every query as
            // "too big" instead of syncing a truncated set.
            {
                let mut w = conn.relay.config.write().await;
                w.limits.max_neg_items = 5;
            }
            conn.handle_neg_open(&[json!("a"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            conn.outgoing.clear();
            conn.handle_neg_open(&[json!("b"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            conn.outgoing.clear();
            conn.handle_neg_open(&[json!("c"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NEG-ERR" && m[2].as_str().unwrap().contains("too many")),
                "the total item cap must close the third subscription"
            );
            conn.outgoing.clear();
            conn.handle_neg_close(&[json!("a")]);
            conn.handle_neg_close(&[json!("b")]);
            conn.handle_neg_close(&[json!("c")]);

            // Protected events are withheld from anonymous peers. Raise the
            // item cap so the six stored events (five public + one hidden)
            // fit: the query is complete and the hidden event is filtered
            // after the scan.
            {
                let mut w = conn.relay.config.write().await;
                w.limits.max_neg_items = 10;
            }
            let mut protected = signed_note(conn.relay.secp(), "secret", now, vec![]);
            protected.tags = vec![vec!["-".into()]];
            protected.id = crate::nips::nip01::compute_id(&protected);
            conn.relay.db.put(protected, now).await;
            conn.handle_neg_open(&[json!("s"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            assert!(
                outgoing_json(&conn).iter().any(|m| m[0] == "NEG-MSG"),
                "an anonymous NEG-OPEN over protected events still succeeds"
            );
            conn.outgoing.clear();

            // A NEG-MSG for an unknown subscription closes with NEG-ERR.
            conn.handle_neg_msg(&[json!("ghost"), json!("61000000")])
                .await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NEG-ERR" && m[2].as_str().unwrap().contains("unknown")),
                "a NEG-MSG for an unknown sub must close with NEG-ERR"
            );
            conn.outgoing.clear();
            // Malformed NEG-MSG frames: with a known id they close via
            // NEG-ERR (NIP-77), without one via NOTICE.
            conn.handle_neg_msg(&[json!("s")]).await;
            assert!(
                outgoing_json(&conn).iter().any(|m| m[0] == "NEG-ERR"
                    && m[1] == "s"
                    && m[2].as_str().unwrap().contains("NEG-MSG")),
                "a short NEG-MSG must yield a NEG-ERR: {:?}",
                outgoing_json(&conn)
            );
            assert!(
                !conn.neg.contains_key("s"),
                "a short NEG-MSG must close the subscription"
            );
            conn.outgoing.clear();
            conn.handle_neg_msg(&[json!(true), json!("61000000")]).await;
            assert!(
                outgoing_json(&conn).iter().any(|m| m[0] == "NOTICE"),
                "a non-string sub id must yield a NOTICE: {:?}",
                outgoing_json(&conn)
            );
            conn.outgoing.clear();
            // The short-frame check above closed "s": reopen it so the
            // malformed-payload checks below run against a known id (an
            // unknown id is refused before the payload is parsed).
            conn.handle_neg_open(&[json!("s"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            conn.outgoing.clear();
            conn.handle_neg_msg(&[json!("s"), json!(42)]).await;
            assert!(
                outgoing_json(&conn).iter().any(|m| m[0] == "NEG-ERR"
                    && m[1] == "s"
                    && m[2].as_str().unwrap().contains("hex")),
                "a non-string NEG-MSG message must yield a NEG-ERR"
            );
            assert!(
                !conn.neg.contains_key("s"),
                "a malformed NEG-MSG must close the subscription"
            );
            conn.outgoing.clear();
            // Reopen "s" again (the check above closed it) for the non-hex
            // payload check.
            conn.handle_neg_open(&[json!("s"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            conn.outgoing.clear();
            conn.handle_neg_msg(&[json!("s"), json!("zzz")]).await;
            assert!(
                outgoing_json(&conn).iter().any(|m| m[0] == "NEG-ERR"
                    && m[1] == "s"
                    && m[2].as_str().unwrap().contains("hex")),
                "a non-hex NEG-MSG message must yield a NEG-ERR"
            );
            assert!(
                !conn.neg.contains_key("s"),
                "a non-hex NEG-MSG must close the subscription"
            );
            conn.outgoing.clear();

            // Exhausting the round budget closes the subscription.
            conn.handle_neg_open(&[json!("r"), json!({}), json!("61000000")])
                .await;
            conn.outgoing.clear();
            if let Some(state) = conn.neg.get_mut("r") {
                state.rounds_left = 0;
            }
            conn.handle_neg_msg(&[json!("r"), json!("61000000")]).await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NEG-ERR" && m[2].as_str().unwrap().contains("too many")),
                "an exhausted round budget must close the subscription"
            );
            assert!(!conn.neg.contains_key("r"), "the sub must be released");
            conn.outgoing.clear();

            // A NEG-MSG whose response exceeds the byte budget closes the
            // subscription and releases its items.
            conn.handle_neg_open(&[json!("b"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            conn.outgoing.clear();
            conn.req_response_bytes = 10;
            // A fingerprint range with a bogus fingerprint forces the relay
            // to answer with the full id list (a large response).
            let ask_all = format!("61000001{}", "00".repeat(16));
            conn.handle_neg_msg(&[json!("b"), json!(ask_all)]).await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NEG-ERR" && m[2].as_str().unwrap().contains("too large")),
                "an over-budget NEG-MSG response must close the subscription: {:?}",
                outgoing_json(&conn)
            );
            assert!(!conn.neg.contains_key("b"), "the sub must be released");
            conn.outgoing.clear();

            // A saturated outgoing queue fails the round with a retryable
            // NEG-ERR instead of accumulating unbounded NEG bytes.
            conn.req_response_bytes = 0;
            conn.handle_neg_open(&[json!("q"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            conn.outgoing.clear();
            conn.out_queue_bytes = 1;
            conn.out_bytes = 100;
            conn.handle_neg_msg(&[json!("q"), json!("61000000")]).await;
            assert!(
                outgoing_json(&conn).iter().any(|m| m[0] == "NEG-ERR"
                    && m[1] == "q"
                    && m[2].as_str().unwrap().contains("overloaded")),
                "a backpressured NEG-MSG must fail retryably: {:?}",
                outgoing_json(&conn)
            );
            assert!(
                !conn.neg.contains_key("q"),
                "a backpressured round must close the subscription"
            );
            conn.outgoing.clear();
            conn.out_queue_bytes = 256 * 1024;
            conn.out_bytes = 0;

            // NEG-CLOSE with a missing id yields a NOTICE.
            conn.handle_neg_close(&[]);
            assert!(outgoing_json(&conn).iter().any(|m| m[0] == "NOTICE"));
            conn.outgoing.clear();

            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn neg_syncs_loose_protected_tag_as_public() {
        // `["-", "extra"]` is public like the REQ path: only the exact
        // `["-"]` tag is protected. An anonymous NEG-OPEN must include it
        // in the sync set instead of withholding it.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            let mut ev = signed_note(conn.relay.secp(), "loose", now, vec![]);
            ev.tags = vec![vec!["-".into(), "extra".into()]];
            ev.id = crate::nips::nip01::compute_id(&ev);
            conn.relay.db.put(ev.clone(), now).await;
            {
                let mut w = conn.relay.config.write().await;
                w.limits.max_neg_items = 10;
            }
            conn.handle_neg_open(&[json!("loose"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            let state = conn.neg.get("loose").expect("sync must stay open");
            let want = ev.id_bytes().expect("test event id");
            assert!(
                state.items.iter().any(|(_, id)| *id == want),
                "a [\"-\", \"extra\"] event must be synced to anonymous peers"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn neg_open_remaining_gates_and_limit() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            // A search filter over-fetches (the relevance budget): with a
            // small max_neg_items the query returns more records than the
            // cap and the NIP-77 "too big" NEG-ERR fires.
            for i in 0..5 {
                let e = signed_note(conn.relay.secp(), &format!("needle {i}"), now - i, vec![]);
                conn.relay.db.put(e.clone(), now).await;
            }
            {
                let mut w = conn.relay.config.write().await;
                w.limits.max_neg_items = 2;
            }
            conn.handle_neg_open(&[json!("big"), json!({"search": "needle"}), json!("61000000")])
                .await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NEG-ERR" && m[2].as_str().unwrap().contains("too big")),
                "a search query over the cap must close with NEG-ERR: {:?}",
                outgoing_json(&conn)
            );
            conn.outgoing.clear();
            {
                let mut w = conn.relay.config.write().await;
                w.limits.max_neg_items = 100_000;
            }

            // NIP-78 / NIP-59 / NIP-29 item filtering: a kind-78 event, a
            // gift wrap for another recipient and a private group event are
            // withheld from an anonymous peer (the response is empty).
            let secp = conn.relay.secp();
            let mut app = signed_note(secp, "app data", now, vec![]);
            app.kind = crate::nips::nip78::APP_SPECIFIC_KIND;
            conn.relay.db.put(app, now).await;
            let mut wrap = signed_note(secp, "secret dm", now, vec![]);
            wrap.kind = crate::nips::nip62::GIFT_WRAP_KIND;
            wrap.tags = vec![vec!["p".into(), "cc".repeat(32)]];
            conn.relay.db.put(wrap, now).await;
            conn.handle_neg_open(&[
                json!("filtered"),
                json!({"kinds": [78, 1059]}),
                json!("61000000"),
            ])
            .await;
            let msgs = outgoing_json(&conn);
            assert!(
                msgs.iter().any(|m| m[0] == "NEG-MSG" && m[2] == "61000000"),
                "withheld items must produce an empty sync response: {msgs:?}"
            );
            conn.outgoing.clear();
            conn.handle_neg_close(&[json!("filtered")]);

            // The per-connection NEG-OPEN limit (MAX_NEG_OPENS).
            conn.neg_opens_total = super::negentropy::MAX_NEG_OPENS;
            conn.handle_neg_open(&[json!("s"), json!({}), json!("61000000")])
                .await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NEG-ERR"
                        && m[2].as_str().unwrap().contains("connection limit")),
                "the NEG-OPEN count limit must be enforced"
            );
            conn.outgoing.clear();
            conn.neg_opens_total = 0;

            // A blocked authed pubkey: NEG-MSG is refused and the state is
            // released.
            let blocked = "dd".repeat(32);
            conn.authed_pubkeys.push(blocked.clone());
            conn.relay
                .access
                .write()
                .await
                .blocked_pubkeys
                .push((blocked, String::new()));
            conn.handle_neg_open(&[json!("bk"), json!({}), json!("61000000")])
                .await;
            conn.outgoing.clear();
            conn.handle_neg_msg(&[json!("bk"), json!("61000000")]).await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "NEG-ERR" && m[2].as_str().unwrap().contains("restricted")),
                "a blocked pubkey's NEG-MSG must be refused"
            );
            assert!(!conn.neg.contains_key("bk"), "the blocked sync is released");
            conn.outgoing.clear();
            conn.authed_pubkeys.clear();
            conn.relay.access.write().await.blocked_pubkeys.clear();

            // A NEG-MSG that fails to parse closes the subscription and
            // releases its items (an over-range-count message fails the
            // response).
            conn.handle_neg_open(&[json!("r2"), json!({}), json!("61000000")])
                .await;
            conn.outgoing.clear();
            // Many fingerprint ranges force the codec's per-message range
            // cap to trip: MAX_NEG_RANGES_PER_MSG + 1 ranges.
            let ranges = 1025; // MAX_NEG_RANGES_PER_MSG + 1
            // Encode each range as [infinity bound][mode fingerprint][fp]:
            // a single multi-range message.
            let mut wire = vec![0x61u8];
            for _ in 0..ranges {
                wire.extend_from_slice(&[0x00, 0x00, 0x01]);
                wire.extend_from_slice(&[0u8; 16]);
            }
            let hex_msg = hex::encode(&wire);
            conn.handle_neg_msg(&[json!("r2"), json!(hex_msg)]).await;
            assert!(
                outgoing_json(&conn).iter().any(|m| m[0] == "NEG-ERR"),
                "an unprocessable NEG-MSG must close the subscription: {:?}",
                outgoing_json(&conn)
            );
            assert!(!conn.neg.contains_key("r2"), "the sub is released");

            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn failed_neg_opens_consume_the_connection_budget() {
        // A NEG-OPEN that runs the database scan and then fails (here: the
        // response exceeds the per-connection byte budget) must still spend
        // the connection-wide open budget, or a client could run scans
        // unbounded by always failing the open after the scan.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            conn.req_response_bytes = 1;
            conn.handle_neg_open(&[json!("s"), json!({}), json!("61000000")])
                .await;
            assert!(
                outgoing_json(&conn).iter().any(|m| m[0] == "NEG-ERR"),
                "the oversized response must be refused"
            );
            assert_eq!(
                conn.neg_opens_total, 1,
                "a refused open must still spend the connection budget"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn exhausted_neg_open_budget_skips_the_database_query() {
        // The connection-wide NEG-OPEN cap is checked before the large
        // database query: an exhausted budget answers "connection limit"
        // instead of spending the scan and then reporting a different
        // refusal.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            // More events than a tiny item cap, so the scan would answer
            // "too big" if it ran.
            conn.relay.config.write().await.limits.max_neg_items = 1;
            for i in 0..3 {
                let ev = signed_note(conn.relay.secp(), &format!("e{i}"), now - i, vec![]);
                conn.relay.db.put(ev, now).await;
            }
            conn.neg_opens_total = super::negentropy::MAX_NEG_OPENS;
            conn.handle_neg_open(&[json!("s"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            let msgs = outgoing_json(&conn);
            let err = msgs
                .iter()
                .find(|m| m[0] == "NEG-ERR")
                .expect("the open must be refused");
            assert!(
                err[2].as_str().unwrap().contains("connection limit"),
                "the budget check must run before the database query: {err:?}"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn neg_open_counts_towards_active_subscriptions() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let stats = conn.relay.stats.clone();
            let before = stats
                .subscriptions_active
                .load(std::sync::atomic::Ordering::Relaxed);
            // A NEG-OPEN with an empty client set (skip-to-infinity).
            conn.handle_neg_open(&[json!("s"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            let after_open = stats
                .subscriptions_active
                .load(std::sync::atomic::Ordering::Relaxed);
            assert_eq!(
                after_open,
                before + 1,
                "an open NEG subscription must hold a slot"
            );
            conn.handle_neg_close(&[json!("s")]);
            let after_close = stats
                .subscriptions_active
                .load(std::sync::atomic::Ordering::Relaxed);
            assert_eq!(
                after_close, before,
                "closing the NEG subscription must release the slot"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn neg_open_failed_replace_closes_the_old_subscription() {
        // NIP-77: "If a NEG-OPEN is issued for a currently open subscription
        // ID, the existing subscription is first closed", and "after a
        // NEG-ERR is issued, the subscription is considered to be closed".
        // A failed replacement therefore closes the id instead of leaving
        // the old state running.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let stats = conn.relay.stats.clone();
            let before = stats
                .subscriptions_active
                .load(std::sync::atomic::Ordering::Relaxed);
            conn.handle_neg_open(&[json!("s"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            assert_eq!(
                stats
                    .subscriptions_active
                    .load(std::sync::atomic::Ordering::Relaxed),
                before + 1,
                "the first open holds a slot"
            );
            assert!(conn.neg.contains_key("s"), "the first open is live");
            // A syntactically valid hex message that fails to parse:
            // version byte followed by an out-of-order bound.
            let bad = hex::encode([0x61u8, 0x02, 0x00, 0x01]);
            conn.handle_neg_open(&[json!("s"), json!({"kinds": [1]}), json!(bad)])
                .await;
            assert!(
                conn.outgoing
                    .iter()
                    .any(|m| m.message.to_text().is_ok_and(|t| t.contains("NEG-ERR"))),
                "the failed replacement must send a NEG-ERR"
            );
            assert!(
                !conn.neg.contains_key("s"),
                "a NEG-ERR closes the subscription: the old state is released"
            );
            assert_eq!(
                stats
                    .subscriptions_active
                    .load(std::sync::atomic::Ordering::Relaxed),
                before,
                "the closed id's subscription slot is released"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn neg_open_byte_cap_rejects_oversized_initial_response() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            // A small response budget: any mode-2 answer over it is
            // rejected with NEG-ERR, which closes the (here non-existent)
            // subscription.
            // Any initial answer is at least the version byte plus a
            // bound, so a 1-byte budget rejects everything.
            conn.req_response_bytes = 1;
            conn.handle_neg_open(&[json!("s"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            assert!(
                conn.outgoing
                    .iter()
                    .any(|m| m.message.to_text().is_ok_and(|t| t.contains("NEG-ERR"))),
                "the oversized response must produce a NEG-ERR"
            );
            assert!(
                conn.neg.is_empty(),
                "the failed open must not leave a subscription"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn neg_open_replacement_success_is_net_zero() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let stats = conn.relay.stats.clone();
            let before = stats
                .subscriptions_active
                .load(std::sync::atomic::Ordering::Relaxed);
            conn.handle_neg_open(&[json!("s"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            conn.handle_neg_open(&[json!("s"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            assert_eq!(
                stats
                    .subscriptions_active
                    .load(std::sync::atomic::Ordering::Relaxed),
                before + 1,
                "a successful replacement keeps exactly one slot"
            );
            conn.handle_neg_close(&[json!("s")]);
            assert_eq!(
                stats
                    .subscriptions_active
                    .load(std::sync::atomic::Ordering::Relaxed),
                before,
                "closing releases the slot"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn neg_open_item_cap_closes_the_old_subscription() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            // Open "s" against an empty database: it succeeds and holds
            // state.
            conn.handle_neg_open(&[json!("s"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            assert_eq!(conn.neg.len(), 1, "the first open succeeds");
            conn.relay.config.write().await.limits.max_neg_items = 2;
            // Store more matching events than the cap, then replace "s":
            // the over-cap NEG-ERR closes the id (NIP-77).
            for i in 0..3 {
                let ev = signed_note(conn.relay.secp(), &format!("e{i}"), now - i, vec![]);
                conn.relay.db.put(ev, now).await;
            }
            conn.handle_neg_open(&[json!("s"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| { m[0] == "NEG-ERR" && m[2].as_str().unwrap().contains("too big") }),
                "the over-cap query must be refused"
            );
            assert!(
                conn.neg.is_empty(),
                "the NEG-ERR must close the old subscription"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn req_hidden_events_do_not_consume_limit_slots() {
        // Regression: NIP-70 protected events used to consume the per-filter
        // limit during the scan, so a REQ with limit N returned fewer than N
        // visible events (and re-REQing could never recover them). The scan
        // now over-fetches and the connection truncates the visible results.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            let hidden = signed_note(conn.relay.secp(), "secret", now, vec![vec!["-".into()]]);
            let v1 = signed_note(conn.relay.secp(), "v1", now - 1, vec![]);
            let v2 = signed_note(conn.relay.secp(), "v2", now - 2, vec![]);
            let v3 = signed_note(conn.relay.secp(), "v3", now - 3, vec![]);
            for e in [&hidden, &v1, &v2, &v3] {
                conn.relay.db.put(e.clone(), now).await;
            }
            conn.handle_req(&[json!("sub"), json!({"kinds": [1], "limit": 3})])
                .await;
            conn.pump_pending_reqs();
            let contents: Vec<String> = outgoing_json(&conn)
                .iter()
                .filter(|m| m[0] == "EVENT")
                .map(|m| m[2]["content"].as_str().unwrap().to_string())
                .collect();
            assert_eq!(
                contents,
                vec!["v1", "v2", "v3"],
                "the hidden event must not consume a limit slot"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn req_boundary_tie_beyond_the_page_is_dropped_whole() {
        // NIP-01/NIP-67 boundary rule: events sharing the boundary
        // `created_at` travel together — never a partial tie. When the tie
        // block fills the page and the response is incomplete, keeping it
        // would make an inclusive client (`until = T`) re-read the same
        // block forever; the handler drops the whole boundary second and
        // reports `more`, so the client advances to `T - 1` and finishes.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            let v1 = signed_note(conn.relay.secp(), "v1", now, vec![]);
            let v2 = signed_note(conn.relay.secp(), "v2", now, vec![]);
            let v3 = signed_note(conn.relay.secp(), "v3", now - 1, vec![]);
            for e in [&v1, &v2, &v3] {
                conn.relay.db.put(e.clone(), now).await;
            }
            conn.handle_req(&[json!("sub"), json!({"kinds": [1], "limit": 1})])
                .await;
            conn.pump_pending_reqs();
            let msgs = outgoing_json(&conn);
            let contents: Vec<&str> = msgs
                .iter()
                .filter(|m| m[0] == "EVENT")
                .map(|m| m[2]["content"].as_str().unwrap())
                .collect();
            assert!(
                !contents.contains(&"v1") && !contents.contains(&"v2"),
                "an oversized boundary tie must not be delivered partially: {contents:?}"
            );
            assert!(
                msgs.iter()
                    .any(|m| m[0] == "EOSE" && m[1] == "sub" && m[2] == json!(["more"])),
                "the dropped second must keep the more hint: {msgs:?}"
            );
            // The client advances to `T - 1` and completes.
            conn.outgoing.clear();
            conn.out_bytes = 0;
            conn.handle_req(&[
                json!("sub"),
                json!({"kinds": [1], "limit": 1, "until": now - 1}),
            ])
            .await;
            conn.pump_pending_reqs();
            let msgs = outgoing_json(&conn);
            assert!(
                msgs.iter()
                    .any(|m| m[0] == "EVENT" && m[2]["content"] == "v3"),
                "the next page must serve the older event: {msgs:?}"
            );
            assert!(
                msgs.iter()
                    .any(|m| m[0] == "EOSE" && m[1] == "sub" && m[2] == json!(["finish"])),
                "the follow-up page must complete: {msgs:?}"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn same_second_tie_flood_paginates_to_finish() {
        // A same-second flood larger than the scan's tie cap used to
        // return the same tie block on every page, so an inclusive client
        // (`until = oldest created_at`) never finished. The handler drops
        // the boundary second and the client advances on the next step.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            // Far more matching events at `now` than the page can carry,
            // plus a few older events that make progress observable.
            for i in 0..60 {
                let ev = signed_note(conn.relay.secp(), &format!("flood-{i}"), now, vec![]);
                conn.relay.db.put(ev, now).await;
            }
            for i in 1..=5u64 {
                let ev = signed_note(conn.relay.secp(), &format!("older-{i}"), now - i, vec![]);
                conn.relay.db.put(ev, now).await;
            }
            let mut until = now;
            let mut finished = false;
            for round in 0..12 {
                conn.handle_req(&[
                    json!("sub"),
                    json!({"kinds": [1], "limit": 5, "until": until}),
                ])
                .await;
                conn.pump_pending_reqs();
                let msgs = outgoing_json(&conn);
                if msgs
                    .iter()
                    .any(|m| m[0] == "EOSE" && m[1] == "sub" && m[2] == json!(["finish"]))
                {
                    finished = true;
                    break;
                }
                let oldest = msgs
                    .iter()
                    .filter(|m| m[0] == "EVENT")
                    .filter_map(|m| m[2]["created_at"].as_u64())
                    .min();
                // The inclusive client: `until` becomes the oldest event
                // seen (no `- 1`); an empty page steps back one second.
                until = oldest.unwrap_or_else(|| until.saturating_sub(1));
                assert!(
                    until < now,
                    "round {round} must make progress: {until} < {now}"
                );
                conn.outgoing.clear();
                conn.out_bytes = 0;
            }
            assert!(
                finished,
                "the inclusive client must reach finish within 12 rounds"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn req_response_chunks_through_the_outgoing_byte_cap() {
        // Backpressure: REQ responses are pumped through the capped
        // outgoing queue in bounded chunks — the queue never holds more
        // than the byte cap, and no response event is dropped (a dropped
        // event is lost permanently — the subscription is answered once).
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            // A tiny per-connection cap so one chunk holds a single event.
            conn.out_queue_bytes = 1024;
            let now = unix_now();
            let big = "x".repeat(10_000);
            let mut ids = Vec::new();
            for i in 0..5 {
                let ev = signed_note(
                    conn.relay.secp(),
                    &format!("big-{i}-{big}"),
                    now - i,
                    vec![],
                );
                conn.relay.db.put(ev.clone(), now).await;
                ids.push(ev.id.clone());
            }
            conn.handle_req(&[json!("sub"), json!({"kinds": [1], "limit": 5})])
                .await;
            assert_eq!(
                conn.pending_reqs.len(),
                1,
                "the response is queued for the pump"
            );
            // Pump in chunks until the response is fully queued. Each
            // pump respects the byte cap: the queue never grows past it.
            let mut delivered = Vec::new();
            loop {
                conn.pump_pending_reqs();
                assert!(
                    conn.out_bytes <= conn.out_queue_bytes + 11_000,
                    "the queue is bounded by the cap plus one event (a single \
                     oversized event must still be delivered)"
                );
                for msg in outgoing_json(&conn) {
                    if msg[0] == "EVENT" {
                        delivered.push(msg[2]["id"].as_str().unwrap().to_string());
                    }
                }
                conn.outgoing.clear();
                conn.out_bytes = 0;
                if conn.pending_reqs.is_empty() {
                    break;
                }
            }
            assert_eq!(
                delivered.len(),
                5,
                "all five response events must be delivered through the chunks"
            );
            assert!(
                ids.iter().all(|id| delivered.contains(id)),
                "no response event may be dropped"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn live_events_wait_for_the_pending_eose() {
        // NIP-01: EOSE marks the end of stored events and the beginning of
        // the real-time stream. A live event that arrives while a stored
        // response is still pumping must be queued after the EOSE, never
        // ahead of the remaining stored events.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            // One stored event per pump, so the live event arrives while the
            // response is still being drained.
            conn.out_queue_bytes = 1024;
            let now = unix_now();
            conn.subs
                .insert("s".into(), (vec![Filter::default()], 0, "\"s\"".into()));
            let mut events = std::collections::VecDeque::new();
            for i in 0..3 {
                events.push_back(signed_note(
                    conn.relay.secp(),
                    &format!("stored-{i}-{}", "x".repeat(2_000)),
                    now - i,
                    vec![],
                ));
            }
            conn.enqueue_pending_req(PendingReq {
                sub_id: "s".into(),
                events,
                eose_hint: false,
                truncated_or_more: false,
                auth_hint: false,
                sent_bytes: 0,
                live: Default::default(),
                live_bytes: 0,
                eose_sent: false,
                budget: None,
                reserved: 0,
            });
            // A live event for the same subscription arrives mid-response:
            // it must be held for the post-EOSE stream.
            let live = signed_note(conn.relay.secp(), "live", now, vec![]);
            let live_json = serde_json::to_string(&live).unwrap();
            conn.deliver_live(&live, &live_json, None);
            assert!(
                !outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "EVENT" && m[2]["content"] == "live"),
                "the live event must not overtake the stored response"
            );

            // Drain the queue chunk by chunk, collecting the message order.
            let mut order = Vec::new();
            for _ in 0..20 {
                conn.pump_pending_reqs();
                order.extend(outgoing_json(&conn));
                conn.outgoing.clear();
                conn.out_bytes = 0;
                if conn.pending_reqs.is_empty() {
                    break;
                }
            }
            assert!(
                conn.pending_reqs.is_empty(),
                "the response must finish within the drain loop"
            );
            let stored = |m: &Value| {
                m[0] == "EVENT"
                    && m[2]["content"]
                        .as_str()
                        .is_some_and(|c| c.starts_with("stored-"))
            };
            let eose = order
                .iter()
                .position(|m| m[0] == "EOSE" && m[1] == "s")
                .expect("the EOSE must be queued");
            let last_stored = order.iter().rposition(stored).expect("stored events");
            let live_pos = order
                .iter()
                .position(|m| m[0] == "EVENT" && m[2]["content"] == "live")
                .expect("the live event must be queued");
            assert_eq!(
                order.iter().filter(|m| stored(m)).count(),
                3,
                "all stored events must be delivered"
            );
            assert!(
                last_stored < eose,
                "every stored event must precede the EOSE"
            );
            assert!(live_pos > eose, "the live event must follow the EOSE");
            conn.relay.db.shutdown();
        });
    }

    /// A sink that never becomes ready: models a peer that stopped reading.
    struct NeverReady;

    impl futures_util::Sink<Message> for NeverReady {
        type Error = axum::Error;
        fn poll_ready(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Pending
        }
        fn start_send(self: std::pin::Pin<&mut Self>, _item: Message) -> Result<(), Self::Error> {
            Ok(())
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Pending
        }
        fn poll_close(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Pending
        }
    }

    /// A sink whose writes always fail: models a socket that is already gone.
    struct FailingSink;

    impl futures_util::Sink<Message> for FailingSink {
        type Error = axum::Error;
        fn poll_ready(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn start_send(self: std::pin::Pin<&mut Self>, _item: Message) -> Result<(), Self::Error> {
            Err(axum::Error::new(std::io::Error::other("sink gone")))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_close(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn blocked_drain_yields_to_the_idle_deadline() {
        // A peer that stops reading must not pin the connection task: the
        // drain races the idle deadline, so the connection is reaped even
        // while the socket is unwritable.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            conn.send(Message::Text("x".into()));
            let mut sink = NeverReady;
            let mut idle_sleep = Some(Box::pin(tokio::time::sleep(Duration::from_millis(50))));
            let (_ip_tx, mut ip_rx) = tokio::sync::watch::channel(0u64);
            let (_overflow_tx, mut overflow_rx) = tokio::sync::watch::channel(());
            let (_drain_tx, mut drain_rx) = tokio::sync::watch::channel(false);
            let outcome = tokio::time::timeout(
                Duration::from_secs(2),
                drain_outgoing(
                    &mut conn,
                    &mut sink,
                    &mut idle_sleep,
                    &mut ip_rx,
                    &mut overflow_rx,
                    &mut drain_rx,
                ),
            )
            .await
            .expect("the blocked drain must yield to the idle deadline");
            assert!(matches!(outcome, DrainOutcome::Stop));
            // The in-flight message is preserved for a connection that keeps
            // running (the idle/overflow signals end it, the IP change may
            // not).
            assert_eq!(conn.outgoing.len(), 1);
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn blocked_drain_yields_to_shutdown() {
        // On shutdown the drain must observe the signal even while the
        // socket is unwritable, so the connection can flush its pending
        // batch and close instead of being killed with the process.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            conn.send(Message::Text("x".into()));
            let mut sink = NeverReady;
            let mut idle_sleep = None;
            let (_ip_tx, mut ip_rx) = tokio::sync::watch::channel(0u64);
            let (_overflow_tx, mut overflow_rx) = tokio::sync::watch::channel(());
            let (drain_tx, mut drain_rx) = tokio::sync::watch::channel(false);
            // Signal before the drain parks: a `watch` receiver treats the
            // value as changed from the one seen at subscribe time, so the
            // drain observes it deterministically (no timer needed).
            let _ = drain_tx.send(true);
            let outcome = tokio::time::timeout(
                Duration::from_secs(2),
                drain_outgoing(
                    &mut conn,
                    &mut sink,
                    &mut idle_sleep,
                    &mut ip_rx,
                    &mut overflow_rx,
                    &mut drain_rx,
                ),
            )
            .await
            .expect("the shutdown signal must end the blocked drain");
            assert!(matches!(outcome, DrainOutcome::Stop));
            assert_eq!(conn.outgoing.len(), 1);
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn drain_reports_a_failing_sink_as_stop() {
        // A sink error means the socket is gone: the drain must report
        // Stop so the caller tears the connection down instead of treating
        // the queue as drained (which would leave the loop spinning on a
        // dead sink and the connection slot pinned).
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            conn.send(Message::Text("x".into()));
            let mut sink = FailingSink;
            let mut idle_sleep = Some(Box::pin(tokio::time::sleep(Duration::from_secs(60))));
            let (_ip_tx, mut ip_rx) = tokio::sync::watch::channel(0u64);
            let (_overflow_tx, mut overflow_rx) = tokio::sync::watch::channel(());
            let (_drain_tx, mut drain_rx) = tokio::sync::watch::channel(false);
            let outcome = tokio::time::timeout(
                Duration::from_secs(2),
                drain_outgoing(
                    &mut conn,
                    &mut sink,
                    &mut idle_sleep,
                    &mut ip_rx,
                    &mut overflow_rx,
                    &mut drain_rx,
                ),
            )
            .await
            .expect("a failing sink must not park the drain");
            assert!(matches!(outcome, DrainOutcome::Stop));
            // The failed frame stays queued (its feed never succeeded).
            assert_eq!(conn.outgoing.len(), 1);
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn blocked_teardown_completes_on_the_grace_deadline() {
        // A peer that stopped reading must not pin the connection task
        // after the loop ends: the final flush/close is bounded by a short
        // grace, so the task (and its connection slot, live-index entry and
        // subscription accounting) is released even with a stalled sink.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            conn.send(Message::Text("x".into()));
            let mut sink = NeverReady;
            tokio::time::timeout(
                Duration::from_secs(2),
                flush_and_close(&mut conn, &mut sink, Duration::from_millis(50)),
            )
            .await
            .expect("the teardown must not park on a stalled sink");
            // The in-flight frame was popped before the blocked send and
            // its byte accounting released; the rest is abandoned.
            assert!(conn.outgoing.is_empty());
            assert_eq!(conn.out_bytes, 0);
            // The grace dropped the teardown mid-send: the stuck frame
            // never reached the wire, so it must not linger in the
            // message/lifetime counters flushed to shared stats (phantom
            // traffic after a stalling-peer disconnect).
            assert_eq!(conn.out_msgs, 0);
            assert_eq!(conn.out_bytes_total, 0);
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn neg_backpressure_applies_without_a_configured_queue_cap() {
        // An unset byte cap (`0` = unlimited) used to disable the NEG
        // backpressure gate entirely; it now falls back to the absolute
        // control ceiling instead of bounding nothing.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            // Capped case (unchanged): 4x the configured cap refuses.
            conn.out_queue_bytes = 100;
            conn.out_bytes = 400;
            assert!(!conn.neg_backpressured());
            conn.out_bytes = 401;
            assert!(conn.neg_backpressured());
            // Unset cap: the control ceiling is the reference.
            conn.out_queue_bytes = 0;
            let ceiling = conn.out_queue_cap();
            conn.out_bytes = ceiling.saturating_mul(4);
            assert!(!conn.neg_backpressured());
            conn.out_bytes = ceiling.saturating_mul(4).saturating_add(1);
            assert!(
                conn.neg_backpressured(),
                "an unlimited queue must still refuse NEG past 4x the control ceiling"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn pump_closes_oversized_responses() {
        // `max_req_response_bytes`: a response exceeding the budget is
        // closed with `CLOSED ... response too large`; the events already
        // queued stay, and the client can re-request with a narrower
        // filter instead of the subscription hanging.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            conn.req_response_bytes = 3_000;
            let now = unix_now();
            let mut events = std::collections::VecDeque::new();
            for i in 0..3 {
                let ev = signed_note(
                    conn.relay.secp(),
                    &format!("big-{i}-{}", "y".repeat(2_000)),
                    now - i,
                    vec![],
                );
                events.push_back(ev);
            }
            conn.subs
                .insert("s".into(), (Vec::new(), 0, "\"s\"".into()));
            conn.enqueue_pending_req(PendingReq {
                sub_id: "s".into(),
                events,
                eose_hint: false,
                truncated_or_more: false,
                auth_hint: false,
                sent_bytes: 0,
                live: Default::default(),
                live_bytes: 0,
                eose_sent: false,
                budget: None,
                reserved: 0,
            });
            conn.pump_pending_reqs();
            let msgs = outgoing_json(&conn);
            let events_sent = msgs.iter().filter(|m| m[0] == "EVENT").count();
            let closed = msgs.iter().find(|m| m[0] == "CLOSED" && m[1] == "s");
            assert!(
                !conn.subs.contains_key("s"),
                "the CLOSED must release the subscription"
            );
            assert_eq!(events_sent, 1, "the first event fits the budget");
            assert!(
                closed.is_some_and(|m| m[2].as_str().unwrap().contains("response too large")),
                "the over-budget response must be closed"
            );
            assert!(
                !msgs.iter().any(|m| m[0] == "EOSE"),
                "a closed response must not send EOSE"
            );
            assert!(
                conn.pending_reqs.is_empty(),
                "the closed response must not stay queued"
            );
            // An event larger than the whole budget closes immediately.
            let mut events = std::collections::VecDeque::new();
            events.push_back(signed_note(
                conn.relay.secp(),
                &"z".repeat(10_000),
                now,
                vec![],
            ));
            conn.subs
                .insert("s2".into(), (Vec::new(), 0, "\"s2\"".into()));
            conn.enqueue_pending_req(PendingReq {
                sub_id: "s2".into(),
                events,
                eose_hint: false,
                truncated_or_more: false,
                auth_hint: false,
                sent_bytes: 0,
                live: Default::default(),
                live_bytes: 0,
                eose_sent: false,
                budget: None,
                reserved: 0,
            });
            conn.pump_pending_reqs();
            let msgs = outgoing_json(&conn);
            assert!(
                msgs.iter().any(|m| m[0] == "CLOSED" && m[1] == "s2"),
                "an event beyond the whole budget closes without delivery"
            );
            assert!(!conn.subs.contains_key("s2"));
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn pump_oversized_response_keeps_the_next_pending() {
        // Regression: the over-budget CLOSED removed its entry via
        // `remove_req_subscription` and then popped the queue front again,
        // silently discarding the *next* subscription's stored response
        // (no events, no EOSE), so that client waited forever.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            conn.req_response_bytes = 3_000;
            let now = unix_now();
            conn.subs
                .insert("a".into(), (Vec::new(), 0, "\"a\"".into()));
            let mut big = std::collections::VecDeque::new();
            for i in 0..3 {
                big.push_back(signed_note(
                    conn.relay.secp(),
                    &format!("big-{i}-{}", "y".repeat(2_000)),
                    now - i,
                    vec![],
                ));
            }
            conn.enqueue_pending_req(PendingReq {
                sub_id: "a".into(),
                events: big,
                eose_hint: false,
                truncated_or_more: false,
                auth_hint: false,
                sent_bytes: 0,
                live: Default::default(),
                live_bytes: 0,
                eose_sent: false,
                budget: None,
                reserved: 0,
            });
            conn.subs
                .insert("b".into(), (Vec::new(), 0, "\"b\"".into()));
            let mut small = std::collections::VecDeque::new();
            small.push_back(signed_note(conn.relay.secp(), "small", now, vec![]));
            conn.enqueue_pending_req(PendingReq {
                sub_id: "b".into(),
                events: small,
                eose_hint: false,
                truncated_or_more: false,
                auth_hint: false,
                sent_bytes: 0,
                live: Default::default(),
                live_bytes: 0,
                eose_sent: false,
                budget: None,
                reserved: 0,
            });
            conn.pump_pending_reqs();
            let msgs = outgoing_json(&conn);
            assert!(
                msgs.iter().any(|m| m[0] == "CLOSED" && m[1] == "a"),
                "the over-budget response is closed"
            );
            assert_eq!(
                msgs.iter()
                    .filter(|m| m[0] == "EVENT" && m[1] == "b")
                    .count(),
                1,
                "the next subscription's event must still be delivered"
            );
            assert!(
                msgs.iter().any(|m| m[0] == "EOSE" && m[1] == "b"),
                "the next subscription must still receive its EOSE"
            );
            assert!(
                !conn.subs.contains_key("a") && !conn.pending_reqs.iter().any(|p| p.sub_id == "b"),
                "a is released and b is fully pumped"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn pending_reqs_are_bounded_and_the_oldest_is_cut_off() {
        // More than MAX_PENDING_REQS queued REQ responses (a client
        // flooding REQs while reading slowly): the oldest is cut off with
        // its EOSE sent immediately, so the subscription never hangs.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            for i in 0..5 {
                conn.subs
                    .insert(format!("s{i}"), (Vec::new(), 0, String::new()));
                let mut events = std::collections::VecDeque::new();
                events.push_back(signed_note(
                    conn.relay.secp(),
                    &format!("e{i}"),
                    now - i,
                    vec![],
                ));
                conn.enqueue_pending_req(PendingReq {
                    sub_id: format!("s{i}"),
                    events,
                    eose_hint: true,
                    truncated_or_more: false,
                    auth_hint: false,
                    sent_bytes: 0,
                    live: Default::default(),
                    live_bytes: 0,
                    eose_sent: false,
                    budget: None,
                    reserved: 0,
                });
            }
            assert_eq!(
                conn.pending_reqs.len(),
                MAX_PENDING_REQS,
                "the queue must be bounded"
            );
            // The cut-off response (s0) got its EOSE immediately.
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "EOSE" && m[1] == "s0"),
                "the oldest response must be finished with an EOSE"
            );
            // The remaining responses are pumped in order with their
            // EOSEs (eose_hint = true -> the hint variant).
            let mut all = Vec::new();
            loop {
                conn.pump_pending_reqs();
                for m in outgoing_json(&conn) {
                    all.push(m.clone());
                }
                conn.outgoing.clear();
                conn.out_bytes = 0;
                if conn.pending_reqs.is_empty() {
                    break;
                }
            }
            for i in 1..5 {
                assert!(
                    all.iter()
                        .any(|m| m[0] == "EOSE" && m[1] == format!("s{i}")),
                    "response s{i} must finish with its EOSE"
                );
            }
            assert!(
                all.iter()
                    .any(|m| m[0] == "EOSE" && m[1] == "s1" && m[2] == json!(["finish"])),
                "the hint variant must be sent when eose_hint is on"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn pending_req_cutoff_does_not_resend_eose() {
        // A pending response whose EOSE was already sent (its buffered live
        // events still queued) must not receive a second EOSE when the
        // pending queue overflows, and a CLOSEd subscription must not
        // receive an EOSE at all.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            conn.subs
                .insert("s0".into(), (Vec::new(), 0, "\"s0\"".into()));
            let mut live = std::collections::VecDeque::new();
            live.push_back("[\"EVENT\",\"s0\",{}]".to_string());
            conn.enqueue_pending_req(PendingReq {
                sub_id: "s0".into(),
                events: Default::default(),
                eose_hint: true,
                truncated_or_more: false,
                auth_hint: false,
                sent_bytes: 0,
                live,
                live_bytes: 0,
                eose_sent: true,
                budget: None,
                reserved: 0,
            });
            for i in 1..=MAX_PENDING_REQS {
                conn.subs
                    .insert(format!("s{i}"), (Vec::new(), 0, String::new()));
                conn.enqueue_pending_req(PendingReq {
                    sub_id: format!("s{i}"),
                    events: Default::default(),
                    eose_hint: true,
                    truncated_or_more: false,
                    auth_hint: false,
                    sent_bytes: 0,
                    live: Default::default(),
                    live_bytes: 0,
                    eose_sent: false,
                    budget: None,
                    reserved: 0,
                });
            }

            assert!(
                !outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "EOSE" && m[1] == "s0"),
                "a response whose EOSE was already sent must not get a second EOSE"
            );

            // The same cutoff for a CLOSEd subscription stays silent.
            conn.pending_reqs.clear();
            conn.outgoing.clear();
            conn.out_bytes = 0;
            conn.enqueue_pending_req(PendingReq {
                sub_id: "gone".into(),
                events: Default::default(),
                eose_hint: true,
                truncated_or_more: false,
                auth_hint: false,
                sent_bytes: 0,
                live: Default::default(),
                live_bytes: 0,
                eose_sent: false,
                budget: None,
                reserved: 0,
            });
            for i in 0..MAX_PENDING_REQS {
                conn.enqueue_pending_req(PendingReq {
                    sub_id: format!("t{i}"),
                    events: Default::default(),
                    eose_hint: true,
                    truncated_or_more: false,
                    auth_hint: false,
                    sent_bytes: 0,
                    live: Default::default(),
                    live_bytes: 0,
                    eose_sent: false,
                    budget: None,
                    reserved: 0,
                });
            }
            assert!(
                !outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "EOSE" && m[1] == "gone"),
                "a CLOSEd subscription must not receive an EOSE"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn pending_req_cutoff_closes_a_subscription_with_pre_eose_live_events() {
        // Live events buffered before the EOSE cannot be delivered once the
        // response is cut off: without a CLOSED the subscription would look
        // healthy while silently missing them (ephemeral events are not
        // recoverable by a re-REQ).
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            conn.subs
                .insert("s0".into(), (Vec::new(), 0, "\"s0\"".into()));
            let mut live = std::collections::VecDeque::new();
            live.push_back("[\"EVENT\",\"s0\",{}]".to_string());
            conn.enqueue_pending_req(PendingReq {
                sub_id: "s0".into(),
                events: Default::default(),
                eose_hint: true,
                truncated_or_more: false,
                auth_hint: false,
                sent_bytes: 0,
                live,
                live_bytes: 0,
                eose_sent: false,
                budget: None,
                reserved: 0,
            });
            for i in 1..=MAX_PENDING_REQS {
                conn.subs
                    .insert(format!("s{i}"), (Vec::new(), 0, String::new()));
                conn.enqueue_pending_req(PendingReq {
                    sub_id: format!("s{i}"),
                    events: Default::default(),
                    eose_hint: true,
                    truncated_or_more: false,
                    auth_hint: false,
                    sent_bytes: 0,
                    live: Default::default(),
                    live_bytes: 0,
                    eose_sent: false,
                    budget: None,
                    reserved: 0,
                });
            }
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "CLOSED" && m[1] == "s0"),
                "dropping buffered live events must close the subscription"
            );
            assert!(
                !conn.subs.contains_key("s0"),
                "the closed subscription must be released"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn close_removes_pending_req_response() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            conn.enqueue_pending_req(PendingReq {
                sub_id: "stale".into(),
                events: std::collections::VecDeque::from([Event {
                    id: "a".repeat(64),
                    pubkey: "b".repeat(64),
                    created_at: 1,
                    kind: 1,
                    tags: Vec::new(),
                    content: "stale".into(),
                    sig: "c".repeat(128),
                }]),
                eose_hint: false,
                truncated_or_more: false,
                auth_hint: false,
                sent_bytes: 0,
                live: Default::default(),
                live_bytes: 0,
                eose_sent: false,
                budget: None,
                reserved: 0,
            });

            conn.remove_req_subscription("stale");
            conn.pump_pending_reqs();

            assert!(conn.pending_reqs.is_empty());
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .all(|message| message[0] != "EVENT" && message[0] != "EOSE"),
                "closing a subscription must discard its pending response"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn rering_purges_stale_control_frames_for_the_replaced_id() {
        // Regression: control frames were queued untagged, so a re-REQ
        // could not purge a CLOSED queued by the previous incarnation (a
        // failed filters-less REQ) and the client saw its new subscription
        // closed on the wire.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            conn.handle_req(&[json!("s")]).await;
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "CLOSED" && m[1] == "s"),
                "the filters-less refusal is queued as a tagged CLOSED"
            );
            // The corrected re-REQ must purge the stale CLOSED before
            // queueing the new response.
            conn.handle_req(&[json!("s"), json!({"kinds": [1]})]).await;
            conn.pump_pending_reqs();
            let msgs = outgoing_json(&conn);
            assert!(
                !msgs.iter().any(|m| m[0] == "CLOSED" && m[1] == "s"),
                "a stale CLOSED must not close the new subscription: {msgs:?}"
            );
            assert_eq!(
                msgs.iter()
                    .filter(|m| m[0] == "EOSE" && m[1] == "s")
                    .count(),
                1,
                "only the replacement's EOSE is delivered"
            );
            assert!(conn.subs.contains_key("s"), "the new subscription is open");

            // CLOSE purges a still-queued EOSE of the id too.
            conn.outgoing.clear();
            conn.out_bytes = 0;
            conn.handle_req(&[json!("s"), json!({"kinds": [1]})]).await;
            conn.pump_pending_reqs();
            assert!(
                outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "EOSE" && m[1] == "s"),
                "the resubscribed response is queued"
            );
            conn.handle_close(&[json!("s")]);
            assert!(
                !outgoing_json(&conn)
                    .iter()
                    .any(|m| m[0] == "EOSE" && m[1] == "s"),
                "CLOSE must purge the still-queued EOSE of the id"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn purge_adjusts_all_outgoing_counters() {
        // The removed frames were counted when queued but never reach the
        // wire: the purge must forget them in every counter, not only
        // `out_bytes`.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            assert!(conn.send_tagged(
                Message::Text("[\"EVENT\",\"s\",{}]".into()),
                Some(sub_fingerprint("s")),
            ));
            conn.send_closed("s", "error: stale");
            conn.send(Message::Text("[\"NOTICE\",\"keep\"]".into()));
            let (bytes, msgs, total) = (conn.out_bytes, conn.out_msgs, conn.out_bytes_total);
            assert_eq!(conn.outgoing.len(), 3);

            conn.purge_queued_events_for("s");

            assert_eq!(conn.outgoing.len(), 1, "only the untagged NOTICE remains");
            let removed_bytes = bytes - conn.out_bytes;
            assert!(removed_bytes > 0, "the tagged frames carried bytes");
            assert_eq!(conn.out_msgs, msgs - 2, "both tagged frames are uncounted");
            assert_eq!(conn.out_bytes_total, total - removed_bytes as u64);
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn teardown_abandon_uncounts_unsent_frames() {
        // Frames that never reach the socket must not count as traffic:
        // a teardown against a dead sink abandons the whole queue, so the
        // flush must release every counter it charged at queue time.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            conn.send(Message::Text("[\"NOTICE\",\"a\"]".into()));
            conn.send(Message::Text("[\"NOTICE\",\"b\"]".into()));
            assert_eq!(conn.outgoing.len(), 2);
            assert!(conn.out_msgs > 0 && conn.out_bytes_total > 0);

            let mut sink = FailingSink;
            flush_and_close(&mut conn, &mut sink, Duration::from_secs(5)).await;

            assert!(conn.outgoing.is_empty(), "the abandoned queue is drained");
            assert_eq!(conn.out_bytes, 0, "abandoned bytes are released");
            assert_eq!(conn.out_msgs, 0, "unsent frames are not messages out");
            assert_eq!(conn.out_bytes_total, 0, "unsent frames are not bytes out");
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn pending_live_overflow_marks_connection_for_close() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            conn.subs
                .insert("sub".into(), (vec![Filter::default()], 0, "\"sub\"".into()));
            let live = std::collections::VecDeque::from_iter(
                (0..OUT_QUEUE_LIMIT).map(|_| "[\"EVENT\",\"sub\",{}]".to_string()),
            );
            conn.enqueue_pending_req(PendingReq {
                sub_id: "sub".into(),
                events: Default::default(),
                eose_hint: false,
                truncated_or_more: false,
                auth_hint: false,
                sent_bytes: 0,
                live,
                live_bytes: 0,
                eose_sent: false,
                budget: None,
                reserved: 0,
            });

            let event = signed_note(conn.relay.secp(), "overflow", unix_now(), vec![]);
            let json = serde_json::to_string(&event).unwrap();
            conn.deliver_live(&event, &json, None);
            conn.close_for_live_overflow();

            assert!(
                conn.live_overflowed,
                "pending live overflow must close the connection"
            );
            assert!(
                outgoing_json(&conn).iter().any(|message| {
                    message[0] == "CLOSED"
                        && message[1] == "sub"
                        && message[2]
                            .as_str()
                            .unwrap_or("")
                            .contains("reconnect and resubscribe")
                }),
                "overflow must tell the client to reconnect and resubscribe"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn pending_live_hold_applies_the_safety_ceiling_when_uncapped() {
        // `max_out_queue_bytes = 0` means "no configured cap", not "no
        // bound": the pending-live hold must use the same safety ceiling
        // as the drain path, or a slow reader with no configured cap
        // could pin gigabytes in the per-response backlog.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            conn.subs
                .insert("sub".into(), (vec![Filter::default()], 0, "\"sub\"".into()));
            conn.enqueue_pending_req(PendingReq {
                sub_id: "sub".into(),
                events: Default::default(),
                eose_hint: false,
                truncated_or_more: false,
                auth_hint: false,
                sent_bytes: 0,
                live: Default::default(),
                live_bytes: 0,
                eose_sent: false,
                budget: None,
                reserved: 0,
            });
            // Unset queue cap, tiny REQ budget: the safety ceiling is
            // 2 * 100 = 200 bytes.
            conn.out_queue_bytes = 0;
            conn.req_response_bytes = 100;
            // One live frame larger than the ceiling must overflow the
            // pending backlog instead of accumulating without bound.
            let event = signed_note(conn.relay.secp(), &"x".repeat(300), unix_now(), vec![]);
            let json = serde_json::to_string(&event).unwrap();
            conn.deliver_live(&event, &json, None);
            assert!(
                conn.live_overflowed,
                "the pending backlog must respect the safety ceiling when uncapped"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn live_drop_at_the_outgoing_cap_marks_overflow() {
        // A live event dropped at the outgoing cap (for a subscription
        // whose stored response already EOSE'd) is unrecoverable —
        // ephemeral events are not stored anywhere — so the connection
        // must be closed for resynchronization instead of silently
        // missing the event.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            conn.subs
                .insert("s".into(), (vec![Filter::default()], 0, "\"s\"".into()));
            // One queued frame plus a one-byte cap: the next queued frame
            // (the live event) is dropped.
            conn.out_queue_bytes = 1;
            conn.send(Message::Text("x".into()));
            assert_eq!(conn.outgoing.len(), 1);

            let event = signed_note(conn.relay.secp(), "live", unix_now(), vec![]);
            let json = serde_json::to_string(&event).unwrap();
            conn.deliver_live(&event, &json, None);

            assert!(
                conn.live_overflowed,
                "a live drop at the outgoing cap must mark the connection for close"
            );
            conn.close_for_live_overflow();
            assert!(
                outgoing_json(&conn).iter().any(|message| {
                    message[0] == "CLOSED"
                        && message[1] == "s"
                        && message[2]
                            .as_str()
                            .unwrap_or("")
                            .contains("reconnect and resubscribe")
                }),
                "the client must be told to resubscribe"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn eose_auth_hint_is_preceded_by_a_challenge() {
        // NIP-67 `"auth"` hint: the hint array carries `"auth"`, and the
        // spec's MUST — an AUTH message before the EOSE — is honored by
        // queueing the challenge ahead of the EOSE.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            conn.subs
                .insert("s".into(), (Vec::new(), 0, "\"s\"".into()));
            conn.enqueue_pending_req(PendingReq {
                sub_id: "s".into(),
                events: std::collections::VecDeque::new(),
                eose_hint: true,
                truncated_or_more: false,
                auth_hint: true,
                sent_bytes: 0,
                live: Default::default(),
                live_bytes: 0,
                eose_sent: false,
                budget: None,
                reserved: 0,
            });
            conn.pump_pending_reqs();
            let msgs = outgoing_json(&conn);
            let eose = msgs
                .iter()
                .position(|m| m[0] == "EOSE")
                .expect("an EOSE is sent");
            let auth = msgs
                .iter()
                .position(|m| m[0] == "AUTH")
                .expect("the AUTH challenge must precede the hint EOSE");
            assert!(
                auth < eose,
                "the AUTH challenge must be queued before the EOSE containing the hint"
            );
            assert_eq!(
                msgs[eose][2],
                json!(["auth", "finish"]),
                "the hint array carries auth and finish"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn req_emits_auth_hint_when_protected_events_are_withheld() {
        // An anonymous REQ over a subscription that also matches NIP-70
        // protected events gets `["EOSE", sub, ["auth", "finish"]]` with a
        // challenge first; the authenticated owner instead receives the
        // protected event and a plain `["finish"]`.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay_with("").await;
            let mut conn = build_conn_on(relay.clone()).await;
            let now = unix_now();
            let normal = signed_note(relay.secp(), "public", now, vec![]);
            let protected = signed_note(relay.secp(), "secret", now, vec![vec!["-".into()]]);
            relay.db.put(normal.clone(), now).await;
            relay.db.put(protected.clone(), now).await;

            conn.handle_req(&[json!("sub"), json!({"kinds": [1]})])
                .await;
            conn.pump_pending_reqs();
            let msgs = outgoing_json(&conn);
            assert!(
                !msgs
                    .iter()
                    .any(|m| m[0] == "EVENT" && m[2]["id"] == protected.id),
                "the protected event stays hidden from anonymous"
            );
            let eose = msgs
                .iter()
                .position(|m| m[0] == "EOSE")
                .expect("an EOSE is sent");
            assert_eq!(
                msgs[eose][2],
                json!(["auth", "finish"]),
                "withheld auth-gated events must carry the auth hint"
            );
            assert!(
                msgs.iter().take(eose).any(|m| m[0] == "AUTH"),
                "the challenge must be queued before the auth-hinted EOSE"
            );

            // The authenticated owner fetches the whole subscription: no
            // auth hint, no extra challenge.
            let mut owner = build_conn_on(relay).await;
            let auth = signed_auth(owner.relay.secp(), "test-challenge", now);
            owner
                .handle_auth(&[serde_json::to_value(&auth).unwrap()])
                .await;
            owner
                .handle_req(&[json!("sub"), json!({"kinds": [1]})])
                .await;
            owner.pump_pending_reqs();
            let msgs = outgoing_json(&owner);
            assert!(
                !msgs.iter().any(|m| m[0] == "AUTH"),
                "an authed owner needs no extra challenge"
            );
            let eose = msgs
                .iter()
                .position(|m| m[0] == "EOSE")
                .expect("an EOSE is sent");
            assert_eq!(
                msgs[eose][2],
                json!(["finish"]),
                "the authed owner gets a plain finish"
            );

            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn pump_skips_closed_subscriptions_and_replaced_ids() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            let mut events = std::collections::VecDeque::new();
            events.push_back(signed_note(conn.relay.secp(), "e0", now, vec![]));
            // A response whose subscription was CLOSEd in the meantime is
            // dropped by the pump without events or EOSE.
            conn.enqueue_pending_req(PendingReq {
                sub_id: "closed".into(),
                events,
                eose_hint: true,
                truncated_or_more: false,
                auth_hint: false,
                sent_bytes: 0,
                live: Default::default(),
                live_bytes: 0,
                eose_sent: false,
                budget: None,
                reserved: 0,
            });
            conn.pump_pending_reqs();
            assert!(
                conn.pending_reqs.is_empty(),
                "the response of a closed subscription must be dropped"
            );
            assert!(
                outgoing_json(&conn).is_empty(),
                "no events or EOSE may be queued for a closed subscription"
            );
            // A REQ replacing the same subscription id drops the stale
            // still-pumping response.
            conn.subs
                .insert("s".into(), (Vec::new(), 0, "\"s\"".into()));
            let mut first = std::collections::VecDeque::new();
            first.push_back(signed_note(conn.relay.secp(), "old", now, vec![]));
            conn.enqueue_pending_req(PendingReq {
                sub_id: "s".into(),
                events: first,
                eose_hint: false,
                truncated_or_more: false,
                auth_hint: false,
                sent_bytes: 0,
                live: Default::default(),
                live_bytes: 0,
                eose_sent: false,
                budget: None,
                reserved: 0,
            });
            let mut second = std::collections::VecDeque::new();
            second.push_back(signed_note(conn.relay.secp(), "new", now - 1, vec![]));
            conn.enqueue_pending_req(PendingReq {
                sub_id: "s".into(),
                events: second,
                eose_hint: false,
                truncated_or_more: false,
                auth_hint: false,
                sent_bytes: 0,
                live: Default::default(),
                live_bytes: 0,
                eose_sent: false,
                budget: None,
                reserved: 0,
            });
            assert_eq!(conn.pending_reqs.len(), 1, "the stale response is dropped");
            conn.pump_pending_reqs();
            let msgs = outgoing_json(&conn);
            assert!(
                msgs.iter()
                    .any(|m| m[0] == "EVENT" && m[2]["content"] == "new"),
                "only the replacement response is delivered"
            );
            assert!(
                !msgs
                    .iter()
                    .any(|m| m[0] == "EVENT" && m[2]["content"] == "old"),
                "the stale response must not be delivered"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn eose_is_delivered_even_at_the_message_count_cap() {
        // A REQ response of exactly OUT_QUEUE_LIMIT events fills the
        // queue to the message-count cap; the EOSE must still be queued
        // (a dropped EOSE would leave the client hanging on a completed
        // subscription).
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            // A byte cap generous enough that the message-count cap is the
            // binding constraint for ~300-byte events (4096 of them).
            conn.out_queue_bytes = 8 << 20;
            conn.subs
                .insert("s".into(), (Vec::new(), 0, "\"s\"".into()));
            let now = unix_now();
            let mut events = std::collections::VecDeque::new();
            for i in 0..OUT_QUEUE_LIMIT {
                events.push_back(signed_note(
                    conn.relay.secp(),
                    &format!("tiny-{i}"),
                    now - i as u64,
                    vec![],
                ));
            }
            conn.enqueue_pending_req(PendingReq {
                sub_id: "s".into(),
                events,
                eose_hint: false,
                truncated_or_more: false,
                auth_hint: false,
                sent_bytes: 0,
                live: Default::default(),
                live_bytes: 0,
                eose_sent: false,
                budget: None,
                reserved: 0,
            });
            conn.pump_pending_reqs();
            let msgs = outgoing_json(&conn);
            assert_eq!(
                msgs.iter().filter(|m| m[0] == "EVENT").count(),
                OUT_QUEUE_LIMIT,
                "all events must be queued"
            );
            assert!(
                msgs.iter().any(|m| m[0] == "EOSE" && m[1] == "s"),
                "the EOSE must be delivered even at the message-count cap"
            );
            assert!(
                conn.pending_reqs.is_empty(),
                "the response must be finished"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn pending_event_batch_is_bounded_by_count_and_bytes() {
        // A flood of maximum-size frames must not accumulate parsed events
        // up to the whole window cap: the batch is flushed at EVENT_BATCH
        // events or one full frame's bytes, whichever comes first.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            let max_msg = 1 << 20;
            assert!(!conn.pending_batch_full(max_msg));
            // Bytes: one full-size frame trips the bound.
            let ev = signed_note(conn.relay.secp(), "big", now, vec![]);
            conn.queue_event_sized(ev, max_msg).await;
            assert_eq!(conn.pending_bytes, max_msg);
            assert!(conn.pending_batch_full(max_msg), "the byte bound must trip");
            conn.flush_pending_events().await;
            assert!(conn.pending_events.is_empty());
            assert_eq!(conn.pending_bytes, 0, "the byte counter resets on flush");
            assert!(!conn.pending_batch_full(max_msg));
            // Count: EVENT_BATCH small events trip the bound.
            for i in 0..EVENT_BATCH - 1 {
                let ev = signed_note(
                    conn.relay.secp(),
                    &format!("small-{i}"),
                    now - i as u64,
                    vec![],
                );
                conn.queue_event_sized(ev, 64).await;
            }
            assert!(
                !conn.pending_batch_full(max_msg),
                "below the count bound the batch stays open"
            );
            let ev = signed_note(conn.relay.secp(), "last", now, vec![]);
            conn.queue_event_sized(ev, 64).await;
            assert!(
                conn.pending_batch_full(max_msg),
                "the count bound must trip"
            );
            conn.flush_pending_events().await;
            assert_eq!(conn.pending_bytes, 0);
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn refused_count_releases_the_same_id_req_subscription() {
        // NIP-01/NIP-45: CLOSED is terminal for a subscription id. A COUNT
        // refused with CLOSED for an id that is also an active REQ
        // subscription must release that subscription, or the client would
        // consider it closed while the relay kept delivering live events.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            // Open a REQ subscription "x".
            conn.handle_req(&[json!("x"), json!({"kinds": [1]})]).await;
            conn.pump_pending_reqs();
            assert!(conn.subs.contains_key("x"), "the REQ subscription is open");
            // Disable COUNT and refuse a COUNT with the same id.
            conn.relay.config.write().await.relay.disabled_nips.push(45);
            conn.handle_count(&[json!("x"), json!({"kinds": [1]})])
                .await;
            let msgs = outgoing_json(&conn);
            assert!(
                msgs.iter().any(|m| m[0] == "CLOSED" && m[1] == "x"),
                "the refusal must be a CLOSED"
            );
            assert!(
                !conn.subs.contains_key("x"),
                "the same-id REQ subscription must be released with the CLOSED"
            );
            // The live index no longer wakes the connection for "x".
            assert!(
                conn.relay
                    .sub_index
                    .read()
                    .unwrap_or_else(|p| p.into_inner())
                    .candidates(&signed_note(conn.relay.secp(), "after", unix_now(), vec![]))
                    .is_empty(),
                "a closed subscription must not receive live events"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn filters_less_req_and_count_are_closed_when_an_id_is_present() {
        // NIP-01/NIP-45 refusals: with a subscription id the client gets a
        // correlated CLOSED carrying an `invalid:` prefix; only when no id
        // can be echoed is a NOTICE the best reply.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            conn.handle_req(&[json!("sub")]).await;
            let msgs = outgoing_json(&conn);
            let closed = msgs
                .iter()
                .find(|m| m[0] == "CLOSED" && m[1] == "sub")
                .expect("a filters-less REQ with an id must be closed");
            assert!(
                closed[2].as_str().unwrap_or("").starts_with("invalid:"),
                "the refusal must carry an invalid: prefix: {closed:?}"
            );
            assert!(
                !msgs.iter().any(|m| m[0] == "NOTICE"),
                "the id allows a correlated CLOSED instead of a NOTICE"
            );

            conn.outgoing.clear();
            conn.out_bytes = 0;
            conn.handle_req(&[]).await;
            let msgs = outgoing_json(&conn);
            assert!(msgs.iter().any(|m| m[0] == "NOTICE"));
            assert!(!msgs.iter().any(|m| m[0] == "CLOSED"));

            conn.outgoing.clear();
            conn.out_bytes = 0;
            conn.handle_count(&[json!("sub")]).await;
            let msgs = outgoing_json(&conn);
            let closed = msgs
                .iter()
                .find(|m| m[0] == "CLOSED" && m[1] == "sub")
                .expect("a filters-less COUNT with an id must be closed");
            assert!(
                closed[2].as_str().unwrap_or("").starts_with("invalid:"),
                "the COUNT refusal must carry an invalid: prefix: {closed:?}"
            );
            assert!(!msgs.iter().any(|m| m[0] == "NOTICE"));

            conn.outgoing.clear();
            conn.out_bytes = 0;
            conn.handle_count(&[]).await;
            let msgs = outgoing_json(&conn);
            assert!(msgs.iter().any(|m| m[0] == "NOTICE"));
            assert!(!msgs.iter().any(|m| m[0] == "CLOSED"));
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn source_ip_blocked_and_change_notification() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let conn = build_conn().await;
            let peer: std::net::IpAddr = "198.51.100.7".parse().unwrap();
            assert!(!conn.source_ip_blocked(peer).await);
            // A v4-mapped entry must match the plain IPv4 peer.
            conn.relay
                .access
                .write()
                .await
                .blocked_ips
                .push("::ffff:198.51.100.7".into(), String::new());
            assert!(conn.source_ip_blocked(peer).await);
            // Every mutation wakes the connection's watcher immediately,
            // which is what disconnects read-only subscribers.
            let mut rx = conn.relay.ip_blocks_tx.subscribe();
            conn.relay.note_ip_blocks_changed();
            assert!(
                rx.changed().await.is_ok(),
                "the block change must wake the connection watcher"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn malformed_event_and_auth_still_get_ok() {
        // NIP-01/NIP-42: EVENT and AUTH messages must be answered with OK
        // even when the payload is malformed, as long as an id can be
        // correlated.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let id = "ab".repeat(32);
            conn.handle_text(&format!(r#"["EVENT", {{"id":"{id}","created_at":-1}}]"#))
                .await;
            let msgs = outgoing_json(&conn);
            let ok = msgs
                .iter()
                .find(|m| m[0] == "OK" && m[1] == id)
                .expect("a malformed EVENT with an id must get an OK");
            assert_eq!(ok[2], false);
            assert!(
                ok[3].as_str().unwrap_or("").starts_with("invalid:"),
                "the OK must carry a machine-readable reason: {ok:?}"
            );

            // Without an id the OK correlates with the empty id: NIP-01
            // still requires a response for every EVENT frame.
            conn.outgoing.clear();
            conn.out_bytes = 0;
            conn.handle_text(r#"["EVENT", {"created_at":-1}]"#).await;
            let msgs = outgoing_json(&conn);
            let ok = msgs
                .iter()
                .find(|m| m[0] == "OK" && m[1] == "")
                .expect("a malformed EVENT without an id still gets an OK");
            assert_eq!(ok[2], false);
            assert!(
                ok[3].as_str().unwrap_or("").starts_with("invalid:"),
                "the OK must carry a machine-readable reason: {ok:?}"
            );
            assert!(!msgs.iter().any(|m| m[0] == "NOTICE"));

            // An EVENT frame without an event object likewise gets OK "".
            conn.outgoing.clear();
            conn.out_bytes = 0;
            conn.handle_text(r#"["EVENT"]"#).await;
            let msgs = outgoing_json(&conn);
            assert!(
                msgs.iter()
                    .any(|m| m[0] == "OK" && m[1] == "" && m[2] == false),
                "an EVENT without an object must still get an OK"
            );

            // A malformed AUTH with an id likewise gets OK false.
            conn.outgoing.clear();
            conn.out_bytes = 0;
            conn.handle_text(&format!(r#"["AUTH", {{"id":"{id}","created_at":-1}}]"#))
                .await;
            let msgs = outgoing_json(&conn);
            let ok = msgs
                .iter()
                .find(|m| m[0] == "OK" && m[1] == id)
                .expect("a malformed AUTH with an id must get an OK");
            assert_eq!(ok[2], false);

            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn uppercase_auth_pubkey_is_rejected() {
        // NIP-01: hex fields are lowercase. An uppercase AUTH pubkey would
        // verify but never match the exact-case author checks, so it must be
        // refused instead of stored as an authenticated key.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            let mut auth = signed_auth(conn.relay.secp(), "test-challenge", now);
            auth.pubkey = auth.pubkey.to_ascii_uppercase();
            auth.id = crate::nips::nip01::compute_id(&auth);
            let keypair = Keypair::from_seckey_slice(conn.relay.secp(), &[2u8; 32]).unwrap();
            let id = auth.id_bytes().unwrap();
            auth.sig = conn
                .relay
                .secp()
                .sign_schnorr_no_aux_rand(&id, &keypair)
                .to_string();
            conn.handle_auth(&[serde_json::to_value(&auth).unwrap()])
                .await;
            let msgs = outgoing_json(&conn);
            let ok = msgs
                .iter()
                .find(|m| m[0] == "OK" && m[1] == auth.id)
                .expect("AUTH must be answered with OK");
            assert_eq!(ok[2], false, "uppercase pubkeys must be rejected");
            assert!(!conn.is_authed(), "no key must be recorded");
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn auth_attempt_cap_still_answers_ok() {
        // NIP-42: every AUTH must be answered with OK, including the
        // attempt-cap refusal (a NOTICE leaves the client without a
        // correlated response).
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            conn.auth_attempts = 256;
            let id = "ab".repeat(32);
            conn.handle_auth(&[json!({"id": id})]).await;
            let msgs = outgoing_json(&conn);
            let ok = msgs
                .iter()
                .find(|m| m[0] == "OK")
                .expect("the attempt-cap refusal must answer OK");
            assert_eq!(ok[1], id);
            assert_eq!(ok[2], false);
            assert!(
                ok[3]
                    .as_str()
                    .unwrap_or("")
                    .contains("too many AUTH attempts"),
                "the OK must carry the attempt-cap reason: {ok:?}"
            );
            assert!(!msgs.iter().any(|m| m[0] == "NOTICE"));
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn auth_key_cap_rejects_new_keys_without_evicting() {
        // The distinct-key cap is a DoS guard, not a FIFO eviction: an
        // eviction would silently invalidate an earlier `OK true`. The new
        // key is refused with an explicit OK false and the list is kept.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            conn.authed_pubkeys = (0..64u64).map(|i| format!("{i:064x}")).collect();
            let auth = signed_auth(conn.relay.secp(), "test-challenge", now);
            conn.handle_auth(&[serde_json::to_value(&auth).unwrap()])
                .await;
            let msgs = outgoing_json(&conn);
            let ok = msgs
                .iter()
                .find(|m| m[0] == "OK" && m[1] == auth.id)
                .expect("AUTH must be answered with OK");
            assert_eq!(ok[2], false);
            assert!(
                ok[3]
                    .as_str()
                    .unwrap_or("")
                    .contains("too many authenticated keys"),
                "the OK must explain the key cap: {ok:?}"
            );
            assert_eq!(conn.authed_pubkeys.len(), 64, "the cap is kept");
            assert!(
                conn.authed_pubkeys.contains(&"0".repeat(64)),
                "the oldest key must not be evicted"
            );
            assert!(
                !conn.authed_pubkeys.contains(&auth.pubkey),
                "the refused key must not be recorded"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn deletion_without_targets_is_rejected() {
        // NIP-09: a deletion request (kind 5) is defined as having one or
        // more `e`/`a` tags; one without targets is rejected.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            let bare = signed_note(conn.relay.secp(), "delete nothing", now, vec![]);
            let mut bare = bare;
            bare.kind = 5;
            bare.id = crate::nips::nip01::compute_id(&bare);
            conn.queue_event_value(bare.clone()).await;
            conn.flush_pending_events().await;
            let msgs = outgoing_json(&conn);
            let ok = msgs
                .iter()
                .find(|m| m[0] == "OK" && m[1] == bare.id)
                .expect("an OK reply is sent");
            assert_eq!(ok[2], false);
            assert!(
                ok[3]
                    .as_str()
                    .unwrap_or("")
                    .contains("deletion request must reference"),
                "the reason must explain the rejection"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn live_index_survives_close_and_resubscribe() {
        // Regression: closing the last subscription used to drop the live
        // receiver (the old design), which the per-connection index delivery
        // never recreated — a resubscribed connection silently stopped
        // receiving live events.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            conn.handle_req(&[json!("a"), json!({"kinds": [1]})]).await;
            conn.handle_close(&[json!("a")]);
            // The connection is unregistered after the close.
            assert!(
                conn.relay
                    .sub_index
                    .read()
                    .unwrap_or_else(|p| p.into_inner())
                    .candidates(&signed_note(conn.relay.secp(), "x", now, vec![]))
                    .is_empty(),
                "no subscriptions after CLOSE"
            );
            // Resubscribe: the live receiver must still be alive and the
            // connection must be a candidate again.
            conn.handle_req(&[json!("b"), json!({"kinds": [1]})]).await;
            assert!(
                conn.live.is_some(),
                "live receiver survives a CLOSE + REQ cycle"
            );
            let ev = signed_note(conn.relay.secp(), "resubscribed", now, vec![]);
            let ev_id = ev.id.clone();
            assert!(conn.relay.broadcast(ev).await.is_ok());
            let received = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                conn.live.as_mut().unwrap().recv(),
            )
            .await
            .expect("live delivery resumes after CLOSE + REQ")
            .expect("the live channel stays open");
            assert!(
                received.iter().any(|(e, _)| e.id == ev_id),
                "the resubscribed connection must receive the event"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn send_control_is_bounded_as_last_resort() {
        // `send_control` bypasses the byte cap so completion-critical
        // messages are never dropped, but the queue length still caps at
        // twice `OUT_QUEUE_LIMIT`: 8192 tiny EOSEs queued without a drain
        // means an attacker, not a slow reader.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            for _ in 0..OUT_QUEUE_LIMIT * 2 {
                conn.send_control(serde_json::json!(["EOSE", "s"]));
            }
            assert_eq!(conn.outgoing.len(), OUT_QUEUE_LIMIT * 2);
            let dropped_before = conn.dropped;
            conn.send_control(serde_json::json!(["EOSE", "s"]));
            assert_eq!(conn.outgoing.len(), OUT_QUEUE_LIMIT * 2);
            assert_eq!(conn.dropped, dropped_before + 1);
            // The connection loop closes exactly on this mark, so the peer
            // waiting on the dropped frame can resynchronize instead of
            // hanging forever.
            assert!(
                conn.control_overflowed,
                "a dropped completion-critical frame must mark the connection \
                 for close so the peer can resynchronize"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn unset_out_queue_bytes_still_enforces_the_control_ceiling() {
        // `max_out_queue_bytes = 0` is "no configured cap", not "no
        // bound": without the safety ceiling (twice the REQ-response
        // budget) OUT_QUEUE_LIMIT frames of up to `max_ws_message_bytes`
        // could pin ~4 GiB per connection.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            conn.out_queue_bytes = 0;
            conn.req_response_bytes = 100;
            assert_eq!(conn.control_ceiling(), 200);
            // The first frame of an empty queue is never dropped (a single
            // event larger than the ceiling is not lost).
            assert!(conn.send_tagged(Message::Text("a".repeat(150).into()), None));
            let dropped_before = conn
                .relay
                .stats
                .buffers_dropped
                .load(std::sync::atomic::Ordering::Relaxed);
            // The next frame crosses the ceiling: dropped and counted.
            assert!(!conn.send_tagged(Message::Text("b".repeat(150).into()), None));
            assert_eq!(conn.outgoing.len(), 1, "only the first frame is queued");
            assert_eq!(
                conn.relay
                    .stats
                    .buffers_dropped
                    .load(std::sync::atomic::Ordering::Relaxed),
                dropped_before + 1,
                "the ceiling drop must be counted"
            );
            // A frame that keeps the queue below the ceiling still fits.
            assert!(conn.send_tagged(Message::Text("c".repeat(20).into()), None));
            assert_eq!(conn.outgoing.len(), 2);
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn unset_out_queue_bytes_still_caps_pumped_responses() {
        // `max_out_queue_bytes = 0` must not disable the byte check on the
        // REQ pump: without the effective cap a queued backlog was moved
        // into the outgoing queue up to the count limit, defeating the
        // documented ceiling on exactly this path.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            conn.out_queue_bytes = 0;
            conn.req_response_bytes = 3_000;
            let cap = conn.out_queue_cap();
            assert_eq!(cap, 6_000);
            let now = unix_now();
            // MAX_PENDING_REQS responses of two ~1.4 KiB events each: all
            // four together exceed the cap, each stays below its own
            // per-response budget (so no over-budget CLOSED fires).
            for sub in ["s0", "s1", "s2", "s3"] {
                conn.subs
                    .insert(sub.into(), (Vec::new(), 0, format!("\"{sub}\"")));
                let mut events = std::collections::VecDeque::new();
                for i in 0..2 {
                    events.push_back(signed_note(
                        conn.relay.secp(),
                        &format!("{sub}-{i}-{}", "z".repeat(1_000)),
                        now - i,
                        vec![],
                    ));
                }
                conn.enqueue_pending_req(PendingReq {
                    sub_id: sub.into(),
                    events,
                    eose_hint: false,
                    truncated_or_more: false,
                    auth_hint: false,
                    sent_bytes: 0,
                    live: Default::default(),
                    live_bytes: 0,
                    eose_sent: false,
                    budget: None,
                    reserved: 0,
                });
            }
            conn.pump_pending_reqs();
            assert!(
                conn.out_bytes <= cap,
                "the unset queue cap must still bound the pump: {} > {cap}",
                conn.out_bytes
            );
            // Nothing is lost: draining and re-pumping delivers every
            // event and every EOSE.
            let mut delivered = 0usize;
            let mut eoses = 0usize;
            loop {
                for msg in outgoing_json(&conn) {
                    match msg[0].as_str() {
                        Some("EVENT") => delivered += 1,
                        Some("EOSE") => eoses += 1,
                        _ => {}
                    }
                }
                conn.outgoing.clear();
                conn.out_bytes = 0;
                if conn.pending_reqs.is_empty() {
                    break;
                }
                conn.pump_pending_reqs();
            }
            assert_eq!(delivered, 8, "no response event may be dropped");
            assert_eq!(eoses, 4, "every response must end in its EOSE");
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn unset_out_queue_bytes_still_caps_pumped_live_backlog() {
        // The live backlog held for a pumping response takes the same
        // effective cap: with the configured cap unset, the old check was
        // skipped and the whole backlog moved into the queue.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            conn.out_queue_bytes = 0;
            conn.req_response_bytes = 1_000;
            let cap = conn.out_queue_cap();
            assert_eq!(cap, 2_000);
            conn.subs
                .insert("s".into(), (Vec::new(), 0, "\"s\"".into()));
            let now = unix_now();
            let mut live = std::collections::VecDeque::new();
            let mut live_bytes = 0usize;
            for i in 0..10 {
                let ev = signed_note(
                    conn.relay.secp(),
                    &format!("live-{i}-{}", "z".repeat(1_000)),
                    now - i,
                    vec![],
                );
                let frame = format!("[\"EVENT\",\"s\",{}]", serde_json::to_string(&ev).unwrap());
                live_bytes += frame.len();
                live.push_back(frame);
            }
            conn.enqueue_pending_req(PendingReq {
                sub_id: "s".into(),
                events: Default::default(),
                eose_hint: false,
                truncated_or_more: false,
                auth_hint: false,
                sent_bytes: 0,
                live,
                live_bytes,
                eose_sent: false,
                budget: None,
                reserved: 0,
            });
            conn.pump_pending_reqs();
            assert!(
                conn.out_bytes <= cap,
                "the unset queue cap must still bound the live backlog: {} > {cap}",
                conn.out_bytes
            );
            let remaining = conn
                .pending_reqs
                .front()
                .map(|pending| pending.live.len())
                .unwrap_or(0);
            assert!(
                remaining > 0,
                "the live backlog beyond the cap must stay queued, not be moved"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn ok_ack_bypasses_outgoing_byte_cap() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            conn.out_queue_bytes = 1;
            conn.out_bytes = 100;

            conn.send_ok("event-id", true, "");

            let messages = outgoing_json(&conn);
            assert!(
                messages
                    .iter()
                    .any(|message| message[0] == "OK" && message[1] == "event-id"),
                "completion ACK must remain queued under outgoing byte backpressure"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn pending_response_budget_rejects_and_releases() {
        // The relay-wide budget bounds the total memory pinned by
        // materialized responses across connections: a response that does
        // not fit fails fast with a retryable CLOSED instead of pinning
        // events, and the reservation is returned when the response
        // completes, is closed, or its connection drops (the latter two
        // through `PendingReq`'s Drop, which the panic path relies on too).
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            for i in 0..2 {
                let ev = signed_note(conn.relay.secp(), &format!("e{i}"), now - i as u64, vec![]);
                conn.relay.db.put(ev, now).await;
            }
            let budget = Arc::clone(&conn.pending_budget);
            let limit = pending_response_budget_bytes(conn.req_response_bytes);
            assert!(limit > 0);
            // Fill the budget as if other connections held responses.
            assert!(
                budget.try_reserve(limit, limit).is_some(),
                "the budget accepts its full size"
            );
            conn.handle_req(&[json!("sub"), json!({"kinds": [1]})])
                .await;
            let msgs = outgoing_json(&conn);
            assert!(
                msgs.iter().any(|m| m[0] == "CLOSED"
                    && m[1] == "sub"
                    && m[2].as_str().unwrap_or("").contains("overloaded")),
                "an over-budget response must fail fast with CLOSED: {msgs:?}"
            );
            assert!(conn.pending_reqs.is_empty(), "no response may be queued");
            assert!(
                !conn.subs.contains_key("sub"),
                "the over-budget subscription must be released"
            );
            assert_eq!(
                budget.used(),
                limit,
                "the refused response must not reserve anything"
            );

            // The other connection's response completes: the same REQ now
            // succeeds, and completing its own response returns the bytes.
            budget.release(limit);
            conn.handle_req(&[json!("sub"), json!({"kinds": [1]})])
                .await;
            assert!(
                budget.used() > 0,
                "the materialized response must be reserved"
            );
            assert!(conn.subs.contains_key("sub"));
            conn.pump_pending_reqs();
            assert!(conn.pending_reqs.is_empty(), "the response completed");
            assert_eq!(budget.used(), 0, "completion must release the reservation");

            // A CLOSE of a still-pending response releases it too.
            conn.handle_req(&[json!("sub2"), json!({"kinds": [1]})])
                .await;
            assert!(budget.used() > 0);
            conn.handle_close(&[json!("sub2")]);
            assert_eq!(
                budget.used(),
                0,
                "CLOSE must release the pending reservation"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn pending_response_budget_accounts_and_saturates() {
        let budget = PendingResponseBudget::new();
        assert_eq!(budget.used(), 0);
        // An unlimited budget (and an empty response) accepts without
        // accounting, so nothing may be released later.
        assert_eq!(budget.try_reserve(1_000, 0), Some(0));
        assert_eq!(budget.used(), 0);
        assert_eq!(budget.try_reserve(0, 10), Some(0));
        // A bounded budget accounts exactly and refuses over-budget
        // reservations.
        assert_eq!(budget.try_reserve(6, 10), Some(6));
        assert_eq!(budget.try_reserve(5, 10), None);
        assert_eq!(budget.used(), 6);
        budget.release(4);
        assert_eq!(budget.used(), 2);
        // A spurious release cannot wrap past zero (which would disable
        // the budget).
        budget.release(u64::MAX);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn pending_response_budget_sizes_from_config() {
        assert_eq!(pending_response_budget_bytes(1_000), 16_000);
        assert_eq!(
            pending_response_budget_bytes(0),
            32 * 1024 * 1024 * PENDING_RESPONSE_BUDGET_FACTOR,
            "a disabled per-response budget still gets the relay-wide default"
        );
    }

    #[test]
    fn neg_budget_sizes_from_config() {
        assert_eq!(
            neg_budget_bytes(1_000),
            1_000 * NEG_ITEM_BYTES * NEG_BUDGET_FACTOR,
            "the budget is the per-query item cap times the item estimate and factor"
        );
        assert_eq!(
            neg_budget_bytes(0),
            100_000 * NEG_ITEM_BYTES * NEG_BUDGET_FACTOR,
            "a zero item cap still gets the relay-wide default (0 would disable the budget)"
        );
    }

    #[test]
    fn neg_cpu_budget_sizes_from_config() {
        assert_eq!(
            neg_cpu_budget_units(1_000),
            1_000 * NEG_CPU_BUDGET_FACTOR,
            "the budget is the per-query item cap times the CPU factor"
        );
        assert_eq!(
            neg_cpu_budget_units(0),
            100_000 * NEG_CPU_BUDGET_FACTOR,
            "a zero item cap still gets the relay-wide default"
        );
    }

    #[test]
    fn neg_cpu_budget_accounts_and_rejects() {
        let budget = NegCpuBudget::new();
        // Frozen so the assertions are independent of the wall clock: the
        // production window rolls over once per second.
        budget.freeze();
        assert!(
            budget.try_charge(3, 10),
            "the first charge opens the window"
        );
        assert!(budget.try_charge(7, 10), "charges add up to the limit");
        assert!(
            !budget.try_charge(1, 10),
            "the exhausted window refuses further work"
        );
        assert!(
            budget.try_charge(0, 0),
            "an empty charge is always admitted"
        );
        // A shrunken configured limit starts a fresh window instead of
        // refusing every charge for the rest of the second.
        assert!(
            budget.try_charge(2, 5),
            "a limit below the spent amount resets the window"
        );
        assert!(budget.try_charge(3, 5));
        assert!(!budget.try_charge(1, 5));
        // A charge above the whole budget is refused without poisoning a
        // fresh window for everyone else.
        let fresh = NegCpuBudget::new();
        fresh.freeze();
        assert!(!fresh.try_charge(11, 10));
        assert!(
            fresh.try_charge(10, 10),
            "the refused oversized charge must not have consumed the window"
        );
    }

    #[test]
    fn neg_global_cpu_budget_rejects_opens_and_rounds() {
        // The relay-wide CPU budget closes the 64 connections × 256 opens
        // × 128 rounds amplification: once the shared per-second window is
        // spent, both the NEG-OPEN scan and the NEG-MSG round are refused
        // retryably (and, per NIP-77, the NEG-ERR closes the id).
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            conn.neg_cpu_budget.freeze();
            let max_items = conn.relay.config.read().await.limits.max_neg_items;
            let limit = neg_cpu_budget_units(max_items);
            // Exhaust the window as another connection would.
            assert!(conn.neg_cpu_budget.try_charge(limit, limit));

            conn.handle_neg_open(&[json!("s"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            let msgs = outgoing_json(&conn);
            assert!(
                msgs.iter().any(|m| m[0] == "NEG-ERR"
                    && m[1] == "s"
                    && m[2].as_str().unwrap_or("").contains("overloaded")),
                "an over-budget open must be refused retryably before the scan: {msgs:?}"
            );
            assert!(conn.neg.is_empty(), "no over-budget state may be pinned");
            conn.outgoing.clear();

            // A NEG-MSG is charged by its held item count and refused once
            // the window is exhausted.
            conn.neg.insert(
                "held".into(),
                super::negentropy::NegState {
                    items: vec![(1, [7u8; 32])],
                    last_active: std::time::Instant::now(),
                    rounds_left: super::negentropy::MAX_NEG_MSG_ROUNDS,
                    budget: None,
                    reserved: 0,
                },
            );
            conn.handle_neg_msg(&[json!("held"), json!("61000000")])
                .await;
            let msgs = outgoing_json(&conn);
            assert!(
                msgs.iter().any(|m| m[0] == "NEG-ERR"
                    && m[1] == "held"
                    && m[2].as_str().unwrap_or("").contains("overloaded")),
                "an over-budget round must be refused retryably: {msgs:?}"
            );
            assert!(
                !conn.neg.contains_key("held"),
                "the over-budget NEG-ERR closes the subscription"
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn neg_idle_subscriptions_are_reaped_and_release() {
        // A sync that exchanges no message for longer than
        // `NEG_IDLE_TIMEOUT` must be closed with a `NEG-ERR` (`closed:`),
        // releasing its items and budget reservation — otherwise a client
        // could pin state forever by keeping the connection alive with
        // PONGs, which reset the connection idle deadline but never touch
        // NEG state. A live sync must survive the sweep untouched.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let budget = Arc::clone(&conn.neg_budget);
            let limit = neg_budget_bytes(conn.relay.config.read().await.limits.max_neg_items);
            let stale_ago = super::negentropy::NEG_IDLE_TIMEOUT + std::time::Duration::from_secs(1);
            // The stale sync holds a real reservation, like a live one.
            assert!(budget.try_reserve(128, limit).is_some());
            conn.neg.insert(
                "stale".into(),
                super::negentropy::NegState {
                    items: vec![(1, [7u8; 32])],
                    last_active: std::time::Instant::now() - stale_ago,
                    rounds_left: super::negentropy::MAX_NEG_MSG_ROUNDS,
                    budget: Some(Arc::clone(&budget)),
                    reserved: 128,
                },
            );
            conn.neg.insert(
                "live".into(),
                super::negentropy::NegState {
                    items: vec![(2, [8u8; 32])],
                    last_active: std::time::Instant::now(),
                    rounds_left: super::negentropy::MAX_NEG_MSG_ROUNDS,
                    budget: None,
                    reserved: 0,
                },
            );
            conn.reap_idle_negentropy();
            assert!(
                !conn.neg.contains_key("stale"),
                "the idle sync must be released"
            );
            assert!(
                conn.neg.contains_key("live"),
                "a live sync must survive the sweep"
            );
            assert_eq!(
                budget.used(),
                0,
                "the reaped sync must return its budget reservation exactly once"
            );
            assert!(
                outgoing_json(&conn).iter().any(|m| m[0] == "NEG-ERR"
                    && m[1] == "stale"
                    && m[2].as_str().unwrap_or("").contains("closed")),
                "the client must be told the sync is over: {:?}",
                outgoing_json(&conn)
            );
            // A failing message must not sweep: only the id it names is
            // affected, and other idle syncs are left for the next
            // successful round or keep-alive tick.
            conn.neg.insert(
                "other".into(),
                super::negentropy::NegState {
                    items: Vec::new(),
                    last_active: std::time::Instant::now() - stale_ago,
                    rounds_left: 1,
                    budget: None,
                    reserved: 0,
                },
            );
            conn.outgoing.clear();
            conn.handle_neg_msg(&[json!("bad"), json!("not-hex")]).await;
            assert!(
                conn.neg.contains_key("other"),
                "a failing message must not reap unrelated idle syncs"
            );
            assert!(
                outgoing_json(&conn).iter().all(|m| m[1] != "other"),
                "no NEG-ERR may name the untouched sync: {:?}",
                outgoing_json(&conn)
            );
            // Touching a stale subscription refreshes it instead of
            // closing it: a message for a live sync must never produce a
            // second, confusing NEG-ERR for the same id. (Close "other"
            // first: the sweep below would otherwise — correctly — reap
            // it too, which is a separate assertion from the one above.)
            conn.handle_neg_close(&[json!("other")]);
            conn.neg.insert(
                "slow".into(),
                super::negentropy::NegState {
                    items: Vec::new(),
                    last_active: std::time::Instant::now() - stale_ago,
                    rounds_left: 1,
                    budget: None,
                    reserved: 0,
                },
            );
            conn.outgoing.clear();
            conn.touch_and_reap_neg("slow");
            assert!(
                conn.neg.contains_key("slow"),
                "a message for the sync itself must revive it before the sweep"
            );
            assert!(
                outgoing_json(&conn).is_empty(),
                "reviving must not emit any NEG-ERR: {:?}",
                outgoing_json(&conn)
            );
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn neg_global_budget_rejects_and_releases() {
        // The relay-wide NEG budget bounds the items held across all
        // connections: an open that does not fit fails retryably with
        // NEG-ERR (which per NIP-77 closes the id) instead of pinning the
        // items, and the reservation is returned exactly once on NEG-CLOSE,
        // replacement, connection drop and panic (the latter through
        // `NegState`'s Drop, like `PendingReq`).
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            let mut ids = Vec::new();
            for i in 0..2 {
                let ev = signed_note(conn.relay.secp(), &format!("e{i}"), now - i as u64, vec![]);
                conn.relay.db.put(ev.clone(), now).await;
                ids.push(ev.id);
            }
            let budget = Arc::clone(&conn.neg_budget);
            let limit = neg_budget_bytes(conn.relay.config.read().await.limits.max_neg_items);
            assert!(limit > 0, "held NEG state must always be budgeted");
            // Fill the budget as if other connections held syncs.
            assert!(budget.try_reserve(limit, limit).is_some());

            conn.handle_neg_open(&[json!("sub"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            let msgs = outgoing_json(&conn);
            assert!(
                msgs.iter().any(|m| m[0] == "NEG-ERR"
                    && m[1] == "sub"
                    && m[2].as_str().unwrap_or("").contains("overloaded")),
                "an over-budget open must fail retryably with NEG-ERR: {msgs:?}"
            );
            assert!(conn.neg.is_empty(), "no over-budget state may be pinned");
            assert_eq!(
                budget.used(),
                limit,
                "the refused open must not reserve anything"
            );

            // Freeing a slot admits the open; the held set is reserved
            // exactly (one reservation per held item).
            budget.release(limit);
            conn.outgoing.clear();
            conn.handle_neg_open(&[json!("sub"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            assert!(conn.neg.contains_key("sub"));
            let held = budget.used();
            assert_eq!(
                held,
                2 * NEG_ITEM_BYTES,
                "the held item count must be reserved exactly"
            );

            // A successful replacement releases the old reservation before
            // taking the new one: net zero for the same set.
            conn.handle_neg_open(&[json!("sub"), json!({"kinds": [1]}), json!("61000000")])
                .await;
            assert_eq!(budget.used(), held, "replacement must be net zero");

            // A second subscription reserves its own set; NEG-CLOSE returns
            // exactly that one.
            conn.outgoing.clear();
            conn.handle_neg_open(&[json!("one"), json!({"ids": [ids[0]]}), json!("61000000")])
                .await;
            assert!(conn.neg.contains_key("one"));
            assert_eq!(
                budget.used(),
                held + NEG_ITEM_BYTES,
                "the second set must be reserved on top"
            );
            conn.handle_neg_close(&[json!("sub")]);
            assert_eq!(
                budget.used(),
                NEG_ITEM_BYTES,
                "NEG-CLOSE must release exactly the closed set"
            );
            assert!(!conn.neg.contains_key("sub"));

            // Connection drop releases whatever is still held.
            conn.relay.db.shutdown();
            drop(conn);
            assert_eq!(
                budget.used(),
                0,
                "connection drop must release the remaining reservation"
            );

            // Panic path: a `NegState` dropped while unwinding releases its
            // reservation (the connection guard relies on this when the
            // connection task panics).
            let panic_budget = Arc::new(PendingResponseBudget::new());
            assert_eq!(panic_budget.try_reserve(128, 128), Some(128));
            let state_budget = Arc::clone(&panic_budget);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _state = super::negentropy::NegState {
                    items: Vec::new(),
                    last_active: std::time::Instant::now(),
                    rounds_left: 1,
                    budget: Some(state_budget),
                    reserved: 128,
                };
                panic!("simulated panic while the NEG state is held");
            }));
            assert!(result.is_err(), "the simulated panic must unwind");
            assert_eq!(
                panic_budget.used(),
                0,
                "a panic must release the NEG reservation exactly once"
            );
        });
    }

    #[test]
    fn multi_key_auth_is_not_refused_by_the_attempt_cap() {
        // Regression: the AUTH attempt cap (16) was lower than the
        // distinct-key cap (64) while counting successful auths, so a
        // multi-key client was refused mid-way. Successes still count as
        // attempts, but the cap is comfortably above the key cap.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            for seed in 1..=17u8 {
                let auth = signed_auth_seeded(conn.relay.secp(), seed, "test-challenge", now);
                conn.handle_auth(&[serde_json::to_value(&auth).unwrap()])
                    .await;
                let ok = outgoing_json(&conn)
                    .iter()
                    .rev()
                    .find(|m| m[0] == "OK" && m[1] == auth.id)
                    .cloned()
                    .unwrap_or_else(|| panic!("AUTH seed {seed} must be answered with OK"));
                assert_eq!(ok[2], true, "seed {seed} must authenticate: {ok:?}");
            }
            assert_eq!(conn.authed_pubkeys.len(), 17);

            // NIP-42: a parsed AUTH frame with no recoverable id is still
            // answered with OK (empty id) and an `invalid:` reason, never a
            // NOTICE.
            conn.handle_auth(&[json!({"not": "an event"})]).await;
            let msgs = outgoing_json(&conn);
            let malformed = msgs
                .iter()
                .rev()
                .find(|m| {
                    m[0] == "OK"
                        && m[1] == ""
                        && m[2] == false
                        && m[3].as_str().unwrap_or("").starts_with("invalid:")
                })
                .expect("a malformed AUTH must be answered with OK \"\"");
            assert!(
                !msgs.iter().any(|m| m[0] == "NOTICE"),
                "a parsed AUTH must never get a NOTICE"
            );
            // A missing event object is a parsed AUTH frame too.
            conn.handle_auth(&[]).await;
            assert!(
                outgoing_json(&conn).iter().any(|m| m[0] == "OK"
                    && m[1] == ""
                    && m[2] == false
                    && m[3].as_str().unwrap_or("").contains("requires an event")),
                "an AUTH without an event object must be answered with OK"
            );
            assert!(malformed[3].as_str().unwrap().contains("malformed"));
            conn.relay.db.shutdown();
        });
    }

    #[test]
    fn req_multiple_filters_keep_their_own_limits() {
        // Regression: the visible truncation cut the *union* at the sum of
        // the limits, so a filter with many matches consumed a later
        // filter's quota. Each filter's `limit` must be honored on its own
        // (the scan's per-filter attribution), with the EOSE reporting
        // "more" for the events that did not fit.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut conn = build_conn().await;
            let now = unix_now();
            let a1 = signed_note(
                conn.relay.secp(),
                "a1",
                now,
                vec![vec!["t".into(), "a".into()]],
            );
            let a2 = signed_note(
                conn.relay.secp(),
                "a2",
                now - 1,
                vec![vec!["t".into(), "a".into()]],
            );
            let b1 = signed_note(
                conn.relay.secp(),
                "b1",
                now - 2,
                vec![vec!["t".into(), "b".into()]],
            );
            let b2 = signed_note(
                conn.relay.secp(),
                "b2",
                now - 3,
                vec![vec!["t".into(), "b".into()]],
            );
            for e in [&a1, &a2, &b1, &b2] {
                conn.relay.db.put(e.clone(), now).await;
            }
            conn.handle_req(&[
                json!("sub"),
                json!({"#t": ["a"], "limit": 1}),
                json!({"#t": ["b"], "limit": 1}),
            ])
            .await;
            conn.pump_pending_reqs();
            let contents: Vec<String> = outgoing_json(&conn)
                .iter()
                .filter(|m| m[0] == "EVENT" && m[1] == "sub")
                .map(|m| m[2]["content"].as_str().unwrap().to_string())
                .collect();
            assert_eq!(
                contents,
                vec!["a1".to_string(), "b1".to_string()],
                "each filter must keep its own limit (the old union cut dropped b1)"
            );
            let eose = outgoing_json(&conn)
                .into_iter()
                .find(|m| m[0] == "EOSE" && m[1] == "sub")
                .expect("the response must end in an EOSE");
            assert_eq!(
                eose[2],
                json!(["more"]),
                "matches that did not fit must carry the more hint"
            );
            conn.relay.db.shutdown();
        });
    }

    /// Waits (bounded) for `ready` to hold, polling at 10 ms.
    async fn wait_for(ready: impl FnMut() -> bool, what: &str) {
        wait_for_within(ready, Duration::from_secs(5), what).await;
    }

    /// Like [`wait_for`] with an explicit bound.
    async fn wait_for_within(mut ready: impl FnMut() -> bool, timeout: Duration, what: &str) {
        let deadline = tokio::time::Instant::now() + timeout;
        while !ready() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for {what}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// The next JSON text frame of a tungstenite client, skipping PING/
    /// PONG/other frames; fails on close, error, or a 5-second silence.
    async fn ws_next_json<S>(ws: &mut S) -> Value
    where
        S: futures_util::Stream<
                Item = Result<
                    tokio_tungstenite::tungstenite::Message,
                    tokio_tungstenite::tungstenite::Error,
                >,
            > + Unpin,
    {
        let deadline = tokio::time::sleep(Duration::from_secs(5));
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                msg = futures_util::StreamExt::next(ws) => match msg {
                    Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text))) => {
                        return serde_json::from_str(text.as_str())
                            .expect("a server text frame must be JSON");
                    }
                    Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_)))
                    | Some(Err(_))
                    | None => panic!("the websocket closed before the expected reply"),
                    Some(Ok(_)) => {}
                },
                _ = &mut deadline => panic!("timed out waiting for a websocket reply"),
            }
        }
    }

    /// Spawns the same axum WebSocket listener the E2E test builds inline,
    /// serving `handle_connection` on `/`, and returns its address and task.
    async fn spawn_ws_server(
        relay: Arc<Relay>,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let app = axum::Router::new()
            .route(
                "/",
                axum::routing::any(
                    |ws: axum::extract::ws::WebSocketUpgrade,
                     axum::extract::State(relay): axum::extract::State<Arc<Relay>>| async move {
                        ws.on_upgrade(move |socket| async move {
                            crate::ws::handle_connection(
                                socket,
                                relay,
                                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                                "/".to_string(),
                                None,
                            )
                            .await;
                        })
                    },
                ),
            )
            .with_state(Arc::clone(&relay));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (addr, server)
    }

    /// Connects a real tokio-tungstenite client over a TCP socket the test
    /// owns (so it can half-close it or set SO_LINGER). `recv_buffer` is
    /// applied before the handshake: a tiny receive buffer makes a
    /// non-reading client stall the server's writes deterministically
    /// instead of absorbing the backlog into kernel buffers.
    async fn connect_ws(
        addr: std::net::SocketAddr,
        recv_buffer: Option<u32>,
    ) -> tokio_tungstenite::WebSocketStream<tokio::net::TcpStream> {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        if let Some(size) = recv_buffer {
            socket.set_recv_buffer_size(size).unwrap();
        }
        let tcp = socket.connect(addr).await.unwrap();
        tcp.set_nodelay(true).unwrap();
        let (ws, _) = tokio_tungstenite::client_async(format!("ws://{addr}/"), tcp)
            .await
            .expect("the WebSocket connects");
        ws
    }

    /// The next text frame of a tungstenite client, or `None` when the
    /// server closed the connection (Close, EOF or a transport error);
    /// fails on a 5-second silence. Unlike [`ws_next_json`] this tolerates
    /// the close and returns the raw wire text (for byte-cap assertions).
    async fn ws_next_text<S>(ws: &mut S) -> Option<String>
    where
        S: futures_util::Stream<
                Item = Result<
                    tokio_tungstenite::tungstenite::Message,
                    tokio_tungstenite::tungstenite::Error,
                >,
            > + Unpin,
    {
        let deadline = tokio::time::sleep(Duration::from_secs(5));
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                msg = futures_util::StreamExt::next(ws) => match msg {
                    Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text))) => {
                        return Some(text.as_str().to_string());
                    }
                    Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_)))
                    | Some(Err(_))
                    | None => return None,
                    Some(Ok(_)) => {}
                },
                _ = &mut deadline => panic!("timed out waiting for a websocket frame"),
            }
        }
    }

    /// Whether every per-connection accounting structure and both
    /// relay-wide budgets are back at their baseline. `probes` cover the
    /// filter components of every subscription the test opened: the live
    /// index is only inspectable through `candidates`.
    fn accounting_clean(relay: &Arc<Relay>, probes: &[&Event]) -> bool {
        let connections_idle = relay
            .stats
            .connections_active
            .load(std::sync::atomic::Ordering::Relaxed)
            == 0;
        let subscriptions_idle = relay
            .stats
            .subscriptions_active
            .load(std::sync::atomic::Ordering::Relaxed)
            == 0;
        let index_empty = {
            let index = relay.sub_index.read().unwrap_or_else(|p| p.into_inner());
            probes
                .iter()
                .all(|event| index.candidates(event).is_empty())
        };
        let queues_empty = relay
            .conn_queues
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_empty();
        connections_idle
            && subscriptions_idle
            && index_empty
            && queues_empty
            && pending_response_budget(relay).used() == 0
            && neg_budget(relay).used() == 0
    }

    #[test]
    fn websocket_end_to_end_publish_and_drain() {
        // Full-stack harness: a real axum WebSocket listener serving
        // `handle_connection`, a real tokio-tungstenite client, an EVENT
        // round trip with DB visibility, then `signal_drain()` and every
        // accounting structure back to baseline.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay_with("").await;
            let app = axum::Router::new()
                .route(
                    "/",
                    axum::routing::any(
                        |ws: axum::extract::ws::WebSocketUpgrade,
                         axum::extract::State(relay): axum::extract::State<Arc<Relay>>| async move {
                            ws.on_upgrade(move |socket| async move {
                                crate::ws::handle_connection(
                                    socket,
                                    relay,
                                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                                    "/".to_string(),
                                    None,
                                )
                                .await;
                            })
                        },
                    ),
                )
                .with_state(Arc::clone(&relay));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let _ = axum::serve(listener, app).await;
            });

            let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/"))
                .await
                .expect("the WebSocket connects");

            // A REQ opens the subscription whose accounting must return to
            // baseline after the drain.
            futures_util::SinkExt::send(
                &mut ws,
                tokio_tungstenite::tungstenite::Message::Text(
                    json!(["REQ", "e2e", {"kinds": [1]}]).to_string().into(),
                ),
            )
            .await
            .unwrap();
            // The first frame is the NIP-42 challenge (the default is
            // `send_auth_challenge = true`); skip until the EOSE.
            let mut saw_eose = false;
            for _ in 0..4 {
                let msg = ws_next_json(&mut ws).await;
                if msg[0] == "EOSE" && msg[1] == "e2e" {
                    saw_eose = true;
                    break;
                }
            }
            assert!(saw_eose, "the subscription must be answered with EOSE");

            // Publish an EVENT and wait for its OK.
            let event = signed_note(relay.secp(), "e2e hello", unix_now(), vec![]);
            futures_util::SinkExt::send(
                &mut ws,
                tokio_tungstenite::tungstenite::Message::Text(
                    json!(["EVENT", event]).to_string().into(),
                ),
            )
            .await
            .unwrap();
            let mut accepted = false;
            for _ in 0..4 {
                let msg = ws_next_json(&mut ws).await;
                if msg[0] == "OK" && msg[1] == event.id {
                    assert_eq!(msg[2], true, "the event must be accepted: {msg:?}");
                    accepted = true;
                    break;
                }
            }
            assert!(accepted, "the EVENT must be acknowledged");

            // DB visibility: the OK is only sent after the batch commit.
            let (stored, _) = relay
                .db
                .query_req(
                    vec![serde_json::from_value(json!({"ids": [event.id]})).unwrap()],
                    1,
                    unix_now(),
                )
                .await;
            assert!(
                stored.iter().any(|e| e.id == event.id),
                "the accepted event must be stored"
            );

            assert_eq!(
                relay
                    .stats
                    .connections_active
                    .load(std::sync::atomic::Ordering::Relaxed),
                1,
                "the connection is active"
            );
            assert_eq!(
                relay
                    .stats
                    .subscriptions_active
                    .load(std::sync::atomic::Ordering::Relaxed),
                1,
                "the subscription is active"
            );

            // Drain: the connection loop tears down and releases every
            // accounting structure within a bounded deadline.
            relay.signal_drain();
            wait_for(
                || {
                    relay
                        .stats
                        .connections_active
                        .load(std::sync::atomic::Ordering::Relaxed)
                        == 0
                        && relay
                            .stats
                            .subscriptions_active
                            .load(std::sync::atomic::Ordering::Relaxed)
                            == 0
                        && relay
                            .sub_index
                            .read()
                            .unwrap_or_else(|p| p.into_inner())
                            .candidates(&event)
                            .is_empty()
                        && relay
                            .conn_queues
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .is_empty()
                },
                "all connection and subscription accounting to return to baseline",
            )
            .await;

            drop(ws);
            server.abort();
            relay.db.shutdown();
        });
    }

    #[test]
    fn websocket_abrupt_reset_releases_response_and_neg_state() {
        // An abrupt TCP reset (SO_LINGER 0) while a REQ response is still
        // pumping and a NEG-OPEN holds items must release every accounting
        // structure within a bounded deadline: the connection and
        // subscription counters, the live index, the delivery map and both
        // relay-wide budgets (the pending response's RAII reservation and
        // the NEG state's).
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay_with_limits("", |cfg| {
                cfg.relay.send_auth_challenge = false;
                cfg.limits.ws_idle_timeout_secs = 0;
                cfg.limits.max_limit = 1_000;
                cfg.limits.max_req_response_bytes = 1 << 20;
                cfg.limits.max_out_queue_bytes = 4 * 1024;
            })
            .await;
            let now = unix_now();
            // The stored set is far larger than the client's receive buffer
            // and the relay-wide queue cap, so the materialized prefix stays
            // reserved while the client is not reading.
            let stored: Vec<(Event, u64)> = (0..512)
                .map(|i| {
                    (
                        signed_note(
                            relay.secp(),
                            &format!("reset-{i}-{}", "x".repeat(3_500)),
                            now - i as u64,
                            vec![],
                        ),
                        now,
                    )
                })
                .collect();
            let probe = stored[0].0.clone();
            relay.db.put_batch(stored).await;

            let (addr, server) = spawn_ws_server(Arc::clone(&relay)).await;
            // The tiny receive buffer makes the stall deterministic (see
            // `connect_ws`): the server cannot push the prefix into kernel
            // buffers, so the pending reservation stays live.
            let mut ws = connect_ws(addr, Some(4 * 1024)).await;
            futures_util::SinkExt::send(
                &mut ws,
                tokio_tungstenite::tungstenite::Message::Text(
                    json!(["REQ", "reset", {"kinds": [1]}]).to_string().into(),
                ),
            )
            .await
            .unwrap();
            // One delivered EVENT proves the response is on the wire while
            // the rest is still pinned.
            let first = ws_next_text(&mut ws).await.expect("an EVENT frame");
            let parsed: Value = serde_json::from_str(&first).unwrap();
            assert_eq!(parsed[0], "EVENT", "the first frame must be the response");
            assert!(
                pending_response_budget(&relay).used() > 0,
                "the stalled response must hold its relay-wide reservation"
            );

            // A NEG-OPEN holds its items (and their reservation) until the
            // connection is gone. The server only reads it once the client
            // has drained enough of the stalled response to leave the
            // outgoing drain, so keep reading until the reservation lands.
            futures_util::SinkExt::send(
                &mut ws,
                tokio_tungstenite::tungstenite::Message::Text(
                    json!(["NEG-OPEN", "neg", {"kinds": [1]}, "61000000"])
                        .to_string()
                        .into(),
                ),
            )
            .await
            .unwrap();
            let neg_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            while neg_budget(&relay).used() == 0 {
                assert!(
                    tokio::time::Instant::now() < neg_deadline,
                    "timed out waiting for the NEG-OPEN items to be reserved"
                );
                ws_next_text(&mut ws)
                    .await
                    .expect("the socket must stay up until the NEG-OPEN is processed");
            }

            // Abrupt reset: SO_LINGER 0 makes the close send RST instead of
            // FIN, so the server sees a broken socket, not a close
            // handshake.
            ws.get_mut().set_zero_linger().unwrap();
            drop(ws);

            wait_for(
                || accounting_clean(&relay, &[&probe]),
                "all accounting after an abrupt reset",
            )
            .await;
            server.abort();
            relay.db.shutdown();
        });
    }

    #[test]
    fn websocket_half_close_serves_then_closes_cleanly() {
        // A client that half-closes its write side (FIN) while keeping the
        // read side open: the relay must either finish serving the in-flight
        // REQ (EVENTs + EOSE) or close cleanly, without panicking, and must
        // release all accounting. The relay must stay healthy for new
        // connections afterwards.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay_with_limits("", |cfg| {
                cfg.relay.send_auth_challenge = false;
                cfg.limits.ws_idle_timeout_secs = 0;
            })
            .await;
            let now = unix_now();
            let stored: Vec<(Event, u64)> = (0..3)
                .map(|i| {
                    (
                        signed_note(relay.secp(), &format!("half-{i}"), now - i as u64, vec![]),
                        now,
                    )
                })
                .collect();
            let probe = stored[0].0.clone();
            relay.db.put_batch(stored).await;

            let (addr, server) = spawn_ws_server(Arc::clone(&relay)).await;
            let mut ws = connect_ws(addr, None).await;
            futures_util::SinkExt::send(
                &mut ws,
                tokio_tungstenite::tungstenite::Message::Text(
                    json!(["REQ", "half", {"kinds": [1]}]).to_string().into(),
                ),
            )
            .await
            .unwrap();
            // Half-close the write direction: the REQ is already flushed,
            // and the server sees EOF while the client keeps reading.
            tokio::io::AsyncWriteExt::shutdown(ws.get_mut())
                .await
                .unwrap();

            let mut saw_eose = false;
            let mut served = 0usize;
            while let Some(text) = ws_next_text(&mut ws).await {
                let msg: Value = serde_json::from_str(&text).unwrap();
                match msg[0].as_str() {
                    Some("EVENT") => served += 1,
                    Some("EOSE") if msg[1] == "half" => saw_eose = true,
                    _ => {}
                }
            }
            // Tungstenite maps a TCP EOF to "connection closed", so the
            // queued response may be abandoned when the write side is
            // already terminated; either way the connection must close
            // cleanly, and a response that does reach the wire must be
            // complete (never a partial page without its EOSE).
            assert!(
                (served == 0 && !saw_eose) || (served == 3 && saw_eose),
                "a half-closed REQ must be served completely or not at all \
                 (served={served}, eose={saw_eose})"
            );

            wait_for(
                || accounting_clean(&relay, &[&probe]),
                "accounting after a half-close",
            )
            .await;
            assert!(!server.is_finished(), "the listener must stay healthy");

            // A fresh connection must still be served.
            let mut fresh = connect_ws(addr, None).await;
            let event = signed_note(relay.secp(), "after half-close", now, vec![]);
            futures_util::SinkExt::send(
                &mut fresh,
                tokio_tungstenite::tungstenite::Message::Text(
                    json!(["EVENT", event]).to_string().into(),
                ),
            )
            .await
            .unwrap();
            let mut accepted = false;
            for _ in 0..3 {
                let msg = ws_next_json(&mut fresh).await;
                if msg[0] == "OK" && msg[1] == event.id {
                    assert_eq!(msg[2], true, "the event must be accepted: {msg:?}");
                    accepted = true;
                    break;
                }
            }
            assert!(accepted, "a new connection must still be served");
            drop(fresh);
            wait_for(
                || accounting_clean(&relay, &[&probe]),
                "accounting after the health-check connection",
            )
            .await;
            server.abort();
            relay.db.shutdown();
        });
    }

    #[test]
    fn websocket_slow_reader_stops_at_the_response_budget() {
        // A client that stops reading stalls the pump. The relay must never
        // stream past `max_req_response_bytes`: when the stored response is
        // larger, the subscription ends in a retryable CLOSED (the
        // connection itself stays usable) and every byte and reservation is
        // released afterwards.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay_with_limits("", |cfg| {
                cfg.relay.send_auth_challenge = false;
                cfg.limits.ws_idle_timeout_secs = 0;
                cfg.limits.max_limit = 1_000;
                cfg.limits.max_req_response_bytes = 128 * 1024;
                cfg.limits.max_out_queue_bytes = 4 * 1024;
            })
            .await;
            let now = unix_now();
            let stored: Vec<(Event, u64)> = (0..512)
                .map(|i| {
                    (
                        signed_note(
                            relay.secp(),
                            &format!("slow-{i}-{}", "y".repeat(300)),
                            now - i as u64,
                            vec![],
                        ),
                        now,
                    )
                })
                .collect();
            let probe = stored[0].0.clone();
            relay.db.put_batch(stored).await;

            let (addr, server) = spawn_ws_server(Arc::clone(&relay)).await;
            let mut ws = connect_ws(addr, Some(4 * 1024)).await;
            futures_util::SinkExt::send(
                &mut ws,
                tokio_tungstenite::tungstenite::Message::Text(
                    json!(["REQ", "slow", {"kinds": [1]}]).to_string().into(),
                ),
            )
            .await
            .unwrap();
            // Do not read: the tiny receive buffer stalls the socket and the
            // materialized prefix stays pinned (and bounded).
            wait_for(
                || pending_response_budget(&relay).used() > 0,
                "the stalled response to hold its reservation",
            )
            .await;
            let budget = 128 * 1024u64;
            let held = pending_response_budget(&relay).used();
            assert!(
                held <= budget + 8 * 1024,
                "the pinned prefix must stay near the response budget, got {held}"
            );

            // Start reading: the pump stops at the exact budget and ends the
            // subscription with a retryable CLOSED.
            let mut event_bytes = 0usize;
            let mut closed = false;
            while let Some(text) = ws_next_text(&mut ws).await {
                let msg: Value = serde_json::from_str(&text).unwrap();
                match msg[0].as_str() {
                    Some("EVENT") => event_bytes += text.len(),
                    Some("CLOSED") if msg[1] == "slow" => {
                        let reason = msg[2].as_str().unwrap_or("");
                        assert!(
                            reason.contains("response too large"),
                            "a retryable reason is expected, got {reason}"
                        );
                        closed = true;
                        break;
                    }
                    Some("EOSE") => {
                        panic!("a truncated response must not claim completion")
                    }
                    _ => {}
                }
            }
            assert!(closed, "the over-budget response must end in CLOSED");
            assert!(
                event_bytes <= budget as usize,
                "the wire bytes must not exceed the response budget: {event_bytes} > {budget}"
            );
            // CLOSED releases the subscription; the connection stays up.
            wait_for(
                || {
                    relay
                        .stats
                        .subscriptions_active
                        .load(std::sync::atomic::Ordering::Relaxed)
                        == 0
                        && relay
                            .stats
                            .connections_active
                            .load(std::sync::atomic::Ordering::Relaxed)
                            == 1
                },
                "the over-budget subscription to be released",
            )
            .await;
            assert_eq!(
                pending_response_budget(&relay).used(),
                0,
                "the released response must return its reservation"
            );
            drop(ws);
            wait_for(
                || accounting_clean(&relay, &[&probe]),
                "accounting after the slow reader",
            )
            .await;
            server.abort();
            relay.db.shutdown();
        });
    }

    #[test]
    fn websocket_drain_flushes_pending_ok_and_closed() {
        // Graceful drain while a live subscription, a queued CLOSED (an
        // over-budget response) and a publisher's pending OKs are in
        // flight: the queued completion frames must be flushed before the
        // socket closes (within the teardown grace), and all accounting
        // must return to baseline.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay_with_limits("", |cfg| {
                cfg.relay.send_auth_challenge = false;
                cfg.limits.ws_idle_timeout_secs = 0;
                cfg.limits.max_req_response_bytes = 2_000;
            })
            .await;
            let now = unix_now();
            // Events that overrun the tiny response budget: the subscription
            // ends in a CLOSED, which the subscriber does not read yet.
            let big: Vec<(Event, u64)> = (0..4)
                .map(|i| {
                    (
                        signed_kind_note_seeded(
                            relay.secp(),
                            9,
                            9999,
                            &format!("big-{i}-{}", "z".repeat(600)),
                            now - i as u64,
                            vec![],
                        ),
                        now,
                    )
                })
                .collect();
            let probe_big = big[0].0.clone();
            relay.db.put_batch(big).await;

            let (addr, server) = spawn_ws_server(Arc::clone(&relay)).await;

            // The subscriber: a live REQ that stays open, plus an
            // over-budget REQ whose CLOSED is queued and unread.
            let mut subscriber = connect_ws(addr, None).await;
            futures_util::SinkExt::send(
                &mut subscriber,
                tokio_tungstenite::tungstenite::Message::Text(
                    json!(["REQ", "live", {"kinds": [1]}]).to_string().into(),
                ),
            )
            .await
            .unwrap();
            let mut saw_eose = false;
            for _ in 0..3 {
                let msg = ws_next_json(&mut subscriber).await;
                if msg[0] == "EOSE" && msg[1] == "live" {
                    saw_eose = true;
                    break;
                }
            }
            assert!(saw_eose, "the live subscription must be answered");
            futures_util::SinkExt::send(
                &mut subscriber,
                tokio_tungstenite::tungstenite::Message::Text(
                    json!(["REQ", "big", {"kinds": [9999]}]).to_string().into(),
                ),
            )
            .await
            .unwrap();
            wait_for(
                || {
                    relay
                        .stats
                        .subscriptions_total
                        .load(std::sync::atomic::Ordering::Relaxed)
                        >= 2
                },
                "the over-budget REQ to be registered",
            )
            .await;
            wait_for(
                || {
                    relay
                        .stats
                        .subscriptions_active
                        .load(std::sync::atomic::Ordering::Relaxed)
                        == 1
                        && pending_response_budget(&relay).used() == 0
                },
                "the over-budget CLOSED to be queued",
            )
            .await;

            // The publisher: its OKs are queued (the events become visible
            // in the database) but not read before the drain.
            let mut publisher = connect_ws(addr, None).await;
            let live: Vec<Event> = (0..5)
                .map(|i| signed_note_seeded(relay.secp(), 1, &format!("live-{i}"), now, vec![]))
                .collect();
            let ids: Vec<String> = live.iter().map(|event| event.id.clone()).collect();
            for event in &live {
                futures_util::SinkExt::send(
                    &mut publisher,
                    tokio_tungstenite::tungstenite::Message::Text(
                        json!(["EVENT", event]).to_string().into(),
                    ),
                )
                .await
                .unwrap();
            }
            let probe_live = live[0].clone();
            let filter: Filter = serde_json::from_value(json!({"ids": ids})).unwrap();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            loop {
                let (stored, _) = relay
                    .db
                    .query_req(vec![filter.clone()], live.len(), unix_now())
                    .await;
                if stored.len() == live.len() {
                    break;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "timed out waiting for the live events to be accepted"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }

            relay.signal_drain();

            // The subscriber's queued CLOSED is flushed before the close.
            let mut saw_closed = false;
            while let Some(text) = ws_next_text(&mut subscriber).await {
                let msg: Value = serde_json::from_str(&text).unwrap();
                if msg[0] == "CLOSED" && msg[1] == "big" {
                    saw_closed = true;
                }
            }
            assert!(
                saw_closed,
                "the pending CLOSED must be flushed before the socket closes"
            );

            // The publisher's pending OKs are flushed before the close too.
            let mut oks = std::collections::HashSet::new();
            while let Some(text) = ws_next_text(&mut publisher).await {
                let msg: Value = serde_json::from_str(&text).unwrap();
                if msg[0] == "OK" {
                    assert_eq!(msg[2], true, "the event must be accepted: {msg:?}");
                    oks.insert(msg[1].as_str().unwrap_or("").to_string());
                }
            }
            for event in &live {
                assert!(
                    oks.contains(&event.id),
                    "the OK for {} was lost in the drain",
                    event.id
                );
            }

            drop(subscriber);
            drop(publisher);
            wait_for(
                || accounting_clean(&relay, &[&probe_live, &probe_big]),
                "accounting after the graceful drain",
            )
            .await;
            server.abort();
            relay.db.shutdown();
        });
    }

    #[test]
    fn websocket_keepalive_spares_the_alive_and_reaps_the_dead() {
        // ws_idle_timeout_secs with the keep-alive PING: a silent client
        // that keeps reading (tungstenite auto-answers the PING with a
        // PONG) is not reaped, while one that never reads is closed. 6s is
        // the smallest idle timeout above the relay's 5s PING floor.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay_with_limits("", |cfg| {
                cfg.relay.send_auth_challenge = false;
                cfg.limits.ws_idle_timeout_secs = 6;
            })
            .await;
            let (addr, server) = spawn_ws_server(Arc::clone(&relay)).await;
            let probe = signed_note(relay.secp(), "keepalive", unix_now(), vec![]);

            let mut alive = connect_ws(addr, None).await;
            let mut dead = connect_ws(addr, None).await;
            wait_for(
                || {
                    relay
                        .stats
                        .connections_active
                        .load(std::sync::atomic::Ordering::Relaxed)
                        == 2
                },
                "both connections to be accepted",
            )
            .await;

            // Past the idle deadline (6s plus up to 2s of jitter): the
            // polled client keeps auto-answering the PINGs.
            let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
            loop {
                tokio::select! {
                    _ = tokio::time::sleep_until(deadline) => break,
                    msg = futures_util::StreamExt::next(&mut alive) => match msg {
                        Some(Ok(_)) => {}
                        Some(Err(e)) => panic!("the polled client was closed: {e}"),
                        None => panic!("the polled client was reaped"),
                    },
                }
            }

            // The dead client never answered (it never read the PING): it
            // must be reaped, leaving only the polled connection.
            wait_for(
                || {
                    relay
                        .stats
                        .connections_active
                        .load(std::sync::atomic::Ordering::Relaxed)
                        == 1
                },
                "the silent dead client to be reaped",
            )
            .await;
            assert_eq!(
                relay
                    .conn_queues
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .len(),
                1,
                "only the alive connection may remain"
            );
            let close_deadline = tokio::time::Instant::now() + Duration::from_secs(2);
            loop {
                match tokio::time::timeout_at(
                    close_deadline,
                    futures_util::StreamExt::next(&mut dead),
                )
                .await
                {
                    Ok(Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_))))
                    | Ok(None)
                    | Ok(Some(Err(_))) => break,
                    Ok(Some(Ok(_))) => continue,
                    Err(_) => panic!("the dead client's socket was not closed"),
                }
            }

            // The kept-alive connection is still fully functional.
            futures_util::SinkExt::send(
                &mut alive,
                tokio_tungstenite::tungstenite::Message::Text(
                    json!(["REQ", "kp", {"kinds": [1]}]).to_string().into(),
                ),
            )
            .await
            .unwrap();
            let mut saw_eose = false;
            for _ in 0..3 {
                let msg = ws_next_json(&mut alive).await;
                if msg[0] == "EOSE" && msg[1] == "kp" {
                    saw_eose = true;
                    break;
                }
            }
            assert!(saw_eose, "the kept-alive connection must still be served");

            drop(alive);
            drop(dead);
            wait_for(
                || accounting_clean(&relay, &[&probe]),
                "accounting after the keep-alive test",
            )
            .await;
            server.abort();
            relay.db.shutdown();
        });
    }
}
