//! The relay: event acceptance (single and batched), live
//! broadcasting, NIP-29/NIP-43 group and role state, and the
//! live-delivery subscription index.
//! relay-generated event publishing. Event validation lives in
//! [`validate`].
//!
//! # NIP-62 vanish semantics
//!
//! A vanish request covers the events up to its `created_at`
//! (`until_created`), but this relay deliberately keeps a stricter,
//! fail-closed bar: once the request is honored the pubkey is recorded in
//! the database's vanish set and **every** later event from it is rejected,
//! including ones created after `until_created`. Persisted events that
//! predate the request are purged and stay rejected on re-broadcast. The
//! stricter bar means a vanished key cannot resume publishing through this
//! relay; the alternative (serving post-request events from a pubkey whose
//! deletion was asked for and whose pre-request history is gone) would let
//! a partial, deleted identity remain visible.

mod commands;
mod index;
pub(crate) use index::{FilterComponents, SubscriptionIndex};
mod roles;
mod validate;

use std::sync::Arc;

use secp256k1::{Keypair, Secp256k1, XOnlyPublicKey};
use std::collections::HashMap;
use std::sync::atomic::{AtomicIsize, AtomicU64, AtomicUsize, Ordering};
use tokio::sync::RwLock;
use tokio::sync::mpsc;

use crate::config::{AccessControl, Config};
use crate::db::{DbClient, PutOutcome};
use crate::event::Event;
use crate::nips::nip09;
use crate::nips::nip29::{self, GroupStore};
use crate::nips::nip43::{self, RoleStore};
use crate::nips::nip62;
use crate::stats::Stats;
use crate::util::unix_now;

/// Per-connection live-delivery queue capacity (in batches): a
/// connection that stops reading is closed when its queue fills so it can
/// reconnect and resynchronize instead of missing events silently.
pub(crate) const LIVE_QUEUE_CAPACITY: usize = 64;

pub struct Relay {
    pub config: Arc<RwLock<Config>>,
    pub access: Arc<RwLock<AccessControl>>,
    pub db: DbClient,
    pub stats: Arc<Stats>,
    /// The live subscription index: filter components (kinds, authors,
    /// tags) → connection ids. The bus task looks up the candidate
    /// connections for each event batch and delivers only to them, so an
    /// event wakes the connections that can match it instead of every
    /// subscriber (the per-connection filter match remains the final
    /// check).
    pub sub_index: std::sync::Arc<std::sync::RwLock<crate::relay::SubscriptionIndex>>,
    /// Per-connection live-delivery queues and overflow signals. A full
    /// queue signals the connection to close instead of silently losing a
    /// batch.
    pub conn_queues: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<u64, LiveQueue>>>,
    /// Connection id counter: the id identifies a connection in the
    /// subscription index and the queue map.
    pub next_conn_id: std::sync::atomic::AtomicU64,
    live_tx: mpsc::Sender<(Arc<Event>, Arc<String>)>,
    live_rx: Option<mpsc::Receiver<(Arc<Event>, Arc<String>)>>,
    live_batch_interval_ms: u64,
    live_batch_size: usize,
    pub groups: Arc<RwLock<GroupStore>>,
    /// The coalesced NIP-29 group rebuild that follows a vanish, NIP-09
    /// deletion or expiry of group-state events: `pending` is set when the
    /// in-memory state is known stale, so `persist_groups` must not save it
    /// (the persisted snapshot is dropped instead and the next startup
    /// rebuilds from the surviving events).
    groups_rebuild: std::sync::Arc<GroupsRebuild>,
    /// NIP-43 role definitions and member assignments.
    pub roles: Arc<RwLock<RoleStore>>,
    /// Limits concurrent `/api/v1` queries so a flood of REST traffic
    /// fails fast (503) instead of piling up behind WebSocket work. The
    /// limit is adjustable at runtime (SIGHUP config reload).
    pub api_limit: Arc<ApiLimiter>,
    /// Per-pubkey sliding window of accepted event timestamps
    /// (`relay.max_events_per_min_per_pubkey`). Bounded: at most 10k
    /// pubkeys are tracked — a full map never clears (tracked windows are
    /// preserved); fresh pubkeys alone are fail-open until old windows
    /// expire.
    publish_rate: std::sync::Mutex<HashMap<String, std::collections::VecDeque<u64>>>,
    /// When the publish-rate map was last pruned. The map is bounded, and
    /// pruning it is a full scan: a flood of fresh pubkeys must not run that
    /// scan once per event.
    publish_rate_pruned_at: std::sync::atomic::AtomicU64,
    /// Serializes `persist_access`: two concurrent NIP-86 mutations must
    /// not capture snapshots in one order and queue their writes in the
    /// other, or the older snapshot lands last and loses the newer entry
    /// (a ban silently disappearing on the next restart).
    persist_access_lock: tokio::sync::Mutex<()>,
    /// Serializes `persist_roles` snapshot capture and write (same hazard
    /// as `persist_access_lock`: a stale role snapshot must not overwrite a
    /// newer one). `persist_groups` uses `GroupsRebuild::persist_lock`.
    persist_roles_lock: tokio::sync::Mutex<()>,
    /// Serializes the Blossom allowlist snapshot capture and write (NIP-86
    /// or the `/blossom allow|deny` command events, and the SIGHUP reload):
    /// without it a command that captured an older snapshot can queue its
    /// write after a newer one and drop the newer entry on the next restart.
    persist_blossom_allow_lock: tokio::sync::Mutex<()>,
    /// NIP-86 blockip/unblockip: every list change notifies each
    /// connection's watcher, so established read-only subscribers (which
    /// never send a frame) are disconnected too — a version counter could
    /// only be observed on an inbound frame.
    pub ip_blocks_tx: tokio::sync::watch::Sender<u64>,
    /// Bumped on every SIGHUP config reload: connections cache the NIP-40/
    /// NIP-42 flags against this version and refresh them only when it
    /// changes, so the hot live path never takes the shared config lock.
    pub config_version: std::sync::atomic::AtomicU64,
    /// Graceful-shutdown signal for the WebSocket connection loops: on
    /// shutdown the loops wake, flush their pending event batches (so the
    /// accepted events and their OKs are not lost to the process exit) and
    /// close. The sender lives here because the upgraded WebSocket tasks
    /// are detached from the HTTP connection they came from.
    drain_tx: tokio::sync::watch::Sender<bool>,
    /// The relay's own keypair (from `relay.private_key`), used to sign
    /// NIP-29 and NIP-43 relay-generated events.
    key: Option<Keypair>,
    /// Cached hex pubkey of the relay's own key (fixed at startup, like
    /// `key`). The access-control checks exempt it, so the operator can
    /// always publish command events and read on restricted relays.
    pub(crate) relay_pubkey: Option<String>,
    secp: Secp256k1<secp256k1::All>,
    /// Path of the config file, set at startup so NIP-86 runtime changes
    /// (relay name/description/icon) can be persisted to disk; without
    /// persistence a SIGHUP config reload would silently revert them.
    pub config_path: Arc<tokio::sync::RwLock<Option<std::path::PathBuf>>>,
    /// Strictly monotonic stamp for relay-generated events: see
    /// [`StampClock`].
    stamps: StampClock,
    /// The Blossom file server state (when configured), so its handlers can
    /// share the relay's state.
    pub blossom: Arc<tokio::sync::RwLock<Option<Arc<crate::server::blossom::BlossomState>>>>,
    /// The Blossom upload allowlist (normalized hex pubkeys), loaded from
    /// the relay database at startup and refreshed on SIGHUP.
    pub blossom_allow: Arc<tokio::sync::RwLock<Vec<String>>>,
    /// Rate-limited audit trail of the management operations (NIP-86).
    pub audit: crate::audit::AuditLog,
    /// NIP-98 replay guard: every HTTP auth event authorizes exactly one
    /// management request (a captured header must not be reusable within
    /// its 60-second window).
    pub nip98_replay: crate::nips::nip98::ReplayGuard,
    /// Command event ids already executed during this process. Event ids are
    /// persisted in the database, but this guard also makes direct/replayed
    /// side-effect dispatch idempotent before another response is emitted.
    command_events: std::sync::Mutex<std::collections::HashSet<String>>,
    /// Cached static part of the NIP-11 information document (the volatile
    /// `stats` section is rebuilt per request); invalidated by the config
    /// version and the access lists the document reads.
    pub(crate) nip11_cache: std::sync::Mutex<Option<crate::nips::nip11::Nip11Cache>>,
}

/// Issues strictly increasing timestamps for relay-generated events.
///
/// The relay stamps its generated replaceable events (NIP-29 39000-39005,
/// NIP-43 33534/13534) so that the newest group/role state always wins the
/// NIP-01 replacement tie-break. With plain `unix_now()` stamps, two group
/// events applied in the same second would share a timestamp and the
/// replacement would fall back to the id comparison — where a *stale*,
/// later-committed version could beat the newer state. The clock guarantees
/// that stamps reflect the order in which the state was applied, not the
/// order in which the events happen to be stored.
pub(crate) struct StampClock {
    last: AtomicU64,
}

impl StampClock {
    /// Starts the clock from a previously issued stamp (restart recovery):
    /// later stamps stay greater than everything issued before the restart,
    /// so stored relay-generated events can never outrank fresh state.
    /// Pass `0` on a fresh start.
    fn new_with_last(last: u64) -> Self {
        StampClock {
            last: AtomicU64::new(last),
        }
    }

    /// Returns a timestamp strictly greater than every previously issued
    /// stamp and at least `floor`, while values remain. The increment is
    /// capped at `u64::MAX - 1` so it never overflows. Once that cap is
    /// reached (unreachable in practice at one stamp per second) the clock
    /// saturates and keeps returning the cap: strict monotonicity is
    /// impossible beyond the last usable timestamp, but the clock never
    /// regresses and never returns `u64::MAX`.
    pub(crate) fn stamp(&self, floor: u64) -> u64 {
        let mut cur = self.last.load(Ordering::Relaxed);
        loop {
            let next = cur
                .max(floor.saturating_sub(1))
                .min(u64::MAX - 2)
                .saturating_add(1);
            match self
                .last
                .compare_exchange_weak(cur, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return next,
                Err(actual) => cur = actual,
            }
        }
    }
}

/// Minimum seconds between two completed post-vanish group rebuilds. A
/// vanish is exempt from the publish rate limit, so any keypair can trigger
/// one; without a floor a burst of vanishes (or an attacker cycling fresh
/// keys through create-and-vanish) would run a full-history scan per event.
/// Requests arriving inside the window coalesce into the next scan via the
/// dirty flag.
const GROUPS_REBUILD_MIN_INTERVAL_SECS: u64 = 2;

/// Bound on the group events buffered while a rebuild scan runs. The scan
/// does not hold `groups.write()`, so events arriving meanwhile are applied
/// to the live store and buffered for replay on the fresh one; a burst
/// larger than this cannot be replayed safely, so the worker discards the
/// fresh store and rebuilds again later (the live store keeps serving and
/// the persisted snapshot stays dropped until a scan completes cleanly).
const GROUPS_REBUILD_BUFFER_MAX: usize = 4096;

/// A group event accepted while a rebuild scan was in flight, replayed onto
/// the fresh store once the scan completes.
struct BufferedGroupEvent {
    event: Arc<Event>,
    now: u64,
}

/// Group mutations accepted while a rebuild scan is in flight. The scan
/// runs without `groups.write()` (a full-history paged scan must not stall
/// every NIP-29 request), so the events it would otherwise miss are
/// buffered and replayed onto the fresh store under the final write lock.
#[derive(Default)]
struct RebuildBuffer {
    /// A scan is in flight: group mutations are captured here.
    scanning: bool,
    /// Captured events, bounded by [`GROUPS_REBUILD_BUFFER_MAX`]. The local
    /// `Mutex` serializes the capture with the worker's take-and-swap, so
    /// no event can slip between the two.
    events: Vec<BufferedGroupEvent>,
    /// The buffer is full (or a mutation the database cannot replay
    /// happened): the worker must discard the fresh store and rebuild later
    /// instead of applying a partial set.
    overflow: bool,
    /// A mutation whose effect is not reconstructible from the database
    /// (a `9008`'s ghost/tombstone/purge outcome, a vanish's member
    /// removal) landed during the scan: the fresh store predates it, so the
    /// worker must discard it and rebuild.
    retry: bool,
}

/// Coordination state for the coalesced NIP-29 group rebuild that follows a
/// vanish (or another removal of group-state-relevant events). Kept in an
/// `Arc` so the background worker can run without borrowing the relay.
struct GroupsRebuild {
    /// At least one removal happened since the last completed rebuild.
    dirty: std::sync::atomic::AtomicBool,
    /// A worker task owns (or is about to own) the rebuild loop: triggers
    /// only set the flags.
    running: std::sync::atomic::AtomicBool,
    /// The in-memory state is known stale: persisted snapshots must be
    /// dropped until a rebuild completes (fail-closed).
    pending: std::sync::atomic::AtomicBool,
    /// Unix seconds of the last attempt, the minimum-interval floor.
    last: std::sync::atomic::AtomicU64,
    /// Completed scans, for tests asserting that a burst coalesces.
    rebuilds: std::sync::atomic::AtomicU64,
    /// Single-flight token: only the task that takes it drains the loop.
    lock: tokio::sync::Mutex<()>,
    /// Serializes snapshot capture and write (like `persist_access_lock`):
    /// without it a mutation that captured an older snapshot could queue its
    /// write after a newer one and overwrite it, and a snapshot from before
    /// a vanish could land after the post-vanish clear.
    persist_lock: tokio::sync::Mutex<()>,
    /// Mutations accepted while the scan runs (see [`RebuildBuffer`]).
    buffer: tokio::sync::Mutex<RebuildBuffer>,
}

impl Default for GroupsRebuild {
    fn default() -> Self {
        GroupsRebuild {
            dirty: std::sync::atomic::AtomicBool::new(false),
            running: std::sync::atomic::AtomicBool::new(false),
            pending: std::sync::atomic::AtomicBool::new(false),
            last: std::sync::atomic::AtomicU64::new(0),
            rebuilds: std::sync::atomic::AtomicU64::new(0),
            lock: tokio::sync::Mutex::new(()),
            persist_lock: tokio::sync::Mutex::new(()),
            buffer: tokio::sync::Mutex::new(RebuildBuffer::default()),
        }
    }
}

impl GroupsRebuild {
    /// Persists the current group state, dropping the snapshot when the
    /// state is known stale. The re-check *follows* the snapshot: a vanish
    /// that marked the state stale in between must not have pre-vanish
    /// state written out. Holding the lock across capture and write keeps a
    /// stale snapshot from landing after a newer one.
    ///
    /// Returns whether the intended write committed. On `false` the caller
    /// must keep the state pending (fail-closed): a failed clear leaves the
    /// stale snapshot on disk, and a failed save is not durable state.
    async fn persist(&self, db: &DbClient, groups: &RwLock<GroupStore>) -> bool {
        let _guard = self.persist_lock.lock().await;
        if self.pending.load(Ordering::SeqCst) {
            return db.clear_groups_snapshot().await;
        }
        let snapshot = groups.read().await.snapshot();
        if self.pending.load(Ordering::SeqCst) {
            return db.clear_groups_snapshot().await;
        }
        db.save_groups(snapshot).await
    }
}

/// Marks the group state stale and schedules the coalesced background
/// rebuild (single-flight via the state's lock and the `running` flag).
fn schedule_groups_rebuild(
    db: DbClient,
    groups: std::sync::Arc<RwLock<GroupStore>>,
    config: std::sync::Arc<RwLock<Config>>,
    state: std::sync::Arc<GroupsRebuild>,
) {
    if state.running.swap(true, Ordering::SeqCst) {
        // A worker is already draining; it re-checks the dirty flag before
        // it exits, so this request is covered.
        return;
    }
    tokio::spawn(groups_rebuild_worker(db, groups, config, state));
}

/// The coalesced group-state rebuild worker. Holds the single-flight lock,
/// drains the dirty flag (running at most one scan per
/// [`GROUPS_REBUILD_MIN_INTERVAL_SECS`]) and swaps in the rebuilt store.
///
/// The scan itself runs **without** `groups.write()`: a full-history paged
/// scan can take seconds, and holding the write lock across it stalled
/// every NIP-29 read and write behind an unauthenticated vanish. Group
/// events accepted while the scan runs are captured in
/// [`GroupsRebuild::buffer`] and applied to the fresh store under the short
/// final write lock, together with the hidden markers captured before the
/// scan; a mutation the database cannot replay (a `9008`'s purge outcome, a
/// vanish's member removal) or a buffer overflow discards the fresh store
/// and rebuilds again instead of swapping a state that predates it.
async fn groups_rebuild_worker(
    db: DbClient,
    groups: std::sync::Arc<RwLock<GroupStore>>,
    config: std::sync::Arc<RwLock<Config>>,
    state: std::sync::Arc<GroupsRebuild>,
) {
    {
        // Scope the single-flight guard so it is released before the
        // trailing re-schedule below (which may move `state`).
        let _single_flight = state.lock.lock().await;
        loop {
            if !state.dirty.swap(false, Ordering::SeqCst) {
                break;
            }
            // The first scan runs immediately (`last == 0`); later requests
            // wait out the remainder of the interval. Requests that arrive
            // while waiting coalesce into this rebuild (the flag is drained
            // above, and any later trigger sets it again).
            let elapsed = unix_now().saturating_sub(state.last.load(Ordering::Relaxed));
            if elapsed < GROUPS_REBUILD_MIN_INTERVAL_SECS {
                tokio::time::sleep(std::time::Duration::from_secs(
                    GROUPS_REBUILD_MIN_INTERVAL_SECS - elapsed,
                ))
                .await;
            }
            // Read the cap before taking the group lock: the accept paths take
            // `config.read` and then `groups.read`, so the worker must not hold
            // `groups.write` while awaiting `config.read`.
            let cap = config.read().await.relay.max_groups;
            // Enter the buffering window *before* snapshotting the markers:
            // an event accepted in between is buffered and its in-memory
            // effect is reflected in the captured sets, and the worker will
            // still replay it onto the fresh store.
            {
                let mut buffer = state.buffer.lock().await;
                buffer.scanning = true;
                buffer.events.clear();
                buffer.overflow = false;
                buffer.retry = false;
            }
            // The ids known before the rebuild seed the ghost detection and
            // the hidden markers: groups the removed events took out of the
            // store are gone from the rebuilt one (their surviving ordinary
            // posts must not become world-readable on a keyless relay), and
            // the delete tombstones must survive so a confirmed purge stays
            // re-creatable.
            let (previous, previous_deleted, previous_ghost) = {
                let store = groups.read().await;
                (
                    store.hidden_group_ids(),
                    store.deleted_group_ids(),
                    store.ghost_group_ids(),
                )
            };
            let mut fresh = GroupStore::with_cap(cap);
            let rebuilt = fresh
                .rebuild_after_vanish(&db, previous, previous_deleted, previous_ghost)
                .await;
            state
                .last
                .store(unix_now(), std::sync::atomic::Ordering::Relaxed);
            state
                .rebuilds
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if !rebuilt {
                // Release the buffering window: the events captured while
                // the scan ran are already applied to the live store, which
                // stays authoritative. A failed scan keeps the state
                // pending (the snapshot stays dropped fail-closed) until
                // another removal schedules a retry.
                let mut buffer = state.buffer.lock().await;
                buffer.scanning = false;
                buffer.events.clear();
                buffer.retry = false;
                buffer.overflow = false;
                drop(buffer);
                log::error!(
                    "group state rebuild after a vanish failed; dropping the persisted \
                     snapshot so the next restart rebuilds from the surviving events"
                );
                state.pending.store(true, Ordering::SeqCst);
                continue;
            }
            // Finalize under the buffer lock: the take and the swap are one
            // atomic step against the accept paths (which hold the same
            // lock across their live-store apply), so an event either lands
            // in the captured set and is replayed here, or applies to the
            // swapped-in store afterwards.
            let retry = {
                let mut buffer = state.buffer.lock().await;
                let buffered = std::mem::take(&mut buffer.events);
                let retry = buffer.retry || buffer.overflow;
                buffer.retry = false;
                buffer.overflow = false;
                if retry {
                    // A mutation the scan cannot replay happened: discard
                    // the fresh store and rebuild again later. The event
                    // and the captured set stay on the live store (which is
                    // still authoritative), so nothing is lost.
                    state.dirty.store(true, Ordering::SeqCst);
                    state.pending.store(true, Ordering::SeqCst);
                    log::warn!(
                        "group state rebuild discarded: an unreplayable mutation or a buffer \
                         overflow happened during the scan; rebuilding again"
                    );
                } else {
                    let mut store = groups.write().await;
                    for buffered in buffered {
                        fresh.apply(&buffered.event, "", buffered.now, false, true);
                    }
                    *store = fresh;
                }
                buffer.scanning = false;
                retry
            };
            if retry {
                continue;
            }
            // Only mark the store current when no further removal arrived
            // while the scan ran: otherwise the next iteration rebuilds
            // again and the snapshot stays dropped (fail-closed) until that
            // rebuild completes.
            if !state.dirty.load(Ordering::SeqCst) {
                state.pending.store(false, Ordering::SeqCst);
                if state.dirty.load(Ordering::SeqCst) {
                    // A removal marked the state stale while the flag was
                    // being cleared: keep it fail-closed; the loop rebuilds
                    // again.
                    state.pending.store(true, Ordering::SeqCst);
                }
            }
            if !state.persist(&db, &groups).await {
                // A failed save is not durable state, and a failed clear
                // left the stale snapshot on disk: keep pending so the next
                // persist retries the clear instead of treating the state
                // as clean.
                log::error!(
                    "could not persist the rebuilt group state; keeping the stored snapshot \
                     dropped so a restart rebuilds from the surviving events"
                );
                state.pending.store(true, Ordering::SeqCst);
            }
        }
    }
    // Release the single-flight claim, then re-check: a trigger that set the
    // dirty flag between the last swap and this release saw `running ==
    // true` and did not spawn, so it must not be lost.
    state.running.store(false, Ordering::SeqCst);
    if state.dirty.load(Ordering::SeqCst) {
        schedule_groups_rebuild(db, groups, config, state);
    }
}

/// Tuning of the live fan-out bus.
#[derive(Debug, Clone, Copy)]
pub struct LiveBusConfig {
    /// Bound on the queue of events waiting to be broadcast.
    pub buffer: usize,
    /// The bus flushes at least this often (milliseconds).
    pub batch_interval_ms: u64,
    /// Maximum events per flushed batch.
    pub batch_size: usize,
}

pub(crate) struct LiveQueue {
    pub(crate) sender: mpsc::Sender<crate::ws::LiveBatch>,
    pub(crate) overflow: tokio::sync::watch::Sender<()>,
}

fn enqueue_live_batch(queue: &LiveQueue, batch: crate::ws::LiveBatch) {
    if let Err(error) = queue.sender.try_send(batch)
        && matches!(error, mpsc::error::TrySendError::Full(_))
    {
        let _ = queue.overflow.send(());
    }
}

/// Forces every subscribed connection to resynchronize after a live-bus
/// panic. The batch may have been persisted already and may have been
/// delivered to only some queues, so closing only affected queues cannot
/// establish a safe delivery boundary.
fn signal_live_resync(
    conn_queues: &std::sync::Arc<std::sync::Mutex<std::collections::HashMap<u64, LiveQueue>>>,
) {
    let queues = conn_queues.lock().unwrap_or_else(|p| p.into_inner());
    for queue in queues.values() {
        let _ = queue.overflow.send(());
    }
}

/// Bounds the number of concurrently served `/api/v1` queries. Implemented
/// with a cheap atomic counter instead of a `tokio::sync::Semaphore` so the
/// limit can be changed at runtime (SIGHUP config reload) without
/// reallocating the shared handle.
pub struct ApiLimiter {
    max: AtomicUsize,
    in_flight: AtomicIsize,
}

/// An acquired `/api/v1` slot; the slot is released when the guard drops,
/// on every exit path of the request handler.
pub struct ApiPermit {
    limiter: Arc<ApiLimiter>,
}

impl Drop for ApiPermit {
    fn drop(&mut self) {
        self.limiter.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

impl ApiLimiter {
    fn new(max: usize) -> Arc<ApiLimiter> {
        Arc::new(ApiLimiter {
            max: AtomicUsize::new(max.max(1)),
            in_flight: AtomicIsize::new(0),
        })
    }

    /// Applies a new concurrency ceiling (from a config reload). The ceiling
    /// takes effect for every new request.
    pub fn set_max(&self, max: usize) {
        self.max.store(max.max(1), Ordering::Relaxed);
    }

    /// Reserves one in-flight slot when one is free, returning the guard
    /// that releases it. `None` when the limiter is saturated (503).
    pub fn try_acquire(self: &Arc<Self>) -> Option<ApiPermit> {
        let max = self.max.load(Ordering::Relaxed) as isize;
        let mut cur = self.in_flight.load(Ordering::Relaxed);
        loop {
            if cur >= max {
                return None;
            }
            match self.in_flight.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Some(ApiPermit {
                        limiter: Arc::clone(self),
                    });
                }
                Err(actual) => cur = actual,
            }
        }
    }
}

impl Relay {
    pub async fn new(
        config: Arc<RwLock<Config>>,
        db: DbClient,
        stats: Arc<Stats>,
        private_key_hex: &str,
        live_bus: LiveBusConfig,
    ) -> Relay {
        let (live_tx, live_rx) = mpsc::channel(live_bus.buffer.max(16));
        let live_batch_interval_ms = live_bus.batch_interval_ms.clamp(1, 1000);
        let live_batch_size = live_bus.batch_size.max(1);
        let secp = Secp256k1::new();
        let key = if private_key_hex.is_empty() {
            None
        } else {
            match hex::decode(private_key_hex) {
                Ok(bytes) if bytes.len() == 32 => Keypair::from_seckey_slice(&secp, &bytes).ok(),
                _ => {
                    log::warn!("invalid relay.private_key: ignoring");
                    None
                }
            }
        };
        let relay_pubkey = key
            .as_ref()
            .map(|keypair| XOnlyPublicKey::from_keypair(keypair).0.to_string());
        let api_max_concurrent = config.read().await.limits.max_api_concurrent;
        // Bootstrap the relay-event stamp clock from the newest stored
        // relay-generated replaceable: without this a burst-then-restart in
        // the same second could stamp fresh state below a pre-restart event,
        // letting stale metadata win the NIP-01 replacement tie-break.
        // The startup-style read reports a failed/unanswered scan instead of
        // degrading to "no stored event": a miss would start the clock at 0
        // and let a pre-restart event keep a higher stamp, so it is fatal.
        let stamp_last = match &relay_pubkey {
            Some(pk) => {
                let filter = crate::filter::Filter {
                    authors: Some(vec![pk.clone()]),
                    kinds: Some(vec![
                        nip29::GROUP_META,
                        nip29::GROUP_ADMINS,
                        nip29::GROUP_MEMBERS,
                        nip29::GROUP_ROLES,
                        nip29::GROUP_PARTICIPANTS,
                        nip29::GROUP_PINS,
                        nip43::ROLE_DEFINITION,
                        nip43::MEMBERSHIP_LIST,
                        // The relay's own NIP-66 discovery event is
                        // relay-signed and addressable too: without it a
                        // restart in the same second (or after generated
                        // stamps ran ahead of the wall clock) leaves the
                        // fresh publish on the losing side of the id
                        // tie-break until the next 12h refresh.
                        crate::nips::nip66::DISCOVERY,
                    ]),
                    ..Default::default()
                };
                match db
                    .query_full_startup(vec![filter], 1, unix_now(), false)
                    .await
                {
                    Some((events, _)) => {
                        events.into_iter().map(|e| e.created_at).max().unwrap_or(0)
                    }
                    None => {
                        log::error!(
                            "cannot read the stored relay event stamps; refusing to start \
                             (a pre-restart event could outrank fresh relay state)"
                        );
                        std::process::exit(1);
                    }
                }
            }
            None => 0,
        };
        // Seed the access control: the persisted runtime state wins, so NIP-86
        // bans/allowlists survive restarts; the config `access` section seeds
        // the very first run only (when no runtime state exists yet). The
        // pubkey allow/deny lists live in the relay database (LMDB),
        // managed with `nostrfy relay allow/deny` — never in the config.
        let mut access = match db.load_access().await {
            crate::db::LoadAccessOutcome::Loaded(access) => access,
            crate::db::LoadAccessOutcome::Missing => config.read().await.access.clone(),
            crate::db::LoadAccessOutcome::Failed => {
                // A failed read must not be mistaken for "nothing was ever
                // persisted": the config seed would silently replace the
                // persisted NIP-86 bans/IP blocks with it (fail-open).
                log::error!("cannot load the persisted access control state; refusing to start");
                std::process::exit(1);
            }
        };
        // `restrict_relay` is config-owned: an older persisted blob (which
        // predates the flag) would otherwise silently override it with the
        // serde default `false`.
        access.restrict_relay = config.read().await.access.restrict_relay;
        // Migration: an older `allowkind` implementation pushed into
        // `allowed_kinds`, turning the config allowlist into an exhaustive
        // runtime one. Persisted that way, a config with an empty
        // allowlist (the common case) would reject every kind not listed.
        // The config file is the authoritative allowlist; a persisted list
        // with an empty config list is stale state and is cleared.
        if config.read().await.access.allowed_kinds.is_empty() && !access.allowed_kinds.is_empty() {
            log::warn!(
                "clearing the persisted access.allowed_kinds ({:?}): the old `allowkind` \
                 semantics populated it and it would block every other kind; the config \
                 allowlist is the authoritative allowlist",
                access.allowed_kinds
            );
            access.allowed_kinds.clear();
        }
        // The pubkey lists and the Blossom allowlist are stored in the
        // relay database and loaded into memory at startup (and refreshed
        // on SIGHUP). A failed load must stop the relay instead of
        // starting with empty (fail-open) security state: an empty deny
        // list lifts every ban, and an empty allowlist opens an
        // allowlist-only relay.
        let (deny, allow) = match db.load_relay_pubkeys().await {
            Some(lists) => lists,
            None => {
                log::error!(
                    "cannot load the persisted relay pubkey access lists; refusing to start"
                );
                std::process::exit(1);
            }
        };
        access.blocked_pubkeys = deny;
        access.allowed_pubkeys = allow;
        let blossom_allow = match db.load_blossom_allow().await {
            Some(list) => list,
            None => {
                log::error!(
                    "cannot load the persisted Blossom upload allowlist; refusing to start"
                );
                std::process::exit(1);
            }
        };
        Relay {
            config: Arc::clone(&config),
            access: Arc::new(RwLock::new(access)),
            db,
            stats,
            sub_index: std::sync::Arc::new(std::sync::RwLock::new(SubscriptionIndex::default())),
            conn_queues: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            next_conn_id: std::sync::atomic::AtomicU64::new(1),
            live_tx,
            live_rx: Some(live_rx),
            live_batch_interval_ms,
            live_batch_size,
            groups: Arc::new(RwLock::new(GroupStore::with_cap(
                config.read().await.relay.max_groups,
            ))),
            groups_rebuild: std::sync::Arc::new(GroupsRebuild::default()),
            roles: Arc::new(RwLock::new(RoleStore::default())),
            api_limit: ApiLimiter::new(api_max_concurrent),
            publish_rate: std::sync::Mutex::new(HashMap::new()),
            publish_rate_pruned_at: std::sync::atomic::AtomicU64::new(0),
            persist_access_lock: tokio::sync::Mutex::new(()),
            persist_roles_lock: tokio::sync::Mutex::new(()),
            persist_blossom_allow_lock: tokio::sync::Mutex::new(()),
            ip_blocks_tx: tokio::sync::watch::channel(0).0,
            config_version: AtomicU64::new(0),
            drain_tx: tokio::sync::watch::channel(false).0,
            key,
            relay_pubkey,
            secp,
            config_path: Arc::new(tokio::sync::RwLock::new(None)),
            stamps: StampClock::new_with_last(stamp_last),
            blossom: Arc::new(tokio::sync::RwLock::new(None)),
            blossom_allow: Arc::new(tokio::sync::RwLock::new(blossom_allow)),
            audit: crate::audit::AuditLog::default(),
            nip98_replay: Default::default(),
            command_events: std::sync::Mutex::new(std::collections::HashSet::new()),
            nip11_cache: std::sync::Mutex::new(None),
        }
    }

    /// A strictly monotonic timestamp for relay-generated events (see
    /// [`StampClock`]): at least `floor`, and greater than every stamp
    /// issued before.
    pub(crate) fn stamp_floor(&self, floor: u64) -> u64 {
        self.stamps.stamp(floor)
    }

    /// Signals every WebSocket connection to flush and close (graceful
    /// shutdown). Idempotent; the relay's shutdown sequence waits for
    /// `stats.connections_active` to reach zero before stopping the
    /// database, so the flushed batches are still committed.
    pub fn signal_drain(&self) {
        let _ = self.drain_tx.send(true);
    }

    /// A receiver for a connection loop to observe [`Self::signal_drain`].
    pub fn subscribe_drain(&self) -> tokio::sync::watch::Receiver<bool> {
        self.drain_tx.subscribe()
    }

    /// Spawns the live batching task. Must be called once, after the relay
    /// is created.
    pub fn start_live_bus(&mut self) {
        let Some(mut rx) = self.live_rx.take() else {
            return;
        };
        let sub_index = std::sync::Arc::clone(&self.sub_index);
        let conn_queues = std::sync::Arc::clone(&self.conn_queues);
        let interval_ms = self.live_batch_interval_ms;
        let batch_size = self.live_batch_size;
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut batch: Vec<(Arc<Event>, Arc<String>)> = Vec::with_capacity(batch_size);
            let flush = |batch: &mut Vec<(Arc<Event>, Arc<String>)>| {
                if batch.is_empty() {
                    return;
                }
                let batch = Arc::new(std::mem::take(batch));
                // Deliver to the candidate connections only: the
                // subscription index maps each event's components to the
                // connections that could match, so an event wakes the
                // subscribers that can see it instead of all of them.
                // The per-connection filter match remains the final
                // check; the per-connection queues drop when full (the
                // same backpressure as the old broadcast).
                let conns = {
                    let index = sub_index.read().unwrap_or_else(|p| p.into_inner());
                    let mut conns = std::collections::HashSet::new();
                    for (event, _) in batch.iter() {
                        index.extend_candidates(event, &mut conns);
                    }
                    conns
                };
                // Collect the candidate queues under the lock, then drop
                // the lock before delivering. A full queue signals its
                // connection to close instead of silently losing a batch.
                let queues: Vec<LiveQueue> = {
                    let queues = conn_queues.lock().unwrap_or_else(|p| p.into_inner());
                    conns
                        .iter()
                        .filter_map(|conn| {
                            queues.get(conn).map(|queue| LiveQueue {
                                sender: queue.sender.clone(),
                                overflow: queue.overflow.clone(),
                            })
                        })
                        .collect()
                };
                for queue in queues {
                    enqueue_live_batch(&queue, batch.clone());
                }
            };
            loop {
                tokio::select! {
                    event = rx.recv() => match event {
                        Some((event, json)) => {
                            batch.push((event, json));
                            if batch.len() >= batch_size {
                                // A panic in candidate lookup must not kill
                                // the bus (which would silently stop all live
                                // delivery once the channel fills): contain it
                                // and keep serving.
                                let r = std::panic::catch_unwind(
                                    std::panic::AssertUnwindSafe(|| flush(&mut batch)),
                                );
                                if r.is_err() {
                                    log::error!(
                                        "live bus recovered from a panic; forcing all subscribers to resynchronize"
                                    );
                                    signal_live_resync(&conn_queues);
                                    batch.clear();
                                }
                            }
                        }
                        None => {
                            let r = std::panic::catch_unwind(
                                std::panic::AssertUnwindSafe(|| flush(&mut batch)),
                            );
                            if r.is_err() {
                                log::error!(
                                    "live bus recovered from a panic; forcing all subscribers to resynchronize"
                                );
                                signal_live_resync(&conn_queues);
                            }
                            return;
                        }
                    },
                    _ = interval.tick() => {
                        let r = std::panic::catch_unwind(
                            std::panic::AssertUnwindSafe(|| flush(&mut batch)),
                        );
                        if r.is_err() {
                            log::error!(
                                "live bus recovered from a panic; forcing all subscribers to resynchronize"
                            );
                            signal_live_resync(&conn_queues);
                            batch.clear();
                        }
                    }
                }
            }
        });
    }

    /// Queues an event for live delivery to subscribers. Backpressure from
    /// the bounded live buffer is propagated to the accepting task so an
    /// accepted event is never silently lost before fan-out. The JSON is
    /// encoded once here — every subscriber shares the same serialization.
    /// Accepts an [`Arc<Event>`] (or an owned [`Event`]) so the accept path
    /// can share one allocation with the database write.
    pub async fn broadcast(&self, event: impl Into<Arc<Event>>) -> Result<(), ()> {
        let event = event.into();
        let json = Arc::new(serde_json::to_string(&*event).unwrap_or_default());
        if self.live_tx.send((event, json)).await.is_err() {
            log::error!("live bus stopped before an accepted event could be broadcast");
            self.stats.bump(&self.stats.db_errors, 1);
            return Err(());
        }
        Ok(())
    }

    /// Whether `pubkey` may publish another event under
    /// `relay.max_events_per_min_per_pubkey` (a sliding 60-second window;
    /// 0 = unlimited). Each window holds at most `max` timestamps, so one
    /// key pins at most that many `u64`s. The window map is bounded at
    /// 10,000 pubkeys — the
    /// cap never clears the whole map (a clear would reset every window
    /// and permanently disable the limit): expired windows are evicted
    /// first, and a still-full map rejects the new pubkey because its
    /// window cannot be tracked safely.
    pub(crate) fn publish_rate_allowed(&self, cfg: &Config, pubkey: &str, now: u64) -> bool {
        const MAX_TRACKED_PUBKEYS: usize = 10_000;
        let max = cfg.relay.max_events_per_min_per_pubkey;
        if max == 0 {
            return true;
        }
        let mut rate = self.publish_rate.lock().unwrap_or_else(|p| p.into_inner());
        // Already-tracked pubkeys are always enforced: the cap logic below
        // only decides whether a *new* pubkey is tracked, so a full map
        // can never disable the limit for tracked keys.
        if let Some(window) = rate.get_mut(pubkey) {
            while window.front().is_some_and(|t| now.saturating_sub(*t) >= 60) {
                window.pop_front();
            }
            if window.len() >= max as usize {
                return false;
            }
            window.push_back(now);
            return true;
        }
        // New pubkey: never clear the whole map (a clear would reset every
        // window and permanently disable the limit). Expired windows are
        // evicted first; a still-full map rejects the new pubkey because
        // admitting an untracked identity would bypass the configured
        // limit. The eviction is a full scan, so it runs at most once per
        // second: a flood of fresh pubkeys would otherwise walk the whole
        // map per event.
        if rate.len() >= MAX_TRACKED_PUBKEYS {
            let last_pruned = self
                .publish_rate_pruned_at
                .load(std::sync::atomic::Ordering::Relaxed);
            if now.saturating_sub(last_pruned) >= 1 {
                self.publish_rate_pruned_at
                    .store(now, std::sync::atomic::Ordering::Relaxed);
                rate.retain(|_, w| w.front().is_some_and(|t| now.saturating_sub(*t) < 60));
            }
            if rate.len() >= MAX_TRACKED_PUBKEYS {
                return false;
            }
        }

        rate.entry(pubkey.to_string()).or_default().push_back(now);
        true
    }

    /// Releases one publish-rate reservation when database admission rejects
    /// the event after validation. The timestamp is unique to this
    /// reservation only by count, so remove exactly one matching entry.
    pub(crate) fn publish_rate_rollback(&self, pubkey: &str, now: u64) {
        let mut rate = self.publish_rate.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(window) = rate.get_mut(pubkey)
            && let Some(pos) = window.iter().rposition(|timestamp| *timestamp == now)
        {
            window.remove(pos);
        }
        if rate.get(pubkey).is_some_and(|window| window.is_empty()) {
            rate.remove(pubkey);
        }
    }

    /// Hex pubkey of the relay's own key, if configured.
    pub fn relay_pubkey(&self) -> Option<String> {
        self.relay_pubkey.clone()
    }

    /// Borrowed form of [`Self::relay_pubkey`]: the per-event validation
    /// paths only compare against it and must not clone the string.
    pub fn relay_pubkey_ref(&self) -> Option<&str> {
        self.relay_pubkey.as_deref()
    }

    pub fn secp(&self) -> &Secp256k1<secp256k1::All> {
        &self.secp
    }

    /// Persists the current access control lists to the database so NIP-86
    /// runtime bans/allowlists survive restarts. Callers must release the
    /// `access` write lock before awaiting this.
    ///
    /// The snapshot and both writes are serialized: without the lock two
    /// concurrent mutations could read snapshots in one order (older first)
    /// but queue their writes in the other, so the stale lists are the last
    /// ones committed and the newer entry is lost after a restart.
    /// Returns whether both writes committed: the NIP-86 methods surface
    /// a failure instead of reporting a change that is only in memory.
    pub async fn persist_access(&self) -> bool {
        let _guard = self.persist_access_lock.lock().await;
        let access = self.access.read().await.clone();
        let deny = access.blocked_pubkeys.clone();
        let allow = access.allowed_pubkeys.clone();
        let saved = self.db.save_access(access).await;
        // The pubkey lists are excluded from the `access` blob: keep them
        // in their own LMDB key so the CLI and NIP-86 share one source.
        let lists_saved = self.db.save_relay_pubkeys(&deny, &allow).await;
        saved && lists_saved
    }

    /// Reloads the database-owned access state (Blossom upload allowlist,
    /// relay pubkey deny/allow lists) at SIGHUP. A failed or timed-out
    /// load keeps the previous lists: overwriting them with an empty
    /// result would silently lift every ban (fail-open).
    ///
    /// The reload reads and applies each list under the same lock its
    /// writer uses (`persist_access_lock` / `persist_blossom_allow_lock`):
    /// without it a NIP-86 ban or `/blossom allow` that commits between the
    /// read and the in-memory apply would be overwritten by the older
    /// snapshot (the ban silently disappearing until the next restart).
    pub async fn reload_db_state(&self) {
        {
            let _guard = self.persist_blossom_allow_lock.lock().await;
            match self.db.try_load_blossom_allow().await {
                Some(list) => {
                    *self.blossom_allow.write().await = list;
                    log::info!("Blossom upload allowlist reloaded from the database");
                }
                None => {
                    log::warn!("Blossom upload allowlist reload failed; keeping the previous list")
                }
            }
        }
        // Read the config *before* taking the access write lock: the
        // accept paths hold `config.read` while awaiting `access.read`, so
        // acquiring `access.write` first and then awaiting `config.read`
        // would set up a lock cycle (this method holding the write lock
        // awaiting `config.read`, an accept holding `config.read` awaiting
        // `access.read`).
        let restrict_relay = self.config.read().await.access.restrict_relay;
        {
            let _guard = self.persist_access_lock.lock().await;
            match self.db.try_load_relay_pubkeys().await {
                Some((deny, allow)) => {
                    let mut access = self.access.write().await;
                    access.blocked_pubkeys = deny;
                    access.allowed_pubkeys = allow;
                    access.restrict_relay = restrict_relay;
                    log::info!("relay pubkey access lists reloaded from the database");
                }
                None => {
                    log::warn!(
                        "relay pubkey access lists reload failed; keeping the previous lists"
                    )
                }
            }
        }
    }

    pub fn has_relay_key(&self) -> bool {
        self.key.is_some()
    }

    /// Notifies every connection that the blocked-IP list changed, so each
    /// re-checks its source IP (and closes when it is now blocked).
    pub fn note_ip_blocks_changed(&self) {
        self.ip_blocks_tx.send_modify(|version| {
            *version = version.wrapping_add(1);
        });
    }

    /// Persists a runtime change of one `[relay]` config field (e.g. the
    /// NIP-86 `changerelayname`/`changerelaydescription`/`changerelayicon`
    /// methods) to the config file, preserving comments and unrelated
    /// lines. A failure only warns: the change stays applied in memory
    /// until the next config reload.
    pub async fn persist_relay_field(&self, field: &str, value: &str) {
        let Some(path) = self.config_path.read().await.clone() else {
            log::warn!(
                "cannot persist relay.{field}: the config file path is unknown \
                 (running without a config file?); the change applies until the \
                 next config reload"
            );
            return;
        };
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                let updated = crate::config::set_relay_field_in_text(&text, field, value);
                if let Err(e) = crate::config::write_text_atomic(&path, &updated) {
                    log::warn!(
                        "cannot persist relay.{field} to {}: {e}; the change applies \
                         until the next config reload",
                        path.display()
                    );
                }
            }
            Err(e) => {
                log::warn!(
                    "cannot read {} to persist relay.{field}: {e}",
                    path.display()
                );
            }
        }
    }

    /// Validates and stores a single event. The live path batches events
    /// through [`Self::accept_events_batch`], which falls back to this
    /// method for batches containing group-state events. Test-only: the
    /// accept paths call [`Self::accept_event_verified`] directly.
    #[cfg(test)]
    pub async fn accept_event(
        &self,
        event: Event,
        authed: &[String],
        known_prefixes: Option<&std::collections::HashSet<Vec<u8>>>,
    ) -> PutOutcome {
        self.accept_event_verified(event, authed, known_prefixes, None)
            .await
    }

    /// Like [`Self::accept_event`], but accepts a precomputed signature
    /// verdict (the mixed-batch path verifies a whole batch in parallel and
    /// hands the verdicts to the sequential events instead of re-checking
    /// each signature inline).
    async fn accept_event_verified(
        &self,
        event: Event,
        authed: &[String],
        known_prefixes: Option<&std::collections::HashSet<Vec<u8>>>,
        verified: Option<bool>,
    ) -> PutOutcome {
        let now = unix_now();
        let cfg = self.config.read().await;
        let access = self.access.read().await;

        match self
            .precheck(&cfg, &access, &event, now, authed, known_prefixes, verified)
            .await
        {
            crate::relay::validate::Precheck::Reject(reason) => {
                self.stats.bump(&self.stats.events_rejected, 1);
                return PutOutcome::Invalid(reason);
            }
            crate::relay::validate::Precheck::Duplicate(msg) => {
                self.stats.bump(&self.stats.events_duplicate, 1);
                return PutOutcome::Duplicate(msg);
            }
            crate::relay::validate::Precheck::Vanish => {
                // NIP-62: delete everything by this pubkey and never
                // accept anything from it again. The access/rate/first-seen
                // gates are intentionally bypassed here: the spec requires
                // the request to be honored "regardless of the user's
                // status". A replay cannot be used as a DoS amplifier
                // because the database records the furthest honored
                // `until_created` and covered requests become a no-op
                // (and the group/role snapshots are only rewritten when a
                // membership actually changed). The rejection is permanent
                // for the pubkey, including events created after
                // `until_created` (see the module docs): a vanished key
                // must not be able to resume publishing here.
                let Some(pubkey) = event.pubkey_bytes() else {
                    return PutOutcome::Invalid("invalid: bad pubkey".into());
                };
                // `vanish_pubkey` re-reads the config: release this guard
                // first. Holding a read guard across that second read would
                // deadlock against a queued config writer (SIGHUP reload,
                // NIP-86 command), freezing every later config read.
                drop(cfg);
                drop(access);
                self.vanish_pubkey(pubkey, event.created_at).await;
                // A vanish request is accepted like any other event (the
                // OK:true is sent): count it so the accepted/rejected
                // accounting stays consistent with the OKs.
                self.stats.bump(&self.stats.events_accepted, 1);
                return PutOutcome::Stored;
            }
            crate::relay::validate::Precheck::Accept => {}
        }

        // First-seen trust check: a pubkey's first accepted event records
        // its arrival; events from pubkeys first seen within the configured
        // window are rejected (spam from freshly created accounts). The
        // lookup is read-only here — the first-seen timestamp is only
        // persisted once an event actually stores, so a rejected first event
        // (expired/duplicate/invalid) cannot pre-warm the account-age clock.
        let mut persist_first_seen = false;
        if cfg.relay.new_pubkey_min_age_secs > 0
            && let Some(pubkey) = event.pubkey_bytes()
        {
            let first_seens = self.db.first_seen_batch(vec![pubkey]).await;
            let Some(&(created, first_seen)) = first_seens.first() else {
                // The database is unavailable or overloaded: fail closed.
                self.stats.bump(&self.stats.events_rejected, 1);
                return PutOutcome::Invalid("error: database unavailable".into());
            };
            persist_first_seen = created;
            if !created && now.saturating_sub(first_seen) < cfg.relay.new_pubkey_min_age_secs {
                self.stats.bump(&self.stats.events_rejected, 1);
                return PutOutcome::Invalid("restricted: your account is too new".into());
            }
        }

        if !self.publish_rate_allowed(&cfg, &event.pubkey, now) {
            self.stats.bump(&self.stats.events_rejected, 1);
            return PutOutcome::Invalid("rate-limited: too many events".into());
        }
        // The first-seen reservation rides along with the put: applied in
        // the same write transaction (one commit/fsync) only when the event
        // actually stores.
        let first_seen = if persist_first_seen {
            event.pubkey_bytes().map(|pubkey| (pubkey, now))
        } else {
            None
        };
        // One allocation shared by the database write and the live
        // broadcast: the event content is never deep-copied on this path.
        let event = Arc::new(event);
        let outcome = self
            .db
            .put_with_first_seen(Arc::clone(&event), now, first_seen)
            .await;
        let (nip9, nip43, nip29_enabled) =
            (cfg.nip_enabled(9), cfg.nip_enabled(43), cfg.nip_enabled(29));
        drop(access);

        let accepted = matches!(
            outcome,
            PutOutcome::Stored | PutOutcome::Replaced | PutOutcome::Ephemeral
        );
        if !accepted {
            self.publish_rate_rollback(&event.pubkey, now);
        }
        drop(cfg);
        match outcome {
            PutOutcome::Stored | PutOutcome::Replaced | PutOutcome::Ephemeral => {
                if !self.after_put(event, now, nip9, nip43, nip29_enabled).await {
                    log::error!("event persisted but live delivery failed");
                }
                self.stats.bump(&self.stats.events_accepted, 1);
                outcome
            }
            PutOutcome::Duplicate(_) => {
                self.stats.bump(&self.stats.events_duplicate, 1);
                outcome
            }
            other => {
                self.stats.bump(&self.stats.events_rejected, 1);
                other
            }
        }
    }

    /// Accepts a batch of events from one connection, returning the outcome
    /// of each. The database layer commits the whole batch in a single write
    /// transaction, so the commit cost is paid once per batch instead of
    /// once per event. Ordering and per-event replies are preserved.
    pub async fn accept_events_batch(
        &self,
        events: Vec<Event>,
        authed: &[String],
    ) -> Vec<(String, PutOutcome)> {
        let batch = self.accept_batch_begin(events, authed).await;
        batch.finish(self).await
    }

    /// Phase 1 of [`Self::accept_events_batch`]: the per-event checks and
    /// the writer queueing. The write is *queued* (not awaited), so the
    /// caller can keep reading frames while the writer commits; the
    /// outcomes arrive through [`PendingBatch::finish`]. Batches containing
    /// state-mutating events are split into stateless runs (committed as
    /// batches) and sequential singletons, resolved before returning.
    pub(crate) async fn accept_batch_begin(
        &self,
        events: Vec<Event>,
        authed: &[String],
    ) -> PendingBatch {
        // Events with post-commit state effects must be applied before the
        // later events of the batch are prechecked (e.g. a put-user
        // followed by the new member's post), so they split the batch. The
        // common group traffic — `h`-tagged chat messages — has no such
        // effects and keeps the batched fast path instead of forcing the
        // whole batch through per-event commits.
        if events.iter().any(|e| self.has_state_effects(e)) {
            return self.accept_batch_mixed(events, authed).await;
        }
        // The fast path needs the same prefetched `previous` references as
        // the mixed path: without them the precheck issues one database
        // round trip per reference (unbounded amplification) and rejects
        // sibling references it cannot resolve yet.
        let known = self.batch_known_prefixes(&events).await;
        self.accept_batch_non_group(events, authed, Some(&known), None)
            .await
    }

    /// The batch's pre-resolved `previous` tag references plus every
    /// sibling event id prefix, collected in one database round trip. The
    /// precheck must not issue one lookup per reference (a single event can
    /// carry thousands) and must accept references to sibling events that
    /// are not committed yet.
    async fn batch_known_prefixes(&self, events: &[Event]) -> std::collections::HashSet<Vec<u8>> {
        // Dedup with a set so that a batch full of distinct `previous` tags
        // (up to max_tags per event) cannot turn the dedup itself quadratic.
        // The collection is additionally capped: without a bound a single
        // batch (EVENT_BATCH * 32 events x max_tags references) could pin
        // megabytes of prefixes and force millions of LMDB range probes
        // inside one read transaction, stalling the reader. References past
        // the cap are treated as unknown, so the affected events fail closed
        // instead of stalling the relay.
        const MAX_PREVIOUS_PREFIXES: usize = 1024;
        let mut prefixes: Vec<Vec<u8>> = Vec::new();
        let mut seen_prefixes: std::collections::HashSet<Vec<u8>> =
            std::collections::HashSet::new();
        let mut previous_capped = false;
        'collect: for event in events {
            for prefix in nip29::previous_tags(event) {
                if prefixes.len() >= MAX_PREVIOUS_PREFIXES {
                    previous_capped = true;
                    break 'collect;
                }
                let Ok(prefix) = hex::decode(&prefix) else {
                    continue;
                };
                if !prefix.is_empty() && seen_prefixes.insert(prefix.clone()) {
                    prefixes.push(prefix);
                }
            }
        }
        if previous_capped {
            log::warn!(
                "capped previous-tag references at {MAX_PREVIOUS_PREFIXES} for a batch of {} events",
                events.len()
            );
        }
        let mut known: std::collections::HashSet<Vec<u8>> = if prefixes.is_empty() {
            std::collections::HashSet::new()
        } else {
            let existing = self.db.prefixes_exist(prefixes.clone()).await;
            prefixes
                .into_iter()
                .zip(existing)
                .filter_map(|(p, exists)| exists.then_some(p))
                .collect()
        };
        // References to sibling events of the same batch are valid: an
        // earlier event of the batch is a legitimate `previous` target even
        // though it is not committed to the database yet.
        for event in events {
            if let Ok(id_bytes) = hex::decode(&event.id) {
                for len in 1..=id_bytes.len() {
                    known.insert(id_bytes[..len].to_vec());
                }
            }
        }
        known
    }

    /// Whether accepting `event` has post-commit effects that later events
    /// of the same batch must observe before their own prechecks: NIP-29
    /// group state and NIP-43 role mutations, NIP-62 vanish requests and
    /// relay command events (kind:1 signed by the relay's own key, which
    /// can change the running config).
    fn has_state_effects(&self, event: &Event) -> bool {
        (nip29::MOD_MIN..=nip29::MOD_MAX).contains(&event.kind)
            || event.kind == nip29::JOIN
            || event.kind == nip29::LEAVE
            || event.kind == nip43::LEAVE
            || nip62::is_vanish(event)
            || (event.kind == 1 && self.relay_pubkey.as_deref() == Some(event.pubkey.as_str()))
    }

    /// Hybrid path for a batch containing state-mutating events: maximal
    /// runs of stateless events are committed as batches, the mutating
    /// events are processed one at a time in order. The signature
    /// verification of the whole batch runs once, in parallel, and both
    /// paths reuse the verdicts.
    async fn accept_batch_mixed(&self, events: Vec<Event>, authed: &[String]) -> PendingBatch {
        let known = self.batch_known_prefixes(&events).await;
        // One parallel pass for the whole batch: the sequential singletons
        // below must not re-verify each signature inline.
        let verified = crate::relay::validate::verify_signatures_parallel(&events, self.secp());
        let mut out: Vec<(String, PutOutcome)> = Vec::with_capacity(events.len());
        let mut run: Vec<Event> = Vec::new();
        let mut run_verdicts: Vec<bool> = Vec::new();
        for (index, event) in events.into_iter().enumerate() {
            if self.has_state_effects(&event) {
                if !run.is_empty() {
                    let resolved = self
                        .accept_batch_non_group(
                            std::mem::take(&mut run),
                            authed,
                            Some(&known),
                            Some(&run_verdicts),
                        )
                        .await
                        .finish(self)
                        .await;
                    out.extend(resolved);
                    run_verdicts.clear();
                }
                let id = event.id.clone();
                let outcome = self
                    .accept_event_verified(event, authed, Some(&known), Some(verified[index]))
                    .await;
                out.push((id, outcome));
            } else {
                run_verdicts.push(verified[index]);
                run.push(event);
            }
        }
        if !run.is_empty() {
            let resolved = self
                .accept_batch_non_group(run, authed, Some(&known), Some(&run_verdicts))
                .await
                .finish(self)
                .await;
            out.extend(resolved);
        }
        PendingBatch {
            receiver: None,
            resolved: Some(out),
            results: Vec::new(),
            put_slots: Vec::new(),
            puts: Vec::new(),
            new_pubkeys: Vec::new(),
            vanishes: Vec::new(),
            now: 0,
            nip9: false,
            nip43: false,
            nip29: false,
        }
    }

    /// The batched fast path: the per-event checks run in order and the
    /// writes are merged into one transaction. `known_prefixes` supplies
    /// the batch's pre-fetched `previous` references (None = per-reference
    /// database lookups); `verified` supplies precomputed signature
    /// verdicts (None = verify the batch in parallel here).
    async fn accept_batch_non_group(
        &self,
        events: Vec<Event>,
        authed: &[String],
        known_prefixes: Option<&std::collections::HashSet<Vec<u8>>>,
        verified: Option<&[bool]>,
    ) -> PendingBatch {
        let now = unix_now();
        let cfg = self.config.read().await;
        let access = self.access.read().await;
        let mut results: Vec<(String, PutOutcome)> = Vec::with_capacity(events.len());
        let mut puts: Vec<Arc<Event>> = Vec::new();
        let mut put_slots: Vec<usize> = Vec::new();
        // (slot, id, event) of the vanish requests, resolved at the end so
        // the OK replies keep the order of the received batch.
        let mut vanishes: Vec<(usize, String, Event)> = Vec::new();

        // The Schnorr signature check dominates the per-event accept cost
        // (tens of microseconds), so a large batch verifies every signature
        // in parallel across the machine's cores and the sequential loop
        // below reuses the verdicts. `validate_base` runs its cheap checks
        // before consulting a verdict, so the reject reasons are identical
        // to the inline-verify path.
        let computed;
        let verified: &[bool] = match verified {
            Some(verdicts) => verdicts,
            None => {
                computed = crate::relay::validate::verify_signatures_parallel(&events, self.secp());
                &computed
            }
        };
        for event in events {
            let id = event.id.clone();
            let verified = verified.get(results.len()).copied();
            match self
                .precheck(&cfg, &access, &event, now, authed, known_prefixes, verified)
                .await
            {
                crate::relay::validate::Precheck::Reject(reason) => {
                    self.stats.bump(&self.stats.events_rejected, 1);
                    results.push((id, PutOutcome::Invalid(reason)));
                    continue;
                }
                crate::relay::validate::Precheck::Vanish => {
                    vanishes.push((results.len(), id, event));
                    results.push((String::new(), PutOutcome::Invalid(String::new())));
                    continue;
                }
                crate::relay::validate::Precheck::Duplicate(msg) => {
                    self.stats.bump(&self.stats.events_duplicate, 1);
                    results.push((id, PutOutcome::Duplicate(msg)));
                    continue;
                }
                crate::relay::validate::Precheck::Accept => {}
            }
            put_slots.push(results.len());
            results.push((String::new(), PutOutcome::Invalid(String::new())));
            puts.push(Arc::new(event));
        }

        let groups_enabled = cfg.nip_enabled(29);
        let roles_enabled = cfg.nip_enabled(43);
        let nip9_enabled = cfg.nip_enabled(9);
        let min_age = cfg.relay.new_pubkey_min_age_secs;
        let rate_limit = cfg.relay.max_events_per_min_per_pubkey;
        drop(access);

        // First-seen trust check: pubkeys first seen within the configured
        // window may not publish (their first event established the
        // account). Performed in one database round trip for the batch. The
        // lookup is read-only; first-seen is only persisted for events that
        // actually store, so a failed first event cannot pre-warm the clock.
        let mut new_pubkeys: Vec<bool> = Vec::new();
        if min_age > 0 && !puts.is_empty() {
            let pubkeys: Vec<[u8; 32]> = puts
                .iter()
                .map(|e| e.pubkey_bytes().unwrap_or([0u8; 32]))
                .collect();
            let first_seens = self.db.first_seen_batch(pubkeys).await;
            if first_seens.len() != puts.len() {
                // The database is unavailable or overloaded: every pending
                // event of the batch fails closed.
                for (event, slot) in puts.into_iter().zip(put_slots) {
                    self.stats.bump(&self.stats.events_rejected, 1);
                    results[slot] = (
                        event.id.clone(),
                        PutOutcome::Invalid("error: database unavailable".into()),
                    );
                }
                puts = Vec::new();
                put_slots = Vec::new();
            } else {
                let mut kept = Vec::with_capacity(puts.len());
                let mut kept_slots = Vec::with_capacity(put_slots.len());
                let mut kept_new = Vec::with_capacity(puts.len());
                for ((event, slot), (created, first_seen)) in
                    puts.into_iter().zip(put_slots).zip(first_seens)
                {
                    if !created && now.saturating_sub(first_seen) < min_age {
                        self.stats.bump(&self.stats.events_rejected, 1);
                        results[slot] = (
                            event.id.clone(),
                            PutOutcome::Invalid("restricted: your account is too new".into()),
                        );
                    } else {
                        kept_new.push(created);
                        kept.push(event);
                        kept_slots.push(slot);
                    }
                }
                puts = kept;
                put_slots = kept_slots;
                new_pubkeys = kept_new;
            }
        }

        if rate_limit > 0 && !puts.is_empty() {
            let mut kept = Vec::with_capacity(puts.len());
            let mut kept_slots = Vec::with_capacity(put_slots.len());
            let mut kept_new = Vec::with_capacity(new_pubkeys.len());
            let new_flags = if new_pubkeys.is_empty() {
                vec![false; puts.len()]
            } else {
                new_pubkeys
            };
            for ((event, slot), is_new) in puts.into_iter().zip(put_slots).zip(new_flags) {
                if self.publish_rate_allowed(&cfg, &event.pubkey, now) {
                    kept.push(event);
                    kept_slots.push(slot);
                    kept_new.push(is_new);
                } else {
                    self.stats.bump(&self.stats.events_rejected, 1);
                    results[slot] = (
                        event.id.clone(),
                        PutOutcome::Invalid("rate-limited: too many events".into()),
                    );
                }
            }
            puts = kept;
            put_slots = kept_slots;
            new_pubkeys = kept_new;
        }
        let receiver = if puts.is_empty() {
            None
        } else {
            self.db
                .put_batch_deferred(puts.iter().map(|e| (Arc::clone(e), now)).collect())
        };
        drop(cfg);

        PendingBatch {
            receiver,
            resolved: None,
            results,
            put_slots,
            puts,
            new_pubkeys,
            vanishes,
            now,
            nip9: nip9_enabled,
            nip43: roles_enabled,
            nip29: groups_enabled,
        }
    }

    async fn after_put(
        &self,
        event: Arc<Event>,
        now: u64,
        nip9: bool,
        nip43: bool,
        nip29_enabled: bool,
    ) -> bool {
        if nip9 && event.kind == nip09::DELETION_KIND {
            // NIP-29/NIP-43: a deletion that removes state events
            // (moderation, join/leave, role state) invalidates the derived
            // state, exactly like a vanish. The targets are gone once the
            // deletion applies, so the relevance check must run first; a
            // failed lookup fails closed (the rebuild runs even if the
            // targets turn out unrelated). Deleting ordinary posts does not
            // touch the derived state and takes no rebuild.
            let touches_group_state =
                (nip29_enabled || nip43) && self.deletion_touches_group_state(&event).await;
            match self
                .db
                .apply_deletion_checked(
                    nip09::deletion_targets(&event),
                    nip09::deletion_addresses(&event),
                    Some(event.pubkey.clone()),
                    event.created_at,
                )
                .await
            {
                Some(removed) => {
                    self.stats.bump(&self.stats.events_deleted, removed as u64);
                    if touches_group_state && removed > 0 {
                        // The live state still holds state derived from the
                        // deleted events: mark it stale and let the
                        // coalesced background worker rebuild.
                        self.mark_group_state_stale().await;
                    }
                }
                None => {
                    // The deletion event stored but its side effect was
                    // dropped (writer overload): make it visible instead of
                    // reporting a silent success.
                    log::error!("NIP-09 deletion side effect was not applied");
                    self.stats.bump(&self.stats.db_errors, 1);
                }
            }
            // NIP-59: gift wraps are signed by random keys, so their
            // recipient cannot delete them via NIP-09; the relay
            // deletes wraps addressed to the deleter instead.
            if let Some(pubkey) = event.pubkey_bytes() {
                match self.db.delete_gift_wraps_to_checked(pubkey).await {
                    Some(purged) => self.stats.bump(&self.stats.events_deleted, purged as u64),
                    None => {
                        log::error!("NIP-59 gift-wrap purge was not applied");
                        self.stats.bump(&self.stats.db_errors, 1);
                    }
                }
            }
        }
        if nip43 && event.kind == nip43::LEAVE {
            // NIP-43: leave requests (ephemeral kinds) update the member
            // list without being stored.
            self.apply_leave_request(&event).await;
        }
        let is_group_event = nip29_enabled
            && ((nip29::MOD_MIN..=nip29::MOD_MAX).contains(&event.kind)
                || event.kind == nip29::JOIN
                || event.kind == nip29::LEAVE);
        if is_group_event {
            self.apply_group_event(&event, now).await;
        }
        // Command events: with `relay.enabled_command_events` a kind:1
        // event authored by the relay's own pubkey carries an operator
        // command; it is executed here (after storage, like the other
        // side effects) and answered with a relay-signed kind:1111 event.
        if event.kind == 1 {
            self.handle_command_event(&event).await;
        }
        self.broadcast(event).await.is_ok()
    }

    /// Persists the live NIP-29 group state (write-through: call after
    /// every mutation so restarts restore without replaying history).
    /// Fire-and-forget: a failed commit only logs (the next mutation
    /// retries the full snapshot).
    ///
    /// Stale state is never persisted: while a post-vanish/NIP-09/expiry
    /// rebuild is pending the snapshot is dropped instead, so the next
    /// startup rebuilds from the surviving events rather than restoring
    /// state that predates the removals. The snapshot and the write are
    /// serialized (`GroupsRebuild::persist_lock`) so an older snapshot
    /// cannot land after a newer one.
    ///
    /// Returns whether the intended write committed. A `false` leaves the
    /// caller responsible for keeping the state pending (fail-closed): the
    /// stale snapshot may still be on disk, and the fresh one is not
    /// durable.
    pub(crate) async fn persist_groups(&self) -> bool {
        self.groups_rebuild.persist(&self.db, &self.groups).await
    }

    /// Persists the live NIP-43 role state (same lifecycle as
    /// [`Self::persist_groups`]). The lock keeps a stale snapshot from
    /// overwriting a newer one: two concurrent mutations could otherwise
    /// capture snapshots in one order and queue their writes in the other.
    /// Returns whether the write committed.
    pub(crate) async fn persist_roles(&self) -> bool {
        let _guard = self.persist_roles_lock.lock().await;
        let snapshot = self.roles.read().await.snapshot();
        self.db.save_roles(snapshot).await
    }

    /// Whether `event` may remove events the NIP-29/NIP-43 derived state is
    /// built from (moderation, join/leave and role state kinds). `a`-tag
    /// addresses carry their kind directly; `e`-tag targets are looked up in
    /// the database because the deletion removes them. A failed lookup fails
    /// closed: the state is rebuilt even if the targets turn out unrelated.
    async fn deletion_touches_group_state(&self, event: &Event) -> bool {
        fn is_state_kind(kind: u64) -> bool {
            (nip29::MOD_MIN..=nip29::MOD_MAX).contains(&kind)
                || kind == nip29::JOIN
                || kind == nip29::LEAVE
                || matches!(
                    kind,
                    nip43::ROLE_DEFINITION
                        | nip43::MEMBERSHIP_LIST
                        | nip43::ADD_USER
                        | nip43::REMOVE_USER
                        | nip43::JOIN
                        | nip43::LEAVE
                )
        }
        if nip09::deletion_addresses(event)
            .iter()
            .any(|address| is_state_kind(address.kind))
        {
            return true;
        }
        let targets = nip09::deletion_targets(event);
        if targets.is_empty() {
            return false;
        }
        let mut kinds: Vec<u64> = (nip29::MOD_MIN..=nip29::MOD_MAX)
            .chain([nip29::JOIN, nip29::LEAVE])
            .collect();
        kinds.extend([
            nip43::ROLE_DEFINITION,
            nip43::MEMBERSHIP_LIST,
            nip43::ADD_USER,
            nip43::REMOVE_USER,
            nip43::JOIN,
            nip43::LEAVE,
        ]);
        let filter = crate::filter::Filter {
            ids: Some(targets),
            kinds: Some(kinds),
            ..Default::default()
        };
        match self
            .db
            .query_full_startup(vec![filter], 1, unix_now(), false)
            .await
        {
            Some((events, _)) => !events.is_empty(),
            // The database did not answer: assume the deletion matters.
            None => true,
        }
    }

    /// Marks the in-memory group state as stale after events it derives
    /// from were removed (NIP-62 vanish, NIP-09 deletion, NIP-40 expiry)
    /// and schedules the coalesced background rebuild. The persisted
    /// snapshot is dropped immediately: it predates the removals, so a
    /// crash before the rebuild completes must not restore it. The accept
    /// path never blocks on the rebuild scan (see `groups_rebuild_worker`).
    pub(crate) async fn mark_group_state_stale(&self) {
        self.groups_rebuild.dirty.store(true, Ordering::SeqCst);
        self.groups_rebuild.pending.store(true, Ordering::SeqCst);
        self.persist_groups().await;
        schedule_groups_rebuild(
            self.db.clone(),
            Arc::clone(&self.groups),
            Arc::clone(&self.config),
            Arc::clone(&self.groups_rebuild),
        );
    }

    /// Whether a `kind:9008` group purge committed. The purge API reports a
    /// failure as zero removed (indistinguishable from "nothing to purge"),
    /// so the id is confirmed clean only when no stored `h`-tagged event
    /// remains. A failed or truncated query fails closed: the id stays
    /// ghosted rather than becoming re-creatable with its history intact.
    async fn group_purge_confirmed(&self, gid: &str) -> bool {
        let filter: crate::filter::Filter =
            serde_json::from_value(serde_json::json!({ "#h": [gid] })).expect("static filter");
        match self
            .db
            .query_full_startup(vec![filter], 1, unix_now(), false)
            .await
        {
            Some((events, more)) => !more && events.is_empty(),
            None => false,
        }
    }

    /// NIP-62: deletes every event by `pubkey` and relinks the NIP-29 group
    /// state to the surviving events.
    ///
    /// When the vanish actually removed events, the group state is rebuilt
    /// from what survives: moderation events authored by the vanished key
    /// (settings edits, invites, pins, parent links, create/delete) are gone
    /// from the database, so their derived state must go too, and a group
    /// whose create event was deleted becomes a ghost (content withheld)
    /// instead of turning world-readable. The rebuild runs in the coalesced
    /// background worker (see [`Self::mark_group_state_stale`]): repeated
    /// vanishes do not each pay for a full-history scan. The scan runs
    /// without the group lock; group events accepted meanwhile apply to the
    /// live store and are buffered for replay onto the rebuilt store, and
    /// the persisted snapshot is dropped (fail-closed) until it completes,
    /// so a crash in between rebuilds on the next startup instead of
    /// restoring the stale state.
    async fn vanish_pubkey(&self, pubkey: [u8; 32], until_created: u64) {
        let pubkey_hex = hex::encode(pubkey);
        let (removed, group_state_removed) =
            match self.db.apply_vanish_checked(pubkey, until_created).await {
                Some(outcome) => outcome,
                None => {
                    // The vanish was accepted (OK) but its side effect was
                    // dropped: the marker is not stored, so the pubkey would
                    // come back. Surface the failure in the logs and metrics.
                    log::error!("NIP-62 vanish side effect was not applied");
                    self.stats.bump(&self.stats.db_errors, 1);
                    return;
                }
            };
        self.stats.bump(&self.stats.events_deleted, removed as u64);
        if self.config.read().await.nip_enabled(29) {
            if group_state_removed {
                // A moderation/join/leave event was removed: the derived
                // state (settings, pins, members, invites) must be rebuilt
                // from the surviving history. The rebuild is a full-history
                // scan and vanishes are exempt from the publish rate limit,
                // so any fresh keypair could otherwise stall every group
                // write on the group lock; mark the state stale and let the
                // coalesced background worker rebuild instead (the snapshot
                // is dropped fail-closed until it completes).
                self.mark_group_state_stale().await;
            } else {
                // A replayed vanish, one that removed nothing, or one that
                // only deleted ordinary posts: the live state only needs the
                // vanished pubkey dropped from its memberships, and only a
                // real change is worth a snapshot write. The removal is not
                // reconstructible from the database (an admin's surviving
                // 9000 may re-add the pubkey after the scan's vanished-set
                // snapshot), so an in-flight rebuild discards its scan.
                let changed = {
                    let mut buffer = self.groups_rebuild.buffer.lock().await;
                    if buffer.scanning {
                        buffer.retry = true;
                    }
                    let mut groups = self.groups.write().await;
                    groups.remove_member_everywhere(&pubkey_hex)
                };
                if changed && !self.persist_groups().await {
                    log::error!(
                        "could not persist the group state after a vanish; it will be \
                         rebuilt on the next restart"
                    );
                }
            }
        }
        // NIP-43 role assignments hold pubkeys too: a vanished author
        // must not keep its roles.
        if self.config.read().await.nip_enabled(43) {
            let changed = {
                let mut roles = self.roles.write().await;
                roles.assignments.remove(&pubkey_hex).is_some()
            };
            if changed {
                self.persist_roles().await;
            }
        }
    }

    /// Captures a group event for replay while a rebuild scan runs, then
    /// applies it to the live store under the same buffer lock: the capture
    /// and the live apply are one step against the worker's take-and-swap,
    /// so an event can never fall between the two (it is either replayed
    /// onto the fresh store or applied to the swapped-in one). A `9008` is
    /// not buffered — its ghost/tombstone/purge outcome is not
    /// reconstructible from the database — so it forces the worker to
    /// discard the scan and rebuild instead.
    async fn apply_group_state(&self, event: &Event, now: u64) -> Vec<Event> {
        let relay_pubkey = self.relay_pubkey().unwrap_or_default();
        // Relay-generated events are stamped with the strictly monotonic
        // clock (not plain `now`): two events applied in the same second
        // must still be distinguishable, or the NIP-01 id tie-break could
        // let a stale, later-committed version win. The floor is clamped
        // to `now`: a group event may carry a future created_at (allowed
        // up to max_created_at_future_secs), and stamping the metadata in
        // the future would make it invisible to `until: now` scans and,
        // after a restart, unreplaceable until the wall clock catches up.
        let stamp = self.stamp_floor(now);
        let mut buffer = self.groups_rebuild.buffer.lock().await;
        if buffer.scanning {
            if event.kind == nip29::DELETE_GROUP {
                buffer.retry = true;
            } else if buffer.events.len() >= GROUPS_REBUILD_BUFFER_MAX {
                buffer.overflow = true;
            } else {
                buffer.events.push(BufferedGroupEvent {
                    event: Arc::new(event.clone()),
                    now,
                });
            }
        }
        self.groups
            .write()
            .await
            .apply(event, &relay_pubkey, stamp, self.has_relay_key(), false)
    }

    /// Marks a `9008` id as a ghost on the live store, before the delete is
    /// applied and persisted (see [`Self::apply_group_event`]). An
    /// in-flight rebuild scan is discarded: a scan that predates the delete
    /// could reconstruct the group and lose the fail-closed marker.
    async fn ghost_deleted_group(&self, gid: &str) {
        let mut buffer = self.groups_rebuild.buffer.lock().await;
        if buffer.scanning {
            buffer.retry = true;
        }
        self.groups.write().await.mark_ghost(gid);
    }

    /// Clears a `9008` ghost after its purge was confirmed. An in-flight
    /// rebuild scan is discarded: it captured the pre-purge state and would
    /// re-ghost the id from its seed.
    async fn unghost_confirmed(&self, gid: &str) {
        let mut buffer = self.groups_rebuild.buffer.lock().await;
        if buffer.scanning {
            buffer.retry = true;
        }
        self.groups.write().await.unghost(gid);
    }

    /// Applies a stored NIP-29 event to the group state and publishes the
    /// relay-generated metadata events.
    async fn apply_group_event(&self, event: &Event, now: u64) {
        // A `kind:9008` purge may fail (or the process may crash before it
        // commits). The delete tombstone alone would let a later create
        // clear it and expose the un-purged history, so the id is ghosted
        // *before* the delete is applied and persisted: the persisted
        // snapshot stays fail-closed even if the purge never completes. The
        // ghost is downgraded to the ordinary tombstone only after the purge
        // is confirmed (below).
        if event.kind == nip29::DELETE_GROUP
            && let Some(gid) = nip29::group_id(event)
        {
            self.ghost_deleted_group(gid).await;
            if !self.persist_groups().await {
                log::error!(
                    "could not persist the pre-delete group ghost for {gid}; the in-memory \
                     state stays fail-closed"
                );
            }
        }
        let generated = self.apply_group_state(event, now).await;
        // Write-through persistence: restarts restore from the snapshot
        // instead of replaying history.
        if !self.persist_groups().await {
            log::error!("could not persist the group state");
        }

        if event.kind == 9005 {
            // Group moderation delete-event: admins may delete events, but
            // only within their own group — an admin of one group must not
            // be able to delete another group's content (or the relay's
            // metadata) by referencing its id.
            if let Some(gid) = nip29::group_id(event) {
                // The relevance check must run before the deletion removes
                // the targets. Like the NIP-09 path it fails closed (a
                // failed lookup assumes the deletion matters), and the
                // derived state is only rebuilt when a state-kind event was
                // actually removed.
                let touches_group_state = self.deletion_touches_group_state(event).await;
                match self
                    .db
                    .apply_group_deletion_checked(nip29::delete_targets(event), gid.to_string())
                    .await
                {
                    Some(removed) => {
                        self.stats.bump(&self.stats.events_deleted, removed as u64);
                        if touches_group_state && removed > 0 {
                            // Removing a moderation/join/leave event
                            // invalidates the in-memory state derived from
                            // it (a deleted 9000 grant must revoke the
                            // membership): mark it stale and let the
                            // coalesced worker rebuild.
                            self.mark_group_state_stale().await;
                        }
                    }
                    None => {
                        // The 9005 stored but its side effect was dropped
                        // (writer overload): make it visible instead of
                        // reporting a silent success (same OK semantics as
                        // the NIP-09 deletion path).
                        log::error!("NIP-29 9005 deletion side effect was not applied");
                        self.stats.bump(&self.stats.db_errors, 1);
                    }
                }
            }
        }

        if event.kind == nip29::DELETE_GROUP
            && let Some(gid) = nip29::group_id(event)
        {
            // NIP-29: purge the deleted group's stored events. A fresh
            // create on the same id installs a public group, which would
            // otherwise expose the old (possibly private) history. The
            // purge records a per-group cut in the database, so a later
            // re-broadcast of the purged history stays rejected. The purge
            // reports a failure as zero removed, so success is confirmed by
            // the state below: only then does the id return to the ordinary
            // delete tombstone (which a create may clear).
            let removed = self.db.group_purge(gid.to_string(), unix_now()).await;
            self.stats.bump(&self.stats.events_deleted, removed as u64);
            if self.group_purge_confirmed(gid).await {
                // The history is gone: the id may be re-created normally.
                self.unghost_confirmed(gid).await;
                if !self.persist_groups().await {
                    log::error!("could not persist the confirmed group purge for {gid}");
                }
            } else {
                log::error!(
                    "group purge for {gid} was not confirmed; keeping the id ghosted so a \
                     re-create cannot expose the un-purged history"
                );
            }
        }

        // One moderation event can generate several versions of the same
        // replaceable metadata slot (e.g. a parent loses two adopted
        // children in one 9002, rebuilding its 39000 after each removal).
        // They all share the single per-apply stamp, so the NIP-01 id
        // tie-break would keep one arbitrarily — retaining the stale
        // version when its id happens to be lower and dropping the
        // corrected one as a duplicate. Keep only the last build per `d`
        // slot: the emit order lists the group's final state last.
        let mut seen = std::collections::HashSet::new();
        let mut generated: Vec<Event> = generated
            .into_iter()
            .rev()
            .filter(|ev| {
                let d = ev
                    .tags
                    .iter()
                    .find(|t| t.len() >= 2 && t[0] == "d")
                    .map(|t| t[1].clone())
                    .unwrap_or_default();
                seen.insert((ev.kind, d))
            })
            .collect();
        generated.reverse();

        for mut ev in generated {
            let result = self.store_relay_event(&mut ev).await;
            if result.is_err() {
                // The in-memory group state moved on, but the stored
                // metadata did not: without this the saved 39000-39005
                // stay stale until the next edit (and the restart rebuild
                // replays the older moderation events). Surface it.
                log::warn!(
                    "could not store the relay-generated group event for {}",
                    ev.tags
                        .iter()
                        .find(|t| t.first().map(String::as_str) == Some("d"))
                        .and_then(|t| t.get(1))
                        .cloned()
                        .unwrap_or_default()
                );
            } else if matches!(result, Ok(false)) {
                log::warn!(
                    "stored the relay-generated group event but live delivery failed for {}",
                    ev.tags
                        .iter()
                        .find(|t| t.first().map(String::as_str) == Some("d"))
                        .and_then(|t| t.get(1))
                        .cloned()
                        .unwrap_or_default()
                );
            }
        }
    }
}

pub(crate) struct PendingBatch {
    receiver: Option<tokio::sync::oneshot::Receiver<Vec<PutOutcome>>>,
    resolved: Option<Vec<(String, PutOutcome)>>,
    results: Vec<(String, PutOutcome)>,
    put_slots: Vec<usize>,
    puts: Vec<Arc<Event>>,
    new_pubkeys: Vec<bool>,
    vanishes: Vec<(usize, String, Event)>,
    now: u64,
    nip9: bool,
    nip43: bool,
    nip29: bool,
}

impl PendingBatch {
    /// Phase 2 of [`Self::accept_events_batch`]: awaits the commit
    /// (for non-group batches) and applies the side effects
    /// (first-seen persistence, vanish resolution, NIP-09/29/43 and
    /// the live broadcast). Group batches were fully resolved in
    /// `begin` and return their results here.
    pub(crate) async fn finish(self, relay: &Relay) -> Vec<(String, PutOutcome)> {
        if let Some(resolved) = self.resolved {
            return resolved;
        }
        let mut results = self.results;
        let puts = self.puts;
        let put_slots = self.put_slots;
        let new_pubkeys = self.new_pubkeys;
        let vanishes = self.vanishes;
        let now = self.now;
        let nip9 = self.nip9;
        let nip43 = self.nip43;
        let nip29 = self.nip29;
        let Some(receiver) = self.receiver else {
            for (event, slot) in puts.into_iter().zip(put_slots) {
                relay.publish_rate_rollback(&event.pubkey, now);
                relay.stats.bump(&relay.stats.events_rejected, 1);
                results[slot] = (
                    event.id.clone(),
                    PutOutcome::Invalid("error: database overloaded".into()),
                );
            }
            // A batch that only carries vanish requests has no puts and
            // therefore no receiver: the vanish acknowledgements must be
            // resolved here all the same, or the placeholder replies
            // (empty id, `invalid:`) would leak to the client.
            for (slot, id, event) in vanishes {
                if let Some(pubkey) = event.pubkey_bytes() {
                    relay.vanish_pubkey(pubkey, event.created_at).await;
                }
                relay.stats.bump(&relay.stats.events_accepted, 1);
                results[slot] = (id, PutOutcome::Stored);
            }
            return results;
        };
        let mut outcomes = receiver.await.unwrap_or_default();
        if outcomes.len() != puts.len() {
            // The write was rejected before it was queued (overload
            // fail-fast): nothing will commit, so every pending event
            // is reported as failed instead of being replied with an
            // empty id.
            outcomes = vec![PutOutcome::Invalid("error: database overloaded".into()); puts.len()];
        }

        // Record the first-seen timestamp only for accounts whose first
        // event actually stored: a failed first event must not pre-warm
        // the account-age clock.
        let is_new_vec = if new_pubkeys.is_empty() {
            vec![false; puts.len()]
        } else {
            new_pubkeys
        };
        let mut persist_first_seen: Vec<[u8; 32]> = Vec::new();
        for (((event, outcome), slot), is_new) in puts
            .into_iter()
            .zip(outcomes)
            .zip(put_slots)
            .zip(is_new_vec)
        {
            let id = event.id.clone();
            let first_seen_pubkey = if is_new { event.pubkey_bytes() } else { None };
            match outcome {
                PutOutcome::Stored | PutOutcome::Replaced | PutOutcome::Ephemeral => {
                    if !relay.after_put(event, now, nip9, nip43, nip29).await {
                        log::error!("event persisted but live delivery failed");
                    }
                    if let Some(pk) = first_seen_pubkey {
                        persist_first_seen.push(pk);
                    }
                    relay.stats.bump(&relay.stats.events_accepted, 1);
                }
                PutOutcome::Duplicate(_) => {
                    relay.publish_rate_rollback(&event.pubkey, now);
                    relay.stats.bump(&relay.stats.events_duplicate, 1);
                }
                _ => {
                    relay.publish_rate_rollback(&event.pubkey, now);
                    relay.stats.bump(&relay.stats.events_rejected, 1);
                }
            }
            results[slot] = (id, outcome);
        }
        if !persist_first_seen.is_empty() {
            relay
                .db
                .touch_first_seen_batch(
                    persist_first_seen.into_iter().map(|pk| (pk, now)).collect(),
                )
                .await;
        }

        for (slot, id, event) in vanishes {
            if let Some(pubkey) = event.pubkey_bytes() {
                relay.vanish_pubkey(pubkey, event.created_at).await;
            }
            // Same accounting as the single-event path: a vanish is
            // accepted (its OK:true is sent) and counts as accepted.
            relay.stats.bump(&relay.stats.events_accepted, 1);
            results[slot] = (id, PutOutcome::Stored);
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::BufferedGroupEvent;
    use super::GROUPS_REBUILD_BUFFER_MAX;
    use super::LiveQueue;
    use super::Relay;
    use super::StampClock;
    use super::enqueue_live_batch;
    use super::signal_live_resync;
    use super::validate::contains_secret_key;

    /// Builds a relay with an empty database.
    async fn build_relay() -> std::sync::Arc<Relay> {
        build_relay_cfg(false).await
    }

    async fn build_relay_cfg(disable_fsync: bool) -> std::sync::Arc<Relay> {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join("nostrfy-relay-dbstate")
            .join(format!("{:x}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        let mut cfg = crate::config::Config::default();
        cfg.database.path = path;
        cfg.database.map_size = 16 * 1024 * 1024;
        cfg.database.max_map_size = 64 * 1024 * 1024;
        cfg.database.disabled_fsync = disable_fsync;
        let db = crate::db::DbClient::open(
            &cfg.database,
            true,
            std::sync::Arc::new(Default::default()),
            0,
            128,
            4096,
            262144,
        )
        .unwrap();
        let config = std::sync::Arc::new(tokio::sync::RwLock::new(cfg));
        let stats = crate::stats::Stats::new();
        let relay = Relay::new(
            config,
            db,
            stats,
            "",
            crate::relay::LiveBusConfig {
                buffer: 1024,
                batch_interval_ms: 10,
                batch_size: 64,
            },
        )
        .await;
        std::sync::Arc::new(relay)
    }

    #[tokio::test]
    async fn full_live_queue_signals_connection_overflow() {
        let (sender, receiver) = tokio::sync::mpsc::channel(crate::relay::LIVE_QUEUE_CAPACITY);
        let (overflow, overflow_rx) = tokio::sync::watch::channel(());
        let queue = LiveQueue { sender, overflow };
        let batch = std::sync::Arc::new(Vec::new());

        for _ in 0..crate::relay::LIVE_QUEUE_CAPACITY {
            enqueue_live_batch(&queue, batch.clone());
        }
        assert!(
            !overflow_rx.has_changed().unwrap(),
            "a queue at capacity must not signal overflow"
        );

        enqueue_live_batch(&queue, batch);
        assert!(
            overflow_rx.has_changed().unwrap(),
            "a full queue must signal the connection to close"
        );
        assert_eq!(receiver.len(), crate::relay::LIVE_QUEUE_CAPACITY);
    }

    #[tokio::test]
    async fn live_bus_panic_signals_every_subscriber_to_resync() {
        let queues = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let mut receivers = Vec::new();
        for id in 0..2 {
            let (sender, _receiver) = tokio::sync::mpsc::channel(crate::relay::LIVE_QUEUE_CAPACITY);
            let (overflow, overflow_rx) = tokio::sync::watch::channel(());
            queues
                .lock()
                .unwrap()
                .insert(id, LiveQueue { sender, overflow });
            receivers.push(overflow_rx);
        }

        signal_live_resync(&queues);

        assert!(
            receivers
                .iter()
                .all(|receiver| receiver.has_changed().unwrap()),
            "every subscriber must be told to resynchronize"
        );
    }

    #[tokio::test]
    async fn broadcast_reports_stopped_live_bus() {
        let mut relay = match std::sync::Arc::try_unwrap(build_relay().await) {
            Ok(relay) => relay,
            Err(_) => panic!("test relay must have a single owner"),
        };
        relay.live_rx.take();

        let event = crate::event::Event {
            id: String::new(),
            pubkey: String::new(),
            created_at: 0,
            kind: 1,
            tags: Vec::new(),
            content: String::new(),
            sig: String::new(),
        };
        assert!(relay.broadcast(event).await.is_err());
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn persisted_event_stays_accepted_when_live_bus_stops() {
        let mut relay = match std::sync::Arc::try_unwrap(build_relay().await) {
            Ok(relay) => relay,
            Err(_) => panic!("test relay must have a single owner"),
        };
        let secp = secp256k1::Secp256k1::new();
        let keypair = secp256k1::Keypair::from_seckey_slice(&secp, &[9u8; 32]).unwrap();
        let pubkey = secp256k1::XOnlyPublicKey::from_keypair(&keypair)
            .0
            .to_string();
        let mut event = crate::event::Event {
            id: String::new(),
            pubkey,
            created_at: crate::util::unix_now(),
            kind: 1,
            tags: vec![],
            content: "persisted".into(),
            sig: String::new(),
        };
        event.id = crate::nips::nip01::compute_id(&event);
        event.sig = secp
            .sign_schnorr_no_aux_rand(&event.id_bytes().unwrap(), &keypair)
            .to_string();
        relay.live_rx.take();

        let outcome = relay.accept_event(event.clone(), &[], None).await;
        assert_eq!(outcome, crate::db::PutOutcome::Stored);
        let (events, _) = relay
            .db
            .query(
                vec![serde_json::from_value(serde_json::json!({ "ids": [event.id] })).unwrap()],
                1,
                crate::util::unix_now(),
            )
            .await;
        assert_eq!(events.len(), 1, "the accepted event must remain queryable");
        relay.db.shutdown();
    }

    /// Builds a relay with NIP-43 enabled and an optional relay key.
    async fn build_role_relay(key: Option<&str>) -> std::sync::Arc<Relay> {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join("nostrfy-role-test")
            .join(format!("{:x}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        let mut cfg = crate::config::Config::default();
        cfg.database.path = path;
        cfg.database.map_size = 16 * 1024 * 1024;
        cfg.database.max_map_size = 64 * 1024 * 1024;
        if let Some(key) = key {
            cfg.relay.enabled_nips = vec![43];
            cfg.relay.private_key = key.to_string();
        }
        let db = crate::db::DbClient::open(
            &cfg.database,
            true,
            std::sync::Arc::new(Default::default()),
            0,
            128,
            4096,
            262144,
        )
        .unwrap();
        let config = std::sync::Arc::new(tokio::sync::RwLock::new(cfg));
        let stats = crate::stats::Stats::new();
        let relay = Relay::new(
            config,
            db,
            stats,
            key.unwrap_or(""),
            crate::relay::LiveBusConfig {
                buffer: 1024,
                batch_interval_ms: 10,
                batch_size: 64,
            },
        )
        .await;
        std::sync::Arc::new(relay)
    }

    #[tokio::test]
    async fn role_admin_lifecycle() {
        let key = "01".repeat(32);
        let relay = build_role_relay(Some(&key)).await;
        let member = "aa".repeat(32);

        // Without NIP-43 / a relay key every operation reports false.
        let keyless = build_role_relay(None).await;
        assert!(!keyless.create_role("r1", "R", "", "", None).await);
        assert!(!keyless.assign_role(&member, "r1").await);
        assert!(!keyless.delete_role("r1").await);
        assert!(
            !keyless
                .publish_membership(Some((true, member.clone())))
                .await
        );

        // create -> edit -> assign -> unassign -> delete.
        assert!(
            relay
                .create_role("r1", "Role 1", "desc", "red", Some(1))
                .await
        );
        assert!(relay.roles.read().await.roles.contains_key("r1"));
        // The role event (kind 33534) landed in the database.
        let f: crate::filter::Filter =
            serde_json::from_value(serde_json::json!({"kinds": [33534]})).unwrap();
        let (stored, _) = relay.db.query(vec![f], 10, crate::util::unix_now()).await;
        assert_eq!(stored.len(), 1, "the role definition must be stored");

        // edit on a missing id fails; on an existing id succeeds.
        assert!(!relay.edit_role("nope", "R", "", "", None).await);
        assert!(
            relay
                .edit_role("r1", "Role 1b", "desc2", "blue", None)
                .await
        );

        // assign to an unknown role fails; to a known role succeeds and
        // publishes the membership (kind 39002 for this relay... the
        // membership event kind is derived from the relay's own key).
        assert!(!relay.assign_role(&member, "nope").await);
        assert!(relay.assign_role(&member, "r1").await);
        assert!(relay.roles.read().await.is_member_of(&member));

        // unassign a non-assignment fails; the real one succeeds.
        assert!(!relay.unassign_role(&member, "nope").await);
        assert!(relay.unassign_role(&member, "r1").await);
        assert!(!relay.roles.read().await.is_member_of(&member));

        // delete a missing role fails; the real one succeeds and stores a
        // tombstone (kind 33534 with a `deleted` tag).
        assert!(!relay.delete_role("nope").await);
        assert!(relay.delete_role("r1").await);
        assert!(!relay.roles.read().await.roles.contains_key("r1"));

        // A leave request from a member removes and republishes; a
        // non-member is a no-op.
        assert!(relay.create_role("r1", "Role 1", "desc", "red", None).await);
        assert!(relay.assign_role(&member, "r1").await);
        let mut leave = crate::event::Event {
            id: String::new(),
            pubkey: member.clone(),
            created_at: crate::util::unix_now(),
            kind: 28936,
            tags: vec![],
            content: String::new(),
            sig: String::new(),
        };
        leave.id = crate::nips::nip01::compute_id(&leave);
        relay.apply_leave_request(&leave).await;
        assert!(!relay.roles.read().await.is_member_of(&member));
        let other = "bb".repeat(32);
        let mut leave = crate::event::Event {
            id: String::new(),
            pubkey: other.clone(),
            created_at: crate::util::unix_now(),
            kind: 28936,
            tags: vec![],
            content: String::new(),
            sig: String::new(),
        };
        leave.id = crate::nips::nip01::compute_id(&leave);
        relay.apply_leave_request(&leave).await;
        assert!(!relay.roles.read().await.is_member_of(&other));

        relay.db.shutdown();
        keyless.db.shutdown();
    }

    #[tokio::test]
    async fn generated_event_reports_stored_when_live_delivery_fails() {
        let key = "02".repeat(32);
        let mut relay = match std::sync::Arc::try_unwrap(build_role_relay(Some(&key)).await) {
            Ok(relay) => relay,
            Err(_) => panic!("test relay must have a single owner"),
        };
        relay.live_rx.take();
        let relay_pubkey = relay.relay_pubkey().unwrap();
        let mut event = crate::event::Event {
            id: String::new(),
            pubkey: relay_pubkey,
            created_at: crate::util::unix_now(),
            kind: 33534,
            tags: vec![vec!["d".into(), "delivery-test".into()]],
            content: String::new(),
            sig: String::new(),
        };

        assert_eq!(relay.store_relay_event(&mut event).await, Ok(false));
        let filter: crate::filter::Filter =
            serde_json::from_value(serde_json::json!({"ids": [event.id]})).unwrap();
        let (stored, _) = relay
            .db
            .query(vec![filter], 1, crate::util::unix_now())
            .await;
        assert_eq!(stored.len(), 1);
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn api_limiter_caps_concurrent_acquisitions() {
        // The limiter caps concurrent acquisitions and honors set_max.
        // (Per-IP connection accounting moved to the accept layer; its unit
        // tests live in `crate::conn`.)
        let relay = build_relay().await;
        let limiter = relay.api_limit.clone();
        limiter.set_max(2);
        let a = limiter.try_acquire().unwrap();
        let b = limiter.try_acquire().unwrap();
        assert!(limiter.try_acquire().is_none(), "the cap is enforced");
        drop(b);
        let c = limiter.try_acquire().unwrap();
        limiter.set_max(1);
        assert!(
            limiter.try_acquire().is_none(),
            "a lower ceiling applies to new acquisitions"
        );
        drop(a);
        drop(c);
        limiter.set_max(0);
        let _d = limiter.try_acquire().unwrap();
        assert!(limiter.try_acquire().is_none());
        drop(_d);
        assert_eq!(
            limiter.in_flight.load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn persist_relay_field_roundtrip() {
        let relay = build_relay().await;
        // No config path: the change warns and stays in memory.
        *relay.config_path.write().await = None;
        relay.persist_relay_field("name", "newname").await;
        // A writable temp config: the field is updated on disk.
        let dir = std::env::temp_dir().join("nostrfy-persist-field-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nostrfy.toml");
        std::fs::write(&path, "[relay]\nname = \"old\"\ndescription = \"d\"\n").unwrap();
        *relay.config_path.write().await = Some(path.clone());
        relay.persist_relay_field("name", "newname").await;
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.contains("newname"),
            "the field must be persisted: {text}"
        );
        // An unreadable path warns and leaves the in-memory change applied.
        *relay.config_path.write().await = Some(dir.join("missing.toml"));
        relay.persist_relay_field("description", "x").await;
        let _ = std::fs::remove_dir_all(&dir);
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn first_seen_min_age_gates_new_pubkeys() {
        let relay = build_relay().await;
        {
            let mut cfg = relay.config.write().await;
            cfg.relay.new_pubkey_min_age_secs = 100;
        }
        let secp = secp256k1::Secp256k1::new();
        let keypair = secp256k1::Keypair::from_seckey_slice(&secp, &[7u8; 32]).unwrap();
        let pubkey = secp256k1::XOnlyPublicKey::from_keypair(&keypair)
            .0
            .to_string();
        let mut ev = crate::event::Event {
            id: String::new(),
            pubkey: pubkey.clone(),
            created_at: crate::util::unix_now(),
            kind: 1,
            tags: vec![],
            content: "too young".into(),
            sig: String::new(),
        };
        ev.id = crate::nips::nip01::compute_id(&ev);
        let id = ev.id_bytes().unwrap();
        ev.sig = secp.sign_schnorr_no_aux_rand(&id, &keypair).to_string();
        // A pubkey recorded ten seconds ago is still inside the 100-second
        // gate: its event is rejected as too new.
        relay
            .db
            .touch_first_seen_batch(vec![(
                hex::decode(&pubkey).unwrap().try_into().unwrap(),
                crate::util::unix_now() - 10,
            )])
            .await;
        let outcome = relay.accept_event(ev.clone(), &[], None).await;
        assert!(
            matches!(&outcome, crate::db::PutOutcome::Invalid(r) if r.contains("too new")),
            "a too-new account must be gated: {outcome:?}"
        );
        // A pubkey with no recorded first-seen (its very first event) is
        // allowed: the event establishes the account's arrival time.
        let other_keypair = secp256k1::Keypair::from_seckey_slice(&secp, &[8u8; 32]).unwrap();
        let other_pubkey = secp256k1::XOnlyPublicKey::from_keypair(&other_keypair)
            .0
            .to_string();
        let mut ev2 = crate::event::Event {
            id: String::new(),
            pubkey: other_pubkey,
            created_at: crate::util::unix_now(),
            kind: 1,
            tags: vec![],
            content: "first event".into(),
            sig: String::new(),
        };
        ev2.id = crate::nips::nip01::compute_id(&ev2);
        let id = ev2.id_bytes().unwrap();
        ev2.sig = secp
            .sign_schnorr_no_aux_rand(&id, &other_keypair)
            .to_string();
        let outcome = relay.accept_event(ev2, &[], None).await;
        assert!(
            matches!(outcome, crate::db::PutOutcome::Stored),
            "the first event of an unknown pubkey is accepted"
        );
        let _ = ev;
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn reload_db_state_applies_persisted_lists() {
        let relay = build_relay().await;
        relay
            .db
            .save_relay_pubkeys(&[("aa".repeat(32), "test".into())], &[])
            .await;
        relay.reload_db_state().await;
        assert_eq!(
            relay.access.read().await.blocked_pubkeys.len(),
            1,
            "the persisted deny list must be applied"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn concurrent_access_persists_keep_every_entry() {
        // Two concurrent mutations must not capture snapshots in one order
        // and queue their writes in the other: the older snapshot would be
        // committed last and drop the newer entry from the persisted lists
        // (a ban silently vanishing on the next restart). `persist_access`
        // serializes the snapshot and both writes.
        let relay = build_relay().await;
        for i in 0..32u32 {
            let a = format!("a{i:020x}");
            let b = format!("b{i:020x}");
            let ra = relay.clone();
            let rb = relay.clone();
            let (a2, b2) = (a.clone(), b.clone());
            let ta = tokio::spawn(async move {
                ra.access
                    .write()
                    .await
                    .blocked_pubkeys
                    .push((a2, String::new()));
                ra.persist_access().await;
            });
            let tb = tokio::spawn(async move {
                rb.access
                    .write()
                    .await
                    .blocked_pubkeys
                    .push((b2, String::new()));
                rb.persist_access().await;
            });
            ta.await.unwrap();
            tb.await.unwrap();
            let (deny, _) = relay
                .db
                .load_relay_pubkeys()
                .await
                .expect("the access lists must load");
            assert!(
                deny.iter().any(|(p, _)| p == &a),
                "iteration {i} lost {a}: {} entries persisted",
                deny.len()
            );
            assert!(
                deny.iter().any(|(p, _)| p == &b),
                "iteration {i} lost {b}: {} entries persisted",
                deny.len()
            );
        }
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn reload_db_state_keeps_previous_lists_on_failure() {
        let relay = build_relay().await;
        // Mark the live lists: a failed reload must not overwrite them
        // with an empty (fail-open) result.
        relay
            .access
            .write()
            .await
            .blocked_pubkeys
            .push(("bb".repeat(32), "marker".into()));
        relay.blossom_allow.write().await.push("npub1marker".into());
        // The reader thread is gone: every reload request is reported as
        // failed.
        relay.db.shutdown();
        relay.reload_db_state().await;
        assert_eq!(
            relay.access.read().await.blocked_pubkeys.len(),
            1,
            "the previous deny list must survive a failed reload"
        );
        assert_eq!(
            relay.blossom_allow.read().await.len(),
            1,
            "the previous allowlist must survive a failed reload"
        );
    }

    #[test]
    fn batch_path_vanish_replies_ok_with_real_id() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay().await;
            let now = crate::util::unix_now();
            let secp = secp256k1::Secp256k1::new();
            let keypair = secp256k1::Keypair::from_seckey_slice(&secp, &[3u8; 32]).unwrap();
            let pubkey = secp256k1::XOnlyPublicKey::from_keypair(&keypair).0.to_string();
            let mut ev = crate::event::Event {
                id: String::new(),
                pubkey: pubkey.clone(),
                created_at: now,
                kind: 62,
                tags: vec![vec!["relay".into(), "ws://127.0.0.1:8080".into()]],
                content: "vanish".into(),
                sig: String::new(),
            };
            ev.id = crate::nips::nip01::compute_id(&ev);
            let id = ev.id_bytes().unwrap();
            ev.sig = secp.sign_schnorr_no_aux_rand(&id, &keypair).to_string();
            let results = relay.accept_events_batch(vec![ev], &[]).await;
            assert_eq!(results.len(), 1);
            assert!(
                matches!(&results[0], (rid, crate::db::PutOutcome::Stored) if rid == &results[0].0 && !rid.is_empty()),
                "the vanish reply must carry the event's real id: {:?}",
                results
            );
            relay.db.shutdown();
        });
    }

    #[test]
    fn deleting_a_group_purges_its_stored_events() {
        // NIP-29: a deleted group's stored events are purged, so re-creating
        // the id (which installs a public group) cannot expose the old
        // possibly-private history.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay().await;
            let now = crate::util::unix_now();
            let secp = secp256k1::Secp256k1::new();
            let keypair = secp256k1::Keypair::from_seckey_slice(&secp, &[4u8; 32]).unwrap();
            let pubkey = secp256k1::XOnlyPublicKey::from_keypair(&keypair)
                .0
                .to_string();
            let signed = |kind: u64, content: &str, created_at: u64| {
                let mut e = crate::event::Event {
                    id: String::new(),
                    pubkey: pubkey.clone(),
                    created_at,
                    kind,
                    tags: vec![vec!["h".into(), "g1".into()]],
                    content: content.into(),
                    sig: String::new(),
                };
                e.id = crate::nips::nip01::compute_id(&e);
                let id = e.id_bytes().unwrap();
                e.sig = secp.sign_schnorr_no_aux_rand(&id, &keypair).to_string();
                e
            };
            // A stored group message (direct DB put: the purge is the target).
            // It predates the purge cut, so a replay after the re-create is
            // rejected by the per-group purge marker.
            let msg = signed(1, "secret group message", now - 10);
            assert_eq!(
                relay.db.put(msg.clone(), now).await,
                crate::db::PutOutcome::Stored
            );
            let create = signed(crate::nips::nip29::CREATE_GROUP, "", now - 5);
            assert!(matches!(
                relay.accept_event(create, &[], None).await,
                crate::db::PutOutcome::Stored
            ));
            let delete = signed(crate::nips::nip29::DELETE_GROUP, "", now);
            assert!(matches!(
                relay.accept_event(delete, &[], None).await,
                crate::db::PutOutcome::Stored
            ));
            let f: crate::filter::Filter =
                serde_json::from_value(serde_json::json!({"#h": ["g1"]})).unwrap();
            let (res, _) = relay.db.query(vec![f], 10, now).await;
            assert!(res.is_empty(), "the deleted group's events must be purged");
            // The purge was confirmed, so the fail-closed ghost was
            // downgraded to the ordinary tombstone: the id is re-creatable.
            // The purge marker still rejects a re-broadcast of the purged
            // history (one cut per group, not one tombstone per event).
            let recreate = signed(crate::nips::nip29::CREATE_GROUP, "recreate", now + 1);
            assert!(matches!(
                relay.accept_event(recreate, &[], None).await,
                crate::db::PutOutcome::Stored
            ));
            assert!(
                relay.groups.read().await.group("g1").is_some(),
                "a confirmed purge must leave the id re-creatable"
            );
            assert_eq!(
                relay.db.put(msg, now + 1).await,
                crate::db::PutOutcome::PreviouslyDeleted,
                "the purged history must not re-enter after the re-create"
            );
            relay.db.shutdown();
        });
    }

    #[test]
    fn one_edit_keeps_only_the_final_group_metadata() {
        // A single 9002 can rebuild the same parent metadata several times
        // (adopting B1 and B2 in one edit clears the old parent's child list
        // after each move). With one shared stamp per moderation event, the
        // NIP-01 id tie-break could keep the stale version and drop the
        // corrected one as a duplicate, leaving the stored children
        // inconsistent with the in-memory group state.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let key = "01".repeat(32);
            let relay = build_role_relay(Some(&key)).await;
            relay.config.write().await.relay.enabled_nips.push(29);
            let now = crate::util::unix_now();
            let secp = secp256k1::Secp256k1::new();
            let keypair = secp256k1::Keypair::from_seckey_slice(&secp, &[4u8; 32]).unwrap();
            let pubkey = secp256k1::XOnlyPublicKey::from_keypair(&keypair)
                .0
                .to_string();
            let signed = |kind: u64, gid: &str, tags: Vec<Vec<String>>| {
                let mut all = vec![vec!["h".to_string(), gid.to_string()]];
                all.extend(tags);
                let mut e = crate::event::Event {
                    id: String::new(),
                    pubkey: pubkey.clone(),
                    created_at: now,
                    kind,
                    tags: all,
                    content: String::new(),
                    sig: String::new(),
                };
                e.id = crate::nips::nip01::compute_id(&e);
                let id = e.id_bytes().unwrap();
                e.sig = secp.sign_schnorr_no_aux_rand(&id, &keypair).to_string();
                e
            };
            // Create A (the adopting group), X (the old parent) and both
            // children.
            for gid in ["a", "x", "b1", "b2"] {
                let ev = signed(crate::nips::nip29::CREATE_GROUP, gid, vec![]);
                assert!(matches!(
                    relay.accept_event(ev, &[], None).await,
                    crate::db::PutOutcome::Stored
                ));
            }
            // Both children point at X.
            for child in ["b1", "b2"] {
                let ev = signed(
                    9002,
                    child,
                    vec![vec!["parent".to_string(), "x".to_string()]],
                );
                assert!(matches!(
                    relay.accept_event(ev, &[], None).await,
                    crate::db::PutOutcome::Stored
                ));
            }
            // One 9002 on A adopts both: X's metadata is rebuilt after each
            // removal.
            let ev = signed(
                9002,
                "a",
                vec![
                    vec!["child".to_string(), "b1".to_string()],
                    vec!["child".to_string(), "b2".to_string()],
                ],
            );
            assert!(matches!(
                relay.accept_event(ev, &[], None).await,
                crate::db::PutOutcome::Stored
            ));
            let f: crate::filter::Filter = serde_json::from_value(
                serde_json::json!({"kinds": [crate::nips::nip29::GROUP_META], "#d": ["x"]}),
            )
            .unwrap();
            let (stored, _) = relay.db.query(vec![f], 10, now).await;
            assert_eq!(stored.len(), 1, "exactly one X metadata event");
            assert!(
                !stored[0]
                    .tags
                    .iter()
                    .any(|t| t.first().map(String::as_str) == Some("child")),
                "the final X metadata must not list its old children: {:?}",
                stored[0].tags
            );
            relay.db.shutdown();
        });
    }

    #[test]
    fn stamp_clock_is_strictly_monotonic() {
        let clock = StampClock::new_with_last(0);
        let a = clock.stamp(100);
        let b = clock.stamp(50);
        let c = clock.stamp(1000);
        let d = clock.stamp(0);
        assert!(a >= 100);
        assert!(b > a, "a lower floor must not lower the stamp");
        assert!(c > b && c >= 1000);
        assert!(d > c, "a zero floor must not lower the stamp");
    }

    #[test]
    fn stamp_clock_saturates_without_regressing() {
        // At the cap strict monotonicity is impossible (no larger value
        // exists), but the clock must stay at the last usable stamp and
        // never regress or return the reserved `u64::MAX`.
        let clock = StampClock::new_with_last(u64::MAX - 1);
        let a = clock.stamp(u64::MAX);
        assert_eq!(a, u64::MAX - 1, "the cap is the last usable stamp");
        let b = clock.stamp(u64::MAX);
        assert_eq!(b, u64::MAX - 1, "saturated stamps stay at the cap");
        assert_ne!(b, u64::MAX, "u64::MAX is never issued");
    }

    #[test]
    fn stamp_clock_resumes_above_bootstrapped_last() {
        // Restart recovery: stamps issued after bootstrapping from the
        // newest stored relay event must exceed every pre-restart stamp.
        let clock = StampClock::new_with_last(1_700_000_000);
        let a = clock.stamp(1_700_000_000);
        assert!(
            a > 1_700_000_000,
            "a post-restart stamp must exceed the bootstrapped last: {a}"
        );
        assert!(clock.stamp(a) > a);
    }

    #[test]
    fn relay_bootstraps_stamps_from_stored_relay_events() {
        // End-to-end restart recovery: a relay-signed replaceable stored
        // before (re)construction must be outranked by fresh stamps.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join("nostrfy-stamp-bootstrap")
                .join(format!("{:x}-{id}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            let mut cfg = crate::config::Config::default();
            cfg.database.path = path;
            cfg.database.map_size = 16 * 1024 * 1024;
            cfg.database.max_map_size = 64 * 1024 * 1024;
            let db = crate::db::DbClient::open(
                &cfg.database,
                true,
                std::sync::Arc::new(Default::default()),
                0,
                128,
                4096,
                262144,
            )
            .unwrap();
            let secp = secp256k1::Secp256k1::new();
            let keypair =
                secp256k1::Keypair::from_seckey_slice(&secp, &[11u8; 32]).expect("test key");
            let pubkey = secp256k1::XOnlyPublicKey::from_keypair(&keypair)
                .0
                .to_string();
            let secret = hex::encode([11u8; 32]);
            let stamped = 1_700_000_000u64;
            let mut ev = crate::event::Event {
                id: String::new(),
                pubkey: pubkey.clone(),
                created_at: stamped,
                kind: crate::nips::nip29::GROUP_META,
                tags: vec![vec!["d".to_string(), "g".to_string()]],
                content: String::new(),
                sig: String::new(),
            };
            ev.id = crate::nips::nip01::compute_id(&ev);
            let raw = ev.id_bytes().expect("test id");
            ev.sig = secp.sign_schnorr_no_aux_rand(&raw, &keypair).to_string();
            assert!(matches!(
                db.put(ev, stamped).await,
                crate::db::PutOutcome::Stored
            ));
            let config = std::sync::Arc::new(tokio::sync::RwLock::new(cfg));
            let relay = Relay::new(
                config,
                db,
                crate::stats::Stats::new(),
                &secret,
                crate::relay::LiveBusConfig {
                    buffer: 1024,
                    batch_interval_ms: 10,
                    batch_size: 64,
                },
            )
            .await;
            assert!(
                relay.stamp_floor(stamped) > stamped,
                "fresh stamps must outrank the stored relay event"
            );
            relay.db.shutdown();
        });
    }

    #[test]
    fn relay_bootstraps_stamps_from_the_discovery_event() {
        // NIP-66: the relay's own 30166 is relay-signed and addressable, so
        // the stamp clock must bootstrap from it too. Otherwise a restart
        // with no groups or roles starts the clock at 0 and a same-second
        // re-publish can lose the NIP-01 tie-break, leaving the stale
        // discovery event served until the next 12h refresh.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join("nostrfy-stamp-bootstrap-nip66")
                .join(format!("{:x}-{id}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            let mut cfg = crate::config::Config::default();
            cfg.database.path = path;
            cfg.database.map_size = 16 * 1024 * 1024;
            cfg.database.max_map_size = 64 * 1024 * 1024;
            let db = crate::db::DbClient::open(
                &cfg.database,
                true,
                std::sync::Arc::new(Default::default()),
                0,
                128,
                4096,
                262144,
            )
            .unwrap();
            let secp = secp256k1::Secp256k1::new();
            let keypair =
                secp256k1::Keypair::from_seckey_slice(&secp, &[11u8; 32]).expect("test key");
            let pubkey = secp256k1::XOnlyPublicKey::from_keypair(&keypair)
                .0
                .to_string();
            let secret = hex::encode([11u8; 32]);
            let stamped = 1_700_000_000u64;
            let mut ev = crate::event::Event {
                id: String::new(),
                pubkey: pubkey.clone(),
                created_at: stamped,
                kind: crate::nips::nip66::DISCOVERY,
                tags: vec![
                    vec!["d".to_string(), "wss://relay.example.com/".to_string()],
                    vec!["-".to_string()],
                ],
                content: String::new(),
                sig: String::new(),
            };
            ev.id = crate::nips::nip01::compute_id(&ev);
            let raw = ev.id_bytes().expect("test id");
            ev.sig = secp.sign_schnorr_no_aux_rand(&raw, &keypair).to_string();
            assert!(matches!(
                db.put(ev, stamped).await,
                crate::db::PutOutcome::Stored
            ));
            let config = std::sync::Arc::new(tokio::sync::RwLock::new(cfg));
            let relay = Relay::new(
                config,
                db,
                crate::stats::Stats::new(),
                &secret,
                crate::relay::LiveBusConfig {
                    buffer: 1024,
                    batch_interval_ms: 10,
                    batch_size: 64,
                },
            )
            .await;
            assert!(
                relay.stamp_floor(stamped) > stamped,
                "fresh stamps must outrank the stored discovery event"
            );
            relay.db.shutdown();
        });
    }

    #[test]
    fn nsec_detection() {
        // A real nsec (checksum-valid bech32m) is detected.
        let key = crate::nips::nip19::bech32_encode("nsec", &[0x42u8; 32]).unwrap();
        assert_eq!(key.len(), 63);
        assert!(contains_secret_key(&format!("look at my key {key} here")));
        assert!(contains_secret_key(&key));

        // Embedded in tags.
        assert!(contains_secret_key(&format!("prefix-{key}-suffix")));

        // Too short: not a key.
        assert!(!contains_secret_key("nsec1"));
        assert!(!contains_secret_key(&format!("nsec1{}", &key[5..45])));

        // Invalid bech32 characters are not matched.
        let mut bad = key[5..].chars().collect::<Vec<_>>();
        bad[0] = 'B'; // 'B' is not in the bech32 charset
        let bad: String = bad.into_iter().collect();
        assert!(!contains_secret_key(&format!("nsec1{bad}")));

        // A checksum-invalid look-alike (quoted fake key / garbage) is NOT
        // flagged: content cannot be censored by baiting a user into quoting
        // an nsec-shaped string.
        let fake_body: String = (0..58)
            .map(|i| "qpzry9x8gf2tvdw0s3jn54khce6mua7l".as_bytes()[i % 32] as char)
            .collect();
        assert!(
            !contains_secret_key(&format!("nsec1{fake_body}")),
            "an invalid-checksum nsec look-alike must not be flagged"
        );

        // Case-insensitive prefix with a valid checksum: an all-uppercase
        // key is still a real key (bech32 permits all-uppercase).
        let upper = key.to_uppercase();
        assert!(contains_secret_key(&upper));

        // A *mixed-case* string (uppercase prefix, lowercase data) is
        // invalid bech32 and must not be flagged.
        assert!(!contains_secret_key(&format!("NSEC1{}", &key[5..])));

        // A multi-byte boundary must not panic: a 63-byte window ending
        // inside a multi-byte character is skipped, not sliced.
        let boundary = format!("{}😀{}ab", "a".repeat(60), key);
        assert!(contains_secret_key(&boundary));
        let split_emoji = format!("{}😀{}", "a".repeat(60), "b".repeat(60));
        assert!(!contains_secret_key(&split_emoji));

        // A bech32m-valid look-alike is not a spendable nsec key (real nsec
        // is legacy bech32) and must not mute the event.
        let m_key = crate::nips::nip19::bech32m_encode("nsec", &[0x42u8; 32]).unwrap();
        assert_ne!(m_key, key, "bech32m encoding differs from bech32");
        assert!(
            !contains_secret_key(&m_key),
            "a bech32m-only nsec look-alike must not be flagged"
        );
    }

    /// Ingestion throughput benchmark through the real write path:
    /// `accept_event[s]` → precheck (Schnorr verify) → batched LMDB commit →
    /// first-seen / side effects → live broadcast. Reports the parallel vs
    /// sequential signature-verify cost and the durable (fsync) vs
    /// fsync-disabled end-to-end ingest. Run with:
    /// `cargo test --release -- --ignored bench_ingest --nocapture`.
    #[ignore]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn bench_ingest_events_per_sec() {
        fn bench_signed(
            secp: &secp256k1::Secp256k1<secp256k1::All>,
            i: usize,
            now: u64,
        ) -> crate::event::Event {
            // `i` spans the run counter, so no two runs reuse (pubkey, id)s.
            // The low bytes vary so every seckey < the curve order n.
            let mut seckey = [0u8; 32];
            seckey[31] = ((i % 250) as u8) + 1;
            seckey[30] = (i / 250) as u8;
            let keypair = secp256k1::Keypair::from_seckey_slice(secp, &seckey).unwrap();
            let pubkey = secp256k1::XOnlyPublicKey::from_keypair(&keypair)
                .0
                .to_string();
            let mut ev = crate::event::Event {
                id: String::new(),
                pubkey,
                created_at: now,
                kind: 1,
                tags: vec![vec!["t".into(), "bench".into()]],
                content: format!("bench event {i}"),
                sig: String::new(),
            };
            ev.id = crate::nips::nip01::compute_id(&ev);
            let sig = secp.sign_schnorr_no_aux_rand(&ev.id_bytes().unwrap(), &keypair);
            ev.sig = sig.to_string();
            ev
        }

        let relay = build_relay().await;
        let fsync_off_relay = build_relay_cfg(true).await;
        let secp = relay.secp(); // shares the relay's precomputed context

        // Signature-verify cost alone (the dominant per-event CPU work), one
        // batch through the parallel path vs the sequential inline path. The
        // end-to-end numbers below include DB commit time, which dominates on
        // slow disks, so this section isolates the parallel verify gain.
        {
            const N: usize = 8000;
            let now = crate::util::unix_now();
            let big: Vec<crate::event::Event> =
                (0..N).map(|i| bench_signed(secp, i, now)).collect();
            let t0 = std::time::Instant::now();
            for batch in big.chunks(1000) {
                let v = crate::relay::validate::verify_signatures_parallel(batch, secp);
                assert!(v.iter().all(|b| *b));
            }
            let par = t0.elapsed().as_secs_f64();
            let t0 = std::time::Instant::now();
            for batch in big.chunks(1000) {
                let v: Vec<bool> = batch
                    .iter()
                    .map(|e| crate::nips::nip01::verify(e, secp).is_ok())
                    .collect();
                assert!(v.iter().all(|b| *b));
            }
            let seq = t0.elapsed().as_secs_f64();
            println!(
                "verify only: {N} sigs parallel {:>6.0}/s vs sequential {:>6.0}/s ({:.1}x)",
                N as f64 / par,
                N as f64 / seq,
                seq / par
            );
        }

        // End-to-end ingest through the full accept path, with the durable
        // (fsync) DB and the fsync-disabled DB side by side.
        let mut run = 0usize;
        for (set, total) in [("flood batch", 1000usize), ("stream batch", 5000usize)] {
            let now = crate::util::unix_now();
            let pre: Vec<crate::event::Event> = (0..total)
                .map(|i| bench_signed(secp, run + i, now))
                .collect();
            run += total;
            for (name, target) in [("durable", &relay), ("fsync-off", &fsync_off_relay)] {
                let t0 = std::time::Instant::now();
                for chunk in pre.chunks(100) {
                    let results = target.accept_events_batch(chunk.to_vec(), &[]).await;
                    let accepted = results
                        .iter()
                        .filter(|(_, o)| matches!(o, crate::db::PutOutcome::Stored))
                        .count();
                    assert_eq!(accepted, chunk.len(), "every benchmark event must store");
                }
                let elapsed = t0.elapsed().as_secs_f64();
                let eps = total as f64 / elapsed;
                println!("{set} ({name}): {total} events in {elapsed:.3} s -> {eps:.0} events/sec");
            }
        }
        relay.db.shutdown();
        fsync_off_relay.db.shutdown();
    }

    #[test]
    fn sibling_previous_references_resolve_in_one_batch() {
        // A batch of `h`-tagged posts where the second references the first
        // via `previous`: the fast path must resolve the sibling against the
        // batch's prefetched set (the event is not committed yet). Before
        // the prefetch was restored this was rejected as "unknown previous
        // tag" and every reference cost its own database round trip.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            use crate::db::PutOutcome;

            let relay = build_relay().await;
            let now = crate::util::unix_now();
            let secp = secp256k1::Secp256k1::new();
            let kp = |seed: u8| secp256k1::Keypair::from_seckey_slice(&secp, &[seed; 32]).unwrap();
            let signed = |seed: u8, kind: u64, content: &str, tags: Vec<Vec<String>>| {
                let keypair = kp(seed);
                let mut e = crate::event::Event {
                    id: String::new(),
                    pubkey: secp256k1::XOnlyPublicKey::from_keypair(&keypair)
                        .0
                        .to_string(),
                    created_at: now,
                    kind,
                    tags,
                    content: content.into(),
                    sig: String::new(),
                };
                e.id = crate::nips::nip01::compute_id(&e);
                let id = e.id_bytes().unwrap();
                e.sig = secp.sign_schnorr_no_aux_rand(&id, &keypair).to_string();
                e
            };
            let h = |tags: Vec<Vec<String>>| {
                let mut tags = tags;
                tags.insert(0, vec!["h".into(), "g-prev".into()]);
                tags
            };
            let mut results = relay
                .accept_events_batch(vec![signed(7, 9007, "", h(vec![]))], &[])
                .await;
            assert!(matches!(results.remove(0).1, PutOutcome::Stored));

            let first = signed(7, 1, "first", h(vec![]));
            let prefix = first.id[..8].to_string();
            let second = signed(
                7,
                1,
                "second",
                h(vec![vec!["previous".into(), prefix.clone()]]),
            );
            let first_id = first.id.clone();
            let second_id = second.id.clone();
            let results = relay.accept_events_batch(vec![first, second], &[]).await;
            assert_eq!(results[0].0, first_id);
            assert!(
                matches!(results[0].1, PutOutcome::Stored),
                "the referenced sibling itself must store: {results:?}"
            );
            assert_eq!(results[1].0, second_id);
            assert!(
                matches!(results[1].1, PutOutcome::Stored),
                "a sibling previous reference must resolve against the batch: {results:?}"
            );
            // A reference outside the batch and outside the database still
            // fails closed.
            let unknown = signed(
                7,
                1,
                "unknown",
                h(vec![vec!["previous".into(), "ab".repeat(4)]]),
            );
            let results = relay.accept_events_batch(vec![unknown], &[]).await;
            assert!(
                matches!(results[0].1, PutOutcome::Invalid(_)),
                "an unknown previous reference must be rejected: {results:?}"
            );
            relay.db.shutdown();
        });
    }

    #[test]
    fn mixed_batch_applies_state_mutations_between_runs_in_order() {
        // A batch with `h`-tagged posts around group-state mutations: each
        // post must be prechecked against the state *at its position* —
        // after an earlier 9000 but before a later 9001 — even though the
        // stateless posts are committed as one batch.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            use crate::db::PutOutcome;

            let relay = build_relay().await;
            let now = crate::util::unix_now();
            let secp = secp256k1::Secp256k1::new();
            let kp = |seed: u8| secp256k1::Keypair::from_seckey_slice(&secp, &[seed; 32]).unwrap();
            let member = secp256k1::XOnlyPublicKey::from_keypair(&kp(8))
                .0
                .to_string();
            let signed = |seed: u8, kind: u64, content: &str, tags: Vec<Vec<String>>| {
                let keypair = kp(seed);
                let mut e = crate::event::Event {
                    id: String::new(),
                    pubkey: secp256k1::XOnlyPublicKey::from_keypair(&keypair)
                        .0
                        .to_string(),
                    created_at: now,
                    kind,
                    tags,
                    content: content.into(),
                    sig: String::new(),
                };
                e.id = crate::nips::nip01::compute_id(&e);
                let id = e.id_bytes().unwrap();
                e.sig = secp.sign_schnorr_no_aux_rand(&id, &keypair).to_string();
                e
            };
            let h = |tags: Vec<Vec<String>>| {
                let mut tags = tags;
                tags.insert(0, vec!["h".into(), "g-mixed".into()]);
                tags
            };
            // Create a restricted group (only members may post).
            let mut results = relay
                .accept_events_batch(vec![signed(7, 9007, "", h(vec![]))], &[])
                .await;
            assert!(matches!(results.remove(0).1, PutOutcome::Stored));
            let mut results = relay
                .accept_events_batch(
                    vec![signed(7, 9002, "", h(vec![vec!["restricted".into()]]))],
                    &[],
                )
                .await;
            assert!(matches!(results.remove(0).1, PutOutcome::Stored));

            // [post (rejected: no member yet), 9000 add member, post (accepted)]
            let results = relay
                .accept_events_batch(
                    vec![
                        signed(8, 1, "before-add", h(vec![])),
                        signed(7, 9000, "", h(vec![vec!["p".into(), member.clone()]])),
                        signed(8, 1, "after-add", h(vec![])),
                    ],
                    &[],
                )
                .await;
            assert!(
                matches!(results[0].1, PutOutcome::Invalid(_)),
                "the post before the 9000 must see the pre-add state: {results:?}"
            );
            assert!(matches!(results[1].1, PutOutcome::Stored), "{results:?}");
            assert!(
                matches!(results[2].1, PutOutcome::Stored),
                "the post after the 9000 must see the added member: {results:?}"
            );

            // [post (accepted), 9001 remove member, post (rejected)]
            let results = relay
                .accept_events_batch(
                    vec![
                        signed(8, 1, "before-remove", h(vec![])),
                        signed(7, 9001, "", h(vec![vec!["p".into(), member.clone()]])),
                        signed(8, 1, "after-remove", h(vec![])),
                    ],
                    &[],
                )
                .await;
            assert!(
                matches!(results[0].1, PutOutcome::Stored),
                "the post before the 9001 must still see the member: {results:?}"
            );
            assert!(matches!(results[1].1, PutOutcome::Stored), "{results:?}");
            assert!(
                matches!(results[2].1, PutOutcome::Invalid(_)),
                "the post after the 9001 must see the removed member: {results:?}"
            );
            relay.db.shutdown();
        });
    }

    #[tokio::test]
    async fn nip11_document_cache_tracks_access_and_config_version() {
        let relay = build_relay().await;
        let doc = relay.relay_info_document().await;
        assert_eq!(doc["limitation"]["restricted_writes"], false);
        assert_eq!(doc["stats"]["events"]["accepted"].as_u64(), Some(0));
        // An access-only change (no SIGHUP) must invalidate the cached
        // document: NIP-86 kind lists are reloaded without a version bump.
        relay.access.write().await.allowed_kinds.push(1);
        let doc = relay.relay_info_document().await;
        assert_eq!(doc["limitation"]["restricted_writes"], true);
        // The reload path bumps the version after swapping the config.
        relay.config.write().await.relay.name = "renamed".into();
        relay
            .config_version
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let doc = relay.relay_info_document().await;
        assert_eq!(doc["name"], "renamed");
        // Stats stay fresh on the cached path too.
        relay.stats.bump(&relay.stats.events_accepted, 5);
        let doc = relay.relay_info_document().await;
        assert_eq!(doc["stats"]["events"]["accepted"].as_u64(), Some(5));
        relay.db.shutdown();
    }

    #[test]
    fn repeated_vanishes_coalesce_the_rebuild() {
        // A vanish is exempt from the publish rate limit, so any keypair can
        // trigger the post-vanish rebuild. The coalesced worker must run one
        // scan for a burst of vanishes (not one per event) and still
        // converge on the surviving state.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            use crate::db::PutOutcome;

            let relay = build_relay().await;
            let now = crate::util::unix_now();
            let secp = secp256k1::Secp256k1::new();
            let sign = |seed: u8, gid: &str| {
                let keypair = secp256k1::Keypair::from_seckey_slice(&secp, &[seed; 32]).unwrap();
                let mut e = crate::event::Event {
                    id: String::new(),
                    pubkey: secp256k1::XOnlyPublicKey::from_keypair(&keypair)
                        .0
                        .to_string(),
                    created_at: now,
                    kind: crate::nips::nip29::CREATE_GROUP,
                    tags: vec![vec!["h".into(), gid.into()]],
                    content: String::new(),
                    sig: String::new(),
                };
                e.id = crate::nips::nip01::compute_id(&e);
                let id = e.id_bytes().unwrap();
                e.sig = secp.sign_schnorr_no_aux_rand(&id, &keypair).to_string();
                e
            };
            let gids = ["g0", "g1", "g2", "g3", "g4"];
            let mut events = Vec::new();
            for (i, gid) in gids.iter().enumerate() {
                let ev = sign(30 + i as u8, gid);
                assert_eq!(relay.db.put(ev.clone(), now).await, PutOutcome::Stored);
                relay.groups.write().await.apply(&ev, "", now, false, false);
                events.push(ev);
            }
            // All five vanish in a burst: each removes its creator's 9007,
            // so each is a non-no-op that used to run a full scan inline.
            for ev in &events {
                relay
                    .vanish_pubkey(ev.pubkey_bytes().unwrap(), ev.created_at)
                    .await;
            }
            let mut converged = false;
            for _ in 0..600 {
                if !relay
                    .groups_rebuild
                    .pending
                    .load(std::sync::atomic::Ordering::SeqCst)
                {
                    converged = true;
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            assert!(converged, "the coalesced rebuild must converge");
            let state = relay.groups.read().await;
            assert!(state.groups.is_empty(), "every group lost its create");
            let hidden = state.hidden_group_ids();
            for gid in gids {
                assert!(
                    hidden.iter().any(|id| id == gid),
                    "{gid} must be ghosted after the rebuild"
                );
            }
            drop(state);
            let scans = relay
                .groups_rebuild
                .rebuilds
                .load(std::sync::atomic::Ordering::Relaxed);
            assert!(
                scans < gids.len() as u64,
                "a burst of vanishes must coalesce into fewer scans, got {scans}"
            );
            relay.db.shutdown();
        });
    }

    #[test]
    fn concurrent_group_persists_keep_every_group() {
        // Snapshot capture and write are serialized: without the lock a
        // mutation that captured an older snapshot could queue its write
        // after a newer one, silently dropping a group from the persisted
        // state on the next restart.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay().await;
            let now = crate::util::unix_now();
            let create = |gid: &str| {
                let mut e = crate::event::Event {
                    id: String::new(),
                    pubkey: "aa".repeat(32),
                    created_at: now,
                    kind: crate::nips::nip29::CREATE_GROUP,
                    tags: vec![vec!["h".into(), gid.into()]],
                    content: String::new(),
                    sig: String::new(),
                };
                e.id = crate::nips::nip01::compute_id(&e);
                e
            };
            for i in 0..32u32 {
                let a = format!("a{i:02}");
                let b = format!("b{i:02}");
                let ev_a = create(&a);
                let ev_b = create(&b);
                let ra = relay.clone();
                let rb = relay.clone();
                let (a2, b2) = (a.clone(), b.clone());
                let ta = tokio::spawn(async move {
                    ra.groups.write().await.apply(&ev_a, "", now, false, false);
                    ra.persist_groups().await;
                });
                let tb = tokio::spawn(async move {
                    rb.groups.write().await.apply(&ev_b, "", now, false, false);
                    rb.persist_groups().await;
                });
                ta.await.unwrap();
                tb.await.unwrap();
                let snap = relay.db.load_groups().await.expect("snapshot persisted");
                assert!(
                    snap.groups.contains_key(&a2) && snap.groups.contains_key(&b2),
                    "iteration {i} lost a group: {} persisted",
                    snap.groups.len()
                );
            }
            relay.db.shutdown();
        });
    }

    #[test]
    fn persist_groups_drops_the_snapshot_while_the_rebuild_is_pending() {
        // A snapshot from before a vanish must not survive the state being
        // marked stale (a crash before the rebuild would restore it).
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay().await;
            let now = crate::util::unix_now();
            let mut create = crate::event::Event {
                id: String::new(),
                pubkey: "aa".repeat(32),
                created_at: now,
                kind: crate::nips::nip29::CREATE_GROUP,
                tags: vec![vec!["h".into(), "g1".into()]],
                content: String::new(),
                sig: String::new(),
            };
            create.id = crate::nips::nip01::compute_id(&create);
            relay
                .groups
                .write()
                .await
                .apply(&create, "", now, false, false);
            relay.persist_groups().await;
            assert!(relay.db.load_groups().await.is_some());

            relay
                .groups_rebuild
                .pending
                .store(true, std::sync::atomic::Ordering::SeqCst);
            relay.persist_groups().await;
            assert!(
                relay.db.load_groups().await.is_none(),
                "a stale-state snapshot must be dropped, not saved"
            );
            relay.db.shutdown();
        });
    }

    #[test]
    fn has_state_effects_includes_nip43_leave() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay().await;
            let leave = crate::event::Event {
                id: String::new(),
                pubkey: "aa".repeat(32),
                created_at: crate::util::unix_now(),
                kind: crate::nips::nip43::LEAVE,
                tags: Vec::new(),
                content: String::new(),
                sig: String::new(),
            };
            assert!(
                relay.has_state_effects(&leave),
                "a NIP-43 LEAVE mutates role state and must order in batches"
            );
            relay.db.shutdown();
        });
    }

    #[test]
    fn deleting_a_moderation_event_revokes_the_derived_group_state() {
        // NIP-09: deleting the 9002 that made a group private must revoke
        // the in-memory setting (the state is rebuilt from the survivors),
        // not merely remove the stored event.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            use crate::db::PutOutcome;

            let relay = build_relay().await;
            let now = crate::util::unix_now();
            let secp = secp256k1::Secp256k1::new();
            let keypair = secp256k1::Keypair::from_seckey_slice(&secp, &[4u8; 32]).unwrap();
            let pubkey = secp256k1::XOnlyPublicKey::from_keypair(&keypair)
                .0
                .to_string();
            let signed = |kind: u64, tags: Vec<Vec<String>>| {
                let mut e = crate::event::Event {
                    id: String::new(),
                    pubkey: pubkey.clone(),
                    created_at: now,
                    kind,
                    tags,
                    content: String::new(),
                    sig: String::new(),
                };
                e.id = crate::nips::nip01::compute_id(&e);
                let id = e.id_bytes().unwrap();
                e.sig = secp.sign_schnorr_no_aux_rand(&id, &keypair).to_string();
                e
            };
            let mut create = signed(crate::nips::nip29::CREATE_GROUP, Vec::new());
            create.tags.push(vec!["h".into(), "g1".into()]);
            create.id = crate::nips::nip01::compute_id(&create);
            let id = create.id_bytes().unwrap();
            create.sig = secp.sign_schnorr_no_aux_rand(&id, &keypair).to_string();
            assert!(matches!(
                relay.accept_event(create, &[], None).await,
                PutOutcome::Stored
            ));
            let mut edit = signed(9002, vec![vec!["private".into()]]);
            edit.tags.push(vec!["h".into(), "g1".into()]);
            edit.id = crate::nips::nip01::compute_id(&edit);
            let id = edit.id_bytes().unwrap();
            edit.sig = secp.sign_schnorr_no_aux_rand(&id, &keypair).to_string();
            let edit_id = edit.id.clone();
            assert!(matches!(
                relay.accept_event(edit, &[], None).await,
                PutOutcome::Stored
            ));
            assert!(
                relay
                    .groups
                    .read()
                    .await
                    .group("g1")
                    .unwrap()
                    .settings
                    .private
            );
            // The author deletes the 9002: the derived setting must go too.
            let deletion = signed(5, vec![vec!["e".into(), edit_id]]);
            assert!(matches!(
                relay.accept_event(deletion, &[], None).await,
                PutOutcome::Stored
            ));
            let mut converged = false;
            for _ in 0..600 {
                if !relay
                    .groups_rebuild
                    .pending
                    .load(std::sync::atomic::Ordering::SeqCst)
                {
                    converged = true;
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            assert!(converged, "the deletion must trigger the rebuild");
            assert!(
                !relay
                    .groups
                    .read()
                    .await
                    .group("g1")
                    .unwrap()
                    .settings
                    .private,
                "the deleted 9002's private setting must be revoked"
            );
            relay.db.shutdown();
        });
    }

    #[tokio::test]
    async fn relay_allow_command_reports_persistence_failure() {
        let relay = build_relay().await;
        // The writer is gone: the mutation applies in memory but cannot be
        // persisted, and the reply must say so instead of `ok:`.
        relay.db.shutdown();
        let text = relay
            .execute_command(&crate::relay::commands::Command::RelayAllow(
                "aa".repeat(32),
            ))
            .await;
        assert!(text.starts_with("error:"), "{text}");
    }

    /// A NIP-01-signed group event for the rebuild tests.
    fn signed_group_event(
        secp: &secp256k1::Secp256k1<secp256k1::All>,
        keypair: &secp256k1::Keypair,
        kind: u64,
        gid: &str,
        mut tags: Vec<Vec<String>>,
        created_at: u64,
    ) -> crate::event::Event {
        let mut e = crate::event::Event {
            id: String::new(),
            pubkey: secp256k1::XOnlyPublicKey::from_keypair(keypair)
                .0
                .to_string(),
            created_at,
            kind,
            tags: vec![vec!["h".into(), gid.to_string()]],
            content: String::new(),
            sig: String::new(),
        };
        e.tags.append(&mut tags);
        e.id = crate::nips::nip01::compute_id(&e);
        let id = e.id_bytes().unwrap();
        e.sig = secp.sign_schnorr_no_aux_rand(&id, keypair).to_string();
        e
    }

    /// Waits until no rebuild worker is running (successful or failed).
    async fn wait_for_rebuild_worker(relay: &Relay) -> bool {
        for _ in 0..600 {
            if !relay
                .groups_rebuild
                .running
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        false
    }

    #[tokio::test]
    async fn confirmed_purged_group_stays_recreatable_after_a_rebuild() {
        // Regression: `hidden_group_ids` carries the delete tombstones, and
        // a rebuild seeded only from the database scan would ghost a
        // confirmed-purged id (the 9008's purge removed the events, so the
        // scan cannot reconstruct the tombstone) — blocking re-creation
        // forever. The worker re-seeds the captured tombstones.
        let relay = build_relay().await;
        let now = crate::util::unix_now();
        let secp = secp256k1::Secp256k1::new();
        let admin = secp256k1::Keypair::from_seckey_slice(&secp, &[4u8; 32]).unwrap();
        let create = signed_group_event(
            &secp,
            &admin,
            crate::nips::nip29::CREATE_GROUP,
            "g1",
            vec![],
            now.saturating_sub(5),
        );
        assert!(matches!(
            relay.accept_event(create, &[], None).await,
            crate::db::PutOutcome::Stored
        ));
        let delete = signed_group_event(
            &secp,
            &admin,
            crate::nips::nip29::DELETE_GROUP,
            "g1",
            vec![],
            now,
        );
        assert!(matches!(
            relay.accept_event(delete, &[], None).await,
            crate::db::PutOutcome::Stored
        ));
        assert!(relay.groups.read().await.group("g1").is_none());
        // Trigger a rebuild (a vanish of unrelated state does the same).
        relay.mark_group_state_stale().await;
        assert!(
            wait_for_rebuild_worker(&relay).await,
            "the rebuild must finish"
        );
        let recreate = signed_group_event(
            &secp,
            &admin,
            crate::nips::nip29::CREATE_GROUP,
            "g1",
            vec![],
            now.saturating_add(1),
        );
        assert!(
            matches!(
                relay.accept_event(recreate, &[], None).await,
                crate::db::PutOutcome::Stored
            ),
            "a confirmed-purged id must stay re-creatable after a rebuild"
        );
        assert!(relay.groups.read().await.group("g1").is_some());
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn deleting_a_9000_grant_with_9005_revokes_the_membership() {
        // A `9005` delete-event removing a state event must invalidate the
        // derived state (the deleted 9000's grant) like a NIP-09 deletion:
        // the in-memory membership is rebuilt from the survivors.
        let relay = build_relay().await;
        let now = crate::util::unix_now();
        let secp = secp256k1::Secp256k1::new();
        let admin = secp256k1::Keypair::from_seckey_slice(&secp, &[4u8; 32]).unwrap();
        let member_pair = secp256k1::Keypair::from_seckey_slice(&secp, &[8u8; 32]).unwrap();
        let member = secp256k1::XOnlyPublicKey::from_keypair(&member_pair)
            .0
            .to_string();
        let create = signed_group_event(
            &secp,
            &admin,
            crate::nips::nip29::CREATE_GROUP,
            "g1",
            vec![],
            now,
        );
        assert!(matches!(
            relay.accept_event(create, &[], None).await,
            crate::db::PutOutcome::Stored
        ));
        let grant = signed_group_event(
            &secp,
            &admin,
            9000,
            "g1",
            vec![vec!["p".into(), member.clone(), "mod".into()]],
            now,
        );
        let grant_id = grant.id.clone();
        assert!(matches!(
            relay.accept_event(grant, &[], None).await,
            crate::db::PutOutcome::Stored
        ));
        assert!(
            relay
                .groups
                .read()
                .await
                .group("g1")
                .unwrap()
                .is_member(&member)
        );
        let delete = signed_group_event(
            &secp,
            &admin,
            9005,
            "g1",
            vec![vec!["e".into(), grant_id]],
            now,
        );
        assert!(matches!(
            relay.accept_event(delete, &[], None).await,
            crate::db::PutOutcome::Stored
        ));
        assert!(
            wait_for_rebuild_worker(&relay).await,
            "the 9005 must trigger the rebuild"
        );
        assert!(
            !relay
                .groups
                .read()
                .await
                .group("g1")
                .unwrap()
                .is_member(&member),
            "the deleted 9000's grant must be revoked"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn failed_snapshot_clear_keeps_the_state_pending() {
        // A failed clear leaves the stale snapshot on disk; the state must
        // stay pending so the next persist retries the clear instead of
        // assuming the (possibly stale) snapshot is gone.
        let relay = build_relay().await;
        relay
            .groups_rebuild
            .pending
            .store(true, std::sync::atomic::Ordering::SeqCst);
        relay.db.shutdown();
        assert!(
            !relay.persist_groups().await,
            "the failed clear must be reported"
        );
        assert!(
            relay
                .groups_rebuild
                .pending
                .load(std::sync::atomic::Ordering::SeqCst),
            "a failed clear must keep the state pending"
        );
    }

    #[tokio::test]
    async fn failed_rebuild_keeps_the_state_pending() {
        // The failure branch of the worker must keep the snapshot dropped
        // (fail-closed), not treat the incomplete rebuild as current.
        let relay = build_relay().await;
        relay.db.shutdown();
        relay.mark_group_state_stale().await;
        assert!(
            wait_for_rebuild_worker(&relay).await,
            "the failed worker must finish"
        );
        assert!(
            relay
                .groups_rebuild
                .pending
                .load(std::sync::atomic::Ordering::SeqCst),
            "a failed rebuild must keep the state pending"
        );
    }

    #[test]
    fn group_events_accepted_during_a_rebuild_are_buffered_and_replayed() {
        // The scan runs without `groups.write()`; an event accepted while
        // it runs lands on the live store and is captured for replay onto
        // the fresh store, so the swap cannot lose it.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay().await;
            let now = crate::util::unix_now();
            let secp = secp256k1::Secp256k1::new();
            let admin = secp256k1::Keypair::from_seckey_slice(&secp, &[4u8; 32]).unwrap();
            let member_pair = secp256k1::Keypair::from_seckey_slice(&secp, &[8u8; 32]).unwrap();
            let member = secp256k1::XOnlyPublicKey::from_keypair(&member_pair)
                .0
                .to_string();
            let create = signed_group_event(
                &secp,
                &admin,
                crate::nips::nip29::CREATE_GROUP,
                "g1",
                vec![],
                now,
            );
            relay
                .groups
                .write()
                .await
                .apply(&create, "", now, false, false);
            // The worker is scanning: enter its buffering window.
            {
                let mut buffer = relay.groups_rebuild.buffer.lock().await;
                buffer.scanning = true;
                buffer.events.clear();
                buffer.overflow = false;
                buffer.retry = false;
            }
            let grant = signed_group_event(
                &secp,
                &admin,
                9000,
                "g1",
                vec![vec!["p".into(), member.clone(), "mod".into()]],
                now,
            );
            relay.apply_group_event(&grant, now).await;
            let buffered = {
                let mut buffer = relay.groups_rebuild.buffer.lock().await;
                assert_eq!(
                    buffer.events.len(),
                    1,
                    "the accepted event must be captured for replay"
                );
                let events = std::mem::take(&mut buffer.events);
                buffer.scanning = false;
                events
            };
            // The scan completed (the create was part of the history):
            // replay the captured events onto the fresh store and swap.
            let mut fresh = crate::nips::nip29::GroupStore::with_cap(0);
            fresh.apply(&create, "", now, false, true);
            {
                let mut store = relay.groups.write().await;
                for buffered in buffered {
                    fresh.apply(&buffered.event, "", buffered.now, false, true);
                }
                *store = fresh;
            }
            assert!(
                relay
                    .groups
                    .read()
                    .await
                    .group("g1")
                    .unwrap()
                    .is_member(&member),
                "the buffered event must survive the swap"
            );
            relay.db.shutdown();
        });
    }

    #[test]
    fn rebuild_buffer_overflow_forces_a_retry() {
        // A full buffer must not apply a partial event set: the live store
        // still applies the event (reads and metadata stay current), the
        // capture sets `overflow`, and the worker discards the scan.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay().await;
            let now = crate::util::unix_now();
            let secp = secp256k1::Secp256k1::new();
            let admin = secp256k1::Keypair::from_seckey_slice(&secp, &[4u8; 32]).unwrap();
            let member_pair = secp256k1::Keypair::from_seckey_slice(&secp, &[8u8; 32]).unwrap();
            let member = secp256k1::XOnlyPublicKey::from_keypair(&member_pair)
                .0
                .to_string();
            let create = signed_group_event(
                &secp,
                &admin,
                crate::nips::nip29::CREATE_GROUP,
                "g1",
                vec![],
                now,
            );
            relay
                .groups
                .write()
                .await
                .apply(&create, "", now, false, false);
            {
                let mut buffer = relay.groups_rebuild.buffer.lock().await;
                buffer.scanning = true;
                buffer.events.clear();
                buffer.overflow = false;
                buffer.retry = false;
                while buffer.events.len() < GROUPS_REBUILD_BUFFER_MAX {
                    buffer.events.push(BufferedGroupEvent {
                        event: std::sync::Arc::new(create.clone()),
                        now,
                    });
                }
            }
            let grant = signed_group_event(
                &secp,
                &admin,
                9000,
                "g1",
                vec![vec!["p".into(), member.clone(), "mod".into()]],
                now,
            );
            relay.apply_group_event(&grant, now).await;
            {
                let buffer = relay.groups_rebuild.buffer.lock().await;
                assert!(
                    buffer.overflow,
                    "an overflowing buffer must force the worker to discard the scan"
                );
                assert_eq!(
                    buffer.events.len(),
                    GROUPS_REBUILD_BUFFER_MAX,
                    "no partial event set may be kept"
                );
            }
            assert!(
                relay
                    .groups
                    .read()
                    .await
                    .group("g1")
                    .unwrap()
                    .is_member(&member),
                "the live store still applies the overflowing event"
            );
            relay.db.shutdown();
        });
    }

    #[test]
    fn persisted_allowkind_list_is_cleared_without_a_config_allowlist() {
        // The old `allowkind` semantics persisted every runtime allowance
        // into `allowed_kinds`, which `allows_kind` treats as exhaustive:
        // after an upgrade that would brick every kind not on the list. The
        // config allowlist is authoritative, so the stale persisted list is
        // cleared when the config list is empty.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join("nostrfy-allowkind-migration")
                .join(format!("{:x}-{id}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            let mut cfg = crate::config::Config::default();
            cfg.database.path = path;
            cfg.database.map_size = 16 * 1024 * 1024;
            cfg.database.max_map_size = 64 * 1024 * 1024;
            let db = crate::db::DbClient::open(
                &cfg.database,
                true,
                std::sync::Arc::new(Default::default()),
                0,
                128,
                4096,
                262144,
            )
            .unwrap();
            let persisted = crate::config::AccessControl {
                allowed_kinds: vec![1, 9000],
                ..Default::default()
            };
            assert!(
                db.save_access(persisted).await,
                "the legacy access blob must persist"
            );
            let config = std::sync::Arc::new(tokio::sync::RwLock::new(cfg));
            let relay = Relay::new(
                config,
                db,
                crate::stats::Stats::new(),
                "",
                crate::relay::LiveBusConfig {
                    buffer: 1024,
                    batch_interval_ms: 10,
                    batch_size: 64,
                },
            )
            .await;
            let access = relay.access.read().await;
            assert!(
                access.allowed_kinds.is_empty(),
                "the stale persisted allowlist must be cleared"
            );
            assert!(access.allows_kind(1), "every kind must be allowed again");
            drop(access);
            relay.db.shutdown();
        });
    }

    #[tokio::test]
    async fn blossom_command_persists_and_reports_failure() {
        let relay = build_relay().await;
        let pk = "aa".repeat(32);
        let text = relay
            .execute_command(&crate::relay::commands::Command::BlossomAllow(pk.clone()))
            .await;
        assert_eq!(text, format!("ok: /blossom allow {pk}"));
        let stored = relay
            .db
            .load_blossom_allow()
            .await
            .expect("the allowlist must load");
        assert!(stored.contains(&pk), "the entry must be persisted");
        // Revoking a missing entry is a no-op and reports `ok:`.
        let text = relay
            .execute_command(&crate::relay::commands::Command::BlossomDeny(
                "bb".repeat(32),
            ))
            .await;
        assert_eq!(text, "ok: /blossom deny is not on the allowlist");
        // The writer is gone: an applied change must not be reported as ok.
        relay.db.shutdown();
        let text = relay
            .execute_command(&crate::relay::commands::Command::BlossomAllow(
                "cc".repeat(32),
            ))
            .await;
        assert!(text.starts_with("error:"), "{text}");
    }

    #[tokio::test]
    async fn concurrent_blossom_persists_keep_every_entry() {
        // Snapshot capture and write are serialized: without the lock a
        // command that captured an older snapshot could queue its write
        // after a newer one and silently drop an entry on the next restart.
        let relay = build_relay().await;
        for i in 0..16u32 {
            let a = format!("a{i:020x}");
            let b = format!("b{i:020x}");
            let ra = relay.clone();
            let rb = relay.clone();
            let (a2, b2) = (a.clone(), b.clone());
            let ta = tokio::spawn(async move {
                ra.execute_command(&crate::relay::commands::Command::BlossomAllow(a2))
                    .await;
            });
            let tb = tokio::spawn(async move {
                rb.execute_command(&crate::relay::commands::Command::BlossomAllow(b2))
                    .await;
            });
            ta.await.unwrap();
            tb.await.unwrap();
            let stored = relay.db.load_blossom_allow().await.expect("the list loads");
            assert!(
                stored.contains(&a),
                "iteration {i} lost {a}: {} entries persisted",
                stored.len()
            );
            assert!(
                stored.contains(&b),
                "iteration {i} lost {b}: {} entries persisted",
                stored.len()
            );
        }
        relay.db.shutdown();
    }
}
