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
pub(crate) mod roles;
mod validate;

use std::sync::Arc;

use secp256k1::{Keypair, Secp256k1, XOnlyPublicKey};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU64, AtomicUsize, Ordering};
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
    /// The live access state. Runtime mutations must pair an apply with
    /// [`Self::push_access_ops`]: `persist_access` replaces this state with
    /// the persisted view merged with the queued ops, so an unqueued
    /// mutation would be reverted on the next persist (and a reload would
    /// drop it). See [`crate::config::AccessOp`].
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
    /// The coalesced NIP-43 role rebuild that follows a NIP-09 deletion,
    /// NIP-62 vanish or NIP-40 expiry of a role-state event: while stale,
    /// the live store is the fail-closed empty store and `persist_roles`
    /// must not save it (see [`RolesRebuild`]).
    roles_rebuild: std::sync::Arc<RolesRebuild>,
    /// Limits concurrent `/api/v1` queries so a flood of REST traffic
    /// fails fast (503) instead of piling up behind WebSocket work. The
    /// limit is adjustable at runtime (SIGHUP config reload).
    pub api_limit: Arc<ApiLimiter>,
    /// Per-pubkey sliding window of accepted event timestamps
    /// (`relay.max_events_per_min_per_pubkey`). Bounded: at most 10k
    /// pubkeys are tracked — a full map evicts expired windows at most once
    /// per second and otherwise rejects fresh pubkeys (fail-closed, so an
    /// untracked identity cannot bypass the configured limit).
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
    /// Daemon-side access-control mutations not yet written through (see
    /// [`crate::config::AccessOp`]): applied to memory immediately, drained
    /// onto a freshly reloaded persisted state by `persist_access`, and
    /// replayed (not drained) by `reload_db_state`. A plain `Mutex` (never
    /// held across an await) is enough: both drain sites already hold
    /// `persist_access_lock`.
    access_ops: std::sync::Mutex<Vec<crate::config::AccessOp>>,
    /// Serializes `persist_roles` snapshot capture and write (same hazard
    /// as `persist_access_lock`: a stale role snapshot must not overwrite a
    /// newer one). Shared with the role rebuild worker, which persists the
    /// fresh store under the same lock. `persist_groups` uses
    /// `GroupsRebuild::persist_lock`.
    persist_roles_lock: std::sync::Arc<tokio::sync::Mutex<()>>,
    /// Debounced NIP-29/NIP-43 snapshot persistence: the hot mutation paths
    /// set a dirty flag and let one background worker clone+save at most
    /// once per [`SNAPSHOT_PERSIST_INTERVAL_MS`], instead of paying the
    /// O(total state) clone+serialize on every event.
    snapshot_persist: std::sync::Arc<SnapshotPersist>,
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

/// Minimum seconds between two completed role rebuilds, mirroring
/// [`GROUPS_REBUILD_MIN_INTERVAL_SECS`]: a NIP-09 deletion burst (or a
/// client deleting many role-state events) must not run a full role scan
/// per event. Requests arriving inside the window coalesce into the next
/// scan through the dirty flag.
const ROLES_REBUILD_MIN_INTERVAL_SECS: u64 = 2;

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

/// Tracks derived-state mutations between the point their database write is
/// issued and the point their in-memory effect is applied. A snapshot
/// captured in that window would be stamped with the post-commit
/// generation while holding pre-mutation state, and a later startup would
/// accept it; `persist` refuses to save while a mutation is in flight (it
/// simply defers: the mutation path schedules the next debounced save and a
/// removal marks the state stale itself).
#[derive(Default)]
struct DerivedMutationEpoch {
    started: std::sync::atomic::AtomicU64,
    finished: std::sync::atomic::AtomicU64,
}

impl DerivedMutationEpoch {
    fn in_flight(&self) -> bool {
        self.started.load(Ordering::SeqCst) != self.finished.load(Ordering::SeqCst)
    }

    fn begin(&self) -> DerivedMutationGuard<'_> {
        self.started.fetch_add(1, Ordering::SeqCst);
        DerivedMutationGuard { epoch: self }
    }
}

/// Releases one in-flight claim when the in-memory apply completes (or the
/// mutation is abandoned).
struct DerivedMutationGuard<'a> {
    epoch: &'a DerivedMutationEpoch,
}

impl Drop for DerivedMutationGuard<'_> {
    fn drop(&mut self) {
        self.epoch.finished.fetch_add(1, Ordering::SeqCst);
    }
}

/// Result of the post-commit side effects (see [`Relay::after_put`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemovalAck {
    /// The side effects applied; the bool is whether live delivery succeeded.
    Applied(bool),
    /// A required removal (NIP-09 deletion or NIP-29 9005) was not applied
    /// (writer overload): the client must be told to retry, not `OK true`.
    NotApplied,
}

/// Result of a snapshot persist attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PersistOutcome {
    /// The snapshot was written (or a stale one cleared).
    Committed,
    /// A derived mutation was in flight: nothing was written and the state
    /// must not be treated as stale. The next debounced pass retries.
    Deferred,
    /// The intended write failed: the caller must keep the state
    /// fail-closed (pending) so the next startup rebuilds.
    Failed,
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
    /// Failed rebuild attempts (scan failure, discarded buffer, failed
    /// persist): exposed as the `nostrfy_rebuild_failures` counter, which
    /// the startup rebuild (fatal, never counted here) cannot hide.
    failed_rebuilds: std::sync::atomic::AtomicU64,
    /// Single-flight token: only the task that takes it drains the loop.
    lock: tokio::sync::Mutex<()>,
    /// Serializes snapshot capture and write (like `persist_access_lock`):
    /// without it a mutation that captured an older snapshot could queue its
    /// write after a newer one and overwrite it, and a snapshot from before
    /// a vanish could land after the post-vanish clear.
    persist_lock: tokio::sync::Mutex<()>,
    /// Mutations accepted while the scan runs (see [`RebuildBuffer`]).
    buffer: tokio::sync::Mutex<RebuildBuffer>,
    /// Derived-state mutations committed but not yet applied in memory
    /// (see [`DerivedMutationEpoch`]).
    derived: DerivedMutationEpoch,
}

impl Default for GroupsRebuild {
    fn default() -> Self {
        GroupsRebuild {
            dirty: std::sync::atomic::AtomicBool::new(false),
            running: std::sync::atomic::AtomicBool::new(false),
            pending: std::sync::atomic::AtomicBool::new(false),
            last: std::sync::atomic::AtomicU64::new(0),
            rebuilds: std::sync::atomic::AtomicU64::new(0),
            failed_rebuilds: std::sync::atomic::AtomicU64::new(0),
            lock: tokio::sync::Mutex::new(()),
            persist_lock: tokio::sync::Mutex::new(()),
            buffer: tokio::sync::Mutex::new(RebuildBuffer::default()),
            derived: DerivedMutationEpoch::default(),
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
    /// The snapshot carries the database's group-state generation
    /// (`DbClient::state_stamp`) and group-state sequence
    /// (`DbClient::state_seq_group`) so a later restore can reject a snapshot
    /// that predates a state removal or a state event. The generation is
    /// read *before* the capture and re-checked after it: a state change
    /// committed in between advances past the one the captured state can
    /// claim, so the snapshot is dropped. An unavailable generation read
    /// drops the snapshot too (fail-closed): its currency cannot be
    /// established.
    ///
    /// A `Deferred` outcome (a derived mutation was in flight) must not be
    /// treated as a failure: the capture simply could not certify a
    /// generation yet, and a later debounced pass retries. Only `Failed`
    /// requires the caller to keep the state pending (fail-closed).
    async fn persist(&self, db: &DbClient, groups: &RwLock<GroupStore>) -> PersistOutcome {
        let _guard = self.persist_lock.lock().await;
        if self.pending.load(Ordering::SeqCst) {
            return if db.clear_groups_snapshot().await {
                PersistOutcome::Committed
            } else {
                PersistOutcome::Failed
            };
        }
        // A mutation committed to the database but not yet applied in
        // memory: the capture would hold pre-mutation state while claiming
        // the post-commit generation. Defer (do not clear: the mutation
        // path schedules the next save, and a removal marks the state
        // stale itself).
        if self.derived.in_flight() {
            return PersistOutcome::Deferred;
        }
        let Some((stamp, seq)) = read_group_generation(db).await else {
            // The generation is unknown: a snapshot whose currency cannot
            // be established must not be saved. Keep the state pending so
            // every retry stays fail-closed.
            self.pending.store(true, Ordering::SeqCst);
            log::error!(
                "cannot read the group state generation; dropping the persisted snapshot \
                 so the next restart rebuilds from the surviving events"
            );
            return if db.clear_groups_snapshot().await {
                PersistOutcome::Committed
            } else {
                PersistOutcome::Failed
            };
        };
        let mut snapshot = groups.read().await.snapshot();
        if self.pending.load(Ordering::SeqCst) {
            return if db.clear_groups_snapshot().await {
                PersistOutcome::Committed
            } else {
                PersistOutcome::Failed
            };
        }
        if self.derived.in_flight() {
            return PersistOutcome::Deferred;
        }
        match read_group_generation(db).await {
            // A group-state removal committed between the stamp read and
            // the capture (or a state event was stored after it): the
            // in-memory snapshot predates it and must not claim the newer
            // generation. The old snapshot stays on disk with its older
            // generation, so the next startup rejects it and rebuilds.
            Some((current_stamp, current_seq)) if current_stamp > stamp || current_seq > seq => {
                log::error!(
                    "the group state generation advanced while the snapshot was captured; \
                     dropping this save so the next startup rebuilds from the surviving events"
                );
                PersistOutcome::Failed
            }
            // Same fail-closed rule as the first read.
            None => {
                self.pending.store(true, Ordering::SeqCst);
                log::error!(
                    "cannot re-read the group state generation; dropping the persisted \
                     snapshot so the next restart rebuilds from the surviving events"
                );
                if db.clear_groups_snapshot().await {
                    PersistOutcome::Committed
                } else {
                    PersistOutcome::Failed
                }
            }
            Some(_) => {
                snapshot.stamp = stamp;
                snapshot.seq = seq;
                if db.save_groups(snapshot).await {
                    PersistOutcome::Committed
                } else {
                    PersistOutcome::Failed
                }
            }
        }
    }
}

/// Reads the database's derived-state generation for the NIP-29 group
/// family: `(stamp, group_seq)`. `None` when either read failed: a snapshot
/// whose currency cannot be established must not be saved. The per-family
/// sequence means a NIP-43 role event cannot invalidate a group snapshot.
async fn read_group_generation(db: &DbClient) -> Option<(u64, u64)> {
    let stamp = db.state_stamp().await?;
    let seq = db.state_seq_group().await?;
    Some((stamp, seq))
}

/// Reads the database's derived-state generation for the NIP-43 role family
/// (the counterpart of [`read_group_generation`]).
async fn read_role_generation(db: &DbClient) -> Option<(u64, u64)> {
    let stamp = db.state_stamp().await?;
    let seq = db.state_seq_role().await?;
    Some((stamp, seq))
}

/// Bound on the role mutations buffered while a rebuild scan runs. The scan
/// does not hold `roles.write()`, so NIP-86 mutations and NIP-43 leaves
/// accepted meanwhile apply to the live store and are captured here for
/// replay on the fresh one; a burst larger than this cannot be replayed
/// safely, so the worker discards the fresh store and rebuilds again later
/// (the live store keeps serving, and `persist_roles` keeps refusing while
/// the rebuild is dirty). Mirrors [`GROUPS_REBUILD_BUFFER_MAX`].
const ROLES_REBUILD_BUFFER_MAX: usize = 4096;

/// A role mutation accepted while a rebuild is pending or in flight,
/// replayed onto the fresh store once the scan completes. The high-level
/// action (not the published event) is buffered, so a mutation is replayed
/// only when it actually changed the store — except removals the revoked
/// empty store cannot confirm, which callers force-buffer (see
/// [`Relay::apply_leave_request`]).
#[derive(Debug, Clone)]
enum BufferedRoleMutation {
    /// `create_role` / `edit_role` (both install the role definition).
    Create {
        id: String,
        label: String,
        description: String,
        color: String,
        order: Option<i64>,
    },
    Delete {
        id: String,
    },
    Assign {
        pubkey: String,
        role: String,
    },
    Unassign {
        pubkey: String,
        role: String,
    },
    /// `apply_leave_request` / a vanish dropping the pubkey's assignments.
    RemovePubkey {
        pubkey: String,
    },
    /// NIP-86 `createclaim` / `deleteclaim` (invite codes have no events
    /// behind them, so the snapshot is their only persistence).
    CreateClaim {
        claim: String,
    },
    DeleteClaim {
        claim: String,
    },
    /// A `kind:28934` join admitted by invite code.
    AdmitMember {
        pubkey: String,
    },
}

/// Which derived stores a removal of stored events invalidates: a NIP-29
/// moderation/join/leave event rebuilds the group store, a NIP-43 role-state
/// event rebuilds the role store. Kept separate so a NIP-29-only removal
/// does not revoke the live NIP-43 grants (and schedule a full role scan).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct StateTouch {
    groups: bool,
    roles: bool,
}

/// Role mutations accepted while a rebuild scan is in flight (see
/// [`ROLES_REBUILD_BUFFER_MAX`]). The local `Mutex` serializes the capture
/// with the worker's take-and-swap, so no mutation can slip between the
/// two.
#[derive(Default)]
struct RolesRebuildBuffer {
    /// A scan is in flight: role mutations are captured here.
    scanning: bool,
    /// Captured mutations, bounded by [`ROLES_REBUILD_BUFFER_MAX`].
    mutations: Vec<BufferedRoleMutation>,
    /// The buffer is full: the worker must discard the fresh store and
    /// rebuild later instead of applying a partial set.
    overflow: bool,
}

/// Applies one captured mutation to a freshly rebuilt store.
fn replay_role_mutation(store: &mut RoleStore, mutation: &BufferedRoleMutation) {
    match mutation {
        BufferedRoleMutation::Create {
            id,
            label,
            description,
            color,
            order,
        } => store.create(id, label, description, color, *order),
        BufferedRoleMutation::Delete { id } => {
            store.delete(id);
        }
        BufferedRoleMutation::Assign { pubkey, role } => {
            store.assign(pubkey, role);
        }
        BufferedRoleMutation::Unassign { pubkey, role } => {
            store.unassign(pubkey, role);
        }
        BufferedRoleMutation::RemovePubkey { pubkey } => {
            store.remove_pubkey(pubkey);
        }
        BufferedRoleMutation::CreateClaim { claim } => {
            store.add_claim(claim);
        }
        BufferedRoleMutation::DeleteClaim { claim } => {
            store.remove_claim(claim);
        }
        BufferedRoleMutation::AdmitMember { pubkey } => {
            store.admit(pubkey);
        }
    }
}

/// Coordination state for the coalesced NIP-43 role rebuild that follows a
/// NIP-09 deletion, NIP-62 vanish or NIP-40 expiry of a role-state event.
/// Kept in an `Arc` so the background worker can run without borrowing the
/// relay.
///
/// The marking path replaces the live store with an empty one **before** the
/// rebuild runs (revocation): the removed event may have defined a role or
/// granted a membership, and keeping the old grants authorized until the scan
/// completes would leave the deleted grant accepted. The stored snapshot
/// keeps its older generation, so the next startup rejects it and rebuilds
/// from the surviving events. Mutations accepted while the scan runs are
/// buffered and replayed onto the fresh store before the swap (see
/// [`RolesRebuildBuffer`]), so a mutation applied to the fail-closed empty
/// store is not lost when the rebuilt store replaces it.
#[derive(Default)]
struct RolesRebuild {
    /// At least one role-state removal happened since the last completed
    /// rebuild: the live store is the fail-closed empty store and
    /// `persist_roles` must not save it. The worker drains it before a scan
    /// and restores it when the scan fails.
    dirty: std::sync::atomic::AtomicBool,
    /// A worker task owns (or is about to own) the rebuild loop: triggers
    /// only set the flags.
    running: std::sync::atomic::AtomicBool,
    /// Unix seconds of the last completed attempt, the minimum-interval
    /// floor (see [`ROLES_REBUILD_MIN_INTERVAL_SECS`]).
    last: std::sync::atomic::AtomicU64,
    /// Completed scans: tests assert that a NIP-29-only removal schedules
    /// no role scan at all.
    rebuilds: std::sync::atomic::AtomicU64,
    /// Failed rebuild attempts (scan failure, discarded buffer, failed
    /// persist): summed with the group worker's counter by
    /// [`Relay::rebuild_failures`].
    failed_rebuilds: std::sync::atomic::AtomicU64,
    /// Mutations accepted while the scan runs (see [`RolesRebuildBuffer`]).
    buffer: tokio::sync::Mutex<RolesRebuildBuffer>,
    /// Derived-state mutations committed but not yet applied in memory
    /// (see [`DerivedMutationEpoch`]).
    derived: DerivedMutationEpoch,
}

impl RolesRebuild {
    /// Releases the buffering window after a failed or aborted scan, or on
    /// shutdown before a scan starts. The buffered mutations were applied
    /// to the live store, which stays authoritative; the fresh store is
    /// discarded. Buffered leaves that never reached the live store (the
    /// revoked window) are lost here: they are counted and warned about
    /// so the operator knows a re-leave may be needed.
    async fn leave_buffering(&self) {
        let mut buffer = self.buffer.lock().await;
        buffer.scanning = false;
        // A dropped leave (buffered while the live store was revoked, never
        // applied to it) resurrects its member on the next rebuild: the
        // remove-user event published for it keeps clients correct, but the
        // rebuild only honors membership lists. Surface the count so the
        // operator knows a re-leave may be needed.
        let dropped_leaves = buffer
            .mutations
            .iter()
            .filter(|m| matches!(m, BufferedRoleMutation::RemovePubkey { .. }))
            .count();
        if dropped_leaves > 0 {
            log::warn!(
                "role state rebuild abandoned with {dropped_leaves} buffered leave(s) unapplied; \
                 affected members may resurface until they leave again"
            );
        }
        buffer.mutations.clear();
        buffer.overflow = false;
    }

    /// Applies the buffered mutations to `fresh` and swaps it into the live
    /// store, atomically against the mutation capture. The buffer lock is
    /// held across the replay **and** the swap: a mutation accepted in the
    /// gap between taking the buffer and taking `roles.write` would see
    /// `scanning == false` and apply to the live store, and the swap would
    /// then overwrite it with a fresh store that predates it (silently
    /// losing the mutation). Holding the lock makes every mutation either
    /// land in `buffered` or wait and apply to the swapped-in store.
    ///
    /// Returns false when the buffer overflowed or a removal landed while
    /// the scan ran: the fresh store is discarded and the dirty flag stays
    /// set so the worker rebuilds again instead of swapping a state that
    /// predates the lost mutations.
    async fn finish_rebuild(&self, roles: &RwLock<RoleStore>, mut fresh: RoleStore) -> bool {
        let mut buffer = self.buffer.lock().await;
        let buffered = std::mem::take(&mut buffer.mutations);
        let overflow = buffer.overflow;
        buffer.overflow = false;
        buffer.scanning = false;
        if overflow {
            self.dirty.store(true, Ordering::SeqCst);
            self.failed_rebuilds
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            log::warn!(
                "role state rebuild discarded: the mutation buffer overflowed during the \
                 scan; rebuilding again"
            );
            return false;
        }
        let mut store = roles.write().await;
        for mutation in &buffered {
            replay_role_mutation(&mut fresh, mutation);
        }
        *store = fresh;
        if self.dirty.load(Ordering::SeqCst) {
            // A removal landed while the scan ran (or during the swap): the
            // fresh store may predate it and the swap may have reinstated a
            // removed grant. Restore the fail-closed empty store and let
            // the worker rebuild again.
            *store = RoleStore::default();
            self.failed_rebuilds
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return false;
        }
        true
    }
}

/// Marks the role state stale, revokes the live grants and schedules the
/// coalesced background rebuild (single-flight via the `running` flag).
fn schedule_roles_rebuild(
    db: DbClient,
    roles: std::sync::Arc<RwLock<RoleStore>>,
    relay_pubkey: String,
    persist_lock: std::sync::Arc<tokio::sync::Mutex<()>>,
    state: std::sync::Arc<RolesRebuild>,
    drain: tokio::sync::watch::Receiver<bool>,
) {
    if *drain.borrow() {
        return;
    }
    if state.running.swap(true, Ordering::SeqCst) {
        // A worker is already draining; its loop re-checks the dirty flag
        // before it exits, so this request is covered.
        return;
    }
    tokio::spawn(roles_rebuild_worker(
        db,
        roles,
        relay_pubkey,
        persist_lock,
        state,
        drain,
    ));
}

/// The coalesced role rebuild worker. Holds the single-flight token, drains
/// the dirty flag and swaps a freshly rebuilt store into the live one.
///
/// The scan runs **without** the roles lock: a full-history paged scan must
/// not stall role authorization, and the live store is the fail-closed empty
/// store meanwhile. The swap and the persist happen under the short final
/// locks. The worker observes the relay's drain signal: it refuses to start a
/// scan after shutdown and aborts an in-flight scan at its next await. Either
/// way the live store stays fail-closed and the dirty flag stays set, so the
/// next startup rebuilds from the surviving events.
async fn roles_rebuild_worker(
    db: DbClient,
    roles: std::sync::Arc<RwLock<RoleStore>>,
    relay_pubkey: String,
    persist_lock: std::sync::Arc<tokio::sync::Mutex<()>>,
    state: std::sync::Arc<RolesRebuild>,
    mut drain: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        // Shutdown: stop before starting another scan. The removal that
        // dirtied the state already cleared the live store, so the next
        // startup rebuilds from the surviving events. Buffered captures
        // (e.g. a leave accepted while revoked) are reported and dropped:
        // the process is dying, so they can never replay.
        if *drain.borrow() {
            state.leave_buffering().await;
            break;
        }
        if !state.dirty.swap(false, Ordering::SeqCst) {
            break;
        }
        // The first scan runs immediately (`last == 0`); later requests wait
        // out the remainder of the interval. Requests that arrive while
        // waiting coalesce into this rebuild (the flag is drained above, and
        // any later trigger sets it again); a shutdown aborts the wait
        // without starting the scan.
        let elapsed = unix_now().saturating_sub(state.last.load(Ordering::Relaxed));
        if elapsed < ROLES_REBUILD_MIN_INTERVAL_SECS {
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(
                    ROLES_REBUILD_MIN_INTERVAL_SECS - elapsed,
                )) => {}
                _ = drain.changed() => {
                    state.dirty.store(true, Ordering::SeqCst);
                    state.leave_buffering().await;
                    break;
                }
            }
        }
        // Enter the buffering window *before* the scan starts: a mutation
        // accepted meanwhile is captured and replayed onto the fresh store,
        // so it cannot be lost when the rebuilt store replaces the live one.
        // Captures from the pre-scan gap (marked, worker not yet walking)
        // are kept: they belong to this pending window, and clearing them
        // here would drop removals the revoked store could not confirm.
        {
            let mut buffer = state.buffer.lock().await;
            buffer.scanning = true;
            buffer.overflow = false;
        }
        let mut fresh = RoleStore::default();
        // The scan must not outlive a shutdown: abort it at its next await
        // and keep the state dirty, so the live store stays fail-closed.
        let rebuilt = tokio::select! {
            rebuilt = fresh.rebuild(&db, &relay_pubkey) => rebuilt,
            _ = drain.changed() => {
                state.dirty.store(true, Ordering::SeqCst);
                state.leave_buffering().await;
                log::warn!(
                    "role state rebuild aborted by shutdown; keeping the live role store \
                     empty (fail-closed) so the next startup rebuilds from the surviving \
                     events"
                );
                break;
            }
        };
        state.last.store(unix_now(), Ordering::Relaxed);
        state.rebuilds.fetch_add(1, Ordering::Relaxed);
        if !rebuilt {
            // Keep the fail-closed empty store and leave the state dirty:
            // the next role-state removal schedules another attempt, and a
            // restart rebuilds from the surviving events. The buffered
            // mutations were applied to the live store, which stays.
            state.dirty.store(true, Ordering::SeqCst);
            state
                .failed_rebuilds
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            state.leave_buffering().await;
            log::error!(
                "role state rebuild failed; keeping the live role store empty (fail-closed) \
                 and retrying on the next role-state removal"
            );
            state.running.store(false, Ordering::SeqCst);
            // The worker is done: drop the post-swap captures it may have
            // accepted while still marked running. They were applied to the live
            // store (and scheduled for persistence) like normal mutations, so
            // replaying them in a later rebuild would wrongly re-apply stale
            // intent. Clearing runs after `running` is already false, so a racing
            // mutation either lands before the clear (applied live, safe to drop)
            // or after it (sees a closed window and stays live-only, like normal).
            {
                let mut buffer = state.buffer.lock().await;
                buffer.mutations.clear();
                buffer.overflow = false;
            }
            return;
        }
        if state.dirty.load(Ordering::SeqCst) {
            // A role-state removal committed while the scan ran: the fresh
            // store may predate it. Keep the fail-closed live store and
            // rebuild again. The buffered mutations are kept for the
            // rescan — they were accepted during the same pending window,
            // so dropping them here would lose removals the revoked store
            // could not confirm.
            continue;
        }
        // Replay the mutations accepted during the scan onto the fresh
        // store and swap it in, atomically against the mutation capture.
        // An overflow discards the fresh store and rebuilds again instead
        // of swapping a state that predates the lost mutations.
        if !state.finish_rebuild(&roles, fresh).await {
            continue;
        }
        // Persist the fresh store under the mutation-serializing lock. A
        // mutation that lands in the meantime is refused persistence (the
        // state is not established yet) and a removal clears the store
        // again; the loop then rebuilds with the surviving state.
        let _persist = persist_lock.lock().await;
        if persist_fresh_roles(&db, &roles, &state).await == PersistOutcome::Failed {
            state
                .failed_rebuilds
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            log::error!(
                "could not persist the rebuilt role state; the stored snapshot keeps its \
                 older stamp so the next startup rebuilds from the surviving events"
            );
        }
    }
    state.running.store(false, Ordering::SeqCst);
    // A removal that arrived after the loop's last dirty check (while
    // `running` was still set) saw a running worker and did not spawn one:
    // re-check and reschedule. A signaled drain keeps the state dirty
    // (fail-closed) instead so the next startup rebuilds.
    if state.dirty.load(Ordering::SeqCst) && !*drain.borrow() {
        schedule_roles_rebuild(db, roles, relay_pubkey, persist_lock, state, drain);
    }
}

/// Saves the live role store with the database's current generation stamp
/// and sequence. The rebuild worker calls this after it swapped a fresh
/// store and holds the single-flight claim: the worker re-checks the dirty
/// flag around the swap, so the store is not stale here.
async fn persist_fresh_roles(
    db: &DbClient,
    roles: &RwLock<RoleStore>,
    state: &RolesRebuild,
) -> PersistOutcome {
    // A role mutation committed but not yet applied in memory: the capture
    // would hold pre-mutation state while claiming the post-commit
    // generation. Defer; the mutation path schedules the next save.
    if state.derived.in_flight() {
        return PersistOutcome::Deferred;
    }
    let Some((stamp, seq)) = read_role_generation(db).await else {
        log::error!(
            "cannot read the state generation; keeping the persisted NIP-43 role \
             snapshot so the next startup rebuilds from the surviving events"
        );
        return PersistOutcome::Failed;
    };
    let mut snapshot = roles.read().await.snapshot();
    // A removal that landed after the swap check replaced the live store
    // with the fail-closed empty one: saving it with the current generation
    // would make the next startup accept state that predates the removal.
    if state.dirty.load(Ordering::SeqCst) {
        return PersistOutcome::Failed;
    }
    if state.derived.in_flight() {
        return PersistOutcome::Deferred;
    }
    snapshot.stamp = stamp;
    snapshot.seq = seq;
    if db.save_roles(snapshot).await {
        PersistOutcome::Committed
    } else {
        PersistOutcome::Failed
    }
}

/// Captures and saves the live role store under the mutation-serializing
/// lock (used by [`Relay::persist_roles`] and the debounced snapshot
/// worker).
///
/// The snapshot carries the database's state generation
/// (`DbClient::state_stamp`) and role-state sequence
/// (`DbClient::state_seq_role`) so a later restore can reject a snapshot
/// that predates a NIP-09 deletion of a role-state event or a role-state
/// event itself. The generation is read *before* the capture: a change
/// committed in between leaves the snapshot with the older generation, so
/// the startup comparison rejects it. An unavailable generation read leaves
/// the pre-existing snapshot untouched (its currency cannot be
/// established).
///
/// While a role rebuild is dirty/running the store is known stale (or owned
/// by the worker): the write is refused (`Failed`) so the stale store cannot
/// be stamped with the already-advanced generation (which would make the next
/// startup accept it). A derived mutation in flight (`Deferred`) only skips
/// this pass; the mutation path schedules the next one.
async fn persist_roles_now(
    db: &DbClient,
    roles: &RwLock<RoleStore>,
    state: &RolesRebuild,
    lock: &tokio::sync::Mutex<()>,
) -> PersistOutcome {
    let _guard = lock.lock().await;
    // A stale store must never overwrite the stored snapshot: while a
    // removal is pending a rebuild (`dirty`) or a worker owns the state
    // (`running`), the live store is the fail-closed empty store or a
    // store that may predate the removal, and stamping it with the
    // already-advanced generation would make the next startup accept it.
    // The stored snapshot keeps its older generation, so startup rejects it
    // and rebuilds from the surviving events.
    let stale = || state.dirty.load(Ordering::SeqCst) || state.running.load(Ordering::SeqCst);
    if stale() {
        return PersistOutcome::Failed;
    }
    if state.derived.in_flight() {
        return PersistOutcome::Deferred;
    }
    let Some((stamp, seq)) = read_role_generation(db).await else {
        log::error!(
            "cannot read the state generation; keeping the persisted NIP-43 role \
             snapshot so the next startup rebuilds from the surviving events"
        );
        return PersistOutcome::Failed;
    };
    let mut snapshot = roles.read().await.snapshot();
    // Re-check after the capture: a removal that landed while the store
    // was being captured must not have its pre-removal grants stamped
    // with the removal's generation.
    if stale() {
        return PersistOutcome::Failed;
    }
    if state.derived.in_flight() {
        return PersistOutcome::Deferred;
    }
    snapshot.stamp = stamp;
    snapshot.seq = seq;
    if db.save_roles(snapshot).await {
        PersistOutcome::Committed
    } else {
        PersistOutcome::Failed
    }
}

/// Marks the group state stale and schedules the coalesced background
/// rebuild (single-flight via the state's lock and the `running` flag).
/// A signaled drain never starts a worker: the state stays pending (the
/// removal that scheduled the rebuild set it), so the snapshot stays
/// dropped and the next startup rebuilds from the surviving events.
fn schedule_groups_rebuild(
    db: DbClient,
    groups: std::sync::Arc<RwLock<GroupStore>>,
    config: std::sync::Arc<RwLock<Config>>,
    relay_pubkey: Option<String>,
    state: std::sync::Arc<GroupsRebuild>,
    drain: tokio::sync::watch::Receiver<bool>,
) {
    if *drain.borrow() {
        return;
    }
    if state.running.swap(true, Ordering::SeqCst) {
        // A worker is already draining; it re-checks the dirty flag before
        // it exits, so this request is covered.
        return;
    }
    tokio::spawn(groups_rebuild_worker(
        db,
        groups,
        config,
        relay_pubkey,
        state,
        drain,
    ));
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
///
/// The worker observes the relay's drain signal: it refuses to start a
/// scan after shutdown, aborts the interval wait, and drops an in-flight
/// scan future at its next await. An aborted rebuild keeps the state
/// pending, so the snapshot stays dropped and the next startup rebuilds
/// from the surviving events (fail-closed) instead of running a
/// full-history pass after shutdown.
async fn groups_rebuild_worker(
    db: DbClient,
    groups: std::sync::Arc<RwLock<GroupStore>>,
    config: std::sync::Arc<RwLock<Config>>,
    relay_pubkey: Option<String>,
    state: std::sync::Arc<GroupsRebuild>,
    mut drain: tokio::sync::watch::Receiver<bool>,
) {
    {
        // Scope the single-flight guard so it is released before the
        // trailing re-schedule below (which may move `state`).
        let _single_flight = state.lock.lock().await;
        loop {
            // Shutdown: stop before starting another scan. The removal that
            // dirtied the state already set the pending flag, so the
            // snapshot stays dropped and the next startup rebuilds from the
            // surviving events.
            if *drain.borrow() {
                state.pending.store(true, Ordering::SeqCst);
                break;
            }
            if !state.dirty.swap(false, Ordering::SeqCst) {
                break;
            }
            // The first scan runs immediately (`last == 0`); later requests
            // wait out the remainder of the interval. Requests that arrive
            // while waiting coalesce into this rebuild (the flag is drained
            // above, and any later trigger sets it again); a shutdown
            // aborts the wait without starting the scan.
            let elapsed = unix_now().saturating_sub(state.last.load(Ordering::Relaxed));
            if elapsed < GROUPS_REBUILD_MIN_INTERVAL_SECS {
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(
                        GROUPS_REBUILD_MIN_INTERVAL_SECS - elapsed,
                    )) => {}
                    _ = drain.changed() => {
                        state.pending.store(true, Ordering::SeqCst);
                        break;
                    }
                }
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
            // The scan must not outlive a shutdown: abort it at its next
            // await (a page query) and keep the state pending. The fresh
            // store is local and was never swapped in, so the live store
            // stays authoritative and the snapshot stays dropped
            // (fail-closed) until a later startup rebuild completes.
            let rebuilt = tokio::select! {
                rebuilt = fresh.rebuild_after_vanish(
                    &db,
                    relay_pubkey.as_deref(),
                    previous,
                    previous_deleted,
                    previous_ghost,
                ) => rebuilt,
                _ = drain.changed() => {
                    let mut buffer = state.buffer.lock().await;
                    buffer.scanning = false;
                    buffer.events.clear();
                    buffer.retry = false;
                    buffer.overflow = false;
                    drop(buffer);
                    log::warn!(
                        "group state rebuild aborted by shutdown; keeping the persisted \
                         snapshot dropped so the next startup rebuilds from the surviving events"
                    );
                    state.pending.store(true, Ordering::SeqCst);
                    break;
                }
            };
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
                state
                    .failed_rebuilds
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
                    state
                        .failed_rebuilds
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
            if state.persist(&db, &groups).await == PersistOutcome::Failed {
                // A failed save is not durable state, and a failed clear
                // left the stale snapshot on disk: keep pending so the next
                // persist retries the clear instead of treating the state
                // as clean. A `Deferred` pass (a mutation was in flight) is
                // retried by the debounced worker instead.
                state
                    .failed_rebuilds
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
    // true` and did not spawn, so it must not be lost. After a drain the
    // re-schedule is suppressed: the pending flag stays set (fail-closed)
    // and the next startup rebuilds instead.
    state.running.store(false, Ordering::SeqCst);
    if state.dirty.load(Ordering::SeqCst) && !*drain.borrow() {
        schedule_groups_rebuild(db, groups, config, relay_pubkey, state, drain);
    }
}

/// Minimum time between two debounced snapshot passes. A burst of group or
/// role mutations coalesces into one clone+serialize per store instead of
/// one per event; correctness never depends on the debounce, because every
/// state event advances its family's database sequence (`state_seq_group` /
/// `state_seq_role`) and a snapshot that was skipped (or a crash before the
/// worker ran) is rejected
/// at startup and rebuilt from the surviving events.
const SNAPSHOT_PERSIST_INTERVAL_MS: u64 = 1_000;

/// Debounced persistence of the NIP-29 group and NIP-43 role snapshots.
/// The mutation paths only set a dirty flag and schedule the single
/// background worker, so the O(total state) clone+serialize stays off the
/// event path (see [`SNAPSHOT_PERSIST_INTERVAL_MS`]). Rare fail-closed
/// paths (a pre-delete ghost, a stale-state clear or the rebuild workers)
/// keep using the immediate `persist_groups`/`persist_roles` calls.
#[derive(Default)]
struct SnapshotPersist {
    /// A group/role mutation happened since the last debounced pass.
    groups_dirty: AtomicBool,
    roles_dirty: AtomicBool,
    /// A worker task owns (or is about to own) the debounce loop.
    running: AtomicBool,
}

impl SnapshotPersist {
    fn any_dirty(&self) -> bool {
        self.groups_dirty.load(Ordering::SeqCst) || self.roles_dirty.load(Ordering::SeqCst)
    }
}

/// The handles the debounced snapshot worker needs. Bundled into one value
/// so the scheduler and the worker stay under the argument-count lint as the
/// set of persisted stores grows.
struct SnapshotPersistCtx {
    db: DbClient,
    groups: Arc<RwLock<GroupStore>>,
    groups_rebuild: Arc<GroupsRebuild>,
    roles: Arc<RwLock<RoleStore>>,
    roles_rebuild: Arc<RolesRebuild>,
    persist_roles_lock: Arc<tokio::sync::Mutex<()>>,
    state: Arc<SnapshotPersist>,
}

/// Marks the store dirty and wakes the single debounce worker. A mutation
/// that arrives after the worker's last dirty check but before it releases
/// the `running` claim schedules a new worker (the worker re-checks before
/// exiting), so a dirty flag cannot be lost.
fn schedule_snapshot_persist(ctx: SnapshotPersistCtx, drain: tokio::sync::watch::Receiver<bool>) {
    if *drain.borrow() {
        return;
    }
    if ctx.state.running.swap(true, Ordering::SeqCst) {
        // A worker is already draining; its loop re-checks the dirty flags
        // before it exits, so this request is covered.
        return;
    }
    tokio::spawn(snapshot_persist_worker(ctx, drain));
}

/// The debounce worker: waits out one coalescing interval (aborted by
/// shutdown), then saves each dirty store at most once. Skipping a save is
/// always safe (the database sequence detects the staleness at startup), so
/// a drain stops the loop after one final best-effort pass.
async fn snapshot_persist_worker(
    ctx: SnapshotPersistCtx,
    mut drain: tokio::sync::watch::Receiver<bool>,
) {
    let SnapshotPersistCtx {
        db,
        groups,
        groups_rebuild,
        roles,
        roles_rebuild,
        persist_roles_lock,
        state,
    } = ctx;
    loop {
        // The coalescing window: every mutation arriving before it elapses
        // folds into this pass. A shutdown aborts the wait and still
        // attempts one final save (best-effort: correctness does not depend
        // on it, see [`SNAPSHOT_PERSIST_INTERVAL_MS`]).
        if !*drain.borrow() {
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_millis(
                    SNAPSHOT_PERSIST_INTERVAL_MS,
                )) => {}
                _ = drain.changed() => {}
            }
        }
        if state.groups_dirty.swap(false, Ordering::SeqCst) {
            groups_rebuild.persist(&db, &groups).await;
        }
        if state.roles_dirty.swap(false, Ordering::SeqCst) {
            persist_roles_now(&db, &roles, &roles_rebuild, &persist_roles_lock).await;
        }
        if *drain.borrow() {
            break;
        }
        if state.any_dirty() {
            continue;
        }
        state.running.store(false, Ordering::SeqCst);
        if state.any_dirty() {
            // A mutation set a dirty flag between the check and the
            // release: either re-claim the loop or let the scheduler that
            // saw `running == false` own it.
            if state.running.swap(true, Ordering::SeqCst) {
                break;
            }
            continue;
        }
        break;
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
        let access = match db.load_access().await {
            crate::db::LoadAccessOutcome::Loaded(access) => (access, Vec::new()),
            crate::db::LoadAccessOutcome::Missing => {
                // First run: the config seeds both memory and (via the op
                // log) the first persist, so the seed survives the
                // write-through merge instead of being overwritten by the
                // empty database state.
                let seed = config.read().await.access.clone();
                let ops = crate::config::access_seed_ops(&seed);
                (seed, ops)
            }
            crate::db::LoadAccessOutcome::Failed => {
                // A failed read must not be mistaken for "nothing was ever
                // persisted": the config seed would silently replace the
                // persisted NIP-86 bans/IP blocks with it (fail-open).
                log::error!("cannot load the persisted access control state; refusing to start");
                std::process::exit(1);
            }
        };
        let (mut access, mut seed_ops) = access;
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
            // Clear through the op log (not just in memory) so the next
            // write-through persist completes the migration in the
            // database too instead of resurrecting the stale list.
            for kind in std::mem::take(&mut access.allowed_kinds) {
                seed_ops.push(crate::config::AccessOp::UnallowKind { kind });
            }
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
            roles_rebuild: std::sync::Arc::new(RolesRebuild::default()),
            api_limit: ApiLimiter::new(api_max_concurrent),
            publish_rate: std::sync::Mutex::new(HashMap::new()),
            publish_rate_pruned_at: std::sync::atomic::AtomicU64::new(0),
            persist_access_lock: tokio::sync::Mutex::new(()),
            access_ops: std::sync::Mutex::new(seed_ops),
            persist_roles_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            snapshot_persist: std::sync::Arc::new(SnapshotPersist::default()),
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
        // `send_replace` (not `send`): tokio's `send` is a no-op when no
        // receiver is subscribed right now, which would leave the signal
        // unrecorded and let a later `subscribe_drain` see `false` (a
        // removal arriving after shutdown could then schedule a rebuild).
        self.drain_tx.send_replace(true);
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
    /// Queues daemon-side access-control mutations for write-through
    /// persistence (see [`crate::config::AccessOp`]). The caller applies
    /// them to memory first (live enforcement); `persist_access` drains
    /// them onto a freshly reloaded persisted state. A plain `Mutex`
    /// suffices: pushes are synchronous and short, and both drain sites
    /// hold `persist_access_lock`.
    pub(crate) fn push_access_ops(&self, ops: Vec<crate::config::AccessOp>) {
        let mut queued = self
            .access_ops
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        queued.extend(ops);
        // No cap: dropping queued intent would lose bans (fail-open). The
        // queue drains on every successful persist and only grows while
        // the database is failing, when the relay is broken anyway.
        if queued.len() > 1024 {
            log::warn!(
                "access op log holds {} unpersisted mutations; the database is not accepting writes",
                queued.len()
            );
        }
    }

    /// Drains the queued daemon access ops (see [`Self::push_access_ops`]).
    /// Used by `persist_access`; the queue is restored on failure so a
    /// later persist retries the same intent.
    fn take_access_ops(&self) -> Vec<crate::config::AccessOp> {
        std::mem::take(
            &mut *self
                .access_ops
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        )
    }

    /// Restores drained ops after a failed write, preserving order (the
    /// failed batch is older than anything queued meanwhile).
    fn unwrite_access_ops(&self, mut ops: Vec<crate::config::AccessOp>) {
        let mut queued = self
            .access_ops
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        ops.append(&mut *queued);
        *queued = ops;
    }

    /// Persists the access state (see [`Self::push_access_ops`]): reloads
    /// the persisted access blob and pubkey lists fresh, replays the queued
    /// daemon ops onto them, and writes the merged state in one
    /// transaction. A concurrent CLI write is therefore merged instead of
    /// overwritten (the old snapshot-then-write lost whichever side
    /// committed first). The merged state becomes the live truth, so a CLI
    /// change is enforced immediately, not just at the next SIGHUP.
    /// Returns whether the write committed: the NIP-86 methods surface a
    /// failure instead of reporting a change that is only in memory. A
    /// failed load or write restores the op queue and reports `false`
    /// (fail-closed and retryable); the in-memory mutations stay live.
    ///
    /// The snapshot and write hold the cross-process `access.lock` shared
    /// with the CLI's read-modify-write (`src/cli.rs`): a CLI mutation can
    /// no longer land between the reload and the write. The blocking
    /// `flock` is acquired on the blocking pool and the guard is held
    /// across the database awaits; the CLI never waits on the daemon, so
    /// the ordering cannot deadlock. When the lock cannot be taken the
    /// write is refused (`false`) instead of proceeding unserialized.
    pub async fn persist_access(&self) -> bool {
        let db_path = self.config.read().await.database.path.clone();
        let _guard = self.persist_access_lock.lock().await;
        // The cross-process lock is taken *before* the reload so the CLI
        // cannot slip a read-modify-write between the capture and the write.
        let Some(_state_lock) = crate::db::lock_access_state_async(db_path).await else {
            log::warn!("cannot take the access state lock; refusing the access write");
            return false;
        };
        let ops = self.take_access_ops();
        // Reload the persisted state fresh (fail closed on load error):
        // merging onto it is what keeps a concurrent CLI write.
        let (Some(mut merged), Some((deny, allow))) = (
            self.db.try_load_access().await,
            self.db.try_load_relay_pubkeys().await,
        ) else {
            log::warn!("cannot reload the persisted access state; refusing the access write");
            self.unwrite_access_ops(ops);
            return false;
        };
        merged.blocked_pubkeys = deny;
        merged.allowed_pubkeys = allow;
        for op in &ops {
            crate::config::apply_access_op(&mut merged, op);
        }
        // `restrict_relay` is config-owned (the reload always takes it from
        // the config file): never let a stale persisted blob regress it.
        merged.restrict_relay = self.config.read().await.access.restrict_relay;
        // The pubkey lists are excluded from the `access` blob and kept in
        // their own LMDB key so the CLI and NIP-86 share one source. The
        // blob and both lists commit in one transaction: a crash (or a
        // failed second write) must not leave the NIP-86 ban list ahead of
        // the persisted access blob.
        let deny = merged.blocked_pubkeys.clone();
        let allow = merged.allowed_pubkeys.clone();
        if !self
            .db
            .save_access_and_pubkeys(&merged, &deny, &allow)
            .await
        {
            self.unwrite_access_ops(ops);
            return false;
        }
        *self.access.write().await = merged;
        true
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
                    // Merge, don't overwrite: a daemon mutation applied to
                    // memory but not yet persisted (its op is still queued)
                    // must survive the reload, and a concurrent CLI write
                    // must survive too. Replaying the queued ops onto the
                    // freshly loaded lists keeps both (every op is
                    // idempotent, so replaying an already-persisted op is
                    // harmless).
                    let ops: Vec<crate::config::AccessOp> = self
                        .access_ops
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .clone();
                    let mut access = self.access.write().await;
                    access.blocked_pubkeys = deny;
                    access.allowed_pubkeys = allow;
                    for op in &ops {
                        crate::config::apply_access_op(&mut access, op);
                    }
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

    /// Failed runtime derived-state rebuilds (group + role) since startup.
    /// The startup rebuild is fatal and never reaches this counter; this is
    /// the background rebuild worker's failure total, exposed as the
    /// `nostrfy_rebuild_failures` metric.
    pub(crate) fn rebuild_failures(&self) -> u64 {
        self.groups_rebuild
            .failed_rebuilds
            .load(Ordering::Relaxed)
            .saturating_add(self.roles_rebuild.failed_rebuilds.load(Ordering::Relaxed))
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
    pub async fn persist_relay_field(&self, field: &str, value: &str) -> bool {
        let Some(path) = self.config_path.read().await.clone() else {
            log::warn!(
                "cannot persist relay.{field}: the config file path is unknown \
                 (running without a config file?); the change applies until the \
                 next config reload"
            );
            return false;
        };
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                let updated = match crate::config::rewrite_config_checked(
                    &text,
                    "relay",
                    field,
                    &format!("\"{}\"", crate::config::toml_escape(value)),
                ) {
                    Ok(updated) => updated,
                    Err(e) => {
                        log::warn!(
                            "cannot persist relay.{field} to {}: {e}; the change applies \
                             until the next config reload",
                            path.display()
                        );
                        return false;
                    }
                };
                if let Err(e) = crate::config::write_text_atomic(&path, &updated) {
                    log::warn!(
                        "cannot persist relay.{field} to {}: {e}; the change applies \
                         until the next config reload",
                        path.display()
                    );
                    return false;
                }
                true
            }
            Err(e) => {
                log::warn!(
                    "cannot read {} to persist relay.{field}: {e}",
                    path.display()
                );
                false
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
        let known = known_prefixes.map(|known| crate::relay::validate::KnownPrevious {
            known,
            // The single-event path never caps its per-reference lookups.
            capped: false,
        });
        self.accept_event_verified(event, authed, known.as_ref(), None)
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
        known_prefixes: Option<&crate::relay::validate::KnownPrevious<'_>>,
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
            crate::relay::validate::Precheck::Admit(msg) => {
                // NIP-43 join by invite code (ephemeral, never stored):
                // record the membership like a vanish records its removal
                // (the access gates above are intentionally bypassed for
                // the admission itself: the code is the authorization).
                // The event pubkey was signature-verified before the
                // precheck, so it names the joiner.
                drop(cfg);
                drop(access);
                if !self.admit_member(&event.pubkey).await {
                    // NIP-43 is disabled or the relay key is missing: the
                    // membership was not recorded, so a welcome would lie.
                    self.stats.bump(&self.stats.events_rejected, 1);
                    return PutOutcome::Invalid(
                        "error: membership could not be recorded; retry".into(),
                    );
                }
                // Acknowledged without storing (the welcome text rides the
                // duplicate-style ack): counted like the member-rejoin
                // verdict below.
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
                if !self.vanish_pubkey(pubkey, event.created_at).await {
                    // The removal side effect (and its recoverable pending
                    // record) was not applied: a `true` ack would tell the
                    // client the vanish took effect while the pubkey can
                    // keep publishing. Report a retryable failure instead.
                    self.stats.bump(&self.stats.events_rejected, 1);
                    return PutOutcome::Invalid(
                        "error: database overloaded: vanish was not applied; retry".into(),
                    );
                }
                // A vanish request is accepted like any other event (the
                // OK:true is sent): count it so the accepted/rejected
                // accounting stays consistent with the OKs.
                self.stats.bump(&self.stats.events_accepted, 1);
                return PutOutcome::Stored;
            }
            crate::relay::validate::Precheck::Accept => {}
        }

        // A stored NIP-29 group action mutates the derived group state in
        // `after_put`, after its database write committed. The in-flight
        // claim keeps a concurrent snapshot persist from certifying the
        // post-commit state generation while the in-memory apply is still
        // pending (see [`DerivedMutationEpoch`]).
        let _group_mutation = (cfg.nip_enabled(29) && nip29::is_group_action(&event))
            .then(|| self.groups_rebuild.derived.begin());

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
                match self.after_put(event, now, nip9, nip43, nip29_enabled).await {
                    RemovalAck::Applied(delivered) => {
                        if !delivered {
                            log::error!("event persisted but live delivery failed");
                        }
                        self.stats.bump(&self.stats.events_accepted, 1);
                        outcome
                    }
                    // The event stored but a required removal side effect
                    // (NIP-09/9005) was dropped: the client must retry
                    // instead of receiving a `true` ack for a deletion that
                    // did not happen. `after_put` already counted the
                    // database error.
                    RemovalAck::NotApplied => {
                        self.stats.bump(&self.stats.events_rejected, 1);
                        PutOutcome::Invalid(
                            "error: database overloaded: removal was not applied; retry".into(),
                        )
                    }
                }
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
        let (known, previous_capped) = self.batch_known_prefixes(&events).await;
        let known = crate::relay::validate::KnownPrevious {
            known: &known,
            capped: previous_capped,
        };
        self.accept_batch_non_group(events, authed, Some(&known), None)
            .await
    }

    /// The batch's pre-resolved `previous` tag references, collected in one
    /// database round trip, and whether the reference collection hit its
    /// cap. The precheck must not issue one lookup per reference (a single
    /// event can carry thousands). Sibling references are *not* included
    /// here: an event's id becomes known only once that event was actually
    /// accepted (or already stored), so a rejected sibling cannot satisfy a
    /// later event's `previous` tag (see `accept_batch_non_group`).
    async fn batch_known_prefixes(
        &self,
        events: &[Event],
    ) -> (std::collections::HashSet<Vec<u8>>, bool) {
        // Dedup with a set so that a batch full of distinct `previous` tags
        // (up to max_tags per event) cannot turn the dedup itself quadratic.
        // The collection is additionally capped: without a bound a single
        // batch (EVENT_BATCH * 32 events x max_tags references) could pin
        // megabytes of prefixes and force millions of LMDB range probes
        // inside one read transaction, stalling the reader. References past
        // the cap are treated as unknown, so the affected events fail closed
        // instead of stalling the relay; the caller is told the prefetch was
        // capped so their rejections are reported as retryable instead of
        // blaming the reference.
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
        let known: std::collections::HashSet<Vec<u8>> = if prefixes.is_empty() {
            std::collections::HashSet::new()
        } else {
            let existing = self.db.prefixes_exist(prefixes.clone()).await;
            prefixes
                .into_iter()
                .zip(existing)
                .filter_map(|(p, exists)| exists.then_some(p))
                .collect()
        };
        (known, previous_capped)
    }

    /// Inserts every prefix of `id` into the batch's known-reference set:
    /// once an event is accepted (or already stored), later events of the
    /// same batch may reference it via `previous` even though it is not
    /// committed yet. A rejected sibling is never inserted.
    fn insert_event_prefixes(known: &mut std::collections::HashSet<Vec<u8>>, id: &str) {
        if let Ok(id_bytes) = hex::decode(id) {
            for len in 1..=id_bytes.len() {
                known.insert(id_bytes[..len].to_vec());
            }
        }
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
        // The known-reference set grows with each event that is actually
        // accepted (or already stored): a later event may reference an
        // earlier sibling, but never a rejected one.
        let (mut known_set, previous_capped) = self.batch_known_prefixes(&events).await;
        // One parallel pass for the whole batch: the sequential singletons
        // below must not re-verify each signature inline.
        let verified = crate::relay::validate::verify_signatures_parallel(&events, self.secp());
        let mut out: Vec<(String, PutOutcome)> = Vec::with_capacity(events.len());
        let mut run: Vec<Event> = Vec::new();
        let mut run_verdicts: Vec<bool> = Vec::new();
        for (index, event) in events.into_iter().enumerate() {
            if self.has_state_effects(&event) {
                if !run.is_empty() {
                    let known = crate::relay::validate::KnownPrevious {
                        known: &known_set,
                        capped: previous_capped,
                    };
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
                    for (id, outcome) in &resolved {
                        if matches!(
                            outcome,
                            PutOutcome::Stored
                                | PutOutcome::Replaced
                                | PutOutcome::Ephemeral
                                | PutOutcome::Duplicate(_)
                        ) {
                            Self::insert_event_prefixes(&mut known_set, id);
                        }
                    }
                    out.extend(resolved);
                    run_verdicts.clear();
                }
                let id = event.id.clone();
                let outcome = {
                    let known = crate::relay::validate::KnownPrevious {
                        known: &known_set,
                        capped: previous_capped,
                    };
                    self.accept_event_verified(event, authed, Some(&known), Some(verified[index]))
                        .await
                };
                if matches!(
                    outcome,
                    PutOutcome::Stored
                        | PutOutcome::Replaced
                        | PutOutcome::Ephemeral
                        | PutOutcome::Duplicate(_)
                ) {
                    Self::insert_event_prefixes(&mut known_set, &id);
                }
                out.push((id, outcome));
            } else {
                run_verdicts.push(verified[index]);
                run.push(event);
            }
        }
        if !run.is_empty() {
            let known = crate::relay::validate::KnownPrevious {
                known: &known_set,
                capped: previous_capped,
            };
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
        known_prefixes: Option<&crate::relay::validate::KnownPrevious<'_>>,
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
        // The set of `previous` targets known so far. It starts from the
        // database prefetch and grows with each event that is actually
        // accepted (or already stored); a rejected sibling's id is never
        // inserted, so it cannot satisfy a later event's `previous` tag.
        // `None` means no prefetch: each reference is looked up in the
        // database.
        let per_reference_lookup = known_prefixes.is_none();
        let previous_capped = known_prefixes.is_some_and(|known| known.capped);
        let mut known_set: std::collections::HashSet<Vec<u8>> = known_prefixes
            .map(|known| known.known.clone())
            .unwrap_or_default();

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
            let known = (!per_reference_lookup).then_some(crate::relay::validate::KnownPrevious {
                known: &known_set,
                capped: previous_capped,
            });
            match self
                .precheck(&cfg, &access, &event, now, authed, known.as_ref(), verified)
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
                    // Already stored: its id is a valid reference even
                    // though this reply is a duplicate.
                    Self::insert_event_prefixes(&mut known_set, &id);
                    self.stats.bump(&self.stats.events_duplicate, 1);
                    results.push((id, PutOutcome::Duplicate(msg)));
                    continue;
                }
                crate::relay::validate::Precheck::Admit(msg) => {
                    // NIP-43 join by invite code: admit inline (the
                    // membership mutation is idempotent, like the
                    // single-event path above) and acknowledge without
                    // storing the ephemeral request (welcome text rides
                    // the duplicate-style ack).
                    if !self.admit_member(&event.pubkey).await {
                        self.stats.bump(&self.stats.events_rejected, 1);
                        results.push((
                            id,
                            PutOutcome::Invalid(
                                "error: membership could not be recorded; retry".into(),
                            ),
                        ));
                        continue;
                    }
                    Self::insert_event_prefixes(&mut known_set, &id);
                    self.stats.bump(&self.stats.events_duplicate, 1);
                    results.push((id, PutOutcome::Duplicate(msg)));
                    continue;
                }
                crate::relay::validate::Precheck::Accept => {
                    // Accepted and queued for the same commit as the later
                    // events: later events of the batch may reference it.
                    Self::insert_event_prefixes(&mut known_set, &id);
                }
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
    ) -> RemovalAck {
        let mut removal_failed = false;
        if nip9 && event.kind == nip09::DELETION_KIND {
            // NIP-29/NIP-43: a deletion that removes state events
            // (moderation, join/leave, role state) invalidates the derived
            // state, exactly like a vanish. The targets are gone once the
            // deletion applies, so the relevance check must run first; a
            // failed lookup fails closed (the rebuild runs even if the
            // targets turn out unrelated). Deleting ordinary posts does not
            // touch the derived state and takes no rebuild.
            //
            // The removal commits in the database before the in-memory
            // state is updated (or marked stale): the in-flight claims keep
            // a concurrent snapshot persist from certifying the
            // post-removal generation while the in-memory effect is
            // pending.
            let _groups_in_flight = nip29_enabled.then(|| self.groups_rebuild.derived.begin());
            let _roles_in_flight = nip43.then(|| self.roles_rebuild.derived.begin());
            let touch = if nip29_enabled || nip43 {
                self.deletion_touches_group_state(&event).await
            } else {
                StateTouch::default()
            };
            let (removed, state_removed) = self
                .db
                .apply_deletion_checked(
                    nip09::deletion_targets(&event),
                    nip09::deletion_addresses(&event),
                    Some(event.pubkey.clone()),
                    event.created_at,
                )
                .await;
            match removed {
                Some(removed) => self.stats.bump(&self.stats.events_deleted, removed as u64),
                None => {
                    // The deletion event stored but its side effect was
                    // dropped (writer overload): the client must retry
                    // instead of receiving a `true` ack for a deletion that
                    // did not happen.
                    log::error!("NIP-09 deletion side effect was not applied");
                    self.stats.bump(&self.stats.db_errors, 1);
                    removal_failed = true;
                }
            }
            if state_removed {
                // The live state still holds state derived from a removed
                // event: mark the touched store(s) stale and let the
                // coalesced background workers rebuild. A NIP-29-only
                // removal must not revoke the role grants (or pay for a
                // role scan). When the relevance pre-check could not
                // classify the targets, both stores are marked (fail
                // closed).
                let unknown = !touch.groups && !touch.roles;
                if touch.groups || unknown {
                    self.mark_group_state_stale().await;
                }
                if touch.roles || unknown {
                    self.mark_roles_stale().await;
                }
            }
            // NIP-59: gift wraps are signed by random keys, so their
            // recipient cannot delete them via NIP-09; the relay
            // deletes wraps addressed to the deleter instead. A failure
            // only logs: the purge has no pending record, so a client
            // retry is a duplicate and cannot resume it (the next restart's
            // expiry/name maintenance does not re-run it either).
            if let Some(pubkey) = event.pubkey_bytes() {
                match self.db.delete_gift_wraps_to_checked(pubkey, u64::MAX).await {
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
        if nip29_enabled
            && nip29::is_group_action(&event)
            && !self.apply_group_event(&event, now).await
        {
            removal_failed = true;
        }
        // Command events: with `relay.enabled_command_events` a kind:1
        // event authored by the relay's own pubkey carries an operator
        // command; it is executed here (after storage, like the other
        // side effects) and answered with a relay-signed kind:1111 event.
        if event.kind == 1 {
            self.handle_command_event(&event).await;
        }
        // Live broadcast is at-most-once per subscriber, in one respect:
        // a REQ racing this broadcast registers its index before scanning
        // history, which covers stored events — but an ephemeral event is
        // never stored, so a subscription created in that microsecond
        // window misses it with no history fallback. Fundamental to
        // pub/sub (there is nothing to replay from); stored events cannot
        // miss this way.
        let delivered = self.broadcast(event).await.is_ok();
        if removal_failed {
            RemovalAck::NotApplied
        } else {
            RemovalAck::Applied(delivered)
        }
    }

    /// Persists the live NIP-29 group state immediately. The hot mutation
    /// path uses the debounced [`Self::schedule_groups_persist`] instead;
    /// this immediate form is kept for the fail-closed paths (a pre-delete
    /// ghost, a stale-state clear, the rebuild worker) and tests.
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
        self.persist_groups_outcome().await == PersistOutcome::Committed
    }

    /// Like [`Self::persist_groups`], reporting a deferred save (a derived
    /// mutation was in flight) separately from a failed one: callers must
    /// only treat `Failed` as fail-closed (the state may still be current).
    async fn persist_groups_outcome(&self) -> PersistOutcome {
        self.groups_rebuild.persist(&self.db, &self.groups).await
    }

    /// Publishes the relay-signed metadata events (39000/39001/39002/39005)
    /// for every live group. Called after a rebuild from stored events: a
    /// database whose group state was rebuilt — a migration from another
    /// relay, or a dropped snapshot — has no (or stale) stored metadata,
    /// and NIP-29 clients need it to display the groups. Requires the relay
    /// key (without it the relay cannot sign metadata and NIP-29 is hidden
    /// in NIP-11 anyway). A failed store only logs: the in-memory state is
    /// already correct, and the next moderation event republishes.
    pub(crate) async fn publish_group_metadata(&self) {
        let Some(relay_pubkey) = self.relay_pubkey() else {
            return;
        };
        let now = self.stamp_floor(unix_now());
        let events = {
            let mut groups = self.groups.write().await;
            groups.all_metadata_events(&relay_pubkey, now)
        };
        let mut stored = 0usize;
        for mut event in events {
            if self.store_relay_event(&mut event).await.is_ok() {
                stored += 1;
            }
        }
        if stored > 0 {
            log::info!("republished {stored} NIP-29 group metadata event(s) after the rebuild");
        }
    }

    /// Persists the live NIP-43 role state (same lifecycle as
    /// [`Self::persist_groups`]). The lock keeps a stale snapshot from
    /// overwriting a newer one: two concurrent mutations could otherwise
    /// capture snapshots in one order and queue their writes in the other.
    ///
    /// The snapshot carries the database's state generation
    /// (`DbClient::state_stamp`) and role-state sequence
    /// (`DbClient::state_seq_role`) so a later restore can reject a snapshot
    /// that predates a NIP-09 deletion of a role-state event or a
    /// role-state event itself. The generation is read *before* the
    /// capture: a change committed in between leaves the snapshot with the
    /// older generation and the startup comparison rejects it. An
    /// unavailable read leaves the pre-existing snapshot untouched (its
    /// currency cannot be established): the next startup then rejects that
    /// older generation and rebuilds from the surviving events.
    ///
    /// While a role rebuild is dirty/running the store is known stale (or
    /// owned by the worker): the write is refused so the stale store cannot
    /// be stamped with the already-advanced generation (which would make the
    /// next startup accept it). Returns whether the write committed. The
    /// hot mutation paths use the debounced [`Self::schedule_roles_persist`]
    /// instead; this immediate form is kept for the rebuild worker and the
    /// fail-closed paths.
    pub(crate) async fn persist_roles(&self) -> bool {
        persist_roles_now(
            &self.db,
            &self.roles,
            &self.roles_rebuild,
            &self.persist_roles_lock,
        )
        .await
            == PersistOutcome::Committed
    }

    /// Marks the group snapshot dirty and wakes the debounced worker (see
    /// [`SnapshotPersist`]). The hot mutation paths use this instead of
    /// [`Self::persist_groups`]: the clone+serialize is coalesced into one
    /// background pass, and a skipped save is detected at startup through
    /// the database sequence.
    fn schedule_groups_persist(&self) {
        self.snapshot_persist
            .groups_dirty
            .store(true, Ordering::SeqCst);
        schedule_snapshot_persist(self.snapshot_persist_ctx(), self.subscribe_drain());
    }

    /// The worker/scheduler handles for this relay.
    fn snapshot_persist_ctx(&self) -> SnapshotPersistCtx {
        SnapshotPersistCtx {
            db: self.db.clone(),
            groups: Arc::clone(&self.groups),
            groups_rebuild: Arc::clone(&self.groups_rebuild),
            roles: Arc::clone(&self.roles),
            roles_rebuild: Arc::clone(&self.roles_rebuild),
            persist_roles_lock: Arc::clone(&self.persist_roles_lock),
            state: Arc::clone(&self.snapshot_persist),
        }
    }

    /// Marks the role snapshot dirty and wakes the debounced worker (same
    /// contract as [`Self::schedule_groups_persist`]). The immediate
    /// [`Self::persist_roles`] remains for the rebuild worker and the
    /// fail-closed paths.
    pub(crate) fn schedule_roles_persist(&self) {
        self.snapshot_persist
            .roles_dirty
            .store(true, Ordering::SeqCst);
        schedule_snapshot_persist(self.snapshot_persist_ctx(), self.subscribe_drain());
    }

    /// Whether `event` may remove events the NIP-29/NIP-43 derived state is
    /// built from (moderation, join/leave and role state kinds), split per
    /// store: a NIP-29-only removal must not revoke and rescan the NIP-43
    /// role state (and vice versa). `a`-tag addresses carry their kind
    /// directly; `e`-tag targets are looked up in the database because the
    /// deletion removes them. A failed lookup fails closed: both stores are
    /// rebuilt even if the targets turn out unrelated.
    async fn deletion_touches_group_state(&self, event: &Event) -> StateTouch {
        fn classify(kind: u64) -> StateTouch {
            StateTouch {
                groups: (nip29::MOD_MIN..=nip29::MOD_MAX).contains(&kind)
                    || kind == nip29::JOIN
                    || kind == nip29::LEAVE,
                roles: matches!(
                    kind,
                    nip43::ROLE_DEFINITION
                        | nip43::MEMBERSHIP_LIST
                        | nip43::ADD_USER
                        | nip43::REMOVE_USER
                        | nip43::JOIN
                        | nip43::LEAVE
                ),
            }
        }
        let mut touch = StateTouch::default();
        for address in nip09::deletion_addresses(event) {
            let classified = classify(address.kind);
            touch.groups |= classified.groups;
            touch.roles |= classified.roles;
        }
        let targets = nip09::deletion_targets(event);
        if targets.is_empty() {
            return touch;
        }
        // The lookup is only a per-family existence check, so one event per
        // family is enough: a single capped page over both families could
        // fill up on one side (a deletion naming 64 group-state ids plus a
        // role-state id) and miss the other store, leaving deleted role
        // grants live (or vice versa).
        let group_kinds: Vec<u64> = (nip29::MOD_MIN..=nip29::MOD_MAX)
            .chain([nip29::JOIN, nip29::LEAVE])
            .collect();
        let role_kinds = vec![
            nip43::ROLE_DEFINITION,
            nip43::MEMBERSHIP_LIST,
            nip43::ADD_USER,
            nip43::REMOVE_USER,
            nip43::JOIN,
            nip43::LEAVE,
        ];
        for (kinds, is_group) in [(group_kinds, true), (role_kinds, false)] {
            let filter = crate::filter::Filter {
                ids: Some(targets.clone()),
                kinds: Some(kinds),
                ..Default::default()
            };
            match self
                .db
                .query_full_startup(vec![filter], 1, unix_now(), false)
                .await
            {
                Some((events, _)) => {
                    if !events.is_empty() {
                        if is_group {
                            touch.groups = true;
                        } else {
                            touch.roles = true;
                        }
                    }
                }
                // The database did not answer: assume the deletion matters.
                None => {
                    return StateTouch {
                        groups: true,
                        roles: true,
                    };
                }
            }
        }
        touch
    }

    /// Marks the in-memory group state as stale after events it derives
    /// from were removed (NIP-62 vanish, NIP-09 deletion, NIP-40 expiry)
    /// and schedules the coalesced background rebuild. The persisted
    /// snapshot is dropped immediately: it predates the removals, so a
    /// crash before the rebuild completes must not restore it. The accept
    /// path never blocks on the rebuild scan (see `groups_rebuild_worker`).
    ///
    /// This only touches the group store: callers that know a NIP-43
    /// role-state event was removed ([`StateTouch::roles`]) call
    /// [`Self::mark_roles_stale`] separately, so a NIP-29-only removal does
    /// not revoke the live role grants and schedule a full role scan.
    pub(crate) async fn mark_group_state_stale(&self) {
        self.groups_rebuild.dirty.store(true, Ordering::SeqCst);
        self.groups_rebuild.pending.store(true, Ordering::SeqCst);
        self.persist_groups().await;
        schedule_groups_rebuild(
            self.db.clone(),
            Arc::clone(&self.groups),
            Arc::clone(&self.config),
            self.relay_pubkey.clone(),
            Arc::clone(&self.groups_rebuild),
            self.subscribe_drain(),
        );
    }

    /// Marks the live NIP-43 role store stale and schedules the coalesced
    /// background rebuild. The store is replaced with an empty one *under
    /// the write lock in this path* (revocation): the removed event may have
    /// defined a role or granted a membership, and the NIP-43 JOIN path and
    /// the RPC check the live store, so keeping the old grants until the
    /// scan completes would keep authorizing them. The persisted snapshot
    /// keeps its older generation stamp, so the next startup rejects it and
    /// rebuilds from the surviving events; `persist_roles` refuses to
    /// overwrite it until the rebuild completes.
    pub(crate) async fn mark_roles_stale(&self) {
        self.roles_rebuild.dirty.store(true, Ordering::SeqCst);
        *self.roles.write().await = RoleStore::default();
        schedule_roles_rebuild(
            self.db.clone(),
            Arc::clone(&self.roles),
            self.relay_pubkey().unwrap_or_default(),
            Arc::clone(&self.persist_roles_lock),
            Arc::clone(&self.roles_rebuild),
            self.subscribe_drain(),
        );
    }

    /// Whether a `kind:9008` group purge committed. The purge API reports a
    /// failure as zero removed (indistinguishable from "nothing to purge"),
    /// so the id is confirmed clean only when no stored `h`-tagged event
    /// remains. A failed or truncated query fails closed: the id stays
    /// ghosted rather than becoming re-creatable with its history intact.
    async fn group_purge_confirmed(&self, gid: &str, until: u64) -> bool {
        let mut filter: crate::filter::Filter =
            serde_json::from_value(serde_json::json!({ "#h": [gid] })).expect("static filter");
        // A migration-recorded purge is bounded: events after the cut are
        // the re-created group's and must not fail the confirmation.
        if until != u64::MAX {
            filter.until = Some(until);
        }
        match self
            .db
            .query_full_startup(vec![filter], 1, unix_now(), false)
            .await
        {
            Some((events, more)) => !more && events.is_empty(),
            None => false,
        }
    }

    /// Startup barrier for the database writer's recovery: the server
    /// awaits this before it serves. The writer resumes interrupted NIP-62
    /// vanishes and NIP-09 deletions synchronously before `DbClient::open`
    /// returns, so the await joins an already-completed recovery; if a
    /// resumed deletion removed a NIP-29/NIP-43 state event (the db exposes
    /// the fact via `resumed_deletion_state_removed`), the derived state is
    /// marked stale here so the group/role stores rebuild from the
    /// surviving events before they are trusted. Kept as an async relay
    /// API so a future asynchronous recovery can be awaited without the
    /// server changing its startup order.
    pub async fn recovery_done(&self) {
        if self.db.resumed_deletion_state_removed() {
            log::warn!(
                "startup recovery removed a derived-state event; rebuilding the NIP-29/NIP-43 \
                 state from the surviving events"
            );
            self.mark_group_state_stale().await;
            self.mark_roles_stale().await;
        }
    }

    /// Crash recovery for `kind:9008` group purges: re-runs every purge the
    /// database recorded as pending (a purge that was accepted but whose
    /// walk did not complete, e.g. the process crashed mid-walk). The
    /// server calls this at startup, before serving. An unreadable pending
    /// list is fail-closed: the restored/rebuilt ghosts and the database's
    /// pending records stay in place. Idempotent when nothing is pending.
    pub(crate) async fn resume_pending_purges(&self) {
        let pending: Vec<(String, u64, u64)> = match self.db.pending_purges().await {
            Some(pending) => pending,
            None => {
                // The recorded purges are unknown: some pending purge may
                // still need resuming, so the fail-closed state (ghosted
                // ids, dropped snapshot) stays as restored.
                log::error!(
                    "cannot read the pending group purges; leaving the fail-closed state \
                     in place"
                );
                return;
            }
        };
        for (gid, purge_now, until) in pending {
            self.resume_pending_purge(&gid, purge_now, until).await;
        }
    }

    /// Resumes one recorded purge (see [`Self::resume_pending_purges`]):
    /// re-runs the purge, confirms it, then downgrades the ghost to the
    /// ordinary delete tombstone and persists. Kept separate from the
    /// database read so the resume path is testable without a real
    /// mid-walk failure.
    async fn resume_pending_purge(&self, gid: &str, purge_now: u64, until: u64) {
        // The id must stay ghosted until the purge is confirmed: mark it
        // (and persist) before touching the database, so a crash mid-resume
        // cannot restore a snapshot that would let a create expose the
        // (possibly un-purged) history.
        self.ghost_deleted_group(gid).await;
        if self.persist_groups_outcome().await == PersistOutcome::Failed {
            log::error!(
                "could not persist the pending-purge ghost for {gid}; the persisted state \
                 stays fail-closed"
            );
        }
        let removed = self
            .db
            .group_purge_until(gid.to_string(), purge_now, until)
            .await;
        self.stats
            .bump(&self.stats.events_deleted, removed.unwrap_or(0) as u64);
        if self.group_purge_confirmed(gid, until).await {
            if until == u64::MAX {
                // The history is gone: downgrade to the ordinary tombstone,
                // like the 9008 path.
                self.unghost_confirmed(gid).await;
                if self.persist_groups_outcome().await == PersistOutcome::Failed {
                    log::error!("could not persist the confirmed group purge for {gid}");
                }
            } else {
                // A bounded (migration) purge leaves the re-created group's
                // later events: clear the fail-closed ghost and rebuild the
                // state from the survivors. The tombstone is only restored
                // for an id the rebuild does not reconstruct, so a
                // legitimate re-creation is revealed.
                self.unghost_confirmed(gid).await;
                self.mark_group_state_stale().await;
            }
        } else {
            log::error!(
                "could not confirm the resumed group purge for {gid}; keeping the id \
                 ghosted so a re-create cannot expose the un-purged history"
            );
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
    /// Returns whether the vanish removal was applied: `false` means the
    /// database did not commit the removal (and its recoverable pending
    /// record), so the caller must not acknowledge the request.
    async fn vanish_pubkey(&self, pubkey: [u8; 32], until_created: u64) -> bool {
        let pubkey_hex = hex::encode(pubkey);
        let nip29_enabled = self.config.read().await.nip_enabled(29);
        let nip43_enabled = self.config.read().await.nip_enabled(43);
        let mut changed_member = false;
        let mut role_changed = false;
        // The removal commits in the database before the in-memory derived
        // state is updated: hold the in-flight claims until the per-store
        // effects (member/role removal or the stale marking) are applied, so
        // a concurrent snapshot persist cannot certify the post-removal
        // generation against pre-removal state.
        let groups_in_flight = nip29_enabled.then(|| self.groups_rebuild.derived.begin());
        let roles_in_flight = nip43_enabled.then(|| self.roles_rebuild.derived.begin());
        let (removed, group_state_removed) =
            match self.db.apply_vanish_checked(pubkey, until_created).await {
                Some(outcome) => outcome,
                None => {
                    // The vanish side effect was dropped: the marker is not
                    // stored (and no pending record exists), so the pubkey
                    // would come back. Surface the failure in the logs and
                    // metrics; the accept path turns the request into a
                    // retryable failure.
                    log::error!("NIP-62 vanish side effect was not applied");
                    self.stats.bump(&self.stats.db_errors, 1);
                    return false;
                }
            };
        self.stats.bump(&self.stats.events_deleted, removed as u64);
        if nip29_enabled && !group_state_removed {
            // A replayed vanish, one that removed nothing, or one that only
            // deleted ordinary posts: the live state only needs the vanished
            // pubkey dropped from its memberships, and only a real change is
            // worth a snapshot write. The removal is not reconstructible
            // from the database (an admin's surviving 9000 may re-add the
            // pubkey after the scan's vanished-set snapshot), so an
            // in-flight rebuild discards its scan.
            changed_member = {
                let mut buffer = self.groups_rebuild.buffer.lock().await;
                if buffer.scanning {
                    buffer.retry = true;
                }
                let mut groups = self.groups.write().await;
                groups.remove_member_everywhere(&pubkey_hex)
            };
        }
        // NIP-43 role assignments hold pubkeys too: a vanished author must
        // not keep its roles.
        if nip43_enabled {
            role_changed = self
                .mutate_roles(
                    BufferedRoleMutation::RemovePubkey {
                        pubkey: pubkey_hex.clone(),
                    },
                    |roles| {
                        let changed = roles.assignments.remove(&pubkey_hex).is_some();
                        (changed, changed)
                    },
                )
                .await;
        }
        if nip29_enabled && group_state_removed {
            // A moderation/join/leave (or role-state) event was removed: the
            // derived state must be rebuilt from the surviving history. The
            // db reports one combined flag, so both stores are marked stale
            // (a relay-signed role event can only be removed when the
            // operator's own key vanished, but the fail-closed revocation is
            // cheap compared to resurrecting a grant). The marks run while
            // the in-flight claims are held: `mark_group_state_stale` sets
            // `pending` and its persist clears the snapshot through that
            // branch, so no concurrent save can certify pre-removal state in
            // the window. The rebuilds are full-history scans and vanishes
            // are exempt from the publish rate limit, so any fresh keypair
            // could otherwise stall every group write; the coalesced
            // background workers keep it amortized.
            self.mark_group_state_stale().await;
            self.mark_roles_stale().await;
        }
        drop(groups_in_flight);
        if nip29_enabled && !group_state_removed && changed_member && !self.persist_groups().await {
            log::error!(
                "could not persist the group state after a vanish; it will be \
                 rebuilt on the next restart"
            );
        }
        drop(roles_in_flight);
        if nip43_enabled && role_changed {
            self.schedule_roles_persist();
        }
        true
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
    ///
    /// Returns `false` when a required `9005` removal side effect was not
    /// applied: the caller must report the retryable outcome instead of
    /// `OK true`. Every other path returns `true` (a failed `9008` purge
    /// keeps the id fail-closed as a ghost, which is a safe, non-removal
    /// outcome).
    async fn apply_group_event(&self, event: &Event, now: u64) -> bool {
        let mut removal_failed = false;
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
            if self.persist_groups_outcome().await == PersistOutcome::Failed {
                log::error!(
                    "could not persist the pre-delete group ghost for {gid}; the in-memory \
                     state stays fail-closed"
                );
            }
        }
        let generated = self.apply_group_state(event, now).await;
        // Debounced persistence: restarts restore from the snapshot instead
        // of replaying history, and a skipped save is detected at startup
        // through the group-state sequence (`DbClient::state_seq_group`).
        self.schedule_groups_persist();

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
                let touch = self.deletion_touches_group_state(event).await;
                let (removed, state_removed) = self
                    .db
                    .apply_group_deletion_checked(nip29::delete_targets(event), gid.to_string())
                    .await;
                match removed {
                    Some(removed) => self.stats.bump(&self.stats.events_deleted, removed as u64),
                    None => {
                        // The 9005 stored but its side effect was dropped
                        // (writer overload): report the retryable failure
                        // instead of a silent success (same OK semantics as
                        // the NIP-09 deletion path).
                        log::error!("NIP-29 9005 deletion side effect was not applied");
                        self.stats.bump(&self.stats.db_errors, 1);
                        removal_failed = true;
                    }
                }
                if state_removed {
                    // Removing a moderation/join/leave event invalidates
                    // the in-memory state derived from it (a deleted 9000
                    // grant must revoke the membership): mark the touched
                    // store(s) stale and let the coalesced workers rebuild.
                    // An unclassifiable pre-check marks both (fail closed).
                    let unknown = !touch.groups && !touch.roles;
                    if touch.groups || unknown {
                        self.mark_group_state_stale().await;
                    }
                    if touch.roles || unknown {
                        self.mark_roles_stale().await;
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
            // re-broadcast of the purged history stays rejected. A failed
            // purge reports `None` (its removed count stays out of the
            // stats), so success is confirmed by the state below: only then
            // does the id return to the ordinary delete tombstone (which a
            // create may clear).
            let removed = self.db.group_purge(gid.to_string(), unix_now()).await;
            self.stats
                .bump(&self.stats.events_deleted, removed.unwrap_or(0) as u64);
            if self.group_purge_confirmed(gid, u64::MAX).await {
                // The history is gone: the id may be re-created normally.
                self.unghost_confirmed(gid).await;
                if self.persist_groups_outcome().await == PersistOutcome::Failed {
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
        !removal_failed
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
                let applied = match event.pubkey_bytes() {
                    Some(pubkey) => relay.vanish_pubkey(pubkey, event.created_at).await,
                    None => false,
                };
                if applied {
                    relay.stats.bump(&relay.stats.events_accepted, 1);
                    results[slot] = (id, PutOutcome::Stored);
                } else {
                    relay.stats.bump(&relay.stats.events_rejected, 1);
                    results[slot] = (
                        id,
                        PutOutcome::Invalid(
                            "error: database overloaded: vanish was not applied; retry".into(),
                        ),
                    );
                }
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
            let mut ack_override = None;
            match outcome {
                PutOutcome::Stored | PutOutcome::Replaced | PutOutcome::Ephemeral => {
                    let ack = relay.after_put(event, now, nip9, nip43, nip29).await;
                    // The first-seen timestamp belongs to the stored event
                    // regardless of a removal side effect.
                    if let Some(pk) = first_seen_pubkey {
                        persist_first_seen.push(pk);
                    }
                    match ack {
                        RemovalAck::Applied(delivered) => {
                            if !delivered {
                                log::error!("event persisted but live delivery failed");
                            }
                            relay.stats.bump(&relay.stats.events_accepted, 1);
                        }
                        RemovalAck::NotApplied => {
                            // The event stored but a required removal was
                            // not: report the retryable failure (see the
                            // single-event path).
                            relay.stats.bump(&relay.stats.events_rejected, 1);
                            ack_override = Some(PutOutcome::Invalid(
                                "error: database overloaded: removal was not applied; retry".into(),
                            ));
                        }
                    }
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
            results[slot] = (id, ack_override.unwrap_or(outcome));
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
            let applied = match event.pubkey_bytes() {
                Some(pubkey) => relay.vanish_pubkey(pubkey, event.created_at).await,
                None => false,
            };
            if applied {
                // Same accounting as the single-event path: a vanish is
                // accepted (its OK:true is sent) and counts as accepted.
                relay.stats.bump(&relay.stats.events_accepted, 1);
                results[slot] = (id, PutOutcome::Stored);
            } else {
                // The removal side effect was not applied: a retryable
                // failure instead of `OK true` (see the single-event path).
                relay.stats.bump(&relay.stats.events_rejected, 1);
                results[slot] = (
                    id,
                    PutOutcome::Invalid(
                        "error: database overloaded: vanish was not applied; retry".into(),
                    ),
                );
            }
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::BufferedGroupEvent;
    use super::BufferedRoleMutation;
    use super::GROUPS_REBUILD_BUFFER_MAX;
    use super::LiveQueue;
    use super::ROLES_REBUILD_BUFFER_MAX;
    use super::Relay;
    use super::StampClock;
    use super::enqueue_live_batch;
    use super::roles::RoleChange;
    use super::signal_live_resync;
    use super::validate::contains_secret_key;
    use crate::nips::nip43::RoleStore;
    use std::sync::atomic::Ordering;

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

        // Without NIP-43 / a relay key every operation reports failure.
        let keyless = build_role_relay(None).await;
        assert!(!keyless.create_role("r1", "R", "", "", None).await);
        assert_eq!(keyless.assign_role(&member, "r1").await, RoleChange::Failed);
        assert_eq!(keyless.delete_role("r1").await, RoleChange::Failed);
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

        // assign to an unknown role reports Unknown; to a known role
        // applies and publishes the membership (kind 39002 for this
        // relay... the membership event kind is derived from the relay's
        // own key). A repeat grant is a no-op success.
        assert_eq!(
            relay.assign_role(&member, "nope").await,
            RoleChange::Unknown
        );
        assert_eq!(relay.assign_role(&member, "r1").await, RoleChange::Applied);
        assert_eq!(relay.assign_role(&member, "r1").await, RoleChange::Noop);
        assert!(relay.roles.read().await.is_member_of(&member));

        // unassign of a non-assignment is a no-op success; the real one
        // applies.
        assert_eq!(relay.unassign_role(&member, "nope").await, RoleChange::Noop);
        assert_eq!(
            relay.unassign_role(&member, "r1").await,
            RoleChange::Applied
        );
        assert!(!relay.roles.read().await.is_member_of(&member));

        // delete a missing role fails; the real one succeeds and stores a
        // tombstone (kind 33534 with a `deleted` tag).
        assert_eq!(relay.delete_role("nope").await, RoleChange::Noop);
        assert_eq!(relay.delete_role("r1").await, RoleChange::Applied);
        assert!(!relay.roles.read().await.roles.contains_key("r1"));

        // A leave request from a member removes and republishes; a
        // non-member is a no-op.
        assert!(relay.create_role("r1", "Role 1", "desc", "red", None).await);
        assert_eq!(relay.assign_role(&member, "r1").await, RoleChange::Applied);
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
    async fn leave_during_role_rebuild_is_buffered_not_lost() {
        // A LEAVE arriving while the live store is revoked (a role rebuild
        // is in flight) must still take effect: the removal reports "not a
        // member" on the empty store, so without force-buffering the replay
        // would never see it and the rebuild would resurrect the member.
        // The client already got `OK` (LEAVE is ephemeral), so there is no
        // failure to report and retry.
        let key = "01".repeat(32);
        let relay = build_role_relay(Some(&key)).await;
        let member = "aa".repeat(32);
        assert!(relay.create_role("r1", "Role 1", "", "", None).await);
        assert_eq!(relay.assign_role(&member, "r1").await, RoleChange::Applied);
        assert!(relay.roles.read().await.is_member_of(&member));
        // Simulate the revoked window without racing a real worker: the
        // store is empty and a rebuild is pending.
        relay.roles_rebuild.dirty.store(true, Ordering::SeqCst);
        *relay.roles.write().await = RoleStore::default();
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
        // Not applied live (the store is revoked), but captured for replay...
        assert!(!relay.roles.read().await.is_member_of(&member));
        {
            let buffer = relay.roles_rebuild.buffer.lock().await;
            assert!(
                buffer.mutations.iter().any(|m| matches!(
                    m,
                    BufferedRoleMutation::RemovePubkey { pubkey } if pubkey == &member
                )),
                "the leave must be buffered for the rebuild replay"
            );
        }
        // ...and announced with a remove-user event (kind 8001), without
        // the revoked store's member list.
        let f: crate::filter::Filter =
            serde_json::from_value(serde_json::json!({"kinds": [8001]})).unwrap();
        let (stored, _) = relay.db.query(vec![f], 10, crate::util::unix_now()).await;
        assert!(
            stored.iter().any(|e| e
                .tags
                .iter()
                .any(|t| t == &vec!["p".into(), member.clone()])),
            "a remove-user event must announce the departure"
        );
        // The replay applies the buffered leave to the fresh store: a fresh
        // store that still names the member (the rebuild window input)
        // comes out without them.
        relay.roles_rebuild.dirty.store(false, Ordering::SeqCst);
        let mut fresh = RoleStore::default();
        fresh.create("r1", "Role 1", "", "", None);
        fresh.assign(&member, "r1");
        assert!(
            relay
                .roles_rebuild
                .finish_rebuild(&relay.roles, fresh)
                .await
        );
        assert!(
            !relay.roles.read().await.is_member_of(&member),
            "the replayed leave must survive the swap"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn leave_marked_mid_flight_is_buffered_not_lost() {
        // The rebuild mark landing between the leave's pending snapshot and
        // its mutation must not lose the leave: the mutation re-reads the
        // pending flags under the write lock (marking stores `dirty`
        // before revoking under the same lock), so a removal on the
        // already-revoked empty store is still force-buffered for the
        // replay. The buffer lock orders the interleaving deterministically:
        // the spawned leave snapshots (both flags false) and blocks on the
        // held lock, the test marks and revokes, then releases.
        let key = "01".repeat(32);
        let relay = build_role_relay(Some(&key)).await;
        let member = "bb".repeat(32);
        assert!(relay.create_role("r1", "Role 1", "", "", None).await);
        assert_eq!(relay.assign_role(&member, "r1").await, RoleChange::Applied);
        let guard = relay.roles_rebuild.buffer.lock().await;
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
        let task = tokio::spawn({
            let relay = std::sync::Arc::clone(&relay);
            async move { relay.apply_leave_request(&leave).await }
        });
        // Let the spawned leave run to the held buffer lock (its snapshot
        // already sees both flags false).
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        // The mark lands mid-flight: flag first, then revoke the store.
        relay.roles_rebuild.dirty.store(true, Ordering::SeqCst);
        *relay.roles.write().await = RoleStore::default();
        drop(guard);
        task.await.expect("the leave task must complete");
        {
            let buffer = relay.roles_rebuild.buffer.lock().await;
            assert!(
                buffer.mutations.iter().any(|m| matches!(
                    m,
                    BufferedRoleMutation::RemovePubkey { pubkey } if pubkey == &member
                )),
                "a leave marked mid-flight must still be buffered for replay"
            );
        }
        let f: crate::filter::Filter =
            serde_json::from_value(serde_json::json!({"kinds": [8001]})).unwrap();
        let (stored, _) = relay.db.query(vec![f], 10, crate::util::unix_now()).await;
        assert!(
            stored.iter().any(|e| e
                .tags
                .iter()
                .any(|t| t == &vec!["p".into(), member.clone()])),
            "the mid-flight leave must still announce its departure"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn persist_roles_stamps_the_snapshot_and_fails_closed_without_a_stamp() {
        // The role snapshot carries the database generation (`state_stamp`)
        // so a later restore can reject it. When the generation cannot be
        // read, the persist must fail without overwriting the pre-existing
        // snapshot: that snapshot keeps its older stamp, so the startup
        // comparison rejects it and the replay migration rebuilds.
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join("nostrfy-role-stamp-test")
            .join(format!("{:x}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        let mut cfg = crate::config::Config::default();
        cfg.database.path = path;
        cfg.database.map_size = 16 * 1024 * 1024;
        cfg.database.max_map_size = 64 * 1024 * 1024;
        let database = cfg.database.clone();
        let db = crate::db::DbClient::open(
            &database,
            true,
            std::sync::Arc::new(Default::default()),
            0,
            128,
            4096,
            262144,
        )
        .unwrap();
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

        relay.roles.write().await.create("mod", "Mod", "", "", None);
        assert!(relay.persist_roles().await, "the stamp is readable");
        let saved = relay.db.load_roles().await.expect_loaded("snapshot");
        assert_eq!(saved.stamp, relay.db.state_stamp().await.expect("stamp"));
        assert!(saved.roles.contains_key("mod"));

        // The database is gone: the generation cannot be read, so the
        // fresh in-memory state must not overwrite the saved snapshot.
        relay.db.shutdown();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        relay
            .roles
            .write()
            .await
            .create("ghost", "Ghost", "", "", None);
        assert!(
            !relay.persist_roles().await,
            "an unreadable stamp must fail the persist"
        );

        // Reopen the same database: the pre-existing snapshot is intact
        // (the ghost role was never written) and keeps its older stamp.
        let db = crate::db::DbClient::open(
            &database,
            true,
            std::sync::Arc::new(Default::default()),
            0,
            128,
            4096,
            262144,
        )
        .unwrap();
        let persisted = db.load_roles().await.expect_loaded("snapshot");
        assert!(!persisted.roles.contains_key("ghost"));
        assert_eq!(persisted.stamp, saved.stamp);
        db.shutdown();
    }

    #[tokio::test]
    async fn persist_access_waits_for_the_cli_lock() {
        // The daemon's access persistence shares the CLI's cross-process
        // `access.lock`: while the CLI holds it, the snapshot+write must
        // not proceed (otherwise the CLI's read-modify-write could be
        // interleaved with the daemon's stale snapshot).
        let relay = build_relay().await;
        let db_path = relay.config.read().await.database.path.clone();
        let held = crate::db::lock_access_state(&db_path).expect("the lock file opens");
        let persist = {
            let relay = relay.clone();
            tokio::spawn(async move { relay.persist_access().await })
        };
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert!(
            !persist.is_finished(),
            "persist_access must wait for the CLI's access lock"
        );
        drop(held);
        let committed = tokio::time::timeout(std::time::Duration::from_secs(5), persist)
            .await
            .expect("the persist must proceed once the lock is released")
            .expect("the persist task must not panic");
        assert!(committed, "the access snapshot must commit after the wait");
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn access_op_log_merges_concurrent_cli_writes() {
        // A CLI write landing between the daemon's mutation and its persist
        // must be merged, not overwritten: the old snapshot-then-write lost
        // whichever side committed first (a fail-open ban loss).
        let relay = build_relay().await;
        let daemon_ban = "aa".repeat(32);
        let cli_ban = "bb".repeat(32);
        // Daemon-side: ban in memory + queue the op (as `banpubkey` does),
        // without persisting yet.
        {
            let op = crate::config::AccessOp::BanPubkey {
                pubkey: daemon_ban.clone(),
                reason: "spam".into(),
                insensitive: true,
            };
            let mut access = relay.access.write().await;
            crate::config::apply_access_op(&mut access, &op);
            relay.push_access_ops(vec![op]);
        }
        // CLI-side: ban straight to the database (as `nostrfy relay deny`
        // does: load, mutate, save under the cross-process lock).
        {
            let (mut deny, allow) = relay
                .db
                .try_load_relay_pubkeys()
                .await
                .expect("the pubkey lists must load");
            deny.push((cli_ban.clone(), String::new()));
            let access = match relay.db.load_access().await {
                crate::db::LoadAccessOutcome::Loaded(access) => access,
                // A fresh test database never persisted the blob: merge
                // onto an empty base like a fresh seed.
                crate::db::LoadAccessOutcome::Missing => crate::config::AccessControl::default(),
                other => panic!("the access blob must load: {other:?}"),
            };
            assert!(
                relay
                    .db
                    .save_access_and_pubkeys(&access, &deny, &allow)
                    .await,
                "the CLI-side write must commit"
            );
        }
        // The daemon persist merges instead of overwriting.
        assert!(relay.persist_access().await, "the merged write must commit");
        let (deny, _) = relay
            .db
            .try_load_relay_pubkeys()
            .await
            .expect("the pubkey lists must load");
        assert!(
            deny.iter().any(|(p, _)| p == &daemon_ban),
            "the daemon ban must survive the persist"
        );
        assert!(
            deny.iter().any(|(p, _)| p == &cli_ban),
            "the concurrent CLI ban must survive the persist (no overwrite)"
        );
        // The merged state is live immediately, not just at the next SIGHUP.
        assert!(
            relay.access.read().await.blocked_pubkeys.len() == 2,
            "both bans must be enforced live"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn access_reload_replays_unpersisted_daemon_ops() {
        // A SIGHUP reload must not clobber a daemon mutation applied to
        // memory but not yet persisted: the queued op replays onto the
        // freshly loaded lists.
        let relay = build_relay().await;
        let daemon_ban = "cc".repeat(32);
        {
            let op = crate::config::AccessOp::BanPubkey {
                pubkey: daemon_ban.clone(),
                reason: String::new(),
                insensitive: true,
            };
            let mut access = relay.access.write().await;
            crate::config::apply_access_op(&mut access, &op);
            relay.push_access_ops(vec![op]);
        }
        relay.reload_db_state().await;
        assert!(
            relay
                .access
                .read()
                .await
                .blocked_pubkeys
                .iter()
                .any(|(p, _)| p == &daemon_ban),
            "the reload must keep the unpersisted daemon ban"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn nip09_deletion_of_a_role_definition_revokes_and_rebuilds_survivors() {
        // NIP-09: deleting a relay-signed role-state event must revoke the
        // grants derived from it immediately (the marking path clears the
        // live store fail-closed) and the background rebuild must restore
        // only the grants whose role definition survived.
        let key = "01".repeat(32);
        let relay = build_role_relay(Some(&key)).await;
        // NIP-09 must be enabled for the deletion side effect to run.
        relay.config.write().await.relay.enabled_nips = vec![9, 43];

        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        assert!(relay.create_role("r1", "R1", "", "", None).await);
        assert!(relay.create_role("r2", "R2", "", "", None).await);
        assert_eq!(relay.assign_role(&a, "r1").await, RoleChange::Applied);
        assert_eq!(relay.assign_role(&b, "r2").await, RoleChange::Applied);
        assert!(relay.roles.read().await.is_member_of(&a));
        assert!(relay.roles.read().await.is_member_of(&b));

        // The r1 definition's stored event id (the relay published it on
        // create) is the deletion target.
        let filter: crate::filter::Filter =
            serde_json::from_value(serde_json::json!({"kinds": [33534]})).unwrap();
        let (stored, _) = relay
            .db
            .query(vec![filter], 10, crate::util::unix_now())
            .await;
        let role_event = stored
            .iter()
            .find(|event| {
                event
                    .tags
                    .iter()
                    .any(|tag| tag.len() >= 2 && tag[0] == "d" && tag[1] == "r1")
            })
            .expect("the r1 definition must be stored")
            .clone();

        // NIP-09: only the author may delete, so the relay signs with its own
        // key.
        let secp = secp256k1::Secp256k1::new();
        let relay_key = secp256k1::Keypair::from_seckey_slice(&secp, &[1u8; 32]).unwrap();
        let mut deletion = crate::event::Event {
            id: String::new(),
            pubkey: secp256k1::XOnlyPublicKey::from_keypair(&relay_key)
                .0
                .to_string(),
            created_at: crate::util::unix_now(),
            kind: crate::nips::nip09::DELETION_KIND,
            tags: vec![vec!["e".into(), role_event.id.clone()]],
            content: String::new(),
            sig: String::new(),
        };
        deletion.id = crate::nips::nip01::compute_id(&deletion);
        deletion.sig = secp
            .sign_schnorr_no_aux_rand(&deletion.id_bytes().unwrap(), &relay_key)
            .to_string();
        assert!(matches!(
            relay.accept_event(deletion, &[], None).await,
            crate::db::PutOutcome::Stored
        ));

        // The deleted role's grant is revoked before the rebuild completes
        // (the live store was cleared fail-closed), and the rebuild never
        // resurrects it: only r2 (whose definition survived) authorizes.
        assert!(
            !relay.roles.read().await.is_member_of(&a),
            "the deleted role's grant must be revoked"
        );
        assert!(
            wait_for_roles_rebuild_worker(&relay).await,
            "the role rebuild must finish"
        );
        let roles = relay.roles.read().await;
        assert!(!roles.roles.contains_key("r1"));
        assert!(roles.roles.contains_key("r2"));
        assert!(
            !roles.is_member_of(&a),
            "the deleted role's grant must not resurface"
        );
        assert!(
            roles.is_member_of(&b),
            "the surviving role's grant must be restored"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn persist_roles_during_staleness_keeps_the_stored_snapshot() {
        // A persist while the role state is stale must not overwrite the
        // stored snapshot with the fail-closed empty store (or a store that
        // predates the removal): the stored snapshot keeps its older
        // generation stamp, so the next startup rejects it and rebuilds
        // from the surviving events. The drain keeps the rebuild from
        // running, so the staleness is the only reason the write is
        // refused (the database is reachable).
        let key = "01".repeat(32);
        let relay = build_role_relay(Some(&key)).await;
        assert!(relay.create_role("mod", "Mod", "", "", None).await);
        // The mutation path debounces its snapshot save: persist the
        // pre-marking snapshot explicitly so the refusal below has a stored
        // snapshot to protect.
        assert!(relay.persist_roles().await);
        let saved = relay.db.load_roles().await.expect_loaded("snapshot");
        assert!(saved.roles.contains_key("mod"));

        relay.signal_drain();
        relay.mark_roles_stale().await;
        assert!(
            !relay.persist_roles().await,
            "a persist while the role state is stale must be refused"
        );
        // A mutation accepted while stale must not sneak through the gate
        // either.
        relay
            .roles
            .write()
            .await
            .create("ghost", "Ghost", "", "", None);
        assert!(
            !relay.persist_roles().await,
            "a post-marking mutation must not be saved while stale"
        );

        let persisted = relay.db.load_roles().await.expect_loaded("snapshot");
        assert!(
            persisted.roles.contains_key("mod"),
            "the stored snapshot must be untouched"
        );
        assert!(
            !persisted.roles.contains_key("ghost"),
            "the stale store must not overwrite the snapshot"
        );
        assert_eq!(
            persisted.stamp, saved.stamp,
            "the refused persist must not re-stamp the snapshot"
        );
        relay.db.shutdown();
    }

    #[test]
    fn snapshot_below_the_state_sequence_is_rejected_and_rebuilt() {
        // (a) A snapshot saved at sequence N must not be restored once the
        // database advanced to N+1 (a state event was stored): the startup
        // comparison rejects it and the replay rebuild reconstructs the
        // state from the surviving events. The stamp alone cannot detect a
        // put, so the sequence is what protects a skipped debounced save.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
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
                now,
            );
            assert!(matches!(
                relay.accept_event(create.clone(), &[], None).await,
                crate::db::PutOutcome::Stored
            ));
            // The snapshot claims the state before the event: sequence 0.
            let mut snapshot = relay.groups.read().await.snapshot();
            snapshot.stamp = relay.db.state_stamp().await.expect("stamp");
            snapshot.seq = 0;
            assert!(relay.db.save_groups(snapshot).await);

            // The stored event advanced the sequence to 1.
            let seq = relay.db.state_seq_group().await.expect("seq");
            assert_eq!(seq, 1, "the group event must advance the sequence");
            let stamp = relay.db.state_stamp().await.expect("stamp");
            let saved = relay.db.load_groups().await.expect_loaded("snapshot");
            let mut restored = crate::nips::nip29::GroupStore::with_cap(0);
            assert!(
                !restored.restore_checked(saved, stamp, seq),
                "a snapshot below the current sequence must be rejected"
            );
            assert!(
                restored.group("g1").is_none(),
                "the rejected snapshot must not be applied"
            );

            // The rebuild path (what startup runs instead) recovers it.
            let mut rebuilt = crate::nips::nip29::GroupStore::with_cap(0);
            assert!(
                rebuilt.rebuild(&relay.db, None).await,
                "the replay rebuild must succeed"
            );
            assert!(
                rebuilt.group("g1").is_some(),
                "the state event must be rebuilt from the surviving events"
            );
            relay.db.shutdown();
        });
    }

    #[tokio::test]
    async fn snapshot_captured_between_put_and_apply_is_not_certified() {
        // A state event's put commits (advancing the sequence) before its
        // in-memory apply runs. A persist in that window would capture the
        // pre-apply store but stamp it with the post-commit sequence, and
        // the next startup would accept the snapshot and silently lose the
        // event. The in-flight epoch makes the persist defer instead.
        let relay = build_relay().await;
        // The baseline snapshot at sequence 0.
        assert!(relay.persist_groups().await, "the baseline snapshot saves");
        let baseline = relay
            .db
            .load_groups()
            .await
            .expect_loaded("baseline snapshot");

        // The event's put commits, but its in-memory apply has not run yet:
        // claim the epoch the way `accept_event_verified` does.
        let now = crate::util::unix_now();
        let secp = secp256k1::Secp256k1::new();
        let admin = secp256k1::Keypair::from_seckey_slice(&secp, &[4u8; 32]).unwrap();
        let create = signed_group_event(
            &secp,
            &admin,
            crate::nips::nip29::CREATE_GROUP,
            "g1",
            vec![],
            now,
        );
        assert!(matches!(
            relay.db.put(create, now).await,
            crate::db::PutOutcome::Stored
        ));
        let in_flight = relay.groups_rebuild.derived.begin();

        assert!(
            !relay.persist_groups().await,
            "a persist with an unapplied state event must defer"
        );
        let saved = relay.db.load_groups().await.expect_loaded("snapshot");
        assert_eq!(
            saved.seq, baseline.seq,
            "no snapshot may claim the unapplied generation"
        );
        let stamp = relay.db.state_stamp().await.expect("stamp");
        let seq = relay.db.state_seq_group().await.expect("seq");
        assert!(seq > saved.seq, "the put advanced the sequence");
        let mut restored = crate::nips::nip29::GroupStore::with_cap(0);
        assert!(
            !restored.restore_checked(saved, stamp, seq),
            "the pre-apply snapshot must not be accepted as current"
        );

        // Once the apply completes, the next save is certified at the
        // current generation.
        drop(in_flight);
        assert!(relay.persist_groups().await, "the post-apply save lands");
        let saved = relay.db.load_groups().await.expect_loaded("snapshot");
        assert_eq!(saved.seq, seq, "the fresh snapshot carries the sequence");
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn debounced_snapshot_converges_and_restores_after_reopen() {
        // (b) The debounced worker must eventually save the latest state
        // with the database's sequence, and a restart (a new open of the
        // same database) must accept it and restore the state. Correctness
        // does not depend on the save landing (the sequence rejects a
        // skipped save), but a landing save must carry the current
        // sequence.
        let relay = build_relay().await;
        let database = relay.config.read().await.database.clone();
        let now = crate::util::unix_now();
        let secp = secp256k1::Secp256k1::new();
        let admin = secp256k1::Keypair::from_seckey_slice(&secp, &[4u8; 32]).unwrap();
        let create = signed_group_event(
            &secp,
            &admin,
            crate::nips::nip29::CREATE_GROUP,
            "g1",
            vec![],
            now,
        );
        assert!(matches!(
            relay.db.put(create.clone(), now).await,
            crate::db::PutOutcome::Stored
        ));
        relay
            .groups
            .write()
            .await
            .apply(&create, "", now, false, false);
        relay.schedule_groups_persist();

        let mut persisted = None;
        for _ in 0..600 {
            if let crate::db::LoadGroupsOutcome::Loaded(snap) = relay.db.load_groups().await
                && snap.seq == relay.db.state_seq_group().await.unwrap_or(u64::MAX)
            {
                persisted = Some(snap);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let persisted = persisted.expect("the debounced save must converge");
        assert!(persisted.groups.contains_key("g1"));
        relay.db.shutdown();

        // Crash-style check: open the same database fresh and restore.
        let db = crate::db::DbClient::open(
            &database,
            true,
            std::sync::Arc::new(Default::default()),
            0,
            128,
            4096,
            262144,
        )
        .unwrap();
        let saved = db
            .load_groups()
            .await
            .expect_loaded("snapshot after reopen");
        let seq = db.state_seq_group().await.expect("seq");
        assert_eq!(
            saved.seq, seq,
            "the reopened snapshot must carry the latest sequence"
        );
        let mut store = crate::nips::nip29::GroupStore::with_cap(0);
        assert!(
            store.restore_checked(saved, db.state_stamp().await.expect("stamp"), seq),
            "a snapshot at the current sequence must restore"
        );
        assert!(store.group("g1").is_some());
        db.shutdown();
    }

    #[tokio::test]
    async fn role_mutation_during_a_rebuild_survives_the_swap() {
        // (c) A mutation accepted while the rebuild scan runs lands on the
        // fail-closed live store; it must be replayed onto the freshly
        // rebuilt store instead of being lost by the swap.
        let key = "01".repeat(32);
        let relay = build_role_relay(Some(&key)).await;
        let member = "aa".repeat(32);
        assert!(relay.create_role("king", "King", "", "", None).await);
        // The scan is in flight: enter its buffering window.
        relay.roles_rebuild.buffer.lock().await.scanning = true;
        assert_eq!(
            relay.assign_role(&member, "king").await,
            RoleChange::Applied
        );
        {
            let buffer = relay.roles_rebuild.buffer.lock().await;
            assert_eq!(
                buffer.mutations.len(),
                1,
                "the accepted mutation must be captured for replay"
            );
        }
        // The scan completed: it found the stored role definition but
        // predates the assignment.
        let mut fresh = RoleStore::default();
        fresh.create("king", "King", "", "", None);
        assert!(
            relay
                .roles_rebuild
                .finish_rebuild(&relay.roles, fresh)
                .await,
            "the fresh store must be swapped in"
        );
        assert!(
            relay.roles.read().await.is_member_of(&member),
            "the buffered mutation must survive the swap"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn finish_rebuild_holds_the_buffer_lock_across_the_swap() {
        // A mutation accepted after the buffer take but before the swap
        // would apply to the live store and then be overwritten by the
        // freshly rebuilt store (its capture would see `scanning == false`).
        // Holding the buffer lock across the swap makes it either land in
        // the buffered set or wait and apply to the swapped-in store.
        let key = "01".repeat(32);
        let relay = build_role_relay(Some(&key)).await;
        let member = "aa".repeat(32);
        // Hold the roles write lock so `finish_rebuild` blocks while
        // already holding the buffer lock: the interleaving is then
        // deterministic.
        let gate = relay.roles.write().await;
        let mut fresh = RoleStore::default();
        fresh.create("king", "King", "", "", None);
        let task_relay = relay.clone();
        let handle = tokio::spawn(async move {
            task_relay
                .roles_rebuild
                .finish_rebuild(&task_relay.roles, fresh)
                .await
        });
        tokio::task::yield_now().await;
        assert!(
            relay.roles_rebuild.buffer.try_lock().is_err(),
            "the buffer lock must be held from the take through the swap"
        );
        drop(gate);
        assert!(handle.await.unwrap(), "the fresh store must be swapped in");
        assert_eq!(
            relay.assign_role(&member, "king").await,
            RoleChange::Applied
        );
        assert!(
            relay.roles.read().await.is_member_of(&member),
            "the post-swap mutation must apply to the swapped-in store"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn nip29_only_deletion_does_not_scan_roles() {
        // A NIP-09 deletion of a NIP-29 state event must mark only the
        // group store stale: revoking and rescanning the NIP-43 roles on
        // every group deletion is both a correctness hazard (a NIP-29-only
        // removal clears live grants) and a full-history scan per event.
        let key = "01".repeat(32);
        let relay = build_role_relay(Some(&key)).await;
        relay.config.write().await.relay.enabled_nips = vec![9, 29, 43];
        let member = "aa".repeat(32);
        assert!(relay.create_role("mod", "Mod", "", "", None).await);
        assert_eq!(relay.assign_role(&member, "mod").await, RoleChange::Applied);

        let now = crate::util::unix_now();
        let secp = secp256k1::Secp256k1::new();
        let author = secp256k1::Keypair::from_seckey_slice(&secp, &[21u8; 32]).unwrap();
        let edit = signed_group_event(&secp, &author, 9002, "g-state", vec![], now);
        assert_eq!(
            relay.db.put(edit.clone(), now).await,
            crate::db::PutOutcome::Stored
        );

        let mut deletion = crate::event::Event {
            id: String::new(),
            pubkey: secp256k1::XOnlyPublicKey::from_keypair(&author)
                .0
                .to_string(),
            created_at: now,
            kind: crate::nips::nip09::DELETION_KIND,
            tags: vec![vec!["e".into(), edit.id.clone()]],
            content: String::new(),
            sig: String::new(),
        };
        deletion.id = crate::nips::nip01::compute_id(&deletion);
        let raw = deletion.id_bytes().unwrap();
        deletion.sig = secp.sign_schnorr_no_aux_rand(&raw, &author).to_string();
        assert!(matches!(
            relay.accept_event(deletion, &[], None).await,
            crate::db::PutOutcome::Stored
        ));

        assert!(
            wait_for_rebuild_worker(&relay).await,
            "the group rebuild must run"
        );
        assert_eq!(
            relay
                .roles_rebuild
                .rebuilds
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "a NIP-29-only removal must not trigger a role scan"
        );
        assert!(
            relay.roles.read().await.is_member_of(&member),
            "the live role grants must survive a NIP-29-only deletion"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn recovery_done_marks_the_state_stale_after_a_resumed_deletion() {
        // The db writer resumes an interrupted NIP-09 deletion during
        // `open`; when it removed a derived-state event, the startup
        // barrier must mark the group/role stores stale so the startup
        // restore/rebuild cannot certify pre-removal state.
        use crate::db::store::{Store, encode_pending_deletion, pending_deletion_key};
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join("nostrfy-relay-resumed-deletion")
            .join(format!("{:x}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        let mut cfg = crate::config::Config::default();
        cfg.database.path = path;
        cfg.database.map_size = 16 * 1024 * 1024;
        cfg.database.max_map_size = 64 * 1024 * 1024;
        let expiry = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let store = Store::open(&cfg.database, std::sync::Arc::clone(&expiry), 128)
            .expect("the scratch store opens");
        let now = crate::util::unix_now();
        // A stored NIP-29 state event and the pending deletion that targets
        // it (what a crash mid-walk leaves behind).
        let author = "aa".repeat(32);
        let mut edit = crate::event::Event {
            id: String::new(),
            pubkey: author.clone(),
            created_at: now.saturating_sub(10),
            kind: 9002,
            tags: vec![vec!["h".into(), "g1".into()]],
            content: String::new(),
            sig: String::new(),
        };
        edit.id = crate::nips::nip01::compute_id(&edit);
        {
            let mut wtxn = store.env.write_txn().unwrap();
            store
                .put_event_in(&mut wtxn, &edit, now)
                .expect("the state event stores");
            wtxn.commit().unwrap();
        }
        let encoded = encode_pending_deletion(
            &[edit.id.clone()],
            &[],
            Some(author.as_str()),
            u64::MAX,
            None,
        );
        {
            let mut wtxn = store.env.write_txn().unwrap();
            store
                .delete_pending
                .put(&mut wtxn, &pending_deletion_key(&encoded), &encoded)
                .unwrap();
            wtxn.commit().unwrap();
        }
        let db = crate::db::DbClient::open_with_store(
            &cfg.database,
            store,
            expiry,
            std::sync::Arc::new(Default::default()),
            0,
            128,
            4096,
        )
        .expect("the db client opens");
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
        assert!(
            relay.db.resumed_deletion_state_removed(),
            "the startup resume must expose the removed state event"
        );
        assert!(
            !relay
                .groups_rebuild
                .pending
                .load(std::sync::atomic::Ordering::SeqCst),
            "the state is not marked before the barrier runs"
        );
        // Drain first so the scheduled rebuild workers cannot clear the
        // flags before the assertions (fail-closed is what matters for a
        // real shutdown, and this keeps the interleaving deterministic).
        relay.signal_drain();
        relay.recovery_done().await;
        assert!(
            relay
                .groups_rebuild
                .pending
                .load(std::sync::atomic::Ordering::SeqCst),
            "a resumed state removal must keep the group snapshot dropped"
        );
        assert!(
            relay
                .roles_rebuild
                .dirty
                .load(std::sync::atomic::Ordering::SeqCst),
            "a resumed state removal must revoke the live role grants"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn role_rebuild_buffer_overflow_forces_a_retry() {
        // A full buffer must not replay a partial mutation set: the worker
        // discards the fresh store, keeps the fail-closed live store and
        // marks the state dirty for another rebuild.
        let key = "01".repeat(32);
        let relay = build_role_relay(Some(&key)).await;
        let member = "aa".repeat(32);
        assert!(relay.create_role("king", "King", "", "", None).await);
        {
            let mut buffer = relay.roles_rebuild.buffer.lock().await;
            buffer.scanning = true;
            buffer.mutations.clear();
            buffer.overflow = false;
            while buffer.mutations.len() < ROLES_REBUILD_BUFFER_MAX {
                buffer
                    .mutations
                    .push(BufferedRoleMutation::Delete { id: "x".into() });
            }
        }
        assert_eq!(
            relay.assign_role(&member, "king").await,
            RoleChange::Applied
        );
        {
            let buffer = relay.roles_rebuild.buffer.lock().await;
            assert!(
                buffer.overflow,
                "an overflowing buffer must force the worker to discard the scan"
            );
            assert_eq!(
                buffer.mutations.len(),
                ROLES_REBUILD_BUFFER_MAX,
                "no partial mutation set may be kept"
            );
        }
        let mut fresh = RoleStore::default();
        fresh.create("king", "King", "", "", None);
        assert!(
            !relay
                .roles_rebuild
                .finish_rebuild(&relay.roles, fresh)
                .await,
            "an overflow must discard the fresh store"
        );
        assert!(
            relay.roles_rebuild.dirty.load(Ordering::SeqCst),
            "the overflow must mark the state dirty for another rebuild"
        );
        assert!(
            relay.roles.read().await.is_member_of(&member),
            "the live store keeps the applied mutation"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn failed_role_rebuild_keeps_the_store_empty_and_dirty() {
        // A failed rebuild must keep the live store fail-closed (empty) and
        // the dirty flag set, so the next removal retries and the next
        // startup rebuilds from the surviving events.
        let key = "01".repeat(32);
        let relay = build_role_relay(Some(&key)).await;
        assert!(relay.create_role("mod", "Mod", "", "", None).await);
        relay.db.shutdown();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        relay.mark_roles_stale().await;
        assert!(
            relay.roles.read().await.roles.is_empty(),
            "the marking path must revoke the live grants immediately"
        );
        assert!(
            wait_for_roles_rebuild_worker(&relay).await,
            "the failed worker must finish"
        );
        assert!(
            relay
                .roles_rebuild
                .dirty
                .load(std::sync::atomic::Ordering::SeqCst),
            "a failed rebuild must preserve the dirty flag"
        );
        assert!(
            relay.roles.read().await.roles.is_empty(),
            "a failed rebuild must leave the fail-closed empty store"
        );
        assert_eq!(
            relay.rebuild_failures(),
            1,
            "the failed role scan must be counted exactly once"
        );
    }

    #[tokio::test]
    async fn drain_prevents_new_role_rebuilds() {
        // Shutdown must not start a role rebuild scan whose result cannot be
        // persisted: the live store stays fail-closed (empty) and dirty, and
        // the next startup rebuilds from the surviving events.
        let key = "01".repeat(32);
        let relay = build_role_relay(Some(&key)).await;
        assert!(relay.create_role("mod", "Mod", "", "", None).await);
        relay.signal_drain();
        relay.mark_roles_stale().await;
        assert!(
            !relay
                .roles_rebuild
                .running
                .load(std::sync::atomic::Ordering::SeqCst),
            "a drained relay must not spawn a role rebuild worker"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            relay.roles.read().await.roles.is_empty(),
            "a drained relay must not run a rebuild scan"
        );
        assert!(
            relay
                .roles_rebuild
                .dirty
                .load(std::sync::atomic::Ordering::SeqCst),
            "the unchanged state must stay dirty so the next startup rebuilds"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn drain_stops_the_role_rebuild_worker() {
        // A worker that is already scheduled must observe the drain before
        // its first scan and exit: the live store stays fail-closed. The
        // signal is sent before the spawned worker gets its first poll (the
        // test runtime is single-threaded and `mark_roles_stale` yields no
        // pending await), so the drain is visible at the loop head.
        let key = "01".repeat(32);
        let relay = build_role_relay(Some(&key)).await;
        assert!(relay.create_role("mod", "Mod", "", "", None).await);
        relay.mark_roles_stale().await;
        relay.signal_drain();
        assert!(
            wait_for_roles_rebuild_worker(&relay).await,
            "the draining worker must finish"
        );
        assert!(
            relay.roles.read().await.roles.is_empty(),
            "a draining worker must not restore the live store"
        );
        assert!(
            relay
                .roles_rebuild
                .dirty
                .load(std::sync::atomic::Ordering::SeqCst),
            "the aborted state must stay dirty so the next startup rebuilds"
        );
        relay.db.shutdown();
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
        assert!(
            !relay.persist_relay_field("name", "newname").await,
            "an unpersisted change must report failure"
        );
        // A writable temp config: the field is updated on disk.
        let dir = std::env::temp_dir().join("nostrfy-persist-field-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nostrfy.toml");
        std::fs::write(&path, "[relay]\nname = \"old\"\ndescription = \"d\"\n").unwrap();
        *relay.config_path.write().await = Some(path.clone());
        assert!(relay.persist_relay_field("name", "newname").await);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.contains("newname"),
            "the field must be persisted: {text}"
        );
        // An unreadable path warns and leaves the in-memory change applied.
        *relay.config_path.write().await = Some(dir.join("missing.toml"));
        assert!(
            !relay.persist_relay_field("description", "x").await,
            "an unwritable path must report failure"
        );
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
        // (a ban silently vanishing on the next restart). Mutations go
        // through the op log (as the NIP-86 paths do) and each persist
        // merges onto a freshly reloaded state under one lock.
        let relay = build_relay().await;
        for i in 0..32u32 {
            let a = format!("a{i:020x}");
            let b = format!("b{i:020x}");
            let ra = relay.clone();
            let rb = relay.clone();
            let (a2, b2) = (a.clone(), b.clone());
            let ta = tokio::spawn(async move {
                let op = crate::config::AccessOp::BanPubkey {
                    pubkey: a2,
                    reason: String::new(),
                    insensitive: true,
                };
                {
                    let mut access = ra.access.write().await;
                    crate::config::apply_access_op(&mut access, &op);
                    ra.push_access_ops(vec![op]);
                }
                ra.persist_access().await;
            });
            let tb = tokio::spawn(async move {
                let op = crate::config::AccessOp::BanPubkey {
                    pubkey: b2,
                    reason: String::new(),
                    insensitive: true,
                };
                {
                    let mut access = rb.access.write().await;
                    crate::config::apply_access_op(&mut access, &op);
                    rb.push_access_ops(vec![op]);
                }
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

    /// Builds a relay whose database store has a one-shot removal fault
    /// armed, so the retryable acknowledgment paths are testable without a
    /// real partial walk.
    async fn build_faulty_relay(arm_vanish: bool, arm_delete: bool) -> std::sync::Arc<Relay> {
        use crate::db::store::Store;
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join("nostrfy-relay-removal-fault")
            .join(format!("{:x}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        let mut cfg = crate::config::Config::default();
        cfg.database.path = path;
        cfg.database.map_size = 16 * 1024 * 1024;
        cfg.database.max_map_size = 64 * 1024 * 1024;
        let expiry = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let store = Store::open(&cfg.database, std::sync::Arc::clone(&expiry), 128)
            .expect("the scratch store opens");
        if arm_vanish {
            store
                .fail_next_vanish_chunk
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        if arm_delete {
            store
                .fail_next_delete_chunk
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        let db = crate::db::DbClient::open_with_store(
            &cfg.database,
            store,
            expiry,
            std::sync::Arc::new(Default::default()),
            0,
            128,
            4096,
        )
        .expect("the db client opens");
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
        std::sync::Arc::new(relay)
    }

    #[test]
    fn vanish_failure_is_reported_as_retryable() {
        // A vanish whose removal walk fails must not be acknowledged with
        // `OK true`: the client retries, and the pending record lets the
        // next startup finish the removal.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            use crate::db::PutOutcome;
            let relay = build_faulty_relay(true, false).await;
            let now = crate::util::unix_now();
            let secp = secp256k1::Secp256k1::new();
            let keypair = secp256k1::Keypair::from_seckey_slice(&secp, &[3u8; 32]).unwrap();
            let pubkey = secp256k1::XOnlyPublicKey::from_keypair(&keypair)
                .0
                .to_string();
            // A stored event by the vanishing pubkey: the walk has work and
            // fails after its first chunk committed.
            let mut old = crate::event::Event {
                id: String::new(),
                pubkey: pubkey.clone(),
                created_at: now.saturating_sub(10),
                kind: 1,
                tags: vec![],
                content: "old".into(),
                sig: String::new(),
            };
            old.id = crate::nips::nip01::compute_id(&old);
            let raw = old.id_bytes().unwrap();
            old.sig = secp.sign_schnorr_no_aux_rand(&raw, &keypair).to_string();
            assert_eq!(relay.db.put(old.clone(), now).await, PutOutcome::Stored);

            let mut vanish = crate::event::Event {
                id: String::new(),
                pubkey: pubkey.clone(),
                created_at: now,
                kind: 62,
                tags: vec![vec!["relay".into(), "ws://127.0.0.1:8080".into()]],
                content: "vanish".into(),
                sig: String::new(),
            };
            vanish.id = crate::nips::nip01::compute_id(&vanish);
            let raw = vanish.id_bytes().unwrap();
            vanish.sig = secp.sign_schnorr_no_aux_rand(&raw, &keypair).to_string();

            let outcome = relay.accept_event(vanish, &[], None).await;
            assert!(
                matches!(&outcome, PutOutcome::Invalid(r) if r.contains("vanish") && r.contains("retry")),
                "a failed vanish must report a retryable failure: {outcome:?}"
            );
            // The walk failed before completion, so no completed marker was
            // written and the in-progress record remains for the startup
            // resume (the pubkey must still be accepted until then).
            let counts = relay
                .db
                .table_counts()
                .await
                .expect("the table counts must be readable");
            assert_eq!(
                counts.vanish, 0,
                "a failed vanish must not write the completed marker"
            );
            assert!(
                counts.vanish_pending >= 1,
                "the in-progress vanish record must exist for the startup resume"
            );
            relay.db.shutdown();
        });
    }

    #[test]
    fn batch_vanish_failure_is_reported_as_retryable() {
        // The batch path (a vanish-only batch resolves without a writer
        // receiver) must apply the same retryable-failure ack.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_faulty_relay(true, false).await;
            let now = crate::util::unix_now();
            let secp = secp256k1::Secp256k1::new();
            let keypair = secp256k1::Keypair::from_seckey_slice(&secp, &[5u8; 32]).unwrap();
            let pubkey = secp256k1::XOnlyPublicKey::from_keypair(&keypair)
                .0
                .to_string();
            let mut vanish = crate::event::Event {
                id: String::new(),
                pubkey,
                created_at: now,
                kind: 62,
                tags: vec![vec!["relay".into(), "ws://127.0.0.1:8080".into()]],
                content: "vanish".into(),
                sig: String::new(),
            };
            vanish.id = crate::nips::nip01::compute_id(&vanish);
            let raw = vanish.id_bytes().unwrap();
            vanish.sig = secp.sign_schnorr_no_aux_rand(&raw, &keypair).to_string();
            let results = relay.accept_events_batch(vec![vanish], &[]).await;
            assert_eq!(results.len(), 1);
            assert!(
                matches!(&results[0].1, crate::db::PutOutcome::Invalid(r) if r.contains("vanish") && r.contains("retry")),
                "the batch vanish ack must be retryable on failure: {results:?}"
            );
            relay.db.shutdown();
        });
    }

    #[test]
    fn nip09_deletion_failure_is_reported_as_retryable() {
        // A NIP-09 deletion whose removal walk fails mid-way must report a
        // retryable failure (the client retries; the durable pending record
        // lets the startup resume finish it) and still mark the derived
        // state stale for the events the partial walk removed.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            use crate::db::PutOutcome;
            let relay = build_faulty_relay(false, true).await;
            let now = crate::util::unix_now();
            let secp = secp256k1::Secp256k1::new();
            let author = secp256k1::Keypair::from_seckey_slice(&secp, &[6u8; 32]).unwrap();
            let author_pk = secp256k1::XOnlyPublicKey::from_keypair(&author)
                .0
                .to_string();
            // A stored NIP-29 state event the deletion targets.
            let mut edit = crate::event::Event {
                id: String::new(),
                pubkey: author_pk.clone(),
                created_at: now.saturating_sub(10),
                kind: 9002,
                tags: vec![
                    vec!["h".into(), "g1".into()],
                    vec!["private".into()],
                ],
                content: String::new(),
                sig: String::new(),
            };
            edit.id = crate::nips::nip01::compute_id(&edit);
            let raw = edit.id_bytes().unwrap();
            edit.sig = secp.sign_schnorr_no_aux_rand(&raw, &author).to_string();
            assert_eq!(relay.db.put(edit.clone(), now).await, PutOutcome::Stored);

            let mut deletion = crate::event::Event {
                id: String::new(),
                pubkey: author_pk,
                created_at: now,
                kind: crate::nips::nip09::DELETION_KIND,
                tags: vec![vec!["e".into(), edit.id.clone()]],
                content: String::new(),
                sig: String::new(),
            };
            deletion.id = crate::nips::nip01::compute_id(&deletion);
            let raw = deletion.id_bytes().unwrap();
            deletion.sig = secp.sign_schnorr_no_aux_rand(&raw, &author).to_string();

            let outcome = relay.accept_event(deletion, &[], None).await;
            assert!(
                matches!(&outcome, PutOutcome::Invalid(r) if r.contains("removal") && r.contains("retry")),
                "a failed deletion side effect must report a retryable failure: {outcome:?}"
            );
            let pending = relay
                .db
                .pending_deletions()
                .await
                .expect("the pending deletions must be readable");
            assert_eq!(
                pending.len(),
                1,
                "the durable pending record must exist for the startup resume"
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
    fn rejected_sibling_does_not_satisfy_a_previous_reference() {
        // The batch's known-reference set may only contain events that were
        // actually accepted (or already stored): a rejected sibling must not
        // satisfy a later event's `previous` tag.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            use crate::db::PutOutcome;

            let relay = build_relay().await;
            let now = crate::util::unix_now();
            let secp = secp256k1::Secp256k1::new();
            let keypair = secp256k1::Keypair::from_seckey_slice(&secp, &[7u8; 32]).unwrap();
            let signed = |kind: u64, content: &str, tags: Vec<Vec<String>>| {
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
                tags.insert(0, vec!["h".into(), "g-rejected".into()]);
                tags
            };
            let mut results = relay
                .accept_events_batch(vec![signed(9007, "", h(vec![]))], &[])
                .await;
            assert!(matches!(results.remove(0).1, PutOutcome::Stored));

            // The first sibling is rejected (corrupted signature); the
            // second references its id prefix via `previous`.
            let mut first = signed(1, "first", h(vec![]));
            first.sig = "00".repeat(64);
            let prefix = first.id[..8].to_string();
            let second = signed(
                1,
                "second",
                h(vec![vec!["previous".into(), prefix.clone()]]),
            );
            let first_id = first.id.clone();
            let results = relay.accept_events_batch(vec![first, second], &[]).await;
            assert_eq!(results[0].0, first_id);
            assert!(
                matches!(&results[0].1, PutOutcome::Invalid(r) if r.contains("signature")),
                "the first sibling must be rejected: {results:?}"
            );
            assert!(
                matches!(&results[1].1, PutOutcome::Invalid(r) if r.contains("previous")),
                "a rejected sibling must not satisfy a previous reference: {results:?}"
            );
            relay.db.shutdown();
        });
    }

    #[test]
    fn capped_previous_prefetch_reports_a_retryable_rejection() {
        // A batch whose `previous` references exceed the prefetch cap: the
        // references past the cap are absent from `known` through no fault
        // of the client, so the precheck must report the miss as a
        // retryable rate limit instead of claiming the reference is
        // unknown. The event is still rejected and no per-reference lookup
        // is added.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            use crate::db::PutOutcome;

            let relay = build_relay().await;
            let now = crate::util::unix_now();
            let secp = secp256k1::Secp256k1::new();
            let keypair = secp256k1::Keypair::from_seckey_slice(&secp, &[7u8; 32]).unwrap();
            let signed = |kind: u64, content: &str, tags: Vec<Vec<String>>| {
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
                tags.insert(0, vec!["h".into(), "g-capped".into()]);
                tags
            };
            let mut results = relay
                .accept_events_batch(vec![signed(9007, "", h(vec![]))], &[])
                .await;
            assert!(matches!(results.remove(0).1, PutOutcome::Stored));

            // 1025 distinct, uncommitted references: the prefetch stops at
            // 1024 and reports the cap.
            let mut previous = vec!["previous".to_string()];
            previous.extend((0..1025).map(|i| format!("{i:08x}")));
            let event = signed(1, "capped", h(vec![previous]));
            let (_, capped) = relay
                .batch_known_prefixes(std::slice::from_ref(&event))
                .await;
            assert!(capped, "the prefetch must report the cap");
            let results = relay.accept_events_batch(vec![event], &[]).await;
            match &results[0].1 {
                PutOutcome::Invalid(m) => {
                    assert!(
                        m.contains("rate-limited") && m.contains("retry"),
                        "a capped-prefetch miss must be retryable: {m}"
                    );
                    assert!(
                        !m.contains("unknown previous"),
                        "a capped-prefetch miss must not blame the reference: {m}"
                    );
                }
                other => panic!("the capped event must be rejected: {other:?}"),
            }
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
            // While the state is pending the on-disk snapshot must stay
            // dropped (fail-closed): a crash now must rebuild from the
            // surviving events, not restore pre-vanish state. The flag is
            // sampled around the load so a rebuild that completed in
            // between (and legitimately persisted the fresh snapshot)
            // cannot trip the invariant.
            let pending_before = relay
                .groups_rebuild
                .pending
                .load(std::sync::atomic::Ordering::SeqCst);
            let snapshot = relay.db.load_groups().await;
            let pending_after = relay
                .groups_rebuild
                .pending
                .load(std::sync::atomic::Ordering::SeqCst);
            if pending_before && pending_after {
                assert!(
                    snapshot.is_none(),
                    "a pending rebuild must leave the persisted snapshot dropped"
                );
            }
            // Wait for the worker to finish and persist the fresh snapshot:
            // the pending flag clears just before the save, so the snapshot
            // is the completion signal.
            let mut persisted = None;
            for _ in 0..600 {
                if !relay
                    .groups_rebuild
                    .pending
                    .load(std::sync::atomic::Ordering::SeqCst)
                    && let crate::db::LoadGroupsOutcome::Loaded(snap) = relay.db.load_groups().await
                {
                    persisted = Some(snap);
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            assert!(
                persisted.is_some(),
                "the coalesced rebuild must converge and persist"
            );
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
            // A real bound: at least one scan must run (zero means the
            // rebuild never happened) and the five vanishes must coalesce
            // into fewer scans than triggers (the minimum-interval floor
            // batches the tail). An absolute cap would be flaky on slow
            // runners, where each vanish can take longer than the floor.
            let scans = relay
                .groups_rebuild
                .rebuilds
                .load(std::sync::atomic::Ordering::Relaxed);
            assert!(
                scans >= 1 && scans < gids.len() as u64,
                "a burst of {} vanishes must coalesce into fewer than {} scans, got {scans}",
                gids.len(),
                gids.len()
            );
            // The fresh snapshot carries the rebuilt (fail-closed) state: a
            // restart must not resurrect the vanished groups.
            let snapshot = persisted.expect("checked above");
            assert!(
                snapshot.groups.is_empty() && snapshot.ghost.len() >= gids.len(),
                "the rebuilt snapshot must carry the ghosts, not the groups"
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
                let snap = relay
                    .db
                    .load_groups()
                    .await
                    .expect_loaded("snapshot persisted");
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

    /// Waits until no group rebuild worker is running (successful or
    /// failed).
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

    /// Waits until no role rebuild worker is running (successful or failed).
    async fn wait_for_roles_rebuild_worker(relay: &Relay) -> bool {
        for _ in 0..600 {
            if !relay
                .roles_rebuild
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
    async fn deletion_touching_both_stores_marks_both() {
        // A single capped page over both families could fill up on one
        // side (a deletion naming 64 group-state ids plus a role-state
        // id) and miss the other store, leaving deleted role grants live.
        // The relevance check is per family, so one event per side suffices.
        let relay = build_relay().await;
        let secp = secp256k1::Secp256k1::new();
        let keypair = secp256k1::Keypair::from_seckey_slice(&secp, &[7u8; 32]).unwrap();
        let now = crate::util::unix_now();
        let mut target_ids = Vec::new();
        // The role event is older than the 64 group events: a single capped
        // page filled newest-first can never contain it, so the old code
        // could not mark the role store.
        for i in 0..64u64 {
            let event = signed_group_event(
                &secp,
                &keypair,
                9000,
                "g1",
                vec![vec!["p".into(), format!("m{i:04}")]],
                now.saturating_sub(50),
            );
            target_ids.push(event.id.clone());
            relay.db.put(event, now).await;
        }
        let role = signed_group_event(
            &secp,
            &keypair,
            crate::nips::nip43::ROLE_DEFINITION,
            "g1",
            vec![],
            now.saturating_sub(100),
        );
        target_ids.push(role.id.clone());
        relay.db.put(role, now).await;
        let mut tags = vec![];
        for id in &target_ids {
            tags.push(vec!["e".into(), id.clone()]);
        }
        let deletion = signed_group_event(&secp, &keypair, 5, "g1", tags, now);
        let touch = relay.deletion_touches_group_state(&deletion).await;
        assert!(
            touch.groups && touch.roles,
            "a deletion touching both families must mark both, got {touch:?}"
        );
        relay.db.shutdown();
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
    async fn pending_group_purge_is_resumed_to_completion() {
        // A crash mid-walk leaves the purge recorded in the database's
        // pending table. The startup resume must finish the purge, confirm
        // it, downgrade the fail-closed ghost to the ordinary delete
        // tombstone and persist — so a create can re-use the id while the
        // un-purged history cannot surface. The pending record is seeded
        // directly (an in-process crash cannot be reproduced).
        use crate::db::PutOutcome;
        use crate::db::store::{Store, encode_pending_purge, purged_group_key};

        let now = crate::util::unix_now();
        let mut cfg = crate::config::Config::default();
        cfg.database.map_size = 16 * 1024 * 1024;
        cfg.database.max_map_size = 64 * 1024 * 1024;
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        cfg.database.path = std::env::temp_dir()
            .join("nostrfy-resume-purge")
            .join(format!("{:x}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&cfg.database.path);
        let expiry = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let store = Store::open(&cfg.database, std::sync::Arc::clone(&expiry), 128)
            .expect("the scratch store opens");
        {
            // What a crash after `purge_group`'s first commit leaves behind:
            // the purge marker plus the in-progress record, no completed walk.
            let mut wtxn = store.env.write_txn().unwrap();
            store
                .purge_pending
                .put(
                    &mut wtxn,
                    &purged_group_key("g1"),
                    &encode_pending_purge("g1", now, now, u64::MAX, None),
                )
                .unwrap();
            wtxn.commit().unwrap();
        }
        let db = crate::db::DbClient::open_with_store(
            &cfg.database,
            store,
            expiry,
            std::sync::Arc::new(Default::default()),
            0,
            128,
            4096,
        )
        .unwrap();
        let config = std::sync::Arc::new(tokio::sync::RwLock::new(cfg));
        let mut relay = Relay::new(
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
        relay.start_live_bus();
        let relay = std::sync::Arc::new(relay);

        assert_eq!(
            relay.db.pending_purges().await,
            Some(vec![("g1".to_string(), now, u64::MAX)]),
            "the seeded pending purge must be visible at startup"
        );

        let secp = secp256k1::Secp256k1::new();
        let admin = secp256k1::Keypair::from_seckey_slice(&secp, &[4u8; 32]).unwrap();
        let create = signed_group_event(
            &secp,
            &admin,
            crate::nips::nip29::CREATE_GROUP,
            "g1",
            vec![],
            now.saturating_sub(10),
        );
        let message = signed_group_event(&secp, &admin, 1, "g1", vec![], now.saturating_sub(10));
        let delete = signed_group_event(
            &secp,
            &admin,
            crate::nips::nip29::DELETE_GROUP,
            "g1",
            vec![],
            now,
        );
        for event in [&create, &message, &delete] {
            assert_eq!(relay.db.put(event.clone(), now).await, PutOutcome::Stored);
        }
        // The pre-crash in-memory state: the 9008 applied (the group is
        // gone) and its id is ghosted because the purge was never confirmed.
        {
            let mut groups = relay.groups.write().await;
            groups.apply(&create, "", now.saturating_sub(10), false, false);
            groups.apply(&delete, "", now, false, false);
        }
        relay.ghost_deleted_group("g1").await;
        let filter: crate::filter::Filter =
            serde_json::from_value(serde_json::json!({"#h": ["g1"]})).unwrap();
        assert_eq!(
            relay.db.query(vec![filter.clone()], 10, now).await.0.len(),
            3,
            "the crashed purge must leave the group's history stored"
        );

        // The startup call the server makes after the snapshot restore.
        relay.resume_pending_purges().await;

        assert_eq!(
            relay.db.pending_purges().await,
            Some(Vec::new()),
            "the resumed purge must clear the pending record"
        );
        assert!(
            relay.db.query(vec![filter], 10, now).await.0.is_empty(),
            "the resumed purge must remove the group's stored events"
        );
        {
            let groups = relay.groups.read().await;
            assert!(
                !groups.ghost_group_ids().contains(&"g1".to_string()),
                "a confirmed resume must clear the fail-closed ghost"
            );
            assert!(
                groups.deleted_group_ids().contains(&"g1".to_string()),
                "the confirmed purge must downgrade the ghost to the delete tombstone"
            );
        }
        // The persisted snapshot must reflect the confirmed purge (with the
        // generation stamp of the purge's state-stamp bump), so a restart
        // does not re-ghost the id.
        let snap = relay
            .db
            .load_groups()
            .await
            .expect_loaded("the confirmed resume must persist a snapshot");
        assert!(
            snap.stamp > 0,
            "the snapshot must carry the purge's generation stamp"
        );
        assert!(
            !snap.ghost.contains("g1") && snap.deleted.contains("g1"),
            "the snapshot must hold the downgraded tombstone, not the ghost"
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
                PutOutcome::Stored
            ),
            "a resumed, confirmed purge must leave the id re-creatable"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn a_bounded_pending_purge_resumes_and_reveals_the_recreated_group() {
        // A migration-recorded purge is bounded by the 9008's timestamp: a
        // crash mid-purge leaves the re-created group's later events, and
        // the resume must confirm against the bound (an unbounded
        // confirmation would keep the id ghosted for the whole session)
        // and rebuild the state from the survivors.
        use crate::db::PutOutcome;
        use crate::db::store::{
            Store, encode_pending_purge, encode_purged_group_marker, purged_group_key,
        };

        let now = crate::util::unix_now();
        let mut cfg = crate::config::Config::default();
        cfg.database.map_size = 16 * 1024 * 1024;
        cfg.database.max_map_size = 64 * 1024 * 1024;
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        cfg.database.path = std::env::temp_dir()
            .join("nostrfy-resume-bounded-purge")
            .join(format!("{:x}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&cfg.database.path);
        let expiry = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let store = Store::open(&cfg.database, std::sync::Arc::clone(&expiry), 128)
            .expect("the scratch store opens");
        let secp = secp256k1::Secp256k1::new();
        let admin = secp256k1::Keypair::from_seckey_slice(&secp, &[4u8; 32]).unwrap();
        let create = signed_group_event(
            &secp,
            &admin,
            crate::nips::nip29::CREATE_GROUP,
            "g1",
            vec![],
            now.saturating_sub(10),
        );
        let create_id: [u8; 32] = create.id_bytes().expect("a valid id");
        let message = signed_group_event(&secp, &admin, 1, "g1", vec![], now.saturating_sub(10));
        let delete = signed_group_event(
            &secp,
            &admin,
            crate::nips::nip29::DELETE_GROUP,
            "g1",
            vec![],
            now,
        );
        let recreate = signed_group_event(
            &secp,
            &admin,
            crate::nips::nip29::CREATE_GROUP,
            "g1",
            vec![],
            now.saturating_add(1),
        );
        let new_post = signed_group_event(&secp, &admin, 1, "g1", vec![], now.saturating_add(2));
        {
            // The events were imported before the purge started: store them
            // first, then seed what a bounded `purge_group_until`'s first
            // commit leaves (the marker and the in-progress record, both
            // carrying the bound and the purged create's id).
            let mut wtxn = store.env.write_txn().unwrap();
            for event in [&create, &message, &delete, &recreate, &new_post] {
                store.put_event_in(&mut wtxn, event, now).unwrap();
            }
            wtxn.commit().unwrap();
            let mut wtxn = store.env.write_txn().unwrap();
            store
                .purged_groups
                .put(
                    &mut wtxn,
                    &purged_group_key("g1"),
                    &encode_purged_group_marker(now, now, Some(&create_id)),
                )
                .unwrap();
            store
                .purge_pending
                .put(
                    &mut wtxn,
                    &purged_group_key("g1"),
                    &encode_pending_purge("g1", now, now, now, Some(&create_id)),
                )
                .unwrap();
            wtxn.commit().unwrap();
        }
        let db = crate::db::DbClient::open_with_store(
            &cfg.database,
            store,
            expiry,
            std::sync::Arc::new(Default::default()),
            0,
            128,
            4096,
        )
        .unwrap();
        let config = std::sync::Arc::new(tokio::sync::RwLock::new(cfg));
        let mut relay = Relay::new(
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
        relay.start_live_bus();
        let relay = std::sync::Arc::new(relay);

        relay.resume_pending_purges().await;

        assert_eq!(
            relay.db.pending_purges().await,
            Some(Vec::new()),
            "the bounded resume must clear the pending record"
        );
        let filter: crate::filter::Filter =
            serde_json::from_value(serde_json::json!({"#h": ["g1"]})).unwrap();
        let stored = relay.db.query(vec![filter], 10, now).await.0;
        assert_eq!(
            stored.len(),
            2,
            "only the re-created group's later events may remain"
        );
        assert!(
            stored.iter().any(|event| event.id == recreate.id)
                && stored.iter().any(|event| event.id == new_post.id),
            "the re-created group's events must survive"
        );
        assert!(
            matches!(
                relay.db.put(create, now).await,
                PutOutcome::PreviouslyDeleted
            ),
            "an exact replay of the purged create must stay blocked"
        );
        // The scheduled rebuild reconstructs the group from the survivors.
        for _ in 0..100 {
            if relay.groups.read().await.group("g1").is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let groups = relay.groups.read().await;
        assert!(
            groups.group("g1").is_some(),
            "the re-created group must be visible after the resume"
        );
        assert!(
            !groups.ghost_group_ids().contains(&"g1".to_string())
                && !groups.deleted_group_ids().contains(&"g1".to_string()),
            "the id must not stay ghosted or deleted"
        );
        drop(groups);
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
        assert_eq!(
            relay.rebuild_failures(),
            1,
            "the failed group scan must be counted exactly once"
        );
    }

    #[tokio::test]
    async fn drain_prevents_new_group_rebuilds() {
        // Shutdown must not start a full-history rebuild whose result
        // cannot be persisted: the state stays pending (fail-closed) and
        // the next startup rebuilds from the surviving events.
        let relay = build_relay().await;
        relay.signal_drain();
        relay.mark_group_state_stale().await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(
            relay
                .groups_rebuild
                .rebuilds
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "a drained relay must not run a rebuild scan"
        );
        assert!(
            relay
                .groups_rebuild
                .pending
                .load(std::sync::atomic::Ordering::SeqCst),
            "the state must stay pending so the snapshot stays dropped"
        );
        assert!(
            relay.db.load_groups().await.is_none(),
            "the stale snapshot must be dropped, not saved"
        );
        relay.db.shutdown();
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
    async fn blossom_command_merges_a_concurrently_persisted_entry() {
        // A CLI `blossom allow` can commit between the daemon's last load
        // and the command. The command re-reads the persisted list under the
        // cross-process lock and unions it with the in-memory list, so the
        // CLI entry must survive instead of being overwritten by the
        // daemon's older snapshot.
        let relay = build_relay().await;
        let cli = "cc".repeat(32);
        assert!(
            relay
                .db
                .save_blossom_allow(std::slice::from_ref(&cli))
                .await,
            "the concurrent CLI write must persist"
        );
        // The daemon's in-memory list never observed the CLI write.
        assert!(relay.blossom_allow.read().await.is_empty());
        let pk = "aa".repeat(32);
        let text = relay
            .execute_command(&crate::relay::commands::Command::BlossomAllow(pk.clone()))
            .await;
        assert_eq!(text, format!("ok: /blossom allow {pk}"));
        let stored = relay.db.try_load_blossom_allow().await.expect("loads");
        assert!(
            stored.contains(&cli),
            "the CLI entry must not be dropped: {stored:?}"
        );
        assert!(
            stored.contains(&pk),
            "the new entry must be persisted: {stored:?}"
        );
        assert_eq!(
            *relay.blossom_allow.read().await,
            stored,
            "the in-memory list must mirror the written list"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn blossom_deny_removes_a_persisted_cli_entry() {
        // The daemon's in-memory list does not contain the CLI-added entry:
        // the command must remove it from the re-read persisted list instead
        // of reporting a no-op while the entry survives on disk.
        let relay = build_relay().await;
        let cli = "cc".repeat(32);
        assert!(
            relay
                .db
                .save_blossom_allow(std::slice::from_ref(&cli))
                .await
        );
        assert!(relay.blossom_allow.read().await.is_empty());
        let text = relay
            .execute_command(&crate::relay::commands::Command::BlossomDeny(cli.clone()))
            .await;
        assert_eq!(text, format!("ok: /blossom deny {cli}"));
        let stored = relay.db.try_load_blossom_allow().await.expect("loads");
        assert!(
            !stored.contains(&cli),
            "the CLI entry must be removed: {stored:?}"
        );
        assert!(relay.blossom_allow.read().await.is_empty());
        relay.db.shutdown();
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
