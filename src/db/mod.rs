//! LMDB-backed event storage.
//!
//! The module is split into three layers:
//! - [`self`] (mod.rs): the [`DbClient`] handle, the request channel with
//!   its dedicated writer/reader threads and the batched write plumbing;
//! - [`store`]: the [`Store`] owning the LMDB environment, the write path
//!   (put/replace/delete/vanish/ban/expiry) and the index maintenance;
//! - [`scan`]: the query engine — filter matching, index-selected range
//!   walks and the REQ/COUNT/negentropy collectors.

mod removal;
mod scan;

/// The cap on search terms per filter, shared by the scan path and the
/// live delivery (`pub(crate)` re-export because `scan` is private).
pub(crate) use scan::SEARCH_MAX_TERMS;
pub(crate) mod store;
#[cfg(test)]
mod tests;
mod threads;

use std::sync::Arc;

use tokio::sync::{mpsc, oneshot};

pub(crate) use scan::{FULL_SCAN_BUDGET, NegItem, NegItems, SCAN_BUDGET};
use store::Store;

use crate::config::DatabaseConfig;
use crate::error::Result;
use crate::event::Event;
use crate::filter::Filter;
use crate::nips::nip09;

/// Outcome of the startup access-control load. `Missing` and `Failed` must
/// stay distinct: `Missing` seeds the config's `access` section on the very
/// first run, while `Failed` must stop the relay — treating a failed read
/// as "nothing persisted" would silently replace the persisted NIP-86 bans
/// and IP blocks with the config seed (fail-open).
#[derive(Debug, Default)]
pub enum LoadAccessOutcome {
    /// The persisted state was read successfully.
    Loaded(crate::config::AccessControl),
    /// Nothing was ever persisted (first run).
    Missing,
    /// The database could not answer. Also the [`Default`]: a missing reply
    /// is a failure, never "nothing was persisted".
    #[default]
    Failed,
}

/// Outcome of the startup NIP-29 group-state load. `Missing` and `Failed`
/// must stay distinct: `Missing` (first run or pre-persistence database)
/// runs the replay migration, while `Failed` must stop the relay — with an
/// empty group store every group id reads as public, so starting on a
/// failed read would silently expose private group content.
#[derive(Debug, Default)]
pub enum LoadGroupsOutcome {
    /// The persisted snapshot was read successfully.
    Loaded(crate::nips::nip29::GroupsSnapshot),
    /// No snapshot was ever persisted.
    Missing,
    /// The database could not answer. Also the [`Default`]: a missing reply
    /// is a failure, never "no snapshot".
    #[default]
    Failed,
}

/// Outcome of the startup NIP-43 role-state load, with the same
/// missing/failed distinction as [`LoadGroupsOutcome`]: a failed read must
/// stop the relay instead of starting with an empty role store.
#[derive(Debug, Default)]
pub enum LoadRolesOutcome {
    /// The persisted snapshot was read successfully.
    Loaded(crate::nips::nip43::RolesSnapshot),
    /// No snapshot was ever persisted.
    Missing,
    /// The database could not answer. Also the [`Default`].
    #[default]
    Failed,
}

impl LoadGroupsOutcome {
    /// Tests only: unwrap the loaded snapshot. Production callers must
    /// match explicitly so `Missing` and `Failed` take different paths.
    #[cfg(test)]
    pub fn expect_loaded(self, msg: &str) -> crate::nips::nip29::GroupsSnapshot {
        match self {
            LoadGroupsOutcome::Loaded(snap) => snap,
            other => panic!("{msg}: {other:?}"),
        }
    }

    /// Tests only: whether a snapshot was persisted at all.
    #[cfg(test)]
    pub fn is_some(&self) -> bool {
        matches!(self, LoadGroupsOutcome::Loaded(_))
    }

    /// Tests only: whether no snapshot was persisted.
    #[cfg(test)]
    pub fn is_none(&self) -> bool {
        matches!(self, LoadGroupsOutcome::Missing)
    }
}

impl LoadRolesOutcome {
    /// Tests only: unwrap the loaded snapshot. Production callers must
    /// match explicitly so `Missing` and `Failed` take different paths.
    #[cfg(test)]
    pub fn expect_loaded(self, msg: &str) -> crate::nips::nip43::RolesSnapshot {
        match self {
            LoadRolesOutcome::Loaded(snap) => snap,
            other => panic!("{msg}: {other:?}"),
        }
    }

    /// Tests only: whether no snapshot was persisted.
    #[cfg(test)]
    pub fn is_none(&self) -> bool {
        matches!(self, LoadRolesOutcome::Missing)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PutOutcome {
    Stored,
    /// A duplicate (or a duplicate-style acknowledgement such as NIP-43's
    /// repeated join claim): acknowledged with OK true and not stored.
    Duplicate(String),
    Replaced,
    Expired,
    PreviouslyDeleted,
    /// NIP-01: kinds 20000-29999 are ephemeral and must not be stored
    /// (NIP-59 requires kind 21059 in particular to never be stored).
    /// The event is delivered live to subscribers and acknowledged with
    /// `OK true` (accepted, empty message).
    Ephemeral,
    Invalid(String),
}

impl Default for PutOutcome {
    fn default() -> Self {
        PutOutcome::Invalid("database unavailable".into())
    }
}

/// Records a database failure: bumps the error counter and logs a clear
/// operator-facing message, especially when the LMDB map size is exhausted.
pub(crate) fn db_error(errors: &Arc<std::sync::atomic::AtomicU64>, e: &anyhow::Error) {
    errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    log::error!("database error: {e}");
}

/// The advisory lock file next to the database that serializes the CLI's
/// read-modify-write of the persisted access state with the daemon's access
/// and Blossom-allowlist writes (`src/cli.rs` locks the same path). It is a
/// lock file only: the name is never read, `flock` gives mutual exclusion
/// across processes, and the lock is released when the handle drops (or the
/// process dies). A stale file is harmless — the kernel lock is what
/// matters — and the file is deliberately not removed: unlinking a locked
/// file would let a third process lock a fresh inode while the holder still
/// holds the old one.
pub(crate) struct AccessStateLock {
    #[cfg(unix)]
    file: std::fs::File,
}

impl Drop for AccessStateLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // Closing the file releases the lock too; the explicit unlock
            // keeps the intent visible.
            unsafe {
                libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}

/// Exclusive cross-process guard for the database directory: held by the
/// serving relay for its whole lifetime so a second instance on the same
/// `database.path` (different pid file or port) fails fast instead of
/// running a split-brain second writer (each writer thread assumes it is
/// the only one: resumes would double-run, snapshots would
/// last-writer-win). The lock releases itself when the holder dies, so it
/// can never go stale. CLI commands never take it (they must keep working
/// alongside a live daemon).
pub(crate) struct DbDirLock {
    #[cfg(unix)]
    file: std::fs::File,
}

impl Drop for DbDirLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            unsafe {
                libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}

/// Takes the exclusive database-directory lock without blocking: `Err`
/// means another relay instance holds it (or the directory is unusable).
/// Unix-only (`flock`); elsewhere this is a no-op guard like
/// [`lock_access_state`].
pub(crate) fn lock_database_dir(db_path: &std::path::Path) -> std::io::Result<DbDirLock> {
    std::fs::create_dir_all(db_path)?;
    let path = db_path.join("nostrfy.lock");
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            // Never truncate: the contents are never read, the inode is
            // what `flock` locks.
            .truncate(false)
            .open(&path)?;
        // SAFETY: `file` holds a valid descriptor for the call.
        let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(DbDirLock { file })
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(DbDirLock {})
    }
}

/// Takes the cross-process advisory lock guarding the persisted access
/// state. Unix-only (`flock`); on other platforms the operation is not
/// serialized across processes (the same LMDB transaction still applies).
/// The caller must hold the returned guard across its whole
/// snapshot-and-write, exactly like the CLI holds its lock across the
/// read-modify-write.
pub(crate) fn lock_access_state(db_path: &std::path::Path) -> std::io::Result<AccessStateLock> {
    std::fs::create_dir_all(db_path)?;
    let path = db_path.join("access.lock");
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            // The lock file's contents are never read or written: the inode
            // is what `flock` locks, so never truncate an existing file.
            .truncate(false)
            .open(&path)?;
        // SAFETY: `file` holds a valid descriptor for the call.
        let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(AccessStateLock { file })
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(AccessStateLock {})
    }
}

/// Acquires [`lock_access_state`] without blocking a runtime worker: the
/// blocking `flock` runs on the blocking pool and the returned guard is held
/// by the caller across the database await. A failure is logged and reported
/// as `None` (the write proceeds unlocked, matching the previous behavior).
pub(crate) async fn lock_access_state_async(
    db_path: std::path::PathBuf,
) -> Option<AccessStateLock> {
    let joined = tokio::task::spawn_blocking(move || lock_access_state(&db_path)).await;
    match joined {
        Ok(Ok(lock)) => Some(lock),
        Ok(Err(e)) => {
            log::warn!("cannot take the access state lock; the write proceeds unserialized: {e}");
            None
        }
        Err(e) => {
            log::warn!("cannot schedule the access state lock; the write proceeds: {e}");
            None
        }
    }
}

enum Msg {
    Put {
        /// Shared with the caller: the relay keeps the same allocation for
        /// its post-commit side effects and live broadcast instead of deep
        /// cloning the content (up to 64 KiB) on every accepted event.
        event: Arc<Event>,
        now: u64,
        /// First-seen reservation applied inside the same write transaction
        /// as the put (see `WriteBatch::first_seen`).
        first_seen: Option<([u8; 32], u64)>,
        reply: oneshot::Sender<PutOutcome>,
    },
    Query {
        filters: Vec<Filter>,
        limit: usize,
        now: u64,
        ascending: bool,
        /// Upper bound on the number of index candidates the scan may
        /// examine before giving up (anti-DoS work budget).
        budget: usize,
        /// REQ-only over-fetch factor for the per-filter limits, so events
        /// hidden by the connection-level visibility rules (NIP-70/59/29)
        /// do not consume the limit slots (see [`scan::Store::scan`]).
        hidden_slack: usize,
        reply: oneshot::Sender<(Vec<Event>, bool)>,
    },
    /// Accepts many events in a single write transaction (one commit).
    PutBatch {
        events: Vec<(Arc<Event>, u64)>,
        reply: oneshot::Sender<Vec<PutOutcome>>,
    },
    /// First-seen trust bookkeeping: records the arrival time of each
    /// pubkey when unknown and returns `(created, first_seen)` per entry.
    TouchFirstSeen {
        entries: Vec<([u8; 32], u64)>,
        reply: oneshot::Sender<Vec<(bool, u64)>>,
    },
    /// Read-only first-seen lookup (does not record anything).
    FirstSeenStatus {
        pubkeys: Vec<[u8; 32]>,
        reply: oneshot::Sender<Vec<(bool, u64)>>,
    },
    /// Read-only list of every vanished pubkey (startup rebuilds consult
    /// it so a vanished author cannot be resurrected as a group member or
    /// role holder by replaying pre-vanish events).
    /// One page of the vanish table (see `Store::vanish_pubkeys_page`).
    VanishPubkeysPage {
        after: Option<Vec<u8>>,
        limit: usize,
        /// `None` when the table could not be read: the caller must fail
        /// closed instead of treating an error as "no vanished pubkeys".
        reply: oneshot::Sender<Option<Vec<Vec<u8>>>>,
    },
    /// One page of the vanish table as raw 32-byte keys (see
    /// `Store::vanish_pubkeys_raw_page`): the rebuilds only need the
    /// decoded key, not two hex spellings per entry. A missing reply (the
    /// sender is dropped on a store error) reports a failed page.
    VanishPubkeysRawPage {
        after: Option<Vec<u8>>,
        limit: usize,
        reply: oneshot::Sender<Vec<[u8; 32]>>,
    },
    /// NIP-77: query returning only `(created_at, id)` records so that large
    /// negentropy ranges do not materialize every full event in memory.
    NegQuery {
        filter: Filter,
        limit: usize,
        now: u64,
        reply: oneshot::Sender<(NegItems, bool)>,
    },
    Count {
        filters: Vec<Filter>,
        limit: usize,
        now: u64,
        reply: oneshot::Sender<(Vec<Event>, bool)>,
    },
    /// REST-API aggregate sample: up to `limit` newest events as lightweight
    /// negentropy records (no content), so the relay-wide kind/author
    /// aggregates can apply the connection visibility rules without loading
    /// hidden event contents.
    AggregateSample {
        limit: usize,
        now: u64,
        reply: oneshot::Sender<Option<(NegItems, bool)>>,
    },
    Delete {
        targets: Vec<String>,
        addresses: Vec<nip09::Address>,
        request_pubkey: Option<String>,
        request_created: u64,
        /// NIP-29 9005 moderation: restrict deletion to events of this group.
        group: Option<String>,
        /// `(removed, group_state_removed)`: the count is `None` when the
        /// removal walk failed (the checked callers must not treat a
        /// skipped deletion as success), while the flag is still set when
        /// an earlier chunk removed a NIP-29/NIP-43 state event — a failed
        /// later chunk must not hide that the derived state went stale.
        reply: oneshot::Sender<(Option<usize>, bool)>,
    },
    /// NIP-29 `kind:9008`: purge every stored event of a deleted group, so a
    /// later re-creation of the id cannot expose the old history.
    GroupPurge {
        group: String,
        /// The purge cut recorded in the group's marker: re-published events
        /// created before it are rejected (see `Store::purge_group`).
        now: u64,
        /// Upper bound (`created_at <= until`) of the walk; `u64::MAX` for
        /// the live unbounded purge.
        until: u64,
        reply: oneshot::Sender<usize>,
    },
    Vanish {
        pubkey: Vec<u8>,
        /// NIP-62: events up to this created_at (the request's `.created_at`)
        /// are deleted.
        until_created: u64,
        /// `Some((removed events, whether a NIP-29/NIP-43 state event was
        /// among them))`, or `None` when the walk failed (no marker is
        /// written, so the checked caller does not report success): only a
        /// removed state event requires the derived state to be rebuilt.
        reply: oneshot::Sender<Option<(usize, bool)>>,
    },
    /// NIP-59: delete gift wraps addressed to a pubkey (on NIP-09 deletion).
    GiftWrapPurge {
        pubkey: Vec<u8>,
        /// Upper bound (`created_at <= until`) of the walk; `u64::MAX` for
        /// the live path, the deletion's timestamp for the migration (a
        /// wrap imported later must survive, matching the live order).
        until: u64,
        /// `None` when the walk failed: the checked caller must not treat a
        /// skipped purge as success.
        reply: oneshot::Sender<Option<usize>>,
    },
    /// Migration-only: records NIP-09 re-publication blocks for deletion
    /// targets absent from the database, scoped to the deletion's author
    /// (see `Store::record_absent_deletion_targets`). `None` when the write
    /// failed: the migration must not report a completed run.
    RecordAbsentDeletionTargets {
        pubkey: Vec<u8>,
        targets: Vec<String>,
        reply: oneshot::Sender<Option<usize>>,
    },
    PrefixExists {
        prefix: Vec<u8>,
        reply: oneshot::Sender<bool>,
    },
    /// Checks many event-id prefixes in one round trip (NIP-29 `previous`
    /// tag validation), so a single event cannot amplify into thousands of
    /// database requests.
    PrefixesExist {
        prefixes: Vec<Vec<u8>>,
        reply: oneshot::Sender<Vec<bool>>,
    },
    Ban {
        id: Vec<u8>,
        reason: String,
        reply: oneshot::Sender<bool>,
    },
    Unban {
        id: Vec<u8>,
        reply: oneshot::Sender<bool>,
    },
    ListBanned {
        reply: oneshot::Sender<Vec<(String, String)>>,
    },
    /// Persists the access control lists (NIP-86 runtime bans/allowlists).
    SaveAccess {
        access: crate::config::AccessControl,
        /// Whether the commit succeeded: the NIP-86 methods must not
        /// report success while the ban/allowlist only lives in memory.
        reply: oneshot::Sender<bool>,
    },
    /// Persists the access blob and the relay pubkey deny/allow lists in a
    /// single transaction, so the two can never be read from different
    /// generations after a crash. The reply reports whether the commit
    /// succeeded.
    SaveAccessAndPubkeys {
        access: crate::config::AccessControl,
        deny: Vec<(String, String)>,
        allow: Vec<(String, String)>,
        reply: oneshot::Sender<bool>,
    },
    /// Loads the persisted access control lists.
    LoadAccess {
        reply: oneshot::Sender<LoadAccessOutcome>,
    },
    /// Loads the persisted Blossom upload allowlist.
    LoadBlossomAllow {
        reply: oneshot::Sender<Option<Vec<String>>>,
    },
    /// Loads the persisted relay pubkey access lists (deny, allow).
    LoadRelayPubkeys {
        reply: oneshot::Sender<Option<crate::db::store::RelayPubkeyLists>>,
    },
    /// Persists the relay pubkey access lists (deny, allow).
    SaveRelayPubkeys {
        deny: Vec<(String, String)>,
        allow: Vec<(String, String)>,
        reply: oneshot::Sender<bool>,
    },
    /// Persists the Blossom upload allowlist; the reply reports whether the
    /// commit succeeded (the CLI/command path must not report a persisted
    /// allowlist change that only lives in memory).
    SaveBlossomAllow {
        entries: Vec<String>,
        reply: oneshot::Sender<bool>,
    },
    /// Persists the NIP-29 group state snapshot (write-through on every
    /// group mutation). The reply reports whether the commit succeeded, so
    /// the relay cannot treat an uncommitted save as durable.
    SaveGroups {
        snapshot: crate::nips::nip29::GroupsSnapshot,
        reply: oneshot::Sender<bool>,
    },
    /// Loads the persisted NIP-29 group state snapshot.
    LoadGroups {
        reply: oneshot::Sender<LoadGroupsOutcome>,
    },
    /// Drops the persisted NIP-29 group state snapshot (a post-vanish
    /// rebuild failure must not leave a stale snapshot behind). The reply
    /// reports whether the commit succeeded: an overload fail-fast must not
    /// silently skip this fail-closed clear.
    ClearGroupsSnapshot {
        reply: oneshot::Sender<bool>,
    },
    /// Persists the NIP-43 role state snapshot (write-through on every
    /// role mutation). The reply reports whether the commit succeeded.
    SaveRoles {
        snapshot: crate::nips::nip43::RolesSnapshot,
        reply: oneshot::Sender<bool>,
    },
    /// Loads the persisted NIP-43 role state snapshot.
    LoadRoles {
        reply: oneshot::Sender<LoadRolesOutcome>,
    },
    /// Adds an owner to a Blossom blob's persisted metadata (atomic);
    /// the reply carries whether the commit succeeded.
    BlossomAddOwner {
        sha256: String,
        mime: String,
        size: u64,
        uploaded: i64,
        pubkey: String,
        reply: oneshot::Sender<bool>,
    },
    /// Loads a Blossom blob's persisted metadata.
    BlossomLoad {
        sha256: String,
        reply: oneshot::Sender<Option<crate::db::store::BlossomMeta>>,
    },
    /// Removes one owner from a Blossom blob's persisted metadata.
    BlossomRemoveOwner {
        sha256: String,
        pubkey: String,
        reply: oneshot::Sender<(bool, bool)>,
    },
    /// Lists the blob hashes uploaded by a pubkey (reverse index), capped
    /// at `limit` entries. Test-only since BUD-12 paging uses the
    /// uploaded-order index (see [`Msg::BlossomListPage`]).
    #[cfg(test)]
    BlossomList {
        pubkey: String,
        limit: usize,
        reply: oneshot::Sender<Vec<String>>,
    },
    /// BUD-12 page of an owner's blobs from the uploaded-order index,
    /// strictly before `(after_uploaded, after_sha)`, newest first.
    BlossomListPage {
        pubkey: String,
        after_uploaded: Option<u64>,
        after_sha: Option<String>,
        limit: usize,
        reply: oneshot::Sender<Vec<(String, crate::db::store::BlossomMeta)>>,
    },
    /// Adds many Blossom mappings in one transaction (auto-migration);
    /// the reply carries whether the commit succeeded.
    BlossomAddMappings {
        entries: Vec<(String, String, u64, i64, String)>,
        reply: oneshot::Sender<bool>,
    },
    /// Whether the one-time legacy migration already ran.
    BlossomMigrationDone {
        reply: oneshot::Sender<bool>,
    },
    /// Marks the one-time legacy migration as done.
    BlossomMarkMigration {
        reply: oneshot::Sender<()>,
    },
    /// NIP-40 expiration purge: `(removed events, whether a NIP-29/NIP-43
    /// state event was among them)`. The second field lets the caller
    /// rebuild the derived state only when it actually changed, and stays
    /// set when a later chunk fails after removing state events.
    /// `first_seen_min_age` is the age (seconds) past which `first_seen`
    /// rows are reaped (0 disables the reap).
    PurgeExpired {
        now: u64,
        first_seen_min_age: u64,
        reply: oneshot::Sender<(usize, bool)>,
    },
    /// Started-but-unfinished NIP-29 group purges as `(gid, purge_now)`
    /// (see `Store::pending_purges`). `None` when the table could not be
    /// read: the caller fails closed instead of treating it as "none".
    PendingPurges {
        reply: oneshot::Sender<Option<Vec<(String, u64, u64)>>>,
    },
    /// Started-but-unfinished NIP-09 deletions. `None` when the table
    /// could not be read: the caller fails closed instead of treating an
    /// unreadable table as "nothing to resume".
    PendingDeletions {
        reply: oneshot::Sender<Option<Vec<store::PendingDeletion>>>,
    },
    /// Row counts of the bookkeeping tables (gauge material). `None` when
    /// the read failed.
    TableCounts {
        reply: oneshot::Sender<Option<store::TableCounts>>,
    },
    /// The persistent derived-group-state stamp (see `Store::state_stamp`).
    /// `None` when the read failed: the caller fails closed instead of
    /// treating a missing stamp as free to overwrite.
    StateStamp {
        reply: oneshot::Sender<Option<u64>>,
    },
    /// The derived-state sequence (see `Store::state_seq`). `None` when the
    /// read failed: the caller fails closed instead of treating a missing
    /// sequence as free to overwrite.
    StateSeq {
        reply: oneshot::Sender<Option<u64>>,
    },
    /// The NIP-29 group-state sequence (see `Store::state_seq_group`).
    /// `None` when the read failed: the caller fails closed.
    StateSeqGroup {
        reply: oneshot::Sender<Option<u64>>,
    },
    /// The NIP-43 role-state sequence (see `Store::state_seq_role`).
    /// `None` when the read failed: the caller fails closed.
    StateSeqRole {
        reply: oneshot::Sender<Option<u64>>,
    },
    DatabaseSize {
        reply: oneshot::Sender<u64>,
    },
    /// NIP-62 bookkeeping gauges: `(vanish markers, pending vanishes)`.
    /// `None` when the read failed (the stats writer keeps the last value).
    VanishCounts {
        reply: oneshot::Sender<Option<(u64, u64)>>,
    },
    /// Last used LMDB page number. The map is opened at its fixed ceiling
    /// and never resized, so tests assert real page growth instead of the
    /// constant `map_size`.
    #[cfg(test)]
    LastPage {
        reply: oneshot::Sender<u64>,
    },
    Shutdown,
}
#[derive(Clone)]
pub struct DbClient {
    tx: mpsc::UnboundedSender<Msg>,
    /// Dedicated channel for read-only requests: they are served by a
    /// separate thread that never takes the write lock, so reads keep
    /// working even when the writer is stalled (a slow disk or an external
    /// lock holder cannot take the relay down for readers).
    /// One channel per reader thread: `read_rr` round-robins requests so
    /// one long scan cannot stall the others (they no longer share a
    /// receiver behind a blocking Mutex).
    read_txs: Vec<mpsc::UnboundedSender<Msg>>,
    read_rr: Arc<std::sync::atomic::AtomicUsize>,
    /// Dedicated channel for REST API queries: served by its own reader
    /// thread, so a flood of `/api/v1` requests can never queue up behind
    /// (or in front of) WebSocket REQ/COUNT/NEG queries on the shared
    /// reader thread.
    api_read_tx: mpsc::UnboundedSender<Msg>,
    errors: Arc<std::sync::atomic::AtomicU64>,
    /// Fail-fast admissions caused by a queue cap (overload), distinct from
    /// [`Self::errors`]: a cap rejection is the relay protecting itself,
    /// not a database fault. Bumped where a request is refused before it
    /// is queued; drained by [`Self::take_overloads`].
    overloads: Arc<std::sync::atomic::AtomicU64>,
    /// The database directory (from the config): the file-system space
    /// checks and the cross-process `access.lock` are anchored here, so the
    /// accessors do not need a round trip to the store thread.
    db_path: std::path::PathBuf,
    expiry: Arc<std::sync::atomic::AtomicBool>,
    /// Shutdown cancellation (shared with the store and every reader
    /// clone): set by [`Self::shutdown`] so a long chunked removal stops
    /// at the next chunk boundary instead of delaying process exit.
    cancel: Arc<std::sync::atomic::AtomicBool>,
    /// Set by the writer's startup resume when an interrupted NIP-09
    /// deletion removed a NIP-29/NIP-43 state event, so the startup path
    /// can mark the derived state stale.
    resumed_deletion_state_removed: Arc<std::sync::atomic::AtomicBool>,
    /// Seconds a request may wait for the database thread before timing out
    /// (0 = wait forever). Keeps the relay responsive even when the storage
    /// is stuck: timed-out requests fail with a clear error instead of
    /// hanging the connection.
    timeout_secs: u64,
    /// Messages queued but not yet drained by the database thread. When the
    /// queue grows past the configured caps, new requests fail fast instead
    /// of piling up in memory: the relay keeps serving (slowly) instead of
    /// running out of memory.
    pending_msgs: Arc<std::sync::atomic::AtomicUsize>,
    /// Events inside the queued `PutBatch`/`Put` messages (the dominant
    /// memory of the queue).
    pending_events: Arc<std::sync::atomic::AtomicUsize>,
    /// Read-only messages queued but not yet drained by the reader threads.
    /// Counted separately from the writer queue so a REQ flood cannot
    /// fail-fast the EVENT writes (and vice versa).
    pending_reads: Arc<std::sync::atomic::AtomicUsize>,
    /// Queued-but-unprocessed REST API queries, counted separately so an API
    /// flood fails fast without tripping the WebSocket-side caps.
    api_pending: Arc<std::sync::atomic::AtomicUsize>,
    /// Queued payload bytes on the writer queue (events and the other
    /// write messages' dominant fields). The count caps alone let a queue
    /// of maximum-size events reach gigabytes before tripping; this counter
    /// enforces `max_pending_bytes` on what actually dominates memory.
    pending_bytes: Arc<std::sync::atomic::AtomicUsize>,
    /// Same, for the WebSocket reader queue (filter fields).
    pending_read_bytes: Arc<std::sync::atomic::AtomicUsize>,
    /// Same, for the dedicated REST API reader queue.
    api_pending_bytes: Arc<std::sync::atomic::AtomicUsize>,
    /// Caps for the counters above (`max_api_pending` is shared so the
    /// SIGHUP reload can adjust it live). `max_pending_bytes` comes from
    /// `database.max_db_queue_bytes` (0 = no byte cap).
    max_pending_msgs: usize,
    max_pending_events: usize,
    max_pending_bytes: usize,
    max_api_pending: Arc<std::sync::atomic::AtomicUsize>,
    /// The spawned database threads, joined by [`Self::shutdown`] after the
    /// Shutdown signals: without the join, work queued behind `Shutdown`
    /// could be dropped without a reply and the final flush could be cut
    /// short by process exit. Shared behind the `DbClient` clone.
    threads: Arc<std::sync::Mutex<Vec<std::thread::JoinHandle<()>>>>,
}

/// An estimate of the heap bytes a queued message pins, used by the
/// `database.max_db_queue_bytes` admission check. Only the dominant
/// payloads are measured (event fields for writes, filter fields for
/// reads, delete targets); metadata-only messages count as zero and stay
/// bounded by the count caps alone. An estimate is enough: it only has to
/// stop a queue of large payloads from exhausting memory, while the count
/// caps keep the exact accounting.
fn msg_bytes(msg: &Msg) -> usize {
    match msg {
        Msg::Put { event, .. } => event_heap_bytes(event),
        Msg::PutBatch { events, .. } => events
            .iter()
            .map(|(event, _)| event_heap_bytes(event))
            .sum(),
        Msg::Query { filters, .. } | Msg::Count { filters, .. } => {
            filters.iter().map(filter_heap_bytes).sum()
        }
        Msg::NegQuery { filter, .. } => filter_heap_bytes(filter),
        // Group/role snapshots are the dominant writer payload after
        // events: each `persist_groups`/`persist_roles` clones the whole
        // live state, and without an estimate a queue of them could reach
        // gigabytes while `max_db_queue_bytes` ignored them entirely.
        Msg::SaveGroups { snapshot, .. } => groups_snapshot_bytes(snapshot),
        Msg::SaveRoles { snapshot, .. } => roles_snapshot_bytes(snapshot),
        Msg::Delete {
            targets,
            addresses,
            request_pubkey,
            group,
            ..
        } => targets
            .iter()
            .map(String::len)
            .sum::<usize>()
            .saturating_add(
                addresses
                    .iter()
                    .map(|address| address.pubkey.len() + address.d.len())
                    .sum(),
            )
            .saturating_add(request_pubkey.as_deref().map_or(0, str::len))
            .saturating_add(group.as_deref().map_or(0, str::len)),
        Msg::RecordAbsentDeletionTargets { targets, .. } => targets.iter().map(String::len).sum(),
        _ => 0,
    }
}

/// The heap bytes an event owns (content, tag strings and the hex fields).
fn event_heap_bytes(event: &Event) -> usize {
    let tags: usize = event
        .tags
        .iter()
        .map(|tag| tag.iter().map(String::len).sum::<usize>())
        .sum();
    event
        .content
        .len()
        .saturating_add(tags)
        .saturating_add(event.id.len())
        .saturating_add(event.pubkey.len())
        .saturating_add(event.sig.len())
}

/// Rough heap estimate of a queued NIP-29 group snapshot: member maps,
/// role sets, settings strings, pins, invites and the deleted/ghost
/// markers. Only used for the queue byte cap, so an estimate is enough.
fn groups_snapshot_bytes(snapshot: &crate::nips::nip29::GroupsSnapshot) -> usize {
    let groups: usize = snapshot
        .groups
        .values()
        .map(|group| {
            let members: usize = group
                .members
                .iter()
                .map(|(pubkey, roles)| {
                    pubkey.len() + roles.iter().map(std::string::String::len).sum::<usize>()
                })
                .sum();
            let settings = group.settings.name.len()
                + group.settings.about.len()
                + group.settings.picture.len()
                + group.settings.banner.len();
            let pins: usize = group
                .pins
                .iter()
                .map(|(tag, value)| tag.len() + value.len())
                .sum();
            let invites: usize = group.invites.iter().map(std::string::String::len).sum();
            members
                .saturating_add(settings)
                .saturating_add(pins)
                .saturating_add(invites)
                .saturating_add(group.parent.as_deref().map_or(0, str::len))
                .saturating_add(
                    group
                        .children
                        .iter()
                        .map(std::string::String::len)
                        .sum::<usize>(),
                )
        })
        .sum();
    groups
        .saturating_add(
            snapshot
                .deleted
                .iter()
                .map(std::string::String::len)
                .sum::<usize>(),
        )
        .saturating_add(
            snapshot
                .ghost
                .iter()
                .map(std::string::String::len)
                .sum::<usize>(),
        )
}

/// Rough heap estimate of a queued NIP-43 role snapshot (role definitions
/// and the per-pubkey assignment lists).
fn roles_snapshot_bytes(snapshot: &crate::nips::nip43::RolesSnapshot) -> usize {
    let roles: usize = snapshot
        .roles
        .values()
        .map(|role| {
            role.label.len()
                + role.description.len()
                + role.color.len()
                + role.order.map_or(0, |_| 8)
        })
        .sum();
    let assignments: usize = snapshot
        .assignments
        .iter()
        .map(|(pubkey, roles)| {
            pubkey.len() + roles.iter().map(std::string::String::len).sum::<usize>()
        })
        .sum();
    roles.saturating_add(assignments)
}

/// The heap bytes a filter owns: the id/author/kind/search strings and the
/// tag constraint values.
fn filter_heap_bytes(filter: &Filter) -> usize {
    let string_list = |values: &Option<Vec<String>>| {
        values
            .as_ref()
            .map_or(0, |v| v.iter().map(String::len).sum::<usize>())
    };
    let strings = string_list(&filter.ids)
        .saturating_add(string_list(&filter.authors))
        .saturating_add(filter.kinds.as_ref().map_or(0, |v| v.len() * 8))
        .saturating_add(filter.search.as_deref().map_or(0, str::len));
    let tags: usize = filter
        .tags
        .iter()
        .map(|(name, value)| name.len().saturating_add(value_heap_bytes(value)))
        .sum();
    strings.saturating_add(tags)
}

/// The heap bytes a JSON filter value owns (tag constraint values).
fn value_heap_bytes(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::String(s) => s.len(),
        serde_json::Value::Array(values) => values.iter().map(value_heap_bytes).sum(),
        serde_json::Value::Object(map) => map
            .iter()
            .map(|(key, value)| key.len().saturating_add(value_heap_bytes(value)))
            .sum(),
        _ => 8,
    }
}

impl DbClient {
    pub fn open(
        cfg: &DatabaseConfig,
        expiry_enabled: bool,
        errors: Arc<std::sync::atomic::AtomicU64>,
        request_timeout_secs: u64,
        max_indexed_words: usize,
        max_pending_msgs: usize,
        max_pending_events: usize,
    ) -> Result<DbClient> {
        let expiry = Arc::new(std::sync::atomic::AtomicBool::new(expiry_enabled));
        let store = Store::open(cfg, Arc::clone(&expiry), max_indexed_words)?;
        Self::build(
            cfg,
            store,
            expiry,
            errors,
            request_timeout_secs,
            max_pending_msgs,
            max_pending_events,
        )
    }

    /// Test-only: builds a client over an already opened store, so a test
    /// can arm the store's one-shot fault hooks before the threads start
    /// (the hooks are consumed by the handler that runs them).
    #[cfg(test)]
    pub(crate) fn open_with_store(
        cfg: &DatabaseConfig,
        store: Store,
        expiry: Arc<std::sync::atomic::AtomicBool>,
        errors: Arc<std::sync::atomic::AtomicU64>,
        request_timeout_secs: u64,
        max_pending_msgs: usize,
        max_pending_events: usize,
    ) -> Result<DbClient> {
        Self::build(
            cfg,
            store,
            expiry,
            errors,
            request_timeout_secs,
            max_pending_msgs,
            max_pending_events,
        )
    }

    /// Assembles a client over an opened store: the one-time access
    /// migration, the thread spawn and the handle.
    fn build(
        cfg: &DatabaseConfig,
        mut store: Store,
        expiry: Arc<std::sync::atomic::AtomicBool>,
        errors: Arc<std::sync::atomic::AtomicU64>,
        request_timeout_secs: u64,
        max_pending_msgs: usize,
        max_pending_events: usize,
    ) -> Result<DbClient> {
        // One-time migration: databases written before the pubkey lists
        // moved into their own key still carry them inside the `access`
        // blob — copy them over so existing bans/allowlists survive.
        store.migrate_access_pubkeys()?;
        log::info!("access control migration check complete");
        // The store is built before the thread plumbing exists, so the
        // shutdown cancellation flag is attached here, before any reader
        // clone is spawned (they share the same `Arc`).
        let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
        store.set_cancel(Arc::clone(&cancel));
        let reader_threads = cfg.reader_threads.clamp(1, 64);
        let threads = threads::spawn(
            store,
            expiry,
            errors,
            request_timeout_secs,
            max_pending_msgs,
            max_pending_events,
            reader_threads,
        )?;
        // Wait for the writer's startup recovery (interrupted vanish and
        // NIP-09 deletion resumes): the server's startup state restore and
        // its stale-state check must observe the completed recovery and
        // its outcome flag, never race the writer. A receive error means
        // the writer thread exited during startup (a panic): starting to
        // serve without a writer would bind the relay and pass readiness
        // while every write fails, so refuse startup instead.
        if threads.recovery_rx.recv().is_err() {
            return Err(anyhow::anyhow!(
                "database writer exited before completing startup recovery"
            ));
        }
        Ok(DbClient {
            tx: threads.tx,
            read_txs: threads.read_txs,
            read_rr: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            api_read_tx: threads.api_read_tx,
            errors: threads.errors,
            overloads: threads.overloads,
            db_path: cfg.path.clone(),
            expiry: threads.expiry,
            cancel,
            resumed_deletion_state_removed: threads.resumed_deletion_state_removed,
            timeout_secs: threads.timeout_secs,
            pending_msgs: threads.pending_msgs,
            pending_events: threads.pending_events,
            pending_reads: threads.pending_reads,
            api_pending: threads.api_pending,
            pending_bytes: threads.pending_bytes,
            pending_read_bytes: threads.pending_read_bytes,
            api_pending_bytes: threads.api_pending_bytes,
            max_pending_msgs: threads.max_pending_msgs,
            max_pending_events: threads.max_pending_events,
            max_pending_bytes: cfg.max_db_queue_bytes,
            max_api_pending: threads.max_api_pending,
            threads: Arc::new(threads.threads),
        })
    }

    pub fn set_expiry_enabled(&self, enabled: bool) {
        self.expiry
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether the process is shutting down: the chunked removals check
    /// this between chunks (via the store's shared flag) and stop early,
    /// leaving their pending record for the next startup.
    pub fn cancelled(&self) -> bool {
        self.cancel.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Whether the writer's startup resume of an interrupted NIP-09
    /// deletion removed a NIP-29/NIP-43 state event. The relay checks
    /// this once at startup to mark its derived group/role state stale
    /// (the persistent [`Self::state_stamp`] is bumped as well, so the
    /// snapshot currency check also fails closed).
    pub fn resumed_deletion_state_removed(&self) -> bool {
        self.resumed_deletion_state_removed
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Adjusts the API reader queue cap live (SIGHUP reload). Values below
    /// 1 are clamped to 1 so the API reader can always drain.
    /// The hard ceiling for the API reader queue: a SIGHUP could otherwise
    /// set an arbitrarily large value and defeat the fail-fast memory
    /// guard (each queued API message can hold filters).
    const MAX_API_PENDING_MSGS: usize = 65_536;

    pub fn set_max_api_pending(&self, max: usize) {
        self.max_api_pending.store(
            max.clamp(1, Self::MAX_API_PENDING_MSGS),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    /// Sends a read-only request to the dedicated reader thread. The
    /// writer-queue counters are not part of the gate: the reader threads
    /// exist so reads keep working while the writer is stalled.
    async fn request_read<R: Default>(&self, make: impl FnOnce(oneshot::Sender<R>) -> Msg) -> R {
        let channel = self.read_channel();
        self.request_with_checked(make, channel, false).await
    }

    /// Round-robin over the per-thread reader channels.
    fn read_channel(&self) -> &mpsc::UnboundedSender<Msg> {
        let index = self
            .read_rr
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % self.read_txs.len();
        &self.read_txs[index]
    }

    /// Reserves one reader-queue slot plus the message's estimated payload
    /// bytes (add-then-check with rollback). Returns `false` when a cap is
    /// exceeded, so the caller fails fast. Every read path must reserve its
    /// bytes through here: the reader thread releases *both* counters on
    /// completion, so an unreserved byte count underflows
    /// `pending_read_bytes` to `usize::MAX` and every later byte-checked
    /// read fails fast for the rest of the process.
    fn reserve_read(&self, bytes: usize) -> bool {
        let reads = self
            .pending_reads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .saturating_add(1);
        let pending_bytes = if bytes > 0 {
            self.pending_read_bytes
                .fetch_add(bytes, std::sync::atomic::Ordering::Relaxed)
                .saturating_add(bytes)
        } else {
            self.pending_read_bytes
                .load(std::sync::atomic::Ordering::Relaxed)
        };
        let over_bytes = self.max_pending_bytes > 0 && pending_bytes > self.max_pending_bytes;
        if reads > self.max_pending_msgs || over_bytes {
            self.release_read(bytes);
            self.overloads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return false;
        }
        true
    }

    /// Reserves a reader slot and payload bytes without the cap check:
    /// startup loads must not fail fast (an empty security state is
    /// fail-open), but the reader still releases both counters, so the
    /// reservation must be recorded to keep the accounting exact.
    fn reserve_read_force(&self, bytes: usize) {
        self.pending_reads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if bytes > 0 {
            self.pending_read_bytes
                .fetch_add(bytes, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Releases a read reservation whose message could not be sent. A
    /// queued message is released by the reader thread instead.
    fn release_read(&self, bytes: usize) {
        self.pending_reads
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        if bytes > 0 {
            self.pending_read_bytes
                .fetch_sub(bytes, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Startup-only read: neither fails fast on a momentarily full queue
    /// nor applies the response timeout. The persisted access control
    /// (deny/allow lists, Blossom allowlist) must not silently degrade to
    /// an empty value while the database is merely slow — an empty deny
    /// list is fail-open. The reader thread always replies; a dead reader
    /// leaves the relay waiting at startup (fail-stop) instead of
    /// starting with empty security state.
    async fn request_read_blocking<R: Default>(
        &self,
        make: impl FnOnce(oneshot::Sender<R>) -> Msg,
    ) -> R {
        let (tx, rx) = oneshot::channel();
        let msg = make(tx);
        let bytes = msg_bytes(&msg);
        self.reserve_read_force(bytes);
        if self.read_channel().send(msg).is_err() {
            // The reader thread's receiver is gone: the relay is shutting
            // down or the thread died. There is no state to load.
            self.release_read(bytes);
            log::error!("database reader is gone; cannot load persisted state");
            return R::default();
        }
        match rx.await {
            Ok(value) => value,
            // The reply sender was dropped: the reader thread panicked
            // while handling the message (it recovers and continues, but
            // this state is lost). The caller logs the failure so a
            // silently-empty security state is never the outcome.
            Err(_) => {
                log::error!("database reader failed to reply; persisted state unavailable");
                R::default()
            }
        }
    }

    /// Startup-only read that reports failure instead of degrading to a
    /// default value: like [`Self::request_read_blocking`] it neither fails
    /// fast nor applies the response timeout (a merely slow database must
    /// not silently turn startup state into an empty one), but a missing
    /// reply is returned as `None` so the caller can fail closed instead of
    /// persisting an empty/incomplete state.
    async fn request_read_startup<R>(
        &self,
        make: impl FnOnce(oneshot::Sender<R>) -> Msg,
    ) -> Option<R> {
        let (tx, rx) = oneshot::channel();
        let msg = make(tx);
        let bytes = msg_bytes(&msg);
        self.reserve_read_force(bytes);
        if self.read_channel().send(msg).is_err() {
            self.release_read(bytes);
            log::error!("database reader is gone; cannot rebuild startup state");
            return None;
        }
        rx.await.ok()
    }

    /// Read-only request that reports failure (`None`) instead of
    /// degrading to a default value: used by the SIGHUP reloads, where
    /// an empty result would overwrite the live deny/allow lists with
    /// nothing (fail-open). Like [`Self::request_read`], reader-queue
    /// accounting is used (never the writer counters), so a write backlog
    /// must not fail-fast the reads.
    async fn request_read_result<R: Default>(
        &self,
        make: impl FnOnce(oneshot::Sender<R>) -> Msg,
    ) -> Option<R> {
        let channel = self.read_channel();
        let rx = self.send_request_read(make, channel)?;
        if self.timeout_secs == 0 {
            return rx.await.ok();
        }
        tokio::time::timeout(std::time::Duration::from_secs(self.timeout_secs), rx)
            .await
            .ok()
            .and_then(|r| r.ok())
    }

    /// Reader-queue variant of [`Self::send_request`]: reserves a slot and
    /// the payload bytes (add-then-check with rollback) and reports
    /// fail-fast as `None`. The reader thread releases both on completion,
    /// so this path must not release them.
    fn send_request_read<R>(
        &self,
        make: impl FnOnce(oneshot::Sender<R>) -> Msg,
        channel: &mpsc::UnboundedSender<Msg>,
    ) -> Option<oneshot::Receiver<R>> {
        let (tx, rx) = oneshot::channel();
        let msg = make(tx);
        let bytes = msg_bytes(&msg);
        if !self.reserve_read(bytes) {
            return None;
        }
        if channel.send(msg).is_err() {
            self.release_read(bytes);
            return None;
        }
        Some(rx)
    }

    /// Sends a write request to the writer thread and waits for the reply
    /// *without* a response timeout. A write that reached the writer queue is
    /// guaranteed to be processed (the writer always replies, on commit,
    /// abort or shutdown), so waiting for the true outcome is preferable to a
    /// false "database timeout": an event that later commits while the caller
    /// already reported failure would skip its side-effects (live broadcast,
    /// NIP-09 deletion, NIP-29 group state, NIP-43 leave). The overload
    /// fail-fast still rejects new writes while the queue is deep.
    async fn request_write<R: Default>(&self, make: impl FnOnce(oneshot::Sender<R>) -> Msg) -> R {
        self.request_write_checked(make).await.unwrap_or_default()
    }

    /// Like [`Self::request_write`], but reports a fail-fast (overload) or a
    /// lost writer as `None` instead of a default value: callers that must
    /// not silently skip a side effect (NIP-09 deletion, NIP-62 vanish,
    /// gift-wrap purge) surface the failure instead.
    async fn request_write_checked<R>(
        &self,
        make: impl FnOnce(oneshot::Sender<R>) -> Msg,
    ) -> Option<R> {
        let rx = self.send_request(make, &self.tx)?;
        rx.await.ok()
    }

    /// Overload check, queued-work accounting and send. Returns the reply
    /// receiver, or `None` when the request failed fast (queue full) or could
    /// not be sent (in which case nothing was queued and nothing will commit).
    fn send_request<R>(
        &self,
        make: impl FnOnce(oneshot::Sender<R>) -> Msg,
        channel: &mpsc::UnboundedSender<Msg>,
    ) -> Option<oneshot::Receiver<R>> {
        self.send_request_checked(make, channel, true)
    }

    /// Like [`Self::send_request`], but with `check_writer` the fail-fast
    /// gate inspects only the writer-queue counters (`pending_msgs` /
    /// `pending_events`). Read-only requests on the dedicated reader
    /// channel pass `false`: they are counted in `pending_reads` (never in
    /// the writer counters), so a read flood cannot fail-fast the writes
    /// and a write backlog must not fail-fast the reads. Accounting uses
    /// add-then-check with rollback so concurrent bursts cannot overshoot
    /// the caps without bound (check-then-add had a TOCTOU window).
    fn send_request_checked<R>(
        &self,
        make: impl FnOnce(oneshot::Sender<R>) -> Msg,
        channel: &mpsc::UnboundedSender<Msg>,
        check_writer: bool,
    ) -> Option<oneshot::Receiver<R>> {
        let (tx, rx) = oneshot::channel();
        let msg = make(tx);
        let is_write = matches!(msg, Msg::Put { .. } | Msg::PutBatch { .. });
        let write_events = match &msg {
            Msg::PutBatch { events, .. } => events.len(),
            Msg::Put { .. } => 1,
            _ => 0,
        };
        let bytes = msg_bytes(&msg);
        let over_bytes =
            |pending: usize| self.max_pending_bytes > 0 && pending > self.max_pending_bytes;
        if check_writer || is_write {
            // Writer path (and any gated path): reserve first, then enforce.
            let msgs = self
                .pending_msgs
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                .saturating_add(1);
            let events = if write_events > 0 {
                self.pending_events
                    .fetch_add(write_events, std::sync::atomic::Ordering::Relaxed)
                    .saturating_add(write_events)
            } else {
                self.pending_events
                    .load(std::sync::atomic::Ordering::Relaxed)
            };
            let pending_bytes = if bytes > 0 {
                self.pending_bytes
                    .fetch_add(bytes, std::sync::atomic::Ordering::Relaxed)
                    .saturating_add(bytes)
            } else {
                self.pending_bytes
                    .load(std::sync::atomic::Ordering::Relaxed)
            };
            if msgs > self.max_pending_msgs
                || events > self.max_pending_events
                || over_bytes(pending_bytes)
            {
                self.pending_msgs
                    .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                if write_events > 0 {
                    self.pending_events
                        .fetch_sub(write_events, std::sync::atomic::Ordering::Relaxed);
                }
                if bytes > 0 {
                    self.pending_bytes
                        .fetch_sub(bytes, std::sync::atomic::Ordering::Relaxed);
                }
                // A cap rejection is overload (the relay shedding load),
                // not a database fault: count it separately.
                self.overloads
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return None;
            }
        } else {
            // Reader path: a separate counter with the same message cap so a
            // REQ flood fails fast instead of growing unbounded and (via the
            // old shared counter) blocking the writes.
            if !self.reserve_read(bytes) {
                return None;
            }
        }
        if let Err(err) = channel.send(msg) {
            let msg = err.0;
            // Release the same counter that was reserved above: `Put` /
            // `PutBatch` always reserve the writer counters, while every
            // other message reserves whichever counter its channel path
            // used (writer counters when gated, reader counters otherwise).
            // Mismatching them here would leak one counter and underflow
            // the other into a permanent fail-fast.
            match &msg {
                Msg::PutBatch { events, .. } => {
                    self.pending_msgs
                        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    self.pending_events
                        .fetch_sub(events.len(), std::sync::atomic::Ordering::Relaxed);
                }
                Msg::Put { .. } => {
                    self.pending_msgs
                        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    self.pending_events
                        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                }
                _ if check_writer => {
                    self.pending_msgs
                        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                }
                _ => {
                    self.pending_reads
                        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
            if bytes > 0 {
                if check_writer || is_write {
                    self.pending_bytes
                        .fetch_sub(bytes, std::sync::atomic::Ordering::Relaxed);
                } else {
                    self.pending_read_bytes
                        .fetch_sub(bytes, std::sync::atomic::Ordering::Relaxed);
                }
            }
            return None;
        }
        Some(rx)
    }

    async fn request_with_checked<R: Default>(
        &self,
        make: impl FnOnce(oneshot::Sender<R>) -> Msg,
        channel: &mpsc::UnboundedSender<Msg>,
        check_writer: bool,
    ) -> R {
        let Some(rx) = self.send_request_checked(make, channel, check_writer) else {
            return R::default();
        };
        if self.timeout_secs == 0 {
            return rx.await.unwrap_or_default();
        }
        match tokio::time::timeout(std::time::Duration::from_secs(self.timeout_secs), rx).await {
            Ok(Ok(value)) => value,
            // The timeout must not silently turn a query into an empty
            // answer (an empty timeline / a destructive negentropy sync):
            // report it loudly (and count it, so the errors metric exposes
            // overload), and the WebSocket callers that use the reporting
            // variants respond with an error instead.
            _ => {
                self.errors
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                log::warn!(
                    "database request timed out after {}s (a query result was dropped)",
                    self.timeout_secs
                );
                R::default()
            }
        }
    }

    pub async fn put(&self, event: impl Into<Arc<Event>>, now: u64) -> PutOutcome {
        self.put_with_first_seen(event.into(), now, None).await
    }

    /// Like [`Self::put`], but records the pubkey's first-seen timestamp in
    /// the same write transaction (one commit/fsync instead of two for a
    /// pubkey's first accepted event). Takes an [`Arc<Event>`] so the caller
    /// can reuse the same allocation for its post-commit side effects.
    pub async fn put_with_first_seen(
        &self,
        event: Arc<Event>,
        now: u64,
        first_seen: Option<([u8; 32], u64)>,
    ) -> PutOutcome {
        self.request_write(|reply| Msg::Put {
            event,
            now,
            first_seen,
            reply,
        })
        .await
    }

    /// Plain query used by tests: production paths use [`Self::query_req`]
    /// (WS visibility slack), [`Self::query_full_startup`] (fail-closed) or
    /// the reported variants.
    #[cfg(test)]
    pub async fn query(&self, filters: Vec<Filter>, limit: usize, now: u64) -> (Vec<Event>, bool) {
        self.query_directed(filters, limit, now, false, 0).await
    }

    /// WebSocket REQ query: like [`Self::query`] but with the hidden-event
    /// slack enabled (the scan over-fetches each filter's limit so that
    /// events withheld by the connection's visibility rules do not consume
    /// the limit slots; the connection truncates the visible results).
    pub async fn query_req(
        &self,
        filters: Vec<Filter>,
        limit: usize,
        now: u64,
    ) -> (Vec<Event>, bool) {
        self.query_directed(filters, limit, now, false, 1).await
    }

    /// Like [`Self::query`] but with an explicit scan direction: `false`
    /// returns newest events first (NIP-01), `true` returns oldest first.
    /// `hidden_slack` over-fetches the per-filter limits (see
    /// [`Msg::Query`]); the WebSocket REQ path uses 1, every other caller 0.
    pub async fn query_directed(
        &self,
        filters: Vec<Filter>,
        limit: usize,
        now: u64,
        ascending: bool,
        hidden_slack: usize,
    ) -> (Vec<Event>, bool) {
        self.request_read(|reply| Msg::Query {
            filters,
            limit,
            now,
            ascending,
            budget: SCAN_BUDGET,
            hidden_slack,
            reply,
        })
        .await
    }

    /// Full-history scan for the startup rebuilds (NIP-29 group state,
    /// NIP-43 role store): the large scan budget walks the whole event
    /// history, and a failed or timed-out reply is reported as `None`
    /// instead of degrading to an empty page. An empty page would be
    /// mistaken for the end of the history, and the resulting incomplete
    /// state would be persisted (missing groups become world-readable).
    ///
    /// The rebuilds page with `ascending = true` and apply each page as it
    /// arrives: the scan always collects every event of the page's boundary
    /// timestamp, so a page never splits a second and advancing `since` past
    /// it cannot skip an event — the rebuild stays bounded to one page in
    /// memory instead of materializing the whole history.
    pub async fn query_full_startup(
        &self,
        filters: Vec<Filter>,
        limit: usize,
        now: u64,
        ascending: bool,
    ) -> Option<(Vec<Event>, bool)> {
        self.request_read_startup(|reply| Msg::Query {
            filters,
            limit,
            now,
            ascending,
            budget: FULL_SCAN_BUDGET,
            hidden_slack: 0,
            reply,
        })
        .await
    }

    /// REST API query: served by the dedicated API reader thread so that
    /// `/api/v1` traffic never blocks WebSocket queries. Applies its own
    /// queue cap: when the API reader's queue is deep (or the query times
    /// out), the request fails fast with `None` instead of piling up behind
    /// WebSocket work — the handlers answer 503, because an empty `200`
    /// result would be indistinguishable from "no events". Admission
    /// reserves first (add-then-check with rollback) so concurrent bursts
    /// cannot overshoot the cap without bound.
    pub async fn api_query(
        &self,
        filters: Vec<Filter>,
        limit: usize,
        now: u64,
        ascending: bool,
    ) -> Option<(Vec<Event>, bool)> {
        let (tx, rx) = oneshot::channel();
        let msg = Msg::Query {
            filters,
            limit,
            now,
            ascending,
            budget: SCAN_BUDGET,
            hidden_slack: 0,
            reply: tx,
        };
        let bytes = msg_bytes(&msg);
        if !self.api_reserve(bytes) {
            return None;
        }
        if self.api_read_tx.send(msg).is_err() {
            self.api_release(bytes);
            return None;
        }
        let out = if self.timeout_secs == 0 {
            rx.await.ok()
        } else {
            tokio::time::timeout(std::time::Duration::from_secs(self.timeout_secs), rx)
                .await
                .ok()
                .and_then(|r| r.ok())
        };
        if out.is_none() {
            self.errors
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            log::warn!("REST API query timed out or was dropped");
        }
        // The API reader thread decrements `api_pending` once it has
        // processed the message (including its panic path), so this path
        // must not decrement again.
        out
    }

    /// REST API count aggregation (COUNT / per-kind / related /
    /// monthly/daily/hourly): served by the dedicated API reader thread
    /// like [`Self::api_query`], so the multi-month loops and per-endpoint
    /// scans never block WebSocket queries on the shared reader. Applies
    /// the same fail-fast queue cap.
    pub async fn api_count(
        &self,
        filters: Vec<Filter>,
        limit: usize,
        now: u64,
    ) -> Option<(Vec<Event>, bool)> {
        let (tx, rx) = oneshot::channel();
        let msg = Msg::Count {
            filters,
            limit,
            now,
            reply: tx,
        };
        let bytes = msg_bytes(&msg);
        if !self.api_reserve(bytes) {
            return None;
        }
        if self.api_read_tx.send(msg).is_err() {
            self.api_release(bytes);
            return None;
        }
        let out = if self.timeout_secs == 0 {
            rx.await.ok()
        } else {
            tokio::time::timeout(std::time::Duration::from_secs(self.timeout_secs), rx)
                .await
                .ok()
                .and_then(|r| r.ok())
        };
        if out.is_none() {
            self.errors
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            log::warn!("REST API count timed out or was dropped");
        }
        // The API reader thread decrements `api_pending` once it has
        // processed the message (including its panic path), so this path
        // must not decrement again.
        out
    }

    /// Records the first-seen time of each pubkey when unknown; returns
    /// `(created, first_seen)` per entry, aligned with the input.
    /// Records the first-seen timestamp of new accounts. A write: it is
    /// routed without a response timeout like every other write, so a
    /// stalled writer cannot silently drop the record (which would
    /// disable the account-age gate while the writer is busy).
    pub async fn touch_first_seen_batch(&self, entries: Vec<([u8; 32], u64)>) -> Vec<(bool, u64)> {
        self.request_write(|reply| Msg::TouchFirstSeen { entries, reply })
            .await
    }

    /// Read-only first-seen lookup (no write): returns `(created, first_seen)`
    /// per pubkey. Used by the pre-store age check so that a failed first
    /// event (expired/duplicate/invalid) does not start the account-age clock.
    pub async fn first_seen_batch(&self, pubkeys: Vec<[u8; 32]>) -> Vec<(bool, u64)> {
        self.request_read(|reply| Msg::FirstSeenStatus { pubkeys, reply })
            .await
    }

    /// Stores a batch of events in a single write transaction. Used by the
    /// tests; the relay itself goes through [`Self::put_batch_deferred`].
    #[allow(dead_code)]
    pub async fn put_batch(&self, events: Vec<(Event, u64)>) -> Vec<PutOutcome> {
        let events = events
            .into_iter()
            .map(|(event, now)| (Arc::new(event), now))
            .collect();
        self.request_write(|reply| Msg::PutBatch { events, reply })
            .await
    }

    /// Like [`Self::put_batch`], reporting a lost writer (or a dropped
    /// reply) as `None` instead of degrading to an empty outcome vector.
    /// The migration must not mistake a failed batch for "no events were
    /// stored" and report a completed run. Takes shared [`Arc`]s so the
    /// caller can apply per-event side effects after the commit without
    /// deep-copying the batch.
    pub async fn put_batch_checked(
        &self,
        events: Vec<(Arc<Event>, u64)>,
    ) -> Option<Vec<PutOutcome>> {
        self.request_write_checked(|reply| Msg::PutBatch { events, reply })
            .await
    }

    /// Queues a batch for the writer and returns the reply receiver
    /// without awaiting it: the connection can keep reading frames while
    /// the writer commits, instead of stalling on the commit (and letting
    /// the socket buffer decide the batch size). Returns `None` when the
    /// queue is full (the batch was not queued). The events are shared
    /// [`Arc`]s so queueing a batch never deep-copies the contents.
    pub fn put_batch_deferred(
        &self,
        events: Vec<(Arc<Event>, u64)>,
    ) -> Option<tokio::sync::oneshot::Receiver<Vec<PutOutcome>>> {
        self.send_request(|reply| Msg::PutBatch { events, reply }, &self.tx)
    }

    /// NIP-77: returns only `(created_at, id)` records of the matching
    /// events, keeping the memory footprint at a few bytes per record.
    /// WebSocket REQ query that reports failure: `None` when the reader
    /// timed out (or the request failed fast). The caller must not
    /// present an empty result as a complete answer — a timed-out query
    /// presented as empty would make the client believe the timeline is
    /// empty.
    pub async fn query_req_reported(
        &self,
        filters: Vec<Filter>,
        limit: usize,
        now: u64,
    ) -> Option<(Vec<Event>, bool)> {
        self.request_read_result(|reply| Msg::Query {
            filters,
            limit,
            now,
            ascending: false,
            budget: SCAN_BUDGET,
            hidden_slack: 1,
            reply,
        })
        .await
    }

    /// COUNT that reports failure (`None` on timeout / fail-fast): a
    /// timed-out count must not be reported as zero.
    pub async fn count_reported(
        &self,
        filters: Vec<Filter>,
        limit: usize,
        now: u64,
    ) -> Option<(Vec<Event>, bool)> {
        self.request_read_result(|reply| Msg::Count {
            filters,
            limit,
            now,
            reply,
        })
        .await
    }

    /// Negentropy query that reports failure (`None` on timeout /
    /// fail-fast): a timed-out sync must not be answered with an empty
    /// item set, or the peer would delete its local events.
    pub async fn neg_items_reported(
        &self,
        filter: Filter,
        limit: usize,
        now: u64,
    ) -> Option<(NegItems, bool)> {
        self.request_read_result(|reply| Msg::NegQuery {
            filter,
            limit,
            now,
            reply,
        })
        .await
    }

    /// WebSocket REQ query that reports failure: `None` when the reader
    /// could not run the scan (store error), timed out or failed fast.
    /// A scan error must never be presented as an empty timeline, so the
    /// reader drops the reply instead of sending `(Vec::new(), false)`.
    ///
    /// Part of the database's published consumer surface (WS/REST), so it
    /// stays compiled even when a build configuration does not call it yet.
    #[allow(dead_code)]
    pub async fn query_req_result(
        &self,
        filters: Vec<Filter>,
        limit: usize,
        now: u64,
    ) -> Option<(Vec<Event>, bool)> {
        self.query_req_reported(filters, limit, now).await
    }

    /// COUNT that reports failure: `None` on a store/scan error, timeout
    /// or fail-fast (never a silent zero). The `u64` is the number of
    /// matching events the scan collected; the bool is the NIP-67
    /// approximate flag.
    ///
    /// Part of the database's published consumer surface (WS/REST), so it
    /// stays compiled even when a build configuration does not call it yet.
    #[allow(dead_code)]
    pub async fn count_result(
        &self,
        filters: Vec<Filter>,
        limit: usize,
        now: u64,
    ) -> Option<(u64, bool)> {
        self.count_reported(filters, limit, now)
            .await
            .map(|(events, more)| (events.len() as u64, more))
    }

    /// NIP-77 NEG query that reports failure: `None` on a store/scan
    /// error, timeout or fail-fast (never an empty item set: the peer
    /// would delete its local events).
    ///
    /// Part of the database's published consumer surface (WS), so it stays
    /// compiled even when a build configuration does not call it yet.
    #[allow(dead_code)]
    pub async fn neg_query_result(
        &self,
        filter: Filter,
        limit: usize,
        now: u64,
    ) -> Option<(NegItems, bool)> {
        self.neg_items_reported(filter, limit, now).await
    }

    /// Aggregate sample that reports failure (`None` on a store/scan
    /// error, timeout or fail-fast): an empty sample must never be
    /// presented as a complete count. Uses the shared reader channel
    /// (never the API reader queue), so the REST handler can serve the
    /// endpoint without competing with `/api/v1` traffic for its slots.
    ///
    /// Part of the database's published consumer surface (REST), so it
    /// stays compiled even when a build configuration does not call it yet.
    #[allow(dead_code)]
    pub async fn aggregate_sample_result(
        &self,
        limit: usize,
        now: u64,
    ) -> Option<(NegItems, bool)> {
        self.request_read_result(|reply| Msg::AggregateSample { limit, now, reply })
            .await
            .flatten()
    }

    /// REST-API aggregate sample: the newest events as lightweight
    /// negentropy records (no content), served by the dedicated API reader
    /// thread so a large sample never stalls WebSocket queries. `None` on
    /// timeout / fail-fast: the aggregate endpoints must not present an
    /// empty sample as a complete count.
    pub async fn api_neg_sample(&self, limit: usize, now: u64) -> Option<(NegItems, bool)> {
        self.api_request(|reply| Msg::AggregateSample { limit, now, reply })
            .await
    }

    /// Generic REST-API reader request with the API queue cap and timeout.
    /// Admission uses [`Self::api_reserve`] (add-then-check with rollback).
    async fn api_request<R: Default>(&self, make: impl FnOnce(oneshot::Sender<R>) -> Msg) -> R {
        let (tx, rx) = oneshot::channel();
        let msg = make(tx);
        let bytes = msg_bytes(&msg);
        if !self.api_reserve(bytes) {
            return R::default();
        }
        if self.api_read_tx.send(msg).is_err() {
            self.api_release(bytes);
            return R::default();
        }
        // The API reader thread decrements `api_pending` on completion
        // (including its panic path), so this path must not decrement again.
        if self.timeout_secs == 0 {
            rx.await.unwrap_or_default()
        } else {
            tokio::time::timeout(std::time::Duration::from_secs(self.timeout_secs), rx)
                .await
                .map(|r| r.unwrap_or_default())
                .unwrap_or_default()
        }
    }

    /// Reserves one API-reader queue slot and its payload bytes
    /// (add-then-check with rollback). Returns `false` when the queue is
    /// deep (fail-fast, counted in stats). The API reader thread releases
    /// the reservation on completion.
    fn api_reserve(&self, bytes: usize) -> bool {
        let pending = self
            .api_pending
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .saturating_add(1);
        let pending_bytes = if bytes > 0 {
            self.api_pending_bytes
                .fetch_add(bytes, std::sync::atomic::Ordering::Relaxed)
                .saturating_add(bytes)
        } else {
            self.api_pending_bytes
                .load(std::sync::atomic::Ordering::Relaxed)
        };
        if pending
            > self
                .max_api_pending
                .load(std::sync::atomic::Ordering::Relaxed)
            || (self.max_pending_bytes > 0 && pending_bytes > self.max_pending_bytes)
        {
            self.api_release(bytes);
            self.overloads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return false;
        }
        true
    }

    /// Releases an API-reader reservation (count and payload bytes) after a
    /// failed send. The reader thread releases it on completion otherwise.
    fn api_release(&self, bytes: usize) {
        self.api_pending
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        if bytes > 0 {
            self.api_pending_bytes
                .fetch_sub(bytes, std::sync::atomic::Ordering::Relaxed);
        }
    }

    #[cfg(test)]
    pub async fn apply_deletion(
        &self,
        targets: Vec<String>,
        addresses: Vec<nip09::Address>,
        request_pubkey: Option<String>,
        request_created: u64,
    ) -> usize {
        self.apply_deletion_checked(targets, addresses, request_pubkey, request_created)
            .await
            .0
            .unwrap_or(0)
    }

    /// Like [`Self::apply_deletion`], reporting a fail-fast/lost writer or
    /// a failed removal walk as `None` in the first element so the caller
    /// does not treat a skipped deletion as success. The second element is
    /// the `group_state_removed` flag: it is still reported when the walk
    /// failed, because a removed NIP-29/NIP-43 state event invalidates the
    /// derived state even if a later chunk aborted.
    pub async fn apply_deletion_checked(
        &self,
        targets: Vec<String>,
        addresses: Vec<nip09::Address>,
        request_pubkey: Option<String>,
        request_created: u64,
    ) -> (Option<usize>, bool) {
        self.request_write(|reply| Msg::Delete {
            targets,
            addresses,
            request_pubkey,
            request_created,
            group: None,
            reply,
        })
        .await
    }

    /// NIP-29 `kind:9005`: deletes the `e`-tag targets but only when they
    /// belong to `group`, so a group admin cannot delete another group's
    /// events. Test-only: production callers must use the checked variant
    /// so a dropped side effect is not reported as success.
    #[cfg(test)]
    pub async fn apply_group_deletion(&self, targets: Vec<String>, group: String) -> usize {
        self.apply_group_deletion_checked(targets, group)
            .await
            .0
            .unwrap_or(0)
    }

    /// Like [`Self::apply_group_deletion`], reporting a fail-fast/lost
    /// writer or a failed removal walk as `None` in the first element (see
    /// [`Self::apply_deletion_checked`] for the group-state flag).
    pub async fn apply_group_deletion_checked(
        &self,
        targets: Vec<String>,
        group: String,
    ) -> (Option<usize>, bool) {
        self.request_write(|reply| Msg::Delete {
            targets,
            addresses: Vec::new(),
            request_pubkey: None,
            request_created: u64::MAX,
            group: Some(group),
            reply,
        })
        .await
    }

    /// NIP-29 `kind:9008`: purges every stored event tagged with the deleted
    /// group id.
    pub async fn group_purge(&self, group: String, now: u64) -> usize {
        self.group_purge_until(group, now, u64::MAX).await
    }

    /// [`Self::group_purge`] bounded to events with `created_at <= until`
    /// (the migration uses the `9008`'s own timestamp so a re-created
    /// group's later events survive).
    pub async fn group_purge_until(&self, group: String, now: u64, until: u64) -> usize {
        self.request_write(|reply| Msg::GroupPurge {
            group,
            now,
            until,
            reply,
        })
        .await
    }

    /// Every vanished pubkey (raw 32-byte keys) for the startup rebuilds.
    /// `None` when the reader could not answer: the caller fails closed
    /// instead of resurrecting vanished identities with an empty list.
    /// Streams every vanished pubkey through `f` in bounded pages (the
    /// caller builds its set), instead of materializing the whole table at
    /// once. Returns `None` when the database did not answer.
    pub async fn vanish_pubkeys_each<F: FnMut(&[u8])>(&self, mut f: F) -> Option<()> {
        const PAGE: usize = 4096;
        let mut after: Option<Vec<u8>> = None;
        loop {
            // Startup-style read: neither fail-fast nor timeout may degrade
            // a failed page to "no vanished pubkeys" — the rebuilds would
            // then resurrect vanished identities (fail-open).
            let page = self
                .request_read_startup(|reply| Msg::VanishPubkeysPage {
                    after: after.clone(),
                    limit: PAGE,
                    reply,
                })
                .await // the reader must reply
                .and_then(|page| page)?;
            for key in &page {
                f(key);
            }
            match page.last() {
                Some(last) if page.len() == PAGE => after = Some(last.clone()),
                _ => return Some(()),
            }
        }
    }

    /// One page of vanished pubkeys as raw 32-byte keys, strictly after
    /// `after`. The startup rebuilds page through this instead of the
    /// hex-spelled form, so holding the whole set costs 32 bytes per entry.
    /// `None` when the reader could not answer (a dropped reply on a store
    /// error): the caller fails closed rather than treating a failed page
    /// as the end of the table.
    ///
    /// Part of the database's published consumer surface (the NIP-29/43
    /// rebuilds), so it stays compiled even when a build configuration does
    /// not call it yet.
    #[allow(dead_code)]
    pub async fn vanish_pubkeys_raw_page(
        &self,
        after: Option<&[u8]>,
        limit: usize,
    ) -> Option<Vec<[u8; 32]>> {
        let after = after.map(<[u8]>::to_vec);
        // Startup-style read: neither fail-fast nor timeout may degrade a
        // failed page to "no vanished pubkeys" (fail-open).
        self.request_read_startup(|reply| Msg::VanishPubkeysRawPage {
            after,
            limit,
            reply,
        })
        .await
    }

    #[cfg(test)]
    pub async fn apply_vanish(&self, pubkey: [u8; 32], until_created: u64) -> usize {
        self.apply_vanish_checked(pubkey, until_created)
            .await
            .map(|(removed, _)| removed)
            .unwrap_or(0)
    }

    /// Like [`Self::apply_vanish`], reporting a fail-fast/lost writer or a
    /// failed removal walk as `None` (in which case no vanish marker was
    /// written, so the re-delivered request must finish the removal). The
    /// second element of the tuple is true when the removed history
    /// contained a NIP-29/NIP-43 state event, so the derived state must be
    /// rebuilt (a plain post deletion does not change it).
    pub async fn apply_vanish_checked(
        &self,
        pubkey: [u8; 32],
        until_created: u64,
    ) -> Option<(usize, bool)> {
        self.request_write(|reply| Msg::Vanish {
            pubkey: pubkey.to_vec(),
            until_created,
            reply,
        })
        .await
    }

    /// NIP-59: deletes `kind:1059` gift wraps p-tagging `pubkey`.
    #[cfg(test)]
    pub async fn delete_gift_wraps_to(&self, pubkey: [u8; 32]) -> usize {
        self.delete_gift_wraps_to_checked(pubkey, u64::MAX)
            .await
            .unwrap_or(0)
    }

    /// Like [`Self::delete_gift_wraps_to`], reporting a fail-fast/lost
    /// writer or a failed removal walk as `None`. `until` bounds the walk
    /// (`created_at <= until`): the migration passes the deletion's own
    /// timestamp so wraps imported after it survive (the live path passes
    /// `u64::MAX` and removes every stored wrap).
    pub async fn delete_gift_wraps_to_checked(
        &self,
        pubkey: [u8; 32],
        until: u64,
    ) -> Option<usize> {
        self.request_write(|reply| Msg::GiftWrapPurge {
            pubkey: pubkey.to_vec(),
            until,
            reply,
        })
        .await
    }

    /// Migration-only: records NIP-09 re-publication blocks for deletion
    /// targets absent from the database, scoped to the deletion's author
    /// (see `Store::record_absent_deletion_targets`). Returns how many
    /// markers were written, or `None` when the write failed (the migration
    /// must not report a completed run).
    pub async fn record_absent_deletion_targets(
        &self,
        pubkey: [u8; 32],
        targets: Vec<String>,
    ) -> Option<usize> {
        self.request_write_checked(|reply| Msg::RecordAbsentDeletionTargets {
            pubkey: pubkey.to_vec(),
            targets,
            reply,
        })
        .await
        .flatten()
    }

    pub async fn event_id_prefix_exists(&self, prefix: &[u8]) -> bool {
        self.request_read(|reply| Msg::PrefixExists {
            prefix: prefix.to_vec(),
            reply,
        })
        .await
    }

    /// Checks many event-id prefixes in a single database round trip.
    pub async fn prefixes_exist(&self, prefixes: Vec<Vec<u8>>) -> Vec<bool> {
        self.request_read(|reply| Msg::PrefixesExist { prefixes, reply })
            .await
    }

    /// Drains and returns the number of database errors since the last call.
    pub fn take_errors(&self) -> u64 {
        self.errors.swap(0, std::sync::atomic::Ordering::Relaxed)
    }

    /// Drains and returns the number of cap (overload) fail-fasts since the
    /// last call. Distinct from [`Self::take_errors`]: an overload is the
    /// relay shedding load, not a storage fault.
    pub fn take_overloads(&self) -> u64 {
        self.overloads.swap(0, std::sync::atomic::Ordering::Relaxed)
    }

    /// Messages queued on the writer channel but not yet drained.
    pub fn pending_msgs(&self) -> usize {
        self.pending_msgs.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Events inside the queued writer messages.
    pub fn pending_events(&self) -> usize {
        self.pending_events
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Queued payload bytes on the writer channel.
    pub fn pending_bytes(&self) -> usize {
        self.pending_bytes
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Read-only messages queued on the WebSocket reader channels.
    pub fn pending_reads(&self) -> usize {
        self.pending_reads
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Queued payload bytes on the WebSocket reader channels.
    pub fn pending_read_bytes(&self) -> usize {
        self.pending_read_bytes
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Queries queued on the dedicated REST API reader channel.
    pub fn api_pending(&self) -> usize {
        self.api_pending.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Queued payload bytes on the dedicated REST API reader channel.
    pub fn api_pending_bytes(&self) -> usize {
        self.api_pending_bytes
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Free bytes on the filesystem hosting the database directory, when
    /// `statvfs` succeeds (the same probe the write path uses).
    pub fn free_disk_bytes(&self) -> Option<u64> {
        store::path_free_space(&self.db_path)
    }

    /// Whether the database filesystem is below the write margin the put
    /// path refuses to commit under (a write to a full disk raises SIGBUS).
    /// `false` when the free space cannot be probed.
    pub fn disk_full(&self) -> bool {
        self.free_disk_bytes().is_some_and(store::disk_below_margin)
    }

    /// Bans an event id (NIP-86 banevent): removes it from storage and
    /// prevents re-publication. Returns whether the event was stored.
    pub async fn ban_event(&self, id: [u8; 32], reason: &str) -> bool {
        self.request_write(|reply| Msg::Ban {
            id: id.to_vec(),
            reason: reason.to_string(),
            reply,
        })
        .await
    }

    pub async fn unban_event(&self, id: [u8; 32]) -> bool {
        self.request_write(|reply| Msg::Unban {
            id: id.to_vec(),
            reply,
        })
        .await
    }

    pub async fn list_banned_events(&self) -> Vec<(String, String)> {
        self.request_read(|reply| Msg::ListBanned { reply }).await
    }

    /// Persists the access control lists (NIP-86 runtime bans/allowlists).
    /// Persists the access control lists; the reply reports whether the
    /// commit succeeded (the NIP-86 methods surface a failure instead of
    /// claiming a change that is only in memory).
    ///
    /// Kept for compatibility; [`Self::save_access_and_pubkeys`] is the
    /// atomic path the relay and CLI migrate to.
    #[allow(dead_code)]
    pub async fn save_access(&self, access: crate::config::AccessControl) -> bool {
        self.request_write(|reply| Msg::SaveAccess { access, reply })
            .await
    }

    /// Persists the relay pubkey access lists ((pubkey, reason) pairs for
    /// the deny and allow lists) under their dedicated LMDB key.
    /// Persists the relay pubkey lists; the reply reports whether the
    /// commit succeeded.
    ///
    /// Kept for compatibility; [`Self::save_access_and_pubkeys`] is the
    /// atomic path the relay and CLI migrate to.
    #[allow(dead_code)]
    pub async fn save_relay_pubkeys(
        &self,
        deny: &[(String, String)],
        allow: &[(String, String)],
    ) -> bool {
        let deny = deny.to_vec();
        let allow = allow.to_vec();
        self.request_write(|reply| Msg::SaveRelayPubkeys { deny, allow, reply })
            .await
    }

    /// Persists the access blob and the relay pubkey deny/allow lists in a
    /// single transaction: a crash between two separate saves could leave
    /// the relay-level bans and the access rules from different
    /// generations. Returns whether the commit succeeded.
    pub async fn save_access_and_pubkeys(
        &self,
        access: &crate::config::AccessControl,
        deny: &[(String, String)],
        allow: &[(String, String)],
    ) -> bool {
        let access = access.clone();
        let deny = deny.to_vec();
        let allow = allow.to_vec();
        self.request_write(|reply| Msg::SaveAccessAndPubkeys {
            access,
            deny,
            allow,
            reply,
        })
        .await
    }

    /// Takes the CLI's cross-process `access.lock` (see [`lock_access_state`])
    /// on the blocking pool, so a caller can hold it across a whole
    /// snapshot-and-write. `None` means the lock could not be taken: the
    /// write then proceeds unserialized, matching [`Self::save_blossom_allow`].
    pub(crate) async fn lock_access_state(&self) -> Option<AccessStateLock> {
        lock_access_state_async(self.db_path.clone()).await
    }

    /// Persists the Blossom upload allowlist under its dedicated LMDB key
    /// (the same key `nostrfy blossom allow/deny` writes). Returns whether
    /// the commit succeeded, so the caller never reports a persisted
    /// allowlist change that only lives in memory.
    ///
    /// The write shares the CLI's cross-process `access.lock`, taken here
    /// for callers that do not already hold it. A caller with an outer
    /// read-modify-write (the `/blossom allow|deny` command handler) takes
    /// [`Self::lock_access_state`] first and calls
    /// [`Self::save_blossom_allow_locked`]: a second `flock` on another
    /// descriptor from the same process would block on the caller's own
    /// lock. Kept for callers without an outer read-modify-write (tests).
    #[allow(dead_code)]
    pub async fn save_blossom_allow(&self, entries: &[String]) -> bool {
        let _state_lock = lock_access_state_async(self.db_path.clone()).await;
        self.save_blossom_allow_locked(entries).await
    }

    /// [`Self::save_blossom_allow`] without taking the cross-process lock:
    /// the caller must already hold it (via [`Self::lock_access_state`])
    /// across its whole read-modify-write. Returns whether the commit
    /// succeeded.
    pub(crate) async fn save_blossom_allow_locked(&self, entries: &[String]) -> bool {
        let entries = entries.to_vec();
        self.request_write(|reply| Msg::SaveBlossomAllow { entries, reply })
            .await
    }

    /// Persists the NIP-29 group state snapshot. The relay's hot mutation
    /// path debounces this call through a background worker; the fail-closed
    /// paths (and tests) save immediately. The returned bool reports whether
    /// the commit succeeded: on `false` (including an overload fail-fast or a
    /// lost writer) the caller must keep the state pending and retry instead
    /// of treating the snapshot as durable.
    pub async fn save_groups(&self, snapshot: crate::nips::nip29::GroupsSnapshot) -> bool {
        self.request_write(|reply| Msg::SaveGroups { snapshot, reply })
            .await
    }

    /// Loads the persisted NIP-29 group state snapshot at startup.
    /// Returns `None` when no snapshot was ever written (pre-persistence
    /// database) or the load failed: the caller runs the replay migration
    /// instead of starting empty (fail-closed).
    /// Loads the persisted NIP-29 group state snapshot at startup: a
    /// failed read is reported as [`LoadGroupsOutcome::Failed`], never
    /// conflated with a first-run [`LoadGroupsOutcome::Missing`].
    pub async fn load_groups(&self) -> LoadGroupsOutcome {
        self.request_read_blocking(|reply| Msg::LoadGroups { reply })
            .await
    }

    /// Drops the persisted NIP-29 group state snapshot: the next startup
    /// rebuilds from the surviving events instead of restoring state that
    /// predates a vanish. The returned bool reports whether the commit
    /// succeeded: on `false` the caller must not assume the fail-closed
    /// clear happened (the next startup could restore the stale snapshot).
    pub async fn clear_groups_snapshot(&self) -> bool {
        self.request_write(|reply| Msg::ClearGroupsSnapshot { reply })
            .await
    }

    /// Persists the NIP-43 role state snapshot (same commit-success
    /// semantics as [`Self::save_groups`]; the relay debounces the hot
    /// mutation path).
    pub async fn save_roles(&self, snapshot: crate::nips::nip43::RolesSnapshot) -> bool {
        self.request_write(|reply| Msg::SaveRoles { snapshot, reply })
            .await
    }

    /// Loads the persisted NIP-43 role state snapshot at startup (see
    /// [`Self::load_groups`]).
    /// Loads the persisted NIP-43 role state snapshot at startup: a
    /// failed read is reported as [`LoadRolesOutcome::Failed`], never
    /// conflated with a first-run [`LoadRolesOutcome::Missing`].
    pub async fn load_roles(&self) -> LoadRolesOutcome {
        self.request_read_blocking(|reply| Msg::LoadRoles { reply })
            .await
    }

    /// Loads the persisted access control at startup: waits for the reader
    /// (no timeout, no fail-fast) so a slow database cannot silently
    /// degrade the security state to "empty = allow everyone". A failed
    /// read is reported as [`LoadAccessOutcome::Failed`], never conflated
    /// with the first-run [`LoadAccessOutcome::Missing`].
    pub async fn load_access(&self) -> LoadAccessOutcome {
        self.request_read_blocking(|reply| Msg::LoadAccess { reply })
            .await
    }

    /// Loads the persisted Blossom upload allowlist at startup (see
    /// [`Self::load_access`]). `None` reports a database failure: the
    /// caller must fail stop instead of starting with an empty (fail-open)
    /// allowlist.
    pub async fn load_blossom_allow(&self) -> Option<Vec<String>> {
        self.request_read_blocking(|reply| Msg::LoadBlossomAllow { reply })
            .await
    }

    /// Loads the persisted relay pubkey access lists (deny, allow) at
    /// startup (see [`Self::load_access`]). `None` reports a database
    /// failure: the caller must fail stop instead of starting with empty
    /// (fail-open) lists.
    pub async fn load_relay_pubkeys(&self) -> Option<crate::db::store::RelayPubkeyLists> {
        self.request_read_blocking(|reply| Msg::LoadRelayPubkeys { reply })
            .await
    }

    /// Reload variant with failure reporting (`None` = the load failed or
    /// timed out): the caller keeps the previous lists instead of
    /// overwriting them with an empty (fail-open) result.
    pub async fn try_load_blossom_allow(&self) -> Option<Vec<String>> {
        self.request_read_result(|reply| Msg::LoadBlossomAllow { reply })
            .await
            .flatten()
    }

    /// Reload variant with failure reporting, see
    /// [`Self::try_load_blossom_allow`].
    pub async fn try_load_relay_pubkeys(&self) -> Option<crate::db::store::RelayPubkeyLists> {
        self.request_read_result(|reply| Msg::LoadRelayPubkeys { reply })
            .await
            .flatten()
    }

    /// Fail-fast load of the persisted access blob for the write-through
    /// merge (see `Relay::persist_access`): `None` refuses the write
    /// instead of merging onto a state the database could not answer. A
    /// missing blob (first run) merges onto an empty base, like a fresh
    /// seed; only a failed load refuses.
    pub async fn try_load_access(&self) -> Option<crate::config::AccessControl> {
        match self
            .request_read_result(|reply| Msg::LoadAccess { reply })
            .await?
        {
            LoadAccessOutcome::Loaded(access) => Some(access),
            LoadAccessOutcome::Missing => Some(crate::config::AccessControl::default()),
            LoadAccessOutcome::Failed => None,
        }
    }

    /// Adds an owner to a Blossom blob's persisted metadata. Returns
    /// whether the commit succeeded.
    pub async fn blossom_add_owner(
        &self,
        sha256: &str,
        mime: &str,
        size: u64,
        uploaded: i64,
        pubkey: &str,
    ) -> bool {
        self.request_write(|reply| Msg::BlossomAddOwner {
            sha256: sha256.to_string(),
            mime: mime.to_string(),
            size,
            uploaded,
            pubkey: pubkey.to_string(),
            reply,
        })
        .await
    }

    /// Loads a Blossom blob's persisted metadata.
    /// Like [`Self::blossom_load`], but distinguishes a database failure
    /// (`None`) from "no mapping" (`Some(None)`): the upload path must not
    /// treat a failed read as "no owner yet" and later roll back a valid
    /// mapping, and a lookup failure must not be reported as 404.
    pub async fn blossom_load_checked(
        &self,
        sha256: &str,
    ) -> Option<Option<crate::db::store::BlossomMeta>> {
        self.request_read_result(|reply| Msg::BlossomLoad {
            sha256: sha256.to_string(),
            reply,
        })
        .await
    }

    pub async fn blossom_load(&self, sha256: &str) -> Option<crate::db::store::BlossomMeta> {
        self.request_read(|reply| Msg::BlossomLoad {
            sha256: sha256.to_string(),
            reply,
        })
        .await
    }

    /// Removes one owner and reports whether the database operation itself
    /// completed successfully.
    pub async fn blossom_remove_owner_checked(&self, sha256: &str, pubkey: &str) -> (bool, bool) {
        self.request_write(|reply| Msg::BlossomRemoveOwner {
            sha256: sha256.to_string(),
            pubkey: pubkey.to_string(),
            reply,
        })
        .await
    }

    /// Lists the blob hashes uploaded by a pubkey, capped at `limit`
    /// entries (see `Store::list_blossom_shas`). Test-only since BUD-12
    /// paging uses the uploaded-order index.
    #[cfg(test)]
    pub async fn blossom_list(&self, pubkey: &str, limit: usize) -> Vec<String> {
        self.request_read(|reply| Msg::BlossomList {
            pubkey: pubkey.to_string(),
            limit,
            reply,
        })
        .await
    }

    /// BUD-12 page with failure reporting: `None` when the request failed
    /// fast, timed out, or the reader could not read the store (the reply
    /// sender is dropped on a store error). A listing failure must be
    /// answered as a server error, not as an empty inventory.
    pub async fn blossom_list_page_checked(
        &self,
        pubkey: &str,
        after_uploaded: Option<u64>,
        after_sha: Option<&str>,
        limit: usize,
    ) -> Option<Vec<(String, crate::db::store::BlossomMeta)>> {
        self.request_read_result(|reply| Msg::BlossomListPage {
            pubkey: pubkey.to_string(),
            after_uploaded,
            after_sha: after_sha.map(str::to_string),
            limit,
            reply,
        })
        .await
    }

    /// Adds many Blossom mappings in one transaction (auto-migration).
    /// Returns whether the commit succeeded.
    pub async fn blossom_add_mappings(
        &self,
        entries: Vec<(String, String, u64, i64, String)>,
    ) -> bool {
        self.request_write(|reply| Msg::BlossomAddMappings { entries, reply })
            .await
    }

    /// Whether the one-time legacy migration already ran.
    pub async fn blossom_migration_done(&self) -> bool {
        self.request_read(|reply| Msg::BlossomMigrationDone { reply })
            .await
    }

    /// Marks the one-time legacy migration as done.
    pub async fn mark_blossom_migration(&self) {
        let _ = self
            .request_write(|reply| Msg::BlossomMarkMigration { reply })
            .await;
    }

    /// NIP-40 expiration purge: `(removed events, whether a NIP-29/NIP-43
    /// state event was among them)`. The caller rebuilds the derived state
    /// only when the second field is true; on a failed later chunk the
    /// partial counts are still reported. `first_seen_min_age` is the age
    /// (seconds) past which `first_seen` rows are reaped (0 disables the
    /// reap), so the table cannot grow forever.
    pub async fn purge_expired(&self, now: u64, first_seen_min_age: u64) -> (usize, bool) {
        self.request_write(|reply| Msg::PurgeExpired {
            now,
            first_seen_min_age,
            reply,
        })
        .await
    }

    /// Started-but-unfinished NIP-29 group purges as `(gid, purge_now)`:
    /// each record was written before its first removal chunk and not
    /// cleared, so the caller re-runs `group_purge(gid, purge_now)` to
    /// finish the walk (idempotent, keeps the furthest cut). `None` when
    /// the database could not answer: the caller fails closed instead of
    /// treating unpurged (ghosted) groups as done.
    pub async fn pending_purges(&self) -> Option<Vec<(String, u64, u64)>> {
        self.request_read_startup(|reply| Msg::PendingPurges { reply })
            .await
            .flatten()
    }

    /// Started-but-unfinished NIP-09 deletions: each record carries the
    /// original request, so a caller can inspect (or, in tests, assert) the
    /// resume queue. `None` when the database could not answer: the caller
    /// fails closed instead of treating an unreadable table as "nothing to
    /// resume".
    ///
    /// Consumed by the recovery tests; the relay gauges use
    /// [`Self::table_counts`] for the row count instead.
    #[allow(dead_code)]
    pub async fn pending_deletions(&self) -> Option<Vec<store::PendingDeletion>> {
        self.request_read_startup(|reply| Msg::PendingDeletions { reply })
            .await
            .flatten()
    }

    /// The persistent "derived group state changed" stamp: monotonic, bumped
    /// inside the write transaction of every group-state-relevant removal,
    /// so a caller can persist it with a group snapshot and compare it at
    /// startup to detect that the stored snapshot predates removals. `None`
    /// when the database could not answer: the caller fails closed.
    pub async fn state_stamp(&self) -> Option<u64> {
        self.request_read_startup(|reply| Msg::StateStamp { reply })
            .await
            .flatten()
    }

    /// The derived-state sequence: monotonic, bumped inside the write
    /// transaction of every NIP-29/NIP-43 state-relevant event put, so a
    /// caller can persist it with a state snapshot and compare it at startup
    /// to detect that the stored snapshot predates a state event. `None`
    /// when the database could not answer: the caller fails closed.
    ///
    /// Kept for backward compatibility; the snapshot restore checks use the
    /// per-family [`Self::state_seq_group`] / [`Self::state_seq_role`]
    /// counters now, and this combined counter remains their max.
    #[allow(dead_code)]
    pub async fn state_seq(&self) -> Option<u64> {
        self.request_read_startup(|reply| Msg::StateSeq { reply })
            .await
            .flatten()
    }

    /// The NIP-29 group-state sequence: bumped by every group-state event
    /// put, untouched by NIP-43 role events. The group snapshot restore
    /// check compares against this counter, so a role event no longer
    /// invalidates a group snapshot. `None` when the database could not
    /// answer: the caller fails closed.
    pub async fn state_seq_group(&self) -> Option<u64> {
        self.request_read_startup(|reply| Msg::StateSeqGroup { reply })
            .await
            .flatten()
    }

    /// The NIP-43 role-state sequence (the counterpart of
    /// [`Self::state_seq_group`]).
    pub async fn state_seq_role(&self) -> Option<u64> {
        self.request_read_startup(|reply| Msg::StateSeqRole { reply })
            .await
            .flatten()
    }

    pub async fn size_on_disk(&self) -> u64 {
        self.request_read(|reply| Msg::DatabaseSize { reply }).await
    }

    /// NIP-62 bookkeeping gauges (`vanish markers`, `pending vanishes`);
    /// `None` when the reader could not answer. Kept for compatibility;
    /// [`Self::table_counts`] reports the same rows in one read.
    #[allow(dead_code)]
    pub async fn vanish_counts(&self) -> Option<(u64, u64)> {
        self.request_read_result(|reply| Msg::VanishCounts { reply })
            .await
            .flatten()
    }

    /// Row counts of the bookkeeping tables (gauge material): `deleted`,
    /// `first_seen`, `purged_groups`, `vanish`, `vanish_pending`,
    /// `purge_pending` and `delete_pending`. `None` when the reader could
    /// not answer (the metrics writer keeps the last value instead of
    /// flipping the gauges to zero).
    pub async fn table_counts(&self) -> Option<store::TableCounts> {
        self.request_read_result(|reply| Msg::TableCounts { reply })
            .await
            .flatten()
    }

    /// Last used LMDB page number (used by tests to verify real database
    /// growth: `map_size` is a fixed upfront reservation).
    #[cfg(test)]
    pub async fn last_page_now(&self) -> u64 {
        self.request_read(|reply| Msg::LastPage { reply }).await
    }

    pub fn shutdown(&self) {
        // Cancel long chunked removals first: the writer drains the
        // Shutdown message only after its current request, and without the
        // flag an hours-long walk would delay the join (and SIGTERM) for
        // the whole walk. The cancelled walk leaves its pending record, so
        // the next startup resumes it.
        self.cancel.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = self.tx.send(Msg::Shutdown);
        // One per reader thread (each owns its receiver).
        for tx in &self.read_txs {
            let _ = tx.send(Msg::Shutdown);
        }
        let _ = self.api_read_tx.send(Msg::Shutdown);
        // Join the threads so the final flush and the shutdown sync finish
        // before the process exits (messages queued behind `Shutdown` used
        // to be dropped without a reply).
        let handles = std::mem::take(
            &mut *self
                .threads
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        for handle in handles {
            let _ = handle.join();
        }
    }
}
