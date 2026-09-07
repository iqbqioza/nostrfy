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

use scan::{FULL_SCAN_BUDGET, NegItems, SCAN_BUDGET};
/// `(pubkey, count)` pairs of a relay-wide author-activity walk.
pub(crate) type AuthorCounts = Vec<(Vec<u8>, u64)>;
use store::Store;

use crate::config::DatabaseConfig;
use crate::error::Result;
use crate::event::Event;
use crate::filter::Filter;
use crate::nips::nip09;

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
    /// an `OK` carrying the `mute:` prefix.
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
pub(crate) fn db_error(errors: &Arc<std::sync::atomic::AtomicU64>, e: &crate::error::Error) {
    errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if matches!(
        e,
        crate::error::Error::Heed(heed::Error::Mdb(heed::MdbError::MapFull))
    ) {
        log::error!("database map is full: increase database.max_map_size in nostrfy.toml");
    } else {
        log::error!("database error: {e}");
    }
}

enum Msg {
    Put {
        event: Event,
        now: u64,
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
        events: Vec<(Event, u64)>,
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
    VanishPubkeys {
        reply: oneshot::Sender<Vec<Vec<u8>>>,
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
    /// Relay-wide per-kind event counts (REST API): walks the `by_kind`
    /// index, examining at most `max_keys` entries.
    KindCounts {
        max_keys: usize,
        reply: oneshot::Sender<(Vec<(u64, u64)>, bool)>,
    },
    /// Relay-wide per-author event counts (REST API): walks the
    /// `by_pubkey` index, examining at most `max_keys` entries.
    AuthorCounts {
        max_keys: usize,
        reply: oneshot::Sender<(AuthorCounts, bool)>,
    },
    Delete {
        targets: Vec<String>,
        addresses: Vec<nip09::Address>,
        request_pubkey: Option<String>,
        request_created: u64,
        /// NIP-29 9005 moderation: restrict deletion to events of this group.
        group: Option<String>,
        reply: oneshot::Sender<usize>,
    },
    Vanish {
        pubkey: Vec<u8>,
        /// NIP-62: events up to this created_at (the request's `.created_at`)
        /// are deleted.
        until_created: u64,
        reply: oneshot::Sender<usize>,
    },
    /// NIP-59: delete gift wraps addressed to a pubkey (on NIP-09 deletion).
    GiftWrapPurge {
        pubkey: Vec<u8>,
        reply: oneshot::Sender<usize>,
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
        reply: oneshot::Sender<()>,
    },
    /// Loads the persisted access control lists.
    LoadAccess {
        reply: oneshot::Sender<Option<crate::config::AccessControl>>,
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
        reply: oneshot::Sender<()>,
    },
    /// Persists the Blossom upload allowlist.
    SaveBlossomAllow {
        entries: Vec<String>,
        reply: oneshot::Sender<()>,
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
        reply: oneshot::Sender<bool>,
    },
    /// Lists the blob hashes uploaded by a pubkey (reverse index).
    BlossomList {
        pubkey: String,
        reply: oneshot::Sender<Vec<String>>,
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
    PurgeExpired {
        now: u64,
        reply: oneshot::Sender<usize>,
    },
    DatabaseSize {
        reply: oneshot::Sender<u64>,
    },
    #[cfg(test)]
    MapSize {
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
    read_tx: mpsc::UnboundedSender<Msg>,
    /// Dedicated channel for REST API queries: served by its own reader
    /// thread, so a flood of `/api/v1` requests can never queue up behind
    /// (or in front of) WebSocket REQ/COUNT/NEG queries on the shared
    /// reader thread.
    api_read_tx: mpsc::UnboundedSender<Msg>,
    errors: Arc<std::sync::atomic::AtomicU64>,
    expiry: Arc<std::sync::atomic::AtomicBool>,
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
    /// Queued-but-unprocessed REST API queries, counted separately so an API
    /// flood fails fast without tripping the WebSocket-side caps.
    api_pending: Arc<std::sync::atomic::AtomicUsize>,
    /// Caps for the counters above.
    max_pending_msgs: usize,
    max_pending_events: usize,
    max_api_pending: usize,
    /// How many threads serve the WebSocket reader queue (from
    /// `database.reader_threads`); used to fan the shutdown messages out.
    reader_threads: usize,
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
        // One-time migration: databases written before the pubkey lists
        // moved into their own key still carry them inside the `access`
        // blob — copy them over so existing bans/allowlists survive.
        store.migrate_access_pubkeys()?;
        log::info!("access control migration check complete");
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
        Ok(DbClient {
            tx: threads.tx,
            read_tx: threads.read_tx,
            api_read_tx: threads.api_read_tx,
            errors: threads.errors,
            expiry: threads.expiry,
            timeout_secs: threads.timeout_secs,
            pending_msgs: threads.pending_msgs,
            pending_events: threads.pending_events,
            api_pending: threads.api_pending,
            max_pending_msgs: threads.max_pending_msgs,
            max_pending_events: threads.max_pending_events,
            max_api_pending: threads.max_api_pending,
            reader_threads: threads.reader_threads,
        })
    }

    pub fn set_expiry_enabled(&self, enabled: bool) {
        self.expiry
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
    }

    /// Sends a read-only request to the dedicated reader thread. The
    /// writer-queue counters are not part of the gate: the reader threads
    /// exist so reads keep working while the writer is stalled.
    async fn request_read<R: Default>(&self, make: impl FnOnce(oneshot::Sender<R>) -> Msg) -> R {
        self.request_with_checked(make, &self.read_tx, false).await
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
        self.pending_msgs
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if self.read_tx.send(msg).is_err() {
            // The reader thread's receiver is gone: the relay is shutting
            // down or the thread died. There is no state to load.
            self.pending_msgs
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
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

    /// Read-only request that reports failure (`None`) instead of
    /// degrading to a default value: used by the SIGHUP reloads, where
    /// an empty result would overwrite the live deny/allow lists with
    /// nothing (fail-open).
    async fn request_read_result<R: Default>(
        &self,
        make: impl FnOnce(oneshot::Sender<R>) -> Msg,
    ) -> Option<R> {
        let rx = self.send_request(make, &self.read_tx)?;
        if self.timeout_secs == 0 {
            return rx.await.ok();
        }
        tokio::time::timeout(std::time::Duration::from_secs(self.timeout_secs), rx)
            .await
            .ok()
            .and_then(|r| r.ok())
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
        let Some(rx) = self.send_request(make, &self.tx) else {
            return R::default();
        };
        rx.await.unwrap_or_default()
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
    /// gate also inspects the writer-queue counters (`pending_msgs` /
    /// `pending_events`). Read-only requests on the dedicated reader
    /// channel pass `false`: the whole point of the separate reader threads
    /// is that reads keep working while the writer is stalled, so a
    /// write-backlog must not fail-fast the reads.
    fn send_request_checked<R>(
        &self,
        make: impl FnOnce(oneshot::Sender<R>) -> Msg,
        channel: &mpsc::UnboundedSender<Msg>,
        check_writer: bool,
    ) -> Option<oneshot::Receiver<R>> {
        let writer_stalled = check_writer
            && (self.pending_msgs.load(std::sync::atomic::Ordering::Relaxed)
                >= self.max_pending_msgs
                || self
                    .pending_events
                    .load(std::sync::atomic::Ordering::Relaxed)
                    >= self.max_pending_events);
        if writer_stalled {
            // Surface the overload in the stats (db_errors).
            self.errors
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return None;
        }
        let (tx, rx) = oneshot::channel();
        let msg = make(tx);
        self.pending_msgs
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if let Msg::PutBatch { events, .. } = &msg {
            self.pending_events
                .fetch_add(events.len(), std::sync::atomic::Ordering::Relaxed);
        } else if let Msg::Put { .. } = &msg {
            self.pending_events
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        if let Err(err) = channel.send(msg) {
            let msg = err.0;
            self.pending_msgs
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            if let Msg::PutBatch { events, .. } = &msg {
                self.pending_events
                    .fetch_sub(events.len(), std::sync::atomic::Ordering::Relaxed);
            } else if let Msg::Put { .. } = &msg {
                self.pending_events
                    .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
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
            // report it loudly, and the WebSocket callers that use the
            // reporting variants respond with an error instead.
            _ => {
                log::warn!(
                    "database request timed out after {}s (a query result was dropped)",
                    self.timeout_secs
                );
                R::default()
            }
        }
    }

    pub async fn put(&self, event: Event, now: u64) -> PutOutcome {
        self.request_write(|reply| Msg::Put { event, now, reply })
            .await
    }

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

    /// Like [`Self::query_directed`] but with a much larger scan budget for
    /// the startup rebuilds (NIP-29 group state, NIP-43 role store): they
    /// legitimately walk the whole event history and must not be truncated
    /// by the anti-DoS candidate budget.
    pub async fn query_full(
        &self,
        filters: Vec<Filter>,
        limit: usize,
        now: u64,
    ) -> (Vec<Event>, bool) {
        self.request_read(|reply| Msg::Query {
            filters,
            limit,
            now,
            ascending: false,
            budget: FULL_SCAN_BUDGET,
            hidden_slack: 0,
            reply,
        })
        .await
    }

    /// REST API query: served by the dedicated API reader thread so that
    /// `/api/v1` traffic never blocks WebSocket queries. Applies its own
    /// queue cap: when the API reader's queue is deep, the request fails
    /// fast with an empty result instead of piling up behind WebSocket
    /// work.
    pub async fn api_query(
        &self,
        filters: Vec<Filter>,
        limit: usize,
        now: u64,
        ascending: bool,
    ) -> (Vec<Event>, bool) {
        if self.api_pending.load(std::sync::atomic::Ordering::Relaxed) >= self.max_api_pending {
            self.errors
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return (Vec::new(), false);
        }
        let (tx, rx) = oneshot::channel();
        self.api_pending
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let msg = Msg::Query {
            filters,
            limit,
            now,
            ascending,
            budget: SCAN_BUDGET,
            hidden_slack: 0,
            reply: tx,
        };
        if self.api_read_tx.send(msg).is_err() {
            self.api_pending
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            return (Vec::new(), false);
        }
        let out = if self.timeout_secs == 0 {
            rx.await.unwrap_or_default()
        } else {
            tokio::time::timeout(std::time::Duration::from_secs(self.timeout_secs), rx)
                .await
                .map(|r| r.unwrap_or_default())
                .unwrap_or_default()
        };
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
    ) -> (Vec<Event>, bool) {
        if self.api_pending.load(std::sync::atomic::Ordering::Relaxed) >= self.max_api_pending {
            self.errors
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return (Vec::new(), false);
        }
        let (tx, rx) = oneshot::channel();
        self.api_pending
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let msg = Msg::Count {
            filters,
            limit,
            now,
            reply: tx,
        };
        if self.api_read_tx.send(msg).is_err() {
            self.api_pending
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            return (Vec::new(), false);
        }
        let out = if self.timeout_secs == 0 {
            rx.await.unwrap_or_default()
        } else {
            tokio::time::timeout(std::time::Duration::from_secs(self.timeout_secs), rx)
                .await
                .map(|r| r.unwrap_or_default())
                .unwrap_or_default()
        };
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
        self.request_write(|reply| Msg::PutBatch { events, reply })
            .await
    }

    /// Queues a batch for the writer and returns the reply receiver
    /// without awaiting it: the connection can keep reading frames while
    /// the writer commits, instead of stalling on the commit (and letting
    /// the socket buffer decide the batch size). Returns `None` when the
    /// queue is full (the batch was not queued).
    pub fn put_batch_deferred(
        &self,
        events: Vec<(Event, u64)>,
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

    /// Relay-wide per-kind event counts (REST API).
    pub async fn kind_counts(&self, max_keys: usize) -> (Vec<(u64, u64)>, bool) {
        self.request_read(|reply| Msg::KindCounts { max_keys, reply })
            .await
    }

    /// Relay-wide per-author event counts (REST API).
    pub async fn author_counts(&self, max_keys: usize) -> (AuthorCounts, bool) {
        self.request_read(|reply| Msg::AuthorCounts { max_keys, reply })
            .await
    }

    pub async fn apply_deletion(
        &self,
        targets: Vec<String>,
        addresses: Vec<nip09::Address>,
        request_pubkey: Option<String>,
        request_created: u64,
    ) -> usize {
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
    /// events.
    pub async fn apply_group_deletion(&self, targets: Vec<String>, group: String) -> usize {
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

    /// Every vanished pubkey (raw 32-byte keys). Startup-only use.
    pub async fn vanish_pubkeys(&self) -> Vec<Vec<u8>> {
        self.request_read(|reply| Msg::VanishPubkeys { reply })
            .await
    }

    pub async fn apply_vanish(&self, pubkey: [u8; 32], until_created: u64) -> usize {
        self.request_write(|reply| Msg::Vanish {
            pubkey: pubkey.to_vec(),
            until_created,
            reply,
        })
        .await
    }

    /// NIP-59: deletes `kind:1059` gift wraps p-tagging `pubkey`.
    pub async fn delete_gift_wraps_to(&self, pubkey: [u8; 32]) -> usize {
        self.request_write(|reply| Msg::GiftWrapPurge {
            pubkey: pubkey.to_vec(),
            reply,
        })
        .await
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
    pub async fn save_access(&self, access: crate::config::AccessControl) {
        let _ = self
            .request_write(|reply| Msg::SaveAccess { access, reply })
            .await;
    }

    /// Persists the relay pubkey access lists ((pubkey, reason) pairs for
    /// the deny and allow lists) under their dedicated LMDB key.
    pub async fn save_relay_pubkeys(&self, deny: &[(String, String)], allow: &[(String, String)]) {
        let deny = deny.to_vec();
        let allow = allow.to_vec();
        let _ = self
            .request_write(|reply| Msg::SaveRelayPubkeys { deny, allow, reply })
            .await;
    }

    /// Persists the Blossom upload allowlist under its dedicated LMDB key
    /// (the same key `nostrfy blossom allow/deny` writes).
    pub async fn save_blossom_allow(&self, entries: &[String]) {
        let entries = entries.to_vec();
        let _ = self
            .request_write(|reply| Msg::SaveBlossomAllow { entries, reply })
            .await;
    }

    /// Loads the persisted access control lists, if any.
    /// Loads the persisted access control at startup: waits for the reader
    /// (no timeout, no fail-fast) so a slow database cannot silently
    /// degrade the security state to "empty = allow everyone".
    pub async fn load_access(&self) -> Option<crate::config::AccessControl> {
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
    pub async fn blossom_load(&self, sha256: &str) -> Option<crate::db::store::BlossomMeta> {
        self.request_read(|reply| Msg::BlossomLoad {
            sha256: sha256.to_string(),
            reply,
        })
        .await
    }

    /// Removes one owner from a Blossom blob's persisted metadata.
    pub async fn blossom_remove_owner(&self, sha256: &str, pubkey: &str) -> bool {
        self.request_write(|reply| Msg::BlossomRemoveOwner {
            sha256: sha256.to_string(),
            pubkey: pubkey.to_string(),
            reply,
        })
        .await
    }

    /// Lists the blob hashes uploaded by a pubkey.
    pub async fn blossom_list(&self, pubkey: &str) -> Vec<String> {
        self.request_read(|reply| Msg::BlossomList {
            pubkey: pubkey.to_string(),
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

    pub async fn purge_expired(&self, now: u64) -> usize {
        self.request_write(|reply| Msg::PurgeExpired { now, reply })
            .await
    }

    pub async fn size_on_disk(&self) -> u64 {
        self.request_read(|reply| Msg::DatabaseSize { reply }).await
    }

    /// Current memory map size in bytes (used by tests to verify growth).
    #[cfg(test)]
    pub async fn map_size_now(&self) -> u64 {
        self.request_read(|reply| Msg::MapSize { reply }).await
    }

    pub fn shutdown(&self) {
        let _ = self.tx.send(Msg::Shutdown);
        // One per reader thread (the WebSocket reader pool is shared
        // behind a mutex; each thread consumes one shutdown message).
        for _ in 0..self.reader_threads {
            let _ = self.read_tx.send(Msg::Shutdown);
        }
        let _ = self.api_read_tx.send(Msg::Shutdown);
    }
}
