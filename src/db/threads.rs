//! The dedicated writer and reader threads behind [`super::DbClient`].
//!
//! All LMDB access happens on these two threads: the writer batches event
//! puts into single write transactions (one fsync per batch) and the
//! reader serves queries without ever taking the write lock, so reads keep
//! working even when the writer is stalled.

use std::sync::Arc;

use tokio::sync::{mpsc, oneshot};

use super::store::WriteBatch;
use super::store::{Store, flush_everything};
use super::{LoadAccessOutcome, Msg, PutOutcome, db_error, msg_bytes};
use crate::db::scan::SCAN_BUDGET;
use anyhow::anyhow;

use crate::error::Result;

/// Releases the writer thread's queued-work accounting for one drain.
/// Inline-completed messages release their share via [`Self::release`] right
/// after their arm replied; the remainder (the deferred puts, whose commit
/// is the flush, plus any arm that returned early) is released when the
/// guard drops. The drop happens on every exit path of the drain (including
/// a panic mid-drain), so the overload-protection counters can never be
/// left elevated (which would reject every new request afterwards).
struct PendingGuard {
    msgs: usize,
    events: usize,
    bytes: usize,
    msgs_counter: Arc<std::sync::atomic::AtomicUsize>,
    events_counter: Arc<std::sync::atomic::AtomicUsize>,
    bytes_counter: Arc<std::sync::atomic::AtomicUsize>,
}

impl PendingGuard {
    /// Releases the accounting of one message that completed inline (its
    /// reply was already sent). The guard's remaining fields shrink too, so
    /// [`Drop`] subtracts only what is left, and the shared counters
    /// saturate so a miscount can never wrap them into a permanent
    /// fail-fast.
    fn release(&mut self, msgs: usize, events: usize, bytes: usize) {
        self.msgs = self.msgs.saturating_sub(msgs);
        self.events = self.events.saturating_sub(events);
        self.bytes = self.bytes.saturating_sub(bytes);
        subtract_counter(&self.msgs_counter, msgs);
        subtract_counter(&self.events_counter, events);
        subtract_counter(&self.bytes_counter, bytes);
    }
}

/// Subtracts from a shared queued-work counter without wrapping: an extra
/// subtraction would otherwise leave it near `usize::MAX` and fail-fast
/// every later request for the rest of the process.
fn subtract_counter(counter: &std::sync::atomic::AtomicUsize, value: usize) {
    if value == 0 {
        return;
    }
    let _ = counter.fetch_update(
        std::sync::atomic::Ordering::Relaxed,
        std::sync::atomic::Ordering::Relaxed,
        |current| Some(current.saturating_sub(value)),
    );
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        subtract_counter(&self.msgs_counter, self.msgs);
        subtract_counter(&self.events_counter, self.events);
        subtract_counter(&self.bytes_counter, self.bytes);
    }
}

/// Why a timed receive returned (see [`recv_timeout`]).
pub(crate) enum RecvOutcome<T> {
    Message(T),
    /// The timeout elapsed with no message.
    TimedOut,
    /// Every sender was dropped.
    Closed,
}

/// Blocks for at most `timeout` for the next message, waking immediately
/// when one arrives. The writer thread only needs this when commits skip
/// the fsync: an unbounded `blocking_recv` would sleep through an idle
/// period and leave the committed tail in the page cache until shutdown.
/// Built on `poll_recv` with a waker that unparks this thread, so no
/// runtime is required and new messages keep their normal latency.
pub(crate) fn recv_timeout(
    rx: &mut mpsc::UnboundedReceiver<Msg>,
    timeout: std::time::Duration,
) -> RecvOutcome<Msg> {
    use std::task::{Context, Poll, Wake, Waker};

    struct Unpark(std::thread::Thread);
    impl Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }

    let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match rx.poll_recv(&mut cx) {
            Poll::Ready(Some(msg)) => return RecvOutcome::Message(msg),
            Poll::Ready(None) => return RecvOutcome::Closed,
            Poll::Pending => {
                let now = std::time::Instant::now();
                if now >= deadline {
                    return RecvOutcome::TimedOut;
                }
                std::thread::park_timeout(deadline - now);
            }
        }
    }
}

/// The channels, counters and flags handed to the [`super::DbClient`] by
/// [`spawn`].
pub(crate) struct DbThreads {
    pub(crate) tx: mpsc::UnboundedSender<Msg>,
    /// One channel per reader thread (its receiver is owned by the thread).
    pub(crate) read_txs: Vec<mpsc::UnboundedSender<Msg>>,
    pub(crate) api_read_tx: mpsc::UnboundedSender<Msg>,
    pub(crate) errors: Arc<std::sync::atomic::AtomicU64>,
    /// Cap (overload) fail-fasts since the last drain (see
    /// `DbClient::take_overloads`), shared with the send paths that refuse
    /// a request before it is queued.
    pub(crate) overloads: Arc<std::sync::atomic::AtomicU64>,
    pub(crate) expiry: Arc<std::sync::atomic::AtomicBool>,
    /// Set once at startup when the resumed NIP-09 deletions removed a
    /// NIP-29/NIP-43 state event: the relay must mark its derived state
    /// stale (the persistent state stamp was bumped too, but the direct
    /// fact lets the startup path act without comparing snapshots).
    pub(crate) resumed_deletion_state_removed: Arc<std::sync::atomic::AtomicBool>,
    /// Receives one message when the writer finished its startup recovery
    /// (interrupted vanish/deletion resumes and the outcome flag). The
    /// [`super::DbClient`] constructor waits on it, so the recovery is
    /// complete and observable before the client is handed out. A receive
    /// error means the writer exited during startup.
    pub(crate) recovery_rx: std::sync::mpsc::Receiver<()>,
    pub(crate) timeout_secs: u64,
    pub(crate) pending_msgs: Arc<std::sync::atomic::AtomicUsize>,
    pub(crate) pending_events: Arc<std::sync::atomic::AtomicUsize>,
    pub(crate) pending_reads: Arc<std::sync::atomic::AtomicUsize>,
    pub(crate) api_pending: Arc<std::sync::atomic::AtomicUsize>,
    /// Queued payload bytes on the writer/reader/API queues (see
    /// `DbClient::max_pending_bytes`).
    pub(crate) pending_bytes: Arc<std::sync::atomic::AtomicUsize>,
    pub(crate) pending_read_bytes: Arc<std::sync::atomic::AtomicUsize>,
    pub(crate) api_pending_bytes: Arc<std::sync::atomic::AtomicUsize>,
    pub(crate) max_pending_msgs: usize,
    pub(crate) max_pending_events: usize,
    /// Independent cap for the API reader queue (adjustable live via
    /// [`super::DbClient::set_max_api_pending`], e.g. on SIGHUP reload).
    pub(crate) max_api_pending: Arc<std::sync::atomic::AtomicUsize>,
    /// The spawned database threads, joined by `DbClient::shutdown` after
    /// the Shutdown signals are sent: without the join a queued write could
    /// be dropped with no reply (and the process could exit before the
    /// final flush).
    pub(crate) threads: std::sync::Mutex<Vec<std::thread::JoinHandle<()>>>,
}

/// Serves one read-only message on a dedicated reader thread. Returns
/// `true` when the thread must shut down.
fn handle_read_msg(store: &Store, errors: &Arc<std::sync::atomic::AtomicU64>, msg: Msg) -> bool {
    // Test-only fault injection: the reader's `catch_unwind` recovery and
    // its queued-work counter release are exercised by panicking once here
    // (the caller's reply sender is dropped, so a reporting caller sees a
    // failure instead of a default value).
    #[cfg(test)]
    if store
        .panic_next_read
        .swap(false, std::sync::atomic::Ordering::SeqCst)
    {
        panic!("test-only reader handler fault");
    }
    match msg {
        Msg::VanishPubkeysPage {
            after,
            limit,
            reply,
        } => {
            let page = match store.vanish_pubkeys_page(after.as_deref(), limit) {
                Ok(page) => Some(page),
                Err(e) => {
                    db_error(errors, &e);
                    None
                }
            };
            let _ = reply.send(page);
            false
        }
        Msg::VanishPubkeysRawPage {
            after,
            limit,
            reply,
        } => {
            // Drop the reply on a store error: the checked caller must
            // distinguish a failed page from a genuinely empty one.
            match store.vanish_pubkeys_raw_page(after.as_deref(), limit) {
                Ok(page) => {
                    let _ = reply.send(page);
                }
                Err(e) => db_error(errors, &e),
            }
            false
        }
        Msg::Query {
            filters,
            limit,
            now,
            ascending,
            budget,
            hidden_slack,
            reply,
        } => {
            // Drop the reply sender on a scan error (like `BlossomLoad`):
            // the reporting callers must see `None` instead of an empty
            // successful result, while the unchecked paths keep their
            // default-empty semantics.
            match store.scan(&filters, now, limit, false, ascending, budget, hidden_slack) {
                Ok(out) => {
                    let _ = reply.send(out);
                }
                Err(e) => db_error(errors, &e),
            }
            false
        }
        Msg::NegQuery {
            filter,
            limit,
            now,
            reply,
        } => {
            match store.scan_neg(&filter, now, limit, SCAN_BUDGET) {
                Ok(out) => {
                    let _ = reply.send(out);
                }
                Err(e) => db_error(errors, &e),
            }
            false
        }
        Msg::Count {
            filters,
            limit,
            now,
            reply,
        } => {
            match store.scan(&filters, now, limit, true, false, SCAN_BUDGET, 0) {
                Ok(out) => {
                    let _ = reply.send(out);
                }
                Err(e) => db_error(errors, &e),
            }
            false
        }
        Msg::PrefixExists { prefix, reply } => {
            let exists = match store.event_id_prefix_exists(&prefix) {
                Ok(exists) => exists,
                Err(e) => {
                    db_error(errors, &e);
                    false
                }
            };
            let _ = reply.send(exists);
            false
        }
        Msg::PrefixesExist { prefixes, reply } => {
            let out = match store.prefixes_exist(&prefixes) {
                Ok(out) => out,
                Err(e) => {
                    db_error(errors, &e);
                    vec![false; prefixes.len()]
                }
            };
            let _ = reply.send(out);
            false
        }
        Msg::ListBanned { reply } => {
            let banned = match store.list_banned() {
                Ok(banned) => banned,
                Err(e) => {
                    db_error(errors, &e);
                    Vec::new()
                }
            };
            let _ = reply.send(banned);
            false
        }
        Msg::AggregateSample { limit, now, reply } => {
            match store.scan_neg(&crate::filter::Filter::default(), now, limit, SCAN_BUDGET) {
                Ok(out) => {
                    let _ = reply.send(Some(out));
                }
                Err(e) => db_error(errors, &e),
            }
            false
        }
        Msg::LoadAccess { reply } => {
            let outcome = match store.load_access() {
                Ok(Some(access)) => LoadAccessOutcome::Loaded(access),
                Ok(None) => LoadAccessOutcome::Missing,
                Err(e) => {
                    db_error(errors, &e);
                    LoadAccessOutcome::Failed
                }
            };
            let _ = reply.send(outcome);
            false
        }
        Msg::LoadBlossomAllow { reply } => {
            let list = match store.load_blossom_allow() {
                Ok(list) => Some(list),
                Err(e) => {
                    db_error(errors, &e);
                    None
                }
            };
            let _ = reply.send(list);
            false
        }
        Msg::LoadRelayPubkeys { reply } => {
            let lists = match store.load_relay_pubkeys() {
                Ok(lists) => Some(lists),
                Err(e) => {
                    db_error(errors, &e);
                    None
                }
            };
            let _ = reply.send(lists);
            false
        }
        Msg::LoadGroups { reply } => {
            // `Ok(None)` means no snapshot was ever written (pre-persistence
            // database): the caller runs the replay migration. An `Err`
            // also yields `None`, and the caller treats it the same way —
            // but logs the failure so a corrupt snapshot is visible.
            // (A corrupt snapshot replays history, which is fail-closed:
            // tombstones rebuild from surviving events.)
            let snap = match store.load_groups() {
                Ok(snap) => snap,
                Err(e) => {
                    db_error(errors, &e);
                    None
                }
            };
            let _ = reply.send(snap);
            false
        }
        Msg::LoadRoles { reply } => {
            let snap = match store.load_roles() {
                Ok(snap) => snap,
                Err(e) => {
                    db_error(errors, &e);
                    None
                }
            };
            let _ = reply.send(snap);
            false
        }
        Msg::BlossomLoad { sha256, reply } => {
            // A store error must not be reported as "no mapping": dropping
            // the reply sender makes reporting callers (`request_read_result`
            // / `blossom_load_checked`) see a failure, while the unchecked
            // `blossom_load` path keeps its default-None semantics.
            match store.load_blossom_mapping(&sha256) {
                Ok(meta) => {
                    let _ = reply.send(meta);
                }
                Err(e) => db_error(errors, &e),
            }
            false
        }
        #[cfg(test)]
        Msg::BlossomList {
            pubkey,
            limit,
            reply,
        } => {
            let shas = match store.list_blossom_shas(&pubkey, limit) {
                Ok(shas) => shas,
                Err(e) => {
                    db_error(errors, &e);
                    Vec::new()
                }
            };
            let _ = reply.send(shas);
            false
        }
        Msg::BlossomListPage {
            pubkey,
            after_uploaded,
            after_sha,
            limit,
            reply,
        } => {
            match store.list_blossom_page(&pubkey, after_uploaded, after_sha.as_deref(), limit) {
                Ok(page) => {
                    let _ = reply.send(page);
                }
                // Drop the reply on a store error (like `BlossomLoad`): the
                // checked caller must be able to distinguish a failed page
                // read from a genuinely empty page instead of reporting an
                // existing inventory as empty.
                Err(e) => db_error(errors, &e),
            }
            false
        }
        Msg::BlossomMigrationDone { reply } => {
            let done = match store.blossom_migration_done() {
                Ok(done) => done,
                Err(e) => {
                    db_error(errors, &e);
                    false
                }
            };
            let _ = reply.send(done);
            false
        }
        Msg::FirstSeenStatus { pubkeys, reply } => {
            let rtxn = match store.env.read_txn() {
                Ok(rtxn) => rtxn,
                Err(e) => {
                    db_error(errors, &e.into());
                    let _ = reply.send(vec![(false, u64::MAX); pubkeys.len()]);
                    return false;
                }
            };
            let mut out = Vec::with_capacity(pubkeys.len());
            for pk in pubkeys {
                match store.first_seen_status(&rtxn, &pk) {
                    Ok(status) => out.push(status),
                    Err(e) => {
                        db_error(errors, &e);
                        // Fail closed: treat the pubkey as too young.
                        out.push((false, u64::MAX));
                    }
                }
            }
            let _ = reply.send(out);
            false
        }
        Msg::DatabaseSize { reply } => {
            let _ = reply.send(store.size_on_disk());
            false
        }
        Msg::VanishCounts { reply } => {
            let counts = match store.vanish_counts() {
                Ok(counts) => Some(counts),
                Err(e) => {
                    db_error(errors, &e);
                    None
                }
            };
            let _ = reply.send(counts);
            false
        }
        Msg::PendingPurges { reply } => {
            // A failed read sends `None`: the caller fails closed instead
            // of treating an unreadable table as "no pending purges".
            let pending = match store.pending_purges() {
                Ok(pending) => Some(pending),
                Err(e) => {
                    db_error(errors, &e);
                    None
                }
            };
            let _ = reply.send(pending);
            false
        }
        Msg::PendingDeletions { reply } => {
            // See `PendingPurges`: an unreadable table must not read as
            // "no deletions to resume".
            let pending = match store.pending_deletions() {
                Ok(pending) => Some(pending),
                Err(e) => {
                    db_error(errors, &e);
                    None
                }
            };
            let _ = reply.send(pending);
            false
        }
        Msg::TableCounts { reply } => {
            let counts = match store.table_counts() {
                Ok(counts) => Some(counts),
                Err(e) => {
                    db_error(errors, &e);
                    None
                }
            };
            let _ = reply.send(counts);
            false
        }
        Msg::StateStamp { reply } => {
            let stamp = match store.state_stamp() {
                Ok(stamp) => Some(stamp),
                Err(e) => {
                    db_error(errors, &e);
                    None
                }
            };
            let _ = reply.send(stamp);
            false
        }
        Msg::StateSeq { reply } => {
            let seq = match store.state_seq() {
                Ok(seq) => Some(seq),
                Err(e) => {
                    db_error(errors, &e);
                    None
                }
            };
            let _ = reply.send(seq);
            false
        }
        Msg::StateSeqGroup { reply } => {
            let seq = match store.state_seq_group() {
                Ok(seq) => Some(seq),
                Err(e) => {
                    db_error(errors, &e);
                    None
                }
            };
            let _ = reply.send(seq);
            false
        }
        Msg::StateSeqRole { reply } => {
            let seq = match store.state_seq_role() {
                Ok(seq) => Some(seq),
                Err(e) => {
                    db_error(errors, &e);
                    None
                }
            };
            let _ = reply.send(seq);
            false
        }
        #[cfg(test)]
        Msg::LastPage { reply } => {
            let _ = reply.send(store.env.info().last_page_number as u64);
            false
        }
        Msg::Shutdown => true,
        _ => unreachable!("read channel received a write message"),
    }
}

pub(crate) fn spawn(
    store: Store,
    expiry: Arc<std::sync::atomic::AtomicBool>,
    errors: Arc<std::sync::atomic::AtomicU64>,
    request_timeout_secs: u64,
    max_pending_msgs: usize,
    max_pending_events: usize,
    reader_threads: usize,
) -> Result<DbThreads> {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut read_txs: Vec<mpsc::UnboundedSender<Msg>> = Vec::with_capacity(reader_threads);
    let (api_read_tx, mut api_read_rx) = mpsc::unbounded_channel();
    let thread_errors = Arc::clone(&errors);
    // Cap fail-fasts, counted by the send paths and drained by the stats
    // writer (see `DbClient::take_overloads`).
    let overloads = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let pending_msgs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let pending_events = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let pending_reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let thread_pending_msgs = Arc::clone(&pending_msgs);
    let thread_pending_events = Arc::clone(&pending_events);
    let thread_pending_reads = Arc::clone(&pending_reads);
    let read_pending = Arc::clone(&pending_reads);
    let api_pending = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let api_thread_pending = Arc::clone(&api_pending);
    let pending_bytes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let thread_pending_bytes = Arc::clone(&pending_bytes);
    let pending_read_bytes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let read_pending_bytes = Arc::clone(&pending_read_bytes);
    let api_pending_bytes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let api_pending_bytes_thread = Arc::clone(&api_pending_bytes);
    // Set by the writer's startup resume of interrupted NIP-09 deletions
    // (see `DbThreads::resumed_deletion_state_removed`).
    let resumed_deletion_state_removed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let thread_resumed_deletion_state_removed = Arc::clone(&resumed_deletion_state_removed);
    // The writer signals once its startup recovery finished; the client
    // constructor waits here (see `DbThreads::recovery_rx`).
    let (recovery_tx, recovery_rx) = std::sync::mpsc::channel::<()>();
    // Dedicated reader threads: serve Query/Count/NEG and the small
    // lookups without ever taking the LMDB write lock. Two threads share
    // the channel (the receiver behind a mutex; each thread holds the
    // lock only for the blocking recv, so a long scan on one thread does
    // not stall the next query on the other), so a single heavy REQ no
    // longer blocks every other subscriber's query. LMDB allows many
    // concurrent read transactions, so the threads read the same data
    // safely.
    let mut handles: Vec<std::thread::JoinHandle<()>> = Vec::with_capacity(reader_threads + 2);
    {
        for _ in 0..reader_threads {
            // Each reader owns its receiver: sharing one behind a Mutex let a
            // worker that held the lock in `blocking_recv` block every other
            // worker from picking up work (audit L7).
            let (read_tx, mut read_rx) = mpsc::unbounded_channel();
            read_txs.push(read_tx);
            let read_store = store.clone_for_reader();
            let read_errors = Arc::clone(&errors);
            let read_pending = Arc::clone(&read_pending);
            let read_pending_bytes = Arc::clone(&read_pending_bytes);
            handles.push(std::thread::spawn(move || {
                'reader: loop {
                    let Some(msg) = read_rx.blocking_recv() else {
                        break;
                    };
                    // `Msg::Shutdown` is never counted: a panic while
                    // handling it must not decrement either (that would
                    // wrap the counter to `usize::MAX` and fail-fast every
                    // later read forever).
                    let is_shutdown = matches!(msg, Msg::Shutdown);
                    let bytes = msg_bytes(&msg);
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let shutdown = handle_read_msg(&read_store, &read_errors, msg);
                        // `Msg::Shutdown` is sent directly (never through
                        // `request_read`), so it was not counted;
                        // decrementing for it would underflow the pending
                        // counter.
                        if !shutdown {
                            read_pending.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                            if bytes > 0 {
                                read_pending_bytes
                                    .fetch_sub(bytes, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                        shutdown
                    }));
                    match result {
                        Ok(true) => break 'reader,
                        Ok(false) => {}
                        Err(_) => {
                            log::error!("reader thread recovered from a panic");
                            if !is_shutdown {
                                read_pending.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                                if bytes > 0 {
                                    read_pending_bytes
                                        .fetch_sub(bytes, std::sync::atomic::Ordering::Relaxed);
                                }
                            }
                        }
                    }
                }
            }));
        }
    }
    // Dedicated REST API reader thread: serves `/api/v1` queries on its own
    // queue so an API flood can never queue behind (or in front of)
    // WebSocket queries on the shared reader thread. LMDB allows many
    // concurrent readers, so both threads read the same data safely.
    {
        let api_store = store.clone_for_reader();
        let api_errors = Arc::clone(&errors);
        handles.push(std::thread::spawn(move || {
            'api_reader: loop {
                let Some(msg) = api_read_rx.blocking_recv() else {
                    break;
                };
                // See the reader thread above: never decrement for an
                // uncounted `Shutdown`.
                let is_shutdown = matches!(msg, Msg::Shutdown);
                let bytes = msg_bytes(&msg);
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let shutdown = handle_read_msg(&api_store, &api_errors, msg);
                    // `Msg::Shutdown` is not counted (see the reader thread).
                    if !shutdown {
                        api_thread_pending.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                        if bytes > 0 {
                            api_pending_bytes_thread
                                .fetch_sub(bytes, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                    shutdown
                }));
                match result {
                    Ok(true) => break 'api_reader,
                    Ok(false) => {}
                    Err(_) => {
                        log::error!("api reader thread recovered from a panic");
                        if !is_shutdown {
                            api_thread_pending.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                            if bytes > 0 {
                                api_pending_bytes_thread
                                    .fetch_sub(bytes, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                    }
                }
            }
        }));
    }
    handles.push(std::thread::spawn(move || {
        // The recovery prelude runs first, before the long index rebuilds:
        // `DbClient::open` waits for `recovery_tx` (see `recovery_rx`), so
        // the server's startup state restore observes the completed
        // recovery and its stale-state flag without racing this thread.
        //
        // One-time backfill of the NIP-59 gift-wrap recipient index: an
        // older database has the wraps but no recipient entries, and the
        // vanish resume below drops the wraps addressed to a vanished
        // pubkey through that index.
        match store.gift_wrap_index_needs_rebuild() {
            Ok(true) => match store.rebuild_gift_wrap_index() {
                Ok(n) => log::info!("gift-wrap recipient index rebuilt ({n} recipients)"),
                Err(e) => log::warn!("gift-wrap recipient index rebuild failed: {e}"),
            },
            Ok(false) => {}
            Err(e) => log::warn!("gift-wrap recipient index check failed: {e}"),
        }
        // Resume interrupted NIP-62 vanishes before serving any message: a
        // crash or store error mid-walk left the pending record, and the
        // remaining events must not stay visible once the relay opens. This
        // runs on the writer thread (the single writer) before the drain
        // loop, so no put can interleave and no `DbClient` round trip is
        // needed (which would deadlock the writer against itself).
        let resumed = store.resume_pending_vanishes(&thread_errors);
        if resumed > 0 {
            log::info!("resumed {resumed} interrupted vanish request(s)");
        }
        // Resume interrupted NIP-09 deletions before serving any message
        // (same reasoning as the vanish resume): a crash mid-walk left the
        // request record, and the half-applied deletion must be completed
        // before the relay opens. A resumed deletion that removed
        // NIP-29/NIP-43 state publishes the fact for the startup path.
        let (resumed_deletions, deletion_state_removed) =
            store.resume_pending_deletions(&thread_errors);
        if resumed_deletions > 0 {
            log::info!("resumed {resumed_deletions} interrupted deletion request(s)");
        }
        thread_resumed_deletion_state_removed
            .store(deletion_state_removed, std::sync::atomic::Ordering::SeqCst);
        // Recovery is complete and its outcome is visible: release the
        // `DbClient::open` barrier. A send failure only means the client
        // was never built (the receiver is dropped), which is harmless.
        let _ = recovery_tx.send(());
        // One-time rebuild of the lightweight metadata index: an older
        // database has events but no meta entries. The rebuild runs on
        // the writer thread before any puts (the single-writer lock is
        // otherwise idle at startup); scans fall back to the full JSON
        // parse until it completes.
        match store.meta_needs_rebuild() {
            Ok(true) => match store.rebuild_event_meta() {
                Ok(n) => log::info!("event metadata index rebuilt ({n} events)"),
                Err(e) => db_error(&thread_errors, &e),
            },
            Ok(false) => {}
            Err(e) => {
                // A failed check must not silently skip the rebuild (that
                // would keep serving a database with a missing meta index):
                // report it and attempt the rebuild anyway.
                db_error(&thread_errors, &e);
                match store.rebuild_event_meta() {
                    Ok(n) => log::info!("event metadata index rebuilt ({n} events)"),
                    Err(e) => db_error(&thread_errors, &e),
                }
            }
        }
        // One-time backfill of the Blossom uploaded-order index (BUD-12
        // paging): databases written before the index existed page from
        // their sha-ordered reverse index, which hid every blob past the
        // scan window.
        match store.blossom_order_needs_rebuild() {
            Ok(true) => match store.rebuild_blossom_order() {
                Ok(n) => log::info!("blossom uploaded-order index rebuilt ({n} owners)"),
                Err(e) => db_error(&thread_errors, &e),
            },
            Ok(false) => {}
            Err(e) => db_error(&thread_errors, &e),
        }
        // Puts are applied in batches sharing one write transaction so
        // that the LMDB commit cost (a full fsync by default) is paid
        // once per batch instead of once per event. Replies are only
        // sent after the commit, so an OK implies durability.
        const BATCH: usize = 64;
        // With fsync disabled, commits land in the OS page cache: sync at
        // most once per interval so a crash loses only a small tail. The
        // default (fsync enabled) keeps the plain blocking receive.
        const SYNC_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
        let mut next_sync = std::time::Instant::now() + SYNC_INTERVAL;
        // Put batches received within the current message drain are merged
        // into a single commit at flush time.
        let mut batch = WriteBatch::default();
        'outer: loop {
            // The periodic sync must fire even under a sustained message
            // stream, where the timed receive below always finds work.
            if store.disabled_fsync && std::time::Instant::now() >= next_sync {
                // Best effort: a failed sync is reported but does not stop
                // the writer (the next tick retries).
                if let Err(e) = store.env.force_sync() {
                    db_error(&thread_errors, &e.into());
                }
                next_sync = std::time::Instant::now() + SYNC_INTERVAL;
            }
            let msg = if store.disabled_fsync {
                match recv_timeout(
                    &mut rx,
                    next_sync.saturating_duration_since(std::time::Instant::now()),
                ) {
                    RecvOutcome::Message(msg) => Some(msg),
                    // The deadline passed while waiting: sync at the top of
                    // the next iteration (a message that arrived at the same
                    // moment was returned instead and is not delayed).
                    RecvOutcome::TimedOut => continue 'outer,
                    RecvOutcome::Closed => None,
                }
            } else {
                rx.blocking_recv()
            };
            let Some(msg) = msg else {
                // The channel is closed (every DbClient was dropped
                // without a shutdown): flush any pending batch so that
                // awaiting requests are not left hanging.
                flush_everything(&store, &thread_errors, &mut batch);
                break;
            };
            // The database thread is the single point of failure for
            // every request: a panic here would hang all clients, so
            // the whole batch handling is isolated. After a panic (which
            // the code audit makes unreachable) the state is reset and
            // the thread keeps serving.
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut msgs = vec![msg];
                for _ in 0..BATCH - 1 {
                    match rx.try_recv() {
                        Ok(m) => msgs.push(m),
                        Err(_) => break,
                    }
                }

                let drained_msgs: usize = msgs
                    .iter()
                    // `Msg::Shutdown` is sent directly (never through
                    // `request`), so it was not counted in `pending_msgs`;
                    // counting it here would underflow the counter.
                    .filter(|m| !matches!(m, Msg::Shutdown))
                    .count();
                let drained_events: usize = msgs
                    .iter()
                    .map(|m| match m {
                        Msg::PutBatch { events, .. } => events.len(),
                        Msg::Put { .. } => 1,
                        _ => 0,
                    })
                    .sum();
                // The payload bytes reserved by the senders (0 for the
                // metadata-only messages, which the count caps bound).
                let drained_bytes: usize = msgs.iter().map(msg_bytes).sum();
                // The drain's queued-work accounting. Messages whose arm
                // replies inline release their share right after that arm
                // (see the loop), so a caller woken by such a reply no
                // longer sees its message counted; the deferred puts stay
                // accounted until the pre-flush drop below. The guard drops
                // on every exit path of the drain (including a panic
                // mid-drain), so the overload-protection counters can never
                // be left elevated.
                let mut pending = PendingGuard {
                    msgs: drained_msgs,
                    events: drained_events,
                    bytes: drained_bytes,
                    msgs_counter: Arc::clone(&thread_pending_msgs),
                    events_counter: Arc::clone(&thread_pending_events),
                    bytes_counter: Arc::clone(&thread_pending_bytes),
                };
                // Coalesce state snapshots within one drain: each write
                // clones and serializes the whole group/role state, but only
                // the newest snapshot in the drain is observable. Earlier
                // ones still get their reply (the mutation is durable via
                // the newest write).
                let last_groups = msgs
                    .iter()
                    .rposition(|m| matches!(m, Msg::SaveGroups { .. }));
                let last_roles = msgs
                    .iter()
                    .rposition(|m| matches!(m, Msg::SaveRoles { .. }));
                // Replies of the snapshots coalesced into the newest one:
                // they are answered with the newest commit's outcome, so an
                // earlier caller never reports durability the newest commit
                // did not establish (and never sees a false failure when the
                // newest write covered its mutation).
                let mut coalesced_group_replies: Vec<oneshot::Sender<bool>> = Vec::new();
                let mut coalesced_role_replies: Vec<oneshot::Sender<bool>> = Vec::new();
                for (msg_index, msg) in msgs.into_iter().enumerate() {
                    // This message's share of the drain accounting, computed
                    // before the match consumes it. `Put`/`PutBatch` keep
                    // their share until the pre-flush drop (their commit *is*
                    // the flush); every other arm releases it as soon as its
                    // reply was sent. `Msg::Shutdown` is not counted (see the
                    // drain accounting above).
                    let deferred = matches!(msg, Msg::Put { .. } | Msg::PutBatch { .. });
                    let accounted_msgs = if matches!(msg, Msg::Shutdown) { 0 } else { 1 };
                    let accounted_events = match &msg {
                        Msg::PutBatch { events, .. } => events.len(),
                        Msg::Put { .. } => 1,
                        _ => 0,
                    };
                    let accounted_bytes = msg_bytes(&msg);
                    match msg {
                        Msg::Put {
                            event,
                            now,
                            first_seen,
                            reply,
                        } => {
                            if batch.pending.is_none() {
                                match store.env.write_txn() {
                                    Ok(txn) => batch.pending = Some(txn),
                                    Err(e) => {
                                        db_error(&thread_errors, &e.into());
                                        let _ = reply
                                            .send(PutOutcome::Invalid("database error".into()));
                                        continue;
                                    }
                                }
                            }
                            batch.puts.push((event, now));
                            batch.first_seen.push(first_seen);
                            batch.senders.push(reply);
                            // Test-only fault injection: panic once *after*
                            // the put joined the batch, so the recovery's
                            // reply revocation (the batch is rolled back
                            // with the transaction) and the `PendingGuard`
                            // counter release are both exercised.
                            #[cfg(test)]
                            if store
                                .panic_next_write
                                .swap(false, std::sync::atomic::Ordering::SeqCst)
                            {
                                panic!("test-only writer handler fault");
                            }
                        }
                        Msg::PutBatch { events, reply } => {
                            batch.pending_batches.push((events, reply));
                        }
                        Msg::Shutdown => {
                            flush_everything(&store, &thread_errors, &mut batch);
                            // The shutdown sync is the last chance to flush
                            // with fsync disabled: a failure must be
                            // reported, not swallowed.
                            if let Err(e) = store.env.force_sync() {
                                db_error(&thread_errors, &e.into());
                            }
                            return true;
                        }
                        other => {
                            // Work that is not a plain put commits the
                            // batch first so that ordering is preserved.
                            flush_everything(&store, &thread_errors, &mut batch);
                            match other {
                                // A read-only list request can only arrive
                                // on the reader channel; this arm keeps the
                                // writer's match exhaustive.
                                Msg::VanishPubkeysPage {
                                    after,
                                    limit,
                                    reply,
                                } => {
                                    let page =
                                        match store.vanish_pubkeys_page(after.as_deref(), limit) {
                                            Ok(page) => Some(page),
                                            Err(e) => {
                                                db_error(&thread_errors, &e);
                                                None
                                            }
                                        };
                                    let _ = reply.send(page);
                                }
                                Msg::VanishPubkeysRawPage {
                                    after,
                                    limit,
                                    reply,
                                } => match store.vanish_pubkeys_raw_page(after.as_deref(), limit) {
                                    Ok(page) => {
                                        let _ = reply.send(page);
                                    }
                                    Err(e) => db_error(&thread_errors, &e),
                                },
                                Msg::BlossomMigrationDone { reply } => {
                                    let done = match store.blossom_migration_done() {
                                        Ok(done) => done,
                                        Err(e) => {
                                            db_error(&thread_errors, &e);
                                            false
                                        }
                                    };
                                    let _ = reply.send(done);
                                }
                                Msg::BlossomLoad { sha256, reply } => {
                                    // See the reader arm: drop the reply
                                    // sender on a store error instead of
                                    // sending `None` (which would conflate
                                    // failure with "no mapping").
                                    match store.load_blossom_mapping(&sha256) {
                                        Ok(meta) => {
                                            let _ = reply.send(meta);
                                        }
                                        Err(e) => db_error(&thread_errors, &e),
                                    }
                                }
                                Msg::BlossomListPage {
                                    pubkey,
                                    after_uploaded,
                                    after_sha,
                                    limit,
                                    reply,
                                } => {
                                    match store.list_blossom_page(
                                        &pubkey,
                                        after_uploaded,
                                        after_sha.as_deref(),
                                        limit,
                                    ) {
                                        Ok(page) => {
                                            let _ = reply.send(page);
                                        }
                                        // Drop the reply on error: the checked
                                        // caller must see a failure, not an
                                        // empty inventory (see the reader arm).
                                        Err(e) => db_error(&thread_errors, &e),
                                    }
                                }
                                #[cfg(test)]
                                Msg::BlossomList {
                                    pubkey,
                                    limit,
                                    reply,
                                } => {
                                    let shas = match store.list_blossom_shas(&pubkey, limit) {
                                        Ok(shas) => shas,
                                        Err(e) => {
                                            db_error(&thread_errors, &e);
                                            Vec::new()
                                        }
                                    };
                                    let _ = reply.send(shas);
                                }
                                Msg::LoadBlossomAllow { reply } => {
                                    let list = match store.load_blossom_allow() {
                                        Ok(list) => Some(list),
                                        Err(e) => {
                                            db_error(&thread_errors, &e);
                                            None
                                        }
                                    };
                                    let _ = reply.send(list);
                                }
                                Msg::LoadRelayPubkeys { reply } => {
                                    let lists = match store.load_relay_pubkeys() {
                                        Ok(lists) => Some(lists),
                                        Err(e) => {
                                            db_error(&thread_errors, &e);
                                            None
                                        }
                                    };
                                    let _ = reply.send(lists);
                                }
                                Msg::LoadGroups { reply } => {
                                    let snap = match store.load_groups() {
                                        Ok(snap) => snap,
                                        Err(e) => {
                                            db_error(&thread_errors, &e);
                                            None
                                        }
                                    };
                                    let _ = reply.send(snap);
                                }
                                Msg::LoadRoles { reply } => {
                                    let snap = match store.load_roles() {
                                        Ok(snap) => snap,
                                        Err(e) => {
                                            db_error(&thread_errors, &e);
                                            None
                                        }
                                    };
                                    let _ = reply.send(snap);
                                }
                                Msg::Query {
                                    filters,
                                    limit,
                                    now,
                                    ascending,
                                    budget,
                                    hidden_slack,
                                    reply,
                                } => {
                                    // See the reader arm: drop the reply on a
                                    // scan error so the reporting callers
                                    // see `None`, not an empty success.
                                    match store.scan(
                                        &filters,
                                        now,
                                        limit,
                                        false,
                                        ascending,
                                        budget,
                                        hidden_slack,
                                    ) {
                                        Ok(out) => {
                                            let _ = reply.send(out);
                                        }
                                        Err(e) => db_error(&thread_errors, &e),
                                    }
                                }
                                Msg::NegQuery {
                                    filter,
                                    limit,
                                    now,
                                    reply,
                                } => match store.scan_neg(&filter, now, limit, SCAN_BUDGET) {
                                    Ok(out) => {
                                        let _ = reply.send(out);
                                    }
                                    Err(e) => db_error(&thread_errors, &e),
                                },
                                Msg::Count {
                                    filters,
                                    limit,
                                    now,
                                    reply,
                                } => {
                                    match store.scan(
                                        &filters,
                                        now,
                                        limit,
                                        true,
                                        false,
                                        SCAN_BUDGET,
                                        0,
                                    ) {
                                        Ok(out) => {
                                            let _ = reply.send(out);
                                        }
                                        Err(e) => db_error(&thread_errors, &e),
                                    }
                                }
                                Msg::AggregateSample { limit, now, reply } => {
                                    match store.scan_neg(
                                        &crate::filter::Filter::default(),
                                        now,
                                        limit,
                                        SCAN_BUDGET,
                                    ) {
                                        Ok(out) => {
                                            let _ = reply.send(Some(out));
                                        }
                                        Err(e) => db_error(&thread_errors, &e),
                                    }
                                }
                                Msg::Delete {
                                    targets,
                                    addresses,
                                    request_pubkey,
                                    request_created,
                                    group,
                                    reply,
                                } => {
                                    // A failed walk replies `None` so the
                                    // checked callers see the failure
                                    // instead of an indistinguishable zero.
                                    // The second element always reports
                                    // whether a group/role-state event was
                                    // removed: a later failed chunk must
                                    // still let the caller mark the derived
                                    // state stale.
                                    let report = store.apply_deletion_group(
                                        &targets,
                                        &addresses,
                                        request_pubkey.as_deref(),
                                        request_created,
                                        group.as_deref(),
                                    );
                                    if let Some(e) = &report.error {
                                        db_error(&thread_errors, e);
                                    }
                                    let _ = reply.send((
                                        report.checked_removed(),
                                        report.group_state_removed,
                                    ));
                                }
                                Msg::GroupPurge { group, now, reply } => {
                                    let n = match store.purge_group(&group, now) {
                                        Ok(n) => n,
                                        Err(e) => {
                                            db_error(&thread_errors, &e);
                                            0
                                        }
                                    };
                                    let _ = reply.send(n);
                                }
                                Msg::Vanish {
                                    pubkey,
                                    until_created,
                                    reply,
                                } => {
                                    // A failed walk replies `None`: no marker
                                    // was written, so the checked caller must
                                    // not report the vanish as applied.
                                    let outcome = match store.apply_vanish(&pubkey, until_created) {
                                        Ok(outcome) => Some(outcome),
                                        Err(e) => {
                                            db_error(&thread_errors, &e);
                                            None
                                        }
                                    };
                                    let _ = reply.send(outcome);
                                }
                                Msg::GiftWrapPurge { pubkey, reply } => {
                                    let n = match store.delete_gift_wraps_to(&pubkey) {
                                        Ok(n) => Some(n),
                                        Err(e) => {
                                            db_error(&thread_errors, &e);
                                            None
                                        }
                                    };
                                    let _ = reply.send(n);
                                }
                                Msg::PrefixExists { prefix, reply } => {
                                    let exists = match store.event_id_prefix_exists(&prefix) {
                                        Ok(exists) => exists,
                                        Err(e) => {
                                            db_error(&thread_errors, &e);
                                            false
                                        }
                                    };
                                    let _ = reply.send(exists);
                                }
                                Msg::PrefixesExist { prefixes, reply } => {
                                    let out = match store.prefixes_exist(&prefixes) {
                                        Ok(out) => out,
                                        Err(e) => {
                                            db_error(&thread_errors, &e);
                                            vec![false; prefixes.len()]
                                        }
                                    };
                                    let _ = reply.send(out);
                                }
                                Msg::Ban { id, reason, reply } => {
                                    let banned = match store.apply_ban(&id, &reason) {
                                        Ok(banned) => banned,
                                        Err(e) => {
                                            db_error(&thread_errors, &e);
                                            false
                                        }
                                    };
                                    let _ = reply.send(banned);
                                }
                                Msg::Unban { id, reply } => {
                                    let unbanned = match store.apply_unban(&id) {
                                        Ok(unbanned) => unbanned,
                                        Err(e) => {
                                            db_error(&thread_errors, &e);
                                            false
                                        }
                                    };
                                    let _ = reply.send(unbanned);
                                }
                                Msg::ListBanned { reply } => {
                                    let banned = match store.list_banned() {
                                        Ok(banned) => banned,
                                        Err(e) => {
                                            db_error(&thread_errors, &e);
                                            Vec::new()
                                        }
                                    };
                                    let _ = reply.send(banned);
                                }
                                Msg::SaveAccess { access, reply } => {
                                    let ok = match store.save_access(&access) {
                                        Ok(()) => true,
                                        Err(e) => {
                                            db_error(&thread_errors, &e);
                                            false
                                        }
                                    };
                                    let _ = reply.send(ok);
                                }
                                Msg::SaveRelayPubkeys { deny, allow, reply } => {
                                    let ok = match store.save_relay_pubkeys(&deny, &allow) {
                                        Ok(()) => true,
                                        Err(e) => {
                                            db_error(&thread_errors, &e);
                                            false
                                        }
                                    };
                                    let _ = reply.send(ok);
                                }
                                Msg::SaveAccessAndPubkeys {
                                    access,
                                    deny,
                                    allow,
                                    reply,
                                } => {
                                    let ok = match store
                                        .save_access_and_pubkeys(&access, &deny, &allow)
                                    {
                                        Ok(()) => true,
                                        Err(e) => {
                                            db_error(&thread_errors, &e);
                                            false
                                        }
                                    };
                                    let _ = reply.send(ok);
                                }
                                Msg::SaveBlossomAllow { entries, reply } => {
                                    let ok = match store.save_blossom_allow(&entries) {
                                        Ok(()) => true,
                                        Err(e) => {
                                            db_error(&thread_errors, &e);
                                            false
                                        }
                                    };
                                    let _ = reply.send(ok);
                                }
                                Msg::SaveGroups { snapshot, reply } => {
                                    if Some(msg_index) == last_groups {
                                        let ok = match store.save_groups(&snapshot) {
                                            Ok(()) => true,
                                            Err(e) => {
                                                db_error(&thread_errors, &e);
                                                false
                                            }
                                        };
                                        for earlier in coalesced_group_replies.drain(..) {
                                            let _ = earlier.send(ok);
                                        }
                                        let _ = reply.send(ok);
                                    } else {
                                        coalesced_group_replies.push(reply);
                                    }
                                }
                                Msg::SaveRoles { snapshot, reply } => {
                                    if Some(msg_index) == last_roles {
                                        let ok = match store.save_roles(&snapshot) {
                                            Ok(()) => true,
                                            Err(e) => {
                                                db_error(&thread_errors, &e);
                                                false
                                            }
                                        };
                                        for earlier in coalesced_role_replies.drain(..) {
                                            let _ = earlier.send(ok);
                                        }
                                        let _ = reply.send(ok);
                                    } else {
                                        coalesced_role_replies.push(reply);
                                    }
                                }
                                Msg::ClearGroupsSnapshot { reply } => {
                                    let ok = match store.clear_groups_snapshot() {
                                        Ok(()) => true,
                                        Err(e) => {
                                            db_error(&thread_errors, &e);
                                            false
                                        }
                                    };
                                    let _ = reply.send(ok);
                                }
                                Msg::BlossomAddOwner {
                                    sha256,
                                    mime,
                                    size,
                                    uploaded,
                                    pubkey,
                                    reply,
                                } => {
                                    let ok = store
                                        .add_blossom_mapping(
                                            &sha256, &mime, size, uploaded, &pubkey,
                                        )
                                        .is_ok();
                                    if !ok {
                                        db_error(
                                            &thread_errors,
                                            &anyhow!("blossom mapping write failed"),
                                        );
                                    }
                                    let _ = reply.send(ok);
                                }
                                Msg::BlossomRemoveOwner {
                                    sha256,
                                    pubkey,
                                    reply,
                                } => {
                                    let removed = match store.remove_blossom_owner(&sha256, &pubkey)
                                    {
                                        Ok(removed) => (removed, true),
                                        Err(e) => {
                                            db_error(&thread_errors, &e);
                                            (false, false)
                                        }
                                    };
                                    let _ = reply.send(removed);
                                }
                                Msg::BlossomAddMappings { entries, reply } => {
                                    let ok = store.add_blossom_mappings(&entries).is_ok();
                                    if !ok {
                                        db_error(
                                            &thread_errors,
                                            &anyhow!("blossom migration batch failed"),
                                        );
                                    }
                                    let _ = reply.send(ok);
                                }
                                Msg::BlossomMarkMigration { reply } => {
                                    if let Err(e) = store.mark_blossom_migration() {
                                        db_error(&thread_errors, &e);
                                    }
                                    let _ = reply.send(());
                                }
                                Msg::PurgeExpired {
                                    now,
                                    first_seen_min_age,
                                    reply,
                                } => {
                                    // A purge self-heals on the next run, but
                                    // a failed later chunk must still report
                                    // the partial removals and the derived-
                                    // state change an earlier chunk applied.
                                    let report = store.purge_expired(now, first_seen_min_age);
                                    if let Some(e) = &report.error {
                                        db_error(&thread_errors, e);
                                    }
                                    let _ =
                                        reply.send((report.removed, report.group_state_removed));
                                }
                                Msg::PendingPurges { reply } => {
                                    let pending = match store.pending_purges() {
                                        Ok(pending) => Some(pending),
                                        Err(e) => {
                                            db_error(&thread_errors, &e);
                                            None
                                        }
                                    };
                                    let _ = reply.send(pending);
                                }
                                Msg::PendingDeletions { reply } => {
                                    let pending = match store.pending_deletions() {
                                        Ok(pending) => Some(pending),
                                        Err(e) => {
                                            db_error(&thread_errors, &e);
                                            None
                                        }
                                    };
                                    let _ = reply.send(pending);
                                }
                                Msg::TableCounts { reply } => {
                                    let counts = match store.table_counts() {
                                        Ok(counts) => Some(counts),
                                        Err(e) => {
                                            db_error(&thread_errors, &e);
                                            None
                                        }
                                    };
                                    let _ = reply.send(counts);
                                }
                                Msg::StateStamp { reply } => {
                                    let stamp = match store.state_stamp() {
                                        Ok(stamp) => Some(stamp),
                                        Err(e) => {
                                            db_error(&thread_errors, &e);
                                            None
                                        }
                                    };
                                    let _ = reply.send(stamp);
                                }
                                Msg::StateSeq { reply } => {
                                    let seq = match store.state_seq() {
                                        Ok(seq) => Some(seq),
                                        Err(e) => {
                                            db_error(&thread_errors, &e);
                                            None
                                        }
                                    };
                                    let _ = reply.send(seq);
                                }
                                Msg::StateSeqGroup { reply } => {
                                    let seq = match store.state_seq_group() {
                                        Ok(seq) => Some(seq),
                                        Err(e) => {
                                            db_error(&thread_errors, &e);
                                            None
                                        }
                                    };
                                    let _ = reply.send(seq);
                                }
                                Msg::StateSeqRole { reply } => {
                                    let seq = match store.state_seq_role() {
                                        Ok(seq) => Some(seq),
                                        Err(e) => {
                                            db_error(&thread_errors, &e);
                                            None
                                        }
                                    };
                                    let _ = reply.send(seq);
                                }
                                Msg::DatabaseSize { reply } => {
                                    let _ = reply.send(store.size_on_disk());
                                }
                                Msg::VanishCounts { reply } => {
                                    let counts = match store.vanish_counts() {
                                        Ok(counts) => Some(counts),
                                        Err(e) => {
                                            db_error(&thread_errors, &e);
                                            None
                                        }
                                    };
                                    let _ = reply.send(counts);
                                }
                                #[cfg(test)]
                                Msg::LastPage { reply } => {
                                    let _ = reply.send(store.env.info().last_page_number as u64);
                                }
                                Msg::TouchFirstSeen { entries, reply } => {
                                    if let Err(e) = store.disk_full_error() {
                                        db_error(&thread_errors, &e);
                                        let _ = reply.send(vec![(false, u64::MAX); entries.len()]);
                                        continue;
                                    }
                                    let mut wtxn = match store.env.write_txn() {
                                        Ok(t) => t,
                                        Err(e) => {
                                            db_error(&thread_errors, &e.into());
                                            let _ =
                                                reply.send(vec![(false, u64::MAX); entries.len()]);
                                            continue;
                                        }
                                    };
                                    let mut out = Vec::with_capacity(entries.len());
                                    for (pubkey, now) in entries {
                                        match store.touch_first_seen(&mut wtxn, &pubkey, now) {
                                            Ok((created, ts)) => out.push((created, ts)),
                                            Err(e) => {
                                                db_error(&thread_errors, &e);
                                                // Fail closed: treat the
                                                // pubkey as too young.
                                                out.push((false, u64::MAX));
                                            }
                                        }
                                    }
                                    match wtxn.commit() {
                                        Ok(()) => {}
                                        Err(e) => db_error(&thread_errors, &e.into()),
                                    }
                                    let _ = reply.send(out);
                                }
                                Msg::PutBatch { .. }
                                | Msg::Put { .. }
                                | Msg::Shutdown
                                | Msg::LoadAccess { .. }
                                | Msg::FirstSeenStatus { .. } => {
                                    unreachable!()
                                }
                            }
                        }
                    }
                    // The deferred puts keep their accounting until the
                    // pre-flush drop; every other arm already sent its reply,
                    // so release now. Arms that `continue`/`return` skip this
                    // and leave their remainder to the guard's `Drop`.
                    if !deferred {
                        pending.release(accounted_msgs, accounted_events, accounted_bytes);
                    }
                }
                // Flush the batch before blocking again: clients await
                // their replies, so a pending batch must not wait for the
                // next message or every requestor deadlocks. The inline
                // messages already released their accounting before their
                // replies (see the loop); the deferred puts' accounting is
                // released *before* the flush replies, so a caller woken by
                // a reply cannot observe a queue that is still counted as
                // full (a transient fail-fast on an empty queue). A panic
                // mid-drain still releases via Drop.
                drop(pending);
                flush_everything(&store, &thread_errors, &mut batch);
                false
            }));
            match result {
                Ok(false) => {}
                Ok(true) => break 'outer,
                Err(_) => {
                    log::error!("database thread recovered from a panic");
                    // Revoke every reply queued for the rolled-back batch:
                    // the pending writes were aborted with the transaction,
                    // so their OK would be a lie. Drain the OLD batch before
                    // resetting it (a fresh batch has nothing to drain).
                    for s in batch.senders.drain(..) {
                        let _ = s.send(PutOutcome::Invalid("database error".into()));
                    }
                    for (events, reply) in batch.pending_batches.drain(..) {
                        let _ = reply.send(vec![
                            PutOutcome::Invalid("database error".into());
                            events.len()
                        ]);
                    }
                    batch = WriteBatch::default();
                }
            }
        }
    }));
    Ok(DbThreads {
        tx,
        read_txs,
        api_read_tx,
        errors,
        overloads,
        expiry,
        resumed_deletion_state_removed,
        recovery_rx,
        timeout_secs: request_timeout_secs,
        pending_msgs,
        pending_events,
        pending_reads: thread_pending_reads,
        api_pending,
        pending_bytes,
        pending_read_bytes,
        api_pending_bytes,
        max_pending_msgs: max_pending_msgs.max(1),
        max_pending_events: max_pending_events.max(1),
        max_api_pending: Arc::new(std::sync::atomic::AtomicUsize::new(max_pending_msgs.max(1))),
        threads: std::sync::Mutex::new(handles),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds three counters holding `value` each.
    fn counters(
        value: usize,
    ) -> (
        Arc<std::sync::atomic::AtomicUsize>,
        Arc<std::sync::atomic::AtomicUsize>,
        Arc<std::sync::atomic::AtomicUsize>,
    ) {
        (
            Arc::new(std::sync::atomic::AtomicUsize::new(value)),
            Arc::new(std::sync::atomic::AtomicUsize::new(value)),
            Arc::new(std::sync::atomic::AtomicUsize::new(value)),
        )
    }

    #[test]
    fn pending_guard_release_subtracts_once_and_saturates() {
        // A partial release shrinks the guard, so Drop subtracts only the
        // remainder instead of double-subtracting the released share.
        let (msgs, events, bytes) = counters(10);
        let mut guard = PendingGuard {
            msgs: 4,
            events: 5,
            bytes: 6,
            msgs_counter: Arc::clone(&msgs),
            events_counter: Arc::clone(&events),
            bytes_counter: Arc::clone(&bytes),
        };
        guard.release(1, 2, 3);
        assert_eq!(msgs.load(std::sync::atomic::Ordering::Relaxed), 9);
        assert_eq!(events.load(std::sync::atomic::Ordering::Relaxed), 8);
        assert_eq!(bytes.load(std::sync::atomic::Ordering::Relaxed), 7);
        drop(guard);
        // The remaining 3/3/3 are subtracted exactly once.
        assert_eq!(msgs.load(std::sync::atomic::Ordering::Relaxed), 6);
        assert_eq!(events.load(std::sync::atomic::Ordering::Relaxed), 5);
        assert_eq!(bytes.load(std::sync::atomic::Ordering::Relaxed), 4);

        // Releasing more than the guard holds (and more than the shared
        // counters hold) saturates: no wrap into a permanent fail-fast and
        // nothing left for Drop to subtract a second time.
        let (msgs, events, bytes) = counters(1);
        let mut guard = PendingGuard {
            msgs: 2,
            events: 2,
            bytes: 2,
            msgs_counter: Arc::clone(&msgs),
            events_counter: Arc::clone(&events),
            bytes_counter: Arc::clone(&bytes),
        };
        guard.release(5, 5, 5);
        assert_eq!(msgs.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(events.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(bytes.load(std::sync::atomic::Ordering::Relaxed), 0);
        drop(guard);
        assert_eq!(msgs.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(events.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(bytes.load(std::sync::atomic::Ordering::Relaxed), 0);

        // A zero-count release (the uncounted `Msg::Shutdown` share) is a
        // no-op, and Drop still subtracts the full remainder.
        let (msgs, events, bytes) = counters(7);
        let mut guard = PendingGuard {
            msgs: 2,
            events: 3,
            bytes: 4,
            msgs_counter: Arc::clone(&msgs),
            events_counter: Arc::clone(&events),
            bytes_counter: Arc::clone(&bytes),
        };
        guard.release(0, 0, 0);
        assert_eq!(msgs.load(std::sync::atomic::Ordering::Relaxed), 7);
        assert_eq!(events.load(std::sync::atomic::Ordering::Relaxed), 7);
        assert_eq!(bytes.load(std::sync::atomic::Ordering::Relaxed), 7);
        drop(guard);
        assert_eq!(msgs.load(std::sync::atomic::Ordering::Relaxed), 5);
        assert_eq!(events.load(std::sync::atomic::Ordering::Relaxed), 4);
        assert_eq!(bytes.load(std::sync::atomic::Ordering::Relaxed), 3);
    }
}
