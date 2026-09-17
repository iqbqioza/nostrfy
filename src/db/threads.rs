//! The dedicated writer and reader threads behind [`super::DbClient`].
//!
//! All LMDB access happens on these two threads: the writer batches event
//! puts into single write transactions (one fsync per batch) and the
//! reader serves queries without ever taking the write lock, so reads keep
//! working even when the writer is stalled.

use std::sync::Arc;

use tokio::sync::mpsc;

use super::store::WriteBatch;
use super::store::{Store, flush_everything};
use super::{LoadAccessOutcome, Msg, PutOutcome, db_error, msg_bytes};
use crate::db::scan::SCAN_BUDGET;
use anyhow::anyhow;

use crate::error::Result;

/// Releases the writer thread's queued-work accounting for one drain. The
/// counters are decremented when the guard drops, so a panic anywhere in
/// the drain cannot leave the overload-protection counters elevated
/// (which would reject every new request afterwards).
struct PendingGuard {
    msgs: usize,
    events: usize,
    bytes: usize,
    msgs_counter: Arc<std::sync::atomic::AtomicUsize>,
    events_counter: Arc<std::sync::atomic::AtomicUsize>,
    bytes_counter: Arc<std::sync::atomic::AtomicUsize>,
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.msgs_counter
            .fetch_sub(self.msgs, std::sync::atomic::Ordering::Relaxed);
        self.events_counter
            .fetch_sub(self.events, std::sync::atomic::Ordering::Relaxed);
        self.bytes_counter
            .fetch_sub(self.bytes, std::sync::atomic::Ordering::Relaxed);
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
    pub(crate) expiry: Arc<std::sync::atomic::AtomicBool>,
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
        Msg::Query {
            filters,
            limit,
            now,
            ascending,
            budget,
            hidden_slack,
            reply,
        } => {
            let out = match store.scan(&filters, now, limit, false, ascending, budget, hidden_slack)
            {
                Ok(out) => out,
                Err(e) => {
                    db_error(errors, &e);
                    (Vec::new(), false)
                }
            };
            let _ = reply.send(out);
            false
        }
        Msg::NegQuery {
            filter,
            limit,
            now,
            reply,
        } => {
            let out = match store.scan_neg(&filter, now, limit, SCAN_BUDGET) {
                Ok(out) => out,
                Err(e) => {
                    db_error(errors, &e);
                    (Vec::new(), false)
                }
            };
            let _ = reply.send(out);
            false
        }
        Msg::Count {
            filters,
            limit,
            now,
            reply,
        } => {
            let out = match store.scan(&filters, now, limit, true, false, SCAN_BUDGET, 0) {
                Ok(out) => out,
                Err(e) => {
                    db_error(errors, &e);
                    (Vec::new(), false)
                }
            };
            let _ = reply.send(out);
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
            let out =
                match store.scan_neg(&crate::filter::Filter::default(), now, limit, SCAN_BUDGET) {
                    Ok(out) => Some(out),
                    Err(e) => {
                        db_error(errors, &e);
                        None
                    }
                };
            let _ = reply.send(out);
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
            let meta = match store.load_blossom_mapping(&sha256) {
                Ok(meta) => meta,
                Err(e) => {
                    db_error(errors, &e);
                    None
                }
            };
            let _ = reply.send(meta);
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
            let page =
                match store.list_blossom_page(&pubkey, after_uploaded, after_sha.as_deref(), limit)
                {
                    Ok(page) => page,
                    Err(e) => {
                        db_error(errors, &e);
                        Vec::new()
                    }
                };
            let _ = reply.send(page);
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
        #[cfg(test)]
        Msg::MapSize { reply } => {
            let _ = reply.send(store.env.info().map_size as u64);
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
        // One-time backfill of the NIP-59 gift-wrap recipient index: an
        // older database has the wraps but no recipient entries, so a
        // NIP-09 deletion would not find them until the index is built.
        match store.gift_wrap_index_needs_rebuild() {
            Ok(true) => match store.rebuild_gift_wrap_index() {
                Ok(n) => log::info!("gift-wrap recipient index rebuilt ({n} recipients)"),
                Err(e) => log::warn!("gift-wrap recipient index rebuild failed: {e}"),
            },
            Ok(false) => {}
            Err(e) => log::warn!("gift-wrap recipient index check failed: {e}"),
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
        // Put batches received within the current message drain are merged
        // into a single commit at flush time.
        let mut batch = WriteBatch::default();
        'outer: loop {
            let Some(msg) = rx.blocking_recv() else {
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
                // Release the queued-work accounting of everything the
                // drain processed. The guard drops on every exit path of
                // the drain (including a panic mid-drain), so the
                // overload-protection counters can never be left elevated.
                let pending = PendingGuard {
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
                for (msg_index, msg) in msgs.into_iter().enumerate() {
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
                                    let meta = match store.load_blossom_mapping(&sha256) {
                                        Ok(meta) => meta,
                                        Err(e) => {
                                            db_error(&thread_errors, &e);
                                            None
                                        }
                                    };
                                    let _ = reply.send(meta);
                                }
                                Msg::BlossomListPage {
                                    pubkey,
                                    after_uploaded,
                                    after_sha,
                                    limit,
                                    reply,
                                } => {
                                    let page = match store.list_blossom_page(
                                        &pubkey,
                                        after_uploaded,
                                        after_sha.as_deref(),
                                        limit,
                                    ) {
                                        Ok(page) => page,
                                        Err(e) => {
                                            db_error(&thread_errors, &e);
                                            Vec::new()
                                        }
                                    };
                                    let _ = reply.send(page);
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
                                    let out = match store.scan(
                                        &filters,
                                        now,
                                        limit,
                                        false,
                                        ascending,
                                        budget,
                                        hidden_slack,
                                    ) {
                                        Ok(out) => out,
                                        Err(e) => {
                                            db_error(&thread_errors, &e);
                                            (Vec::new(), false)
                                        }
                                    };
                                    let _ = reply.send(out);
                                }
                                Msg::NegQuery {
                                    filter,
                                    limit,
                                    now,
                                    reply,
                                } => {
                                    let out = match store.scan_neg(&filter, now, limit, SCAN_BUDGET)
                                    {
                                        Ok(out) => out,
                                        Err(e) => {
                                            db_error(&thread_errors, &e);
                                            (Vec::new(), false)
                                        }
                                    };
                                    let _ = reply.send(out);
                                }
                                Msg::Count {
                                    filters,
                                    limit,
                                    now,
                                    reply,
                                } => {
                                    let out = match store.scan(
                                        &filters,
                                        now,
                                        limit,
                                        true,
                                        false,
                                        SCAN_BUDGET,
                                        0,
                                    ) {
                                        Ok(out) => out,
                                        Err(e) => {
                                            db_error(&thread_errors, &e);
                                            (Vec::new(), false)
                                        }
                                    };
                                    let _ = reply.send(out);
                                }
                                Msg::AggregateSample { limit, now, reply } => {
                                    let out = match store.scan_neg(
                                        &crate::filter::Filter::default(),
                                        now,
                                        limit,
                                        SCAN_BUDGET,
                                    ) {
                                        Ok(out) => Some(out),
                                        Err(e) => {
                                            db_error(&thread_errors, &e);
                                            None
                                        }
                                    };
                                    let _ = reply.send(out);
                                }
                                Msg::Delete {
                                    targets,
                                    addresses,
                                    request_pubkey,
                                    request_created,
                                    group,
                                    reply,
                                } => {
                                    let n = match store.apply_deletion_group(
                                        &targets,
                                        &addresses,
                                        request_pubkey.as_deref(),
                                        request_created,
                                        group.as_deref(),
                                    ) {
                                        Ok(n) => n,
                                        Err(e) => {
                                            db_error(&thread_errors, &e);
                                            0
                                        }
                                    };
                                    let _ = reply.send(n);
                                }
                                Msg::GroupPurge { group, reply } => {
                                    let n = match store.purge_group(&group) {
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
                                    let outcome = match store.apply_vanish(&pubkey, until_created) {
                                        Ok(outcome) => outcome,
                                        Err(e) => {
                                            db_error(&thread_errors, &e);
                                            (0, false)
                                        }
                                    };
                                    let _ = reply.send(outcome);
                                }
                                Msg::GiftWrapPurge { pubkey, reply } => {
                                    let n = match store.delete_gift_wraps_to(&pubkey) {
                                        Ok(n) => n,
                                        Err(e) => {
                                            db_error(&thread_errors, &e);
                                            0
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
                                Msg::SaveBlossomAllow { entries, reply } => {
                                    if let Err(e) = store.save_blossom_allow(&entries) {
                                        db_error(&thread_errors, &e);
                                    }
                                    let _ = reply.send(());
                                }
                                Msg::SaveGroups { snapshot, reply } => {
                                    if Some(msg_index) == last_groups
                                        && let Err(e) = store.save_groups(&snapshot)
                                    {
                                        db_error(&thread_errors, &e);
                                    }
                                    let _ = reply.send(());
                                }
                                Msg::SaveRoles { snapshot, reply } => {
                                    if Some(msg_index) == last_roles
                                        && let Err(e) = store.save_roles(&snapshot)
                                    {
                                        db_error(&thread_errors, &e);
                                    }
                                    let _ = reply.send(());
                                }
                                Msg::ClearGroupsSnapshot { reply } => {
                                    if let Err(e) = store.clear_groups_snapshot() {
                                        db_error(&thread_errors, &e);
                                    }
                                    let _ = reply.send(());
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
                                Msg::PurgeExpired { now, reply } => {
                                    let n = match store.purge_expired(now) {
                                        Ok(n) => n,
                                        Err(e) => {
                                            db_error(&thread_errors, &e);
                                            0
                                        }
                                    };
                                    let _ = reply.send(n);
                                }
                                Msg::DatabaseSize { reply } => {
                                    let _ = reply.send(store.size_on_disk());
                                }
                                #[cfg(test)]
                                Msg::MapSize { reply } => {
                                    let _ = reply.send(store.env.info().map_size as u64);
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
                }
                // Flush the batch before blocking again: clients await
                // their replies, so a pending batch must not wait for the
                // next message or every requestor deadlocks. The queued-work
                // accounting is released *before* the flush replies, so a
                // caller woken by the reply cannot observe a queue that is
                // still counted as full (a transient fail-fast on an empty
                // queue). A panic mid-drain still releases via Drop.
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
        expiry,
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
