//! LMDB persistence layer.
//!
//! [`Store`] owns the database environment and implements the write path:
//! event puts with replaceable/ephemeral/expiry semantics, the index
//! maintenance, NIP-09 deletion, NIP-62 vanish, NIP-86 bans and the
//! NIP-40 expiration purge.

use std::sync::Arc;

use heed::types::Bytes;
use heed::{Database, Env, EnvFlags, EnvOpenOptions, FlagSetMode};
use tokio::sync::oneshot;

use super::{PutOutcome, db_error};

/// The relay pubkey access lists: (deny, allow), each a (pubkey, reason)
/// pair. Shared by the CLI, the database layer and the access checks.
pub(crate) type RelayPubkeyLists = (Vec<(String, String)>, Vec<(String, String)>);

/// One started-but-unfinished NIP-09 deletion request (see
/// [`DELETE_PENDING`]): the full request so the startup resume can replay
/// it without the original event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingDeletion {
    /// `e`-tag event ids.
    pub targets: Vec<String>,
    /// `a`-tag addresses.
    pub addresses: Vec<crate::nips::nip09::Address>,
    /// The deletion request's author (None for NIP-29 `kind:9005` group
    /// moderation, where `group` scopes the request instead).
    pub request_pubkey: Option<String>,
    /// The NIP-09 `created_at` cut for `a`-tag targets.
    pub request_created: u64,
    /// NIP-29 `kind:9005` group scope.
    pub group: Option<String>,
}

/// Row counts of the bookkeeping tables, exposed as gauges so operators
/// can see the tables that grow with removals (`deleted`, `first_seen`,
/// `purged_groups`, `vanish`) and confirm that interrupted removals were
/// resumed (`*_pending`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TableCounts {
    pub deleted: u64,
    pub first_seen: u64,
    pub purged_groups: u64,
    pub vanish: u64,
    pub vanish_pending: u64,
    pub purge_pending: u64,
    pub delete_pending: u64,
}

/// A blob's persisted metadata: the sha256 → owners mapping that lets
/// Blossom resolve a hash without any in-memory index.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct BlossomMeta {
    pub sha256: String,
    pub size: u64,
    pub mime: String,
    pub uploaded: i64,
    /// Uploaders' hex pubkeys, in upload order.
    pub owners: Vec<String>,
}

/// The maximum number of owners one blob may accumulate. Every owner adds
/// an entry to the JSON metadata and an `own:` index row, so an attacker
/// re-uploading a popular blob under many keys could otherwise grow the
/// mapping without bound. New owners past the cap are refused (the blob
/// itself stays reachable through the existing owners).
pub(crate) const MAX_BLOB_OWNERS: usize = 64;

/// The uploaded-order index prefix for one owner:
/// `bls:<pubkey>:<uploaded:020>:<sha256>`. BUD-12 `/list` pages iterate it
/// in reverse, so a page never depends on scanning the sha-ordered reverse
/// index (which hid every blob past the scan window).
const BLOSSOM_ORDER_PREFIX: &str = "bls:";

/// The uploaded-order index key of one owner/blob pair.
fn blossom_order_key(pubkey: &str, uploaded: i64, sha256: &str) -> String {
    format!(
        "{BLOSSOM_ORDER_PREFIX}{pubkey}:{:020}:{sha256}",
        uploaded.max(0) as u64
    )
}
use crate::config::DatabaseConfig;
use crate::error::Result;
use crate::event::Event;
use crate::nips::{nip33, nip40, nip50};

pub(crate) const EVENTS: &str = "events";
/// The lightweight per-event metadata index: id → fixed-length header
/// (kind, created_at, pubkey, expiration). The scan checks these fields
/// before deserializing the full JSON, so candidates failing the
/// kind/since/until/author checks are rejected without the parse.
pub(crate) const EVENT_META: &str = "event_meta";
/// Length of an [`EVENT_META`] header: kind (8) + created_at (8) +
/// pubkey (32) + expiration (8, 0 = none).
pub(crate) const META_LEN: usize = 56;

pub(crate) fn encode_meta(kind: u64, created: u64, pubkey: &[u8], expiry: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(META_LEN);
    v.extend_from_slice(&kind.to_be_bytes());
    v.extend_from_slice(&created.to_be_bytes());
    v.extend_from_slice(&pubkey[..32]);
    v.extend_from_slice(&expiry.to_be_bytes());
    v
}

/// Decodes a meta header into `(kind, created_at, pubkey, expiry)`.
pub(crate) fn decode_meta(raw: &[u8]) -> Option<(u64, u64, [u8; 32], u64)> {
    if raw.len() < META_LEN {
        return None;
    }
    // The length guard above guarantees every slice below is in bounds, so
    // the extraction cannot fail (no unreachable fallback branches).
    let mut b = [0u8; 8];
    b.copy_from_slice(&raw[0..8]);
    let kind = u64::from_be_bytes(b);
    b.copy_from_slice(&raw[8..16]);
    let created = u64::from_be_bytes(b);
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&raw[16..48]);
    b.copy_from_slice(&raw[48..56]);
    let expiry = u64::from_be_bytes(b);
    Some((kind, created, pubkey, expiry))
}

pub(crate) const BY_CREATED: &str = "by_created";
pub(crate) const BY_PUBKEY: &str = "by_pubkey";
pub(crate) const BY_KIND: &str = "by_kind";
pub(crate) const BY_TAG: &str = "by_tag";
pub(crate) const BY_WORD: &str = "by_word";
/// Key/value table for one-time index migrations (a marker key per rebuilt
/// derived index). Separate from [`EVENT_META`], which stores one header per
/// event.
pub(crate) const INDEX_META: &str = "index_meta";
/// Reserved single-byte name for the NIP-59 gift-wrap recipient index inside
/// [`BY_TAG`]. Real tag names are ASCII alphanumeric ([`indexable_tag`]), so
/// `0x01` cannot collide with an actual tag.
pub(crate) const GIFT_WRAP_INDEX: u8 = 0x01;
pub(crate) const DELETED: &str = "deleted";
pub(crate) const EXPIRY: &str = "expiry";
pub(crate) const REPLACEABLE: &str = "replaceable";
pub(crate) const VANISH: &str = "vanish";
pub(crate) const BANNED: &str = "banned";
pub(crate) const FIRST_SEEN: &str = "first_seen";
pub(crate) const ACCESS: &str = "access";
/// sha256 → blob metadata (mime/size/uploaded/owners) plus the per-owner
/// reverse index, persisted so Blossom lookups need no in-memory index.
pub(crate) const BLOSSOM: &str = "blossom";
/// NIP-29 group state snapshot (`groups:snapshot`), persisted so restarts
/// restore groups without replaying the full moderation history.
pub(crate) const GROUPS: &str = "groups";
/// NIP-43 role state snapshot (`roles:snapshot`), persisted for the same
/// reason as [`GROUPS`].
pub(crate) const ROLES: &str = "roles";
/// NIP-29 group purge markers: `sha256(gid) -> purge time (BE u64) || cut
/// (BE u64)`. One record per purged group id instead of one tombstone per
/// purged event: an `h`-tagged re-publication with `created_at <= cut` is
/// rejected, and a `kind:9007` re-create is rejected only while its
/// `created_at` is *before* the purge time (a legitimate re-create passes
/// even when future-dated purged content pushed the cut forward). A
/// create/purge cycle therefore grows this table by one fixed 32-byte key,
/// not by the group's (unbounded) event count. Markers written before the
/// value carried two fields hold the cut alone and are read as
/// `(cut, cut)`.
pub(crate) const PURGED_GROUPS: &str = "purged_groups";
/// In-progress NIP-29 group purges: `sha256(gid) -> gid length (BE u32) ||
/// gid bytes || purge time (BE u64) || cut (BE u64)`. Written in the same
/// commit as the [`PURGED_GROUPS`] marker, before the first removal chunk,
/// and deleted only when the walk completed cleanly. A crash or `MapFull`
/// mid-walk therefore leaves a resumable record instead of a ghosted group
/// whose marker rejects the re-issued `kind:9008` (and every re-published
/// history event) while the old history stays stored. The group id itself
/// is stored because the marker table only keeps its digest.
pub(crate) const PURGE_PENDING: &str = "purge_pending";
/// In-progress NIP-62 vanishes: pubkey (32 bytes) -> until_created (BE
/// u64). Written before the removal walk and cleared in the same commit as
/// the completed [`VANISH`] marker, so an interrupted vanish is resumed at
/// startup instead of leaving removed events with no marker and no cursor.
pub(crate) const VANISH_PENDING: &str = "vanish_pending";
/// In-progress NIP-09 deletions: `sha256(request)` -> the encoded request
/// (targets, addresses, requester, created_at cut and group scope). Written
/// before the first removal chunk and cleared only after the whole walk
/// completed cleanly, so a crash or `MapFull` mid-walk resumes the deletion
/// at startup instead of leaving a half-applied request behind (an `a`-tag
/// tombstone written but the versions still stored, or vice versa).
pub(crate) const DELETE_PENDING: &str = "delete_pending";
/// [`INDEX_META`] key of the persistent derived-group-state stamp: bumped
/// inside the write transaction of every group-state-relevant removal, so
/// the stamp and the removals commit atomically.
pub(crate) const STATE_STAMP_KEY: &[u8] = b"state_stamp";
/// [`INDEX_META`] key of the derived-state sequence: bumped inside the same
/// write transaction as every NIP-29/NIP-43 state-relevant event put, so a
/// persisted snapshot can record the exact state generation it was taken
/// at. Kept as the combined (max) generation for backward compatibility:
/// the per-family counters below are what the snapshot restore checks
/// compare, so a role event no longer invalidates a group snapshot (and
/// vice versa). A snapshot whose `seq` is below the current sequence
/// predates a state event and must not be restored.
pub(crate) const STATE_SEQ_KEY: &[u8] = b"state_seq";
/// [`INDEX_META`] key of the NIP-29 group-state sequence: bumped in the
/// same write transaction as a group-state event put (see
/// [`state_kind_family`]). The group snapshot restore check compares
/// against this counter, so NIP-43 role events cannot cross-invalidate it.
pub(crate) const STATE_SEQ_GROUP_KEY: &[u8] = b"state_seq_group";
/// [`INDEX_META`] key of the NIP-43 role-state sequence: the role snapshot
/// counterpart of [`STATE_SEQ_GROUP_KEY`].
pub(crate) const STATE_SEQ_ROLE_KEY: &[u8] = b"state_seq_role";

/// Which derived store a state-relevant `kind` feeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StateFamily {
    Group,
    Role,
}

/// Classifies a `kind` as a NIP-29 group-state event or a NIP-43 role-state
/// event (see [`StateFamily`]). Such events bump the matching per-family
/// sequence when they store, and removing one bumps [`STATE_STAMP_KEY`], so
/// the snapshot restore checks can detect a snapshot that predates the
/// event.
pub(crate) fn state_kind_family(kind: u64) -> Option<StateFamily> {
    if (crate::nips::nip29::MOD_MIN..=crate::nips::nip29::MOD_MAX).contains(&kind)
        || kind == crate::nips::nip29::JOIN
        || kind == crate::nips::nip29::LEAVE
    {
        Some(StateFamily::Group)
    } else if matches!(
        kind,
        crate::nips::nip43::ROLE_DEFINITION
            | crate::nips::nip43::MEMBERSHIP_LIST
            | crate::nips::nip43::ADD_USER
            | crate::nips::nip43::REMOVE_USER
            | crate::nips::nip43::JOIN
            | crate::nips::nip43::LEAVE
    ) {
        Some(StateFamily::Role)
    } else {
        None
    }
}

/// Whether a `kind` event feeds any derived state (NIP-29 group state or
/// NIP-43 role state). Used by the removal paths, which bump the shared
/// [`STATE_STAMP_KEY`] because a stamp change must invalidate both snapshot
/// families.
pub(crate) fn is_group_state_kind(kind: u64) -> bool {
    state_kind_family(kind).is_some()
}
pub(crate) const CREATED_LEN: usize = 8;
pub(crate) const ID_LEN: usize = 32;
pub(crate) const TAG_VALUE_MAX: usize = 1024;
/// Longest tag value that fits an index key under LMDB's key-size limit:
/// `name(1) + sep(1) + len(4) + value + created(8) + id(32)`.
pub(crate) const TAG_INDEX_VALUE_MAX: usize = MAX_INDEX_KEY - 1 - 1 - 4 - CREATED_LEN - ID_LEN;
/// Longest search term that fits a word-index key under the same limit:
/// `word + sep(1) + created(8) + id(32)`.
pub(crate) const WORD_INDEX_MAX: usize = MAX_INDEX_KEY - 1 - CREATED_LEN - ID_LEN;
/// LMDB's maximum key size (`MDB_MAXKEYSIZE`). Index keys longer than this
/// are rejected with `MDB_BAD_VALSIZE`, which would abort the *entire* write
/// batch and reject every connection's events in the drain window. Over-long
/// variable-length index components (tag values, words, `d` tags) are
/// therefore skipped/truncated at indexing time instead of erroring: the
/// event itself is still stored, only lookup by the pathological value is
/// unavailable.
pub(crate) const MAX_INDEX_KEY: usize = 511;

/// Minimum free space required before a batch of writes is committed.
/// Writing to the memory map of a file on a completely full disk raises
/// SIGBUS (killing the process), so the relay refuses to commit while the
/// free space is below this margin and keeps serving reads.
pub(crate) const DISK_FREE_MARGIN: u64 = 32 * 1024 * 1024;

/// How many index entries `remove_corrupt_event` scans per table before it
/// gives up. Clearing a corrupt event's indexes requires walking whole
/// tables (without the event JSON the index keys cannot be derived); the
/// fallback exists for legacy/corrupt data only, and an unbounded walk
/// would hold the caller's write transaction — blocking every queued write
/// — for seconds on a large relay. Skipped entries are harmless: the scans
/// verify that an event still exists before delivering it, so a dangling
/// index key only costs an existence check.
pub(crate) const CORRUPT_CLEANUP_SCAN_CAP: usize = 50_000;

/// Free bytes on the filesystem hosting `path`, when statvfs succeeds.
pub(crate) fn path_free_space(path: &std::path::Path) -> Option<u64> {
    let dir = if path.is_file() {
        path.parent().unwrap_or(path)
    } else {
        path
    };
    let c_path = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).ok()?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `stat` points at a valid buffer and the path is a valid
    // NUL-terminated string.
    if unsafe { libc::statvfs(c_path.as_ptr(), stat.as_mut_ptr()) } == 0 {
        let stat = unsafe { stat.assume_init() };
        Some(stat.f_bavail.saturating_mul(stat.f_frsize))
    } else {
        None
    }
}

/// Whether `free` bytes is below the write margin: a write to the memory
/// map of a file on a full disk raises SIGBUS, so every writing path refuses
/// to commit below [`DISK_FREE_MARGIN`]. A tiny helper so the margin
/// comparison itself is unit-testable without filling a filesystem.
pub(crate) fn disk_below_margin(free: u64) -> bool {
    free < DISK_FREE_MARGIN
}

/// Refuses a write when the disk hosting `env` is too full for a safe mmap
/// commit (a write to a full disk raises SIGBUS and kills the process).
/// For the CLI and migration paths that own no `Store` handle.
pub(crate) fn check_env_space(env: &Env) -> Result<()> {
    if let Some(free) = path_free_space(env.path())
        && disk_below_margin(free)
    {
        return Err(crate::error::storage_full());
    }
    Ok(())
}

/// Applies `puts` in one write transaction and commits. When the commit
/// fails because the memory map is full, the whole batch is re-applied in a
/// fresh transaction if the map can grow (it cannot at runtime: the map is
/// opened once at its ceiling and never resized, so `MapFull` fails the
/// batch). Returns one outcome per put; all outcomes are `Invalid("...")`
/// when the batch cannot be committed.
pub(crate) fn apply_put_batch(
    store: &Store,
    thread_errors: &Arc<std::sync::atomic::AtomicU64>,
    mut pending: Option<heed::RwTxn>,
    puts: &[(Arc<Event>, u64)],
    first_seen: &[Option<([u8; 32], u64)>],
) -> Vec<PutOutcome> {
    if puts.is_empty() {
        if let Some(txn) = pending
            && let Err(e) = txn.commit()
        {
            db_error(thread_errors, &e.into());
        }
        return Vec::new();
    }
    // Disk-full guard: writing to the memory map of a file on a full disk
    // raises SIGBUS and kills the process, so refuse to commit while the
    // free space is below the margin. Reads keep working.
    if let Some(free) = store.free_space()
        && disk_below_margin(free)
    {
        log::error!(
            "disk is full: refusing to commit {} events ({} bytes free)",
            puts.len(),
            free
        );
        return vec![PutOutcome::Invalid("error: disk is full".into()); puts.len()];
    }
    loop {
        // LMDB allows a single writer: reuse the pending transaction if one
        // is open, otherwise open a fresh one.
        let mut txn = match pending.take() {
            Some(t) => t,
            None => match store.env.write_txn() {
                Ok(t) => t,
                Err(e) => {
                    db_error(thread_errors, &e.into());
                    return vec![PutOutcome::Invalid("database error".into()); puts.len()];
                }
            },
        };
        let mut outcomes = Vec::with_capacity(puts.len());
        let mut poisoned = false;
        for (i, (event, now)) in puts.iter().enumerate() {
            match store.put_event_in(&mut txn, event, *now) {
                Ok(out) => {
                    // Record the first-seen timestamp in the same commit:
                    // the pubkey's account-age clock starts only when the
                    // event actually stored (a rejected first event must
                    // not pre-warm it).
                    if matches!(
                        out,
                        PutOutcome::Stored | PutOutcome::Replaced | PutOutcome::Ephemeral
                    ) && let Some((pubkey, ts)) = first_seen.get(i).copied().flatten()
                        && let Err(e) = store.touch_first_seen(&mut txn, &pubkey, ts)
                    {
                        // Non-fatal: the event is stored either way, and a
                        // missing first-seen only weakens the age gate.
                        db_error(thread_errors, &e);
                    }
                    outcomes.push(out);
                }
                Err(e) => {
                    db_error(thread_errors, &e);
                    poisoned = true;
                    break;
                }
            }
        }

        if poisoned {
            // The transaction is unusable: abort it and revoke every reply
            // queued for it, because the applied puts were rolled back with
            // it and their OK would be a lie.
            return vec![PutOutcome::Invalid("database error".into()); puts.len()];
        }
        // Test-only fault injection: treat the next commit as a full map so
        // the rollback path below is exercised without filling a real
        // environment (the map floor is 16 MiB). The open transaction is
        // dropped (aborted) with the returned batch.
        #[cfg(test)]
        let commit = if store
            .fail_next_commit
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            Err(heed::Error::Mdb(heed::MdbError::MapFull))
        } else {
            txn.commit()
        };
        #[cfg(not(test))]
        let commit = txn.commit();
        match commit {
            Ok(()) => {
                return outcomes;
            }
            Err(heed::Error::Mdb(heed::MdbError::MapFull)) => {
                if !store.grow_map() {
                    // The map cannot grow further: the batch cannot be
                    // committed, so every reply is revoked. Count the
                    // failure as well: `grow_map` only logs, and the
                    // relay's health metrics must see a full map.
                    thread_errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return vec![PutOutcome::Invalid("database error".into()); puts.len()];
                }
                // Retry the whole batch in the larger map.
            }
            Err(e) => {
                db_error(thread_errors, &e.into());
                return vec![PutOutcome::Invalid("database error".into()); puts.len()];
            }
        }
    }
}

/// A batch of events to store in one transaction, with its reply.
pub(crate) type PutBatchMsg = (Vec<(Arc<Event>, u64)>, oneshot::Sender<Vec<PutOutcome>>);

/// The writer thread's pending write state: the open transaction, the
/// queued single puts with their reply channels and the queued put
/// batches.
#[derive(Default)]
pub(crate) struct WriteBatch<'tx> {
    pub(crate) pending: Option<heed::RwTxn<'tx>>,
    pub(crate) puts: Vec<(Arc<Event>, u64)>,
    /// Per-put first-seen reservation, aligned with `puts`: applied inside
    /// the same write transaction as the put it belongs to (one commit and
    /// one fsync instead of two for a pubkey's first accepted event).
    pub(crate) first_seen: Vec<Option<([u8; 32], u64)>>,
    pub(crate) senders: Vec<oneshot::Sender<PutOutcome>>,
    pub(crate) pending_batches: Vec<PutBatchMsg>,
}

/// Commits the pending single-put batch together with every queued
/// `PutBatch`, merging them all into one write transaction (one commit for
/// events arriving from many connections). Replies are only sent after a
/// successful commit, so an OK implies durability.
/// Warns when the kernel refuses large sparse reservations
/// (`vm.overcommit_memory = 2`): LMDB reserves `map_size` (up to 1 TiB by
/// default) of address space up front, so the relay may fail to start
/// there even though physical memory is only used for touched pages.
fn warn_if_overcommit_strict() {
    #[cfg(target_os = "linux")]
    if let Ok(text) = std::fs::read_to_string("/proc/sys/vm/overcommit_memory")
        && text.trim() == "2"
    {
        log::warn!(
            "vm.overcommit_memory=2 is set: the LMDB map reservation \
             (database.max_map_size) may be refused; raise the overcommit \
             ratio or lower the map size"
        );
    }
}

pub(crate) fn flush_everything(
    store: &Store,
    thread_errors: &Arc<std::sync::atomic::AtomicU64>,
    batch: &mut WriteBatch<'_>,
) {
    if batch.puts.is_empty() && batch.pending_batches.is_empty() {
        if let Some(wtxn) = batch.pending.take()
            && let Err(e) = wtxn.commit()
        {
            db_error(thread_errors, &e.into());
        }
        return;
    }
    // Merge the singles and every queued batch into one list; the split
    // points let the outcomes be distributed back in order.
    let mut all: Vec<(Arc<Event>, u64)> = std::mem::take(&mut batch.puts);
    let mut first_seen = std::mem::take(&mut batch.first_seen);
    let mut splits: Vec<usize> = vec![all.len()];
    for (events, _) in batch.pending_batches.iter_mut() {
        all.append(events);
        splits.push(all.len());
    }
    // The batch events carry no first-seen reservation: pad the aligned
    // vector to the merged length.
    first_seen.resize(all.len(), None);
    let outcomes = apply_put_batch(
        store,
        thread_errors,
        batch.pending.take(),
        &all,
        &first_seen,
    );
    for (s, out) in batch
        .senders
        .drain(..)
        .zip(outcomes.iter().take(splits[0]).cloned())
    {
        let _ = s.send(out);
    }
    for (i, (_, reply)) in batch.pending_batches.drain(..).enumerate() {
        let range = splits[i]..splits[i + 1];
        let _ = reply.send(outcomes[range].to_vec());
    }
}

pub(crate) struct Store {
    pub(crate) env: Env,
    pub(crate) events: Database<Bytes, Bytes>,
    pub(crate) by_created: Database<Bytes, Bytes>,
    pub(crate) by_pubkey: Database<Bytes, Bytes>,
    pub(crate) by_kind: Database<Bytes, Bytes>,
    pub(crate) by_tag: Database<Bytes, Bytes>,
    pub(crate) by_word: Option<Database<Bytes, Bytes>>,
    pub(crate) event_meta: Option<Database<Bytes, Bytes>>,
    /// Whether the per-event metadata header (kind/created/pubkey/expiry)
    /// is written for the scan prefilter. Disabling it removes one random
    /// index write per event (keeping the ingest cost flat as the database
    /// grows) at the cost of the scan falling back to the full parse.
    pub(crate) meta_index: bool,
    pub(crate) deleted: Database<Bytes, Bytes>,
    pub(crate) expiry: Database<Bytes, Bytes>,
    pub(crate) replaceable: Database<Bytes, Bytes>,
    pub(crate) vanish: Database<Bytes, Bytes>,
    pub(crate) banned: Database<Bytes, Bytes>,
    /// pubkey (32 bytes) -> unix timestamp of the first accepted event.
    pub(crate) first_seen: Database<Bytes, Bytes>,
    /// Serialized access control lists (NIP-86 runtime bans/allowlists), kept
    /// under a single fixed key so they survive restarts.
    pub(crate) access: Database<Bytes, Bytes>,
    pub(crate) blossom: Database<Bytes, Bytes>,
    /// Serialized NIP-29 group state snapshot (see
    /// [`crate::nips::nip29::GroupsSnapshot`]), written on every group
    /// mutation so restarts restore groups without replaying history.
    pub(crate) groups: Database<Bytes, Bytes>,
    /// Serialized NIP-43 role state snapshot (see
    /// [`crate::nips::nip43::RolesSnapshot`]), same lifecycle as [`Self::groups`].
    pub(crate) roles: Database<Bytes, Bytes>,
    /// NIP-29 purge markers (see [`PURGED_GROUPS`]): a purged group's
    /// history must not be re-publishable after the id is re-created.
    pub(crate) purged_groups: Database<Bytes, Bytes>,
    /// Started-but-unfinished NIP-29 group purges (see [`PURGE_PENDING`]).
    pub(crate) purge_pending: Database<Bytes, Bytes>,
    /// Started-but-unfinished NIP-62 vanishes (see [`VANISH_PENDING`]).
    pub(crate) vanish_pending: Database<Bytes, Bytes>,
    /// Started-but-unfinished NIP-09 deletions (see [`DELETE_PENDING`]).
    pub(crate) delete_pending: Database<Bytes, Bytes>,
    /// One-time index migration markers (see [`INDEX_META`]) plus the
    /// derived-state stamp and sequence (`state_stamp`, `state_seq`).
    pub(crate) index_meta: Database<Bytes, Bytes>,
    /// NIP-40 expiration handling is only active when the NIP is enabled.
    /// Shared with the relay so that a config reload can toggle it at runtime.
    pub(crate) expiry_enabled: Arc<std::sync::atomic::AtomicBool>,
    /// Shutdown cancellation: set by `DbClient::shutdown` (and shared with
    /// every reader clone) so the long chunked removals stop at the next
    /// chunk boundary instead of delaying a SIGTERM for hours. A cancelled
    /// walk leaves its pending record in place: the next startup finishes
    /// it (fail-closed).
    pub(crate) cancel: Arc<std::sync::atomic::AtomicBool>,
    /// NIP-50 word index: maximum number of words indexed per event.
    pub(crate) max_indexed_words: usize,
    /// The limit the existing word index was built with (persisted in
    /// `index_meta`; used by put/remove so they stay symmetric across a
    /// config change).
    pub(crate) indexed_words: usize,
    /// Ceiling for the memory map (bytes): the map is opened at this size
    /// and never resized at runtime.
    pub(crate) map_max_size: u64,
    /// Short-lived cache of NIP-50 document frequencies (term -> (df,
    /// expires_at)). Each miss walks up to `DF_SAMPLE` index entries, and
    /// a popular query repeats over many requests; the scores tolerate a
    /// few minutes of staleness.
    pub(crate) df_cache: Arc<std::sync::Mutex<std::collections::HashMap<String, (u64, u64)>>>,
    /// Test-only one-shot fault injection: the next `apply_put_batch`
    /// commit is treated as a `MapFull` failure so the rollback path
    /// (every put in the batch is revoked) is testable without filling a
    /// real 16 MiB (map floor) environment.
    #[cfg(test)]
    pub(crate) fail_next_commit: std::sync::atomic::AtomicBool,
    /// Whether commits skip the fsync (`database.disabled_fsync`): the
    /// writer thread then syncs periodically instead of only at shutdown.
    /// Set once at open (the flag is not reloadable).
    pub(crate) disabled_fsync: bool,
    /// Test-only one-shot fault injection: the next writer message handler
    /// panics, so the writer's `catch_unwind` recovery, its reply
    /// revocation and the queued-work counter release are testable.
    #[cfg(test)]
    pub(crate) panic_next_write: Arc<std::sync::atomic::AtomicBool>,
    /// Test-only one-shot fault injection for the reader threads (shared
    /// with `clone_for_reader`, so arming the store before the threads
    /// start reaches every reader).
    #[cfg(test)]
    pub(crate) panic_next_read: Arc<std::sync::atomic::AtomicBool>,
    /// Test-only one-shot fault injection: the next `purge_group` removal
    /// chunk fails after the marker and the in-progress record committed,
    /// so the crash-recovery resume is exercised with real in-progress
    /// state instead of hand-written table entries.
    #[cfg(test)]
    pub(crate) fail_next_purge_chunk: std::sync::atomic::AtomicBool,
    /// Test-only one-shot fault injection: the next `apply_vanish` removal
    /// chunk fails after the in-progress record committed.
    #[cfg(test)]
    pub(crate) fail_next_vanish_chunk: std::sync::atomic::AtomicBool,
    /// Test-only one-shot fault injection: the next `apply_deletion_group`
    /// removal chunk fails after the in-progress record committed.
    #[cfg(test)]
    pub(crate) fail_next_delete_chunk: std::sync::atomic::AtomicBool,
    /// Test-only one-shot fault injection: the next scan returns a store
    /// error, so the reported read variants must answer `None` instead of
    /// an empty successful result. Shared with the reader clones so arming
    /// the store before the threads start reaches every reader.
    #[cfg(test)]
    pub(crate) fail_next_scan: Arc<std::sync::atomic::AtomicBool>,
}

/// `(created_at, id, protected, group_id, is_meta)` records returned by the
/// NIP-77 negentropy query. The visibility flags let the connection layer
/// withhold NIP-70 protected events from unauthenticated peers and NIP-29
impl Store {
    pub(crate) fn open(
        cfg: &DatabaseConfig,
        expiry_enabled: Arc<std::sync::atomic::AtomicBool>,
        max_indexed_words: usize,
    ) -> Result<Store> {
        std::fs::create_dir_all(&cfg.path)?;
        // SAFETY: the returned `Env` is owned by `Store` and outlives every
        // transaction created from it within this process.
        // The map is virtual address space: on 64-bit systems the growth
        // ceiling can be huge; on 32-bit systems LMDB is limited to ~2 GiB.
        let mut map_max_size = (cfg.max_map_size as u64)
            .max(cfg.map_size as u64)
            .max(16 * 1024 * 1024);
        if usize::BITS < 64 {
            let cap = 2u64 * 1024 * 1024 * 1024;
            map_max_size = map_max_size.min(cap);
        }
        // The map is opened at `map_max_size` from the start (a sparse
        // virtual reservation: physical memory is only consumed by the
        // pages actually touched) and never resized at runtime. Runtime
        // growth would call `mdb_env_set_mapsize`, which requires that no
        // transactions are active — impossible while the shared reader and
        // the dedicated API reader threads hold concurrent read
        // transactions — and would risk unmapping memory the readers are
        // still using.
        let map_size = map_max_size as usize;
        let env = unsafe {
            EnvOpenOptions::new()
                // 21 named tables, plus the word index when search is on.
                .max_dbs(cfg.max_dbs.max(22))
                // Every reader thread can hold a concurrent read transaction,
                // the writer/API/startup paths take slots too, and some read
                // paths nest a second transaction inside the first
                // (`list_blossom_page` resolves each sha while its outer walk
                // transaction is open). A `max_readers` below that makes LMDB
                // fail queries with MDB_READERS_FULL (surfacing as silent
                // empty scans). Raise the effective floor instead of trusting
                // the configured value alone: two slots per reader thread
                // plus the writer/API/startup paths.
                .max_readers(
                    cfg.max_readers.max(
                        (cfg.reader_threads.clamp(1, 64) as u32)
                            .saturating_mul(2)
                            .saturating_add(3),
                    ),
                )
                .map_size(map_size)
                .open(&cfg.path)?
        };
        warn_if_overcommit_strict();
        if cfg.disabled_fsync {
            // SAFETY: `NO_SYNC` is marked unsafe by heed because it trades
            // durability for throughput (LMDB skips the fsync after each
            // commit). The relay's semantics are unchanged: a write the
            // process acknowledged has been committed to the map and may
            // still be lost on OS crash / power loss — exactly what the
            // option's documentation promises.
            unsafe { env.set_flags(EnvFlags::NO_SYNC, FlagSetMode::Enable)? };
            log::info!(
                "database writes skip the fsync (disabled_fsync = true): commits land in the \
                 OS page cache, so a power loss may lose the most recent writes"
            );
        }

        let mut wtxn = env.write_txn()?;
        let events = env.create_database::<Bytes, Bytes>(&mut wtxn, Some(EVENTS))?;
        let by_created = env.create_database::<Bytes, Bytes>(&mut wtxn, Some(BY_CREATED))?;
        let by_pubkey = env.create_database::<Bytes, Bytes>(&mut wtxn, Some(BY_PUBKEY))?;
        let by_kind = env.create_database::<Bytes, Bytes>(&mut wtxn, Some(BY_KIND))?;
        let by_tag = env.create_database::<Bytes, Bytes>(&mut wtxn, Some(BY_TAG))?;
        let by_word = if cfg.search_index {
            Some(env.create_database::<Bytes, Bytes>(&mut wtxn, Some(BY_WORD))?)
        } else {
            None
        };
        let event_meta = env.create_database::<Bytes, Bytes>(&mut wtxn, Some(EVENT_META))?;
        let deleted = env.create_database::<Bytes, Bytes>(&mut wtxn, Some(DELETED))?;
        let expiry = env.create_database::<Bytes, Bytes>(&mut wtxn, Some(EXPIRY))?;
        let replaceable = env.create_database::<Bytes, Bytes>(&mut wtxn, Some(REPLACEABLE))?;
        let vanish = env.create_database::<Bytes, Bytes>(&mut wtxn, Some(VANISH))?;
        let banned = env.create_database::<Bytes, Bytes>(&mut wtxn, Some(BANNED))?;
        let first_seen = env.create_database::<Bytes, Bytes>(&mut wtxn, Some(FIRST_SEEN))?;
        let access = env.create_database::<Bytes, Bytes>(&mut wtxn, Some(ACCESS))?;
        let blossom = env.create_database::<Bytes, Bytes>(&mut wtxn, Some(BLOSSOM))?;
        let groups = env.create_database::<Bytes, Bytes>(&mut wtxn, Some(GROUPS))?;
        let roles = env.create_database::<Bytes, Bytes>(&mut wtxn, Some(ROLES))?;
        let purged_groups = env.create_database::<Bytes, Bytes>(&mut wtxn, Some(PURGED_GROUPS))?;
        let purge_pending = env.create_database::<Bytes, Bytes>(&mut wtxn, Some(PURGE_PENDING))?;
        let vanish_pending =
            env.create_database::<Bytes, Bytes>(&mut wtxn, Some(VANISH_PENDING))?;
        let delete_pending =
            env.create_database::<Bytes, Bytes>(&mut wtxn, Some(DELETE_PENDING))?;
        let index_meta = env.create_database::<Bytes, Bytes>(&mut wtxn, Some(INDEX_META))?;
        wtxn.commit()?;
        // The word-index limit is persisted with the index it describes: a
        // config change between restarts must not make put/remove
        // asymmetric (removing an event indexed with the old limit would
        // leave stale word keys, or clear a marker that the old limit
        // wrote).
        let configured_words = max_indexed_words.max(1);
        let indexed_words = if by_word.is_some() {
            let mut wtxn = env.write_txn()?;
            let value = match index_meta.get(&wtxn, b"word_limit")? {
                Some(raw) if raw.len() >= 8 => {
                    u64::from_be_bytes(raw[..8].try_into().unwrap()) as usize
                }
                _ => {
                    index_meta.put(
                        &mut wtxn,
                        b"word_limit",
                        &(configured_words as u64).to_be_bytes(),
                    )?;
                    configured_words
                }
            };
            wtxn.commit()?;
            if value != configured_words {
                log::warn!(
                    "search.max_indexed_words changed from {value} to {configured_words}; \
                     the existing word index keeps its original limit (put/remove stay \
                     symmetric) until the index is rebuilt"
                );
            }
            value
        } else {
            configured_words
        };
        let tables = if by_word.is_some() { 22 } else { 21 };
        log::info!(
            "database ready at {} ({} tables, map {} MiB)",
            cfg.path.display(),
            tables,
            map_size / (1024 * 1024)
        );
        Ok(Store {
            env,
            events,
            by_created,
            by_pubkey,
            by_kind,
            by_tag,
            by_word,
            event_meta: Some(event_meta),
            meta_index: cfg.meta_index,
            deleted,
            expiry,
            replaceable,
            vanish,
            banned,
            first_seen,
            access,
            blossom,
            groups,
            roles,
            purged_groups,
            purge_pending,
            vanish_pending,
            delete_pending,
            index_meta,
            expiry_enabled,
            cancel: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            max_indexed_words: max_indexed_words.max(1),
            indexed_words,
            map_max_size,
            df_cache: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            #[cfg(test)]
            fail_next_commit: std::sync::atomic::AtomicBool::new(false),
            disabled_fsync: cfg.disabled_fsync,
            #[cfg(test)]
            panic_next_write: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            #[cfg(test)]
            panic_next_read: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            #[cfg(test)]
            fail_next_purge_chunk: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            fail_next_vanish_chunk: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            fail_next_delete_chunk: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            fail_next_scan: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// The map is opened at its maximum size and never resized at runtime:
    /// LMDB's `mdb_env_set_mapsize` requires that no transactions are
    /// active, which cannot be guaranteed now that the shared reader and
    /// the dedicated API reader threads hold concurrent read transactions.
    /// Returns `false` (the map cannot grow), so a commit that fills the
    /// map fails with `MapFull` and the caller revokes the batch.
    pub(crate) fn grow_map(&self) -> bool {
        log::error!(
            "database map is full ({} bytes, map_max_size)",
            self.map_max_size
        );
        false
    }

    /// Free bytes on the filesystem hosting the data directory, when
    /// statvfs succeeds.
    /// Returns an error when the disk is too full to safely write to the
    /// memory map (writing to a full disk raises SIGBUS and kills the
    /// process): every writing path must refuse to commit below the margin.
    pub(crate) fn disk_full_error(&self) -> Result<()> {
        if let Some(free) = self.free_space()
            && disk_below_margin(free)
        {
            return Err(crate::error::storage_full());
        }
        Ok(())
    }

    pub(crate) fn free_space(&self) -> Option<u64> {
        path_free_space(self.env.path())
    }

    pub(crate) fn size_on_disk(&self) -> u64 {
        self.env.real_disk_size().unwrap_or(0)
    }

    /// A copy of the store for the dedicated reader thread: the heed `Env`
    /// handle is reference-counted and the database handles are plain ids,
    /// so both threads share the same underlying environment.
    pub(crate) fn clone_for_reader(&self) -> Store {
        Store {
            env: self.env.clone(),
            events: self.events,
            by_created: self.by_created,
            by_pubkey: self.by_pubkey,
            by_kind: self.by_kind,
            by_tag: self.by_tag,
            by_word: self.by_word,
            event_meta: self.event_meta,
            meta_index: self.meta_index,
            deleted: self.deleted,
            expiry: self.expiry,
            replaceable: self.replaceable,
            vanish: self.vanish,
            banned: self.banned,
            first_seen: self.first_seen,
            access: self.access,
            blossom: self.blossom,
            groups: self.groups,
            roles: self.roles,
            purged_groups: self.purged_groups,
            purge_pending: self.purge_pending,
            vanish_pending: self.vanish_pending,
            delete_pending: self.delete_pending,
            index_meta: self.index_meta,
            expiry_enabled: Arc::clone(&self.expiry_enabled),
            cancel: Arc::clone(&self.cancel),
            max_indexed_words: self.max_indexed_words,
            indexed_words: self.indexed_words,
            map_max_size: self.map_max_size,
            df_cache: Arc::clone(&self.df_cache),
            #[cfg(test)]
            fail_next_commit: std::sync::atomic::AtomicBool::new(false),
            disabled_fsync: self.disabled_fsync,
            // The panic hooks are shared: a test arms the store before the
            // threads start, and exactly one handler (writer or reader)
            // consumes the one-shot flag.
            #[cfg(test)]
            panic_next_write: Arc::clone(&self.panic_next_write),
            #[cfg(test)]
            panic_next_read: Arc::clone(&self.panic_next_read),
            #[cfg(test)]
            fail_next_purge_chunk: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            fail_next_vanish_chunk: std::sync::atomic::AtomicBool::new(false),
            // The writer owns the original store, so a plain flag is
            // enough (same lifecycle as the purge/vanish hooks).
            #[cfg(test)]
            fail_next_delete_chunk: std::sync::atomic::AtomicBool::new(false),
            // Shared like `panic_next_read`: a test arms the store before
            // the reader threads start and exactly one reader consumes it.
            #[cfg(test)]
            fail_next_scan: Arc::clone(&self.fail_next_scan),
        }
    }

    /// Attaches the shutdown cancellation flag (see `Store::cancel`). The
    /// store is built before the `DbClient` thread plumbing exists, so the
    /// flag is injected once at [`super::DbClient`] construction, before
    /// any thread or reader clone is spawned.
    pub(crate) fn set_cancel(&mut self, cancel: Arc<std::sync::atomic::AtomicBool>) {
        self.cancel = cancel;
    }

    /// Whether the process is shutting down: the chunked removals check
    /// this between chunks and stop early, leaving their pending record for
    /// the next startup.
    pub(crate) fn cancelled(&self) -> bool {
        self.cancel.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Persists the access control lists under a single fixed key. The
    /// whole `AccessControl` is serialized as JSON so NIP-86 mutations
    /// survive restarts.
    pub(crate) fn save_access(&self, access: &crate::config::AccessControl) -> Result<()> {
        self.disk_full_error()?;
        let data = serde_json::to_vec(access)?;
        let mut wtxn = self.env.write_txn()?;
        self.access.put(&mut wtxn, b"access", &data)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Persists the NIP-29 group state snapshot under a single fixed key.
    /// Written on every group mutation (join/leave/moderation/vanish), so
    /// restarts restore groups without replaying the full history.
    pub(crate) fn save_groups(&self, snap: &crate::nips::nip29::GroupsSnapshot) -> Result<()> {
        self.disk_full_error()?;
        let data = serde_json::to_vec(snap)?;
        let mut wtxn = self.env.write_txn()?;
        self.groups.put(&mut wtxn, b"groups:snapshot", &data)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Drops the persisted NIP-29 group snapshot, forcing the next startup
    /// to rebuild the group state from the surviving events (a snapshot that
    /// predates a vanish must never be restored as authoritative).
    pub(crate) fn clear_groups_snapshot(&self) -> Result<()> {
        self.disk_full_error()?;
        let mut wtxn = self.env.write_txn()?;
        self.groups.delete(&mut wtxn, b"groups:snapshot")?;
        wtxn.commit()?;
        Ok(())
    }

    /// Loads the persisted NIP-29 group state snapshot, if any. `None`
    /// means no snapshot was ever written (pre-persistence database): the
    /// caller runs the event-replay migration instead.
    pub(crate) fn load_groups(&self) -> Result<Option<crate::nips::nip29::GroupsSnapshot>> {
        let rtxn = self.env.read_txn()?;
        let Some(raw) = self.groups.get(&rtxn, b"groups:snapshot")? else {
            return Ok(None);
        };
        Ok(Some(serde_json::from_slice(raw)?))
    }

    /// Persists the NIP-43 role state snapshot under a single fixed key.
    /// Same lifecycle as [`Self::save_groups`].
    pub(crate) fn save_roles(&self, snap: &crate::nips::nip43::RolesSnapshot) -> Result<()> {
        self.disk_full_error()?;
        let data = serde_json::to_vec(snap)?;
        let mut wtxn = self.env.write_txn()?;
        self.roles.put(&mut wtxn, b"roles:snapshot", &data)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Loads the persisted NIP-43 role state snapshot, if any (see
    /// [`Self::load_groups`]).
    pub(crate) fn load_roles(&self) -> Result<Option<crate::nips::nip43::RolesSnapshot>> {
        let rtxn = self.env.read_txn()?;
        let Some(raw) = self.roles.get(&rtxn, b"roles:snapshot")? else {
            return Ok(None);
        };
        Ok(Some(serde_json::from_slice(raw)?))
    }

    /// Loads the persisted access control lists, if any.
    pub(crate) fn load_access(&self) -> Result<Option<crate::config::AccessControl>> {
        let rtxn = self.env.read_txn()?;
        let Some(raw) = self.access.get(&rtxn, b"access")? else {
            return Ok(None);
        };
        Ok(Some(serde_json::from_slice(raw)?))
    }

    /// Loads the persisted Blossom upload allowlist (empty when none).
    /// The list is written by the CLI commands (`nostrfy blossom allow/deny`),
    /// which open the same environment from their own process.
    pub(crate) fn load_blossom_allow(&self) -> Result<Vec<String>> {
        let rtxn = self.env.read_txn()?;
        let Some(raw) = self.access.get(&rtxn, b"blossom_allow")? else {
            return Ok(Vec::new());
        };
        Ok(serde_json::from_slice(raw)?)
    }

    /// Persists a blob's metadata and adds an owner to it, atomically:
    /// the `sha:<sha>` entry holds mime/size/uploaded/owners and each owner
    /// gets a `own:<pubkey-hex>:<sha>` reverse key for `/list`.
    pub(crate) fn add_blossom_mapping(
        &self,
        sha256: &str,
        mime: &str,
        size: u64,
        uploaded: i64,
        pubkey: &str,
    ) -> Result<()> {
        self.disk_full_error()?;
        let mut wtxn = self.env.write_txn()?;
        let key = format!("sha:{sha256}");
        let existing: Option<BlossomMeta> = match self.blossom.get(&wtxn, key.as_bytes())? {
            Some(raw) => match serde_json::from_slice(raw) {
                Ok(meta) => Some(meta),
                Err(e) => {
                    log::warn!("corrupt blossom mapping for {sha256}: {e}");
                    None
                }
            },
            None => None,
        };
        let mut meta = existing.unwrap_or_else(|| BlossomMeta {
            sha256: sha256.to_string(),
            size,
            mime: mime.to_string(),
            uploaded,
            owners: Vec::new(),
        });
        if !meta.owners.iter().any(|o| o == pubkey) {
            if meta.owners.len() >= MAX_BLOB_OWNERS {
                return Err(anyhow::anyhow!(
                    "the blob already has the maximum of {MAX_BLOB_OWNERS} owners"
                ));
            }
            meta.owners.push(pubkey.to_string());
            // Keep the uploaded-order index in sync: BUD-12 pages iterate
            // it instead of scanning the sha-ordered reverse index.
            self.blossom.put(
                &mut wtxn,
                blossom_order_key(pubkey, meta.uploaded, sha256).as_bytes(),
                b"",
            )?;
        }
        self.blossom
            .put(&mut wtxn, key.as_bytes(), &serde_json::to_vec(&meta)?)?;
        self.blossom
            .put(&mut wtxn, format!("own:{pubkey}:{sha256}").as_bytes(), b"")?;
        wtxn.commit()?;
        Ok(())
    }

    /// Adds many owners to the mapping in one transaction (used by the
    /// one-time automatic migration).
    pub(crate) fn add_blossom_mappings(
        &self,
        entries: &[(String, String, u64, i64, String)],
    ) -> Result<()> {
        self.disk_full_error()?;
        let mut wtxn = self.env.write_txn()?;
        for (sha256, mime, size, uploaded, pubkey) in entries {
            let key = format!("sha:{sha256}");
            if let Some(raw) = self.blossom.get(&wtxn, key.as_bytes())? {
                // Legacy multi-owner blobs appear once per npub directory:
                // merge the owner into the existing mapping instead of
                // dropping it (up to the per-blob owner cap).
                match serde_json::from_slice::<BlossomMeta>(raw) {
                    Ok(meta)
                        if !meta.owners.iter().any(|o| o == pubkey)
                            && meta.owners.len() < MAX_BLOB_OWNERS =>
                    {
                        let mut meta = meta;
                        meta.owners.push(pubkey.clone());
                        self.blossom
                            .put(&mut wtxn, key.as_bytes(), &serde_json::to_vec(&meta)?)?;
                        self.blossom.put(
                            &mut wtxn,
                            format!("own:{pubkey}:{sha256}").as_bytes(),
                            b"",
                        )?;
                        self.blossom.put(
                            &mut wtxn,
                            blossom_order_key(pubkey, meta.uploaded, sha256).as_bytes(),
                            b"",
                        )?;
                    }
                    Ok(_) => {}
                    Err(e) => log::warn!("corrupt blossom mapping for {sha256}: {e}"),
                }
                continue;
            }
            self.blossom.put(
                &mut wtxn,
                key.as_bytes(),
                &serde_json::to_vec(&BlossomMeta {
                    sha256: sha256.clone(),
                    size: *size,
                    mime: mime.clone(),
                    uploaded: *uploaded,
                    owners: vec![pubkey.clone()],
                })?,
            )?;
            self.blossom
                .put(&mut wtxn, format!("own:{pubkey}:{sha256}").as_bytes(), b"")?;
            self.blossom.put(
                &mut wtxn,
                blossom_order_key(pubkey, *uploaded, sha256).as_bytes(),
                b"",
            )?;
        }
        wtxn.commit()?;
        Ok(())
    }

    /// Whether the one-time legacy migration already ran (marker key).
    pub(crate) fn blossom_migration_done(&self) -> Result<bool> {
        let rtxn = self.env.read_txn()?;
        Ok(self.blossom.get(&rtxn, b"migrated")?.is_some())
    }

    /// Marks the one-time legacy migration as done.
    pub(crate) fn mark_blossom_migration(&self) -> Result<()> {
        self.disk_full_error()?;
        let mut wtxn = self.env.write_txn()?;
        self.blossom.put(&mut wtxn, b"migrated", b"")?;
        wtxn.commit()?;
        Ok(())
    }

    /// Loads a blob's metadata (None when unknown).
    pub(crate) fn load_blossom_mapping(&self, sha256: &str) -> Result<Option<BlossomMeta>> {
        let rtxn = self.env.read_txn()?;
        self.load_blossom_mapping_in(&rtxn, sha256)
    }

    /// [`Self::load_blossom_mapping`] inside an existing read transaction:
    /// `list_blossom_page` resolves the sha of every walked entry, and a
    /// nested read transaction per entry would consume a second LMDB reader
    /// slot (the floor in `open` accounts for the nesting, but sharing the
    /// walk's transaction avoids it entirely).
    fn load_blossom_mapping_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        sha256: &str,
    ) -> Result<Option<BlossomMeta>> {
        let key = format!("sha:{sha256}");
        let Some(raw) = self.blossom.get(rtxn, key.as_bytes())? else {
            return Ok(None);
        };
        match serde_json::from_slice(raw) {
            Ok(meta) => Ok(Some(meta)),
            Err(e) => {
                log::warn!("corrupt blossom mapping for {sha256}: {e}");
                Ok(None)
            }
        }
    }

    /// Removes one owner from a blob's metadata and its reverse key.
    /// Returns whether the blob had this owner.
    pub(crate) fn remove_blossom_owner(&self, sha256: &str, pubkey: &str) -> Result<bool> {
        self.disk_full_error()?;
        let mut wtxn = self.env.write_txn()?;
        let key = format!("sha:{sha256}");
        let Some(raw) = self.blossom.get(&wtxn, key.as_bytes())? else {
            return Ok(false);
        };
        let Some(mut meta) = (match serde_json::from_slice::<BlossomMeta>(raw) {
            Ok(meta) => Some(meta),
            Err(e) => {
                log::warn!("corrupt blossom mapping for {sha256}: {e}");
                None
            }
        }) else {
            return Ok(false);
        };
        let before = meta.owners.len();
        meta.owners.retain(|o| o != pubkey);
        if meta.owners.len() == before {
            return Ok(false);
        }
        self.blossom
            .delete(&mut wtxn, format!("own:{pubkey}:{sha256}").as_bytes())?;
        self.blossom.delete(
            &mut wtxn,
            blossom_order_key(pubkey, meta.uploaded, sha256).as_bytes(),
        )?;
        self.blossom.delete(&mut wtxn, key.as_bytes())?;
        if !meta.owners.is_empty() {
            self.blossom
                .put(&mut wtxn, key.as_bytes(), &serde_json::to_vec(&meta)?)?;
        }
        wtxn.commit()?;
        Ok(true)
    }

    /// Blob hashes uploaded by a pubkey (hex), via the reverse index,
    /// capped at `limit` entries: `GET /list` pages through cursors, so an
    /// unbounded walk for a heavy uploader would materialize hundreds of
    /// thousands of entries per request.
    #[cfg(test)]
    pub(crate) fn list_blossom_shas(&self, pubkey: &str, limit: usize) -> Result<Vec<String>> {
        let rtxn = self.env.read_txn()?;
        let prefix = format!("own:{pubkey}:");
        let mut out = Vec::new();
        let mut iter = self.blossom.prefix_iter(&rtxn, prefix.as_bytes())?;
        while out.len() < limit {
            let Some((key, _)) = iter.next().transpose()? else {
                break;
            };
            let key = String::from_utf8_lossy(key);
            if let Some(sha) = key.strip_prefix(&prefix) {
                out.push(sha.to_string());
            }
        }
        Ok(out)
    }

    /// BUD-12 page: the owner's blobs strictly before the cursor, newest
    /// `uploaded` first, from the uploaded-order index. Returns the sha and
    /// its mapping per entry.
    pub(crate) fn list_blossom_page(
        &self,
        pubkey: &str,
        after_uploaded: Option<u64>,
        after_sha: Option<&str>,
        limit: usize,
    ) -> Result<Vec<(String, BlossomMeta)>> {
        let rtxn = self.env.read_txn()?;
        let prefix = format!("{BLOSSOM_ORDER_PREFIX}{pubkey}:");
        let mut upper_buf: Vec<u8> = Vec::new();
        if let (Some(uploaded), Some(sha)) = (after_uploaded, after_sha) {
            // The cursor must reproduce the key's `:` separator: without it
            // the exclusive bound lands inside the previous key and the same
            // page is served again. The index stores lowercase hex.
            upper_buf = format!("{prefix}{uploaded:020}:{}", sha.to_ascii_lowercase()).into_bytes();
        }
        let upper: std::ops::Bound<&[u8]> = if upper_buf.is_empty() {
            // The whole owner range: `bls:<pubkey>:` up to the next prefix.
            let mut end = prefix.clone().into_bytes();
            *end.last_mut().unwrap() += 1;
            upper_buf = end;
            std::ops::Bound::Excluded(upper_buf.as_slice())
        } else {
            std::ops::Bound::Excluded(upper_buf.as_slice())
        };
        let mut out = Vec::new();
        for item in self.blossom.rev_range(
            &rtxn,
            &(std::ops::Bound::Included(prefix.as_bytes()), upper),
        )? {
            if out.len() >= limit {
                break;
            }
            let (key, _) = item?;
            let rest = &key[prefix.len()..];
            // `<uploaded:020>:<sha256 hex>`; anything else does not come
            // from the uploaded-order index (e.g. the sharded `own:` rows a
            // legacy database may still carry) and must be skipped.
            if rest.len() != 20 + 1 + 64 {
                continue;
            }
            let sha = &rest[21..];
            let Ok(sha) = std::str::from_utf8(sha) else {
                continue;
            };
            let Some(meta) = self.load_blossom_mapping_in(&rtxn, sha)? else {
                // A stale order key (mapping deleted): skip it.
                continue;
            };
            if !meta.owners.iter().any(|o| o == pubkey) {
                continue;
            }
            out.push((sha.to_string(), meta));
        }
        Ok(out)
    }

    /// Whether the uploaded-order index has been built (marker key).
    pub(crate) fn blossom_order_needs_rebuild(&self) -> Result<bool> {
        let rtxn = self.env.read_txn()?;
        Ok(self.index_meta.get(&rtxn, b"blossom_order")?.is_none())
    }

    /// Builds the uploaded-order index from the existing mappings (one-time
    /// backfill for databases written before the index existed).
    pub(crate) fn rebuild_blossom_order(&self) -> Result<usize> {
        const CHUNK: usize = 4096;
        self.disk_full_error()?;
        let mut count = 0usize;
        // Resume from the last mapping key processed: resuming from the
        // owner entries could split one mapping's owner list across chunks
        // and lose the owners after the cut.
        let mut last: Option<Vec<u8>> = None;
        loop {
            // One bounded read + one bounded write transaction per chunk
            // (like `rebuild_event_meta`): a huge table must not pin one
            // unbounded write transaction, and a MapFull aborts only the
            // current chunk instead of the whole rebuild. The completion
            // marker is written last, so a crash mid-rebuild leaves the
            // rebuild pending and a retry rewrites the same idempotent keys.
            let chunk: Vec<(Vec<u8>, String, i64, String)> = {
                let rtxn = self.env.read_txn()?;
                let range = (
                    last.as_deref()
                        .map(std::ops::Bound::Excluded)
                        .unwrap_or(std::ops::Bound::Unbounded),
                    std::ops::Bound::Unbounded,
                );
                let mut out = Vec::with_capacity(CHUNK);
                for item in self.blossom.range(&rtxn, &range)? {
                    let (key, raw) = item?;
                    let key_text = String::from_utf8_lossy(key);
                    let Some(sha) = key_text.strip_prefix("sha:") else {
                        continue;
                    };
                    let Ok(meta) = serde_json::from_slice::<BlossomMeta>(raw) else {
                        continue;
                    };
                    for owner in &meta.owners {
                        out.push((key.to_vec(), owner.clone(), meta.uploaded, sha.to_string()));
                    }
                    // The chunk may exceed CHUNK by one mapping's owners
                    // (bounded by `MAX_BLOB_OWNERS`), but it always ends on
                    // a mapping boundary.
                    if out.len() >= CHUNK {
                        break;
                    }
                }
                out
            };
            if chunk.is_empty() {
                break;
            }
            last = Some(chunk.last().expect("non-empty chunk").0.clone());
            let mut wtxn = self.env.write_txn()?;
            for (_, owner, uploaded, sha) in &chunk {
                self.blossom.put(
                    &mut wtxn,
                    blossom_order_key(owner, *uploaded, sha).as_bytes(),
                    b"",
                )?;
                count += 1;
            }
            wtxn.commit()?;
            if chunk.len() < CHUNK {
                break;
            }
        }
        let mut wtxn = self.env.write_txn()?;
        self.index_meta.put(&mut wtxn, b"blossom_order", b"1")?;
        wtxn.commit()?;
        Ok(count)
    }

    /// One page of vanished pubkeys, ordered by key, strictly after
    /// `after`. Paging keeps the startup collection bounded: materializing
    /// every key at once cost hundreds of MB on a relay with millions of
    /// vanish markers.
    pub(crate) fn vanish_pubkeys_page(
        &self,
        after: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<Vec<u8>>> {
        let rtxn = self.env.read_txn()?;
        let range = match after {
            Some(key) => (std::ops::Bound::Excluded(key), std::ops::Bound::Unbounded),
            None => (std::ops::Bound::Unbounded, std::ops::Bound::Unbounded),
        };
        let mut out = Vec::new();
        for item in self.vanish.range(&rtxn, &range)? {
            let (key, _) = item?;
            out.push(key.to_vec());
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }

    /// One page of vanished pubkeys as raw 32-byte keys, strictly after
    /// `after`. The rebuilds only need the decoded key (the hex spellings
    /// cost two extra `String`s per entry), and a paged reader keeps the
    /// startup collection bounded. Corrupt short/long keys are skipped with
    /// a warning instead of aborting the page.
    pub(crate) fn vanish_pubkeys_raw_page(
        &self,
        after: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<[u8; 32]>> {
        let rtxn = self.env.read_txn()?;
        let range = match after {
            Some(key) => (std::ops::Bound::Excluded(key), std::ops::Bound::Unbounded),
            None => (std::ops::Bound::Unbounded, std::ops::Bound::Unbounded),
        };
        let mut out = Vec::new();
        for item in self.vanish.range(&rtxn, &range)? {
            let (key, _) = item?;
            match <[u8; 32]>::try_from(key) {
                Ok(key) => out.push(key),
                Err(_) => log::warn!(
                    "skipping corrupt vanish key ({} bytes) while paging",
                    key.len()
                ),
            }
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }

    /// Persists the relay pubkey access lists ((pubkey, reason) pairs for
    /// the deny and allow lists) under a single fixed key, so the CLI
    /// commands (`nostrfy relay allow/deny`) and the running server share
    /// one source of truth without touching the config file.
    pub(crate) fn save_relay_pubkeys(
        &self,
        deny: &[(String, String)],
        allow: &[(String, String)],
    ) -> Result<()> {
        self.disk_full_error()?;
        let data = relay_pubkeys_json(deny, allow)?;
        let mut wtxn = self.env.write_txn()?;
        self.access.put(&mut wtxn, b"relay_pubkeys", &data)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Persists the access blob and the relay pubkey deny/allow lists in a
    /// single transaction: a crash (or a failed second write) can never
    /// leave the relay-level bans and the access rules from two different
    /// generations, which the separate save calls allowed (the reload reads
    /// both and would mix them).
    pub(crate) fn save_access_and_pubkeys(
        &self,
        access: &crate::config::AccessControl,
        deny: &[(String, String)],
        allow: &[(String, String)],
    ) -> Result<()> {
        self.disk_full_error()?;
        let access_data = serde_json::to_vec(access)?;
        let lists_data = relay_pubkeys_json(deny, allow)?;
        let mut wtxn = self.env.write_txn()?;
        self.access.put(&mut wtxn, b"access", &access_data)?;
        self.access.put(&mut wtxn, b"relay_pubkeys", &lists_data)?;
        // Test-only fault injection (shared with the put batch path): an
        // aborted commit must leave *both* keys at their previous values.
        #[cfg(test)]
        let commit = if self
            .fail_next_commit
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            Err(heed::Error::Mdb(heed::MdbError::MapFull))
        } else {
            wtxn.commit()
        };
        #[cfg(not(test))]
        let commit = wtxn.commit();
        commit?;
        Ok(())
    }

    /// Persists the Blossom upload allowlist under a single fixed key, so
    /// the CLI command (`nostrfy blossom allow/deny`) and the running
    /// server share one source of truth without touching the config file.
    pub(crate) fn save_blossom_allow(&self, entries: &[String]) -> Result<()> {
        self.disk_full_error()?;
        let data = serde_json::to_vec(entries)?;
        let mut wtxn = self.env.write_txn()?;
        self.access.put(&mut wtxn, b"blossom_allow", &data)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Loads the persisted relay pubkey access lists ((deny, allow)).
    pub(crate) fn load_relay_pubkeys(&self) -> Result<RelayPubkeyLists> {
        let rtxn = self.env.read_txn()?;
        let Some(raw) = self.access.get(&rtxn, b"relay_pubkeys")? else {
            return Ok((Vec::new(), Vec::new()));
        };
        let value: serde_json::Value = serde_json::from_slice(raw)?;
        let deny = serde_json::from_value(value.get("deny").cloned().unwrap_or_default())?;
        let allow = serde_json::from_value(value.get("allow").cloned().unwrap_or_default())?;
        Ok((deny, allow))
    }

    /// One-time migration for databases written before the pubkey lists
    /// moved out of the `access` blob: when the dedicated `relay_pubkeys`
    /// key is absent but the old blob carries pubkey entries, copy them
    /// over. Runs at startup and from the CLI commands, before any request
    /// is served.
    pub(crate) fn migrate_access_pubkeys(&self) -> Result<()> {
        migrate_access_pubkeys(&self.env, &self.access)
    }

    /// Row counts of every bookkeeping table that grows with removals, for
    /// the operator gauges (see [`TableCounts`]).
    pub(crate) fn table_counts(&self) -> Result<TableCounts> {
        let rtxn = self.env.read_txn()?;
        Ok(TableCounts {
            deleted: self.deleted.len(&rtxn)?,
            first_seen: self.first_seen.len(&rtxn)?,
            purged_groups: self.purged_groups.len(&rtxn)?,
            vanish: self.vanish.len(&rtxn)?,
            vanish_pending: self.vanish_pending.len(&rtxn)?,
            purge_pending: self.purge_pending.len(&rtxn)?,
            delete_pending: self.delete_pending.len(&rtxn)?,
        })
    }

    /// Records an in-progress NIP-09 deletion before its first removal
    /// chunk. The key is the request digest, so re-recording the same
    /// request (a re-delivery or a startup resume) overwrites its own
    /// record instead of accumulating duplicates.
    pub(crate) fn put_pending_deletion(&self, key: &[u8], encoded: &[u8]) -> Result<()> {
        self.disk_full_error()?;
        let mut wtxn = self.env.write_txn()?;
        self.delete_pending.put(&mut wtxn, key, encoded)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Clears one completed NIP-09 deletion record. A failed clear leaves
    /// the record in place: the next startup replays the (idempotent) walk
    /// instead of assuming the removal completed.
    pub(crate) fn clear_pending_deletion(&self, key: &[u8]) -> Result<()> {
        self.disk_full_error()?;
        let mut wtxn = self.env.write_txn()?;
        self.delete_pending.delete(&mut wtxn, key)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Every started-but-unfinished NIP-09 deletion, decoded for the
    /// startup resume and the metrics. A malformed record is skipped with a
    /// warning (like the vanish records): one corrupt entry must not abort
    /// the resume of the healthy requests.
    pub(crate) fn pending_deletions(&self) -> Result<Vec<PendingDeletion>> {
        let rtxn = self.env.read_txn()?;
        let mut out = Vec::new();
        for item in self.delete_pending.iter(&rtxn)? {
            let (_, raw) = item?;
            match decode_pending_deletion(raw) {
                Some(request) => out.push(request),
                None => log::warn!(
                    "skipping corrupt pending deletion record ({} bytes)",
                    raw.len()
                ),
            }
        }
        Ok(out)
    }
}

/// The JSON encoding shared by [`Store::save_relay_pubkeys`] and the
/// combined [`Store::save_access_and_pubkeys`], so both write the exact
/// same representation.
fn relay_pubkeys_json(deny: &[(String, String)], allow: &[(String, String)]) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(
        &serde_json::json!({ "deny": deny, "allow": allow }),
    )?)
}

/// Shared migration used by both the relay server (`Store`) and the CLI
/// commands (`nostrfy relay allow/deny`), which open the environment from
/// their own process: without it, a CLI write before the first post-upgrade
/// server start would silently skip the legacy entries.
pub(crate) fn migrate_access_pubkeys(env: &Env, access: &Database<Bytes, Bytes>) -> Result<()> {
    // Disk-full guard like every other write path: committing a migration
    // on a full disk would SIGBUS-kill the process (server at startup, CLI
    // before the first post-upgrade start) instead of failing cleanly.
    check_env_space(env)?;
    let rtxn = env.read_txn()?;
    if access.get(&rtxn, b"relay_pubkeys")?.is_some() {
        return Ok(());
    }
    let Some(raw) = access.get(&rtxn, b"access")? else {
        return Ok(());
    };
    let value: serde_json::Value = serde_json::from_slice(raw)?;
    let entries = |name: &str| -> Vec<(String, String)> {
        value
            .get(name)
            .and_then(serde_json::Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|v| match v {
                        serde_json::Value::String(s) => Some((s.clone(), String::new())),
                        serde_json::Value::Array(a) if a.len() >= 2 => Some((
                            a[0].as_str().unwrap_or("").to_string(),
                            a[1].as_str().unwrap_or("").to_string(),
                        )),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    let deny = entries("blocked_pubkeys");
    let allow = entries("allowed_pubkeys");
    if deny.is_empty() && allow.is_empty() {
        return Ok(());
    }
    let data = serde_json::to_vec(&serde_json::json!({ "deny": deny, "allow": allow }))?;
    let mut wtxn = env.write_txn()?;
    access.put(&mut wtxn, b"relay_pubkeys", &data)?;
    wtxn.commit()?;
    Ok(())
}

// ----- key builders -----

pub(crate) fn created_key(created: u64, id: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(CREATED_LEN + ID_LEN);
    key.extend_from_slice(&created.to_be_bytes());
    key.extend_from_slice(id);
    key
}

pub(crate) fn pubkey_key(pubkey: &[u8], created: u64, id: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(ID_LEN + CREATED_LEN + ID_LEN);
    key.extend_from_slice(pubkey);
    key.extend_from_slice(&created.to_be_bytes());
    key.extend_from_slice(id);
    key
}

pub(crate) fn kind_key(kind: u64, created: u64, id: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(CREATED_LEN * 2 + ID_LEN);
    key.extend_from_slice(&kind.to_be_bytes());
    key.extend_from_slice(&created.to_be_bytes());
    key.extend_from_slice(id);
    key
}

pub(crate) fn tag_key(name: u8, value: &[u8], created: u64, id: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + 1 + 4 + value.len() + CREATED_LEN + ID_LEN);
    key.push(name);
    key.push(0x00);
    key.extend_from_slice(&(value.len() as u32).to_be_bytes());
    key.extend_from_slice(value);
    key.extend_from_slice(&created.to_be_bytes());
    key.extend_from_slice(id);
    key
}

pub(crate) fn tag_range(name: u8, value: &[u8], since: u64, until: u64) -> (Vec<u8>, Vec<u8>) {
    let prefix_len = 1 + 1 + 4 + value.len();
    let mut start = Vec::with_capacity(prefix_len + CREATED_LEN + ID_LEN);
    start.push(name);
    start.push(0x00);
    start.extend_from_slice(&(value.len() as u32).to_be_bytes());
    start.extend_from_slice(value);
    start.extend_from_slice(&since.to_be_bytes());
    start.extend_from_slice(&[0u8; ID_LEN]);

    // Exclusive `(until + 1, 0..)`: covers every event with
    // `created_at <= until`. At the maximal timestamp, append a byte after
    // the maximal id so the exclusive bound remains above every fixed-size
    // event key.
    let mut end = Vec::with_capacity(prefix_len + CREATED_LEN + ID_LEN + 1);
    end.extend_from_slice(&start[..prefix_len]);
    end.extend_from_slice(&until.to_be_bytes());
    if until == u64::MAX {
        end.extend_from_slice(&[0xffu8; ID_LEN]);
        end.push(0);
    } else {
        // Replace the `until` field just appended at `prefix_len`: the
        // exclusive bound is `until + 1`. Copying into `[..prefix_len +
        // CREATED_LEN]` would target the whole buffer and panic (the slice
        // length never equals the 8-byte timestamp), aborting every indexed
        // tag scan that carries an explicit `until`.
        end[prefix_len..prefix_len + CREATED_LEN]
            .copy_from_slice(&until.saturating_add(1).to_be_bytes());
        end.extend_from_slice(&[0u8; ID_LEN]);
    }
    (start, end)
}

/// Builds an exclusive upper bound for an index key whose final components
/// are `(created_at, id)`. A maximal timestamp needs a key longer than every
/// valid fixed-size record; otherwise saturating `until + 1` would exclude
/// that timestamp entirely.
pub(crate) fn range_end(mut key: Vec<u8>, until: u64) -> Vec<u8> {
    if until == u64::MAX {
        // Callers always pass a key with a full 32-byte id tail, but a
        // short (corrupt) one must not underflow `len - ID_LEN` and panic
        // the writer mid-removal. Filling the whole key is the safe
        // fallback: it still sorts above every well-formed key with that
        // prefix (0xff is the largest byte), so the range is not silently
        // collapsed to empty and the removal is not dropped.
        match key.len().checked_sub(ID_LEN) {
            Some(id_start) => key[id_start..].fill(0xff),
            None => {
                log::warn!("range_end called with a short {}-byte key", key.len());
                key.fill(0xff);
            }
        }
        key.push(0);
    }
    key
}

pub(crate) fn word_key(word: &str, created: u64, id: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(word.len() + 1 + CREATED_LEN + ID_LEN);
    key.extend_from_slice(word.as_bytes());
    key.push(0x00);
    key.extend_from_slice(&created.to_be_bytes());
    key.extend_from_slice(id);
    key
}

/// Sentinel word marking an event whose content has more tokens than
/// `max_indexed_words`. The word index stores only the first N tokens, so
/// long events also get this marker and the search scan walks those records
/// (checking the full content per event) to find words past the cap. The
/// sentinel contains a NUL byte, which `tokenize` can never produce (its
/// words are alphanumeric), so it cannot collide with a real term.
pub(crate) const WORD_OVERFLOW: &str = "\u{0}overflow";

pub(crate) fn replaceable_key(kind: u64, pubkey: &[u8], dtag: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(CREATED_LEN + ID_LEN + 4 + dtag.len());
    key.extend_from_slice(&kind.to_be_bytes());
    key.extend_from_slice(pubkey);
    key.extend_from_slice(&(dtag.len() as u32).to_be_bytes());
    key.extend_from_slice(dtag.as_bytes());
    key
}

/// Builds the index-key form of a `d` tag: the value itself when it fits
/// under LMDB's key-size limit (see [`MAX_INDEX_KEY`]), otherwise a
/// truncated prefix followed by a 4-byte fingerprint of the full value.
/// The fingerprint guarantees that two distinct long `d` tags sharing the
/// same prefix never collide in the index (a collision would make one
/// replace the other, breaking NIP-33); the stored event keeps its full
/// `d` tag.
pub(crate) fn dtag_key_safe(dtag: &str) -> String {
    dtag_key_safe_max(dtag, MAX_INDEX_KEY.saturating_sub(CREATED_LEN + ID_LEN + 4))
}

/// [`dtag_key_safe`] with an explicit ceiling. The `a`-tag tombstone key
/// spends one extra byte on its prefix, so its `d` component must be one
/// byte shorter than a replaceable slot key's.
fn dtag_key_safe_max(dtag: &str, max: usize) -> String {
    if dtag.len() <= max {
        return dtag.to_string();
    }
    // Reserve 8 hex chars (4 bytes) of fingerprint space.
    let mut end = max.saturating_sub(8);
    while end > 0 && !dtag.is_char_boundary(end) {
        end -= 1;
    }
    let mut key = String::with_capacity(end + 8);
    key.push_str(&dtag[..end]);
    key.push_str(&dtag_fingerprint(dtag));
    key
}

/// 8 hex characters (4 bytes) of the sha256 of `value`.
fn dtag_fingerprint(value: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(value.as_bytes());
    hex::encode(&digest[..4])
}

/// The [`PURGED_GROUPS`] key of a group id: a fixed 32-byte digest, so a
/// group id of any length (tag values reach 1 KiB) fits LMDB's key-size
/// limit and one marker costs the same regardless of the id.
pub(crate) fn purged_group_key(gid: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(gid.as_bytes()).into()
}

/// Encodes a [`PURGED_GROUPS`] marker value: `(purge time, cut)`, both BE
/// u64. The purge time bounds the `kind:9007` re-create exception (only a
/// create *before* the purge is rejected); the cut bounds `h`-tagged
/// re-publications (`created_at <= cut` is rejected), and includes the
/// newest removed event's timestamp so same-second and future-dated
/// purged content cannot be replayed.
pub(crate) fn encode_purged_group_marker(purge_now: u64, cut: u64) -> [u8; 16] {
    let mut value = [0u8; 16];
    value[..8].copy_from_slice(&purge_now.to_be_bytes());
    value[8..].copy_from_slice(&cut.to_be_bytes());
    value
}

/// Decodes a [`PURGED_GROUPS`] marker value into `(purge time, cut)`.
/// Legacy 8-byte markers (written before the value carried the purge time)
/// count as `(cut, cut)`: the purge time is unknown, so reusing the cut
/// keeps the re-create exception as strict as before, and malformed short
/// values block nothing (`(0, 0)`).
pub(crate) fn decode_purged_group_marker(raw: &[u8]) -> (u64, u64) {
    let u64_at = |bytes: &[u8]| u64::from_be_bytes(bytes.try_into().expect("checked length"));
    if raw.len() >= 16 {
        (u64_at(&raw[..8]), u64_at(&raw[8..16]))
    } else if raw.len() >= 8 {
        let cut = u64_at(&raw[..8]);
        (cut, cut)
    } else {
        (0, 0)
    }
}

/// Encodes a [`PURGE_PENDING`] record: `gid length (BE u32) || gid bytes ||
/// purge time (BE u64) || cut (BE u64)`.
pub(crate) fn encode_pending_purge(gid: &str, purge_now: u64, cut: u64) -> Vec<u8> {
    let mut value = Vec::with_capacity(4 + gid.len() + 16);
    value.extend_from_slice(&(gid.len() as u32).to_be_bytes());
    value.extend_from_slice(gid.as_bytes());
    value.extend_from_slice(&purge_now.to_be_bytes());
    value.extend_from_slice(&cut.to_be_bytes());
    value
}

/// Decodes a [`PURGE_PENDING`] record into `(gid, purge time, cut)`.
pub(crate) fn decode_pending_purge(raw: &[u8]) -> Option<(String, u64, u64)> {
    let gid_len = u32::from_be_bytes(raw.get(..4)?.try_into().ok()?) as usize;
    let gid = raw.get(4..4 + gid_len)?;
    let purge_now = u64::from_be_bytes(raw.get(4 + gid_len..4 + gid_len + 8)?.try_into().ok()?);
    let cut = u64::from_be_bytes(
        raw.get(4 + gid_len + 8..4 + gid_len + 16)?
            .try_into()
            .ok()?,
    );
    Some((String::from_utf8(gid.to_vec()).ok()?, purge_now, cut))
}

/// Encodes a [`DELETE_PENDING`] record: the full deletion request
/// (`request_created (BE u64)`, optional requester and group, the `e`-tag
/// targets and the `a`-tag addresses), so the startup resume replays the
/// request without the original event.
pub(crate) fn encode_pending_deletion(
    targets: &[String],
    addresses: &[crate::nips::nip09::Address],
    request_pubkey: Option<&str>,
    request_created: u64,
    group: Option<&str>,
) -> Vec<u8> {
    fn put_str(out: &mut Vec<u8>, value: &str) {
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value.as_bytes());
    }
    fn put_opt_str(out: &mut Vec<u8>, value: Option<&str>) {
        match value {
            Some(value) => {
                out.push(1);
                put_str(out, value);
            }
            None => out.push(0),
        }
    }
    let mut out = Vec::new();
    out.extend_from_slice(&request_created.to_be_bytes());
    put_opt_str(&mut out, request_pubkey);
    put_opt_str(&mut out, group);
    out.extend_from_slice(&(targets.len() as u32).to_be_bytes());
    for target in targets {
        put_str(&mut out, target);
    }
    out.extend_from_slice(&(addresses.len() as u32).to_be_bytes());
    for address in addresses {
        out.extend_from_slice(&address.kind.to_be_bytes());
        put_str(&mut out, &address.pubkey);
        put_str(&mut out, &address.d);
    }
    out
}

/// Decodes a [`DELETE_PENDING`] record (see [`encode_pending_deletion`]).
/// `None` for a truncated/corrupt record, so the caller fails closed
/// instead of replaying a partial deletion scope.
pub(crate) fn decode_pending_deletion(raw: &[u8]) -> Option<PendingDeletion> {
    /// A bounds-checked byte reader for the length-prefixed record fields.
    struct Reader<'a> {
        raw: &'a [u8],
        pos: usize,
    }
    impl<'a> Reader<'a> {
        fn take(&mut self, len: usize) -> Option<&'a [u8]> {
            let end = self.pos.checked_add(len)?;
            let bytes = self.raw.get(self.pos..end)?;
            self.pos = end;
            Some(bytes)
        }
        fn u8(&mut self) -> Option<u8> {
            Some(self.take(1)?[0])
        }
        fn u32(&mut self) -> Option<u32> {
            Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
        }
        fn u64(&mut self) -> Option<u64> {
            Some(u64::from_be_bytes(self.take(8)?.try_into().ok()?))
        }
        fn string(&mut self) -> Option<String> {
            let len = self.u32()? as usize;
            String::from_utf8(self.take(len)?.to_vec()).ok()
        }
        fn opt_string(&mut self) -> Option<Option<String>> {
            match self.u8()? {
                0 => Some(None),
                1 => Some(Some(self.string()?)),
                _ => None,
            }
        }
    }

    let mut reader = Reader { raw, pos: 0 };
    let request_created = reader.u64()?;
    let request_pubkey = reader.opt_string()?;
    let group = reader.opt_string()?;
    let target_count = reader.u32()? as usize;
    let mut targets = Vec::with_capacity(target_count.min(1024));
    for _ in 0..target_count {
        targets.push(reader.string()?);
    }
    let address_count = reader.u32()? as usize;
    let mut addresses = Vec::with_capacity(address_count.min(1024));
    for _ in 0..address_count {
        let kind = reader.u64()?;
        let pubkey = reader.string()?;
        let d = reader.string()?;
        addresses.push(crate::nips::nip09::Address { kind, pubkey, d });
    }
    Some(PendingDeletion {
        targets,
        addresses,
        request_pubkey,
        request_created,
        group,
    })
}

/// The [`DELETE_PENDING`] key of a request: a digest of its encoding, so
/// the fixed-size key is independent of the (unbounded) `e`/`a` tag counts
/// and re-recording the same request is idempotent.
pub(crate) fn pending_deletion_key(encoded: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(encoded).into()
}

/// Tombstone key for an `a`-tag (address) deletion, stored in the
/// [`DELETED`] table. Event ids are exactly 32 bytes, so the one-byte prefix
/// keeps the two key spaces disjoint. The `d` tag is normalized like the
/// replaceable slot key it mirrors, but with one byte less headroom: the
/// prefix counts against LMDB's key-size limit ([`MAX_INDEX_KEY`]), and a
/// full-size slot key plus prefix would exceed it and abort the whole
/// deletion batch (every sibling `e`-tag target rolled back with it).
pub(crate) fn deleted_address_key(kind: u64, pubkey: &[u8], dtag: &str) -> Vec<u8> {
    let safe = dtag_key_safe_max(
        dtag,
        MAX_INDEX_KEY.saturating_sub(1 + CREATED_LEN + ID_LEN + 4),
    );
    debug_assert!(1 + CREATED_LEN + ID_LEN + 4 + safe.len() <= MAX_INDEX_KEY);
    let mut key = Vec::with_capacity(1 + CREATED_LEN + ID_LEN + 4 + safe.len());
    key.push(b'a');
    key.extend_from_slice(&replaceable_key(kind, pubkey, &safe));
    key
}
impl Store {
    // ----- event persistence -----

    /// Whether `pubkey` has requested a NIP-62 vanish: the completed
    /// [`VANISH`] marker or an in-progress [`VANISH_PENDING`] record both
    /// block new events, so a crash between the walk and the marker cannot
    /// reopen a vanished identity before the startup resume completes.
    /// The pending table is usually empty, so the second lookup is skipped.
    fn vanished_or_pending(&self, wtxn: &heed::RwTxn, pubkey: &[u8]) -> Result<bool> {
        if self.vanish.get(wtxn, pubkey)?.is_some() {
            return Ok(true);
        }
        if self.vanish_pending.is_empty(wtxn)? {
            return Ok(false);
        }
        Ok(self.vanish_pending.get(wtxn, pubkey)?.is_some())
    }

    /// Row counts of the NIP-62 bookkeeping: `(completed vanish markers,
    /// pending vanish records)`. Exposed as gauges so operators can see the
    /// (permanently growing) marker table and confirm that interrupted
    /// vanishes were resumed.
    pub(crate) fn vanish_counts(&self) -> Result<(u64, u64)> {
        let rtxn = self.env.read_txn()?;
        Ok((self.vanish.len(&rtxn)?, self.vanish_pending.len(&rtxn)?))
    }

    /// The persistent derived-group-state stamp: 0 when it was never
    /// bumped (fresh/pre-stamp database). See [`STATE_STAMP_KEY`].
    pub(crate) fn state_stamp(&self) -> Result<u64> {
        let rtxn = self.env.read_txn()?;
        Ok(self
            .index_meta
            .get(&rtxn, STATE_STAMP_KEY)?
            .and_then(|raw| raw.get(..8))
            .map(|bytes| u64::from_be_bytes(bytes.try_into().expect("checked length")))
            .unwrap_or(0))
    }

    /// Bumps the derived-group-state stamp inside an open write
    /// transaction, so the stamp and the group-state-relevant removal it
    /// describes commit atomically (a startup stamp comparison can never
    /// observe one without the other). Callers invoke this only when the
    /// transaction actually removed a group-state event.
    pub(crate) fn bump_state_stamp(&self, wtxn: &mut heed::RwTxn) -> Result<()> {
        self.bump_meta_counter(wtxn, STATE_STAMP_KEY)
    }

    /// The persistent derived-state sequence: 0 when no state-relevant
    /// event was ever stored. The maximum of the legacy combined counter
    /// (kept for backward compatibility) and the two per-family counters,
    /// so a snapshot persisted before the split can still be classified as
    /// old. See [`STATE_SEQ_KEY`].
    pub(crate) fn state_seq(&self) -> Result<u64> {
        let rtxn = self.env.read_txn()?;
        let legacy = self.meta_counter(&rtxn, STATE_SEQ_KEY)?;
        let group = self.meta_counter(&rtxn, STATE_SEQ_GROUP_KEY)?;
        let role = self.meta_counter(&rtxn, STATE_SEQ_ROLE_KEY)?;
        Ok(legacy.max(group).max(role))
    }

    /// The persistent NIP-29 group-state sequence: bumped in the same write
    /// transaction as every group-state event put (see
    /// [`state_kind_family`]). The group snapshot restore check compares
    /// against this counter. See [`STATE_SEQ_GROUP_KEY`].
    pub(crate) fn state_seq_group(&self) -> Result<u64> {
        let rtxn = self.env.read_txn()?;
        self.meta_counter(&rtxn, STATE_SEQ_GROUP_KEY)
    }

    /// The persistent NIP-43 role-state sequence (see
    /// [`Self::state_seq_group`] and [`STATE_SEQ_ROLE_KEY`]).
    pub(crate) fn state_seq_role(&self) -> Result<u64> {
        let rtxn = self.env.read_txn()?;
        self.meta_counter(&rtxn, STATE_SEQ_ROLE_KEY)
    }

    /// Reads one 8-byte `INDEX_META` counter (0 when absent).
    fn meta_counter(&self, rtxn: &heed::RoTxn<'_>, key: &[u8]) -> Result<u64> {
        Ok(self
            .index_meta
            .get(rtxn, key)?
            .and_then(|raw| raw.get(..8))
            .map(|bytes| u64::from_be_bytes(bytes.try_into().expect("checked length")))
            .unwrap_or(0))
    }

    /// Bumps the derived-state sequence of one family (and the legacy
    /// combined counter) inside an open write transaction, so the sequence
    /// and the state-relevant put commit atomically: a snapshot claiming
    /// the sequence can never be persisted for a state event whose put did
    /// not commit. Callers invoke this only when the transaction actually
    /// stored a state-relevant event of that family.
    pub(crate) fn bump_state_seq(&self, wtxn: &mut heed::RwTxn, family: StateFamily) -> Result<()> {
        let family_key = match family {
            StateFamily::Group => STATE_SEQ_GROUP_KEY,
            StateFamily::Role => STATE_SEQ_ROLE_KEY,
        };
        self.bump_meta_counter(wtxn, family_key)?;
        self.bump_meta_counter(wtxn, STATE_SEQ_KEY)
    }

    /// Increments one 8-byte `INDEX_META` counter in place (0 when absent),
    /// saturating at `u64::MAX`.
    fn bump_meta_counter(&self, wtxn: &mut heed::RwTxn, key: &[u8]) -> Result<()> {
        let next = self
            .index_meta
            .get(wtxn, key)?
            .and_then(|raw| raw.get(..8))
            .map(|bytes| u64::from_be_bytes(bytes.try_into().expect("checked length")))
            .unwrap_or(0)
            .saturating_add(1);
        self.index_meta.put(wtxn, key, &next.to_be_bytes())?;
        Ok(())
    }

    /// Whether a NIP-29 purge marker blocks `event`: any `h`-tagged event
    /// with `created_at <= cut` is a re-publication of purged history (see
    /// [`PURGED_GROUPS`]). The `kind:9007` re-create is the exception: it
    /// is compared against the purge time alone, so a legitimate re-create
    /// at (or after) the purge passes even when future-dated purged content
    /// pushed the cut past it.
    fn purged_groups_blocks(&self, wtxn: &heed::RwTxn, event: &Event) -> Result<bool> {
        if !event.tags.iter().any(|tag| tag.len() >= 2 && tag[0] == "h") {
            return Ok(false);
        }
        // No group was ever purged: skip the per-tag hashing entirely (the
        // common case for relays that never deleted a group).
        if self.purged_groups.is_empty(wtxn)? {
            return Ok(false);
        }
        for tag in &event.tags {
            if tag.len() < 2 || tag[0] != "h" {
                continue;
            }
            let Some(raw) = self.purged_groups.get(wtxn, &purged_group_key(&tag[1]))? else {
                continue;
            };
            let (purge_now, cut) = decode_purged_group_marker(raw);
            let blocked = if event.kind == crate::nips::nip29::CREATE_GROUP {
                event.created_at < purge_now
            } else {
                event.created_at <= cut
            };
            if blocked {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Applies a put inside the given write transaction. Used by the DB
    /// thread to batch consecutive puts into one commit; the transaction
    /// must be dropped (aborted) by the caller when this returns an error.
    pub(crate) fn put_event_in(
        &self,
        wtxn: &mut heed::RwTxn,
        event: &Event,
        now: u64,
    ) -> Result<PutOutcome> {
        let id = match event.id_bytes() {
            Some(id) => id,
            None => return Ok(PutOutcome::Invalid("invalid id".into())),
        };
        let pubkey = match event.pubkey_bytes() {
            Some(pk) => pk,
            None => return Ok(PutOutcome::Invalid("invalid pubkey".into())),
        };

        if self.vanished_or_pending(wtxn, &pubkey)? {
            return Ok(PutOutcome::Invalid(
                "blocked: this pubkey has requested to vanish".into(),
            ));
        }
        // A vanished delegator must not be re-published through a
        // delegation: the delegatee's event is indexed under the
        // delegator's pubkey too (NIP-26), which would revive the
        // vanished identity's feed.
        if let Some(delegator) = crate::nips::nip26::delegation(event)
            && let Ok(delegator_bytes) = hex::decode(delegator[0])
            && delegator_bytes.len() == ID_LEN
            && self.vanished_or_pending(wtxn, &delegator_bytes)?
        {
            return Ok(PutOutcome::Invalid(
                "blocked: the delegator has requested to vanish".into(),
            ));
        }
        // NIP-62: "Relays MUST ensure that the deleted events cannot be
        // re-broadcasted into the relay." Gift wraps addressed to a vanished
        // pubkey are signed by random keys, so the author checks above cannot
        // catch them: reject any kind:1059 whose `p` tag names a vanished
        // recipient.
        if event.kind == crate::nips::nip62::GIFT_WRAP_KIND {
            for tag in &event.tags {
                if tag.len() >= 2
                    && tag[0] == "p"
                    && let Ok(recipient) = hex::decode(&tag[1])
                    && recipient.len() == ID_LEN
                    && self.vanished_or_pending(wtxn, &recipient)?
                {
                    return Ok(PutOutcome::Invalid(
                        "blocked: the recipient has requested to vanish".into(),
                    ));
                }
            }
        }
        if self.banned.get(wtxn, &id)?.is_some() {
            return Ok(PutOutcome::Invalid("blocked: event has been banned".into()));
        }
        if self.deleted.get(wtxn, &id)?.is_some() {
            return Ok(PutOutcome::PreviouslyDeleted);
        }
        // NIP-29: a purged group's history must not re-enter the database
        // after the id is re-created (a re-create installs default-public
        // settings, exposing old private posts). One marker per group id
        // records the purge time and the cut; `h`-tagged events with
        // `created_at <= cut` are rejected, including same-second and
        // future-dated events removed by the purge. Only the `kind:9007`
        // re-create compares against the purge time instead, so it passes
        // even when the cut was pushed forward. Only events carrying an
        // `h` tag are checked, so ordinary traffic pays one tag scan at
        // most.
        if self.purged_groups_blocks(wtxn, event)? {
            return Ok(PutOutcome::PreviouslyDeleted);
        }
        // NIP-01: kinds 20000-29999 are ephemeral: they are delivered to
        // currently connected subscribers but never stored or indexed.
        if (20000..30000).contains(&event.kind) {
            return Ok(PutOutcome::Ephemeral);
        }
        // NIP-40: events whose expiration has arrived are dropped. The
        // check comes after the ephemeral range because "an expiration
        // timestamp does not affect storage of ephemeral events".
        if self
            .expiry_enabled
            .load(std::sync::atomic::Ordering::Relaxed)
            && let Some(exp) = nip40::expiry(event)
            && exp <= now
        {
            return Ok(PutOutcome::Expired);
        }

        let outcome = if is_replaceable(event) {
            // NIP-01: normal replaceable kinds (0, 3, 10000-19999) are
            // replaced per (pubkey, kind) — their `d` tag must not create
            // separate slots. Only addressable kinds (30000-39999, NIP-33)
            // key on the `d` tag value.
            let dtag = if nip33::is_param_replaceable_kind(event.kind) {
                nip33::dtag(event)
            } else {
                ""
            };
            // The `d` tag is truncated for the index key only: a value long
            // enough to exceed LMDB's key-size limit would abort the whole
            // write batch, and realistic addressable events use short `d`
            // tags. The stored event keeps its full `d` tag.
            let rkey = replaceable_key(event.kind, &pubkey, &dtag_key_safe(dtag));
            // NIP-09: an `a`-tag deletion tombstones the whole address up to
            // the request's created_at, so a later re-publication of an older
            // (or equal-timestamped) version stays deleted. Newer versions
            // are allowed: the request only covers history up to its own
            // timestamp.
            if let Some(tomb) = self
                .deleted
                .get(wtxn, &deleted_address_key(event.kind, &pubkey, dtag))?
                && tomb.len() >= CREATED_LEN
                && event.created_at <= u64::from_be_bytes(tomb[..CREATED_LEN].try_into().unwrap())
            {
                return Ok(PutOutcome::PreviouslyDeleted);
            }
            let old = self.replaceable.get(wtxn, &rkey)?;
            let had_old = old
                .as_ref()
                .is_some_and(|o| o.len() >= CREATED_LEN + ID_LEN);
            if let Some(old) = old
                && old.len() >= CREATED_LEN + ID_LEN
            {
                let old_created = u64::from_be_bytes(old[..CREATED_LEN].try_into().unwrap());
                let old_id = old[CREATED_LEN..CREATED_LEN + ID_LEN].to_vec();
                // NIP-01: on equal timestamps the event with the lowest id
                // (first in lexical order) is retained.
                let newer = event.created_at > old_created
                    || (event.created_at == old_created && id.as_slice() < old_id.as_slice());
                if !newer {
                    return Ok(PutOutcome::Duplicate(
                        "duplicate: event already stored".into(),
                    ));
                }
                self.remove_event(wtxn, &old_id)?;
            }
            let mut value = Vec::with_capacity(CREATED_LEN + ID_LEN);
            value.extend_from_slice(&event.created_at.to_be_bytes());
            value.extend_from_slice(&id);
            self.replaceable.put(wtxn, &rkey, &value)?;
            if had_old {
                PutOutcome::Replaced
            } else {
                PutOutcome::Stored
            }
        } else {
            if self.events.get(wtxn, &id)?.is_some() {
                return Ok(PutOutcome::Duplicate(
                    "duplicate: event already stored".into(),
                ));
            }
            PutOutcome::Stored
        };

        let raw = serde_json::to_vec(event)?;
        self.events.put(wtxn, &id, &raw)?;
        self.put_indexes(wtxn, event, &id, &pubkey)?;
        // The derived-state sequence advances in the same commit as the
        // state-relevant event it describes: a snapshot can claim a
        // generation only when the events behind it are durable.
        if let Some(family) = state_kind_family(event.kind) {
            self.bump_state_seq(wtxn, family)?;
        }
        Ok(outcome)
    }

    /// Whether the meta index must be rebuilt: an old database written by
    /// a relay before the meta index existed has events but no meta
    /// entries (the derived index is filled in the background at startup;
    /// scans fall back to the full JSON parse until then).
    pub(crate) fn meta_needs_rebuild(&self) -> Result<bool> {
        // Disabled index: nothing to rebuild (the scan falls back to the
        // full parse). Without this check every start would re-derive the
        // whole meta index that the operator explicitly turned off.
        if !self.meta_index {
            return Ok(false);
        }
        let rtxn = self.env.read_txn()?;
        let events = self.by_created.len(&rtxn)?;
        if events == 0 {
            return Ok(false);
        }
        // Compare counts instead of "meta is empty": toggling the index off
        // and on again leaves the *earlier* events without meta while the
        // index is non-empty, and the old check then never rebuilt them
        // (correctness stayed via the full-parse fallback, but scans paid
        // the parse cost forever).
        let meta = self
            .event_meta
            .map(|db| db.len(&rtxn))
            .transpose()?
            .unwrap_or(0);
        Ok(meta < events)
    }

    /// Rebuilds the [`EVENT_META`] index from the stored events (read and
    /// write chunks, so a huge database never holds a giant transaction;
    /// called once at startup when the index is stale).
    pub(crate) fn rebuild_event_meta(&self) -> Result<usize> {
        let Some(meta) = self.event_meta else {
            return Ok(0);
        };
        let mut count = 0usize;
        let mut last: Option<Vec<u8>> = None;
        loop {
            // Read a chunk with a read txn (parsing the headers), then
            // write it with a fresh write txn: the heed iterator borrows
            // the transaction, so the writes cannot share it.
            let chunk = {
                let rtxn = self.env.read_txn()?;
                let range = (
                    last.as_deref()
                        .map(std::ops::Bound::Excluded)
                        .unwrap_or(std::ops::Bound::Unbounded),
                    std::ops::Bound::Unbounded,
                );
                let mut out: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(10_000);
                for item in self.events.range(&rtxn, &range)? {
                    let (id, raw) = item?;
                    let Ok(event) = serde_json::from_slice::<Event>(raw) else {
                        continue;
                    };
                    // A non-32-byte hex pubkey (legacy corruption) must be
                    // skipped: `encode_meta` slices `[..32]` below and would
                    // panic the startup rebuild otherwise.
                    let Ok(pubkey) = hex::decode(&event.pubkey) else {
                        continue;
                    };
                    if pubkey.len() != ID_LEN {
                        continue;
                    }
                    let expiry = crate::nips::nip40::expiry(&event).unwrap_or(0);
                    out.push((
                        id.to_vec(),
                        encode_meta(event.kind, event.created_at, &pubkey, expiry),
                    ));
                    if out.len() >= 10_000 {
                        break;
                    }
                }
                out
            };
            if chunk.is_empty() {
                break;
            }
            let mut wtxn = self.env.write_txn()?;
            for (id, header) in &chunk {
                meta.put(&mut wtxn, id, header)?;
            }
            wtxn.commit()?;
            count += chunk.len();
            last = chunk.last().map(|(id, _)| id.clone());
            if chunk.len() < 10_000 {
                break;
            }
        }
        Ok(count)
    }

    /// Whether the NIP-59 recipient index still needs its one-time backfill.
    /// Marker-based (unlike [`Self::meta_needs_rebuild`]): a database with no
    /// gift wraps is indistinguishable from one that predates the index, so
    /// the marker written after the backfill is authoritative.
    pub(crate) fn gift_wrap_index_needs_rebuild(&self) -> Result<bool> {
        let rtxn = self.env.read_txn()?;
        Ok(self.index_meta.get(&rtxn, b"gift_wrap_index")?.is_none())
    }

    /// One-time backfill of the [`GIFT_WRAP_INDEX`] entries from the stored
    /// `kind:1059` events (chunked read/write like [`Self::rebuild_event_meta`]),
    /// then writes the marker. Runs on the writer thread at startup before
    /// any put, so a NIP-09 deletion after an upgrade still finds wraps that
    /// were stored before the index existed.
    pub(crate) fn rebuild_gift_wrap_index(&self) -> Result<usize> {
        const CHUNK: usize = 4096;
        self.disk_full_error()?;
        let kind = crate::nips::nip62::GIFT_WRAP_KIND;
        let start = kind_key(kind, 0, &[0u8; ID_LEN]);
        let end = range_end(kind_key(kind, u64::MAX, &[0xffu8; ID_LEN]), u64::MAX);
        let mut last_key: Option<Vec<u8>> = None;
        let mut indexed = 0usize;
        loop {
            // Collect a chunk under a read transaction, index it under a
            // separate write transaction (the heed iterator borrows its txn).
            let chunk: Vec<(Vec<u8>, u64, Vec<[u8; ID_LEN]>)> = {
                let rtxn = self.env.read_txn()?;
                let lower = match &last_key {
                    Some(key) => std::ops::Bound::Excluded(key.as_slice()),
                    None => std::ops::Bound::Included(start.as_slice()),
                };
                let mut out = Vec::with_capacity(CHUNK);
                let mut iter = self
                    .by_kind
                    .range(&rtxn, &(lower, std::ops::Bound::Excluded(end.as_slice())))?;
                while out.len() < CHUNK {
                    let Some(item) = iter.next() else { break };
                    let (key, _) = item?;
                    // by_kind keys are always kind(8) + created(8) + id(32);
                    // anything shorter is corruption and is skipped.
                    if key.len() < CREATED_LEN + ID_LEN {
                        continue;
                    }
                    let key = key.to_vec();
                    let created = u64::from_be_bytes(
                        key[8..8 + CREATED_LEN]
                            .try_into()
                            .expect("checked key length"),
                    );
                    let id = &key[key.len() - ID_LEN..];
                    let recipients = match self.events.get(&rtxn, id)? {
                        Some(raw) => serde_json::from_slice::<Event>(raw)
                            .map(|event| gift_wrap_recipients(&event))
                            .unwrap_or_default(),
                        None => Vec::new(),
                    };
                    out.push((key, created, recipients));
                }
                out
            };
            if chunk.is_empty() {
                break;
            }
            last_key = chunk.last().map(|(key, _, _)| key.clone());
            if chunk
                .iter()
                .any(|(_, _, recipients)| !recipients.is_empty())
            {
                let mut wtxn = self.env.write_txn()?;
                for (key, created, recipients) in &chunk {
                    let id = &key[key.len() - ID_LEN..];
                    for recipient in recipients {
                        self.by_tag.put(
                            &mut wtxn,
                            &tag_key(GIFT_WRAP_INDEX, recipient, *created, id),
                            b"",
                        )?;
                        indexed += 1;
                    }
                }
                wtxn.commit()?;
            }
            if chunk.len() < CHUNK {
                break;
            }
        }
        let mut wtxn = self.env.write_txn()?;
        self.index_meta.put(&mut wtxn, b"gift_wrap_index", b"1")?;
        wtxn.commit()?;
        Ok(indexed)
    }

    fn put_indexes(
        &self,
        wtxn: &mut heed::RwTxn,
        event: &Event,
        id: &[u8],
        pubkey: &[u8],
    ) -> Result<()> {
        let created = event.created_at;
        self.by_created.put(wtxn, &created_key(created, id), b"")?;
        self.by_pubkey
            .put(wtxn, &pubkey_key(pubkey, created, id), b"")?;
        // NIP-26: the delegator's pubkey is indexed alongside the author's,
        // so a REQ with `authors: [<delegator>]` also finds events published
        // by a delegatee on the delegator's behalf.
        if let Some(delegator) = crate::nips::nip26::delegation(event)
            && let Ok(delegator_bytes) = hex::decode(delegator[0])
            && delegator_bytes.len() == ID_LEN
        {
            self.by_pubkey
                .put(wtxn, &pubkey_key(&delegator_bytes, created, id), b"")?;
        }
        self.by_kind
            .put(wtxn, &kind_key(event.kind, created, id), b"")?;
        if self.meta_index
            && let Some(meta) = self.event_meta
        {
            let expiry = crate::nips::nip40::expiry(event).unwrap_or(0);
            meta.put(wtxn, id, &encode_meta(event.kind, created, pubkey, expiry))?;
        }
        for tag in &event.tags {
            if indexable_tag(tag) {
                // NIP-01: only the first value in any given tag is indexed.
                // An event may carry several same-name tags; each of them
                // contributes its own first value (see `Filter::matches`).
                let value = &tag[1];
                let key = tag_key(tag[0].as_bytes()[0], value.as_bytes(), created, id);
                // Skip rather than error: an over-long key would abort
                // the whole write batch (see MAX_INDEX_KEY).
                if key.len() <= MAX_INDEX_KEY {
                    self.by_tag.put(wtxn, &key, b"")?;
                }
            }
        }
        // NIP-59: additionally index a gift wrap under each decoded `p`-tag
        // recipient. The visible tag index above stores values verbatim, so
        // without this a recipient lookup would have to walk the whole `p`
        // namespace to catch hex case variants.
        for recipient in gift_wrap_recipients(event) {
            self.by_tag.put(
                wtxn,
                &tag_key(GIFT_WRAP_INDEX, &recipient, created, id),
                b"",
            )?;
        }
        // The expiry index is maintained regardless of the NIP-40 toggle:
        // events stored while the feature was disabled must become
        // purgeable when it is re-enabled. The entries are tiny and are
        // removed with the event by `remove_event`.
        if let Some(exp) = nip40::expiry(event) {
            self.expiry.put(wtxn, &created_key(exp, id), b"")?;
        }
        if let Some(by_word) = self.by_word {
            let words = nip50::tokenize(&event.content);
            let overflow = words.len() > self.indexed_words;
            for word in words.iter().take(self.indexed_words) {
                let key = word_key(word, created, id);
                // Skip rather than error: an over-long word would abort the
                // whole write batch (see MAX_INDEX_KEY).
                if key.len() <= MAX_INDEX_KEY {
                    by_word.put(wtxn, &key, b"")?;
                }
            }
            // Long events also carry the overflow marker so the search scan
            // can check their full content (NIP-50 searches the whole
            // content, but the index only stores the first N tokens).
            if overflow {
                let key = word_key(WORD_OVERFLOW, created, id);
                if key.len() <= MAX_INDEX_KEY {
                    by_word.put(wtxn, &key, b"")?;
                }
            }
        }
        Ok(())
    }

    /// Removes an event and every index entry pointing at it.
    pub(crate) fn remove_event(&self, wtxn: &mut heed::RwTxn, id: &[u8]) -> Result<()> {
        let Some(raw) = self.events.get(wtxn, id)? else {
            return Ok(());
        };
        let event: Event = match serde_json::from_slice(raw) {
            Ok(event) => event,
            Err(error) => {
                log::error!(
                    "removing corrupt event {} and its index entries: {error}",
                    hex::encode(id)
                );
                self.remove_corrupt_event(wtxn, id)?;
                return Ok(());
            }
        };
        let Some(pubkey) = event.pubkey_bytes() else {
            // A legacy/corrupt event with an invalid pubkey cannot have its
            // per-author index entries computed: fall back to the
            // full-index cleanup instead of leaving the event and its
            // indexes behind while reporting success.
            self.remove_corrupt_event(wtxn, id)?;
            return Ok(());
        };

        self.events.delete(wtxn, id)?;
        self.by_created
            .delete(wtxn, &created_key(event.created_at, id))?;
        // NIP-01/33: clear the replaceable/addressable slot so a later
        // re-publication (e.g. after the event was expired or deleted) is
        // judged against the current state instead of a stale entry. The
        // key must match the one written by `put_event_in` (which truncates
        // over-long `d` tags via `dtag_key_safe`).
        if is_replaceable(&event) {
            let dtag = if nip33::is_param_replaceable_kind(event.kind) {
                nip33::dtag(&event)
            } else {
                ""
            };
            self.replaceable.delete(
                wtxn,
                &replaceable_key(event.kind, &pubkey, &dtag_key_safe(dtag)),
            )?;
        }
        self.by_pubkey
            .delete(wtxn, &pubkey_key(&pubkey, event.created_at, id))?;
        // NIP-26: drop the delegator's index entry as well.
        if let Some(delegator) = crate::nips::nip26::delegation(&event)
            && let Ok(delegator_bytes) = hex::decode(delegator[0])
            && delegator_bytes.len() == ID_LEN
        {
            self.by_pubkey
                .delete(wtxn, &pubkey_key(&delegator_bytes, event.created_at, id))?;
        }
        self.by_kind
            .delete(wtxn, &kind_key(event.kind, event.created_at, id))?;
        if let Some(meta) = self.event_meta {
            meta.delete(wtxn, id)?;
        }
        for tag in &event.tags {
            if indexable_tag(tag) {
                // Mirror the put path: only the first tag value was indexed,
                // and over-long keys were skipped at index time (deleting
                // them would hit MDB_BAD_VALSIZE and abort the write batch).
                let value = &tag[1];
                let key = tag_key(tag[0].as_bytes()[0], value.as_bytes(), event.created_at, id);
                if key.len() <= MAX_INDEX_KEY {
                    self.by_tag.delete(wtxn, &key)?;
                }
            }
        }
        // Mirror the NIP-59 recipient index entries written by
        // `put_indexes`.
        for recipient in gift_wrap_recipients(&event) {
            self.by_tag.delete(
                wtxn,
                &tag_key(GIFT_WRAP_INDEX, &recipient, event.created_at, id),
            )?;
        }
        // The expiry entry is deleted regardless of the NIP-40 toggle: a
        // stale key would otherwise survive a removal performed while the
        // feature was disabled and keep purging a re-published event with
        // the same id forever.
        if let Some(exp) = nip40::expiry(&event) {
            self.expiry.delete(wtxn, &created_key(exp, id))?;
        }
        if let Some(by_word) = self.by_word {
            let words = nip50::tokenize(&event.content);
            let overflow = words.len() > self.indexed_words;
            for word in words.iter().take(self.indexed_words) {
                // Mirror the put path for the same reason as tags above.
                let key = word_key(word, event.created_at, id);
                if key.len() <= MAX_INDEX_KEY {
                    by_word.delete(wtxn, &key)?;
                }
            }
            if overflow {
                let key = word_key(WORD_OVERFLOW, event.created_at, id);
                if key.len() <= MAX_INDEX_KEY {
                    by_word.delete(wtxn, &key)?;
                }
            }
        }
        Ok(())
    }

    fn remove_corrupt_event(&self, wtxn: &mut heed::RwTxn, id: &[u8]) -> Result<()> {
        let tables = [
            ("by_created", self.by_created),
            ("by_pubkey", self.by_pubkey),
            ("by_kind", self.by_kind),
            ("by_tag", self.by_tag),
            ("replaceable", self.replaceable),
            ("expiry", self.expiry),
        ];
        let mut capped: Vec<&str> = Vec::new();
        for (name, database) in tables {
            if self.delete_corrupt_index_entries(wtxn, database, id)? {
                capped.push(name);
            }
        }
        if let Some(meta) = self.event_meta {
            meta.delete(wtxn, id)?;
        }
        if let Some(by_word) = self.by_word
            && self.delete_corrupt_index_entries(wtxn, by_word, id)?
        {
            capped.push("by_word");
        }
        self.events.delete(wtxn, id)?;
        if !capped.is_empty() {
            log::warn!(
                "corrupt event {}: index cleanup stopped at the {CORRUPT_CLEANUP_SCAN_CAP}-entry \
                 scan cap for {}; the remaining dangling index entries are skipped by the \
                 existence check",
                hex::encode(id),
                capped.join(", ")
            );
        }
        Ok(())
    }

    /// Deletes every entry of `database` whose key or value ends with `id`,
    /// scanning at most [`CORRUPT_CLEANUP_SCAN_CAP`] entries. Returns
    /// whether the walk stopped at the cap (or an iteration error) before
    /// the table was exhausted.
    fn delete_corrupt_index_entries(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        database: heed::Database<Bytes, Bytes>,
        id: &[u8],
    ) -> Result<bool> {
        let mut keys: Vec<Vec<u8>> = Vec::new();
        let mut capped = false;
        for (scanned, entry) in database.iter(wtxn)?.enumerate() {
            if scanned >= CORRUPT_CLEANUP_SCAN_CAP {
                capped = true;
                break;
            }
            // A mid-iteration error skips the rest of this table: the event
            // itself is still removed and the leftovers are dangling index
            // keys, which the scans tolerate (they verify existence).
            let Ok((key, value)) = entry else {
                capped = true;
                break;
            };
            if key.ends_with(id) || value.ends_with(id) {
                keys.push(key.to_vec());
            }
        }
        for key in keys {
            database.delete(wtxn, &key)?;
        }
        Ok(capped)
    }
    /// Records `now` as the first-seen time of `pubkey` when the pubkey is
    /// unknown, and returns `(created, first_seen)`: `created` is true when
    /// the entry was just written (the pubkey's first accepted event).
    pub(crate) fn touch_first_seen(
        &self,
        wtxn: &mut heed::RwTxn,
        pubkey: &[u8],
        now: u64,
    ) -> Result<(bool, u64)> {
        match self.first_seen.get(wtxn, pubkey)? {
            Some(raw) if raw.len() >= 8 => {
                let ts = u64::from_be_bytes(raw[..8].try_into().unwrap());
                Ok((false, ts))
            }
            _ => {
                self.first_seen.put(wtxn, pubkey, &now.to_be_bytes())?;
                Ok((true, now))
            }
        }
    }

    /// Read-only first-seen lookup: returns `(created, first_seen)` without
    /// recording anything. `created` is `true` when the pubkey has never been
    /// seen (so its first stored event may establish the account).
    pub(crate) fn first_seen_status(
        &self,
        rtxn: &heed::RoTxn,
        pubkey: &[u8],
    ) -> Result<(bool, u64)> {
        match self.first_seen.get(rtxn, pubkey)? {
            Some(raw) if raw.len() >= 8 => {
                let ts = u64::from_be_bytes(raw[..8].try_into().unwrap());
                Ok((false, ts))
            }
            Some(_) => {
                // A corrupt entry must fail closed like a read error: the
                // fail-open `(true, 0)` would treat the pubkey as brand new
                // and let it through the new-pubkey age gate.
                log::warn!(
                    "corrupt first-seen entry for {}; treating the pubkey as too new",
                    hex::encode(pubkey)
                );
                Ok((false, u64::MAX))
            }
            None => Ok((true, 0)),
        }
    }

    /// Returns `true` when an event whose id starts with `prefix` is stored.
    /// Used by NIP-29 `previous` tag validation.
    pub fn event_id_prefix_exists(&self, prefix: &[u8]) -> Result<bool> {
        let rtxn = self.env.read_txn()?;
        let range = (
            std::ops::Bound::Included(prefix),
            std::ops::Bound::Unbounded,
        );
        Ok(self
            .events
            .range(&rtxn, &range)?
            .next()
            .transpose()?
            .map(|(key, _)| key.starts_with(prefix))
            .unwrap_or(false))
    }

    /// Batched variant of [`Self::event_id_prefix_exists`]: answers many
    /// prefix lookups in a single read transaction instead of opening one
    /// transaction per prefix (a batch of NIP-29 `previous` tags can reach
    /// tens of thousands of entries).
    pub fn prefixes_exist(&self, prefixes: &[Vec<u8>]) -> Result<Vec<bool>> {
        let rtxn = self.env.read_txn()?;
        let mut out = Vec::with_capacity(prefixes.len());
        for prefix in prefixes {
            let range = (
                std::ops::Bound::Included(prefix.as_slice()),
                std::ops::Bound::Unbounded,
            );
            let exists = self
                .events
                .range(&rtxn, &range)?
                .next()
                .transpose()?
                .map(|(key, _)| key.starts_with(prefix))
                .unwrap_or(false);
            out.push(exists);
        }
        Ok(out)
    }
}

fn indexable_tag(tag: &[String]) -> bool {
    tag.len() >= 2
        && tag[0].len() == 1
        && tag[0].as_bytes()[0].is_ascii_alphanumeric()
        && tag[1].len() <= TAG_VALUE_MAX
}

/// The decoded `p`-tag recipients of a NIP-59 gift wrap (empty for every
/// other kind). Each recipient is indexed in the reserved
/// [`GIFT_WRAP_INDEX`] namespace of [`BY_TAG`], so a NIP-09 deletion can
/// find the wraps with one narrow, case-insensitive range instead of
/// walking every `p` tag entry in the store.
fn gift_wrap_recipients(event: &Event) -> Vec<[u8; ID_LEN]> {
    if event.kind != crate::nips::nip62::GIFT_WRAP_KIND {
        return Vec::new();
    }
    event
        .tags
        .iter()
        .filter(|tag| tag.len() >= 2 && tag[0] == "p")
        .filter_map(|tag| hex::decode(&tag[1]).ok()?.try_into().ok())
        .collect()
}

pub(crate) fn is_replaceable(event: &Event) -> bool {
    crate::nips::nip01::is_replaceable_kind(event.kind)
        || nip33::is_param_replaceable_kind(event.kind)
}

/// Returns `true` when the event was published under a cryptographically
/// valid NIP-26 delegation granted by `delegator`. Only the first well-formed
/// delegation tag counts, matching the query and index paths.
pub(crate) fn delegated_by(event: &Event, delegator: &str) -> bool {
    let names_delegator = event
        .tags
        .iter()
        .find(|t| t.len() == 4 && t[0] == "delegation")
        .is_some_and(|t| t[1].eq_ignore_ascii_case(delegator));
    names_delegator && crate::nips::nip26::verify(event, &secp256k1::Secp256k1::new())
}
