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

/// Free bytes on the filesystem hosting `path`, when statvfs succeeds.
fn path_free_space(path: &std::path::Path) -> Option<u64> {
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

/// Refuses a write when the disk hosting `env` is too full for a safe mmap
/// commit (a write to a full disk raises SIGBUS and kills the process).
/// For the CLI and migration paths that own no `Store` handle.
pub(crate) fn check_env_space(env: &Env) -> Result<()> {
    if let Some(free) = path_free_space(env.path())
        && free < DISK_FREE_MARGIN
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
    puts: &[(Event, u64)],
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
        && free < DISK_FREE_MARGIN
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
        for (event, now) in puts {
            match store.put_event_in(&mut txn, event, *now) {
                Ok(out) => outcomes.push(out),
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
        match txn.commit() {
            Ok(()) => {
                return outcomes;
            }
            Err(heed::Error::Mdb(heed::MdbError::MapFull)) => {
                if !store.grow_map() {
                    // The map cannot grow further: the batch cannot be
                    // committed, so every reply is revoked.
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
pub(crate) type PutBatchMsg = (Vec<(Event, u64)>, oneshot::Sender<Vec<PutOutcome>>);

/// The writer thread's pending write state: the open transaction, the
/// queued single puts with their reply channels and the queued put
/// batches.
#[derive(Default)]
pub(crate) struct WriteBatch<'tx> {
    pub(crate) pending: Option<heed::RwTxn<'tx>>,
    pub(crate) puts: Vec<(Event, u64)>,
    pub(crate) senders: Vec<oneshot::Sender<PutOutcome>>,
    pub(crate) pending_batches: Vec<PutBatchMsg>,
}

/// Commits the pending single-put batch together with every queued
/// `PutBatch`, merging them all into one write transaction (one commit for
/// events arriving from many connections). Replies are only sent after a
/// successful commit, so an OK implies durability.
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
    let mut all: Vec<(Event, u64)> = std::mem::take(&mut batch.puts);
    let mut splits: Vec<usize> = vec![all.len()];
    for (events, _) in batch.pending_batches.iter_mut() {
        all.append(events);
        splits.push(all.len());
    }
    let outcomes = apply_put_batch(store, thread_errors, batch.pending.take(), &all);
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
    /// NIP-40 expiration handling is only active when the NIP is enabled.
    /// Shared with the relay so that a config reload can toggle it at runtime.
    pub(crate) expiry_enabled: Arc<std::sync::atomic::AtomicBool>,
    /// NIP-50 word index: maximum number of words indexed per event.
    pub(crate) max_indexed_words: usize,
    /// Ceiling for the memory map (bytes): the map is opened at this size
    /// and never resized at runtime.
    pub(crate) map_max_size: u64,
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
                // 16 named tables, plus the word index when search is on.
                .max_dbs(cfg.max_dbs.max(17))
                .max_readers(cfg.max_readers.max(8))
                .map_size(map_size)
                .open(&cfg.path)?
        };
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
        wtxn.commit()?;
        let tables = if by_word.is_some() { 17 } else { 16 };
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
            expiry_enabled,
            max_indexed_words: max_indexed_words.max(1),
            map_max_size,
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
            && free < DISK_FREE_MARGIN
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
            expiry_enabled: Arc::clone(&self.expiry_enabled),
            max_indexed_words: self.max_indexed_words,
            map_max_size: self.map_max_size,
        }
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
            Some(raw) => serde_json::from_slice(raw).ok(),
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
            meta.owners.push(pubkey.to_string());
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
                // dropping it.
                if let Ok(meta) = serde_json::from_slice::<BlossomMeta>(raw)
                    && !meta.owners.iter().any(|o| o == pubkey)
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
        let key = format!("sha:{sha256}");
        let Some(raw) = self.blossom.get(&rtxn, key.as_bytes())? else {
            return Ok(None);
        };
        Ok(serde_json::from_slice(raw).ok())
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
        let Some(mut meta) = serde_json::from_slice::<BlossomMeta>(raw).ok() else {
            return Ok(false);
        };
        let before = meta.owners.len();
        meta.owners.retain(|o| o != pubkey);
        if meta.owners.len() == before {
            return Ok(false);
        }
        self.blossom
            .delete(&mut wtxn, format!("own:{pubkey}:{sha256}").as_bytes())?;
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
        let data = serde_json::to_vec(&serde_json::json!({ "deny": deny, "allow": allow }))?;
        let mut wtxn = self.env.write_txn()?;
        self.access.put(&mut wtxn, b"relay_pubkeys", &data)?;
        wtxn.commit()?;
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
        end[..prefix_len + CREATED_LEN].copy_from_slice(&until.saturating_add(1).to_be_bytes());
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
        let id_start = key.len() - ID_LEN;
        key[id_start..].fill(0xff);
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
    let max = MAX_INDEX_KEY.saturating_sub(CREATED_LEN + ID_LEN + 4);
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

/// Tombstone key for an `a`-tag (address) deletion, stored in the
/// [`DELETED`] table. Event ids are exactly 32 bytes, so the one-byte prefix
/// keeps the two key spaces disjoint; the `d` tag is normalized with
/// [`dtag_key_safe`] exactly like the replaceable slot key it mirrors.
pub(crate) fn deleted_address_key(kind: u64, pubkey: &[u8], dtag: &str) -> Vec<u8> {
    let safe = dtag_key_safe(dtag);
    let mut key = Vec::with_capacity(1 + CREATED_LEN + ID_LEN + 4 + safe.len());
    key.push(b'a');
    key.extend_from_slice(&replaceable_key(kind, pubkey, &safe));
    key
}
impl Store {
    // ----- event persistence -----

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

        if self.vanish.get(wtxn, &pubkey)?.is_some() {
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
            && self.vanish.get(wtxn, &delegator_bytes)?.is_some()
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
                    && self.vanish.get(wtxn, &recipient)?.is_some()
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
                String::new()
            };
            // The `d` tag is truncated for the index key only: a value long
            // enough to exceed LMDB's key-size limit would abort the whole
            // write batch, and realistic addressable events use short `d`
            // tags. The stored event keeps its full `d` tag.
            let rkey = replaceable_key(event.kind, &pubkey, &dtag_key_safe(&dtag));
            // NIP-09: an `a`-tag deletion tombstones the whole address up to
            // the request's created_at, so a later re-publication of an older
            // (or equal-timestamped) version stays deleted. Newer versions
            // are allowed: the request only covers history up to its own
            // timestamp.
            if let Some(tomb) = self
                .deleted
                .get(wtxn, &deleted_address_key(event.kind, &pubkey, &dtag))?
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
        let has_events = !self.by_created.is_empty(&rtxn)?;
        let meta_empty = self
            .event_meta
            .is_none_or(|db| db.is_empty(&rtxn).unwrap_or(true));
        Ok(has_events && meta_empty)
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
        // The expiry index is maintained regardless of the NIP-40 toggle:
        // events stored while the feature was disabled must become
        // purgeable when it is re-enabled. The entries are tiny and are
        // removed with the event by `remove_event`.
        if let Some(exp) = nip40::expiry(event) {
            self.expiry.put(wtxn, &created_key(exp, id), b"")?;
        }
        if let Some(by_word) = self.by_word {
            let words = nip50::tokenize(&event.content);
            let overflow = words.len() > self.max_indexed_words;
            for word in words.iter().take(self.max_indexed_words) {
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
                String::new()
            };
            self.replaceable.delete(
                wtxn,
                &replaceable_key(event.kind, &pubkey, &dtag_key_safe(&dtag)),
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
        // The expiry entry is deleted regardless of the NIP-40 toggle: a
        // stale key would otherwise survive a removal performed while the
        // feature was disabled and keep purging a re-published event with
        // the same id forever.
        if let Some(exp) = nip40::expiry(&event) {
            self.expiry.delete(wtxn, &created_key(exp, id))?;
        }
        if let Some(by_word) = self.by_word {
            let words = nip50::tokenize(&event.content);
            let overflow = words.len() > self.max_indexed_words;
            for word in words.iter().take(self.max_indexed_words) {
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
        let databases = [
            self.by_created,
            self.by_pubkey,
            self.by_kind,
            self.by_tag,
            self.replaceable,
            self.expiry,
        ];
        for database in databases {
            let keys: Vec<Vec<u8>> = database
                .iter(wtxn)?
                .filter_map(|entry| {
                    let (key, value) = entry.ok()?;
                    (key.ends_with(id) || value.ends_with(id)).then(|| key.to_vec())
                })
                .collect();
            for key in keys {
                database.delete(wtxn, &key)?;
            }
        }
        if let Some(meta) = self.event_meta {
            meta.delete(wtxn, id)?;
        }
        if let Some(by_word) = self.by_word {
            let keys: Vec<Vec<u8>> = by_word
                .iter(wtxn)?
                .filter_map(|entry| {
                    let (key, value) = entry.ok()?;
                    (key.ends_with(id) || value.ends_with(id)).then(|| key.to_vec())
                })
                .collect();
            for key in keys {
                by_word.delete(wtxn, &key)?;
            }
        }
        self.events.delete(wtxn, id)?;
        Ok(())
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
            _ => Ok((true, 0)),
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
