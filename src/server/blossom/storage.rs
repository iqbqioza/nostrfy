//! Blossom blob storage: the `bucket/{npub1xxx}/{file}` layout on local
//! disk or in an S3-compatible bucket (AWS S3 / Cloudflare R2).
//!
//! The sha256 → owner mapping is **persisted in the relay database**
//! (LMDB, the `blossom` table): an upload publishes the object first and
//! writes the mapping only after the object is durable, and a lookup reads
//! it straight from LMDB — no in-memory index and no startup scan, so
//! lookups survive restarts, memory stays bounded and startup is
//! independent of the storage size. The blobs themselves are files in
//! `bucket/{npub1xxx}/{file}`; the multi-owner mapping lets every uploader
//! of identical content manage their own copy independently.

use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::db::DbClient;
use crate::stats::Stats;
use anyhow::anyhow;

use crate::error::Result;

use super::s3::S3Client;

/// Metadata of a stored blob (the Blossom `BlobDescriptor` fields).
#[derive(Debug, Clone)]
pub(crate) struct Descriptor {
    pub sha256: String,
    pub size: u64,
    pub mime: String,
    pub uploaded: i64,
    /// One uploader (the first reachable copy); kept for callers that
    /// report ownership. GET opens via `open_stream_any`, which tries every
    /// owner, so this field is informational.
    #[allow(dead_code)]
    pub pubkey: String,
}

/// The file storage backend, chosen by `blossom.storage`.
enum Storage {
    Local(LocalStore),
    S3(S3Store),
}

/// A streamable blob source: the local file (already seeked) or an S3
/// range response. The response bodies are streamed in chunks, so a large
/// blob never has to be held in memory in full.
#[derive(Debug)]
pub(crate) enum BlobStream {
    Local(tokio::fs::File),
    S3(reqwest::Response),
}

/// One legacy-migration row: (sha256, mime, size, uploaded, hex pubkey).
type LegacyEntry = (String, String, u64, i64, String);

/// A failure caused by the database being unavailable, not by the blob
/// backend. The handlers map it to a retryable 503 instead of a 404 (which
/// would hide an existing blob) or a 500 (which reads as a storage fault).
/// The database layer cannot type these failures (its unchecked variants
/// degrade to defaults), so the checked paths tag them here.
#[derive(Debug)]
pub(crate) struct DbUnavailable;

impl std::fmt::Display for DbUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("database unavailable")
    }
}

impl std::error::Error for DbUnavailable {}

fn db_unavailable() -> anyhow::Error {
    anyhow::Error::new(DbUnavailable)
}

/// A new owner past the per-blob cap. This is a client-visible conflict
/// (the database refuses the same add), not an internal fault: the handler
/// answers 409 instead of the generic 500.
#[derive(Debug)]
pub(crate) struct BlobOwnerLimit;

impl std::fmt::Display for BlobOwnerLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the blob already has the maximum number of owners")
    }
}

impl std::error::Error for BlobOwnerLimit {}

/// Mirror of the per-blob owner cap in the database layer
/// (`MAX_BLOB_OWNERS` in src/db/store.rs, deliberately not exported).
/// Pre-checking here only decides the HTTP status; the database still
/// enforces the real cap, so a drift degrades the status to 500, never
/// correctness.
const MAX_BLOB_OWNERS: usize = 64;

/// Result of one [`BlobStore::auto_migrate_legacy`] pass.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum MigrationOutcome {
    /// The pass finished and the database marker is set.
    Completed(usize),
    /// The relay drained before the pass finished. The marker is **not**
    /// set, so the next start reruns the migration; the chunks committed
    /// before the stop are re-added idempotently there.
    Interrupted(usize),
}

/// Blob storage: the LMDB-persisted mapping plus the file backend.
pub(crate) struct BlobStore {
    storage: Storage,
    db: DbClient,
    /// The relay's shared counters; the blossom code bumps
    /// `blossom_missing_objects` through this handle (the stats writer
    /// cannot poll it without reaching into the store).
    stats: Arc<Stats>,
    upload_locks: Vec<tokio::sync::Mutex<()>>,
    /// Stale spool files removed by the startup sweep (see
    /// [`Self::sweep_stale_spools`]): each one is a temporary upload that
    /// died before it could publish, so it doubles as the cheap
    /// orphan/interrupted-upload signal. Exposed via
    /// [`Self::orphan_spools_swept`] for the stats owner.
    orphan_spools_swept: std::sync::atomic::AtomicU64,
    /// Test-only one-shot fault injection: the next owner-mapping commit is
    /// treated as a database failure so the publish-first ordering (an
    /// orphan object, never a phantom mapping) is testable without a real
    /// database fault. Mirrors `Store::fail_next_commit`.
    #[cfg(test)]
    fail_next_mapping: std::sync::atomic::AtomicBool,
}

impl BlobStore {
    const UPLOAD_LOCK_COUNT: usize = 256;

    pub(crate) async fn new(
        storage: &str,
        local_path: &Path,
        min_free_bytes: u64,
        s3: Option<S3Config>,
        db: DbClient,
        stats: Arc<Stats>,
    ) -> Result<BlobStore> {
        let storage = match storage {
            "local" => Storage::Local(LocalStore::new(local_path, min_free_bytes).await?),
            "s3" => Storage::S3(
                S3Store::new(s3.expect("s3 config validated by Config::validate")).await?,
            ),
            other => {
                return Err(crate::error::config_err(format!(
                    "unsupported blossom storage backend {other:?}"
                )));
            }
        };
        Ok(BlobStore {
            storage,
            db,
            stats,
            upload_locks: (0..Self::UPLOAD_LOCK_COUNT)
                .map(|_| tokio::sync::Mutex::new(()))
                .collect(),
            orphan_spools_swept: std::sync::atomic::AtomicU64::new(0),
            #[cfg(test)]
            fail_next_mapping: std::sync::atomic::AtomicBool::new(false),
        })
    }

    async fn blob_lock(&self, sha256: &str) -> tokio::sync::MutexGuard<'_, ()> {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        sha256.hash(&mut hasher);
        let index = (hasher.finish() as usize) % self.upload_locks.len();
        self.upload_locks[index].lock().await
    }

    /// Whether the storage backend currently accepts uploads (the
    /// disk-full guard, shared by the PUT path and the BUD-06 preflight).
    pub(crate) fn check_space(&self) -> Result<()> {
        match &self.storage {
            Storage::Local(s) => s.check_space(),
            Storage::S3(_) => Ok(()),
        }
    }

    /// Test-only: free bytes on the local blob filesystem. The reservation
    /// tests set `min_free_bytes` relative to the real free space so the
    /// floor can be crossed with small fixtures.
    #[cfg(test)]
    pub(crate) fn free_space(&self) -> Option<u64> {
        match &self.storage {
            Storage::Local(s) => s.free_space(),
            Storage::S3(_) => None,
        }
    }

    /// Test-only: bytes currently reserved by in-flight uploads (0 when the
    /// guard is disabled). Every upload path must return this to zero; a
    /// leaked reservation would eventually refuse uploads with 507 while
    /// the disk is empty.
    #[cfg(test)]
    pub(crate) fn reserved_bytes(&self) -> u64 {
        match &self.storage {
            Storage::Local(s) => s.reserved.load(std::sync::atomic::Ordering::Relaxed),
            Storage::S3(_) => 0,
        }
    }

    /// A directory on the blob filesystem where uploads may be spooled, so
    /// the final store is a rename instead of a second full write (None for
    /// S3, which keeps the system temp directory).
    /// Removes spool files left behind by a crash (the Drop cleanup cannot
    /// run on SIGKILL/power loss) so they do not accumulate until the disk
    /// is full. Only files whose owning process start is gone (a dead PID)
    /// or whose token is foreign and that outlived the grace period are
    /// removed: the temp directory is shared, and deleting a live process's
    /// in-flight spool would corrupt its upload (or make it publish a
    /// missing body). Files this process start owns (matching token) and
    /// files of unknown shape are never touched. A removal failure is
    /// ignored (best effort).
    ///
    /// This is the whole file/mapping reconciliation story: the publish
    /// path writes the object first and the LMDB mapping second, so a crash
    /// leaves at most an invisible, overwritable orphan object — never a
    /// mapping that 404s — and the only cheap orphan evidence is the
    /// interrupted upload's spool file. No startup object-vs-mapping diff
    /// is attempted: it would need an unbounded scan of the mapping index
    /// (or the whole blob tree), and a legacy database whose mappings
    /// `auto_migrate_legacy` is still rebuilding would report every
    /// not-yet-mapped object as an orphan.
    pub(crate) fn sweep_stale_spools(&self) {
        let current = spool_process_token();
        let now = std::time::SystemTime::now();
        let mut swept = 0u64;
        let mut dirs = vec![std::env::temp_dir()];
        if let Some(dir) = self.spool_dir() {
            dirs.push(dir);
        }
        for dir in dirs {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                let Some(pid) = spool_pid(&name) else {
                    // Unknown shape: never delete a file that cannot be
                    // attributed to a spool.
                    continue;
                };
                if spool_token(&name) == Some(current) {
                    // This process start's own (possibly in-flight) spool.
                    continue;
                }
                // A foreign token: another process, or a previous process
                // whose PID a restart reused (a container restart always
                // yields PID 1 again). It is stale once its PID is gone, or
                // once it outlived the grace period and can no longer be a
                // live sibling's spool.
                if (!process_alive(pid) || spool_older_than(&entry, now))
                    && std::fs::remove_file(entry.path()).is_ok()
                {
                    swept += 1;
                }
            }
        }
        if swept > 0 {
            self.orphan_spools_swept
                .fetch_add(swept, std::sync::atomic::Ordering::Relaxed);
            log::info!("Blossom spool sweep: removed {swept} orphaned upload spool file(s)");
        }
    }

    /// Stale spool files removed by [`Self::sweep_stale_spools`] since this
    /// store was created. A plain counter the stats owner can wire as
    /// `nostrfy_blossom_orphan_spools_swept` (counter): read
    /// `relay.blossom.read().await` and call this getter.
    #[allow(dead_code)] // Wired into `Stats` by the server/stats owner.
    pub(crate) fn orphan_spools_swept(&self) -> u64 {
        self.orphan_spools_swept
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub(crate) fn spool_dir(&self) -> Option<PathBuf> {
        match &self.storage {
            Storage::Local(s) => Some(s.root.join(".spool")),
            Storage::S3(_) => None,
        }
    }

    /// Reserves `size` bytes against the local free-space floor for the
    /// duration of an upload (no-op on S3). The guard releases on drop.
    pub(crate) fn reserve_space(&self, size: u64) -> Result<SpaceReservation<'_>> {
        if let Storage::Local(s) = &self.storage {
            s.reserve(size)?;
        }
        Ok(SpaceReservation { store: self, size })
    }

    /// Commits the LMDB owner mapping. Called only after the object has
    /// been published durably, so a `false` result leaves an invisible,
    /// overwritable orphan object rather than a phantom mapping.
    async fn commit_owner(
        &self,
        sha256: &str,
        mime: &str,
        size: u64,
        uploaded: i64,
        pubkey: &str,
    ) -> bool {
        #[cfg(test)]
        if self
            .fail_next_mapping
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return false;
        }
        self.db
            .blossom_add_owner(sha256, mime, size, uploaded, pubkey)
            .await
    }

    /// Classifies a failed owner-mapping commit. The pre-check in
    /// [`Self::put_file`] is not atomic with the add, so a concurrent
    /// upload can win the last owner slot and make the database refuse
    /// this add. Re-reading the mapping then shows a full owner list
    /// without the uploader in it — a client-visible conflict (HTTP 409),
    /// not a storage fault. Any other state stays a genuine failure: an
    /// unavailable database (the re-read fails) must not be misreported
    /// as a cap conflict, and neither must a commit failure when the
    /// uploader is already an owner.
    async fn owner_limit_on_failed_commit(
        &self,
        sha256: &str,
        pubkey: &str,
    ) -> Option<anyhow::Error> {
        let meta = self.db.blossom_load_checked(sha256).await??;
        if !meta.owners.iter().any(|o| o == pubkey) && meta.owners.len() >= MAX_BLOB_OWNERS {
            Some(anyhow::Error::new(BlobOwnerLimit))
        } else {
            None
        }
    }

    /// Stores a blob: the object is published first (fsync + rename +
    /// directory fsync) and the LMDB mapping is committed only after it is
    /// durable. A crash in between leaves an invisible, overwritable orphan
    /// object instead of a listed blob whose GET 404s; a failed mapping
    /// commit leaves the same orphan and reports the error.
    #[cfg(test)]
    pub(crate) async fn put(
        &self,
        pubkey: &str,
        sha256: &str,
        bytes: &[u8],
        mime: &str,
    ) -> Result<Descriptor> {
        // Disk-full guard first: a refused upload must not even leave an
        // orphan object behind. The reservation covers the whole upload.
        let _space = self.reserve_space(bytes.len() as u64)?;
        let _blob_guard = self.blob_lock(sha256).await;
        let uploaded = crate::util::unix_now() as i64;
        let npub = npub_of(pubkey);
        let stored = match &self.storage {
            Storage::Local(s) => s.put(&npub, sha256, bytes, mime, uploaded).await,
            Storage::S3(s) => s.put(&npub, sha256, bytes, mime, uploaded).await,
        };
        stored?;
        if !self
            .commit_owner(sha256, mime, bytes.len() as u64, uploaded, pubkey)
            .await
        {
            return Err(self
                .owner_limit_on_failed_commit(sha256, pubkey)
                .await
                .unwrap_or_else(|| anyhow!("blossom mapping write failed")));
        }
        Ok(Descriptor {
            sha256: sha256.to_string(),
            size: bytes.len() as u64,
            mime: mime.to_string(),
            uploaded,
            pubkey: pubkey.to_string(),
        })
    }

    /// Stores a blob from a temporary file, keeping the upload path
    /// bounded to filesystem and transport buffers instead of retaining the
    /// complete request body in memory.
    ///
    /// The object is published first (the spool is fsynced, renamed into
    /// place and its directory fsynced) and the owner mapping is committed
    /// only after it is durable: a crash in between leaves an invisible,
    /// overwritable orphan object instead of a listed blob that 404s. A
    /// failed mapping commit leaves the orphan and reports the error; a
    /// failed publish adds no mapping and never touches the uploader's
    /// pre-existing one.
    pub(crate) async fn put_file(
        &self,
        pubkey: &str,
        sha256: &str,
        path: &Path,
        size: u64,
        mime: &str,
        already_reserved: bool,
    ) -> Result<(Descriptor, bool)> {
        // The upload path reserves the maximum body size before spooling
        // (so the spool itself cannot push the disk under the free-space
        // floor); the copy/test paths reserve the exact size here.
        let _space = if already_reserved {
            None
        } else {
            Some(self.reserve_space(size)?)
        };
        let _blob_guard = self.blob_lock(sha256).await;
        let uploaded = crate::util::unix_now() as i64;
        // Read the pre-upload state first: it decides the 409 cap response
        // and the re-upload descriptor. A failed read must abort before the
        // object is published (a database outage must not create orphans),
        // and it must never be mistaken for "no mapping yet".
        let Some(existing) = self.db.blossom_load_checked(sha256).await else {
            return Err(db_unavailable());
        };
        let existed = existing.is_some();
        // A new owner past the per-blob cap is refused by the database
        // anyway; pre-checking turns the resulting commit failure into a
        // client-visible conflict (409) instead of a 500. The load above is
        // not atomic with the add, so a concurrent upload can still win the
        // last slot — the database cap remains the real guard (the raced
        // loser then leaves an orphan object, never a mapping).
        if let Some(meta) = &existing
            && !meta.owners.iter().any(|o| o == pubkey)
            && meta.owners.len() >= MAX_BLOB_OWNERS
        {
            return Err(anyhow::Error::new(BlobOwnerLimit));
        }
        let npub = npub_of(pubkey);
        let stored = match &self.storage {
            Storage::Local(s) => s.put_file(&npub, sha256, path).await,
            Storage::S3(s) => s.put_file(&npub, sha256, path, size, mime).await,
        };
        // Publish before mapping: without a durable object the mapping
        // would be a phantom that 404s and consumes an owner slot. A
        // failed publish leaves the pre-existing mapping untouched.
        stored?;
        if !self
            .commit_owner(sha256, mime, size, uploaded, pubkey)
            .await
        {
            return Err(self
                .owner_limit_on_failed_commit(sha256, pubkey)
                .await
                .unwrap_or_else(|| {
                    anyhow!(
                        "blossom mapping write failed; the published object is an invisible \
                         orphan that a later upload of the same bytes overwrites"
                    )
                }));
        }
        if existed && let Some(meta) = self.db.blossom_load(sha256).await {
            // A re-upload keeps the original mapping (add_owner only
            // appends the owner): answer with the stored values so the PUT
            // descriptor agrees with GET/list.
            return Ok((
                Descriptor {
                    sha256: sha256.to_string(),
                    size: meta.size,
                    mime: meta.mime,
                    uploaded: meta.uploaded,
                    pubkey: pubkey.to_string(),
                },
                existed,
            ));
        }
        Ok((
            Descriptor {
                sha256: sha256.to_string(),
                size,
                mime: mime.to_string(),
                uploaded,
                pubkey: pubkey.to_string(),
            },
            existed,
        ))
    }

    /// Resolves a blob by its sha256 straight from LMDB. A database
    /// failure is reported as `Err`, never as `Ok(None)`: an existing blob
    /// must not 404 on overload (the handlers answer 503 instead).
    pub(crate) async fn find(&self, sha256: &str) -> crate::error::Result<Option<Descriptor>> {
        let Some(meta) = self.db.blossom_load_checked(sha256).await else {
            return Err(db_unavailable());
        };
        Ok(meta.and_then(|meta| {
            Some(Descriptor {
                sha256: meta.sha256,
                size: meta.size,
                mime: meta.mime,
                uploaded: meta.uploaded,
                pubkey: meta.owners.into_iter().next()?,
            })
        }))
    }

    /// Opens a blob by hash, trying every owner in upload order. The first
    /// owner's file may be gone (crash/manual delete) while a later owner's
    /// copy is intact: opening only `owners[0]` would 404 a retrievable
    /// blob. A storage error for one owner (S3 5xx, local I/O error) is
    /// logged and skipped for the same reason; it is only returned when no
    /// owner could be opened.
    /// Returns the stream and the owner whose file was opened.
    pub(crate) async fn open_stream_any(
        &self,
        sha256: &str,
        start: u64,
        len: u64,
    ) -> Result<Option<(BlobStream, String)>> {
        // The checked load keeps a database failure distinguishable from
        // "no mapping" (`Ok(None)`): the handlers answer 503 for the
        // former and 404 only for the latter.
        let Some(meta) = self.db.blossom_load_checked(sha256).await else {
            return Err(db_unavailable());
        };
        let Some(meta) = meta else {
            return Ok(None);
        };
        let mut last_error: Option<anyhow::Error> = None;
        let mut missing = false;
        for owner in &meta.owners {
            match self.open_stream(owner, sha256, start, len).await {
                Ok(Some(stream)) => return Ok(Some((stream, owner.clone()))),
                // Missing under this owner (a definitive local NotFound, or
                // an S3 404): try the next copy.
                Ok(None) => missing = true,
                Err(e) => {
                    log::warn!("blossom: opening {sha256} for owner {owner} failed: {e}");
                    last_error = Some(e);
                }
            }
        }
        match last_error {
            Some(e) => Err(e),
            None => {
                if missing {
                    // The mapping exists but every owner's object is
                    // definitively gone: count the mapped-but-missing blob
                    // (best effort, no behavior change — the mapping is
                    // kept and a re-upload heals it). An owner error above
                    // means the state is unknown, so it is not counted.
                    self.stats.bump(&self.stats.blossom_missing_objects, 1);
                }
                Ok(None)
            }
        }
    }

    /// Whether `pubkey` has uploaded this blob. A database failure is an
    /// error, not `false`: the DELETE handler must not answer 403 "only the
    /// uploader" for a blob it could not check.
    pub(crate) async fn has(&self, pubkey: &str, sha256: &str) -> Result<bool> {
        let Some(meta) = self.db.blossom_load_checked(sha256).await else {
            return Err(db_unavailable());
        };
        Ok(meta.is_some_and(|meta| meta.owners.iter().any(|o| o == pubkey)))
    }

    /// Opens a streamable reader for the blob, positioned at `start`
    /// (the caller derived `start`/`len` from the descriptor's size and a
    /// parsed Range header). The body is streamed in chunks, so a large
    /// blob is never materialized in memory in full.
    pub(crate) async fn open_stream(
        &self,
        pubkey: &str,
        sha256: &str,
        start: u64,
        len: u64,
    ) -> Result<Option<BlobStream>> {
        // The canonical npub first; a blob stored under the legacy
        // bech32m npub directory (before the encoder became canonical)
        // is found via the fallback so old uploads stay readable.
        let npub = npub_of(pubkey);
        let legacy = legacy_npub_of(pubkey);
        for candidate in [npub.as_str(), legacy.as_str()] {
            if let Some(stream) = match &self.storage {
                Storage::Local(s) => s.open(candidate, sha256, start, len).await?,
                Storage::S3(s) => s.open(candidate, sha256, start, len).await?,
            } {
                return Ok(Some(stream));
            }
        }
        Ok(None)
    }

    /// Deletes the requester's copy: the file under their npub directory
    /// (blob first, so a crash leaves a healable state) and their entry in
    /// the LMDB mapping. Other uploaders of the same bytes keep theirs.
    pub(crate) async fn delete(&self, pubkey: &str, sha256: &str) -> Result<bool> {
        let _blob_guard = self.blob_lock(sha256).await;
        let npub = npub_of(pubkey);
        let legacy = legacy_npub_of(pubkey);
        let mut existed = false;
        for candidate in [npub.as_str(), legacy.as_str()] {
            let hit = match &self.storage {
                Storage::Local(s) => s.delete(candidate, sha256).await?,
                Storage::S3(s) => s.delete(candidate, sha256).await?,
            };
            existed |= hit;
            if hit {
                break;
            }
        }
        let (_, db_ok) = self.db.blossom_remove_owner_checked(sha256, pubkey).await;
        if !db_ok {
            return Err(anyhow!("blossom mapping removal failed"));
        }
        Ok(existed)
    }

    /// One-time automatic migration: rebuilds the sha→owner mapping from
    /// blobs stored before the mapping existed (local files or bucket
    /// objects). Runs in the background at startup; the marker key makes
    /// it idempotent, so later restarts skip it instantly.
    ///
    /// Streaming: scanned entries flow through a bounded channel in 5000-row
    /// chunks and are committed as they arrive, so a legacy store with
    /// hundreds of thousands of blobs never materializes the full listing
    /// (nor a task per object) in memory.
    ///
    /// The relay's `drain` signal is observed before the scan starts and in
    /// the pass loop: shutdown returns [`MigrationOutcome::Interrupted`]
    /// without writing the marker, so the next start reruns the pass (the
    /// chunks already committed are re-added idempotently). The marker is
    /// written only after the scan finished and every chunk committed.
    pub(crate) async fn auto_migrate_legacy(
        &self,
        mut drain: tokio::sync::watch::Receiver<bool>,
    ) -> Result<MigrationOutcome> {
        if self.db.blossom_migration_done().await {
            return Ok(MigrationOutcome::Completed(0));
        }
        // Shutdown before the pass even started: do not scan a store whose
        // database is about to stop, and leave the marker unset.
        if *drain.borrow() {
            return Ok(MigrationOutcome::Interrupted(0));
        }
        // Backpressure of one chunk: the scanner waits while a slow disk
        // commits, bounding transient memory to ~2 chunks + one page.
        let (tx, mut rx) = tokio::sync::mpsc::channel(2);
        let scan = async {
            let r = match &self.storage {
                Storage::Local(s) => s.scan_legacy(tx).await,
                Storage::S3(s) => s.scan_legacy(tx).await,
            };
            r.map(|_| ())
        };
        tokio::pin!(scan);
        let mut count = 0usize;
        let mut scanning = true;
        loop {
            tokio::select! {
                biased;
                // Shutdown: abandon the scan at the next await. The marker
                // stays unset (below is never reached), so the pass is
                // resumable; a sender that is already gone counts as a
                // drain too (the relay is being dropped).
                _ = drain.changed() => {
                    return Ok(MigrationOutcome::Interrupted(count));
                }
                r = &mut scan, if scanning => {
                    // The scanner finished (its sender is dropped): keep
                    // draining already-queued chunks below.
                    scanning = false;
                    r?;
                }
                chunk = rx.recv() => {
                    match chunk {
                        Some(entries) => {
                            count += entries.len();
                            if !self.db.blossom_add_mappings(entries).await {
                                // The marker is not set: the migration
                                // retries on the next startup (the failed
                                // chunk may need a bigger map).
                                return Err(anyhow!(
                                    "blossom migration write failed; will retry on the next start"
                                ));
                            }
                        }
                        // All senders dropped and the queue is empty.
                        None if !scanning => break,
                        None => {}
                    }
                }
            }
        }
        self.db.mark_blossom_migration().await;
        Ok(MigrationOutcome::Completed(count))
    }

    /// Blobs uploaded by `pubkey` (hex), via the persisted reverse index,
    /// resolving at most `limit` descriptors: cursors past the window yield
    /// an empty page (see the `GET /list` handler).
    #[cfg(test)]
    pub(crate) async fn list(&self, pubkey: &str, limit: usize) -> Vec<Descriptor> {
        let mut out = Vec::new();
        for sha in self.db.blossom_list(pubkey, limit).await {
            if let Ok(Some(desc)) = self.find(&sha).await {
                out.push(desc);
            }
        }
        out
    }

    /// BUD-12 page from the uploaded-order index: one database round trip
    /// for the whole page (the metadata is loaded inside the reader's
    /// transaction) instead of a lookup per blob.
    ///
    /// Uses the checked variant so a database failure is a server error
    /// (503) instead of a misleading empty inventory: the handler must
    /// not report an existing `/list` as `200 []`.
    pub(crate) async fn list_page(
        &self,
        pubkey: &str,
        after_uploaded: Option<u64>,
        after_sha: Option<&str>,
        limit: usize,
    ) -> Result<Vec<Descriptor>> {
        let page = self
            .db
            .blossom_list_page_checked(pubkey, after_uploaded, after_sha, limit)
            .await
            .ok_or_else(db_unavailable)?;
        Ok(page
            .into_iter()
            .map(|(sha256, meta)| Descriptor {
                sha256,
                size: meta.size,
                mime: meta.mime,
                uploaded: meta.uploaded,
                pubkey: meta
                    .owners
                    .first()
                    .cloned()
                    .unwrap_or_else(|| pubkey.to_string()),
            })
            .collect())
    }
}

/// Prefix of the temporary files uploads are spooled into:
/// `nostrfy-blossom-<pid>-<token>-<counter>` (see [`spool_file_name`]).
pub(crate) const SPOOL_PREFIX: &str = "nostrfy-blossom-";

/// How long a spool whose owner cannot be proven dead is kept before the
/// sweep removes it. A restarted container reuses PID 1, so the token
/// identifies the current process and a foreign token means "not ours";
/// a young foreign spool may still belong to a live sibling process, so
/// only files older than the grace period are swept on liveness ambiguity.
const SPOOL_GRACE_PERIOD: std::time::Duration = std::time::Duration::from_secs(60 * 60);

/// A per-process-start token embedded in every spool name. The PID alone
/// cannot distinguish a previous process's stale spools from the current
/// process's live ones when a container restart reuses PID 1; a random
/// token (falling back to the start time) makes a name collision with the
/// previous start practically impossible, so `create_new` never fails on
/// a stale spool and the sweep can attribute each file to a process start.
pub(crate) fn spool_process_token() -> &'static str {
    static TOKEN: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    TOKEN.get_or_init(|| {
        let mut bytes = [0u8; 8];
        if getrandom::getrandom(&mut bytes).is_ok() {
            return format!("{:016x}", u64::from_ne_bytes(bytes));
        }
        // No RNG: the wall-clock start time still separates ordinary
        // restarts (the PID alone does not under a container restart).
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        format!("{nanos:x}")
    })
}

/// The spool file name for one upload: unique per process start (token) and
/// per upload (counter), so a restarted process can never collide with a
/// stale spool even before the sweep runs.
pub(crate) fn spool_file_name(counter: u64) -> String {
    format!(
        "{SPOOL_PREFIX}{}-{}-{counter}",
        std::process::id(),
        spool_process_token()
    )
}

/// The PID embedded in a spool file name, when it parses.
fn spool_pid(name: &str) -> Option<u32> {
    name.strip_prefix(SPOOL_PREFIX)?
        .split('-')
        .next()?
        .parse()
        .ok()
}

/// The process token of a spool name, or `None` for the legacy
/// `nostrfy-blossom-<pid>[-<counter>]` shapes that carry no token. The new
/// shape always has a counter segment after the token.
fn spool_token(name: &str) -> Option<&str> {
    let mut parts = name.strip_prefix(SPOOL_PREFIX)?.split('-');
    parts.next()?.parse::<u32>().ok()?;
    let token = parts.next()?;
    parts.next()?;
    if token.is_empty() { None } else { Some(token) }
}

/// Whether a spool file is older than the sweep grace period. A file whose
/// age cannot be read is not considered old (never delete on an unknown).
fn spool_older_than(entry: &std::fs::DirEntry, now: std::time::SystemTime) -> bool {
    entry
        .metadata()
        .ok()
        .and_then(|meta| meta.modified().ok())
        .and_then(|modified| now.duration_since(modified).ok())
        .is_some_and(|age| age >= SPOOL_GRACE_PERIOD)
}

#[cfg(unix)]
fn process_alive(pid: u32) -> bool {
    // SAFETY: `kill` with signal 0 performs only the existence/permission
    // check and delivers nothing.
    if unsafe { libc::kill(pid as libc::pid_t, 0) } == 0 {
        return true;
    }
    // ESRCH is the only errno that proves the process is gone. EPERM means
    // it exists under another user; anything else is unknown, and the safe
    // answer for an unknown PID is "alive" (keep the file).
    std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

#[cfg(not(unix))]
fn process_alive(_pid: u32) -> bool {
    true
}

/// Derives the uploader's hex pubkey from an npub directory name.
/// Shared with the automatic legacy migration.
pub(crate) fn npub_from_dir(dir: &Path) -> anyhow::Result<String> {
    let name = dir
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("directory has no name"))?;
    if let Ok(crate::nips::nip19::Nip19Entity::Pubkey(pk)) = crate::nips::nip19::parse_nip19(name) {
        return Ok(hex::encode(pk));
    }
    if name.len() == 64 && hex::decode(name).is_ok() {
        // Normalize: GET resolves blobs with a lowercased name, so an
        // uppercase legacy directory must be stored lowercased or its
        // blobs stay unreachable.
        return Ok(name.to_ascii_lowercase());
    }
    Err(anyhow!("not an npub directory name: {name}"))
}

fn npub_of(pubkey: &str) -> String {
    match hex::decode(pubkey) {
        Ok(bytes) if bytes.len() == 32 => {
            crate::nips::nip19::bech32_encode("npub", &bytes).unwrap_or_else(|_| pubkey.to_string())
        }
        _ => pubkey.to_string(),
    }
}

/// The legacy bech32m npub that earlier releases used for the storage
/// paths: blobs written before the encoder became spec-canonical stay
/// reachable through this name.
fn legacy_npub_of(pubkey: &str) -> String {
    match hex::decode(pubkey) {
        Ok(bytes) if bytes.len() == 32 => crate::nips::nip19::bech32m_encode("npub", &bytes)
            .unwrap_or_else(|_| pubkey.to_string()),
        _ => pubkey.to_string(),
    }
}

// ----- local storage --------------------------------------------------------

/// Releases a BlobStore space reservation on drop.
pub(crate) struct SpaceReservation<'a> {
    store: &'a BlobStore,
    size: u64,
}

impl Drop for SpaceReservation<'_> {
    fn drop(&mut self) {
        if let Storage::Local(s) = &self.store.storage {
            s.release(self.size);
        }
    }
}

struct LocalStore {
    root: PathBuf,
    // Kept open for the lifetime of the store so fd_root remains valid.
    _root_dir: std::fs::File,
    fd_root: Option<PathBuf>,
    /// The resolved root: every operation's parent directory is
    /// canonicalized and must resolve under this path, so a symlinked
    /// npub directory can never redirect reads, writes or deletes
    /// outside the blob store (the symlink-escape guard).
    canonical_root: PathBuf,
    /// Disk-full guard: uploads are refused while the free space on the
    /// filesystem hosting `root` is below this many bytes (0 disables).
    min_free_bytes: u64,
    /// Bytes reserved by in-flight uploads. Without this the uploads each
    /// check the raw free space and can collectively cross the floor
    /// (TOCTOU on `min_free_bytes`), which risks SIGBUS on LMDB writes.
    reserved: std::sync::atomic::AtomicU64,
}

impl LocalStore {
    async fn new(root: &Path, min_free_bytes: u64) -> Result<LocalStore> {
        tokio::fs::create_dir_all(root).await?;
        let canonical_root = tokio::fs::canonicalize(root).await?;
        let root_dir = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
                .open(&canonical_root)?
        };
        let fd = std::os::fd::AsRawFd::as_raw_fd(&root_dir);
        let fd_root = ["/proc/self/fd", "/dev/fd"]
            .into_iter()
            .map(|base| PathBuf::from(base).join(fd.to_string()))
            .find(|path| path.exists());
        Ok(LocalStore {
            root: root.to_path_buf(),
            _root_dir: root_dir,
            fd_root,
            canonical_root,
            min_free_bytes,
            reserved: std::sync::atomic::AtomicU64::new(0),
        })
    }

    #[cfg(test)]
    fn blob_path(&self, npub: &str, sha256: &str) -> PathBuf {
        self.root.join(npub).join(sha256)
    }

    fn rooted_path(&self, npub: &str, name: &str) -> PathBuf {
        // FreeBSD installations without fdescfs do not expose open
        // descriptors as pathname components. The canonical-root fallback
        // retains the symlink checks and keeps those systems functional.
        self.fd_root
            .as_ref()
            .map(|root| root.join(npub).join(name))
            .unwrap_or_else(|| self.canonical_root.join(npub).join(name))
    }

    fn npub_dir_path(&self, npub: &str) -> PathBuf {
        self.rooted_path(npub, "")
    }

    /// Whether the blob's parent directory is a real directory inside the
    /// canonical root. A symlinked npub directory — even one that stays
    /// inside the root (the blob would land in another npub's directory)
    /// — would resolve elsewhere and is refused. The final blob file
    /// itself is protected by `O_NOFOLLOW` where it is opened.
    async fn parent_within_root(&self, npub: &str) -> bool {
        let dir = self.root.join(npub);
        // The npub directory must not be a symlink itself.
        match tokio::fs::symlink_metadata(&dir).await {
            Ok(meta) if !meta.file_type().is_symlink() => {}
            _ => return false,
        }
        match tokio::fs::canonicalize(&dir).await {
            Ok(canonical) => canonical.starts_with(&self.canonical_root),
            Err(_) => false,
        }
    }

    /// Free bytes on the filesystem hosting the blob root, when statvfs
    /// succeeds (the same check the LMDB writer uses before committing).
    fn free_space(&self) -> Option<u64> {
        let c_path = std::ffi::CString::new(self.root.as_os_str().as_encoded_bytes()).ok()?;
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

    /// Whether the disk currently has room for an upload (the shared
    /// disk-full guard: `put` refuses, the BUD-06 preflight reports).
    fn check_space(&self) -> Result<()> {
        if self.min_free_bytes > 0
            && self
                .free_space()
                .is_some_and(|free| free < self.min_free_bytes)
        {
            return Err(crate::error::storage_full());
        }
        Ok(())
    }

    /// Reserves `size` bytes against the free-space floor: concurrent
    /// uploads would otherwise all pass the raw check and overshoot it.
    fn reserve(&self, size: u64) -> Result<()> {
        if self.min_free_bytes == 0 {
            return Ok(());
        }
        let reserved = self
            .reserved
            .fetch_add(size, std::sync::atomic::Ordering::Relaxed)
            .saturating_add(size);
        let overflow = self
            .free_space()
            .is_some_and(|free| free < self.min_free_bytes.saturating_add(reserved));
        if overflow {
            self.reserved
                .fetch_sub(size, std::sync::atomic::Ordering::Relaxed);
            return Err(crate::error::storage_full());
        }
        // Keep the plain check for when statvfs is unavailable.
        self.check_space()
    }

    fn release(&self, size: u64) {
        // Mirror `reserve`: with the floor disabled nothing was counted, so
        // subtracting here would wrap the counter.
        if self.min_free_bytes == 0 {
            return;
        }
        self.reserved
            .fetch_sub(size, std::sync::atomic::Ordering::Relaxed);
    }

    /// Fsyncs the directory a blob was just renamed into, so the new name
    /// is durable on disk. Without this, a crash after the (already
    /// durable) LMDB mapping commit could leave the mapping pointing at a
    /// file whose directory entry was never written — the blob reads as
    /// missing until the mapping is manually deleted. Best effort: the
    /// failure is logged, not fatal, because the state is healable.
    async fn sync_dir(&self, npub: &str) {
        #[cfg(unix)]
        {
            let dir = self.npub_dir_path(npub);
            let result = match tokio::fs::File::open(&dir).await {
                Ok(file) => file.sync_all().await,
                Err(e) => Err(e),
            };
            if let Err(e) = result {
                log::warn!("blossom: cannot fsync directory {}: {e}", dir.display());
            }
        }
        #[cfg(not(unix))]
        let _ = npub;
    }

    #[cfg(test)]
    async fn put(
        &self,
        npub: &str,
        sha256: &str,
        bytes: &[u8],
        _mime: &str,
        _uploaded: i64,
    ) -> Result<()> {
        let dir = self.root.join(npub);
        tokio::fs::create_dir_all(&dir).await?;
        // Symlink-escape guard: the (possibly pre-existing) npub
        // directory must resolve inside the blob root, or the write
        // would land in the symlink target's directory.
        if !self.parent_within_root(npub).await {
            return Err(anyhow!("blossom storage directory is a symlink"));
        }

        // Atomic write: the bytes land in a temp file first and are moved
        // into place with a rename. A crash mid-write can then never leave
        // a truncated blob at the final path — the file is either complete
        // or absent (the LMDB mapping may already reference the sha, but a
        // missing file is a healable state, a truncated one is not).
        // A stale temp is overwritten — a concurrent upload of the same
        // bytes writes identical content, so no `create_new` exclusivity
        // race can surface as a spurious failure — and O_NOFOLLOW keeps a
        // planted symlink from redirecting the write (or truncating an
        // external file through the link).
        let tmp_path = self.rooted_path(npub, &format!(".{sha256}.tmp"));
        let write = {
            use tokio::io::AsyncWriteExt;
            let mut tmp = tokio::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&tmp_path)
                .await?;
            let result = async {
                tmp.write_all(bytes).await?;
                tmp.flush().await
            }
            .await;
            drop(tmp);
            result
        };
        if let Err(e) = write {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(e.into());
        }
        if let Err(e) = tokio::fs::rename(&tmp_path, self.rooted_path(npub, sha256)).await {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(e.into());
        }
        self.sync_dir(npub).await;
        Ok(())
    }

    async fn put_file(&self, npub: &str, sha256: &str, source: &Path) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        let dir = self.npub_dir_path(npub);
        tokio::fs::create_dir_all(&dir).await?;
        if !self.parent_within_root(npub).await {
            return Err(anyhow!("blossom storage directory is a symlink"));
        }
        // Fast path: a spool on the same filesystem is moved into place
        // instead of copied (the upload already wrote it once). Any rename
        // failure (EXDEV, permissions, a planted directory at the target)
        // falls back to the copy path below.
        //
        // The spool was closed with `flush()` only (a no-op for tokio
        // files), so fsync it before the rename publishes the name: the
        // LMDB mapping that references the sha is already durable, and a
        // crash must not leave a truncated blob at the final path.
        let file = tokio::fs::File::open(source).await?;
        file.sync_all().await?;
        drop(file);
        if tokio::fs::rename(source, self.rooted_path(npub, sha256))
            .await
            .is_ok()
        {
            // Publish the directory entry durably before the caller
            // reports success (the mapping commit already landed).
            self.sync_dir(npub).await;
            return Ok(());
        }
        let tmp_path = self.rooted_path(npub, &format!(".{sha256}.tmp"));
        let mut input = tokio::fs::File::open(source).await?;
        let mut output = tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp_path)
            .await?;
        if let Err(e) = tokio::io::copy(&mut input, &mut output).await {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(e.into());
        }
        if let Err(e) = output.flush().await {
            drop(output);
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(e.into());
        }
        // Flush the file contents to disk before the rename publishes the
        // name: otherwise a crash can leave the final path pointing at a
        // file whose data has not reached the platter yet (the mapping
        // already references the sha, so a truncated blob would surface).
        if let Err(e) = output.sync_all().await {
            drop(output);
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(e.into());
        }
        drop(output);
        if let Err(e) = tokio::fs::rename(&tmp_path, self.rooted_path(npub, sha256)).await {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(e.into());
        }
        self.sync_dir(npub).await;
        Ok(())
    }

    /// Opens the blob for streaming, seeked to `start`; the caller reads
    /// at most `len` bytes from the returned file (`len` is enforced by
    /// the streaming wrapper, not by the file handle).
    async fn open(
        &self,
        npub: &str,
        sha256: &str,
        start: u64,
        _len: u64,
    ) -> Result<Option<BlobStream>> {
        // Symlink-escape guard: a symlinked npub directory would resolve
        // outside the root; a symlinked blob file would be followed by a
        // plain open. Both are refused (the blob reads as missing).
        if !self.parent_within_root(npub).await {
            let dir = self.root.join(npub);
            if let Ok(meta) = tokio::fs::symlink_metadata(&dir).await
                && !meta.file_type().is_symlink()
                && !meta.is_dir()
            {
                return Err(anyhow!("blossom storage directory is not a directory"));
            }
            return Ok(None);
        }
        let mut file = match tokio::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.rooted_path(npub, sha256))
            .await
        {
            Ok(f) => f,
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound
                    || e.raw_os_error() == Some(libc::ELOOP)
                    // FreeBSD reports a refused O_NOFOLLOW open as EMLINK
                    // ("Too many links"), Linux as ELOOP.
                    || e.raw_os_error() == Some(libc::EMLINK) =>
            {
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
        };
        use tokio::io::AsyncSeekExt;
        file.seek(std::io::SeekFrom::Start(start)).await?;
        Ok(Some(BlobStream::Local(file)))
    }

    async fn delete(&self, npub: &str, sha256: &str) -> Result<bool> {
        // Symlink-escape guard: with a symlinked npub directory, removing
        // the blob would remove a file in the symlink target's directory.
        // (A symlinked blob file itself is safe to remove — only the link
        // is deleted.)
        if !self.parent_within_root(npub).await {
            let dir = self.npub_dir_path(npub);
            return match tokio::fs::symlink_metadata(&dir).await {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Ok(_) => Err(anyhow!("blossom storage directory is unsafe")),
                Err(e) => Err(e.into()),
            };
        }
        let path = self.rooted_path(npub, sha256);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Scans `<root>/<npub>/<sha>.meta.json` for the legacy migration.
    /// Scans one legacy store for pre-mapping blobs, streaming entries in
    /// bounded chunks: the caller commits each chunk before the next is
    /// produced, so memory stays flat regardless of store size.
    async fn scan_legacy(&self, tx: tokio::sync::mpsc::Sender<Vec<LegacyEntry>>) -> Result<()> {
        // Metas take precedence: a sha found via its meta is not derived
        // again from the raw blob. A set keeps this O(n) for big stores.
        // (Scoped per uploader directory: metas and blobs of one owner live
        // in one directory, so cross-directory duplicates cannot occur.)
        let mut buf: Vec<(String, String, u64, i64, String)> = Vec::new();
        let mut dirs = tokio::fs::read_dir(&self.root).await?;
        while let Some(entry) = dirs.next_entry().await? {
            let dir = entry.path();
            // `file_type` does not follow symlinks: a symlinked npub
            // directory (an attempt to point the migration at an
            // external directory) is skipped, not scanned.
            let Ok(ft) = entry.file_type().await else {
                continue;
            };
            if !ft.is_dir() {
                continue;
            }
            let Ok(pubkey) = npub_from_dir(&dir) else {
                continue;
            };
            let mut via_meta: std::collections::HashSet<String> = std::collections::HashSet::new();
            // Pass 1: legacy meta files carry the full descriptor.
            let mut files = match tokio::fs::read_dir(&dir).await {
                Ok(f) => f,
                Err(_) => continue,
            };
            while let Some(file) = files.next_entry().await? {
                // A symlinked meta (an attempt to leak an external
                // file's descriptor) is skipped, not read.
                if !file.file_type().await.is_ok_and(|ft| ft.is_file()) {
                    continue;
                }
                let name = file.file_name().to_string_lossy().into_owned();
                let Some(sha) = name.strip_suffix(".meta.json") else {
                    continue;
                };
                // A stray `*.meta.json` whose stem is not a 64-hex sha must
                // not create a bogus mapping (data pollution). The hash is
                // normalized so an uppercase legacy name stays reachable.
                if sha.len() != 64 || hex::decode(sha).is_err() {
                    continue;
                }
                let sha = sha.to_ascii_lowercase();
                if let Ok(raw) = tokio::fs::read(file.path()).await
                    && let Ok(meta) = serde_json::from_slice::<serde_json::Value>(&raw)
                {
                    buf.push((
                        sha.clone(),
                        crate::server::blossom::sanitize_mime(meta["mime"].as_str().unwrap_or("")),
                        meta["size"].as_u64().unwrap_or(0),
                        meta["uploaded"].as_i64().unwrap_or(0),
                        pubkey.clone(),
                    ));
                    via_meta.insert(sha);
                    if buf.len() >= 5000 {
                        let chunk = std::mem::take(&mut buf);
                        if tx.send(chunk).await.is_err() {
                            return Ok(());
                        }
                    }
                }
            }
            // Pass 2: blobs without a meta (written after the metadata
            // moved to LMDB) are derived from the file itself.
            let mut files = match tokio::fs::read_dir(&dir).await {
                Ok(f) => f,
                Err(_) => continue,
            };
            while let Some(file) = files.next_entry().await? {
                // A symlinked blob (pointing at an external file) is
                // skipped, not measured.
                if !file.file_type().await.is_ok_and(|ft| ft.is_file()) {
                    continue;
                }
                // The meta pass stores lowercase hashes: a legacy
                // uppercase file name must be normalized or the derived
                // entry would not match (and GET lowercases too).
                let name = file.file_name().to_string_lossy().to_ascii_lowercase();
                if name.len() != 64 || hex::decode(&name).is_err() || via_meta.contains(&name) {
                    continue;
                }
                let (size, uploaded) = match tokio::fs::metadata(file.path()).await {
                    Ok(meta) => (
                        meta.len(),
                        meta.modified()
                            .ok()
                            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                            .map(|d| d.as_secs() as i64)
                            .unwrap_or(0),
                    ),
                    Err(_) => continue,
                };
                buf.push((
                    name,
                    "application/octet-stream".to_string(),
                    size,
                    uploaded,
                    pubkey.clone(),
                ));
                if buf.len() >= 5000 {
                    let chunk = std::mem::take(&mut buf);
                    if tx.send(chunk).await.is_err() {
                        return Ok(());
                    }
                }
            }
        }
        if !buf.is_empty() && tx.send(buf).await.is_err() {
            // Receiver went away (shutdown): stop early, the marker stays
            // unset so the migration retries on the next startup.
        }
        Ok(())
    }
}

// ----- S3 / R2 storage ------------------------------------------------------

pub(crate) struct S3Config {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub access_key: String,
    pub secret_key: String,
}

struct S3Store {
    client: S3Client,
}

impl S3Store {
    async fn new(cfg: S3Config) -> Result<S3Store> {
        Ok(S3Store {
            client: S3Client::new(
                &cfg.endpoint,
                &cfg.region,
                &cfg.bucket,
                &cfg.access_key,
                &cfg.secret_key,
            ),
        })
    }

    #[cfg(test)]
    async fn put(
        &self,
        npub: &str,
        sha256: &str,
        bytes: &[u8],
        mime: &str,
        _uploaded: i64,
    ) -> Result<()> {
        self.client
            .put_object(&format!("{npub}/{sha256}"), bytes, mime)
            .await
    }

    async fn put_file(
        &self,
        npub: &str,
        sha256: &str,
        source: &Path,
        size: u64,
        mime: &str,
    ) -> Result<()> {
        self.client
            .put_object_file(&format!("{npub}/{sha256}"), source, size, mime)
            .await
    }

    /// Opens the blob for streaming: fetches the `bytes=start-...` range
    /// and returns the response body (streamed in chunks by the caller).
    async fn open(
        &self,
        npub: &str,
        sha256: &str,
        start: u64,
        len: u64,
    ) -> Result<Option<BlobStream>> {
        match self
            .client
            .get_object_range(&format!("{npub}/{sha256}"), start, len)
            .await?
        {
            Some(resp) => Ok(Some(BlobStream::S3(resp))),
            None => Ok(None),
        }
    }

    async fn delete(&self, npub: &str, sha256: &str) -> Result<bool> {
        // The blob is removed first: a crash in between leaves the LMDB
        // mapping (a later delete cleans it up), never an invisible
        // orphan object.
        let existed = self
            .client
            .delete_object(&format!("{npub}/{sha256}"))
            .await?;
        Ok(existed)
    }

    /// Lists the bucket and fetches the meta objects (bounded parallelism)
    /// for the legacy migration.
    /// Streams one legacy bucket's pre-mapping blobs in listing-page order,
    /// resolving each page's small meta objects with bounded concurrency
    /// and emitting 5000-row chunks. A blob and its meta can land on
    /// different pages; same-sha duplicates across pages rewrite the same
    /// mapping bytes, so page-local dedup is sufficient for correctness.
    async fn scan_legacy(&self, tx: tokio::sync::mpsc::Sender<Vec<LegacyEntry>>) -> Result<()> {
        let mut token = String::new();
        loop {
            let (keys, next) = self.client.list_keys_page("", &token).await?;
            token = next;
            // Only the legacy meta objects are fetched (small): the sizes
            // of the blob objects come straight from the listing, so a
            // bucket with many blobs is not downloaded during the
            // migration.
            let mut out = Vec::new();
            let mut via_meta: std::collections::HashSet<String> = std::collections::HashSet::new();
            let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(16));
            let mut tasks = tokio::task::JoinSet::new();
            for (key, size) in keys {
                let (npub, file) = match key.split_once('/') {
                    Some((n, f)) => (n, f),
                    None => continue,
                };
                let Ok(pubkey) = npub_from_dir(std::path::Path::new(npub)) else {
                    continue;
                };
                if let Some(sha) = file.strip_suffix(".meta.json") {
                    // Only a 64-hex stem names a blob; a stray object must
                    // not create a bogus mapping (normalized so an uppercase
                    // legacy name stays reachable).
                    if sha.len() != 64 || hex::decode(sha).is_err() {
                        continue;
                    }
                    let sha = sha.to_ascii_lowercase();
                    via_meta.insert(sha);
                    let client = self.client.clone();
                    let semaphore = std::sync::Arc::clone(&semaphore);
                    tasks.spawn(async move {
                        let _permit = semaphore.acquire().await;
                        let raw = client.get_object(&key).await;
                        (key, pubkey, raw)
                    });
                    continue;
                }
                // Blobs without a meta (metadata moved to LMDB): the size
                // comes from the listing; mime falls back to octet-stream.
                if file.len() == 64 && hex::decode(file).is_ok() {
                    out.push((
                        file.to_string(),
                        "application/octet-stream".to_string(),
                        size,
                        0,
                        pubkey,
                    ));
                }
            }
            while let Some(Ok((key, pubkey, raw))) = tasks.join_next().await {
                let Some(sha) = key
                    .strip_suffix(".meta.json")
                    .and_then(|k| k.split_once('/'))
                    .map(|(_, f)| f)
                else {
                    continue;
                };
                if sha.len() != 64 || hex::decode(sha).is_err() {
                    continue;
                }
                let sha = sha.to_ascii_lowercase();
                if let Ok(Some(raw)) = raw
                    && let Ok(meta) = serde_json::from_slice::<serde_json::Value>(&raw)
                {
                    out.push((
                        sha,
                        crate::server::blossom::sanitize_mime(meta["mime"].as_str().unwrap_or("")),
                        meta["size"].as_u64().unwrap_or(0),
                        meta["uploaded"].as_i64().unwrap_or(0),
                        pubkey,
                    ));
                }
            }
            // The derived entries must not duplicate meta-backed ones.
            out.retain(|(sha, _, _, _, _)| !via_meta.contains(sha));
            // Emit in bounded chunks so one giant page cannot spike memory
            // (S3 pages are ~1000 keys, far below the chunk size, but the
            // bound holds regardless of server behavior).
            for chunk in out.chunks(5000) {
                if tx.send(chunk.to_vec()).await.is_err() {
                    return Ok(());
                }
            }
            if token.is_empty() {
                break;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(i: u8) -> String {
        format!("{:02x}", i).repeat(32)
    }

    async fn db(tmp: &str) -> (DbClient, std::path::PathBuf) {
        let cfg = crate::config::DatabaseConfig {
            path: std::env::temp_dir().join(format!(
                "nostrfy-blossom-store-test-{tmp}-{}",
                std::process::id()
            )),
            // Small mappings: the test VM cannot afford several
            // default-sized (1 GB / 1 TiB) LMDB reservations at once.
            map_size: 16 * 1024 * 1024,
            max_map_size: 32 * 1024 * 1024,
            ..Default::default()
        };
        let _ = std::fs::remove_dir_all(&cfg.path);
        let db = DbClient::open(
            &cfg,
            false,
            std::sync::Arc::new(Default::default()),
            0,
            128,
            4096,
            262144,
        )
        .unwrap();
        (db, cfg.path)
    }

    /// The local store behind the store (the symlink tests need its
    /// paths, which are private to `LocalStore`).
    fn local(s: &BlobStore) -> &LocalStore {
        match &s.storage {
            Storage::Local(l) => l,
            Storage::S3(_) => panic!("local store only"),
        }
    }

    /// Reads a blob through the streaming path (open + collect).
    async fn read_all(store: &BlobStore, pubkey: &str, sha: &str) -> Option<Vec<u8>> {
        use futures_util::StreamExt as _;
        let stream = store.open_stream(pubkey, sha, 0, u64::MAX).await.unwrap()?;
        let mut out = Vec::new();
        match stream {
            crate::server::blossom::storage::BlobStream::Local(mut file) => {
                use tokio::io::AsyncReadExt as _;
                let mut buf = [0u8; 1024];
                loop {
                    let n = file.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    out.extend_from_slice(&buf[..n]);
                }
            }
            crate::server::blossom::storage::BlobStream::S3(resp) => {
                let mut stream = resp.bytes_stream();
                while let Some(chunk) = stream.next().await {
                    out.extend_from_slice(&chunk.unwrap());
                }
            }
        }
        Some(out)
    }

    async fn store(tmp: &str) -> (BlobStore, std::path::PathBuf) {
        let (db, db_path) = db(tmp).await;
        let dir =
            std::env::temp_dir().join(format!("nostrfy-blossom-test-{tmp}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = BlobStore::new("local", &dir, 0, None, db, Stats::new())
            .await
            .unwrap();
        (s, db_path)
    }

    #[tokio::test]
    async fn multi_owner_put_find_list_delete() {
        let (s, _db_path) = store("multi").await;
        let a = pk(1);
        let b = pk(2);
        let sha = "ab".repeat(32);
        let bytes = b"hello blossom";

        let da = s.put(&a, &sha, bytes, "text/plain").await.unwrap();
        assert_eq!(da.pubkey, a);
        // Same bytes by another pubkey: both become owners.
        let db = s.put(&b, &sha, bytes, "text/plain").await.unwrap();
        assert_eq!(db.pubkey, b);

        assert_eq!(s.find(&sha).await.unwrap().unwrap().pubkey, a);
        assert!(s.has(&a, &sha).await.unwrap());
        assert!(s.has(&b, &sha).await.unwrap());
        assert!(!s.has(&pk(3), &sha).await.unwrap());
        assert_eq!(s.list(&a, 10_000).await.len(), 1);
        assert_eq!(s.list(&b, 10_000).await.len(), 1);
        assert_eq!(s.list(&pk(3), 10_000).await.len(), 0);

        let npub_a = npub_of(&a);
        let npub_b = npub_of(&b);
        assert_eq!(read_all(&s, &npub_a, &sha).await.unwrap(), bytes);
        assert_eq!(read_all(&s, &npub_b, &sha).await.unwrap(), bytes);

        // One owner deletes: the other owner's copy survives.
        assert!(s.delete(&b, &sha).await.unwrap());
        assert!(s.find(&sha).await.unwrap().is_some());
        assert!(read_all(&s, &npub_a, &sha).await.is_some());
        assert!(read_all(&s, &npub_b, &sha).await.is_none());
        assert!(!s.has(&b, &sha).await.unwrap());
        assert!(s.has(&a, &sha).await.unwrap());
        assert_eq!(s.list(&a, 10_000).await.len(), 1);
        assert_eq!(s.list(&b, 10_000).await.len(), 0);

        // The last owner's delete removes the mapping.
        assert!(s.delete(&a, &sha).await.unwrap());
        assert!(s.find(&sha).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn open_stream_any_falls_back_to_second_owner() {
        // The first owner's file may vanish out-of-band while a later
        // owner's copy is intact: the blob must still stream.
        let (s, _db_path) = store("fallback").await;
        let a = pk(1);
        let b = pk(2);
        let sha = "cd".repeat(32);
        let bytes = b"fallback blob";
        s.put(&a, &sha, bytes, "text/plain").await.unwrap();
        s.put(&b, &sha, bytes, "text/plain").await.unwrap();
        // Delete A's file behind the mapping's back (same layout as
        // `store()`: tempdir/nostrfy-blossom-test-fallback-<pid>/<npub>/<sha>).
        let dir = std::env::temp_dir().join(format!(
            "nostrfy-blossom-test-fallback-{}",
            std::process::id()
        ));
        tokio::fs::remove_file(dir.join(npub_of(&a)).join(&sha))
            .await
            .unwrap();
        let (stream, owner) = s
            .open_stream_any(&sha, 0, bytes.len() as u64)
            .await
            .unwrap()
            .expect("second owner's copy must stream");
        assert_eq!(owner, b);
        drop(stream);
    }

    #[tokio::test]
    async fn mapped_missing_object_is_counted() {
        // A mapping can outlive its object (an out-of-band delete, or a
        // pre-publish-first build's mapping): the lookup must count the
        // mapped-but-missing blob (best effort) without changing behavior.
        let (s, _db_path) = store("missing-object").await;
        let a = pk(1);
        let sha = "9a".repeat(32);
        s.put(&a, &sha, b"gone soon", "text/plain").await.unwrap();
        let before = s
            .stats
            .blossom_missing_objects
            .load(std::sync::atomic::Ordering::Relaxed);
        // Remove the object behind the mapping's back.
        let dir = std::env::temp_dir().join(format!(
            "nostrfy-blossom-test-missing-object-{}",
            std::process::id()
        ));
        tokio::fs::remove_file(dir.join(npub_of(&a)).join(&sha))
            .await
            .unwrap();
        assert!(s.open_stream_any(&sha, 0, 1).await.unwrap().is_none());
        assert_eq!(
            s.stats
                .blossom_missing_objects
                .load(std::sync::atomic::Ordering::Relaxed),
            before + 1,
            "a mapped-but-missing object must be counted"
        );
        // A missing mapping is not a missing object.
        assert!(
            s.open_stream_any(&"bb".repeat(32), 0, 1)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            s.stats
                .blossom_missing_objects
                .load(std::sync::atomic::Ordering::Relaxed),
            before + 1,
            "an unmapped hash must not be counted"
        );
        // A reachable object is not counted either.
        s.put(&a, &sha, b"gone soon", "text/plain").await.unwrap();
        assert!(s.open_stream_any(&sha, 0, 1).await.unwrap().is_some());
        assert_eq!(
            s.stats
                .blossom_missing_objects
                .load(std::sync::atomic::Ordering::Relaxed),
            before + 1,
            "a successful lookup must not be counted"
        );
        s.db.shutdown();
    }

    #[tokio::test]
    async fn local_put_is_atomic() {
        // The final file must be written via a temp file + rename: no
        // `.tmp` leftovers, and the blob is served from its final path.
        let (s, _db_path) = store("atomic").await;
        let a = pk(1);
        let sha = "ef".repeat(32);
        let bytes = b"atomic blob";
        s.put(&a, &sha, bytes, "text/plain").await.unwrap();
        let npub_a = npub_of(&a);
        assert_eq!(read_all(&s, &npub_a, &sha).await.unwrap(), bytes);
        let npub_dir = std::env::temp_dir().join(format!(
            "nostrfy-blossom-test-atomic-{}",
            std::process::id()
        ));
        let dir = npub_dir.join(&npub_a);
        let entries = std::fs::read_dir(&dir).unwrap();
        let names: Vec<String> = entries
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec![sha], "no temp files may be left behind");
    }

    #[test]
    fn local_store_refuses_uploads_when_disk_is_full() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (s, _db_path) = store("full").await;
            let a = pk(1);
            let sha = "cd".repeat(32);
            // A margin above any real free space: the put is refused.
            let dir = std::env::temp_dir()
                .join(format!("nostrfy-blossom-test-full-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            let full = crate::server::blossom::storage::BlobStore::new(
                "local",
                &dir,
                u64::MAX,
                None,
                s.db.clone(),
                Stats::new(),
            )
            .await
            .unwrap();
            let err = full.put(&a, &sha, b"x", "text/plain").await.unwrap_err();
            assert_eq!(err.to_string(), "storage is full");
            // The guard runs before any write: neither a file nor an orphan
            // mapping may be left behind.
            assert!(
                full.open_stream(&a, &sha, 0, 1).await.unwrap().is_none(),
                "no file may be written for the refused upload"
            );
            assert!(
                full.find(&sha).await.unwrap().is_none(),
                "no mapping may be left for the refused upload"
            );
            // The disabled guard (0) lets the upload through.
            let sha2 = "ef".repeat(32);
            let disabled = crate::server::blossom::storage::BlobStore::new(
                "local",
                &dir,
                0,
                None,
                s.db.clone(),
                Stats::new(),
            )
            .await
            .unwrap();
            assert!(
                disabled.put(&a, &sha2, b"y", "text/plain").await.is_ok(),
                "min_free_bytes = 0 must disable the guard"
            );
            s.db.shutdown();
        });
    }

    #[test]
    fn local_open_stream_serves_full_and_ranges() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (s, _db_path) = store("stream").await;
            let a = pk(1);
            let sha = "12".repeat(32);
            let data: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
            s.put(&a, &sha, &data, "application/octet-stream")
                .await
                .unwrap();
            // Full read: everything from offset 0.
            let full = read_all(&s, &a, &sha).await.unwrap();
            assert_eq!(full, data);
            // Range read: the caller reads at most `len` bytes after seek.
            let mut file = match s.open_stream(&a, &sha, 1_000, 1_000).await.unwrap() {
                Some(crate::server::blossom::storage::BlobStream::Local(f)) => f,
                other => panic!("expected a local stream, got {other:?}"),
            };
            use tokio::io::AsyncReadExt;
            let mut buf = vec![0u8; 1_000];
            file.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, data[1_000..2_000], "the range must be exact");
            // Nonexistent blob: None.
            assert!(
                s.open_stream(&a, &"ab".repeat(32), 0, 10)
                    .await
                    .unwrap()
                    .is_none()
            );
            s.db.shutdown();
        });
    }

    #[test]
    fn open_refuses_symlinked_blob() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (s, _db_path) = store("symlink-read").await;
            let a = pk(1);
            let sha = "12".repeat(32);
            let npub = npub_of(&a);
            s.put(&a, &sha, b"real", "text/plain").await.unwrap();
            // Replace the blob file with a symlink to an external file.
            let external = std::env::temp_dir().join(format!(
                "nostrfy-blossom-symlink-external-{}",
                std::process::id()
            ));
            std::fs::write(&external, b"secret").unwrap();
            std::fs::remove_file(local(&s).blob_path(&npub, &sha)).unwrap();
            std::os::unix::fs::symlink(&external, local(&s).blob_path(&npub, &sha)).unwrap();
            // The symlink is refused: the blob reads as missing, and the
            // external content is never served.
            assert!(
                s.open_stream(&a, &sha, 0, 1).await.unwrap().is_none(),
                "a symlinked blob must not be followed"
            );
            std::fs::remove_file(&external).unwrap();
            s.db.shutdown();
        });
    }

    #[test]
    fn delete_does_not_follow_symlinked_npub_dir() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (s, _db_path) = store("symlink-del").await;
            let a = pk(1);
            let sha = "34".repeat(32);
            let npub = npub_of(&a);
            s.put(&a, &sha, b"real", "text/plain").await.unwrap();
            // Point the npub directory at an external directory.
            let external = std::env::temp_dir().join(format!(
                "nostrfy-blossom-symlink-dir-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&external);
            std::fs::create_dir_all(&external).unwrap();
            std::fs::write(external.join("victim"), b"keep me").unwrap();
            std::fs::remove_dir_all(local(&s).root.join(&npub)).unwrap();
            std::os::unix::fs::symlink(&external, local(&s).root.join(&npub)).unwrap();
            // The delete is refused: the external file must survive.
            assert!(s.delete(&a, &sha).await.is_err());
            assert!(
                s.has(&a, &sha).await.unwrap(),
                "failed delete must keep the mapping"
            );
            assert_eq!(
                std::fs::read(external.join("victim")).unwrap(),
                b"keep me",
                "the symlink target's file must be untouched"
            );
            let _ = std::fs::remove_dir_all(&external);
            s.db.shutdown();
        });
    }

    #[test]
    fn put_refuses_symlinked_npub_dir() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (s, _db_path) = store("symlink-put").await;
            let a = pk(1);
            let sha = "56".repeat(32);
            let npub = npub_of(&a);
            // Point the npub directory at an external directory.
            let external = std::env::temp_dir().join(format!(
                "nostrfy-blossom-symlink-write-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&external);
            std::fs::create_dir_all(&external).unwrap();
            std::os::unix::fs::symlink(&external, local(&s).root.join(&npub)).unwrap();
            let err = s.put(&a, &sha, b"x", "text/plain").await.unwrap_err();
            assert!(
                err.to_string().contains("symlink"),
                "the write must be refused: {err}"
            );
            assert!(
                !external.join(&sha).exists() && !external.join(format!(".{sha}.tmp")).exists(),
                "nothing may be written into the symlink target"
            );
            assert!(
                s.open_stream(&npub, &sha, 0, 1).await.unwrap().is_none(),
                "the blob must not be readable through the symlink"
            );
            assert!(
                s.find(&sha).await.unwrap().is_none(),
                "the failed upload must roll back its owner mapping (no orphan)"
            );
            let _ = std::fs::remove_dir_all(&external);
            s.db.shutdown();
        });
    }

    #[test]
    fn put_overwrites_stale_tmp_and_refuses_internal_symlink() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (s, _db_path) = store("symlink-stale").await;
            let a = pk(1);
            let sha = "78".repeat(32);
            let npub = npub_of(&a);
            // A stale temp (e.g. left by a crash) is overwritten, and a
            // symlink planted at the temp path is never followed.
            let tmp = local(&s).root.join(&npub).join(format!(".{sha}.tmp"));
            s.put(&a, &sha, b"first", "text/plain").await.unwrap();
            std::fs::write(&tmp, b"stale").unwrap();
            s.put(&a, &sha, b"second", "text/plain").await.unwrap();
            let mut file = match s.open_stream(&a, &sha, 0, 6).await.unwrap() {
                Some(crate::server::blossom::storage::BlobStream::Local(f)) => f,
                other => panic!("expected a local stream, got {other:?}"),
            };
            use tokio::io::AsyncReadExt;
            let mut buf = Vec::new();
            file.read_to_end(&mut buf).await.unwrap();
            assert_eq!(buf, b"second", "the stale temp must be overwritten");
            // A symlink at the temp path: the write is refused, the link
            // (not its target) is removed.
            let external = std::env::temp_dir().join(format!(
                "nostrfy-blossom-symlink-tmp-{}",
                std::process::id()
            ));
            std::fs::write(&external, b"precious").unwrap();
            // The second put's rename consumed the temp: plant a fresh
            // symlink at the temp path.
            let _ = std::fs::remove_file(&tmp);
            std::os::unix::fs::symlink(&external, &tmp).unwrap();
            s.put(&a, &sha, b"third", "text/plain").await.unwrap_err();
            assert_eq!(
                std::fs::read(&external).unwrap(),
                b"precious",
                "the symlink target must be untouched"
            );
            // A failed re-upload must keep the uploader's pre-existing,
            // valid mapping (the blob from the second put is still there).
            assert!(
                s.find(&sha).await.unwrap().is_some(),
                "a failed re-upload must not roll back the existing mapping"
            );
            std::fs::remove_file(&external).unwrap();
            s.db.shutdown();
        });
    }

    #[test]
    fn migration_skips_symlinked_npub_dirs() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (s, _db_path) = store("symlink-mig").await;
            // An external directory looks like a legacy store: it must
            // not be scanned through a symlinked npub directory.
            let external = std::env::temp_dir().join(format!(
                "nostrfy-blossom-symlink-migrate-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&external);
            std::fs::create_dir_all(&external).unwrap();
            std::fs::write(
                external.join(format!("{}.meta.json", "ab".repeat(32))),
                r#"{"mime":"text/plain","size":7,"uploaded":1}"#,
            )
            .unwrap();
            let npub = "npub1external";
            std::os::unix::fs::symlink(&external, local(&s).root.join(npub)).unwrap();
            let (_tx, drain) = tokio::sync::watch::channel(false);
            let mapped = s.auto_migrate_legacy(drain).await.unwrap();
            assert_eq!(
                mapped,
                MigrationOutcome::Completed(0),
                "the migration must not map files through a symlinked directory"
            );
            assert!(
                s.find(&"ab".repeat(32)).await.unwrap().is_none(),
                "no mapping may reference the external file"
            );
            let _ = std::fs::remove_dir_all(&external);
            s.db.shutdown();
        });
    }

    #[test]
    fn migration_skips_symlinked_blob_files() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (s, _db_path) = store("symlink-mig2").await;
            let a = pk(1);
            let npub = npub_of(&a);
            let dir = local(&s).root.join(&npub);
            std::fs::create_dir_all(&dir).unwrap();
            // A symlinked blob (pointing at an external file) and a
            // symlinked meta must not be mapped: their descriptors are
            // not external metadata to leak.
            let external = std::env::temp_dir().join(format!(
                "nostrfy-blossom-symlink-migrate2-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_file(&external);
            std::fs::write(&external, b"secret payload").unwrap();
            std::os::unix::fs::symlink(&external, dir.join("ab".repeat(32))).unwrap();
            let meta = std::env::temp_dir().join(format!(
                "nostrfy-blossom-symlink-migrate2-meta-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_file(&meta);
            std::fs::write(&meta, r#"{"mime":"text/plain","size":999,"uploaded":1}"#).unwrap();
            std::os::unix::fs::symlink(&meta, dir.join(format!("{}.meta.json", "cd".repeat(32))))
                .unwrap();
            let (_tx, drain) = tokio::sync::watch::channel(false);
            let mapped = s.auto_migrate_legacy(drain).await.unwrap();
            assert_eq!(
                mapped,
                MigrationOutcome::Completed(0),
                "the migration must not map symlinked blob files"
            );
            assert!(s.find(&"ab".repeat(32)).await.unwrap().is_none());
            assert!(s.find(&"cd".repeat(32)).await.unwrap().is_none());
            let _ = std::fs::remove_file(&external);
            let _ = std::fs::remove_file(&meta);
            s.db.shutdown();
        });
    }

    #[tokio::test]
    async fn mapping_survives_reopen() {
        // The mapping lives in LMDB: a reopened store (new process, no
        // scan, no index) resolves everything.
        let (db, db_path) = db("reopen").await;
        let dir = std::env::temp_dir().join(format!(
            "nostrfy-blossom-test-reopen-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        {
            let s = BlobStore::new("local", &dir, 0, None, db, Stats::new())
                .await
                .unwrap();
            let sha = "cd".repeat(32);
            s.put(&pk(1), &sha, b"x", "image/png").await.unwrap();
            s.put(&pk(2), &sha, b"x", "image/png").await.unwrap();
            let sha2 = "ef".repeat(32);
            s.put(&pk(1), &sha2, b"y", "text/plain").await.unwrap();
        }
        let db = DbClient::open(
            &crate::config::DatabaseConfig {
                path: db_path,
                // Small mappings: the test VM cannot afford several
                // default-sized (1 GB / 1 TiB) LMDB reservations at once.
                map_size: 16 * 1024 * 1024,
                max_map_size: 32 * 1024 * 1024,
                ..Default::default()
            },
            false,
            std::sync::Arc::new(Default::default()),
            0,
            128,
            4096,
            262144,
        )
        .unwrap();
        let s = BlobStore::new("local", &dir, 0, None, db, Stats::new())
            .await
            .unwrap();
        let sha = "cd".repeat(32);
        assert_eq!(s.find(&sha).await.unwrap().unwrap().pubkey, pk(1));
        assert!(s.has(&pk(1), &sha).await.unwrap());
        assert!(s.has(&pk(2), &sha).await.unwrap());
        assert_eq!(s.list(&pk(1), 10_000).await.len(), 2);
        assert_eq!(s.list(&pk(2), 10_000).await.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn auto_migration_merges_multi_owner_blobs() {
        let (db, db_path) = db("mig2").await;
        let dir =
            std::env::temp_dir().join(format!("nostrfy-blossom-test-mig2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // レガシー: 同一 blob が 2 つの npub ディレクトリに存在（メタあり）
        let sha = "dd".repeat(32);
        for pk in [pk(1), pk(2)] {
            let npub = npub_of(&pk);
            let npub_dir = dir.join(&npub);
            std::fs::create_dir_all(&npub_dir).unwrap();
            std::fs::write(npub_dir.join(&sha), b"x").unwrap();
            std::fs::write(
                npub_dir.join(format!("{sha}.meta.json")),
                br#"{"sha256":"dddd","size":1,"mime":"image/png","uploaded":1787000000}"#,
            )
            .unwrap();
        }
        let s = BlobStore::new("local", &dir, 0, None, db, Stats::new())
            .await
            .unwrap();
        let (_tx, drain) = tokio::sync::watch::channel(false);
        let migrated = s.auto_migrate_legacy(drain).await.unwrap();
        assert_eq!(
            migrated,
            MigrationOutcome::Completed(2),
            "both owners are mapped"
        );
        assert!(s.has(&pk(1), &sha).await.unwrap());
        assert!(
            s.has(&pk(2), &sha).await.unwrap(),
            "second owner survives the migration"
        );
        assert_eq!(s.list(&pk(1), 10_000).await.len(), 1);
        assert_eq!(s.list(&pk(2), 10_000).await.len(), 1);
        // 一人削除してももう一人は残る
        assert!(s.delete(&pk(1), &sha).await.unwrap());
        assert!(s.find(&sha).await.unwrap().is_some());
        let _ = std::fs::remove_dir_all(&dir);
        let _ = db_path;
    }

    /// A drain that fires before the pass completes must leave the marker
    /// unset: the marker is written only after a full scan, so the next
    /// start resumes instead of skipping an unmapped store.
    #[tokio::test]
    async fn drained_migration_leaves_the_marker_unset_for_the_next_start() {
        let (db, db_path) = db("mig-drain").await;
        let dir = std::env::temp_dir().join(format!(
            "nostrfy-blossom-test-mig-drain-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let a = pk(1);
        let sha = "ee".repeat(32);
        let npub_dir = dir.join(npub_of(&a));
        std::fs::create_dir_all(&npub_dir).unwrap();
        std::fs::write(npub_dir.join(&sha), b"x").unwrap();
        std::fs::write(
            npub_dir.join(format!("{sha}.meta.json")),
            br#"{"size":1,"mime":"text/plain","uploaded":1787000000}"#,
        )
        .unwrap();
        let s = BlobStore::new("local", &dir, 0, None, db, Stats::new())
            .await
            .unwrap();

        // Already draining: nothing is scanned, nothing is mapped and the
        // marker stays unset.
        let (tx, drain) = tokio::sync::watch::channel(false);
        tx.send_replace(true);
        assert_eq!(
            s.auto_migrate_legacy(drain).await.unwrap(),
            MigrationOutcome::Interrupted(0)
        );
        assert!(
            !s.db.blossom_migration_done().await,
            "an interrupted pass must not write the marker"
        );
        assert!(s.find(&sha).await.unwrap().is_none());

        // The next start (a live drain signal) completes and marks.
        let (_tx, drain) = tokio::sync::watch::channel(false);
        assert_eq!(
            s.auto_migrate_legacy(drain).await.unwrap(),
            MigrationOutcome::Completed(1)
        );
        assert!(s.db.blossom_migration_done().await);
        assert!(s.has(&a, &sha).await.unwrap());
        let _ = std::fs::remove_dir_all(&dir);
        let _ = db_path;
    }

    #[test]
    fn npub_of_roundtrip() {
        let hex = pk(7);
        let npub = npub_of(&hex);
        assert!(npub.starts_with("npub1"));
        assert_eq!(npub_of(&hex), npub, "stable");
    }

    #[tokio::test]
    async fn lookups_report_a_database_failure_as_an_error() {
        // A stopped database must not be reported as "no mapping": find,
        // has, open_stream_any and list_page turn it into an error the
        // handlers map to 503, so an existing blob never 404s (or 403s on
        // DELETE) on overload.
        let (s, _db_path) = store("lookup-db-down").await;
        let sha = "ab".repeat(32);
        s.db.shutdown();
        assert!(s.find(&sha).await.is_err());
        assert!(s.has(&pk(1), &sha).await.is_err());
        assert!(s.open_stream_any(&sha, 0, 1).await.is_err());
        assert!(s.list_page(&pk(1), None, None, 10).await.is_err());
    }

    #[tokio::test]
    async fn owner_cap_is_reported_as_a_conflict_error() {
        let (s, _db_path) = store("owner-cap").await;
        let sha = "cd".repeat(32);
        let bytes = b"shared";
        for i in 0..MAX_BLOB_OWNERS {
            assert!(
                s.db.blossom_add_owner(
                    &sha,
                    "text/plain",
                    bytes.len() as u64,
                    1,
                    &pk(i as u8 + 10),
                )
                .await
            );
        }
        // The 65th owner gets the typed conflict error (not a bare commit
        // failure the handler would report as 500).
        let path = std::env::temp_dir().join(format!(
            "nostrfy-blossom-owner-cap-src-{}",
            std::process::id()
        ));
        std::fs::write(&path, bytes).unwrap();
        let err = s
            .put_file(&pk(99), &sha, &path, bytes.len() as u64, "text/plain", true)
            .await
            .unwrap_err();
        assert!(
            err.downcast_ref::<BlobOwnerLimit>().is_some(),
            "the cap must surface as BlobOwnerLimit: {err}"
        );
        // An existing owner may re-upload even at the cap.
        assert!(
            s.put_file(&pk(10), &sha, &path, bytes.len() as u64, "text/plain", true)
                .await
                .is_ok()
        );
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn raced_owner_cap_commit_is_classified_as_a_conflict() {
        // The put_file pre-check is not atomic with the add: a concurrent
        // upload can win the last owner slot between them. The re-read
        // after the failed add must then surface the typed conflict
        // (HTTP 409); a genuine failure (unavailable database, or the
        // uploader already an owner) must stay generic (HTTP 500).
        let (s, _db_path) = store("owner-cap-race").await;
        let sha = "5b".repeat(32);
        let bytes = b"raced";
        for i in 0..MAX_BLOB_OWNERS {
            assert!(
                s.db.blossom_add_owner(
                    &sha,
                    "text/plain",
                    bytes.len() as u64,
                    1,
                    &pk(i as u8 + 10),
                )
                .await
            );
        }
        // The raced loser's add is refused by the database cap.
        assert!(
            !s.commit_owner(&sha, "text/plain", bytes.len() as u64, 1, &pk(99))
                .await
        );
        let err = s
            .owner_limit_on_failed_commit(&sha, &pk(99))
            .await
            .expect("a full owner list must classify as the owner limit");
        assert!(
            err.downcast_ref::<BlobOwnerLimit>().is_some(),
            "the raced cap must surface as BlobOwnerLimit: {err}"
        );
        // An uploader already in the owner list is not a cap conflict.
        assert!(
            s.owner_limit_on_failed_commit(&sha, &pk(10))
                .await
                .is_none()
        );
        // A failed commit for an unmapped blob is not a cap conflict.
        assert!(
            s.owner_limit_on_failed_commit(&"aa".repeat(32), &pk(99))
                .await
                .is_none()
        );
        // A stopped database must not be misreported as a client conflict.
        s.db.shutdown();
        assert!(
            s.owner_limit_on_failed_commit(&sha, &pk(99))
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn mapping_failure_leaves_orphan_object_not_a_visible_blob() {
        let (s, _db_path) = store("publish-before-map").await;
        let a = pk(1);
        let b = pk(2);
        let sha = "5a".repeat(32);
        let bytes = b"publish before map";
        let src = std::env::temp_dir().join(format!(
            "nostrfy-blossom-publish-src-{}",
            std::process::id()
        ));
        std::fs::write(&src, bytes).unwrap();
        // The object is published before the mapping commits: a commit
        // failure must leave no mapping at all (no list entry, no owner
        // slot), only the invisible orphan object.
        s.fail_next_mapping
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let err = s
            .put_file(&a, &sha, &src, bytes.len() as u64, "text/plain", true)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("mapping"),
            "the commit failure must be reported: {err}"
        );
        assert!(
            s.find(&sha).await.unwrap().is_none(),
            "a failed mapping commit must not leave a mapping"
        );
        assert!(!s.has(&a, &sha).await.unwrap());
        assert!(s.list(&a, 10).await.is_empty());
        // The publish did happen first (the orphan is invisible through the
        // mapping but a later upload overwrites it in place).
        assert!(
            s.open_stream(&a, &sha, 0, u64::MAX)
                .await
                .unwrap()
                .is_some(),
            "the object is published before the mapping commits"
        );

        // A later successful flow overwrites the orphan and lists the blob.
        std::fs::write(&src, bytes).unwrap();
        let (desc, existed) = s
            .put_file(&a, &sha, &src, bytes.len() as u64, "text/plain", true)
            .await
            .unwrap();
        assert_eq!(desc.sha256, sha);
        assert!(!existed);
        assert!(s.find(&sha).await.unwrap().is_some());
        assert!(s.has(&a, &sha).await.unwrap());
        assert_eq!(s.list(&a, 10).await.len(), 1);
        // A second owner appends to the mapping normally.
        std::fs::write(&src, bytes).unwrap();
        let (_, existed) = s
            .put_file(&b, &sha, &src, bytes.len() as u64, "text/plain", true)
            .await
            .unwrap();
        assert!(existed, "the second uploader sees the existing blob");
        assert!(s.has(&b, &sha).await.unwrap());
        assert_eq!(s.list(&b, 10).await.len(), 1);

        // A failed re-upload by an existing owner keeps their mapping.
        s.fail_next_mapping
            .store(true, std::sync::atomic::Ordering::SeqCst);
        std::fs::write(&src, bytes).unwrap();
        assert!(
            s.put_file(&a, &sha, &src, bytes.len() as u64, "text/plain", true)
                .await
                .is_err()
        );
        assert!(
            s.has(&a, &sha).await.unwrap(),
            "a failed re-upload must not delete the pre-existing owner mapping"
        );
        assert_eq!(s.list(&a, 10).await.len(), 1);
        let _ = std::fs::remove_file(&src);
        s.db.shutdown();
    }

    #[test]
    fn spool_pid_parsing() {
        assert_eq!(spool_pid("nostrfy-blossom-123-0"), Some(123));
        assert_eq!(spool_pid("nostrfy-blossom-456"), Some(456));
        assert_eq!(spool_pid("nostrfy-blossom--1"), None);
        assert_eq!(spool_pid("nostrfy-blossom-abc-1"), None);
        assert_eq!(spool_pid("nostrfy-blossom-"), None);
        assert_eq!(spool_pid("unrelated-1-2"), None);
    }

    #[test]
    fn spool_token_parsing() {
        // The new shape is `<pid>-<token>-<counter>`.
        assert_eq!(spool_token("nostrfy-blossom-123-abc-7"), Some("abc"));
        assert_eq!(
            spool_token("nostrfy-blossom-123-deadbeef-0"),
            Some("deadbeef")
        );
        // The legacy shapes carry no token.
        assert_eq!(spool_token("nostrfy-blossom-123-7"), None);
        assert_eq!(spool_token("nostrfy-blossom-123"), None);
        // An unparseable PID is not a spool at all (never swept).
        assert_eq!(spool_token("nostrfy-blossom-abc-1-2"), None);
        assert_eq!(spool_token("unrelated-1-2-3"), None);
        // A generated name parses back to this process start.
        let name = spool_file_name(42);
        assert_eq!(spool_pid(&name), Some(std::process::id()));
        assert_eq!(spool_token(&name), Some(spool_process_token()));
        assert!(
            name.ends_with("-42"),
            "the counter stays in the name: {name}"
        );
        assert_ne!(
            spool_file_name(0),
            spool_file_name(1),
            "concurrent spools need distinct names"
        );
    }

    /// Backdates `path`'s mtime by `age` so the sweep's grace period can be
    /// crossed without waiting an hour.
    fn backdate(path: &std::path::Path, age: std::time::Duration) {
        let file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        let modified = std::time::SystemTime::now() - age;
        file.set_times(std::fs::FileTimes::new().set_modified(modified))
            .unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stale_spool_sweep_keeps_live_and_unattributed_files() {
        let (s, _db_path) = store("sweep-pids").await;
        let dir = s.spool_dir().expect("local store");
        std::fs::create_dir_all(&dir).unwrap();
        let live = dir.join(format!("{}{}-1", SPOOL_PREFIX, std::process::id()));
        let unknown = dir.join(format!("{SPOOL_PREFIX}notapid-2"));
        std::fs::write(&live, b"live").unwrap();
        std::fs::write(&unknown, b"unknown").unwrap();
        s.sweep_stale_spools();
        assert!(live.exists(), "a live process's spool must not be swept");
        assert!(
            unknown.exists(),
            "a file without a parseable PID must not be swept"
        );
        // A dead process's spool is removed. `true` exits immediately, so
        // after the wait its PID is gone (barring an immediate reuse).
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let dead_pid = child.id();
        child.wait().unwrap();
        let dead = dir.join(format!("{SPOOL_PREFIX}{dead_pid}-3"));
        std::fs::write(&dead, b"dead").unwrap();
        s.sweep_stale_spools();
        assert!(!dead.exists(), "a dead process's spool must be swept");
    }

    /// The container case: a restart reuses PID 1, so a stale spool's PID
    /// is alive (the current process). The token, not the PID, decides.
    #[cfg(unix)]
    #[tokio::test]
    async fn stale_spool_sweep_handles_reused_pid_and_tokens() {
        let (s, _db_path) = store("sweep-token").await;
        let dir = s.spool_dir().expect("local store");
        std::fs::create_dir_all(&dir).unwrap();
        let our_pid = std::process::id();
        // A previous process start reused our PID: foreign token, old.
        let reused = dir.join(format!("{SPOOL_PREFIX}{our_pid}-deadbeef-0"));
        // A live sibling process (unknown token) that just wrote its spool.
        let sibling = dir.join(format!("{SPOOL_PREFIX}{our_pid}-cafef00d-1"));
        // This process's own spool, old but owned by the current token.
        let ours = dir.join(spool_file_name(7));
        for path in [&reused, &sibling, &ours] {
            std::fs::write(path, b"spool").unwrap();
        }
        let stale_age = SPOOL_GRACE_PERIOD + std::time::Duration::from_secs(60);
        backdate(&reused, stale_age);
        backdate(&ours, stale_age);
        s.sweep_stale_spools();
        assert!(
            !reused.exists(),
            "a same-PID spool from a previous start (foreign token, old) must be swept"
        );
        assert!(
            sibling.exists(),
            "a young foreign-token spool (live sibling) must not be swept"
        );
        assert!(
            ours.exists(),
            "this process start's own spool must never be swept, even when old"
        );
        // A dead PID is swept regardless of the token and age.
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let dead_pid = child.id();
        child.wait().unwrap();
        let dead = dir.join(format!("{SPOOL_PREFIX}{dead_pid}-deadbeef-2"));
        std::fs::write(&dead, b"dead").unwrap();
        s.sweep_stale_spools();
        assert!(!dead.exists(), "a dead process's spool must be swept");
    }

    /// The sweep counts every stale spool it removes: that counter is the
    /// cheap interrupted-upload signal exposed for the stats owner.
    #[cfg(unix)]
    #[tokio::test]
    async fn stale_spool_sweep_counts_only_the_removed_orphans() {
        let (s, _db_path) = store("sweep-count").await;
        let dir = s.spool_dir().expect("local store");
        std::fs::create_dir_all(&dir).unwrap();
        // Clear any leftover from an earlier test process first: the
        // shared temp directory is swept too, and the count below must
        // only see the orphan this test creates.
        s.sweep_stale_spools();
        let before = s.orphan_spools_swept();
        // This process start's own spool: kept and not counted.
        let ours = dir.join(spool_file_name(3));
        std::fs::write(&ours, b"ours").unwrap();
        // An orphan from a dead process start: removed and counted.
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let dead_pid = child.id();
        child.wait().unwrap();
        let dead = dir.join(format!("{SPOOL_PREFIX}{dead_pid}-deadbeef-0"));
        std::fs::write(&dead, b"orphan").unwrap();
        s.sweep_stale_spools();
        assert!(ours.exists(), "this process start's own spool must be kept");
        assert!(!dead.exists(), "the foreign-token orphan must be swept");
        assert_eq!(
            s.orphan_spools_swept() - before,
            1,
            "exactly the removed orphan must be counted"
        );
        s.sweep_stale_spools();
        assert_eq!(
            s.orphan_spools_swept() - before,
            1,
            "a second sweep must not count the kept spool"
        );
    }
}

#[cfg(test)]
mod scan_debug {
    use super::*;

    #[tokio::test]
    async fn scan_legacy_finds_legacy_files() {
        let dir =
            std::env::temp_dir().join(format!("nostrfy-blossom-scan-debug-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // The directory name comes from the same npub_of() the uploads use
        // (bech32m) — never handcraft a checksum in the test.
        let npub = npub_of(&"01".repeat(32));
        let npub_dir = dir.join(&npub);
        std::fs::create_dir_all(&npub_dir).unwrap();
        std::fs::write(
            npub_dir.join("34f66c6a736a7ee87f5f908bbc48e651f94bcdc4c5d3006dbaa4d8fa5fa4cf5a"),
            b"x",
        )
        .unwrap();
        std::fs::write(
            npub_dir.join("34f66c6a736a7ee87f5f908bbc48e651f94bcdc4c5d3006dbaa4d8fa5fa4cf5a.meta.json"),
            br#"{"sha256":"34f66c6a736a7ee87f5f908bbc48e651f94bcdc4c5d3006dbaa4d8fa5fa4cf5a","size":1,"mime":"image/png","uploaded":1787000000}"#,
        ).unwrap();
        assert!(
            npub_from_dir(&npub_dir).is_ok(),
            "npub_from_dir must accept the bech32m npub"
        );
        let s = LocalStore::new(&dir, 0).await.unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        s.scan_legacy(tx).await.unwrap();
        let mut entries = Vec::new();
        while let Some(chunk) = rx.recv().await {
            entries.extend(chunk);
        }
        assert_eq!(entries.len(), 1, "scan must find the legacy meta");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn scan_legacy_ignores_invalid_meta_names() {
        let dir =
            std::env::temp_dir().join(format!("nostrfy-blossom-scan-meta-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let npub = npub_of(&"02".repeat(32));
        let npub_dir = dir.join(&npub);
        std::fs::create_dir_all(&npub_dir).unwrap();
        // Stray meta names (not a 64-hex hash) must not create mappings.
        for name in ["garbage.meta.json", "short.meta.json", "zz.meta.json"] {
            std::fs::write(npub_dir.join(name), br#"{"size":1}"#).unwrap();
        }
        // A valid but uppercase hash is normalized to lowercase.
        let upper = "AB".repeat(32);
        std::fs::write(
            npub_dir.join(format!("{upper}.meta.json")),
            br#"{"size":1,"mime":"image/png","uploaded":1}"#,
        )
        .unwrap();
        let s = LocalStore::new(&dir, 0).await.unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        s.scan_legacy(tx).await.unwrap();
        let mut entries = Vec::new();
        while let Some(chunk) = rx.recv().await {
            entries.extend(chunk);
        }
        assert_eq!(
            entries.len(),
            1,
            "only the well-formed meta is emitted: {entries:?}"
        );
        assert_eq!(entries[0].0, "ab".repeat(32), "the hash is normalized");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
