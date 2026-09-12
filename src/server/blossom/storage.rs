//! Blossom blob storage: the `bucket/{npub1xxx}/{file}` layout on local
//! disk or in an S3-compatible bucket (AWS S3 / Cloudflare R2).
//!
//! The sha256 → owner mapping is **persisted in the relay database**
//! (LMDB, the `blossom` table): an upload writes the mapping first, and a
//! lookup reads it straight from LMDB — no in-memory index and no startup
//! scan, so lookups survive restarts, memory stays bounded and startup is
//! independent of the storage size. The blobs themselves are files in
//! `bucket/{npub1xxx}/{file}`; the multi-owner mapping lets every uploader
//! of identical content manage their own copy independently.

use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

use crate::db::DbClient;
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

/// Blob storage: the LMDB-persisted mapping plus the file backend.
pub(crate) struct BlobStore {
    storage: Storage,
    db: DbClient,
    upload_locks: Vec<tokio::sync::Mutex<()>>,
}

impl BlobStore {
    const UPLOAD_LOCK_COUNT: usize = 256;

    pub(crate) async fn new(
        storage: &str,
        local_path: &Path,
        min_free_bytes: u64,
        s3: Option<S3Config>,
        db: DbClient,
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
            upload_locks: (0..Self::UPLOAD_LOCK_COUNT)
                .map(|_| tokio::sync::Mutex::new(()))
                .collect(),
        })
    }

    async fn upload_lock(&self, pubkey: &str, sha256: &str) -> tokio::sync::MutexGuard<'_, ()> {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        pubkey.hash(&mut hasher);
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

    /// Stores a blob: the LMDB mapping first (so a crash leaves a healable
    /// state — a mapping without a file can be deleted), then the file.
    #[cfg(test)]
    pub(crate) async fn put(
        &self,
        pubkey: &str,
        sha256: &str,
        bytes: &[u8],
        mime: &str,
    ) -> Result<Descriptor> {
        // Disk-full guard first: a refused upload must not even leave an
        // orphan mapping behind (the mapping-first design heals such
        // leftovers, but only the bytes that will actually land should be
        // committed).
        self.check_space()?;
        let _upload_guard = self.upload_lock(pubkey, sha256).await;
        let uploaded = crate::util::unix_now() as i64;
        // Whether the uploader already owned the blob BEFORE this upload
        // (read before the add: a failed re-upload of identical bytes must
        // not roll back their pre-existing, valid mapping).
        let was_owner = self
            .db
            .blossom_load(sha256)
            .await
            .is_some_and(|m| m.owners.iter().any(|o| o == pubkey));
        // The mapping must land first: without it the file would be an
        // unreachable orphan. Abort the upload when the commit fails.
        if !self
            .db
            .blossom_add_owner(sha256, mime, bytes.len() as u64, uploaded, pubkey)
            .await
        {
            return Err(anyhow!("blossom mapping write failed"));
        }

        let npub = npub_of(pubkey);
        let stored = match &self.storage {
            Storage::Local(s) => s.put(&npub, sha256, bytes, mime, uploaded).await,
            Storage::S3(s) => s.put(&npub, sha256, bytes, mime, uploaded).await,
        };
        if let Err(e) = stored {
            // Roll the owner mapping back: a failed PUT must not leave a
            // mapping pointing at an object that was never stored (an
            // unreachable, billed orphan) — but only when this upload
            // created the mapping (a failed re-upload keeps the
            // pre-existing valid mapping).
            //
            if !was_owner {
                self.db.blossom_remove_owner(sha256, pubkey).await;
            }
            return Err(e);
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
    pub(crate) async fn put_file(
        &self,
        pubkey: &str,
        sha256: &str,
        path: &Path,
        size: u64,
        mime: &str,
    ) -> Result<Descriptor> {
        self.check_space()?;
        let _upload_guard = self.upload_lock(pubkey, sha256).await;
        let uploaded = crate::util::unix_now() as i64;
        let was_owner = self
            .db
            .blossom_load(sha256)
            .await
            .is_some_and(|m| m.owners.iter().any(|o| o == pubkey));
        if !self
            .db
            .blossom_add_owner(sha256, mime, size, uploaded, pubkey)
            .await
        {
            return Err(anyhow!("blossom mapping write failed"));
        }
        let npub = npub_of(pubkey);
        let stored = match &self.storage {
            Storage::Local(s) => s.put_file(&npub, sha256, path).await,
            Storage::S3(s) => s.put_file(&npub, sha256, path, size, mime).await,
        };
        if let Err(e) = stored {
            if !was_owner {
                self.db.blossom_remove_owner(sha256, pubkey).await;
            }
            return Err(e);
        }
        Ok(Descriptor {
            sha256: sha256.to_string(),
            size,
            mime: mime.to_string(),
            uploaded,
            pubkey: pubkey.to_string(),
        })
    }

    /// Resolves a blob by its sha256 straight from LMDB.
    pub(crate) async fn find(&self, sha256: &str) -> Option<Descriptor> {
        let meta = self.db.blossom_load(sha256).await?;
        Some(Descriptor {
            sha256: meta.sha256,
            size: meta.size,
            mime: meta.mime,
            uploaded: meta.uploaded,
            pubkey: meta.owners.into_iter().next()?,
        })
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
        let Some(meta) = self.db.blossom_load(sha256).await else {
            return Ok(None);
        };
        let mut last_error: Option<anyhow::Error> = None;
        for owner in &meta.owners {
            match self.open_stream(owner, sha256, start, len).await {
                Ok(Some(stream)) => return Ok(Some((stream, owner.clone()))),
                // Missing under this owner: try the next copy.
                Ok(None) => {}
                Err(e) => {
                    log::warn!("blossom: opening {sha256} for owner {owner} failed: {e}");
                    last_error = Some(e);
                }
            }
        }
        match last_error {
            Some(e) => Err(e),
            None => Ok(None),
        }
    }

    /// Whether `pubkey` has uploaded this blob.
    pub(crate) async fn has(&self, pubkey: &str, sha256: &str) -> bool {
        self.db
            .blossom_load(sha256)
            .await
            .is_some_and(|meta| meta.owners.iter().any(|o| o == pubkey))
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
        self.db.blossom_remove_owner(sha256, pubkey).await;
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
    pub(crate) async fn auto_migrate_legacy(&self) -> Result<usize> {
        if self.db.blossom_migration_done().await {
            return Ok(0);
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
        Ok(count)
    }

    /// Blobs uploaded by `pubkey` (hex), via the persisted reverse index,
    /// resolving at most `limit` descriptors: cursors past the window yield
    /// an empty page (see the `GET /list` handler).
    pub(crate) async fn list(&self, pubkey: &str, limit: usize) -> Vec<Descriptor> {
        let mut out = Vec::new();
        for sha in self.db.blossom_list(pubkey, limit).await {
            if let Some(desc) = self.find(&sha).await {
                out.push(desc);
            }
        }
        out
    }
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
        return Ok(name.to_string());
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

struct LocalStore {
    root: PathBuf,
    /// The resolved root: every operation's parent directory is
    /// canonicalized and must resolve under this path, so a symlinked
    /// npub directory can never redirect reads, writes or deletes
    /// outside the blob store (the symlink-escape guard).
    canonical_root: PathBuf,
    /// Disk-full guard: uploads are refused while the free space on the
    /// filesystem hosting `root` is below this many bytes (0 disables).
    min_free_bytes: u64,
}

impl LocalStore {
    async fn new(root: &Path, min_free_bytes: u64) -> Result<LocalStore> {
        tokio::fs::create_dir_all(root).await?;
        let canonical_root = tokio::fs::canonicalize(root).await?;
        Ok(LocalStore {
            root: root.to_path_buf(),
            canonical_root,
            min_free_bytes,
        })
    }

    fn blob_path(&self, npub: &str, sha256: &str) -> PathBuf {
        self.root.join(npub).join(sha256)
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
        let tmp_path = dir.join(format!(".{sha256}.tmp"));
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
        if let Err(e) = tokio::fs::rename(&tmp_path, self.blob_path(npub, sha256)).await {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(e.into());
        }
        Ok(())
    }

    async fn put_file(&self, npub: &str, sha256: &str, source: &Path) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        let dir = self.root.join(npub);
        tokio::fs::create_dir_all(&dir).await?;
        if !self.parent_within_root(npub).await {
            return Err(anyhow!("blossom storage directory is a symlink"));
        }
        let tmp_path = dir.join(format!(".{sha256}.tmp"));
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
        drop(output);
        if let Err(e) = tokio::fs::rename(&tmp_path, self.blob_path(npub, sha256)).await {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(e.into());
        }
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
            return Ok(None);
        }
        let mut file = match tokio::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.blob_path(npub, sha256))
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
            let dir = self.root.join(npub);
            return match tokio::fs::symlink_metadata(&dir).await {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Ok(_) => Err(anyhow!("blossom storage directory is unsafe")),
                Err(e) => Err(e.into()),
            };
        }
        let path = self.blob_path(npub, sha256);
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
                let name = file.file_name().to_string_lossy().into_owned();
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
        let s = BlobStore::new("local", &dir, 0, None, db).await.unwrap();
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

        assert_eq!(s.find(&sha).await.unwrap().pubkey, a);
        assert!(s.has(&a, &sha).await);
        assert!(s.has(&b, &sha).await);
        assert!(!s.has(&pk(3), &sha).await);
        assert_eq!(s.list(&a, 10_000).await.len(), 1);
        assert_eq!(s.list(&b, 10_000).await.len(), 1);
        assert_eq!(s.list(&pk(3), 10_000).await.len(), 0);

        let npub_a = npub_of(&a);
        let npub_b = npub_of(&b);
        assert_eq!(read_all(&s, &npub_a, &sha).await.unwrap(), bytes);
        assert_eq!(read_all(&s, &npub_b, &sha).await.unwrap(), bytes);

        // One owner deletes: the other owner's copy survives.
        assert!(s.delete(&b, &sha).await.unwrap());
        assert!(s.find(&sha).await.is_some());
        assert!(read_all(&s, &npub_a, &sha).await.is_some());
        assert!(read_all(&s, &npub_b, &sha).await.is_none());
        assert!(!s.has(&b, &sha).await);
        assert!(s.has(&a, &sha).await);
        assert_eq!(s.list(&a, 10_000).await.len(), 1);
        assert_eq!(s.list(&b, 10_000).await.len(), 0);

        // The last owner's delete removes the mapping.
        assert!(s.delete(&a, &sha).await.unwrap());
        assert!(s.find(&sha).await.is_none());
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
                full.find(&sha).await.is_none(),
                "no mapping may be left for the refused upload"
            );
            // The disabled guard (0) lets the upload through.
            let sha2 = "ef".repeat(32);
            assert!(
                s.put(&a, &sha2, b"y", "text/plain").await.is_ok(),
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
            assert!(s.has(&a, &sha).await, "failed delete must keep the mapping");
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
                s.find(&sha).await.is_none(),
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
                s.find(&sha).await.is_some(),
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
            let mapped = s.auto_migrate_legacy().await.unwrap();
            assert_eq!(
                mapped, 0,
                "the migration must not map files through a symlinked directory"
            );
            assert!(
                s.find(&"ab".repeat(32)).await.is_none(),
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
            let mapped = s.auto_migrate_legacy().await.unwrap();
            assert_eq!(mapped, 0, "the migration must not map symlinked blob files");
            assert!(s.find(&"ab".repeat(32)).await.is_none());
            assert!(s.find(&"cd".repeat(32)).await.is_none());
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
            let s = BlobStore::new("local", &dir, 0, None, db).await.unwrap();
            let sha = "cd".repeat(32);
            s.put(&pk(1), &sha, b"x", "image/png").await.unwrap();
            s.put(&pk(2), &sha, b"x", "image/png").await.unwrap();
            let sha2 = "ef".repeat(32);
            s.put(&pk(1), &sha2, b"y", "text/plain").await.unwrap();
        }
        let db = DbClient::open(
            &crate::config::DatabaseConfig {
                path: db_path,
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
        let s = BlobStore::new("local", &dir, 0, None, db).await.unwrap();
        let sha = "cd".repeat(32);
        assert_eq!(s.find(&sha).await.unwrap().pubkey, pk(1));
        assert!(s.has(&pk(1), &sha).await);
        assert!(s.has(&pk(2), &sha).await);
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
        let s = BlobStore::new("local", &dir, 0, None, db).await.unwrap();
        let migrated = s.auto_migrate_legacy().await.unwrap();
        assert_eq!(migrated, 2, "both owners are mapped");
        assert!(s.has(&pk(1), &sha).await);
        assert!(
            s.has(&pk(2), &sha).await,
            "second owner survives the migration"
        );
        assert_eq!(s.list(&pk(1), 10_000).await.len(), 1);
        assert_eq!(s.list(&pk(2), 10_000).await.len(), 1);
        // 一人削除してももう一人は残る
        assert!(s.delete(&pk(1), &sha).await.unwrap());
        assert!(s.find(&sha).await.is_some());
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
