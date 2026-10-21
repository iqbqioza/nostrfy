//! Operator-supplied landing page and static assets.
//!
//! By default a plain browser GET of the relay URL gets the built-in decoy
//! page (see `nip11_doc`). An operator who *wants* a public page there (relay
//! rules, statistics, contact details) can point `server.landing_page_file`
//! at an HTML file and, optionally, `server.assets_dir` at a directory whose
//! files are served under `/assets/<name>` (images, CSS, scripts referenced
//! by the page). Both are opt-in: with them unset nothing changes.
//!
//! The files are read from disk on demand rather than at startup so that an
//! external generator (a cron job rendering statistics) can rewrite them
//! without restarting the relay. The landing page is cached in memory and
//! re-read only when its mtime or size changes, so a busy relay does not hit
//! the filesystem on every probe.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use axum::body::Body;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

/// Largest file either route serves. The files are operator-controlled, but
/// a mistaken path (a log file, a database) must not be loaded into memory
/// whole and shipped to every visitor.
pub(crate) const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// A cached landing page is revalidated at least this often even when its
/// mtime and length are unchanged: a generator that rewrites in place with
/// the same size on a coarse-mtime filesystem (NFS/ext3, `rsync -t`) must
/// not leave a stale page served forever.
const LANDING_CACHE_TTL: Duration = Duration::from_secs(1);

/// Cached landing page: keyed by the full configured path plus the file's
/// mtime and size, so a rewrite (or a config change to another path) is
/// picked up on the next request.
struct Cached {
    path: PathBuf,
    mtime: Option<SystemTime>,
    len: u64,
    cached_at: Instant,
    body: axum::body::Bytes,
}

static LANDING_CACHE: Mutex<Option<Cached>> = Mutex::new(None);

/// Opens `path` without following a symlink and validates the *opened*
/// descriptor (a regular file within the size cap). The check and the read
/// use the same fd, so replacing the path between them (the previous
/// stat-then-read TOCTOU) cannot redirect the read to another file.
fn open_regular(path: &Path) -> Option<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    // Reject a symlink or a non-regular file without opening it: opening a
    // writer-less FIFO for read blocks until a writer appears (the old
    // O_NOFOLLOW open still blocked on FIFOs). This check is advisory (the
    // path can change), so the open below also uses O_NONBLOCK and
    // re-validates the descriptor before returning it.
    let pre = std::fs::symlink_metadata(path).ok()?;
    if !pre.file_type().is_file() {
        return None;
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let meta = file.metadata().ok()?;
    (meta.file_type().is_file() && meta.len() <= MAX_FILE_BYTES).then_some(file)
}

/// The landing page body for `path`, or `None` when it cannot be served
/// (missing, not a regular file, too large, unreadable). The caller falls
/// back to the decoy page, never to the relay document: a broken landing
/// page must not reveal more than the default does.
pub(crate) fn landing_page(path: &Path) -> Option<axum::body::Bytes> {
    let file = open_regular(path)?;
    let meta = file.metadata().ok()?;
    let mtime = meta.modified().ok();
    let len = meta.len();
    {
        let cache = LANDING_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = cache.as_ref()
            && c.path == path
            && c.mtime == mtime
            && c.len == len
            && c.cached_at.elapsed() < LANDING_CACHE_TTL
        {
            return Some(c.body.clone());
        }
    }
    // Read from the already-open fd (no path re-resolution) and bound the
    // allocation even if the file grew after the fstat.
    use std::io::Read as _;
    let mut body = Vec::with_capacity(len as usize);
    file.take(MAX_FILE_BYTES + 1).read_to_end(&mut body).ok()?;
    if body.len() as u64 > MAX_FILE_BYTES {
        return None;
    }
    let body = axum::body::Bytes::from(body);
    *LANDING_CACHE.lock().unwrap_or_else(|e| e.into_inner()) = Some(Cached {
        path: path.to_path_buf(),
        mtime,
        len,
        cached_at: Instant::now(),
        body: body.clone(),
    });
    Some(body)
}

/// Serves the landing page as `text/html`.
pub(crate) fn landing_response(body: axum::body::Bytes) -> Response {
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            ),
            (
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            ),
            // The page is re-read when its mtime/size changes: make shared
            // and browser caches revalidate instead of pinning an old copy.
            (header::CACHE_CONTROL, HeaderValue::from_static("no-cache")),
        ],
        body,
    )
        .into_response()
}

/// Whether `name` is an acceptable asset file name: one path segment of
/// ASCII letters, digits, `.`, `_` and `-`, not starting with a dot. This
/// rules out traversal (`..`, `/`, `\`), hidden files and percent-decoded
/// surprises without having to canonicalize paths.
pub(crate) fn valid_asset_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Content type for an asset, by extension. Unknown extensions are served
/// as `application/octet-stream` (with `nosniff`, so a browser does not
/// guess its way into executing them).
pub(crate) fn asset_content_type(name: &str) -> &'static str {
    let ext = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "css" => "text/css; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "txt" => "text/plain; charset=utf-8",
        "html" => "text/html; charset=utf-8",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    }
}

/// Serves `/assets/<name>` from `dir`; 404 for anything that is not a valid
/// name of a regular file within the size cap.
pub(crate) async fn asset_response(dir: &Path, name: &str) -> Response {
    if !valid_asset_name(name) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let path = dir.join(name);
    // Same atomic O_NOFOLLOW check as the landing page: the asset is read
    // from the descriptor that was validated, not from a re-resolved path.
    // Keep the blocking open off the async runtime: a slow/NFS mount (and
    // the advisory pre-check) must not park a request worker.
    let Some(file) = tokio::task::spawn_blocking(move || open_regular(&path))
        .await
        .ok()
        .flatten()
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    use tokio::io::AsyncReadExt as _;
    let mut data = Vec::new();
    let file = tokio::fs::File::from_std(file);
    if file
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut data)
        .await
        .is_err()
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    if data.len() as u64 > MAX_FILE_BYTES {
        return StatusCode::NOT_FOUND.into_response();
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, asset_content_type(name))
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .body(Body::from(data))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_names() {
        for ok in ["og.png", "style.min.css", "a_b-c.js", "x"] {
            assert!(valid_asset_name(ok), "{ok}");
        }
        for bad in [
            "", ".", "..", ".env", "../x", "a/b", "a\\b", "a b", "%2e%2e", "é.png",
        ] {
            assert!(!valid_asset_name(bad), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn fifo_assets_are_refused_without_blocking() {
        // Opening a writer-less FIFO for read blocks forever; the
        // symlink_metadata pre-check plus O_NONBLOCK must turn it into a
        // prompt 404 instead of parking a blocking-pool thread.
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("nostrfy-fifo-test-{}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("x.png");
        let c_path = std::ffi::CString::new(
            <std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::as_bytes(path.as_os_str()),
        )
        .unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            asset_response(&dir, "x.png"),
        )
        .await
        .expect("a FIFO asset must not block the request");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_refreshes_a_same_size_same_mtime_rewrite_after_the_ttl() {
        // I-4: a generator that rewrites the page in place with the same
        // length and restores the mtime (coarse-mtime FS, `rsync -t`) must
        // still be picked up after the short TTL.
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "nostrfy-landing-cache-test-{}-{id}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("page.html");
        std::fs::write(&path, b"AAAA").unwrap();
        assert_eq!(&landing_page(&path).unwrap()[..], b"AAAA");
        let mtime = std::fs::metadata(&path).unwrap().modified().unwrap();
        std::fs::write(&path, b"BBBB").unwrap();
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_times(std::fs::FileTimes::new().set_modified(mtime))
            .unwrap();
        assert_eq!(
            &landing_page(&path).unwrap()[..],
            b"AAAA",
            "the short TTL window may serve the cached body"
        );
        std::thread::sleep(LANDING_CACHE_TTL + Duration::from_millis(50));
        assert_eq!(
            &landing_page(&path).unwrap()[..],
            b"BBBB",
            "a same-size, same-mtime rewrite must refresh after the TTL"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn content_types() {
        assert_eq!(asset_content_type("og.PNG"), "image/png");
        assert_eq!(asset_content_type("a.svg"), "image/svg+xml");
        assert_eq!(asset_content_type("noext"), "application/octet-stream");
        assert_eq!(asset_content_type("x.exe"), "application/octet-stream");
    }
}
