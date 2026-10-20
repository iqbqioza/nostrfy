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
use std::time::SystemTime;

use axum::body::Body;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

/// Largest file either route serves. The files are operator-controlled, but
/// a mistaken path (a log file, a database) must not be loaded into memory
/// whole and shipped to every visitor.
pub(crate) const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// Cached landing page: keyed by the full configured path plus the file's
/// mtime and size, so a rewrite (or a config change to another path) is
/// picked up on the next request.
struct Cached {
    path: PathBuf,
    mtime: Option<SystemTime>,
    len: u64,
    body: axum::body::Bytes,
}

static LANDING_CACHE: Mutex<Option<Cached>> = Mutex::new(None);

/// Opens `path` without following a symlink and validates the *opened*
/// descriptor (a regular file within the size cap). The check and the read
/// use the same fd, so replacing the path between them (the previous
/// stat-then-read TOCTOU) cannot redirect the read to another file.
fn open_regular(path: &Path) -> Option<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
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
    let Some(file) = open_regular(&path) else {
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

    #[test]
    fn content_types() {
        assert_eq!(asset_content_type("og.PNG"), "image/png");
        assert_eq!(asset_content_type("a.svg"), "image/svg+xml");
        assert_eq!(asset_content_type("noext"), "application/octet-stream");
        assert_eq!(asset_content_type("x.exe"), "application/octet-stream");
    }
}
