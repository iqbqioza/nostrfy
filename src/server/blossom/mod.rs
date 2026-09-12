//! Blossom file server (BUD-01 / BUD-02).
//!
//! Serves a media/blob store on a hostname dedicated like the REST API:
//! requests whose Host header matches `blossom.host` are served only the
//! Blossom routes. Files are stored as `bucket/{npub1xxx}/{sha256}` on
//! local disk or in an S3-compatible bucket, content-addressed by SHA-256.
//!
//! Endpoints:
//! - `GET /`            — server info
//! - `GET /<sha256>[.ext]` / `HEAD` — fetch / probe a blob (with RFC 7233
//!   byte-range support on `GET`)
//! - `PUT /upload`      — upload (NIP-98 style auth, kind 24242, `t=upload`,
//!   mandatory `expiration` and `x` tags per BUD-11)
//! - `HEAD /upload`     — BUD-06 pre-flight (`X-SHA-256` / `X-Content-Length`
//!   / `X-Content-Type` headers, `t=upload` auth)
//! - `PUT /media` / `HEAD /media` — BUD-05 media upload + pre-flight
//!   (stored verbatim; auth `t=media`, `x` tag required)
//! - `GET /list/<pubkey>` — blobs uploaded by a pubkey
//! - `DELETE /<sha256>[.ext]` — delete (auth, `t=delete`, `x=<sha256>`)

use std::sync::Arc;

use anyhow::anyhow;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path as AxPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use base64::Engine;
use serde_json::{Value, json};

use crate::config::Config;
use crate::relay::Relay;
use crate::util::unix_now;

use storage::BlobStore;

pub(crate) mod s3;
pub(crate) mod storage;

/// State shared by the Blossom handlers.
pub(crate) struct BlossomState {
    pub store: BlobStore,
    /// The configured blossom hostname (used for the `server` auth tag).
    pub host: String,
    /// Upload limit fixed when the HTTP router and semaphore are created.
    /// Config reloads keep this value unchanged because the router cannot be
    /// rebuilt without restarting the listener.
    pub max_upload_bytes: usize,
    /// Shared in-flight upload budget. Upload bodies are spooled to a
    /// temporary file, so this bounds disk-backed work and prevents a burst
    /// of maximum-sized requests from creating unbounded concurrent work.
    pub upload_budget: Arc<tokio::sync::Semaphore>,
}

/// The routes, mounted by `build_router` only when `blossom.host` is set.
pub(crate) async fn routes(relay: &Arc<Relay>, max_upload: usize) -> axum::Router<Arc<Relay>> {
    // The root `/` route belongs to the relay: the WS handler answers it
    // with the Blossom server info when the Host names the Blossom host.
    axum::Router::new()
        .route(
            "/upload",
            put(upload)
                .head(head_upload)
                .layer(DefaultBodyLimit::max(max_upload)),
        )
        .route(
            "/media",
            put(upload_media)
                .head(head_media)
                .layer(DefaultBodyLimit::max(max_upload)),
        )
        .route("/list/{pubkey}", get(list))
        .route("/{blob}", get(get_blob).head(head_blob).delete(delete_blob))
        .with_state(relay.clone())
}

/// The configured Blossom state, when the feature is enabled and the
/// store initialized.
async fn state_of(relay: &Relay) -> Option<Arc<BlossomState>> {
    relay.blossom.read().await.clone()
}

/// Whether a request path belongs to the Blossom server (used by the
/// host-split middleware).
pub(crate) fn is_blossom_path(path: &str) -> bool {
    // The root `/` stays with the relay (WS + NIP-11): the WS handler
    // answers it with the Blossom server info when the Host names the
    // Blossom host.
    if path == "/upload" || path == "/media" {
        return true;
    }
    if let Some(rest) = path.strip_prefix("/list/") {
        return is_pubkey(rest);
    }
    // `/<sha256>` or `/<sha256>.<ext>`
    let segment = path.trim_start_matches('/');
    if segment.is_empty() || segment.contains('/') {
        return false;
    }
    let hash = segment.split('.').next().unwrap_or(segment);
    hash.len() == 64 && hex::decode(hash).is_ok()
}

fn is_pubkey(value: &str) -> bool {
    value.len() == 64 && hex::decode(value).map(|b| b.len() == 32).unwrap_or(false)
}

/// The advisory file extension for a MIME type, appended to the
/// Blossom descriptor `url` (the spec's examples always include it;
/// the extension is a hint — the file is served by hash alone).
/// BUD-02 requires the URL to carry an extension, so unknown types fall
/// back to `.bin` (BUD-10: "If the file extension is unknown, it MUST
/// default to `.bin`").
fn ext_of(mime: &str) -> &'static str {
    match mime {
        "image/jpeg" => ".jpg",
        "image/png" => ".png",
        "image/gif" => ".gif",
        "image/webp" => ".webp",
        "image/avif" => ".avif",
        "image/svg+xml" => ".svg",
        "image/bmp" => ".bmp",
        "image/tiff" => ".tiff",
        "video/mp4" => ".mp4",
        "video/webm" => ".webm",
        "video/quicktime" => ".mov",
        "audio/mpeg" => ".mp3",
        "audio/ogg" => ".ogg",
        "audio/wav" | "audio/wave" | "audio/x-wav" => ".wav",
        "text/plain" => ".txt",
        "text/html" => ".html",
        "text/markdown" => ".md",
        "application/pdf" => ".pdf",
        "application/json" => ".json",
        "application/zip" => ".zip",
        "application/gzip" => ".gz",
        _ => ".bin",
    }
}

/// Splits `/<sha256>.<ext>` into the hash (normalized to lowercase, so
/// an uppercase request matches the stored index) and drops the advisory
/// extension.
fn split_blob(segment: &str) -> Option<String> {
    if segment.contains('/') {
        return None;
    }
    let hash = segment.split('.').next()?;
    if hash.len() == 64 && hex::decode(hash).is_ok() {
        Some(hash.to_ascii_lowercase())
    } else {
        None
    }
}

/// Whether `pubkey` (hex) may upload: unrestricted, or present in
/// `blossom.allow_pubkeys` (npub1... or hex). Read from the live config so
/// `nostrfy blossom allow/deny` + a SIGHUP applies without a restart.
async fn upload_allowed(relay: &Relay, pubkey: &str) -> anyhow::Result<()> {
    let cfg = relay.config.read().await;
    if !cfg.blossom.restrict_uploads {
        return Ok(());
    }
    // The allowlist lives in the relay database (LMDB), loaded into
    // memory at startup and refreshed on SIGHUP (`nostrfy blossom allow/deny`).
    let allowed = relay
        .blossom_allow
        .read()
        .await
        .iter()
        .any(|entry| entry == pubkey);
    if allowed {
        Ok(())
    } else {
        Err(anyhow!(
            "uploads are restricted to the configured allowlist"
        ))
    }
}

/// Normalizes the `server` tag of a Blossom auth event for comparison
/// with `blossom.host`: strips the scheme and any path, IPv6 literals keep
/// their bracket contents (colons are part of the host), and a DNS/IPv4
/// `:port` suffix is removed.
///
/// The port is intentionally ignored: `blossom.host` is a bare hostname
/// (validated portless), and routing matches on hostname only, so a token
/// naming `https://media.example.com:443` and one naming the bare host are
/// the same identity. Unlike NIP-42/98 (whose relay identity carries a
/// port), there is no configured port to compare against.
fn auth_server_host(server: &str) -> String {
    let host_part = server
        .strip_prefix("https://")
        .or_else(|| server.strip_prefix("http://"))
        .unwrap_or(server)
        .split('/')
        .next()
        .unwrap_or(server);
    let host = if let Some(rest) = host_part.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else {
        host_part.split(':').next().unwrap_or(host_part)
    };
    host.to_ascii_lowercase()
}

/// Validates and normalizes the client-sent Content-Type: only the media
/// type (the part before any `;` parameter) is kept, and it must be a
/// well-formed `type/subtype` token pair. Anything else falls back to
/// `application/octet-stream`, so a hostile header can never reach a
/// response header (which would make the response builder panic).
pub(crate) fn sanitize_mime(raw: &str) -> String {
    let media = raw
        .split(';')
        .next()
        .unwrap_or(raw)
        .trim()
        .to_ascii_lowercase();
    let valid = |t: &str| {
        !t.is_empty()
            && t.chars()
                .all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+.^_`|~-".contains(c))
    };
    match media.split_once('/') {
        Some((t, s)) if valid(t) && valid(s) && t.len() <= 32 && s.len() <= 64 => media,
        _ => "application/octet-stream".to_string(),
    }
}

/// The `t`-tag values of `name` in a Blossom auth event.
fn event_tags<'a>(event: &'a crate::event::Event, name: &'a str) -> impl Iterator<Item = &'a str> {
    event
        .tags
        .iter()
        .filter(move |t| t.len() >= 2 && t[0] == name)
        .map(|t| t[1].as_str())
}

/// Validates a Blossom auth event (BUD-11): kind 24242 with a `t` verb, a
/// mandatory `expiration` tag set to a unix timestamp in the future, an
/// optional `server` tag naming our host and — when the endpoint implies a
/// blob hash — a mandatory matching `x` tag. Returns the pubkey.
fn validate_auth_event(
    secp: &secp256k1::Secp256k1<secp256k1::All>,
    event: &crate::event::Event,
    host: &str,
    verb: &str,
    expected_sha: Option<&str>,
    now: u64,
) -> Option<String> {
    if event.kind != 24242 {
        return None;
    }
    if crate::nips::nip01::verify(event, secp).is_err() {
        return None;
    }
    // BUD-11: `created_at` must be in the past — nothing more. A future
    // `created_at` (client clock ahead) is rejected; past timestamps
    // are valid as long as `expiration` (checked below) has not
    // passed, so pre-signed tokens for future uploads stay valid.
    if event.created_at > now {
        return None;
    }
    if !event_tags(event, "t").any(|t| t == verb) {
        return None;
    }
    // BUD-11: the `expiration` tag is mandatory and must be a unix
    // timestamp in the future — a missing or unparseable value is rejected
    // too, so an intercepted token cannot outlive its scope.
    let exp = event_tags(event, "expiration").next()?;
    if exp.parse::<u64>().map(|e| e <= now).unwrap_or(true) {
        return None;
    }
    // The `server` tags (when present) must name our host. BUD-11: a token
    // may carry multiple `server` tags ("the token is valid for all
    // servers" listed), and the relay must accept it when its domain
    // appears in at least one. The tag may carry a scheme and a path; IPv6
    // hosts use brackets (`[::1]`), whose colons must not be mistaken for
    // a port separator.
    let host = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    let servers: Vec<&str> = event_tags(event, "server").collect();
    if !servers.is_empty() && !servers.iter().any(|s| auth_server_host(s) == host) {
        return None;
    }
    // BUD-11: when the endpoint implies a blob hash (upload/delete), at
    // least one `x` tag must match it.
    if let Some(sha) = expected_sha
        && !event_tags(event, "x").any(|x| x == sha)
    {
        return None;
    }
    Some(event.pubkey.clone())
}

/// Verifies a Blossom auth event (BUD-11): kind 24242 with `t` (verb),
/// mandatory future `expiration`, optional `server` and `x` (sha256 scope)
/// tags. Returns the pubkey.
async fn verify_auth(
    relay: &Relay,
    state: &BlossomState,
    headers: &HeaderMap,
    verb: &str,
    expected_sha: Option<&str>,
) -> Option<String> {
    let encoded = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Nostr "))?;
    // BUD-11: the token is Base64url without padding. Accept both the
    // spec encoding and the padded standard variant for leniency.
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(encoded))
        .ok()?;
    let event: crate::event::Event = serde_json::from_slice(&raw).ok()?;
    let pubkey = validate_auth_event(
        relay.secp(),
        &event,
        &state.host,
        verb,
        expected_sha,
        unix_now(),
    )?;
    // NIP-86 `banpubkey` applies to authenticated actions on every
    // endpoint: a blocked pubkey must not upload, delete or list Blossom
    // blobs either (the WebSocket publish/read paths already enforce it).
    let blocked = relay
        .access
        .read()
        .await
        .blocked_pubkeys
        .iter()
        .any(|(pk, _)| pk.eq_ignore_ascii_case(&pubkey));
    if blocked {
        return None;
    }
    Some(pubkey)
}

fn error(status: StatusCode, reason: &str) -> Response {
    // The reason also goes into the `x-reason` header, where control
    // characters and non-ASCII bytes (possible in io/S3 error strings:
    // filenames, XML, OS messages) would panic the response builder.
    // Sanitize the header value; the body keeps the full text.
    let header_reason: String = reason
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(200)
        .collect();
    let reason = reason.to_string();
    (
        status,
        [
            (axum::http::header::CONTENT_TYPE, "text/plain".to_string()),
            (
                axum::http::header::HeaderName::from_static("x-reason"),
                header_reason,
            ),
        ],
        reason,
    )
        .into_response()
}

/// Parses a single `Range: bytes=` request (RFC 7233) against `size`.
///
/// Returns `Ok(None)` when the range should be ignored (a multi-range
/// header, or a unit other than `bytes` — RFC 7233 allows the server to
/// ignore the header), `Ok(Some((start, end)))` for a satisfiable single
/// range (inclusive end, clamped to the blob size) and an error for an
/// unsatisfiable or malformed range (416 with `Content-Range: bytes */`).
fn parse_range(header: &str, size: usize) -> anyhow::Result<Option<(usize, usize)>> {
    let Some(spec) = header
        .trim()
        .strip_prefix("bytes=")
        .or_else(|| header.trim().strip_prefix("Bytes="))
    else {
        return Ok(None); // not a byte range: ignore
    };
    if spec.contains(',') {
        return Ok(None); // multi-range: serve the full blob instead
    }
    let (start, end) = match spec.split_once('-') {
        Some((start, end)) if !start.is_empty() => {
            // `bytes=start-end` / `bytes=start-`
            let start: usize = start.parse()?;
            let end = if end.is_empty() {
                size.saturating_sub(1)
            } else {
                end.parse::<usize>()?.min(size.saturating_sub(1))
            };
            (start, end)
        }
        Some((_, suffix)) => {
            // `bytes=-suffix`: the last `suffix` bytes
            let suffix: usize = suffix.parse()?;
            if suffix == 0 {
                return Err(anyhow::anyhow!("empty range suffix"));
            }
            (size.saturating_sub(suffix), size.saturating_sub(1))
        }
        None => return Err(anyhow::anyhow!("invalid byte range")),
    };
    if start >= size || end < start {
        return Err(anyhow::anyhow!("range is outside blob size"));
    }
    Ok(Some((start, end)))
}

/// Streams a local file in 64 KiB chunks (the `remaining` bound keeps a
/// Range response from reading past the requested window).
struct FileChunks {
    file: tokio::fs::File,
    remaining: u64,
    buf: Vec<u8>,
}

impl futures_util::Stream for FileChunks {
    type Item = Result<bytes::Bytes, std::io::Error>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        use tokio::io::AsyncReadExt;
        let this = &mut *self;
        let to_read = (this.buf.len() as u64).min(this.remaining) as usize;
        if to_read == 0 {
            return std::task::Poll::Ready(None);
        }
        let file = &mut this.file;
        let read = std::task::ready!(std::pin::pin!(file.read(&mut this.buf[..to_read])).poll(_cx));
        match read {
            Ok(0) => std::task::Poll::Ready(None),
            Ok(n) => {
                this.remaining -= n as u64;
                std::task::Poll::Ready(Some(Ok(bytes::Bytes::copy_from_slice(&this.buf[..n]))))
            }
            Err(e) => std::task::Poll::Ready(Some(Err(e))),
        }
    }
}

/// Caps an S3 response stream at `remaining` bytes: the mirror of
/// [`FileChunks`] for providers that ignore or mangle the `Range` header
/// (a 200-with-the-full-object response must not overrun the range).
struct S3Chunks {
    stream: std::pin::Pin<
        Box<dyn futures_util::Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Send>,
    >,
    remaining: u64,
}

impl S3Chunks {
    fn new(resp: reqwest::Response, remaining: u64) -> S3Chunks {
        S3Chunks {
            stream: Box::pin(resp.bytes_stream()),
            remaining,
        }
    }
}

impl futures_util::Stream for S3Chunks {
    type Item = Result<bytes::Bytes, std::io::Error>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        if self.remaining == 0 {
            return std::task::Poll::Ready(None);
        }
        let this = &mut *self;
        let chunk = std::task::ready!(this.stream.as_mut().poll_next(cx));
        match chunk {
            Some(Ok(bytes)) => {
                let take = (bytes.len() as u64).min(this.remaining) as usize;
                this.remaining -= take as u64;
                if take == 0 {
                    return std::task::Poll::Ready(None);
                }
                std::task::Poll::Ready(Some(Ok(bytes.slice(..take))))
            }
            Some(Err(e)) => std::task::Poll::Ready(Some(Err(std::io::Error::other(e)))),
            None => std::task::Poll::Ready(None),
        }
    }
}

/// Whether `mime` is an active document type that a browser would execute
/// if navigated to directly (HTML, SVG, XML, JavaScript). `sanitize_mime`
/// lowercases and strips parameters, so exact matches are enough.
fn is_active_content(mime: &str) -> bool {
    matches!(
        mime,
        "text/html"
            | "application/xhtml+xml"
            | "image/svg+xml"
            | "text/xml"
            | "application/xml"
            | "application/javascript"
            | "text/javascript"
            | "application/x-javascript"
    )
}

/// Anti-XSS hardening for user-uploaded bytes served from the Blossom
/// origin: browsers must never sniff a benign MIME into an active one, and
/// active document types are forced to download with a sandboxed policy.
/// (An SVG served as an `<img>` subresource is unaffected by
/// `Content-Disposition`; only direct navigation downloads it.)
fn harden_blob_response(response: &mut Response, mime: &str) {
    response.headers_mut().insert(
        axum::http::header::HeaderName::from_static("x-content-type-options"),
        axum::http::header::HeaderValue::from_static("nosniff"),
    );
    if is_active_content(mime) {
        response.headers_mut().insert(
            axum::http::header::CONTENT_DISPOSITION,
            axum::http::header::HeaderValue::from_static("attachment"),
        );
        response.headers_mut().insert(
            axum::http::header::HeaderName::from_static("content-security-policy"),
            axum::http::header::HeaderValue::from_static("default-src 'none'; sandbox"),
        );
    }
}

/// `GET /<sha256>` — serve the blob, streamed from the storage backend
/// (with RFC 7233 single-range support): a large blob is never loaded
/// into memory in full.
async fn get_blob(
    State(relay): State<Arc<Relay>>,
    headers: HeaderMap,
    AxPath(blob): AxPath<String>,
) -> Response {
    let Some(state) = state_of(&relay).await else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "blossom not initialized");
    };
    let Some(sha) = split_blob(&blob) else {
        return error(StatusCode::BAD_REQUEST, "invalid blob hash");
    };
    let Some(desc) = state.store.find(&sha).await else {
        return error(StatusCode::NOT_FOUND, "blob not found");
    };
    let size = desc.size;
    // `size` is a `u64` from a stored (possibly corrupt) descriptor: narrow
    // it fallibly so a corrupt entry degrades to a 404-sized empty blob on
    // 32-bit instead of truncating the range arithmetic.
    let Ok(size_usize) = usize::try_from(size) else {
        return error(StatusCode::NOT_FOUND, "blob not found");
    };
    let base_headers = [
        (axum::http::header::CONTENT_TYPE, desc.mime.clone()),
        (axum::http::header::ETAG, format!("\"{sha}\"")),
        (
            axum::http::header::CACHE_CONTROL,
            "public, max-age=31536000, immutable".to_string(),
        ),
        (axum::http::header::ACCEPT_RANGES, "bytes".to_string()),
    ];
    // BUD-01: RFC 7233 range requests (video/audio streaming). A zero-byte
    // blob (an empty upload is legal) has no bytes to serve: a full GET is
    // an empty body, any Range is unsatisfiable (parse_range against
    // size 0 always fails).
    let range = headers
        .get(axum::http::header::RANGE)
        .and_then(|v| v.to_str().ok())
        .map(|r| parse_range(r, size_usize));
    let (start, end) = match range {
        Some(Err(_)) => {
            // Unsatisfiable or malformed range: 416 with the required
            // `Content-Range: bytes */<size>`.
            let mut response = error(
                StatusCode::RANGE_NOT_SATISFIABLE,
                "requested byte range is not satisfiable",
            );
            response.headers_mut().insert(
                axum::http::header::CONTENT_RANGE,
                format!("bytes */{size}").parse().unwrap(),
            );
            return response;
        }
        Some(Ok(Some((start, end)))) => (start, end),
        _ => (0, size_usize.saturating_sub(1)),
    };
    let len = if size == 0 {
        0
    } else {
        (end - start + 1) as u64
    };
    match state.store.open_stream_any(&sha, start as u64, len).await {
        Ok(Some((stream, _owner))) => {
            // A range-unaware S3-compatible backend answers a ranged GET
            // with 200 and the full object from byte 0: serve the whole
            // blob as a 200 instead of mislabeling bytes 0..len as
            // `start..start+len` (BUD-01 range semantics).
            let (body, honored, served_len) = match stream {
                storage::BlobStream::Local(file) => (
                    axum::body::Body::from_stream(FileChunks {
                        file,
                        remaining: len,
                        buf: vec![0u8; 64 * 1024],
                    }),
                    true,
                    len,
                ),
                storage::BlobStream::S3(resp) => {
                    let honored = resp.status() == reqwest::StatusCode::PARTIAL_CONTENT;
                    let served = if honored { len } else { size };
                    (
                        axum::body::Body::from_stream(S3Chunks::new(resp, served)),
                        honored,
                        served,
                    )
                }
            };
            // A response is 206 only for a genuine single satisfiable range
            // that the backend honored: a multi-range or non-bytes Range
            // header, or an ignored backend range, serves the full blob
            // with 200 (RFC 7233).
            let ranged = matches!(range, Some(Ok(Some(_))));
            let mut response = if ranged && honored {
                (StatusCode::PARTIAL_CONTENT, base_headers, body).into_response()
            } else {
                (StatusCode::OK, base_headers, body).into_response()
            };
            if ranged
                && honored
                && let Some(Ok(Some((start, end)))) = range
            {
                response.headers_mut().insert(
                    axum::http::header::CONTENT_RANGE,
                    format!("bytes {start}-{end}/{size}").parse().unwrap(),
                );
            }
            // BUD-01: HEAD must answer with the same Content-Length as GET.
            response.headers_mut().insert(
                axum::http::header::CONTENT_LENGTH,
                served_len.to_string().parse().unwrap(),
            );
            harden_blob_response(&mut response, &desc.mime);
            response
        }
        Ok(None) => error(StatusCode::NOT_FOUND, "blob not found"),
        Err(e) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("storage error: {e}"),
        ),
    }
}

/// `HEAD /<sha256>` — blob headers without the body, mirroring GET: the
/// backing file/object must resolve (a mapping whose blob is gone is a
/// 404, exactly like GET), and a single satisfiable Range yields 206 with
/// `Content-Range` and a ranged `Content-Length`.
async fn head_blob(
    State(relay): State<Arc<Relay>>,
    headers: HeaderMap,
    AxPath(blob): AxPath<String>,
) -> Response {
    let Some(state) = state_of(&relay).await else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "blossom not initialized");
    };
    let Some(sha) = split_blob(&blob) else {
        return error(StatusCode::BAD_REQUEST, "invalid blob hash");
    };
    let Some(desc) = state.store.find(&sha).await else {
        return error(StatusCode::NOT_FOUND, "blob not found");
    };
    let size = desc.size;
    let Ok(size_usize) = usize::try_from(size) else {
        return error(StatusCode::NOT_FOUND, "blob not found");
    };
    let range = headers
        .get(axum::http::header::RANGE)
        .and_then(|v| v.to_str().ok())
        .map(|r| parse_range(r, size_usize));
    let (start, end) = match range {
        Some(Err(_)) => {
            let mut response = error(
                StatusCode::RANGE_NOT_SATISFIABLE,
                "requested byte range is not satisfiable",
            );
            response.headers_mut().insert(
                axum::http::header::CONTENT_RANGE,
                format!("bytes */{size}").parse().unwrap(),
            );
            return response;
        }
        Some(Ok(Some((start, end)))) => (start, end),
        _ => (0, size_usize.saturating_sub(1)),
    };
    let len = if size == 0 {
        0
    } else {
        (end - start + 1) as u64
    };
    // Resolve the backing object exactly like GET: a mapping without a
    // readable blob must 404, and the backend's range support decides
    // whether a Range yields 206 or a full 200.
    let honored = match state.store.open_stream_any(&sha, start as u64, len).await {
        Ok(Some((stream, _owner))) => match stream {
            storage::BlobStream::Local(_) => true,
            storage::BlobStream::S3(resp) => resp.status() == reqwest::StatusCode::PARTIAL_CONTENT,
        },
        Ok(None) => return error(StatusCode::NOT_FOUND, "blob not found"),
        Err(e) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("storage error: {e}"),
            );
        }
    };
    let ranged = matches!(range, Some(Ok(Some(_))));
    let status = if ranged && honored {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    };
    // An S3 backend that ignored the range serves the whole blob (like GET);
    // Content-Length must describe what GET would actually send.
    let served_len = if ranged && honored { len } else { size };
    let mut response = (
        status,
        [
            (axum::http::header::CONTENT_TYPE, desc.mime.clone()),
            (axum::http::header::CONTENT_LENGTH, served_len.to_string()),
            (axum::http::header::ETAG, format!("\"{sha}\"")),
            (
                axum::http::header::CACHE_CONTROL,
                "public, max-age=31536000, immutable".to_string(),
            ),
            (axum::http::header::ACCEPT_RANGES, "bytes".to_string()),
        ],
    )
        .into_response();
    if ranged
        && honored
        && let Some(Ok(Some((start, end)))) = range
    {
        response.headers_mut().insert(
            axum::http::header::CONTENT_RANGE,
            format!("bytes {start}-{end}/{size}").parse().unwrap(),
        );
    }
    harden_blob_response(&mut response, &desc.mime);
    response
}

/// `PUT /upload` — upload a blob (BUD-02). Returns 201 + the descriptor.
async fn upload(State(relay): State<Arc<Relay>>, headers: HeaderMap, body: Body) -> Response {
    put_blob(relay, headers, body, "upload").await
}

/// `PUT /media` — media optimization upload (BUD-05). nostrfy stores the
/// exact bytes received (optimization is a SHOULD, not a MUST); the
/// endpoint exists so clients that treat it as a trusted processing
/// server (e.g. nostter) can upload without changes.
async fn upload_media(State(relay): State<Arc<Relay>>, headers: HeaderMap, body: Body) -> Response {
    put_blob(relay, headers, body, "media").await
}

/// Shared PUT logic for `/upload` (BUD-02) and `/media` (BUD-05).
async fn put_blob(relay: Arc<Relay>, headers: HeaderMap, body: Body, verb: &str) -> Response {
    let Some(state) = state_of(&relay).await else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "blossom not initialized");
    };
    let max_upload = state.max_upload_bytes;
    let permits = match state
        .upload_budget
        .clone()
        .try_acquire_many_owned(max_upload.min(u32::MAX as usize) as u32)
    {
        Ok(permit) => permit,
        Err(_) => {
            return error(
                StatusCode::TOO_MANY_REQUESTS,
                "too many uploads in progress",
            );
        }
    };
    let (path, size, sha) = match spool_upload(body, max_upload).await {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let mut cleanup = TempUploadCleanup::new(path.clone());
    // BUD-02/05: the optional `X-SHA-256` header declares the expected hash
    // of the request body — a provided value that does not match the actual
    // bytes is a 409 Conflict, and a malformed value is a 400.
    if let Some(declared) = headers.get("x-sha-256").and_then(|v| v.to_str().ok()) {
        let declared = declared.trim().to_ascii_lowercase();
        if declared.len() != 64 || hex::decode(&declared).is_err() {
            let _ = tokio::fs::remove_file(&path).await;
            return error(StatusCode::BAD_REQUEST, "malformed X-SHA-256 header");
        }
        if declared != sha {
            let _ = tokio::fs::remove_file(&path).await;
            return error(
                StatusCode::CONFLICT,
                "the X-SHA-256 header does not match the request body",
            );
        }
    }
    // BUD-11: upload/media tokens MUST carry an `x` tag matching the blob
    // hash (the token is scoped to exactly the bytes being uploaded).
    let Some(pubkey) = verify_auth(&relay, &state, &headers, verb, Some(&sha)).await else {
        let _ = tokio::fs::remove_file(&path).await;
        return error(StatusCode::UNAUTHORIZED, "invalid or missing authorization");
    };
    // Upload allowlist: when restrict_uploads is on, only the listed
    // pubkeys (npub1... or hex) may upload.
    if upload_allowed(&relay, &pubkey).await.is_err() {
        let _ = tokio::fs::remove_file(&path).await;
        return error(
            StatusCode::FORBIDDEN,
            "uploads are restricted to the configured allowlist",
        );
    }
    if state.store.check_space().is_err() {
        let _ = tokio::fs::remove_file(&path).await;
        return error(StatusCode::INSUFFICIENT_STORAGE, "storage is full");
    }
    let mime = sanitize_mime(
        headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/octet-stream"),
    );
    // BUD-02/05: 201 for a newly stored blob, 200 when it already exists.
    let existed = state.store.find(&sha).await.is_some();
    let result = state
        .store
        .put_file(&pubkey, &sha, &path, size, &mime)
        .await;
    match tokio::fs::remove_file(&path).await {
        Ok(()) => cleanup.disarm(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => cleanup.disarm(),
        Err(_) => {}
    }
    drop(permits);
    match result {
        Ok(desc) => {
            let url = format!("https://{}/{sha}{}", state.host, ext_of(&desc.mime));
            let status = if existed {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            };
            (
                status,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                serde_json::to_string(&json!({
                    "sha256": desc.sha256,
                    "size": desc.size,
                    "type": desc.mime,
                    "url": url,
                    "uploaded": desc.uploaded,
                }))
                .unwrap(),
            )
                .into_response()
        }

        Err(e) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("storage error: {e}"),
        ),
    }
}

/// Spools an upload to disk while hashing it. The request body is never
/// materialized in one `Bytes` allocation, and the size limit is enforced
/// while reading rather than after the extractor has buffered the body.
async fn spool_upload(
    body: Body,
    max_upload: usize,
) -> Result<(std::path::PathBuf, u64, String), Box<Response>> {
    use futures_util::StreamExt;
    use sha2::{Digest, Sha256};
    use tokio::io::AsyncWriteExt;

    static TEMP_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "nostrfy-blossom-{}-{}",
        std::process::id(),
        TEMP_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let mut cleanup = TempUploadCleanup::new(path.clone());
    let mut file = match tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .await
    {
        Ok(file) => file,
        Err(e) => {
            return Err(Box::new(error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("temporary upload failed: {e}"),
            )));
        }
    };
    let mut stream = body.into_data_stream();
    let mut hash = Sha256::new();
    let mut size = 0u64;
    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(e) => {
                return Err(Box::new(error(
                    StatusCode::BAD_REQUEST,
                    &format!("upload body failed: {e}"),
                )));
            }
        };
        size = size.saturating_add(chunk.len() as u64);
        if size > max_upload as u64 {
            return Err(Box::new(error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "upload exceeds the configured size limit",
            )));
        }
        hash.update(&chunk);
        if let Err(e) = file.write_all(&chunk).await {
            return Err(Box::new(error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("temporary upload failed: {e}"),
            )));
        }
    }
    if let Err(e) = file.flush().await {
        return Err(Box::new(error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("temporary upload failed: {e}"),
        )));
    }
    drop(file);
    cleanup.disarm();
    Ok((path, size, hex::encode(hash.finalize())))
}

struct TempUploadCleanup {
    path: Option<std::path::PathBuf>,
}

impl TempUploadCleanup {
    fn new(path: std::path::PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for TempUploadCleanup {
    fn drop(&mut self) {
        let Some(path) = self.path.take() else {
            return;
        };
        if let Err(e) = std::fs::remove_file(&path)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            log::warn!(
                "cannot remove temporary Blossom upload {}: {e}",
                path.display()
            );
        }
    }
}

/// `HEAD /upload` — BUD-06 pre-flight: whether a `PUT /upload` would be
/// accepted, based on the `X-SHA-256`, `X-Content-Type` and
/// `X-Content-Length` headers alone.
async fn head_upload(State(relay): State<Arc<Relay>>, headers: HeaderMap) -> Response {
    head_preflight(relay, headers, "upload").await
}

/// `HEAD /media` — BUD-05/BUD-06 pre-flight: whether a `PUT /media` would
/// be accepted, based on the `X-SHA-256`, `X-Content-Type` and
/// `X-Content-Length` headers alone.
async fn head_media(State(relay): State<Arc<Relay>>, headers: HeaderMap) -> Response {
    head_preflight(relay, headers, "media").await
}

/// Shared pre-flight logic for `HEAD /upload` (BUD-06) and `HEAD /media`
/// (BUD-05): evaluates the declared `X-SHA-256` / `X-Content-Length` /
/// `X-Content-Type` headers against the server policy and returns whether
/// the corresponding PUT would be accepted.
async fn head_preflight(relay: Arc<Relay>, headers: HeaderMap, verb: &str) -> Response {
    let Some(state) = state_of(&relay).await else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "blossom not initialized");
    };
    // `X-SHA-256` is required: it is the only source of the blob hash
    // without a body.
    let Some(x_sha) = headers.get("x-sha-256").and_then(|v| v.to_str().ok()) else {
        return error(StatusCode::BAD_REQUEST, "missing X-SHA-256 header");
    };
    let x_sha = x_sha.trim().to_ascii_lowercase();
    if x_sha.len() != 64 || hex::decode(&x_sha).is_err() {
        return error(StatusCode::BAD_REQUEST, "malformed X-SHA-256 header");
    }
    // `X-Content-Length` is required and bounded by the upload ceiling.
    let Some(len) = headers
        .get("x-content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
    else {
        return error(
            StatusCode::LENGTH_REQUIRED,
            "missing X-Content-Length header",
        );
    };
    let max_upload = state.max_upload_bytes as u64;
    if len > max_upload {
        return error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "the upload exceeds the configured size limit",
        );
    }
    // BUD-11: upload/media tokens carry the matching verb and an `x` tag
    // matching the declared hash.
    let Some(pubkey) = verify_auth(&relay, &state, &headers, verb, Some(&x_sha)).await else {
        return error(StatusCode::UNAUTHORIZED, "invalid or missing authorization");
    };
    if upload_allowed(&relay, &pubkey).await.is_err() {
        return error(
            StatusCode::FORBIDDEN,
            "uploads are restricted to the configured allowlist",
        );
    }
    // The preflight must reflect the PUT outcome: a full disk would
    // refuse the upload with 507, so the preflight does too.
    if state.store.check_space().is_err() {
        return error(StatusCode::INSUFFICIENT_STORAGE, "storage is full");
    }
    StatusCode::OK.into_response()
}

/// `GET /list/<pubkey>` — blobs uploaded by a pubkey (hex), sorted by
/// `uploaded` descending, with BUD-12 cursor-based pagination
/// (`cursor` = the sha256 of the last entry of the previous page,
/// `limit` = the maximum number of results). The inventory is private:
/// BUD-11 assigns this endpoint the `t=list` verb and the token must be
/// issued by the listed pubkey itself.
async fn list(
    State(relay): State<Arc<Relay>>,
    headers: HeaderMap,
    AxPath(pubkey): AxPath<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let Some(state) = state_of(&relay).await else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "blossom not initialized");
    };
    // BUD-11: `/list/<pubkey>` uses the `t=list` verb. A user's blob
    // inventory is private to that user, so the token must be issued by the
    // listed pubkey.
    let Some(auth_pubkey) = verify_auth(&relay, &state, &headers, "list", None).await else {
        return error(StatusCode::UNAUTHORIZED, "invalid or missing authorization");
    };
    if !is_pubkey(&pubkey) {
        return error(StatusCode::BAD_REQUEST, "invalid pubkey");
    }
    let pubkey = pubkey.to_ascii_lowercase();
    if !auth_pubkey.eq_ignore_ascii_case(&pubkey) {
        return error(StatusCode::FORBIDDEN, "only the owner may list their blobs");
    }
    // BUD-12: malformed query parameters are a 400, not silently ignored
    // (an ignored `cursor` would return an unbounded page).
    if params.get("cursor").is_some_and(|c| !is_pubkey(c)) {
        return error(StatusCode::BAD_REQUEST, "invalid cursor");
    }
    let limit = match params.get("limit") {
        Some(v) => match v.parse::<usize>() {
            // Bound the page: an unbounded `?limit=9999999` would serialize
            // every blob of a heavy uploader into one response.
            Ok(l) => Some(l.min(1000)),
            Err(_) => return error(StatusCode::BAD_REQUEST, "invalid limit"),
        },
        None => Some(100),
    };
    let cursor = params.get("cursor").map(String::as_str);
    // The store walk itself is capped (`LIST_SCAN_CAP`): resolving is what
    // costs (one metadata read per blob), and pages past the window yield
    // an empty page like an unknown cursor below.
    const LIST_SCAN_CAP: usize = 5000;
    let mut blobs = state.store.list(&pubkey, LIST_SCAN_CAP).await;
    // BUD-12: sorted by `uploaded` descending; the page starts after the
    // cursor and never includes it. An unknown (but well-formed) cursor
    // yields an empty page — not the first page — so a client paging with
    // a stale cursor cannot loop over duplicates forever.
    blobs.sort_by_key(|d| std::cmp::Reverse(d.uploaded));
    if let Some(cursor) = cursor {
        match blobs.iter().position(|d| d.sha256 == cursor) {
            Some(pos) => {
                blobs.drain(..=pos);
            }
            None => blobs.clear(),
        }
    }
    if let Some(limit) = limit {
        blobs.truncate(limit);
    }
    let items: Vec<Value> = blobs
        .into_iter()
        .map(|d| {
            json!({
                "sha256": d.sha256,
                "size": d.size,
                "type": d.mime,
                "url": format!(
                    "https://{}/{}{}",
                    state.host,
                    d.sha256,
                    ext_of(&d.mime)
                ),
                "uploaded": d.uploaded,
            })
        })
        .collect();
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&items).unwrap(),
    )
        .into_response()
}

/// `DELETE /<sha256>[.ext]` — delete the requester's own copy of a blob.
async fn delete_blob(
    State(relay): State<Arc<Relay>>,
    headers: HeaderMap,
    AxPath(blob): AxPath<String>,
) -> Response {
    let Some(state) = state_of(&relay).await else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "blossom not initialized");
    };
    let Some(sha) = split_blob(&blob) else {
        return error(StatusCode::BAD_REQUEST, "invalid blob hash");
    };
    let Some(pubkey) = verify_auth(&relay, &state, &headers, "delete", Some(&sha)).await else {
        return error(StatusCode::UNAUTHORIZED, "invalid or missing authorization");
    };
    if state.store.find(&sha).await.is_none() {
        return error(StatusCode::NOT_FOUND, "blob not found");
    }
    // Only an uploader of these bytes may delete their own copy; other
    // uploaders of identical content keep theirs.
    if !state.store.has(&pubkey, &sha).await {
        return error(
            StatusCode::FORBIDDEN,
            "only the uploader may delete this blob",
        );
    }
    match state.store.delete(&pubkey, &sha).await {
        Ok(true) => StatusCode::OK.into_response(),
        Ok(false) => error(StatusCode::NOT_FOUND, "blob not found"),
        Err(e) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("storage error: {e}"),
        ),
    }
}

/// Builds the shared Blossom state from the config (or `None` when the
/// feature is disabled). Must be called before the router is built.
pub(crate) async fn build_state(cfg: &Config, _relay: &Relay) -> Option<Arc<BlossomState>> {
    if cfg.blossom.host.trim().is_empty() {
        return None;
    }
    let s3 = if cfg.blossom.storage == "s3" {
        Some(storage::S3Config {
            endpoint: cfg.blossom.s3_endpoint.clone(),
            region: cfg.blossom.s3_region.clone(),
            bucket: cfg.blossom.s3_bucket.clone(),
            access_key: cfg.blossom.s3_access_key.clone(),
            secret_key: cfg.blossom.s3_secret_key.clone(),
        })
    } else {
        None
    };
    match BlobStore::new(
        &cfg.blossom.storage,
        &cfg.blossom.local_path,
        cfg.blossom.min_free_bytes,
        s3,
        _relay.db.clone(),
    )
    .await
    {
        Ok(store) => {
            let state = Arc::new(BlossomState {
                store,
                host: cfg.blossom.host.clone(),
                max_upload_bytes: cfg.blossom.max_upload_bytes,
                upload_budget: Arc::new(tokio::sync::Semaphore::new(
                    cfg.blossom.max_upload_bytes.saturating_mul(4).max(1),
                )),
            });
            // One-time automatic migration of legacy blobs (storage files
            // that predate the LMDB mapping), in the background so the
            // relay starts instantly.
            let state_for_migration = Arc::clone(&state);
            tokio::spawn(async move {
                match state_for_migration.store.auto_migrate_legacy().await {
                    Ok(n) if n > 0 => {
                        log::info!("Blossom legacy migration: mapped {n} existing blob(s)")
                    }
                    Ok(_) => {}
                    Err(e) => log::warn!("Blossom legacy migration failed: {e}"),
                }
            });
            Some(state)
        }
        Err(e) => {
            log::error!("blossom storage failed to initialize: {e}");
            None
        }
    }
}

/// Whether the request Host header names the Blossom host. Takes the raw
/// header value (not the whole request) so callers can hold it across
/// awaits without borrowing the request.
pub(crate) fn host_is_blossom(blossom_host: &str, host_header: Option<&str>) -> bool {
    if blossom_host.trim().is_empty() {
        return false;
    }
    host_header.is_some_and(|h| {
        let host = crate::server::host_header_host(h).to_ascii_lowercase();
        host == blossom_host
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_ascii_lowercase()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;
    use secp256k1::{Keypair, Secp256k1, XOnlyPublicKey};

    /// Builds a relay with the Blossom feature enabled on local storage.
    async fn build_blossom_relay(min_free_bytes: u64) -> Arc<Relay> {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir()
            .join("nostrfy-blossom-handler")
            .join(format!("{:x}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut cfg = Config::default();
        cfg.database.path = dir.join("db");
        cfg.blossom.host = "media.example.com".into();
        cfg.blossom.storage = "local".into();
        cfg.blossom.local_path = dir.join("blobs");
        cfg.blossom.min_free_bytes = min_free_bytes;
        let db = crate::db::DbClient::open(
            &cfg.database,
            true,
            Arc::new(Default::default()),
            0,
            128,
            4096,
            262144,
        )
        .unwrap();
        let config = Arc::new(tokio::sync::RwLock::new(cfg));
        let stats = crate::stats::Stats::new();
        let mut relay = Relay::new(
            config,
            db,
            stats,
            "",
            crate::relay::LiveBusConfig {
                buffer: 1024,
                batch_interval_ms: 10,
                batch_size: 64,
            },
        )
        .await;
        relay.start_live_bus();
        let relay = Arc::new(relay);
        let state = build_state(&relay.config.read().await.clone(), &relay).await;
        *relay.blossom.write().await = state;
        relay
    }

    fn sha256_hex(data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(data))
    }

    fn auth_event(
        secp: &Secp256k1<secp256k1::All>,
        created: u64,
        verb: &str,
        expiration: Option<u64>,
        x: Option<&str>,
        server: Option<&str>,
    ) -> Event {
        let keypair = Keypair::from_seckey_slice(secp, &[9u8; 32]).unwrap();
        let pubkey = XOnlyPublicKey::from_keypair(&keypair).0.to_string();
        let mut tags: Vec<Vec<String>> = vec![vec!["t".into(), verb.into()]];
        if let Some(exp) = expiration {
            tags.push(vec!["expiration".into(), exp.to_string()]);
        }
        if let Some(x) = x {
            tags.push(vec!["x".into(), x.into()]);
        }
        if let Some(server) = server {
            tags.push(vec!["server".into(), server.into()]);
        }
        let mut ev = Event {
            id: String::new(),
            pubkey,
            created_at: created,
            kind: 24242,
            tags,
            content: String::new(),
            sig: String::new(),
        };
        ev.id = crate::nips::nip01::compute_id(&ev);
        let id = ev.id_bytes().unwrap();
        ev.sig = secp.sign_schnorr_no_aux_rand(&id, &keypair).to_string();
        ev
    }

    /// A valid Blossom `Authorization: Nostr <token>` header for `verb`,
    /// returning the header map and the author's hex pubkey.
    fn auth_headers(secp: &Secp256k1<secp256k1::All>, verb: &str) -> (HeaderMap, String) {
        let now = unix_now();
        let ev = auth_event(secp, now, verb, Some(now + 600), None, None);
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&ev).unwrap());
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Nostr {token}").parse().unwrap(),
        );
        (headers, ev.pubkey)
    }

    #[tokio::test]
    async fn s3_chunks_caps_at_remaining_bytes() {
        use futures_util::StreamExt as _;
        let chunks: Vec<Result<bytes::Bytes, reqwest::Error>> = vec![
            Ok(bytes::Bytes::from_static(&[1, 2, 3])),
            Ok(bytes::Bytes::from_static(&[4, 5, 6, 7, 8])),
            Ok(bytes::Bytes::from_static(&[9])),
        ];
        let stream = S3Chunks {
            stream: Box::pin(futures_util::stream::iter(chunks)),
            remaining: 7,
        };
        let mut out = Vec::new();
        futures_util::pin_mut!(stream);
        while let Some(chunk) = stream.next().await {
            out.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(out, vec![1, 2, 3, 4, 5, 6, 7], "the cap is byte-exact");
    }

    #[tokio::test]
    async fn get_blob_streams_full_and_ranges() {
        let relay = build_blossom_relay(0).await;
        let state = relay.blossom.read().await.clone().unwrap();
        let data: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();
        let sha = sha256_hex(&data);
        state
            .store
            .put(&"aa".repeat(32), &sha, &data, "application/octet-stream")
            .await
            .unwrap();
        // Full GET: the whole blob, streamed.
        let resp = get_blob(State(relay.clone()), HeaderMap::new(), AxPath(sha.clone())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()[axum::http::header::ACCEPT_RANGES], "bytes");
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], &data[..]);
        // Range GET: 206 with the exact bytes and Content-Range.
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::RANGE,
            "bytes=1000-1999".parse().unwrap(),
        );
        let resp = get_blob(State(relay.clone()), headers, AxPath(sha.clone())).await;
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            resp.headers()[axum::http::header::CONTENT_RANGE],
            "bytes 1000-1999/50000"
        );
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], &data[1000..2000]);
        // A multi-range header is ignored (RFC 7233): the full blob with 200,
        // not a 206 without Content-Range.
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::RANGE,
            "bytes=1000-1999,5000-5999".parse().unwrap(),
        );
        let resp = get_blob(State(relay.clone()), headers, AxPath(sha.clone())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(axum::http::header::CONTENT_RANGE),
            None,
            "an ignored range must not claim partial content"
        );
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], &data[..]);
        // A non-bytes range unit is ignored the same way.
        let mut headers = HeaderMap::new();
        headers.insert(axum::http::header::RANGE, "items=0-1".parse().unwrap());
        let resp = get_blob(State(relay.clone()), headers, AxPath(sha.clone())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        // Unsatisfiable range: 416 with `Content-Range: bytes */`.
        let mut headers = HeaderMap::new();
        headers.insert(axum::http::header::RANGE, "bytes=50000-".parse().unwrap());
        let resp = get_blob(State(relay.clone()), headers, AxPath(sha.clone())).await;
        assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(
            resp.headers()[axum::http::header::CONTENT_RANGE],
            "bytes */50000"
        );
        // Unknown blob: 404.
        let resp = get_blob(
            State(relay.clone()),
            HeaderMap::new(),
            AxPath("ab".repeat(32)),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        // Malformed hash: 400 (the host-split middleware would block such
        // a path upstream, but the handler rejects it on its own).
        let resp = get_blob(
            State(relay.clone()),
            HeaderMap::new(),
            AxPath("notahexhash".into()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn get_blob_serves_empty_blob() {
        let relay = build_blossom_relay(0).await;
        let state = relay.blossom.read().await.clone().unwrap();
        let sha = sha256_hex(b"");
        state
            .store
            .put(&"aa".repeat(32), &sha, b"", "application/octet-stream")
            .await
            .unwrap();
        // Full GET of a zero-byte blob: 200 with an empty body (a size-0
        // subtraction must not underflow).
        let resp = get_blob(State(relay.clone()), HeaderMap::new(), AxPath(sha.clone())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(body.is_empty());
        // Any Range on an empty blob: 416.
        let mut headers = HeaderMap::new();
        headers.insert(axum::http::header::RANGE, "bytes=0-0".parse().unwrap());
        let resp = get_blob(State(relay.clone()), headers, AxPath(sha.clone())).await;
        assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(
            resp.headers()[axum::http::header::CONTENT_RANGE],
            "bytes */0"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn preflight_reports_507_when_storage_is_full() {
        let relay = build_blossom_relay(u64::MAX).await;
        let sha = sha256_hex(b"x");
        let now = unix_now();
        let ev = auth_event(
            relay.secp(),
            now,
            "upload",
            Some(now + 300),
            Some(&sha),
            None,
        );
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&ev).unwrap());
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Nostr {token}").parse().unwrap(),
        );
        headers.insert("x-sha-256", sha.parse().unwrap());
        headers.insert("x-content-length", "1".parse().unwrap());
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "text/plain".parse().unwrap(),
        );
        let resp = head_preflight(relay.clone(), headers, "upload").await;
        assert_eq!(
            resp.status(),
            StatusCode::INSUFFICIENT_STORAGE,
            "the preflight must mirror the PUT outcome on a full disk"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn upload_returns_507_when_storage_is_full() {
        let relay = build_blossom_relay(u64::MAX).await;
        let data = b"hello blossom";
        let sha = sha256_hex(data);
        let now = unix_now();
        let ev = auth_event(
            relay.secp(),
            now,
            "upload",
            Some(now + 300),
            Some(&sha),
            None,
        );
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&ev).unwrap());
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Nostr {token}").parse().unwrap(),
        );
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "text/plain".parse().unwrap(),
        );
        let resp = upload(
            State(relay.clone()),
            headers,
            axum::body::Bytes::from_static(data).into(),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::INSUFFICIENT_STORAGE,
            "a full disk must be reported as 507"
        );
        relay.db.shutdown();
    }

    #[test]
    fn auth_event_validation_follows_bud11() {
        let secp = Secp256k1::new();
        let now = unix_now();
        let sha = "a".repeat(64);
        let host = "media.example.com";
        // A fully-specified upload token validates.
        let ev = auth_event(
            &secp,
            now,
            "upload",
            Some(now + 300),
            Some(&sha),
            Some(host),
        );
        assert_eq!(
            validate_auth_event(&secp, &ev, host, "upload", Some(&sha), now),
            Some(ev.pubkey.clone())
        );
        // BUD-11: the `expiration` tag is mandatory.
        let ev = auth_event(&secp, now, "upload", None, Some(&sha), Some(host));
        assert_eq!(
            validate_auth_event(&secp, &ev, host, "upload", Some(&sha), now),
            None,
            "a token without an expiration tag must be rejected"
        );
        // An expired or unparseable expiration is rejected.
        let ev = auth_event(&secp, now, "upload", Some(now - 1), Some(&sha), Some(host));
        assert_eq!(
            validate_auth_event(&secp, &ev, host, "upload", Some(&sha), now),
            None
        );
        let ev = auth_event(&secp, now, "upload", Some(0), Some(&sha), Some(host));
        assert_eq!(
            validate_auth_event(&secp, &ev, host, "upload", Some(&sha), now),
            None
        );
        // The `t` verb must match the endpoint.
        let ev = auth_event(
            &secp,
            now,
            "delete",
            Some(now + 300),
            Some(&sha),
            Some(host),
        );
        assert_eq!(
            validate_auth_event(&secp, &ev, host, "upload", Some(&sha), now),
            None
        );
        // A `server` tag naming another host is rejected.
        let ev = auth_event(
            &secp,
            now,
            "upload",
            Some(now + 300),
            Some(&sha),
            Some("evil.example.com"),
        );
        assert_eq!(
            validate_auth_event(&secp, &ev, host, "upload", Some(&sha), now),
            None
        );
        // BUD-11: multiple `server` tags are accepted when our domain
        // appears in at least one of them.
        let mut ev = auth_event(
            &secp,
            now,
            "upload",
            Some(now + 300),
            Some(&sha),
            Some("evil.example.com"),
        );
        // Re-sign after adding the second `server` tag (the signature must
        // cover the final tag set).
        ev.tags.push(vec!["server".into(), host.into()]);
        ev.id = crate::nips::nip01::compute_id(&ev);
        let id = ev.id_bytes().unwrap();
        let keypair = Keypair::from_seckey_slice(&secp, &[9u8; 32]).unwrap();
        ev.sig = secp.sign_schnorr_no_aux_rand(&id, &keypair).to_string();
        assert_eq!(
            validate_auth_event(&secp, &ev, host, "upload", Some(&sha), now),
            Some(ev.pubkey.clone()),
            "a token listing several servers must be accepted when ours is among them"
        );
        // BUD-11: an upload token must carry an `x` tag matching the blob.
        let ev = auth_event(&secp, now, "upload", Some(now + 300), None, Some(host));
        assert_eq!(
            validate_auth_event(&secp, &ev, host, "upload", Some(&sha), now),
            None,
            "an upload token without an x tag must be rejected"
        );
        let ev = auth_event(
            &secp,
            now,
            "upload",
            Some(now + 300),
            Some("b".repeat(64).as_str()),
            Some(host),
        );
        assert_eq!(
            validate_auth_event(&secp, &ev, host, "upload", Some(&sha), now),
            None,
            "an x tag for a different blob must be rejected"
        );
        // BUD-11: `created_at` must be in the past — a token stamped well
        // in the past stays valid as long as `expiration` has not passed
        // (pre-signed tokens are spec-conformant).
        let ev = auth_event(
            &secp,
            now - 601,
            "upload",
            Some(now + 300),
            Some(&sha),
            Some(host),
        );
        assert_eq!(
            validate_auth_event(&secp, &ev, host, "upload", Some(&sha), now),
            Some(ev.pubkey.clone()),
            "a past-stamped token with a future expiration is valid"
        );
        // A future `created_at` is rejected.
        let ev = auth_event(
            &secp,
            now + 601,
            "upload",
            Some(now + 300),
            Some(&sha),
            Some(host),
        );
        assert_eq!(
            validate_auth_event(&secp, &ev, host, "upload", Some(&sha), now),
            None
        );
        // A wrong event kind is rejected.
        let mut ev = auth_event(
            &secp,
            now,
            "upload",
            Some(now + 300),
            Some(&sha),
            Some(host),
        );
        ev.kind = 22242;
        assert_eq!(
            validate_auth_event(&secp, &ev, host, "upload", Some(&sha), now),
            None
        );
        // A delete token without an `x` tag is rejected (implied hash).
        let ev = auth_event(&secp, now, "delete", Some(now + 300), None, Some(host));
        assert_eq!(
            validate_auth_event(&secp, &ev, host, "delete", Some(&sha), now),
            None
        );
        // An unsigned (invalid signature) token is rejected.
        let mut ev = auth_event(
            &secp,
            now,
            "upload",
            Some(now + 300),
            Some(&sha),
            Some(host),
        );
        ev.sig = "f".repeat(128);
        assert_eq!(
            validate_auth_event(&secp, &ev, host, "upload", Some(&sha), now),
            None
        );
    }

    #[test]
    fn byte_ranges_follow_rfc7233() {
        // Satisfiable ranges (end is inclusive and clamped).
        assert_eq!(parse_range("bytes=0-4", 10).unwrap(), Some((0, 4)));
        assert_eq!(parse_range("bytes=5-", 10).unwrap(), Some((5, 9)));
        assert_eq!(parse_range("bytes=-3", 10).unwrap(), Some((7, 9)));
        assert_eq!(parse_range("bytes=0-99", 10).unwrap(), Some((0, 9)));
        assert_eq!(parse_range("bytes=5-5", 10).unwrap(), Some((5, 5)));
        // Unsatisfiable or malformed ranges.
        assert!(parse_range("bytes=10-", 10).is_err());
        assert!(parse_range("bytes=8-4", 10).is_err());
        assert!(parse_range("bytes=-0", 10).is_err());
        assert!(parse_range("bytes=abc", 10).is_err());
        assert!(parse_range("bytes=0-", 0).is_err());
        // Multi-ranges and non-byte units are ignored (full response).
        assert_eq!(parse_range("bytes=0-4,6-8", 10).unwrap(), None);
        assert_eq!(parse_range("items=0-4", 10).unwrap(), None);
        assert_eq!(parse_range("", 10).unwrap(), None);
    }

    #[test]
    fn auth_server_host_normalization() {
        assert_eq!(auth_server_host("media.example.com"), "media.example.com");
        assert_eq!(
            auth_server_host("media.example.com:8080"),
            "media.example.com"
        );
        assert_eq!(
            auth_server_host("https://media.example.com"),
            "media.example.com"
        );
        assert_eq!(
            auth_server_host("https://media.example.com/path"),
            "media.example.com"
        );
        assert_eq!(auth_server_host("[::1]"), "::1");
        assert_eq!(auth_server_host("[::1]:8080"), "::1");
        assert_eq!(auth_server_host("http://[::1]/upload"), "::1");
        assert_eq!(auth_server_host("MEDIA.EXAMPLE.COM"), "media.example.com");
    }

    #[test]
    fn mime_sanitization() {
        assert_eq!(sanitize_mime("image/png"), "image/png");
        assert_eq!(sanitize_mime("image/png; charset=utf-8"), "image/png");
        assert_eq!(sanitize_mime("  IMAGE/JPEG  "), "image/jpeg");
        assert_eq!(sanitize_mime("image/png; filename=a.png"), "image/png");
        assert_eq!(
            sanitize_mime("image/png\r\nX-Evil: 1"),
            "application/octet-stream"
        );
        assert_eq!(sanitize_mime("image/"), "application/octet-stream");
        assert_eq!(sanitize_mime("/png"), "application/octet-stream");
        assert_eq!(sanitize_mime("not-a-mime"), "application/octet-stream");
        assert_eq!(
            sanitize_mime(&format!("image/{}", "x".repeat(65))),
            "application/octet-stream"
        );
    }

    #[test]
    fn temporary_upload_cleanup_removes_abandoned_file() {
        let path =
            std::env::temp_dir().join(format!("nostrfy-blossom-cleanup-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, b"abandoned").unwrap();
        {
            let _cleanup = TempUploadCleanup::new(path.clone());
        }
        assert!(!path.exists());
    }

    #[test]
    fn mime_extension_mapping() {
        assert_eq!(ext_of("image/png"), ".png");
        assert_eq!(ext_of("image/jpeg"), ".jpg");
        assert_eq!(ext_of("image/svg+xml"), ".svg");
        assert_eq!(ext_of("text/plain"), ".txt");
        assert_eq!(ext_of("video/mp4"), ".mp4");
        // BUD-02/BUD-10: unknown types still get the mandatory extension.
        assert_eq!(ext_of("application/octet-stream"), ".bin");
        assert_eq!(ext_of("unknown/type"), ".bin");
    }

    #[test]
    fn blossom_path_detection() {
        assert!(!is_blossom_path("/"));
        assert!(is_blossom_path("/upload"));
        assert!(is_blossom_path("/media"));
        assert!(is_blossom_path(&format!("/list/{}", "aa".repeat(32))));
        assert!(is_blossom_path(&format!("/{}.jpg", "a".repeat(64))));
        assert!(is_blossom_path(&format!("/{}", "a".repeat(64))));
        assert!(!is_blossom_path("/ws"));
        assert!(!is_blossom_path("/api/v1/npub1..."));
        assert!(!is_blossom_path(&format!("/{}", "a".repeat(63))));
        assert!(!is_blossom_path("/list/nothex"));
    }

    #[test]
    fn blob_segment_splits_extension() {
        assert_eq!(
            split_blob(&format!("{}.png", "a".repeat(64))),
            Some("a".repeat(64))
        );
        assert_eq!(split_blob(&"a".repeat(64)), Some("a".repeat(64)));
        assert_eq!(split_blob("short"), None);
        assert_eq!(split_blob(&format!("{}.png/x", "a".repeat(64))), None);
        assert_eq!(split_blob(&"A".repeat(64)), Some("a".repeat(64)));
    }

    #[tokio::test]
    async fn head_matches_get_for_ranges_and_missing_files() {
        let relay = build_blossom_relay(0).await;
        let state = state_of(&relay).await.expect("blossom state");
        let pk = "aa".repeat(32);
        let data: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let sha = sha256_hex(&data);
        state
            .store
            .put(&pk, &sha, &data, "application/octet-stream")
            .await
            .unwrap();

        // A single satisfiable Range yields 206 + Content-Range, like GET.
        let mut headers = HeaderMap::new();
        headers.insert(axum::http::header::RANGE, "bytes=100-199".parse().unwrap());
        let resp = head_blob(State(relay.clone()), headers, AxPath(sha.clone())).await;
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(resp.headers()[axum::http::header::CONTENT_LENGTH], "100");
        assert_eq!(
            resp.headers()[axum::http::header::CONTENT_RANGE],
            format!("bytes 100-199/{}", data.len())
        );
        // An unsatisfiable range is a 416 with `Content-Range: bytes */`.
        let mut headers = HeaderMap::new();
        headers.insert(axum::http::header::RANGE, "bytes=999999-".parse().unwrap());
        let resp = head_blob(State(relay.clone()), headers, AxPath(sha.clone())).await;
        assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(
            resp.headers()[axum::http::header::CONTENT_RANGE],
            format!("bytes */{}", data.len())
        );

        // The backing file disappears while the LMDB mapping remains:
        // HEAD must 404 exactly like GET (a mapping alone is not a blob).
        let local_path = relay.config.read().await.blossom.local_path.clone();
        let npub = crate::nips::nip19::bech32_encode("npub", &hex::decode(&pk).unwrap()).unwrap();
        std::fs::remove_file(local_path.join(npub).join(&sha)).unwrap();
        let resp = get_blob(State(relay.clone()), HeaderMap::new(), AxPath(sha.clone())).await;
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "GET 404s once the backing file is gone"
        );
        let resp = head_blob(State(relay.clone()), HeaderMap::new(), AxPath(sha)).await;
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "HEAD must agree with GET for a missing backing file"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn blob_responses_are_hardened_against_sniffing() {
        // BUD-01: user-uploaded bytes are served from the Blossom origin, so
        // responses never allow MIME sniffing, and active document types are
        // forced to download under a sandboxed policy.
        let relay = build_blossom_relay(0).await;
        let state = state_of(&relay).await.expect("blossom state");
        let pk = "aa".repeat(32);
        let png = b"not really a png";
        let png_sha = sha256_hex(png);
        state
            .store
            .put(&pk, &png_sha, png, "image/png")
            .await
            .unwrap();
        let html = b"<script>alert(1)</script>";
        let html_sha = sha256_hex(html);
        state
            .store
            .put(&pk, &html_sha, html, "text/html")
            .await
            .unwrap();

        let nosniff = axum::http::header::HeaderName::from_static("x-content-type-options");
        let csp = axum::http::header::HeaderName::from_static("content-security-policy");
        // Safe media: nosniff, but no forced download.
        let resp = get_blob(State(relay.clone()), HeaderMap::new(), AxPath(png_sha)).await;
        assert_eq!(resp.headers().get(&nosniff).unwrap(), "nosniff");
        assert!(
            resp.headers()
                .get(axum::http::header::CONTENT_DISPOSITION)
                .is_none()
        );
        // Active document: nosniff + attachment + sandboxed CSP.
        let resp = get_blob(
            State(relay.clone()),
            HeaderMap::new(),
            AxPath(html_sha.clone()),
        )
        .await;
        assert_eq!(resp.headers().get(&nosniff).unwrap(), "nosniff");
        assert_eq!(
            resp.headers()[axum::http::header::CONTENT_DISPOSITION],
            "attachment"
        );
        assert_eq!(
            resp.headers().get(&csp).unwrap(),
            "default-src 'none'; sandbox"
        );
        // HEAD carries the same hardening.
        let resp = head_blob(State(relay.clone()), HeaderMap::new(), AxPath(html_sha)).await;
        assert_eq!(resp.headers().get(&nosniff).unwrap(), "nosniff");
        assert_eq!(
            resp.headers()[axum::http::header::CONTENT_DISPOSITION],
            "attachment"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn open_stream_any_falls_back_past_a_broken_owner() {
        // A storage error for the first owner must not hide a retrievable
        // copy under a later owner (only a missing file used to fall back).
        let relay = build_blossom_relay(0).await;
        let state = state_of(&relay).await.expect("blossom state");
        let owner0 = "aa".repeat(32);
        let owner1 = "bb".repeat(32);
        let data = b"shared bytes";
        let sha = sha256_hex(data);
        state
            .store
            .put(&owner0, &sha, data, "text/plain")
            .await
            .unwrap();
        state
            .store
            .put(&owner1, &sha, data, "text/plain")
            .await
            .unwrap();
        let local_path = relay.config.read().await.blossom.local_path.clone();
        let dir_of = |pk: &str| {
            let npub =
                crate::nips::nip19::bech32_encode("npub", &hex::decode(pk).unwrap()).unwrap();
            local_path.join(npub)
        };
        // Break owner0's directory (a regular file cannot contain the blob).
        std::fs::remove_dir_all(dir_of(&owner0)).unwrap();
        std::fs::write(dir_of(&owner0), b"not a directory").unwrap();
        let (stream, owner) = state
            .store
            .open_stream_any(&sha, 0, data.len() as u64)
            .await
            .expect("a later working owner must not be masked by an earlier error")
            .expect("the later copy resolves");
        assert_eq!(owner, owner1);
        drop(stream);
        // When every owner fails, the storage error is reported.
        std::fs::remove_dir_all(dir_of(&owner1)).unwrap();
        std::fs::write(dir_of(&owner1), b"not a directory").unwrap();
        assert!(
            state.store.open_stream_any(&sha, 0, 4).await.is_err(),
            "an error is returned when no owner can be opened"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn list_caps_page_size() {
        // `?limit=` is capped at 1000 with a default of 100: a heavy
        // uploader cannot force a single unbounded JSON page.
        let relay = build_blossom_relay(0).await;
        let (headers, pk) = auth_headers(relay.secp(), "list");
        let state = state_of(&relay).await.expect("blossom state");
        for i in 0..5 {
            let sha = sha256_hex(format!("blob-{i}").as_bytes());
            state
                .store
                .put(&pk, &sha, format!("blob-{i}").as_bytes(), "text/plain")
                .await
                .unwrap();
        }
        let query = |limit: Option<&str>| {
            let mut map = std::collections::HashMap::new();
            if let Some(l) = limit {
                map.insert("limit".to_string(), l.to_string());
            }
            axum::extract::Query(map)
        };
        let resp = list(
            State(relay.clone()),
            headers.clone(),
            AxPath(pk.clone()),
            query(Some("9999999")),
        )
        .await;
        let body = axum::body::to_bytes(resp.into_body(), 256 * 1024)
            .await
            .unwrap();
        let items: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            items.as_array().unwrap().len() <= 1000,
            "huge limit must be capped"
        );
        let resp = list(State(relay.clone()), headers, AxPath(pk), query(None)).await;
        let body = axum::body::to_bytes(resp.into_body(), 256 * 1024)
            .await
            .unwrap();
        let items: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            items.as_array().unwrap().len() <= 100,
            "default page must be bounded"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn list_requires_owner_auth() {
        // BUD-11/BUD-12: a user's blob inventory is private; an anonymous
        // request or a token for a different pubkey must not list it.
        let relay = build_blossom_relay(0).await;
        let other = "aa".repeat(32);
        // No Authorization header: 401.
        let resp = list(
            State(relay.clone()),
            HeaderMap::new(),
            AxPath(other.clone()),
            axum::extract::Query(std::collections::HashMap::new()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        // A valid token for a *different* pubkey: 403.
        let (headers, pk) = auth_headers(relay.secp(), "list");
        assert_ne!(pk, other);
        let resp = list(
            State(relay.clone()),
            headers,
            AxPath(other),
            axum::extract::Query(std::collections::HashMap::new()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        // The owner's token works, including an uppercase spelling of the
        // same pubkey (hex is case-insensitive).
        let (headers, pk) = auth_headers(relay.secp(), "list");
        let resp = list(
            State(relay.clone()),
            headers,
            AxPath(pk.to_ascii_uppercase()),
            axum::extract::Query(std::collections::HashMap::new()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn banned_pubkey_cannot_use_blossom() {
        // NIP-86 `banpubkey` must deny authenticated Blossom actions too,
        // not only WebSocket publishing/reading.
        let relay = build_blossom_relay(0).await;
        let (headers, pk) = auth_headers(relay.secp(), "list");
        relay
            .access
            .write()
            .await
            .blocked_pubkeys
            .push((pk.clone(), "spam".into()));
        let resp = list(
            State(relay.clone()),
            headers,
            AxPath(pk),
            axum::extract::Query(std::collections::HashMap::new()),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "a banned pubkey's Blossom token must be refused"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn list_unknown_cursor_yields_empty_page() {
        // A well-formed but unknown cursor must not restart at page one
        // (a stale cursor would loop duplicates forever).
        let relay = build_blossom_relay(0).await;
        let (headers, pk) = auth_headers(relay.secp(), "list");
        let state = state_of(&relay).await.expect("blossom state");
        let sha = sha256_hex(b"one blob");
        state
            .store
            .put(&pk, &sha, b"one blob", "text/plain")
            .await
            .unwrap();
        let mut map = std::collections::HashMap::new();
        map.insert("cursor".to_string(), "cc".repeat(32));
        let resp = list(
            State(relay.clone()),
            headers,
            AxPath(pk),
            axum::extract::Query(map),
        )
        .await;
        let body = axum::body::to_bytes(resp.into_body(), 256 * 1024)
            .await
            .unwrap();
        let items: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            items.as_array().unwrap().len(),
            0,
            "an unknown cursor must yield an empty page"
        );
        relay.db.shutdown();
    }
}
