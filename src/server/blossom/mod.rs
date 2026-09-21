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
    /// In-flight upload count per uploader pubkey (see
    /// [`MAX_UPLOADS_PER_PUBKEY`]), so one identity cannot hold the whole
    /// global budget. A plain mutex: the critical section is two map
    /// operations and never crosses an await.
    pub uploads_inflight: std::sync::Mutex<std::collections::HashMap<String, usize>>,
}

/// The most upload permits one pubkey may hold at once. The global budget
/// allows four maximum-sized uploads; without a per-identity cap a single
/// host with several trickling connections could hold every permit for the
/// whole rate window and 429 all other uploaders.
const MAX_UPLOADS_PER_PUBKEY: usize = 2;

/// In-flight upload count per uploader pubkey. The slot releases on drop,
/// so every path (success, error, timeout, or a cancelled handler future)
/// returns it.
struct UploadSlot {
    state: Arc<BlossomState>,
    pubkey: String,
}

impl BlossomState {
    /// Claims an in-flight upload slot for `pubkey`; `None` when this
    /// identity already holds [`MAX_UPLOADS_PER_PUBKEY`] uploads. The
    /// caller answers 429 before taking a global permit or spooling a body.
    fn try_register_upload(self: &Arc<Self>, pubkey: &str) -> Option<UploadSlot> {
        let mut inflight = self
            .uploads_inflight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let count = inflight.entry(pubkey.to_string()).or_insert(0);
        if *count >= MAX_UPLOADS_PER_PUBKEY {
            return None;
        }
        *count += 1;
        Some(UploadSlot {
            state: Arc::clone(self),
            pubkey: pubkey.to_string(),
        })
    }
}

impl Drop for UploadSlot {
    fn drop(&mut self) {
        let mut inflight = self
            .state
            .uploads_inflight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(count) = inflight.get_mut(&self.pubkey) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                inflight.remove(&self.pubkey);
            }
        }
    }
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
    // NIP-01 hex fields are lowercase by convention. An uppercase-hex
    // pubkey would still verify (Hex parses either case), but the BlobStore
    // owner indexes are built from the lowercase pubkey — such a token
    // could upload and then never list or delete its own blobs. Rejecting
    // all three fields mirrors the WebSocket validation path
    // (src/relay/validate.rs), so "valid on the wire" has one definition.
    if event.pubkey != event.pubkey.to_ascii_lowercase()
        || event.id != event.id.to_ascii_lowercase()
        || event.sig != event.sig.to_ascii_lowercase()
    {
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

/// Decodes the Blossom auth event from the `Authorization: Nostr <token>`
/// header (BUD-11). Accepts both the spec's Base64url-without-padding and
/// the padded standard variant for leniency.
fn decode_auth_event(headers: &HeaderMap) -> Option<crate::event::Event> {
    let encoded = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(crate::nips::nip98::strip_nostr_scheme)?;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(encoded))
        .ok()?;
    serde_json::from_slice(&raw).ok()
}

/// Verifies the parts of a Blossom auth event that do not depend on the
/// request body (kind, signature, expiration, `t`/`server` tags and ban
/// status). Endpoints that must authenticate before reading the body use
/// this first and check the body-scoped `x` tag afterwards. Returns the
/// pubkey.
async fn verify_auth_meta(
    relay: &Relay,
    state: &BlossomState,
    event: &crate::event::Event,
    verb: &str,
) -> Option<String> {
    let pubkey = validate_auth_event(relay.secp(), event, &state.host, verb, None, unix_now())?;
    // The relay's access policy applies to authenticated Blossom actions
    // too, not only to WebSocket publishing: NIP-86 `banpubkey` (always)
    // and the `restrict_relay` allowlist (when enabled) must gate
    // upload/delete/list here as well. `AccessControl::allows_pubkey`
    // combines the deny list and the allow list, matching the WS path.
    // The operator keys (the relay's own key and `relay.pubkey`) are
    // exempt like on the WS path: the operator must not lock themselves
    // out of the Blossom endpoints with a restrictive allow list (config
    // and access lock order matches the WS accept path: config first).
    let allowed = {
        let cfg = relay.config.read().await;
        let access = relay.access.read().await;
        let is_operator = relay
            .relay_pubkey_ref()
            .is_some_and(|pk| pk.eq_ignore_ascii_case(&pubkey))
            || cfg.relay.pubkey.eq_ignore_ascii_case(&pubkey);
        is_operator || access.allows_pubkey(&pubkey)
    };
    if !allowed {
        return None;
    }
    Some(pubkey)
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
    let event = decode_auth_event(headers)?;
    let pubkey = verify_auth_meta(relay, state, &event, verb).await?;
    // BUD-11: when the endpoint implies a blob hash (upload/delete), at
    // least one `x` tag must match it.
    if let Some(sha) = expected_sha
        && !event_tags(&event, "x").any(|x| x == sha)
    {
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

/// Maps a BlobStore error to the HTTP response. A database lookup failure
/// is a retryable 503 (the blob may well exist — a 404/403 would lie),
/// anything else is a storage fault (500). The database-layer errors are
/// tagged with [`storage::DbUnavailable`] by the checked lookup paths.
fn store_error(e: anyhow::Error) -> Response {
    if e.downcast_ref::<storage::DbUnavailable>().is_some() {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "blob lookup unavailable, please retry",
        );
    }
    // Keep the backend detail (S3 XML, OS messages) in the log: the
    // response only carries a generic message.
    log::error!("blossom storage error: {e}");
    error(StatusCode::INTERNAL_SERVER_ERROR, "storage error")
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
    /// Fires when no chunk arrived within the deadline: the streaming S3
    /// client has no total timeout (to avoid truncating large blobs), so a
    /// stalled connection would otherwise pin the download permit forever.
    stall: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
}

/// How long a single S3 stream chunk may take before the download is
/// aborted.
const S3_STREAM_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

impl S3Chunks {
    fn new(resp: reqwest::Response, remaining: u64) -> S3Chunks {
        S3Chunks {
            stream: Box::pin(resp.bytes_stream()),
            remaining,
            stall: None,
        }
    }
}

impl futures_util::Stream for S3Chunks {
    type Item = Result<bytes::Bytes, std::io::Error>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        use std::future::Future;
        if self.remaining == 0 {
            return std::task::Poll::Ready(None);
        }
        let this = &mut *self;
        // The stall timer is (re)armed on every poll where the inner stream
        // is pending and cleared whenever a chunk arrives.
        match this.stall.as_mut() {
            Some(sleep) => {
                if sleep.as_mut().poll(cx).is_ready() {
                    return std::task::Poll::Ready(Some(Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "s3 stream stalled",
                    ))));
                }
            }
            None => {
                this.stall = Some(Box::pin(tokio::time::sleep(S3_STREAM_READ_TIMEOUT)));
            }
        }
        let chunk = std::task::ready!(this.stream.as_mut().poll_next(cx));
        match chunk {
            Some(Ok(bytes)) => {
                this.stall = None;
                let take = (bytes.len() as u64).min(this.remaining) as usize;
                this.remaining -= take as u64;
                if take == 0 {
                    return std::task::Poll::Ready(None);
                }
                std::task::Poll::Ready(Some(Ok(bytes.slice(..take))))
            }
            Some(Err(e)) => {
                this.stall = None;
                std::task::Poll::Ready(Some(Err(std::io::Error::other(e))))
            }
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
    let desc = match state.store.find(&sha).await {
        Ok(Some(desc)) => desc,
        Ok(None) => return error(StatusCode::NOT_FOUND, "blob not found"),
        Err(e) => return store_error(e),
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
            if ranged && honored {
                // A 206 must not be cached as if it were the full blob:
                // drop the immutable cache header and mark the Range
                // variance (the same URL can serve different bytes).
                response
                    .headers_mut()
                    .remove(axum::http::header::CACHE_CONTROL);
                response.headers_mut().insert(
                    axum::http::header::VARY,
                    axum::http::HeaderValue::from_static("Range"),
                );
            }
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
        Err(e) => store_error(e),
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
    let desc = match state.store.find(&sha).await {
        Ok(Some(desc)) => desc,
        Ok(None) => return error(StatusCode::NOT_FOUND, "blob not found"),
        Err(e) => return store_error(e),
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
        Err(e) => return store_error(e),
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
    // Authenticate before reading any body bytes: an unauthenticated client
    // must not be able to drive temp-disk writes and hashing (up to
    // `max_upload` per request) or pin an upload permit with a stalled
    // body. The body-scoped `x` tag is checked after hashing below.
    let Some(auth_event) = decode_auth_event(&headers) else {
        return error(StatusCode::UNAUTHORIZED, "invalid or missing authorization");
    };
    let Some(pubkey) = verify_auth_meta(&relay, &state, &auth_event, verb).await else {
        return error(StatusCode::UNAUTHORIZED, "invalid or missing authorization");
    };
    // Upload allowlist: when restrict_uploads is on, only the listed
    // pubkeys (npub1... or hex) may upload.
    if upload_allowed(&relay, &pubkey).await.is_err() {
        return error(
            StatusCode::FORBIDDEN,
            "uploads are restricted to the configured allowlist",
        );
    }
    // BUD-02/05: the optional `X-SHA-256` header declares the expected hash
    // of the request body — a malformed value is rejected before the body
    // is read; the match itself needs the hash computed below.
    let declared_sha = match headers.get("x-sha-256").and_then(|v| v.to_str().ok()) {
        Some(declared) => {
            let declared = declared.trim().to_ascii_lowercase();
            if declared.len() != 64 || hex::decode(&declared).is_err() {
                return error(StatusCode::BAD_REQUEST, "malformed X-SHA-256 header");
            }
            Some(declared)
        }
        None => None,
    };
    if state.store.check_space().is_err() {
        return error(StatusCode::INSUFFICIENT_STORAGE, "storage is full");
    }
    // Per-identity cap: the global budget allows four maximum-sized
    // uploads, so without this one host trickling several connections
    // could hold every permit for the whole rate window and 429 everyone
    // else. The slot covers the spool and the publish; it releases when
    // this function returns (including on cancellation).
    let Some(_upload_slot) = state.try_register_upload(&pubkey) else {
        return error(
            StatusCode::TOO_MANY_REQUESTS,
            "too many uploads in progress",
        );
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
    // A stalled body must not pin an upload permit forever: the spool
    // aborts when no chunk arrives within the HTTP read timeout (0 means
    // the header timeout is disabled, so a bounded default keeps
    // slow-loris protection for bodies).
    let idle_secs = relay.config.read().await.limits.http_read_timeout_secs;
    let idle_timeout = std::time::Duration::from_secs(if idle_secs == 0 { 60 } else { idle_secs });
    // Sound the declared size before reserving: a Content-Length above the
    // ceiling can be rejected now, exactly like the BUD-06 preflight does.
    let declared_len = headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared_len.is_some_and(|len| len > max_upload as u64) {
        return error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "the upload exceeds the configured size limit",
        );
    }
    // Reserve the size the spool will actually write BEFORE spooling: the
    // spool lives on the store's filesystem, and reserving only at
    // `put_file` (after the body was already written) let concurrent
    // uploads push the disk below `min_free_bytes` while the LMDB writer
    // could still map and commit into the exhausted filesystem. A declared
    // Content-Length reserves exactly that size (capped at the ceiling):
    // reserving the full ceiling refused small uploads with 507 whenever
    // free space was within `max_upload` of the floor, even though the
    // floor check passed. A chunked body (no Content-Length) keeps the
    // full-ceiling reservation, since its size is unknown until it ends:
    // near the floor a chunked upload is refused rather than allowed to
    // overshoot the reservation.
    let reserved = declared_len.map_or(max_upload as u64, |len| len.min(max_upload as u64));
    let _spool_space = match state.store.reserve_space(reserved) {
        Ok(guard) => guard,
        Err(_) => return error(StatusCode::INSUFFICIENT_STORAGE, "storage is full"),
    };
    // Spool on the blob filesystem when possible: the final store is then a
    // rename (no second full write). A missing/uncreatable directory falls
    // back to the system temp dir.
    let drain = relay.subscribe_drain();
    let spool_dir = state.store.spool_dir();
    let spool_dir = match spool_dir.as_deref() {
        Some(dir) => match tokio::fs::create_dir_all(dir).await {
            Ok(()) => Some(dir),
            Err(_) => None,
        },
        None => None,
    };
    let (path, size, sha) = match spool_upload(
        body,
        max_upload as u64,
        reserved,
        idle_timeout,
        spool_dir,
        Some(drain.clone()),
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let mut cleanup = TempUploadCleanup::new(path.clone(), Some(drain));
    if let Some(declared) = declared_sha
        && declared != sha
    {
        return error(
            StatusCode::CONFLICT,
            "the X-SHA-256 header does not match the request body",
        );
    }
    // BUD-11: upload/media tokens MUST carry an `x` tag matching the blob
    // hash (the token is scoped to exactly the bytes being uploaded).
    if !event_tags(&auth_event, "x").any(|x| x == sha.as_str()) {
        return error(StatusCode::UNAUTHORIZED, "invalid or missing authorization");
    }
    // Re-check after the spool: the pre-spool check narrows the window in
    // which the disk can fill while a body is streaming.
    if state.store.check_space().is_err() {
        return error(StatusCode::INSUFFICIENT_STORAGE, "storage is full");
    }
    let mime = sanitize_mime(
        headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/octet-stream"),
    );
    let result = state
        .store
        .put_file(&pubkey, &sha, &path, size, &mime, true)
        .await;
    match tokio::fs::remove_file(&path).await {
        Ok(()) => cleanup.disarm(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => cleanup.disarm(),
        Err(_) => {}
    }
    drop(permits);
    match result {
        Ok((desc, existed)) => {
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

        Err(e) => {
            // A blob already at the owner cap is a client-visible conflict,
            // not a storage fault (the database refused the same add).
            if e.downcast_ref::<storage::BlobOwnerLimit>().is_some() {
                return error(
                    StatusCode::CONFLICT,
                    "the blob already has the maximum number of owners",
                );
            }
            store_error(e)
        }
    }
}

/// Minimum sustained throughput an upload must maintain to keep its
/// permit. The per-chunk idle timeout alone lets a client trickle one byte
/// per window forever, and the upload budget allows four concurrent
/// uploads: four drip connections would then refuse every other upload
/// indefinitely. 64 KiB/s accommodates slow mobile links while bounding a
/// stalled upload to `max_upload / 64 KiB` seconds.
const MIN_UPLOAD_RATE_BYTES_PER_SEC: u64 = 64 * 1024;

/// Hard ceiling for one upload's total body time: the rate-derived budget
/// is capped so a very large `max_upload_bytes` cannot license an hours-long
/// permit hold.
const MAX_UPLOAD_TOTAL_SECS: u64 = 900;

/// Spools an upload to disk while hashing it. The request body is never
/// materialized in one `Bytes` allocation, and the size limit is enforced
/// while reading rather than after the extractor has buffered the body.
/// `reserved` is the disk space the caller reserved for this upload (the
/// declared Content-Length, or the ceiling for a chunked body): the spool
/// refuses to write past it, so the reservation always covers the spool.
/// `idle_timeout` bounds the wait for the next chunk and the rate-derived
/// total deadline bounds the whole body, so a stalled or trickled upload
/// (slow-loris) cannot pin an upload permit or a temp file forever.
async fn spool_upload(
    body: Body,
    max_upload: u64,
    reserved: u64,
    idle_timeout: std::time::Duration,
    spool_dir: Option<&std::path::Path>,
    drain: Option<tokio::sync::watch::Receiver<bool>>,
) -> Result<(std::path::PathBuf, u64, String), Box<Response>> {
    use futures_util::StreamExt;
    use sha2::{Digest, Sha256};
    use tokio::io::AsyncWriteExt;

    static TEMP_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let mut path = spool_dir
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(std::env::temp_dir);
    // The name carries the process PID, a per-process-start token and a
    // counter: the token keeps a restarted process (PID 1 again) from
    // colliding with a previous process's stale spool, and the sweep
    // (storage::sweep_stale_spools) uses it to tell live spools apart.
    path.push(storage::spool_file_name(
        TEMP_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
    ));
    let mut cleanup = TempUploadCleanup::new(path.clone(), drain);
    let mut file = match tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        // The spool may hold a blob that is never published (a rejected or
        // abandoned upload): keep it unreadable to other local users
        // instead of relying on the process umask.
        .mode(0o600)
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
    // Total body budget: the rate-derived time (at least one idle window,
    // so a tiny `max_upload` does not abort immediately), capped hard. The
    // per-chunk idle timeout is capped by the same ceiling: a large
    // `http_read_timeout_secs` must not override it, or one body could pin
    // an upload permit for hours.
    let rate_budget = std::time::Duration::from_secs(
        (max_upload / MIN_UPLOAD_RATE_BYTES_PER_SEC).clamp(1, MAX_UPLOAD_TOTAL_SECS),
    );
    let total_deadline = tokio::time::Instant::now()
        + rate_budget.max(idle_timeout.min(std::time::Duration::from_secs(MAX_UPLOAD_TOTAL_SECS)));
    loop {
        let now = tokio::time::Instant::now();
        if now >= total_deadline {
            return Err(Box::new(error(
                StatusCode::REQUEST_TIMEOUT,
                "upload too slow: the body did not finish in time",
            )));
        }
        let wait = idle_timeout.min(total_deadline - now);
        let chunk = match tokio::time::timeout(wait, stream.next()).await {
            // No chunk within the idle window (or the total deadline): the
            // client stalled. Abort so the upload permit and the temp file
            // are released.
            Err(_) => {
                return Err(Box::new(error(
                    StatusCode::REQUEST_TIMEOUT,
                    "upload stalled: no data received in time",
                )));
            }
            Ok(None) => break,
            Ok(Some(chunk)) => chunk,
        };
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
        if size > max_upload {
            return Err(Box::new(error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "upload exceeds the configured size limit",
            )));
        }
        if size > reserved {
            // The body overran the space the caller reserved for it (a
            // body larger than its declared Content-Length): abort instead
            // of writing past what the disk reservation covers.
            return Err(Box::new(error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "upload exceeds the declared size",
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
    /// The relay drain signal, when the upload ran under the relay: once
    /// shutdown is signaled the cleanup spawns nothing (and the startup
    /// sweep removes the spool instead). `None` in unit tests, where the
    /// file is always removed.
    drain: Option<tokio::sync::watch::Receiver<bool>>,
}

impl TempUploadCleanup {
    fn new(path: std::path::PathBuf, drain: Option<tokio::sync::watch::Receiver<bool>>) -> Self {
        Self {
            path: Some(path),
            drain,
        }
    }

    fn disarm(&mut self) {
        self.path = None;
    }
}

/// Bounds the detached spool-removal tasks: a burst of aborted uploads must
/// not spawn an unbounded number of tasks (each pins a runtime slot and a
/// potentially large unlink). When no permit is free the removal falls back
/// to the synchronous best-effort unlink, which is cheap and cannot pile up.
static SPOOL_REMOVAL_LIMITS: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> =
    std::sync::OnceLock::new();

fn spool_removal_limit() -> Arc<tokio::sync::Semaphore> {
    Arc::clone(SPOOL_REMOVAL_LIMITS.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(16))))
}

impl Drop for TempUploadCleanup {
    fn drop(&mut self) {
        let Some(path) = self.path.take() else {
            return;
        };
        let drain = self.drain.take();
        // Shutdown: leave the spool for the startup sweep instead of
        // spawning work that can outlive the runtime and race the
        // database stop.
        if drain.as_ref().is_some_and(|rx| *rx.borrow()) {
            log::info!(
                "Blossom upload cleanup: shutdown signaled; leaving {} for the startup sweep",
                path.display()
            );
            return;
        }
        // Removing a large spool can block the worker for a while: hand it
        // to the runtime when one is available (Drop runs on the handler
        // task) and a removal task permit is free, and fall back to a sync
        // removal otherwise. The permit bound keeps a storm of aborted
        // uploads from spawning one task per spool.
        if tokio::runtime::Handle::try_current().is_ok()
            && let Ok(permit) = spool_removal_limit().try_acquire_owned()
        {
            tokio::spawn(async move {
                let _permit = permit;
                remove_spool(path, drain).await;
            });
        } else if let Err(e) = std::fs::remove_file(&path)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            log::warn!(
                "cannot remove temporary Blossom upload {}: {e}",
                path.display()
            );
        }
    }
}

/// Removes an abandoned spool file. With a drain receiver, the removal
/// stops early when the relay shuts down: the spool stays for the next
/// startup's sweep, which can always remove it once this process start is
/// gone. A `None` receiver (unit tests) removes unconditionally.
async fn remove_spool(
    path: std::path::PathBuf,
    mut drain: Option<tokio::sync::watch::Receiver<bool>>,
) {
    let removed = match drain.as_mut() {
        Some(rx) => {
            tokio::select! {
                biased;
                _ = rx.changed() => {
                    log::info!(
                        "Blossom upload cleanup: shutdown signaled; leaving {} for the startup sweep",
                        path.display()
                    );
                    return;
                }
                removed = tokio::fs::remove_file(&path) => removed,
            }
        }
        None => tokio::fs::remove_file(&path).await,
    };
    if let Err(e) = removed
        && e.kind() != std::io::ErrorKind::NotFound
    {
        log::warn!(
            "cannot remove temporary Blossom upload {}: {e}",
            path.display()
        );
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
    // The preflight must reflect the PUT outcome: the PUT reserves the
    // declared Content-Length (capped at the ceiling) against the
    // free-space floor, so a reservation of the same size decides the
    // preflight. Testing the bare floor instead claimed 200 while the PUT
    // would have reserved `max_upload` and answered 507. The BUD-06
    // request always declares X-Content-Length, so there is no "unknown
    // size" preflight; a PUT without Content-Length reserves the full
    // ceiling, and the preflight's smaller-or-equal reservation never
    // promises more than that case. The guard releases on drop (this is a
    // read-only check).
    if state.store.reserve_space(len.min(max_upload)).is_err() {
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
    // BUD-12: the cursor is the previous page's last sha256. Its upload
    // time positions the scan in the uploaded-order index; an unknown (but
    // well-formed) cursor yields an empty page — never the first page — so
    // a stale cursor cannot loop over duplicates forever.
    let (after_uploaded, after_sha) = match cursor {
        Some(sha) => match state.store.find(sha).await {
            Ok(Some(desc)) => (Some(desc.uploaded.max(0) as u64), Some(sha.to_string())),
            Err(e) => return store_error(e),
            Ok(None) => {
                let empty: Vec<Value> = Vec::new();
                return (
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    serde_json::to_string(&empty).unwrap(),
                )
                    .into_response();
            }
        },
        None => (None, None),
    };
    // The page comes from the uploaded-order index (newest first), so every
    // blob of the owner is reachable — the old sha-ordered window hid
    // everything past its first 5000 entries. A database failure must be a
    // 503, not an empty page (the store's empty-page probe distinguishes
    // them).
    let blobs = match state
        .store
        .list_page(
            &pubkey,
            after_uploaded,
            after_sha.as_deref(),
            limit.unwrap_or(100),
        )
        .await
    {
        Ok(blobs) => blobs,
        Err(e) => return store_error(e),
    };
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
    match state.store.find(&sha).await {
        Ok(Some(_)) => {}
        Ok(None) => return error(StatusCode::NOT_FOUND, "blob not found"),
        Err(e) => return store_error(e),
    }
    // Only an uploader of these bytes may delete their own copy; other
    // uploaders of identical content keep theirs. A failed ownership check
    // must not answer 403: the requester may well be the uploader.
    match state.store.has(&pubkey, &sha).await {
        Ok(true) => {}
        Ok(false) => {
            return error(
                StatusCode::FORBIDDEN,
                "only the uploader may delete this blob",
            );
        }
        Err(e) => return store_error(e),
    }
    match state.store.delete(&pubkey, &sha).await {
        Ok(true) => StatusCode::OK.into_response(),
        Ok(false) => error(StatusCode::NOT_FOUND, "blob not found"),
        Err(e) => store_error(e),
    }
}

/// Builds the shared Blossom state from the config (or `None` when the
/// feature is disabled). Must be called before the router is built.
/// Builds the Blossom media state: `None` when no Blossom host is
/// configured (media serving stays off), `Some` when the backend
/// initialized. A configured host whose backend fails to initialize is an
/// `Err`: serving the relay without its configured media would mask the
/// outage as a healthy relay, so startup must refuse instead.
pub(crate) async fn build_state(
    cfg: &Config,
    relay: &Relay,
) -> anyhow::Result<Option<Arc<BlossomState>>> {
    if cfg.blossom.host.trim().is_empty() {
        return Ok(None);
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
        relay.db.clone(),
        relay.stats.clone(),
    )
    .await
    {
        Ok(store) => {
            // Remove spool files a crash (SIGKILL/power loss) left behind:
            // their Drop cleanup never ran and they would otherwise
            // accumulate until the disk is full. The sweep also logs (and
            // counts) what it removed; no object/mapping diff is attempted
            // (see `BlobStore::sweep_stale_spools`).
            store.sweep_stale_spools();
            let state = Arc::new(BlossomState {
                store,
                host: cfg.blossom.host.clone(),
                max_upload_bytes: cfg.blossom.max_upload_bytes,
                upload_budget: Arc::new(tokio::sync::Semaphore::new(
                    cfg.blossom.max_upload_bytes.saturating_mul(4).max(1),
                )),
                uploads_inflight: std::sync::Mutex::new(std::collections::HashMap::new()),
            });
            // One-time automatic migration of legacy blobs (storage files
            // that predate the LMDB mapping), in the background so the
            // relay starts instantly. The task observes the relay drain
            // signal: a shutdown stops the pass without writing the marker,
            // so the next start resumes it instead of scanning a stopped
            // database.
            let state_for_migration = Arc::clone(&state);
            let drain = relay.subscribe_drain();
            if *drain.borrow() {
                log::info!("Blossom legacy migration: skipped, the relay is shutting down");
            } else {
                tokio::spawn(async move {
                    match state_for_migration.store.auto_migrate_legacy(drain).await {
                        Ok(storage::MigrationOutcome::Completed(n)) if n > 0 => {
                            log::info!("Blossom legacy migration: mapped {n} existing blob(s)")
                        }
                        Ok(storage::MigrationOutcome::Completed(_)) => {}
                        Ok(storage::MigrationOutcome::Interrupted(n)) => {
                            log::info!(
                                "Blossom legacy migration: stopped after {n} blob(s) for \
                                 shutdown; the pass resumes on the next start"
                            )
                        }
                        Err(e) => log::warn!("Blossom legacy migration failed: {e}"),
                    }
                });
            }
            Ok(Some(state))
        }
        Err(e) => Err(anyhow::anyhow!("blossom storage failed to initialize: {e}")),
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

    #[tokio::test]
    async fn build_state_fails_closed_when_storage_init_fails() {
        // A configured Blossom host whose backend cannot initialize must
        // refuse startup (Err), not serve the relay without its media
        // (None would mask the outage as a healthy relay).
        let relay = build_blossom_relay(0).await;
        let mut cfg = relay.config.read().await.clone();
        cfg.blossom.storage = "bogus-backend".into();
        match build_state(&cfg, &relay).await {
            Err(e) => assert!(
                e.to_string()
                    .contains("blossom storage failed to initialize"),
                "{e}"
            ),
            Ok(_) => panic!("an unusable backend must fail closed"),
        }
        // Disabled Blossom stays off without an error.
        cfg.blossom.host.clear();
        assert!(
            build_state(&cfg, &relay).await.unwrap().is_none(),
            "no host means no media state, not a failure"
        );
    }

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
        // Small mappings: the test VM cannot afford several default-sized
        // (1 GB / 1 TiB) LMDB reservations at once.
        cfg.database.map_size = 16 * 1024 * 1024;
        cfg.database.max_map_size = 32 * 1024 * 1024;
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
        let state = build_state(&relay.config.read().await.clone(), &relay)
            .await
            .expect("test Blossom backend must initialize");
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
        auth_event_with_key(secp, &[9u8; 32], created, verb, expiration, x, server)
    }

    /// Like [`auth_event`], but signed with `seckey`: tests that need two
    /// distinct uploader identities.
    fn auth_event_with_key(
        secp: &Secp256k1<secp256k1::All>,
        seckey: &[u8; 32],
        created: u64,
        verb: &str,
        expiration: Option<u64>,
        x: Option<&str>,
        server: Option<&str>,
    ) -> Event {
        let keypair = Keypair::from_seckey_slice(secp, seckey).unwrap();
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
        auth_headers_scoped(secp, verb, None)
    }

    /// Like [`auth_headers`], but the token carries the body-scoped `x` tag
    /// required by upload/delete endpoints (BUD-11).
    fn auth_headers_scoped(
        secp: &Secp256k1<secp256k1::All>,
        verb: &str,
        sha: Option<&str>,
    ) -> (HeaderMap, String) {
        auth_headers_scoped_with_key(secp, &[9u8; 32], verb, sha)
    }

    /// Like [`auth_headers_scoped`], but signed with `seckey` (a second
    /// uploader identity for the per-pubkey upload-cap tests).
    fn auth_headers_scoped_with_key(
        secp: &Secp256k1<secp256k1::All>,
        seckey: &[u8; 32],
        verb: &str,
        sha: Option<&str>,
    ) -> (HeaderMap, String) {
        let now = unix_now();
        let ev = auth_event_with_key(secp, seckey, now, verb, Some(now + 600), sha, None);
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
            stall: None,
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

    #[tokio::test]
    async fn declared_size_reservation_keeps_small_uploads_possible() {
        // The regression: reserving the full `max_upload` ceiling before
        // spooling refused every upload while free space was within
        // `max_upload` of the floor, even when the actual body fit. Hold a
        // reservation that leaves only 4 MiB of headroom above the floor
        // (1 MiB `min_free` plus the held bytes): the small declared size
        // fits, the 20 MiB ceiling does not. Holding the reservation on the
        // same store makes the headroom exact instead of racing other tests
        // for the filesystem's free space.
        let relay = build_blossom_relay(1 << 20).await;
        let state = state_of(&relay).await.expect("blossom state");
        let headroom = 4 << 20;
        let free = state.store.free_space().expect("local store");
        let held = free.saturating_sub((1 << 20) + headroom);
        assert!(
            held > 0,
            "the test needs a filesystem with free space, got {free}"
        );
        let _held = state
            .store
            .reserve_space(held)
            .expect("holding the headroom must fit");

        let data = b"tiny blossom upload";
        let sha = sha256_hex(data);
        // The BUD-06 preflight with the same declared size says 200...
        let (mut headers, _) = auth_headers_scoped(relay.secp(), "upload", Some(&sha));
        headers.insert("x-sha-256", sha.parse().unwrap());
        headers.insert("x-content-length", data.len().to_string().parse().unwrap());
        let resp = head_preflight(relay.clone(), headers, "upload").await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a declared size within the headroom must preflight as OK"
        );
        // ...and the PUT reserves the declared size, not the ceiling.
        let (mut headers, _) = auth_headers_scoped(relay.secp(), "upload", Some(&sha));
        headers.insert(
            axum::http::header::CONTENT_LENGTH,
            data.len().to_string().parse().unwrap(),
        );
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "text/plain".parse().unwrap(),
        );
        let resp = upload(
            State(relay.clone()),
            headers,
            Body::from(bytes::Bytes::copy_from_slice(data)),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "the small upload fits the free space and must not 507"
        );

        // Both paths agree on a declared size that needs the full ceiling:
        // the headroom cannot cover it, so preflight and PUT both 507.
        let ceiling = state_of(&relay)
            .await
            .expect("blossom state")
            .max_upload_bytes as u64;
        let (mut headers, _) = auth_headers_scoped(relay.secp(), "upload", Some(&sha));
        headers.insert("x-sha-256", sha.parse().unwrap());
        headers.insert("x-content-length", ceiling.to_string().parse().unwrap());
        let resp = head_preflight(relay.clone(), headers, "upload").await;
        assert_eq!(resp.status(), StatusCode::INSUFFICIENT_STORAGE);
        let (mut headers, _) = auth_headers_scoped(relay.secp(), "upload", Some(&sha));
        headers.insert(
            axum::http::header::CONTENT_LENGTH,
            ceiling.to_string().parse().unwrap(),
        );
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "text/plain".parse().unwrap(),
        );
        let resp = upload(
            State(relay.clone()),
            headers,
            Body::from(bytes::Bytes::copy_from_slice(data)),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::INSUFFICIENT_STORAGE);

        // A chunked body (no Content-Length) reserves the full ceiling:
        // near the floor it is refused rather than allowed to overshoot the
        // reservation (BUD-06 has no no-length preflight; its declared size
        // can never promise more than this case).
        let (headers, _) = auth_headers_scoped(relay.secp(), "upload", Some(&sha));
        let resp = upload(
            State(relay.clone()),
            headers,
            Body::from(bytes::Bytes::copy_from_slice(data)),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::INSUFFICIENT_STORAGE);

        relay.db.shutdown();
    }

    #[tokio::test]
    async fn upload_past_the_owner_cap_is_a_conflict() {
        // The database refuses the 65th owner of a blob; that commit
        // failure used to surface as a 500. It is a client-visible
        // conflict: 409, not "storage error".
        let relay = build_blossom_relay(0).await;
        let data = b"shared bytes";
        let sha = sha256_hex(data);
        for i in 0..64u8 {
            let owner = format!("{:02x}", i).repeat(32);
            assert!(
                relay
                    .db
                    .blossom_add_owner(&sha, "text/plain", data.len() as u64, 1, &owner)
                    .await
            );
        }
        let (mut headers, _) = auth_headers_scoped(relay.secp(), "upload", Some(&sha));
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "text/plain".parse().unwrap(),
        );
        let resp = upload(
            State(relay.clone()),
            headers,
            Body::from(bytes::Bytes::from_static(data)),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::CONFLICT,
            "a full owner list must answer 409, not 500"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn relay_access_policy_applies_to_blossom() {
        // The relay's allowlist/deny policy gates authenticated Blossom
        // actions too: a `restrict_relay` allowlist that does not list the
        // token's author must refuse it (like a WS publish), and the
        // operator keys stay exempt.
        let relay = build_blossom_relay(0).await;
        let (headers, pk) = auth_headers(relay.secp(), "list");
        let empty = || axum::extract::Query(std::collections::HashMap::new());
        {
            let mut access = relay.access.write().await;
            access.restrict_relay = true;
            access.allowed_pubkeys.clear();
        }
        let resp = list(
            State(relay.clone()),
            headers.clone(),
            AxPath(pk.clone()),
            empty(),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "a pubkey outside the relay allowlist must not list Blossom blobs"
        );
        // Allowing the pubkey admits it.
        relay
            .access
            .write()
            .await
            .allowed_pubkeys
            .push((pk.clone(), String::new()));
        let resp = list(
            State(relay.clone()),
            headers.clone(),
            AxPath(pk.clone()),
            empty(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        // The operator (relay.pubkey) is exempt even with an empty list.
        relay.access.write().await.allowed_pubkeys.clear();
        relay.config.write().await.relay.pubkey = pk.clone();
        let resp = list(State(relay.clone()), headers, AxPath(pk), empty()).await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "the operator must not lock themselves out of Blossom"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn blob_lookups_answer_503_when_the_database_is_down() {
        // A failed read must be a retryable 503, never a 404 (GET/HEAD), a
        // 403 "only the uploader" (DELETE) or an empty 200 page (list): the
        // blob may well exist and the client must retry.
        let relay = build_blossom_relay(0).await;
        let data = b"real blob";
        let sha = sha256_hex(data);
        state_of(&relay)
            .await
            .expect("blossom state")
            .store
            .put(&"aa".repeat(32), &sha, data, "text/plain")
            .await
            .unwrap();
        // Stop the database: every checked lookup now fails.
        relay.db.shutdown();

        let resp = get_blob(State(relay.clone()), HeaderMap::new(), AxPath(sha.clone())).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let resp = head_blob(State(relay.clone()), HeaderMap::new(), AxPath(sha.clone())).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        let (headers, _) = auth_headers_scoped(relay.secp(), "delete", Some(&sha));
        let resp = delete_blob(State(relay.clone()), headers, AxPath(sha.clone())).await;
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a failed ownership check must not answer 403"
        );

        let (headers, pk) = auth_headers(relay.secp(), "list");
        let resp = list(
            State(relay.clone()),
            headers,
            AxPath(pk),
            axum::extract::Query(std::collections::HashMap::new()),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "an empty page on a failed read must not be a 200"
        );
    }

    #[tokio::test]
    async fn unauthenticated_upload_is_rejected_before_the_body() {
        let relay = build_blossom_relay(0).await;
        // A body that never yields data: an authentication check placed
        // after spooling would wait forever, so the handler must reject the
        // request before reading it.
        let body = Body::from_stream(futures_util::stream::pending::<
            Result<bytes::Bytes, std::io::Error>,
        >());
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "text/plain".parse().unwrap(),
        );
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            upload(State(relay.clone()), headers, body),
        )
        .await
        .expect("an unauthenticated upload must not wait for the body");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn stalled_upload_body_times_out_and_releases_the_permit() {
        use futures_util::StreamExt as _;
        let relay = build_blossom_relay(1).await;
        // A 1-second read timeout keeps the test fast.
        relay.config.write().await.limits.http_read_timeout_secs = 1;
        let data = b"hello";
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
        // The body yields one chunk, then stalls: the handler must abort
        // instead of pinning the upload permit and temp file forever.
        let stream = futures_util::stream::once(async {
            Ok::<_, std::io::Error>(bytes::Bytes::from_static(data))
        })
        .chain(futures_util::stream::pending());
        let resp = upload(State(relay.clone()), headers, Body::from_stream(stream)).await;
        assert_eq!(
            resp.status(),
            StatusCode::REQUEST_TIMEOUT,
            "a stalled upload must be aborted"
        );
        let state = relay.blossom.read().await.clone().unwrap();
        assert_eq!(
            state.upload_budget.available_permits(),
            state.max_upload_bytes.saturating_mul(4).max(1),
            "the aborted upload must release its permit"
        );
        assert!(
            state.uploads_inflight.lock().unwrap().is_empty(),
            "the aborted upload must release its identity slot"
        );
        assert_eq!(
            state.store.reserved_bytes(),
            0,
            "the aborted upload must release its spool reservation"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn upload_reservation_returns_to_zero_on_every_path() {
        use futures_util::StreamExt as _;
        // Every exit path releases the spool reservation: a leaked guard
        // would eventually refuse uploads with 507 while the disk is empty.
        let relay = build_blossom_relay(1).await;
        relay.config.write().await.limits.http_read_timeout_secs = 1;
        let state = state_of(&relay).await.expect("blossom state");
        let data = b"reserved blob";
        let sha = sha256_hex(data);

        // Success: a declared size that matches the body.
        let (mut headers, _) = auth_headers_scoped(relay.secp(), "upload", Some(&sha));
        headers.insert(
            axum::http::header::CONTENT_LENGTH,
            data.len().to_string().parse().unwrap(),
        );
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "text/plain".parse().unwrap(),
        );
        let resp = upload(
            State(relay.clone()),
            headers,
            Body::from(bytes::Bytes::from_static(data)),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(
            state.store.reserved_bytes(),
            0,
            "a successful upload must release its spool reservation"
        );

        // Size error: the body overruns its declared Content-Length (413).
        let (mut headers, _) = auth_headers_scoped(relay.secp(), "upload", Some(&sha));
        headers.insert(axum::http::header::CONTENT_LENGTH, "1".parse().unwrap());
        let resp = upload(
            State(relay.clone()),
            headers,
            Body::from(bytes::Bytes::from_static(data)),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            state.store.reserved_bytes(),
            0,
            "a rejected upload must release its spool reservation"
        );

        // Timeout: one chunk, then a stalled stream (408).
        let (headers, _) = auth_headers_scoped(relay.secp(), "upload", Some(&sha));
        let stream = futures_util::stream::once(async {
            Ok::<_, std::io::Error>(bytes::Bytes::from_static(data))
        })
        .chain(futures_util::stream::pending());
        let resp = upload(State(relay.clone()), headers, Body::from_stream(stream)).await;
        assert_eq!(resp.status(), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(
            state.store.reserved_bytes(),
            0,
            "a timed-out upload must release its spool reservation"
        );
        assert!(
            state.uploads_inflight.lock().unwrap().is_empty(),
            "every path must release its identity slot"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn one_pubkey_cannot_hold_every_upload_permit() {
        let relay = build_blossom_relay(0).await;
        // Long enough that the stalled uploads stay pending while the
        // second identity uploads.
        relay.config.write().await.limits.http_read_timeout_secs = 30;
        let state = state_of(&relay).await.expect("blossom state");
        let data = b"another uploader's blob";
        let sha = sha256_hex(data);
        let (headers_a, pk_a) = auth_headers_scoped(relay.secp(), "upload", Some(&sha));
        let pending = || {
            Body::from_stream(futures_util::stream::pending::<
                Result<bytes::Bytes, std::io::Error>,
            >())
        };
        // Pubkey A fills its per-identity share with stalled uploads.
        let mut stalled = Vec::new();
        for _ in 0..MAX_UPLOADS_PER_PUBKEY {
            stalled.push(tokio::spawn(upload(
                State(relay.clone()),
                headers_a.clone(),
                pending(),
            )));
        }
        let mut a_slots = 0;
        for _ in 0..200 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            a_slots = state
                .uploads_inflight
                .lock()
                .unwrap()
                .get(&pk_a)
                .copied()
                .unwrap_or(0);
            if a_slots >= MAX_UPLOADS_PER_PUBKEY {
                break;
            }
        }
        assert_eq!(
            a_slots, MAX_UPLOADS_PER_PUBKEY,
            "the stalled uploads must register their identity slots"
        );
        // A third upload by A is refused before it can take a permit.
        let before = state.upload_budget.available_permits();
        let resp = upload(State(relay.clone()), headers_a, pending()).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            state.upload_budget.available_permits(),
            before,
            "a refused upload must not take a global permit"
        );
        // Another identity still uploads: A cannot hold the whole budget.
        let (headers_b, _) =
            auth_headers_scoped_with_key(relay.secp(), &[7u8; 32], "upload", Some(&sha));
        let resp = upload(
            State(relay.clone()),
            headers_b,
            Body::from(bytes::Bytes::from_static(data)),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "another uploader must succeed while one identity is saturated"
        );
        // Cancelling the stalled uploads returns every slot and permit.
        for handle in &stalled {
            handle.abort();
        }
        for handle in stalled {
            let _ = handle.await;
        }
        assert!(
            state.uploads_inflight.lock().unwrap().is_empty(),
            "cancelled uploads must release their identity slots"
        );
        assert_eq!(
            state.upload_budget.available_permits(),
            state.max_upload_bytes.saturating_mul(4).max(1),
            "cancelled uploads must release their permits"
        );
        relay.db.shutdown();
    }

    /// A cancelled (or shutdown-torn-down) upload must release all three
    /// resources it holds: the per-pubkey slot, the global permit and the
    /// disk reservation. The reservation is the easy one to leak — it lives
    /// in the storage guard, not the handler's own state.
    #[tokio::test]
    async fn cancelled_upload_releases_slot_permit_and_reservation() {
        // A nonzero floor makes the reservation counter track (0 disables
        // the disk-full guard, and then nothing is reserved at all).
        let relay = build_blossom_relay(1).await;
        relay.config.write().await.limits.http_read_timeout_secs = 30;
        let state = state_of(&relay).await.expect("blossom state");
        let data = b"cancelled blob";
        let sha = sha256_hex(data);
        let (headers, pk) = auth_headers_scoped(relay.secp(), "upload", Some(&sha));
        let handle = tokio::spawn(upload(
            State(relay.clone()),
            headers,
            Body::from_stream(futures_util::stream::pending::<
                Result<bytes::Bytes, std::io::Error>,
            >()),
        ));
        // Wait until the handler holds its slot, permit and reservation.
        let permits_full = state.max_upload_bytes.saturating_mul(4).max(1);
        for _ in 0..200 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            let registered = state
                .uploads_inflight
                .lock()
                .unwrap()
                .get(&pk)
                .copied()
                .unwrap_or(0);
            if registered == 1
                && state.store.reserved_bytes() > 0
                && state.upload_budget.available_permits() < permits_full
            {
                break;
            }
        }
        assert_eq!(
            state.uploads_inflight.lock().unwrap().get(&pk).copied(),
            Some(1),
            "the stalled upload must register its identity slot"
        );
        assert!(
            state.store.reserved_bytes() > 0,
            "the stalled upload must hold its spool reservation"
        );
        assert!(
            state.upload_budget.available_permits() < permits_full,
            "the stalled upload must hold its global permit"
        );
        // The server tears the handler future down on shutdown (drain, then
        // the connection task drops); cancellation must return everything.
        relay.signal_drain();
        handle.abort();
        let _ = handle.await;
        assert!(
            state.uploads_inflight.lock().unwrap().is_empty(),
            "a cancelled upload must release its identity slot"
        );
        assert_eq!(
            state.upload_budget.available_permits(),
            permits_full,
            "a cancelled upload must release its global permit"
        );
        assert_eq!(
            state.store.reserved_bytes(),
            0,
            "a cancelled upload must release its disk reservation"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn trickled_upload_body_is_bounded_by_the_total_deadline() {
        // One byte per idle window passes the per-chunk check, but the
        // rate-derived total deadline (64 KiB => 1 second here) must abort
        // it: otherwise four drip connections pin every upload permit
        // forever.
        let stream = futures_util::stream::unfold(0u32, |i| async move {
            if i >= 40 {
                return None;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            Some((
                Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"x")),
                i + 1,
            ))
        });
        let started = std::time::Instant::now();
        let result = spool_upload(
            Body::from_stream(stream),
            64 * 1024,
            64 * 1024,
            std::time::Duration::from_secs(1),
            None,
            None,
        )
        .await;
        let response = result.expect_err("a trickled body must be aborted");
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "the total deadline must stop the upload"
        );
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
    fn uppercase_hex_auth_fields_are_rejected() {
        // The owner indexes are lowercase: an uppercase-hex token verifies
        // cryptographically but could never list or delete the uploads it
        // authored, so pubkey/id/sig must all be lowercase (mirroring
        // src/relay/validate.rs).
        let secp = Secp256k1::new();
        let now = unix_now();
        let sha = "a".repeat(64);
        let host = "media.example.com";
        let mut ev = auth_event(
            &secp,
            now,
            "upload",
            Some(now + 300),
            Some(&sha),
            Some(host),
        );
        // Uppercase all three fields consistently and re-sign, so the
        // token is valid apart from its case: it must still be rejected.
        ev.pubkey = ev.pubkey.to_ascii_uppercase();
        ev.id = crate::nips::nip01::compute_id(&ev);
        let id = ev.id_bytes().unwrap();
        let keypair = Keypair::from_seckey_slice(&secp, &[9u8; 32]).unwrap();
        ev.sig = secp
            .sign_schnorr_no_aux_rand(&id, &keypair)
            .to_string()
            .to_ascii_uppercase();
        assert!(
            crate::nips::nip01::verify(&ev, &secp).is_ok(),
            "the uppercase token must be cryptographically valid, or the test proves nothing"
        );
        assert_eq!(
            validate_auth_event(&secp, &ev, host, "upload", Some(&sha), now),
            None,
            "uppercase-hex pubkey/id/sig must be rejected"
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
            let _cleanup = TempUploadCleanup::new(path.clone(), None);
        }
        assert!(!path.exists());
    }

    /// A drained relay must not spawn a detached cleanup: the spool stays
    /// for the next startup's sweep, which removes it once this process
    /// start is gone. A live signal removes it as before.
    #[tokio::test]
    async fn drained_upload_cleanup_leaves_the_spool_for_the_startup_sweep() {
        let path = std::env::temp_dir().join(format!(
            "nostrfy-blossom-drain-cleanup-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, b"abandoned").unwrap();
        {
            let (_tx, drain) = tokio::sync::watch::channel(true);
            let _cleanup = TempUploadCleanup::new(path.clone(), Some(drain));
        }
        assert!(
            path.exists(),
            "a drained cleanup must leave the spool for the sweep"
        );
        // The sender stays alive while the spawned removal runs: dropping
        // it would (correctly) read as the relay shutting down.
        let (_tx, drain) = tokio::sync::watch::channel(false);
        {
            let _cleanup = TempUploadCleanup::new(path.clone(), Some(drain));
        }
        let mut removed = false;
        for _ in 0..100 {
            if !path.exists() {
                removed = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(removed, "a live cleanup must remove the spool");
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
    async fn delete_after_a_mapping_failure_reports_the_completed_delete() {
        // A crash between the file removal and a mapping failure leaves
        // the mapping behind with no file: the retry must report the
        // completed delete (200), not 404, and only a repeat delete with
        // nothing left anywhere reports "not found".
        let relay = build_blossom_relay(0).await;
        let state = state_of(&relay).await.expect("blossom state");
        let pk = "cc".repeat(32);
        let data = b"delete me";
        let sha = sha256_hex(data);
        state
            .store
            .put(&pk, &sha, data, "text/plain")
            .await
            .unwrap();
        // Simulate the crash window: remove the object file directly so
        // only the mapping remains.
        let local_path = relay.config.read().await.blossom.local_path.clone();
        let npub = crate::nips::nip19::bech32_encode("npub", &hex::decode(&pk).unwrap()).unwrap();
        std::fs::remove_file(local_path.join(npub).join(&sha)).unwrap();
        assert!(
            state.store.delete(&pk, &sha).await.unwrap(),
            "a mapping that still lists the owner completes the delete"
        );
        assert!(
            !state.store.delete(&pk, &sha).await.unwrap(),
            "with neither file nor mapping left there is nothing to delete"
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
        let mut shas = Vec::new();
        for i in 0..5 {
            let sha = sha256_hex(format!("blob-{i}").as_bytes());
            state
                .store
                .put(&pk, &sha, format!("blob-{i}").as_bytes(), "text/plain")
                .await
                .unwrap();
            shas.push(sha);
        }
        let query = |limit: Option<&str>, cursor: Option<&str>| {
            let mut map = std::collections::HashMap::new();
            if let Some(l) = limit {
                map.insert("limit".to_string(), l.to_string());
            }
            if let Some(c) = cursor {
                map.insert("cursor".to_string(), c.to_string());
            }
            axum::extract::Query(map)
        };
        let page = |resp: axum::response::Response| async move {
            let body = axum::body::to_bytes(resp.into_body(), 256 * 1024)
                .await
                .unwrap();
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()
        };
        let resp = list(
            State(relay.clone()),
            headers.clone(),
            AxPath(pk.clone()),
            query(Some("9999999"), None),
        )
        .await;
        let items = page(resp).await;
        let page_shas: Vec<String> = items
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["sha256"].as_str().unwrap().to_string())
            .collect();
        assert!(page_shas.len() <= 1000, "huge limit must be capped");
        assert_eq!(
            page_shas.len(),
            shas.len(),
            "every uploaded blob must be listed (uploaded-order index)"
        );
        for sha in &shas {
            assert!(page_shas.contains(sha), "missing blob {sha}");
        }
        // Cursor paging: each page must make progress and never repeat a
        // blob. Before the key-format fix the cursor landed inside the same
        // key, so page 2 re-served page 1 (or the pages were empty).
        let first = list(
            State(relay.clone()),
            headers.clone(),
            AxPath(pk.clone()),
            query(Some("2"), None),
        )
        .await;
        let first = page(first).await;
        let first = first.as_array().unwrap();
        assert_eq!(first.len(), 2, "limit 2 must return two blobs");
        let cursor = first.last().unwrap()["sha256"].as_str().unwrap();
        let second = list(
            State(relay.clone()),
            headers.clone(),
            AxPath(pk.clone()),
            query(Some("2"), Some(cursor)),
        )
        .await;
        let second = page(second).await;
        let second = second.as_array().unwrap();
        assert_eq!(second.len(), 2, "the cursor must advance to the next page");
        for item in second {
            let sha = item["sha256"].as_str().unwrap();
            assert!(
                !first.iter().any(|f| f["sha256"] == sha),
                "a paged blob must not repeat on the next page"
            );
        }
        let resp = list(State(relay.clone()), headers, AxPath(pk), query(None, None)).await;
        let items = page(resp).await;
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
