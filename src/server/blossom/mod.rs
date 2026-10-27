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
use axum::http::{Extensions, HeaderMap, StatusCode, Version, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use base64::Engine;
use serde_json::{Value, json};
use tower_http::compression::CompressionLayer;
use tower_http::compression::predicate::Predicate;

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
    /// The relay's own HTTP host. Buzz uploads to the relay origin and
    /// signs its BUD-11 `server` tag with that host, not the dedicated media
    /// host, so both are accepted.
    pub relay_host: String,
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
    /// Bytes reserved by in-flight uploads per uploader pubkey. The count
    /// cap alone still let two identities hold all four maximum-sized
    /// permits; capping each identity at one ceiling leaves half the global
    /// budget available to everyone else while still allowing one maximum
    /// upload per identity (or several smaller concurrent ones).
    pub uploads_reserved: std::sync::Mutex<std::collections::HashMap<String, u64>>,
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
    /// Bytes actually reserved so far (not the declared/ceiling size): a
    /// client that sends no body holds no byte permit.
    reserved: u64,
    pubkey: String,
    /// Global byte permits acquired chunk by chunk. Dropping the slot
    /// returns all of them; a stalled upload therefore cannot occupy the
    /// shared budget before it has sent the bytes.
    permits: Vec<tokio::sync::OwnedSemaphorePermit>,
}

impl BlossomState {
    /// Claims an in-flight upload slot for `pubkey`; `None` when this
    /// identity already holds [`MAX_UPLOADS_PER_PUBKEY`] uploads. The
    /// caller answers 429 before spooling a body. Byte permits are NOT
    /// taken here: the declared Content-Length is untrusted and a chunked
    /// body has none, so reserving a ceiling up front let a few identities
    /// hold the whole global budget without sending a byte (M09).
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
            reserved: 0,
            pubkey: pubkey.to_string(),
            permits: Vec::new(),
        })
    }
}

impl UploadSlot {
    /// Reserves `bytes` against both this identity's ceiling and the
    /// global upload budget, acquiring the global permits incrementally.
    /// Returns `false` (and leaves the slot unchanged) when either limit
    /// would be exceeded; the caller aborts the upload with 429.
    fn try_reserve(&mut self, bytes: u64) -> bool {
        if bytes == 0 {
            return true;
        }
        let limit = self.state.max_upload_bytes as u64;
        // Check under the lock, release it while acquiring the global
        // semaphore, then re-check before committing: two uploads of the
        // same identity must not race past the per-identity ceiling.
        {
            let reserved = self
                .state
                .uploads_reserved
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let held = reserved.get(&self.pubkey).copied().unwrap_or(0);
            if held.saturating_add(bytes) > limit {
                return false;
            }
        }
        let mut acquired = Vec::new();
        let mut remaining = bytes;
        while remaining > 0 {
            let chunk = remaining.min(u32::MAX as u64) as u32;
            match self
                .state
                .upload_budget
                .clone()
                .try_acquire_many_owned(chunk)
            {
                Ok(permit) => acquired.push(permit),
                Err(_) => return false,
            }
            remaining -= chunk as u64;
        }
        let mut reserved = self
            .state
            .uploads_reserved
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let held = reserved.entry(self.pubkey.clone()).or_insert(0);
        if held.saturating_add(bytes) > limit {
            // Another upload of this identity won the race; `acquired`
            // drops here and returns its global permits.
            return false;
        }
        *held = held.saturating_add(bytes);
        self.reserved = self.reserved.saturating_add(bytes);
        self.permits.append(&mut acquired);
        true
    }
}

impl Drop for UploadSlot {
    fn drop(&mut self) {
        let mut inflight = self
            .state
            .uploads_inflight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut reserved = self
            .state
            .uploads_reserved
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(held) = reserved.get_mut(&self.pubkey) {
            *held = held.saturating_sub(self.reserved);
            if *held == 0 {
                reserved.remove(&self.pubkey);
            }
        }
        if let Some(count) = inflight.get_mut(&self.pubkey) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                inflight.remove(&self.pubkey);
            }
        }
        // `self.permits` drops after this body and returns the global
        // semaphore permits exactly once.
    }
}

/// Smallest blob worth compressing: below this the Brotli framing overhead
/// can exceed the saving, and tiny JSON/error responses are already cheap.
const BROTLI_MIN_BYTES: u64 = 1024;

/// Marks a response that must not be compressed even when the client accepts
/// Brotli (the HEAD response: it has no body and must keep the real
/// `Content-Length`, which the compression layer removes).
#[derive(Clone, Copy)]
struct SkipCompression;

/// The Blossom compression policy. Only a full `200` blob is eligible: range
/// responses carry `Content-Range` and are skipped by the layer, HEAD is
/// marked with [`SkipCompression`], and images/text are the types that can
/// benefit. The upper bound keeps a large (already-compressed) photo from
/// spending CPU per request; set `blossom.brotli_max_bytes` to widen it.
fn compression_layer(max_bytes: usize) -> CompressionLayer<impl Predicate> {
    let max_bytes = u64::try_from(max_bytes).unwrap_or(u64::MAX);
    CompressionLayer::new()
        .br(true)
        .no_gzip()
        .no_deflate()
        .compress_when(
            move |status: StatusCode,
                  _version: Version,
                  headers: &HeaderMap,
                  extensions: &Extensions| {
                if status != StatusCode::OK
                    || extensions.get::<SkipCompression>().is_some()
                    || headers.contains_key(header::CONTENT_RANGE)
                    || headers.contains_key(header::CONTENT_ENCODING)
                {
                    return false;
                }
                let Some(len) = headers
                    .get(header::CONTENT_LENGTH)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<u64>().ok())
                else {
                    return false;
                };
                if !(BROTLI_MIN_BYTES..=max_bytes).contains(&len) {
                    return false;
                }
                let Some(content_type) = headers
                    .get(header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                else {
                    return false;
                };
                let content_type = content_type
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_ascii_lowercase();
                content_type.starts_with("image/")
                    || content_type.starts_with("text/")
                    || matches!(
                        content_type.as_str(),
                        "application/json"
                            | "application/xml"
                            | "application/xhtml+xml"
                            | "application/javascript"
                            | "application/x-javascript"
                    )
            },
        )
}

/// The routes, mounted by `build_router` only when `blossom.host` is set.
pub(crate) async fn routes(relay: &Arc<Relay>, max_upload: usize) -> axum::Router<Arc<Relay>> {
    let (brotli, brotli_max_bytes) = {
        let cfg = relay.config.read().await;
        (cfg.blossom.brotli, cfg.blossom.brotli_max_bytes)
    };
    // The root `/` route belongs to the relay: the WS handler answers it
    // with the Blossom server info when the Host names the Blossom host.
    let router = axum::Router::new()
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
        // Buzz's URLs are `/media/{sha256}.{ext}`; keep the standard
        // `/{sha256}` route for BUD-01 clients and accept both spellings.
        // Only PUT: a HEAD route here would overlap the dynamic
        // `/media/{blob}` HEAD route below (Axum rejects the ambiguity).
        // Buzz uploads with PUT and does not pre-flight this alias.
        .route(
            "/media/upload",
            put(upload).layer(DefaultBodyLimit::max(max_upload)),
        )
        .route("/media/{blob}", get(get_blob).head(head_blob))
        .route("/list/{pubkey}", get(list))
        .route("/{blob}", get(get_blob).head(head_blob).delete(delete_blob))
        .with_state(relay.clone());
    if brotli {
        router.layer(compression_layer(brotli_max_bytes))
    } else {
        router
    }
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
    if path == "/upload"
        || path == "/media"
        || path == "/media/upload"
        || path.starts_with("/media/")
    {
        return true;
    }
    if let Some(rest) = path.strip_prefix("/list/") {
        return is_pubkey(rest);
    }
    // Any other single-segment path is the blob route (`/<blob>` or
    // `/<blob>.<ext>`). The handler validates the hash and answers 400 for
    // a malformed one (BUD-01); checking 64-hex here first turned that 400
    // into the host split's 404. Known single-segment relay endpoints stay
    // on the relay.
    let Some(segment) = path.strip_prefix('/') else {
        return false;
    };
    if segment.is_empty() || segment.contains('/') {
        return false;
    }
    !matches!(
        segment,
        "health"
            | "metrics"
            | "inbox"
            | "outbox"
            | "ws"
            | "list"
            | "info"
            | "query"
            | "count"
            | "events"
    )
}

/// The two media paths Buzz uses on the relay's own origin. They are also
/// ordinary Blossom paths on the media host; the host split lets them through
/// on the relay host so the desktop's `/media/upload` and `/media/{sha}.{ext}`
/// work without a second media hostname.
pub(crate) fn is_relay_media_alias(path: &str, method: &axum::http::Method) -> bool {
    if path == "/media/upload" {
        return matches!(*method, axum::http::Method::PUT | axum::http::Method::HEAD);
    }
    let Some(blob) = path.strip_prefix("/media/") else {
        return false;
    };
    !blob.is_empty()
        && !blob.contains('/')
        && matches!(*method, axum::http::Method::GET | axum::http::Method::HEAD)
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
    // Case-insensitive like the relay pubkey lists: entries arrive from
    // operators who may type uppercase hex, while wire pubkeys are
    // lowercase — an exact compare would deny a legitimately listed
    // uploader over letter case (fail-closed, but a paper cut).
    let allowed = relay
        .blossom_allow
        .read()
        .await
        .iter()
        .any(|entry| entry.eq_ignore_ascii_case(pubkey));
    if allowed {
        Ok(())
    } else {
        Err(anyhow!(
            "uploads are restricted to the configured allowlist"
        ))
    }
}

/// The host a BUD-11 `server` tag names, when the value is a bare domain
/// name. BUD-11 requires the value to be a lowercase domain name
/// (`cdn.example.com`), not a URL.
///
/// Anything else names a different identity and must not match: a scheme,
/// userinfo (`@`), a port, a path/query/fragment or IPv6 brackets. Stripping
/// a prefix was a real bypass: `media.example.com:443@evil.example` has
/// `media.example.com:443` as its userinfo and `evil.example` as its host,
/// so the old parser accepted a token scoped to another server here. Case
/// is folded: the signed value keeps what the client wrote, and hostname
/// comparison is case-insensitive.
fn auth_server_host(server: &str) -> Option<String> {
    let host = server.trim();
    if host.is_empty()
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return None;
    }
    // A trailing dot is the DNS absolute-name spelling of the same host;
    // normalize it on both sides so `blossom.host = "media.example.com."`
    // and a token scoped to `media.example.com` agree (BLM-03).
    let host = host.trim_end_matches('.');
    if host.is_empty() {
        return None;
    }
    Some(host.to_ascii_lowercase())
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
    event: &crate::event::Event,
    host: &str,
    relay_host: &str,
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
    if crate::nips::nip01::verify(event).is_err() {
        return None;
    }
    // BUD-11: `created_at` must not lie in the future — with a small
    // clock-skew leeway mirroring the NIP-98 auth window. A token's
    // validity is bounded by `expiration` (checked below), so accepting a
    // `created_at` seconds ahead only keeps skewed clients working, never
    // extends a token's life; without the leeway every request from a
    // clock-ahead client fails with 401.
    if event.created_at > now.saturating_add(60) {
        return None;
    }
    if !event_tags(event, "t").any(|t| t == verb) {
        return None;
    }
    // BUD-11: the `expiration` tag is mandatory and must be a unix
    // timestamp in the future — a missing or unparseable value is rejected
    // too, so an intercepted token cannot outlive its scope. Every tag
    // must parse and the earliest one bounds the token: honoring only the
    // first would let a later, looser tag extend an intercepted token's
    // life past an earlier, stricter one.
    let mut exp: Option<u64> = None;
    for raw in event_tags(event, "expiration") {
        let parsed: u64 = raw.parse().ok()?;
        exp = Some(exp.map_or(parsed, |best: u64| best.min(parsed)));
    }
    if exp.is_none_or(|e| e <= now) {
        return None;
    }
    // The `server` tags (when present) must name our host. BUD-11: a token
    // may carry multiple `server` tags ("the token is valid for all
    // servers" listed), and the relay must accept it when its domain
    // appears in at least one. Each value must be a bare domain name, so
    // only an exact hostname match counts (see `auth_server_host`).
    let normalize = |value: &str| {
        value
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            // A fully-qualified spelling (`relay.example.com.`) names the
            // same host as the canonical form. Keep the dot stripping for
            // both the public and relay hosts while retaining the Buzz
            // wildcard/loopback aliases below.
            .trim_end_matches('.')
            .to_ascii_lowercase()
    };
    let mut hosts = vec![normalize(host), normalize(relay_host)];
    // A wildcard bind address is not a host a client can put in a URL;
    // local Buzz instances sign with the loopback spelling they connect to.
    if matches!(hosts[1].as_str(), "0.0.0.0" | "::" | "") {
        hosts.push("127.0.0.1".into());
        hosts.push("localhost".into());
        hosts.push("::1".into());
    }
    let servers: Vec<&str> = event_tags(event, "server").collect();
    if !servers.is_empty()
        && !servers.iter().any(|s| {
            auth_server_host(s).is_some_and(|value| hosts.iter().any(|host| host == &value))
        })
    {
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
/// header (BUD-11). Accepts the spec's Base64url-without-padding, padded
/// Base64url, and the padded standard variant for leniency: base64
/// libraries commonly emit padding by default, in either alphabet.
fn decode_auth_event(headers: &HeaderMap) -> Option<crate::event::Event> {
    let encoded = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(crate::nips::nip98::strip_nostr_scheme)?;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(encoded))
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
    let pubkey = validate_auth_event(
        event,
        &state.host,
        &state.relay_host,
        verb,
        None,
        unix_now(),
    )?;
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

/// Sanitizes a reason string for the `x-reason` response header, where
/// control characters and non-ASCII bytes (possible in io/S3 error
/// strings: filenames, XML, OS messages) would panic the response
/// builder.
fn sanitize_reason(reason: &str) -> String {
    reason
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(200)
        .collect()
}

fn error(status: StatusCode, reason: &str) -> Response {
    // The body keeps the full text; the header carries the sanitized form.
    let header_reason = sanitize_reason(reason);
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

/// A HEAD error: status + `x-reason` header with no body. HEAD
/// responses must not carry a message body (RFC 9110 §9.3.2), and
/// BUD-05/06 require clients to decide from the status code and headers
/// alone — so unlike [`error`], there is no `text/plain` body here.
fn head_error(status: StatusCode, reason: &str) -> Response {
    (
        status,
        [(
            axum::http::header::HeaderName::from_static("x-reason"),
            sanitize_reason(reason),
        )],
    )
        .into_response()
}

/// [`store_error`] for HEAD handlers: same statuses, no body.
fn store_error_head(e: anyhow::Error) -> Response {
    if e.downcast_ref::<storage::DbUnavailable>().is_some() {
        return head_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "blob lookup unavailable, please retry",
        );
    }
    if let Some(upstream) = e.downcast_ref::<storage::UpstreamStatus>() {
        let status = if upstream.status == 429 {
            StatusCode::TOO_MANY_REQUESTS
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };
        let mut response = head_error(status, "blob storage temporarily unavailable, please retry");
        if let Some(secs) = upstream.retry_after
            && let Ok(value) = secs.to_string().parse()
        {
            response
                .headers_mut()
                .insert(axum::http::header::RETRY_AFTER, value);
        }
        return response;
    }
    log::error!("blossom storage error: {e}");
    head_error(StatusCode::INTERNAL_SERVER_ERROR, "storage error")
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
    if let Some(upstream) = e.downcast_ref::<storage::UpstreamStatus>() {
        let status = if upstream.status == 429 {
            StatusCode::TOO_MANY_REQUESTS
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };
        let mut response = error(status, "blob storage temporarily unavailable, please retry");
        if let Some(secs) = upstream.retry_after
            && let Ok(value) = secs.to_string().parse()
        {
            response
                .headers_mut()
                .insert(axum::http::header::RETRY_AFTER, value);
        }
        return response;
    }
    // Keep the backend detail (S3 XML, OS messages) in the log: the
    // response only carries a generic message.
    log::error!("blossom storage error: {e}");
    error(StatusCode::INTERNAL_SERVER_ERROR, "storage error")
}

/// RFC 7233 §3.2 `If-Range`: the Range is honored only when the
/// validator matches the blob's ETag (`"<sha256>"`; the bare hash is
/// accepted leniently). No `Last-Modified` is ever served, so an
/// HTTP-date validator never matches and the full blob is served.
fn if_range_matches(if_range: Option<&str>, sha: &str) -> bool {
    let Some(value) = if_range else {
        return true;
    };
    let value = value.trim();
    value == format!("\"{sha}\"").as_str() || value == sha
}

/// Parses a single `Range: bytes=` request (RFC 7233) against `size`.
///
/// Returns `Ok(None)` when the range should be ignored (a multi-range
/// header, or a unit other than `bytes` — RFC 7233 allows the server to
/// ignore the header), `Ok(Some((start, end)))` for a satisfiable single
/// range (inclusive end, clamped to the blob size) and an error for an
/// unsatisfiable or malformed range (416 with `Content-Range: bytes */`).
fn parse_range(header: &str, size: usize) -> anyhow::Result<Option<(usize, usize)>> {
    // RFC 7233 §2.1: range units are case-insensitive (`bytes=`, `BYTES=`,
    // `Bytes=` are equivalent). A non-bytes unit is ignored (200).
    let trimmed = header.trim();
    let Some(spec) = trimmed
        .get(..6)
        .filter(|prefix| prefix.eq_ignore_ascii_case("bytes="))
        .map(|_| &trimmed[6..])
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
/// Range response from reading past the requested window). `read_buf` fills
/// a `BytesMut` directly and the chunk is frozen without the extra
/// `Bytes::copy_from_slice` copy the old path made for every 64 KiB.
struct FileChunks {
    file: tokio::fs::File,
    remaining: u64,
}

impl futures_util::Stream for FileChunks {
    type Item = Result<bytes::Bytes, std::io::Error>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        use tokio::io::AsyncReadExt;
        const CHUNK: usize = 64 * 1024;
        let this = &mut *self;
        if this.remaining == 0 {
            return std::task::Poll::Ready(None);
        }
        let want = (this.remaining.min(CHUNK as u64)) as usize;
        let mut buf = bytes::BytesMut::with_capacity(want);
        let file = &mut this.file;
        let read = std::task::ready!(std::pin::pin!(file.read_buf(&mut buf)).poll(_cx));
        match read {
            Ok(0) => std::task::Poll::Ready(None),
            Ok(n) => {
                this.remaining -= n as u64;
                std::task::Poll::Ready(Some(Ok(buf.freeze())))
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
        Box<dyn futures_util::Stream<Item = Result<bytes::Bytes, std::io::Error>> + Send>,
    >,
    remaining: u64,
    /// Fires when no chunk arrived within the deadline: the streaming S3
    /// client has no total timeout (to avoid truncating large blobs), so a
    /// stalled connection would otherwise pin the download permit forever.
    stall: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
    /// Test override for the per-chunk stall deadline.
    stall_timeout: std::time::Duration,
}

/// How long a single S3 stream chunk may take before the download is
/// aborted.
const S3_STREAM_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

impl S3Chunks {
    fn new(resp: reqwest::Response, remaining: u64) -> S3Chunks {
        use futures_util::StreamExt as _;
        Self::from_stream(
            Box::pin(
                resp.bytes_stream()
                    .map(|chunk| chunk.map_err(std::io::Error::other)),
            ),
            remaining,
            S3_STREAM_READ_TIMEOUT,
        )
    }

    fn from_stream(
        stream: std::pin::Pin<
            Box<dyn futures_util::Stream<Item = Result<bytes::Bytes, std::io::Error>> + Send>,
        >,
        remaining: u64,
        stall_timeout: std::time::Duration,
    ) -> S3Chunks {
        S3Chunks {
            stream,
            remaining,
            stall: None,
            stall_timeout,
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
        // Poll the upstream stream first. The timer measures an S3 stall,
        // not the time the downstream client spends not polling us: arming
        // (and checking) it before the inner poll made a client that paused
        // for 60 seconds see a spurious "s3 stream stalled" on resume.
        match this.stream.as_mut().poll_next(cx) {
            std::task::Poll::Ready(Some(Ok(bytes))) => {
                this.stall = None;
                let take = (bytes.len() as u64).min(this.remaining) as usize;
                this.remaining -= take as u64;
                if take == 0 {
                    return std::task::Poll::Ready(None);
                }
                return std::task::Poll::Ready(Some(Ok(bytes.slice(..take))));
            }
            std::task::Poll::Ready(Some(Err(e))) => {
                this.stall = None;
                return std::task::Poll::Ready(Some(Err(e)));
            }
            std::task::Poll::Ready(None) => {
                this.stall = None;
                return std::task::Poll::Ready(None);
            }
            std::task::Poll::Pending => {}
        }
        // The upstream is pending: start (or continue) the stall timer. It
        // is cleared on the next ready chunk above.
        if this.stall.is_none() {
            this.stall = Some(Box::pin(tokio::time::sleep(this.stall_timeout)));
        }
        if this
            .stall
            .as_mut()
            .is_some_and(|sleep| sleep.as_mut().poll(cx).is_ready())
        {
            return std::task::Poll::Ready(Some(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "s3 stream stalled",
            ))));
        }
        std::task::Poll::Pending
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
    // One LMDB load for both the descriptor and the owner list: the old
    // path called `find` and then `open_stream_any`, which loaded the same
    // mapping a second time on every GET.
    let resolved = match state.store.resolve(&sha).await {
        Ok(Some(resolved)) => resolved,
        Ok(None) => return error(StatusCode::NOT_FOUND, "blob not found"),
        Err(e) => return store_error(e),
    };
    let desc = &resolved.descriptor;
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
    // RFC 7233 §3.2: a Range guarded by a non-matching `If-Range`
    // validator is ignored entirely (even a malformed range): the stale
    // client gets the full blob with 200.
    let range_honored = if_range_matches(
        headers
            .get(axum::http::header::IF_RANGE)
            .and_then(|v| v.to_str().ok()),
        &sha,
    );
    let (start, end) = match range {
        Some(Err(_)) if range_honored => {
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
        Some(Ok(Some((start, end)))) if range_honored => (start, end),
        _ => (0, size_usize.saturating_sub(1)),
    };
    let len = if size == 0 {
        0
    } else {
        (end - start + 1) as u64
    };
    match state
        .store
        .open_resolved(&sha, &resolved.owners, start as u64, len)
        .await
    {
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
            let ranged = matches!(range, Some(Ok(Some(_)))) && range_honored;
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
/// 404, exactly like GET). RFC 7233 §3.1 requires ignoring a Range on
/// HEAD, so the full length is always described with 200.
async fn head_blob(
    State(relay): State<Arc<Relay>>,
    _headers: HeaderMap,
    AxPath(blob): AxPath<String>,
) -> Response {
    let Some(state) = state_of(&relay).await else {
        return head_error(StatusCode::SERVICE_UNAVAILABLE, "blossom not initialized");
    };
    let Some(sha) = split_blob(&blob) else {
        return head_error(StatusCode::BAD_REQUEST, "invalid blob hash");
    };
    // One LMDB load for both the descriptor and the owner list (the old
    // path loaded the mapping in `find` and again in `exists_any`).
    let resolved = match state.store.resolve(&sha).await {
        Ok(Some(resolved)) => resolved,
        Ok(None) => return head_error(StatusCode::NOT_FOUND, "blob not found"),
        Err(e) => return store_error_head(e),
    };
    let desc = &resolved.descriptor;
    let size = desc.size;
    // Resolve the backing object exactly like GET: a mapping without a
    // readable blob must 404. This is a HEAD request on the backend
    // (`any_exists`), not an S3 GET whose body is discarded.
    match state.store.any_exists(&sha, &resolved.owners).await {
        Ok(true) => {}
        Ok(false) => return head_error(StatusCode::NOT_FOUND, "blob not found"),
        Err(e) => return store_error_head(e),
    }
    let mut response = (
        StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, desc.mime.clone()),
            (axum::http::header::CONTENT_LENGTH, size.to_string()),
            (axum::http::header::ETAG, format!("\"{sha}\"")),
            (
                axum::http::header::CACHE_CONTROL,
                "public, max-age=31536000, immutable".to_string(),
            ),
            (axum::http::header::ACCEPT_RANGES, "bytes".to_string()),
        ],
    )
        .into_response();
    harden_blob_response(&mut response, &desc.mime);
    // HEAD has no body to compress, and the compression layer would remove
    // the Content-Length the client uses to size the blob. Keep the identity
    // metadata; GET negotiates Brotli independently.
    response.extensions_mut().insert(SkipCompression);
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
    let max_upload = state.max_upload_bytes;
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
    // The per-identity count cap is registered before spooling, but byte
    // permits are acquired chunk by chunk inside the spool: the declared
    // Content-Length (or a chunked body with no length) is untrusted, and
    // reserving it up front let a few identities hold the whole global
    // budget without sending a byte (M09).
    let Some(mut upload_slot) = state.try_register_upload(&pubkey) else {
        return error(
            StatusCode::TOO_MANY_REQUESTS,
            "too many uploads in progress",
        );
    };
    // Spool on the blob filesystem when possible: the final store is then a
    // rename (no second full write). A missing/uncreatable directory falls
    // back to the system temp dir, and that fallback is reserved against
    // `/tmp` (not the blob filesystem whose floor does not cover it).
    let drain = relay.subscribe_drain();
    // A symlinked `.spool` is refused and falls back to the system temp
    // directory; `create_dir_all` would otherwise follow the link.
    let spool_dir = state.store.prepare_spool_dir().await;
    let spool_dir = spool_dir.as_deref();
    let mut spool_space = match if spool_dir.is_some() {
        state.store.reserve_space(0)
    } else {
        state.store.reserve_temp_space(0)
    } {
        Ok(guard) => guard,
        Err(_) => return error(StatusCode::INSUFFICIENT_STORAGE, "storage is full"),
    };
    let (path, size, sha) = match spool_upload(
        body,
        max_upload as u64,
        declared_len,
        idle_timeout,
        spool_dir,
        Some(drain.clone()),
        Some(&mut upload_slot),
        Some(&mut spool_space),
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
    match result {
        Ok((desc, existed)) => {
            // Buzz uploads to the relay origin (its HTTP base URL), so the
            // descriptor must name the host the client actually used. The
            // dedicated Blossom host is only correct for uploads that
            // arrived there; handing it to a relay-origin upload produces a
            // URL the client cannot resolve.
            let url_host = response_url_host(
                &state.host,
                &state.relay_host,
                headers
                    .get(axum::http::header::HOST)
                    .and_then(|value| value.to_str().ok()),
            );
            let url = format!("https://{url_host}/media/{sha}{}", ext_of(&desc.mime));
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
/// `declared_len` is the optional Content-Length: a body that overruns it
/// is rejected. The byte/disk reservations are grown per received chunk
/// through `slot`/`space` (the test-only calls pass `None`), so a client
/// that declares a ceiling but sends nothing holds no permit.
/// `idle_timeout` bounds the wait for the next chunk and the rate-derived
/// total deadline bounds the whole body, so a stalled or trickled upload
/// (slow-loris) cannot pin an upload permit or a temp file forever.
#[allow(clippy::too_many_arguments)]
async fn spool_upload(
    body: Body,
    max_upload: u64,
    declared_len: Option<u64>,
    idle_timeout: std::time::Duration,
    spool_dir: Option<&std::path::Path>,
    drain: Option<tokio::sync::watch::Receiver<bool>>,
    mut slot: Option<&mut UploadSlot>,
    mut space: Option<&mut storage::SpaceReservation<'_>>,
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
    let file = match tokio::fs::OpenOptions::new()
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
    // Coalesce the body chunks into 256 KiB writes: `write_all` on a raw
    // tokio file submits one blocking-pool task per HTTP chunk, which can be
    // as small as a few KiB. The buffer stays on the heap and never crosses
    // an await boundary, so the upload still streams (it does not hold the
    // whole body in memory).
    let mut file = tokio::io::BufWriter::with_capacity(256 * 1024, file);
    let mut stream = body.into_data_stream();
    let mut hash = Sha256::new();
    let mut size = 0u64;
    // A large declared body may not be held for the full rate window with
    // a few bytes per idle tick. After a grace period require a modest
    // average (16 KiB/s): enough for slow mobile links, far above a drip
    // that would monopolize the shared permit budget.
    const MIN_UPLOAD_AVERAGE_BYTES_PER_SEC: u64 = 16 * 1024;
    const UPLOAD_RATE_GRACE_SECS: u64 = 10;
    // Total body budget: the rate-derived time (at least one idle window,
    // so a tiny `max_upload` does not abort immediately), capped hard. The
    // per-chunk idle timeout is capped by the same ceiling: a large
    // `http_read_timeout_secs` must not override it, or one body could pin
    // an upload permit for hours.
    let rate_budget = std::time::Duration::from_secs(
        (declared_len.unwrap_or(max_upload) / MIN_UPLOAD_RATE_BYTES_PER_SEC)
            .clamp(1, MAX_UPLOAD_TOTAL_SECS),
    );
    let started = tokio::time::Instant::now();
    let total_deadline = started
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
        let elapsed = started.elapsed().as_secs();
        if elapsed > UPLOAD_RATE_GRACE_SECS
            && size
                < elapsed
                    .saturating_sub(UPLOAD_RATE_GRACE_SECS)
                    .saturating_mul(MIN_UPLOAD_AVERAGE_BYTES_PER_SEC)
        {
            return Err(Box::new(error(
                StatusCode::REQUEST_TIMEOUT,
                "upload too slow: average rate below the minimum",
            )));
        }
        if size > max_upload {
            return Err(Box::new(error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "upload exceeds the configured size limit",
            )));
        }
        if declared_len.is_some_and(|declared| size > declared) {
            // The body overran its declared Content-Length.
            return Err(Box::new(error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "upload exceeds the declared size",
            )));
        }
        // Reserve the bytes actually received, before writing them. The
        // global/per-identity permit and the disk guard both grow with the
        // body, so a stalled or tiny body cannot hold a ceiling-sized
        // reservation (M09).
        if let Some(slot) = slot.as_deref_mut()
            && !slot.try_reserve(chunk.len() as u64)
        {
            return Err(Box::new(error(
                StatusCode::TOO_MANY_REQUESTS,
                "too many uploads in progress",
            )));
        }
        if let Some(space) = space.as_deref_mut()
            && space.grow(chunk.len() as u64).is_err()
        {
            return Err(Box::new(error(
                StatusCode::INSUFFICIENT_STORAGE,
                "storage is full",
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
    // HEAD carries no body (see `head_error`): every refusal below is
    // status + headers only.
    let Some(state) = state_of(&relay).await else {
        return head_error(StatusCode::SERVICE_UNAVAILABLE, "blossom not initialized");
    };
    // `X-SHA-256` is required: it is the only source of the blob hash
    // without a body.
    let Some(x_sha) = headers.get("x-sha-256").and_then(|v| v.to_str().ok()) else {
        return head_error(StatusCode::BAD_REQUEST, "missing X-SHA-256 header");
    };
    let x_sha = x_sha.trim().to_ascii_lowercase();
    if x_sha.len() != 64 || hex::decode(&x_sha).is_err() {
        return head_error(StatusCode::BAD_REQUEST, "malformed X-SHA-256 header");
    }
    // `X-Content-Length` is required and bounded by the upload ceiling.
    // BUD-06: a missing header is 411, but a present and malformed value is
    // a bad request (400) — and surrounding whitespace is trimmed before
    // parsing. Treating both as 411 hid client bugs behind a misleading
    // "length required".
    let Some(raw_len) = headers.get("x-content-length") else {
        return head_error(
            StatusCode::LENGTH_REQUIRED,
            "missing X-Content-Length header",
        );
    };
    let Some(len) = raw_len
        .to_str()
        .ok()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .and_then(|value| value.parse::<u64>().ok())
    else {
        return head_error(StatusCode::BAD_REQUEST, "malformed X-Content-Length header");
    };
    let max_upload = state.max_upload_bytes as u64;
    if len > max_upload {
        return head_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "the upload exceeds the configured size limit",
        );
    }
    // BUD-11: upload/media tokens carry the matching verb and an `x` tag
    // matching the declared hash.
    let Some(pubkey) = verify_auth(&relay, &state, &headers, verb, Some(&x_sha)).await else {
        return head_error(StatusCode::UNAUTHORIZED, "invalid or missing authorization");
    };
    if upload_allowed(&relay, &pubkey).await.is_err() {
        return head_error(
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
        return head_error(StatusCode::INSUFFICIENT_STORAGE, "storage is full");
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
    // Normalized like the path pubkey above: stored hashes are lowercase
    // and the LMDB lookup is case-sensitive, so an uppercase (but
    // well-formed) cursor must paginate like its lowercase spelling
    // instead of missing the lookup and yielding an empty page.
    let cursor: Option<String> = params.get("cursor").map(|c| c.to_ascii_lowercase());
    // BUD-12: the cursor is the previous page's last sha256. Its upload
    // time positions the scan in the uploaded-order index; an unknown (but
    // well-formed) cursor yields an empty page — never the first page — so
    // a stale cursor cannot loop over duplicates forever.
    let (after_uploaded, after_sha) = match cursor.as_deref() {
        Some(sha) => match state.store.resolve(sha).await {
            Ok(Some(resolved)) => {
                // Owner-scoped cursor: `resolve` is global, so a cursor
                // naming another owner's blob would position this owner's
                // page and reveal the foreign hash exists (existence
                // oracle). Treat a cursor the lister does not own like an
                // unknown one — an empty page — so only owned cursors
                // paginate. The owner list came with the same load as the
                // upload timestamp.
                if resolved.owners.iter().any(|owner| owner == &pubkey) {
                    (
                        Some(resolved.descriptor.uploaded.max(0) as u64),
                        Some(sha.to_string()),
                    )
                } else {
                    let empty: Vec<Value> = Vec::new();
                    return (
                        [(axum::http::header::CONTENT_TYPE, "application/json")],
                        serde_json::to_string(&empty).unwrap(),
                    )
                        .into_response();
                }
            }
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
    // One mapping load answers both "does it exist" and "is the requester an
    // owner"; the old `find` + `has` pair loaded the same row twice.
    let resolved = match state.store.resolve(&sha).await {
        Ok(Some(resolved)) => resolved,
        Ok(None) => return error(StatusCode::NOT_FOUND, "blob not found"),
        Err(e) => return store_error(e),
    };
    // Only an uploader of these bytes may delete their own copy; other
    // uploaders of identical content keep theirs. A failed ownership check
    // must not answer 403: the requester may well be the uploader.
    if !resolved.owners.iter().any(|owner| owner == &pubkey) {
        return error(
            StatusCode::FORBIDDEN,
            "only the uploader may delete this blob",
        );
    }
    match state.store.delete(&pubkey, &sha).await {
        Ok(true) => StatusCode::OK.into_response(),
        Ok(false) => error(StatusCode::NOT_FOUND, "blob not found"),
        Err(e) => store_error(e),
    }
}

/// The host to put in a BlobDescriptor URL after an upload. Use the host the
/// request actually arrived on (Buzz's relay origin or the dedicated
/// Blossom host); fall back to the configured relay/Blossom host when a
/// proxy omits the Host header.
fn response_url_host(blossom_host: &str, relay_host: &str, request_host: Option<&str>) -> String {
    if let Some(request_host) = request_host {
        let request_host = super::host_header_host(request_host);
        if !request_host.is_empty() {
            return request_host.to_string();
        }
    }
    if !relay_host.is_empty() && !matches!(relay_host, "0.0.0.0" | "::" | "[::]") {
        return relay_host.to_string();
    }
    blossom_host.to_string()
}

/// The relay's externally visible HTTP host, as Buzz signs it in a BUD-11
/// `server` tag (derived from `relay.public_url`, else `server.host`).
fn relay_http_host(cfg: &Config) -> String {
    let public = cfg.relay.public_url.trim();
    let authority = if public.is_empty() {
        cfg.server.host.trim()
    } else {
        public
            .split_once("://")
            .map(|(_, rest)| rest)
            .unwrap_or(public)
            .split('/')
            .next()
            .unwrap_or(public)
    };
    super::host_header_host(authority).to_ascii_lowercase()
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
                relay_host: relay_http_host(cfg),
                max_upload_bytes: cfg.blossom.max_upload_bytes,
                upload_budget: Arc::new(tokio::sync::Semaphore::new(
                    cfg.blossom.max_upload_bytes.saturating_mul(4).max(1),
                )),
                uploads_inflight: std::sync::Mutex::new(std::collections::HashMap::new()),
                uploads_reserved: std::sync::Mutex::new(std::collections::HashMap::new()),
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
            .trim_end_matches('.')
            .to_ascii_lowercase()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;
    use futures_util::StreamExt as _;
    use secp256k1::{Keypair, XOnlyPublicKey};

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

    #[tokio::test]
    async fn upload_allowlist_matches_case_insensitively() {
        // Entries arrive from operators who may type uppercase hex, while
        // wire pubkeys are lowercase: an exact compare would deny a
        // legitimately listed uploader over letter case.
        let relay = build_blossom_relay(0).await;
        relay.config.write().await.blossom.restrict_uploads = true;
        let pk = "aa".repeat(32);
        *relay.blossom_allow.write().await = vec![pk.to_ascii_uppercase()];
        assert!(
            upload_allowed(&relay, &pk).await.is_ok(),
            "an allowlisted pubkey must upload regardless of entry letter case"
        );
        assert!(
            upload_allowed(&relay, &"bb".repeat(32)).await.is_err(),
            "a non-listed pubkey must still be refused"
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
        created: u64,
        verb: &str,
        expiration: Option<u64>,
        x: Option<&str>,
        server: Option<&str>,
    ) -> Event {
        auth_event_with_key(&[9u8; 32], created, verb, expiration, x, server)
    }

    /// Like [`auth_event`], but signed with `seckey`: tests that need two
    /// distinct uploader identities.
    fn auth_event_with_key(
        seckey: &[u8; 32],
        created: u64,
        verb: &str,
        expiration: Option<u64>,
        x: Option<&str>,
        server: Option<&str>,
    ) -> Event {
        let keypair = Keypair::from_secret_bytes(*seckey).unwrap();
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
        ev.sig = secp256k1::schnorr::sign_no_aux_rand(&id, &keypair).to_string();
        ev
    }

    /// A valid Blossom `Authorization: Nostr <token>` header for `verb`,
    /// returning the header map and the author's hex pubkey.
    fn auth_headers(verb: &str) -> (HeaderMap, String) {
        auth_headers_scoped(verb, None)
    }

    /// Like [`auth_headers`], but the token carries the body-scoped `x` tag
    /// required by upload/delete endpoints (BUD-11).
    fn auth_headers_scoped(verb: &str, sha: Option<&str>) -> (HeaderMap, String) {
        auth_headers_scoped_with_key(&[9u8; 32], verb, sha)
    }

    /// Like [`auth_headers_scoped`], but signed with `seckey` (a second
    /// uploader identity for the per-pubkey upload-cap tests).
    fn auth_headers_scoped_with_key(
        seckey: &[u8; 32],
        verb: &str,
        sha: Option<&str>,
    ) -> (HeaderMap, String) {
        let now = unix_now();
        let ev = auth_event_with_key(seckey, now, verb, Some(now + 600), sha, None);
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
        let chunks: Vec<Result<bytes::Bytes, std::io::Error>> = vec![
            Ok(bytes::Bytes::from_static(&[1, 2, 3])),
            Ok(bytes::Bytes::from_static(&[4, 5, 6, 7, 8])),
            Ok(bytes::Bytes::from_static(&[9])),
        ];
        let stream = S3Chunks::from_stream(
            Box::pin(futures_util::stream::iter(chunks)),
            7,
            S3_STREAM_READ_TIMEOUT,
        );
        let mut out = Vec::new();
        futures_util::pin_mut!(stream);
        while let Some(chunk) = stream.next().await {
            out.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(out, vec![1, 2, 3, 4, 5, 6, 7], "the cap is byte-exact");
    }

    #[tokio::test]
    async fn s3_chunks_resume_after_a_slow_downstream_pause() {
        // BLM-02: the stall timer must measure an S3 stall, not the time the
        // HTTP client spends not polling the response. A client that pauses
        // longer than the deadline and then resumes must receive the ready
        // upstream chunk, not a spurious timeout.
        use futures_util::StreamExt as _;
        let stream = futures_util::stream::once(async {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"ok"))
        });
        let mut chunks =
            S3Chunks::from_stream(Box::pin(stream), 2, std::time::Duration::from_millis(10));
        // Poll once, then let both the upstream chunk and the stall timer
        // become ready while the downstream is paused.
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(1), chunks.next())
                .await
                .is_err(),
            "the first poll must be pending"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let chunk = chunks
            .next()
            .await
            .expect("the ready upstream chunk must be served")
            .expect("the chunk must be valid");
        assert_eq!(&chunk[..], b"ok");
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
        // RFC 7233 §3.2: a Range with a matching If-Range validator is
        // honored; with a stale validator the Range is ignored (200 full).
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::RANGE,
            "bytes=1000-1999".parse().unwrap(),
        );
        headers.insert(
            axum::http::header::IF_RANGE,
            format!("\"{sha}\"").parse().unwrap(),
        );
        let resp = get_blob(State(relay.clone()), headers, AxPath(sha.clone())).await;
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::RANGE,
            "bytes=1000-1999".parse().unwrap(),
        );
        headers.insert(
            axum::http::header::IF_RANGE,
            format!("\"{}\"", "0".repeat(64)).parse().unwrap(),
        );
        let resp = get_blob(State(relay.clone()), headers, AxPath(sha.clone())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(axum::http::header::CONTENT_RANGE),
            None,
            "a stale If-Range must ignore the Range, not serve 206"
        );
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], &data[..]);
        // A stale If-Range ignores even an unsatisfiable Range (200, not
        // 416: the Range field itself is ignored).
        let mut headers = HeaderMap::new();
        headers.insert(axum::http::header::RANGE, "bytes=50000-".parse().unwrap());
        headers.insert(
            axum::http::header::IF_RANGE,
            format!("\"{}\"", "0".repeat(64)).parse().unwrap(),
        );
        let resp = get_blob(State(relay.clone()), headers, AxPath(sha.clone())).await;
        assert_eq!(resp.status(), StatusCode::OK);
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
    async fn brotli_negotiates_images_and_skips_head_ranges_and_small_blobs() {
        use std::io::Read as _;
        use tower::ServiceExt as _;

        let relay = build_blossom_relay(0).await;
        let state = relay.blossom.read().await.clone().unwrap();
        let owner = "aa".repeat(32);
        // Highly compressible SVG, above the 1 KiB floor.
        let svg = format!("<svg>{}</svg>", "x".repeat(4096)).into_bytes();
        let sha = sha256_hex(&svg);
        state
            .store
            .put(&owner, &sha, &svg, "image/svg+xml")
            .await
            .unwrap();
        let app: axum::Router = routes(&relay, 1024 * 1024).await.with_state(relay.clone());

        let get = |uri: String, extra: &[(&str, &str)]| {
            let mut builder = axum::http::Request::builder().uri(uri);
            for (name, value) in extra {
                builder = builder.header(*name, *value);
            }
            builder.body(Body::empty()).unwrap()
        };
        let br = axum::http::header::ACCEPT_ENCODING.as_str();
        let resp = app
            .clone()
            .oneshot(get(format!("/{sha}"), &[(br, "br")]))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()[axum::http::header::CONTENT_ENCODING], "br");
        assert!(
            resp.headers()
                .get_all(axum::http::header::VARY)
                .iter()
                .any(|value| value
                    .to_str()
                    .is_ok_and(|value| value.eq_ignore_ascii_case("accept-encoding"))),
            "a compressed response must vary on Accept-Encoding"
        );
        assert!(
            resp.headers()
                .get(axum::http::header::CONTENT_LENGTH)
                .is_none(),
            "the compressed length is unknown (chunked)"
        );
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(body.len() < svg.len(), "Brotli must shrink the SVG");
        let mut decoded = Vec::new();
        brotli::Decompressor::new(&body[..], 4096)
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, svg, "the compressed body must round-trip");

        // A range is an identity representation: the layer must not compress
        // the 206 (the handler's Content-Range also makes the layer skip it).
        let resp = app
            .clone()
            .oneshot(get(
                format!("/{sha}"),
                &[
                    (br, "br"),
                    (axum::http::header::RANGE.as_str(), "bytes=0-99"),
                ],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert!(
            resp.headers()
                .get(axum::http::header::CONTENT_ENCODING)
                .is_none()
        );
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], &svg[..100]);

        // HEAD keeps the real Content-Length and is never compressed.
        let head = axum::http::Request::builder()
            .method(axum::http::Method::HEAD)
            .uri(format!("/{sha}"))
            .header(br, "br")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(head).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            resp.headers()
                .get(axum::http::header::CONTENT_ENCODING)
                .is_none()
        );
        assert_eq!(
            resp.headers()[axum::http::header::CONTENT_LENGTH]
                .to_str()
                .unwrap(),
            svg.len().to_string()
        );

        // Small images, videos and opaque binary blobs stay identity.
        for (mime, len) in [
            ("image/png", 512usize),
            ("video/mp4", 4096),
            ("application/octet-stream", 4096),
        ] {
            let data = vec![b'a'; len];
            let data_sha = sha256_hex(&data);
            state
                .store
                .put(&owner, &data_sha, &data, mime)
                .await
                .unwrap();
            let resp = app
                .clone()
                .oneshot(get(format!("/{data_sha}"), &[(br, "br")]))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            assert!(
                resp.headers()
                    .get(axum::http::header::CONTENT_ENCODING)
                    .is_none(),
                "{mime} ({len} bytes) must not be compressed"
            );
        }

        // The configuration switch disables the layer for new routers.
        relay.config.write().await.blossom.brotli = false;
        let plain: axum::Router = routes(&relay, 1024 * 1024).await.with_state(relay.clone());
        let resp = plain
            .oneshot(get(format!("/{sha}"), &[(br, "br")]))
            .await
            .unwrap();
        assert!(
            resp.headers()
                .get(axum::http::header::CONTENT_ENCODING)
                .is_none(),
            "blossom.brotli = false must serve identity"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn head_blob_ignores_range_and_carries_no_body() {
        // RFC 7233 §3.1: a Range on HEAD is ignored (always 200 with the
        // full length); RFC 9110 §9.3.2: HEAD responses carry no body.
        let relay = build_blossom_relay(0).await;
        let state = relay.blossom.read().await.clone().unwrap();
        let data: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let sha = sha256_hex(&data);
        state
            .store
            .put(&"aa".repeat(32), &sha, &data, "application/octet-stream")
            .await
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(axum::http::header::RANGE, "bytes=0-10".parse().unwrap());
        let resp = head_blob(State(relay.clone()), headers, AxPath(sha.clone())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(axum::http::header::CONTENT_RANGE),
            None,
            "HEAD must ignore Range, not answer 206"
        );
        assert_eq!(resp.headers()[axum::http::header::CONTENT_LENGTH], "1000");
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(body.is_empty(), "HEAD must not carry a body");
        // Error paths are bodiless too (BUD-05/06: clients decide from
        // the status code and headers alone).
        let resp = head_blob(
            State(relay.clone()),
            HeaderMap::new(),
            AxPath("ab".repeat(32)),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(body.is_empty(), "a HEAD 404 must not carry a body");
        // Preflight errors are bodiless as well.
        let resp = head_upload(State(relay.clone()), HeaderMap::new()).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            body.is_empty(),
            "a HEAD preflight error must not carry a body"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn head_preflight_distinguishes_a_missing_content_length_from_a_malformed_one() {
        // BUD-06: a missing `X-Content-Length` is 411, but a value that is
        // not a number is a bad request (400), not another "length
        // required"; surrounding whitespace is trimmed.
        let relay = build_blossom_relay(0).await;
        let sha = sha256_hex(b"x");
        let mut headers = HeaderMap::new();
        headers.insert("x-sha-256", sha.parse().unwrap());
        let resp = head_preflight(relay.clone(), headers.clone(), "upload").await;
        assert_eq!(resp.status(), StatusCode::LENGTH_REQUIRED);
        headers.insert("x-content-length", "not-a-number".parse().unwrap());
        let resp = head_preflight(relay.clone(), headers.clone(), "upload").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        // A valid (padded) length reaches the auth gate: 401 without a
        // token, rather than being rejected as malformed.
        headers.insert("x-content-length", " 1 ".parse().unwrap());
        let resp = head_preflight(relay.clone(), headers, "upload").await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
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
        let ev = auth_event(now, "upload", Some(now + 300), Some(&sha), None);
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
        let ev = auth_event(now, "upload", Some(now + 300), Some(&sha), None);
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
        let (mut headers, _) = auth_headers_scoped("upload", Some(&sha));
        headers.insert("x-sha-256", sha.parse().unwrap());
        headers.insert("x-content-length", data.len().to_string().parse().unwrap());
        let resp = head_preflight(relay.clone(), headers, "upload").await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a declared size within the headroom must preflight as OK"
        );
        // ...and the PUT reserves the declared size, not the ceiling.
        let (mut headers, _) = auth_headers_scoped("upload", Some(&sha));
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

        // The preflight still compares the declared ceiling with the
        // headroom (it cannot know the eventual body size), but the PUT
        // reserves only the bytes it receives: a small body behind a huge
        // declaration must succeed because it fits the actual space.
        let ceiling = state_of(&relay)
            .await
            .expect("blossom state")
            .max_upload_bytes as u64;
        let (mut headers, _) = auth_headers_scoped("upload", Some(&sha));
        headers.insert("x-sha-256", sha.parse().unwrap());
        headers.insert("x-content-length", ceiling.to_string().parse().unwrap());
        let resp = head_preflight(relay.clone(), headers, "upload").await;
        assert_eq!(resp.status(), StatusCode::INSUFFICIENT_STORAGE);

        let data2 = b"a small body with a large declared ceiling";
        let sha2 = sha256_hex(data2);
        let (mut headers, _) = auth_headers_scoped("upload", Some(&sha2));
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
            Body::from(bytes::Bytes::copy_from_slice(data2)),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "the actual body fits even though the declared ceiling does not"
        );

        // A chunked body has no declared size: its chunks reserve only the
        // bytes actually received, so a small body also fits.
        let data3 = b"a small chunked body";
        let sha3 = sha256_hex(data3);
        let (headers, _) = auth_headers_scoped("upload", Some(&sha3));
        let resp = upload(
            State(relay.clone()),
            headers,
            Body::from(bytes::Bytes::copy_from_slice(data3)),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "a chunked body must reserve its actual bytes, not the ceiling"
        );
        drop(_held);
        assert_eq!(
            state.store.reserved_bytes(),
            0,
            "all actual-byte reservations must be released"
        );
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
        let (mut headers, _) = auth_headers_scoped("upload", Some(&sha));
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
        let (headers, pk) = auth_headers("list");
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

    #[test]
    fn upstream_throttling_is_propagated_instead_of_a_generic_500() {
        // F-13-4: an S3 429/503 after the client's bounded retries keeps
        // its status (and Retry-After) instead of reading as a local
        // storage fault.
        let throttled = store_error(anyhow::Error::new(
            crate::server::blossom::storage::UpstreamStatus {
                status: 429,
                retry_after: Some(7),
            },
        ));
        assert_eq!(throttled.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(throttled.headers()["retry-after"], "7");
        let unavailable = store_error_head(anyhow::Error::new(
            crate::server::blossom::storage::UpstreamStatus {
                status: 503,
                retry_after: None,
            },
        ));
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(unavailable.headers().get("retry-after").is_none());
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

        let (headers, _) = auth_headers_scoped("delete", Some(&sha));
        let resp = delete_blob(State(relay.clone()), headers, AxPath(sha.clone())).await;
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a failed ownership check must not answer 403"
        );

        let (headers, pk) = auth_headers("list");
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
        let ev = auth_event(now, "upload", Some(now + 300), Some(&sha), None);
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
        let (mut headers, _) = auth_headers_scoped("upload", Some(&sha));
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
        let (mut headers, _) = auth_headers_scoped("upload", Some(&sha));
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
        let (headers, _) = auth_headers_scoped("upload", Some(&sha));
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
    async fn stalled_chunked_uploads_do_not_consume_the_global_budget() {
        // M09: four free identities each open one chunked PUT and send no
        // bytes. Before the fix each reserved the full ceiling and the
        // global byte semaphore was exhausted; now the byte/disk permits
        // grow only with received chunks, so the budget stays available.
        let relay = build_blossom_relay(0).await;
        relay.config.write().await.limits.http_read_timeout_secs = 30;
        let state = state_of(&relay).await.expect("blossom state");
        let data = b"another uploader's blob";
        let sha = sha256_hex(data);
        let pending = || {
            Body::from_stream(futures_util::stream::pending::<
                Result<bytes::Bytes, std::io::Error>,
            >())
        };
        let mut stalled = Vec::new();
        for seed in [3u8, 4, 5, 6] {
            let (headers, _) = auth_headers_scoped_with_key(&[seed; 32], "upload", Some(&sha));
            stalled.push(tokio::spawn(upload(
                State(relay.clone()),
                headers,
                pending(),
            )));
        }
        for _ in 0..200 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            if state
                .uploads_inflight
                .lock()
                .unwrap()
                .values()
                .copied()
                .sum::<usize>()
                >= 4
            {
                break;
            }
        }
        assert_eq!(
            state
                .uploads_inflight
                .lock()
                .unwrap()
                .values()
                .copied()
                .sum::<usize>(),
            4,
            "all four sybil identities must be registered"
        );
        assert!(
            state.uploads_reserved.lock().unwrap().is_empty(),
            "a body-less upload must hold no per-identity bytes"
        );
        assert_eq!(
            state.upload_budget.available_permits(),
            state.max_upload_bytes.saturating_mul(4).max(1),
            "a body-less upload must hold no global byte permit"
        );

        // A normal upload from another identity still succeeds while all
        // four stalled requests are alive.
        let (headers_b, _) = auth_headers_scoped_with_key(&[7u8; 32], "upload", Some(&sha));
        let resp = upload(
            State(relay.clone()),
            headers_b,
            Body::from(bytes::Bytes::from_static(data)),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "the global budget must remain available to another uploader"
        );

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
        assert!(
            state.uploads_reserved.lock().unwrap().is_empty(),
            "cancelled uploads must release their byte budgets"
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
        let data = b"x";
        let sha = sha256_hex(data);
        let (headers, pk) = auth_headers_scoped("upload", Some(&sha));
        let handle = tokio::spawn(upload(
            State(relay.clone()),
            headers,
            Body::from_stream(
                futures_util::stream::once(async {
                    Ok::<_, std::io::Error>(bytes::Bytes::from_static(data))
                })
                .chain(futures_util::stream::pending()),
            ),
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
            Some(64 * 1024),
            std::time::Duration::from_secs(1),
            None,
            None,
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
        let now = unix_now();
        let sha = "a".repeat(64);
        let host = "media.example.com";
        // A fully-specified upload token validates.
        let ev = auth_event(now, "upload", Some(now + 300), Some(&sha), Some(host));
        assert_eq!(
            validate_auth_event(&ev, host, host, "upload", Some(&sha), now),
            Some(ev.pubkey.clone())
        );
        // A configured FQDN with the absolute-name trailing dot and a
        // token scoped to the bare host are the same server (BLM-03).
        assert_eq!(
            validate_auth_event(
                &ev,
                "media.example.com.",
                "media.example.com.",
                "upload",
                Some(&sha),
                now,
            ),
            Some(ev.pubkey.clone())
        );
        let dotted = auth_event(
            now,
            "upload",
            Some(now + 300),
            Some(&sha),
            Some("media.example.com."),
        );
        assert_eq!(
            validate_auth_event(&dotted, host, host, "upload", Some(&sha), now),
            Some(dotted.pubkey.clone())
        );
        // BUD-11: the `expiration` tag is mandatory.
        let ev = auth_event(now, "upload", None, Some(&sha), Some(host));
        assert_eq!(
            validate_auth_event(&ev, host, host, "upload", Some(&sha), now),
            None,
            "a token without an expiration tag must be rejected"
        );
        // An expired or unparseable expiration is rejected.
        let ev = auth_event(now, "upload", Some(now - 1), Some(&sha), Some(host));
        assert_eq!(
            validate_auth_event(&ev, host, host, "upload", Some(&sha), now),
            None
        );
        let ev = auth_event(now, "upload", Some(0), Some(&sha), Some(host));
        assert_eq!(
            validate_auth_event(&ev, host, host, "upload", Some(&sha), now),
            None
        );
        // The `t` verb must match the endpoint.
        let ev = auth_event(now, "delete", Some(now + 300), Some(&sha), Some(host));
        assert_eq!(
            validate_auth_event(&ev, host, host, "upload", Some(&sha), now),
            None
        );
        // A `server` tag naming another host is rejected.
        let ev = auth_event(
            now,
            "upload",
            Some(now + 300),
            Some(&sha),
            Some("evil.example.com"),
        );
        assert_eq!(
            validate_auth_event(&ev, host, host, "upload", Some(&sha), now),
            None
        );
        // The old normalizer stripped everything before `:`/`/`, so a tag
        // whose userinfo spelled our host (`media.example.com:443@evil...`)
        // matched here even though the real host is `evil.example`. The
        // value is not a bare domain, so it must not match.
        let spoofed = format!("{host}:443@evil.example.com");
        let ev = auth_event(now, "upload", Some(now + 300), Some(&sha), Some(&spoofed));
        assert_eq!(
            validate_auth_event(&ev, host, host, "upload", Some(&sha), now),
            None,
            "a userinfo-spoofed server tag must not match our host"
        );
        // BUD-11: multiple `server` tags are accepted when our domain
        // appears in at least one of them.
        let mut ev = auth_event(
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
        let keypair = Keypair::from_secret_bytes([9u8; 32]).unwrap();
        ev.sig = secp256k1::schnorr::sign_no_aux_rand(&id, &keypair).to_string();
        assert_eq!(
            validate_auth_event(&ev, host, host, "upload", Some(&sha), now),
            Some(ev.pubkey.clone()),
            "a token listing several servers must be accepted when ours is among them"
        );
        // BUD-11: an upload token must carry an `x` tag matching the blob.
        let ev = auth_event(now, "upload", Some(now + 300), None, Some(host));
        assert_eq!(
            validate_auth_event(&ev, host, host, "upload", Some(&sha), now),
            None,
            "an upload token without an x tag must be rejected"
        );
        let ev = auth_event(
            now,
            "upload",
            Some(now + 300),
            Some("b".repeat(64).as_str()),
            Some(host),
        );
        assert_eq!(
            validate_auth_event(&ev, host, host, "upload", Some(&sha), now),
            None,
            "an x tag for a different blob must be rejected"
        );
        // BUD-11: `created_at` must be in the past — a token stamped well
        // in the past stays valid as long as `expiration` has not passed
        // (pre-signed tokens are spec-conformant).
        let ev = auth_event(now - 601, "upload", Some(now + 300), Some(&sha), Some(host));
        assert_eq!(
            validate_auth_event(&ev, host, host, "upload", Some(&sha), now),
            Some(ev.pubkey.clone()),
            "a past-stamped token with a future expiration is valid"
        );
        // A future `created_at` is rejected.
        let ev = auth_event(now + 601, "upload", Some(now + 300), Some(&sha), Some(host));
        assert_eq!(
            validate_auth_event(&ev, host, host, "upload", Some(&sha), now),
            None
        );
        // A wrong event kind is rejected.
        let mut ev = auth_event(now, "upload", Some(now + 300), Some(&sha), Some(host));
        ev.kind = 22242;
        assert_eq!(
            validate_auth_event(&ev, host, host, "upload", Some(&sha), now),
            None
        );
        // A delete token without an `x` tag is rejected (implied hash).
        let ev = auth_event(now, "delete", Some(now + 300), None, Some(host));
        assert_eq!(
            validate_auth_event(&ev, host, host, "delete", Some(&sha), now),
            None
        );
        // An unsigned (invalid signature) token is rejected.
        let mut ev = auth_event(now, "upload", Some(now + 300), Some(&sha), Some(host));
        ev.sig = "f".repeat(128);
        assert_eq!(
            validate_auth_event(&ev, host, host, "upload", Some(&sha), now),
            None
        );
    }

    #[test]
    fn blossom_auth_allows_a_small_clock_skew() {
        // Validity is bounded by `expiration`, so a `created_at` seconds
        // in the future only keeps skewed clients working — without the
        // leeway every request from a clock-ahead client fails with 401.
        let now = unix_now();
        let sha = "a".repeat(64);
        let host = "media.example.com";
        let ev = auth_event(now + 30, "upload", Some(now + 300), Some(&sha), Some(host));
        assert_eq!(
            validate_auth_event(&ev, host, host, "upload", Some(&sha), now),
            Some(ev.pubkey.clone()),
            "a token seconds in the future must be accepted within the skew window"
        );
        let ev = auth_event(now + 61, "upload", Some(now + 300), Some(&sha), Some(host));
        assert_eq!(
            validate_auth_event(&ev, host, host, "upload", Some(&sha), now),
            None,
            "a token past the skew window must still be rejected"
        );
    }

    #[test]
    fn blossom_auth_honors_the_earliest_expiration() {
        // Every `expiration` tag must parse and the earliest one bounds
        // the token: honoring only the first would let a later, looser
        // tag extend an intercepted token's life.
        let now = unix_now();
        let sha = "a".repeat(64);
        let host = "media.example.com";
        let with_extra_expiration = |first: u64, extra: &str| {
            let mut ev = auth_event(now, "upload", Some(first), Some(&sha), Some(host));
            ev.tags.push(vec!["expiration".into(), extra.into()]);
            ev.id = crate::nips::nip01::compute_id(&ev);
            let id = ev.id_bytes().unwrap();
            let keypair = Keypair::from_secret_bytes([9u8; 32]).unwrap();
            ev.sig = secp256k1::schnorr::sign_no_aux_rand(&id, &keypair).to_string();
            ev
        };
        // A later first tag with an earlier second tag: the earlier one
        // still bounds (accepted while it is in the future).
        let ev = with_extra_expiration(now + 600, &(now + 300).to_string());
        assert_eq!(
            validate_auth_event(&ev, host, host, "upload", Some(&sha), now),
            Some(ev.pubkey.clone())
        );
        // A past tag anywhere rejects, even behind a future first tag
        // (the old first-only check accepted this token).
        let ev = with_extra_expiration(now + 600, &(now - 10).to_string());
        assert_eq!(
            validate_auth_event(&ev, host, host, "upload", Some(&sha), now),
            None,
            "a past expiration tag must reject even behind a future first tag"
        );
        // An unparseable tag rejects, even behind a valid first tag.
        let ev = with_extra_expiration(now + 600, "soon");
        assert_eq!(
            validate_auth_event(&ev, host, host, "upload", Some(&sha), now),
            None,
            "an unparseable expiration tag must reject"
        );
    }

    #[test]
    fn uppercase_hex_auth_fields_are_rejected() {
        // The owner indexes are lowercase: an uppercase-hex token verifies
        // cryptographically but could never list or delete the uploads it
        // authored, so pubkey/id/sig must all be lowercase (mirroring
        // src/relay/validate.rs).
        let now = unix_now();
        let sha = "a".repeat(64);
        let host = "media.example.com";
        let mut ev = auth_event(now, "upload", Some(now + 300), Some(&sha), Some(host));
        // Uppercase all three fields consistently and re-sign, so the
        // token is valid apart from its case: it must still be rejected.
        ev.pubkey = ev.pubkey.to_ascii_uppercase();
        ev.id = crate::nips::nip01::compute_id(&ev);
        let id = ev.id_bytes().unwrap();
        let keypair = Keypair::from_secret_bytes([9u8; 32]).unwrap();
        ev.sig = secp256k1::schnorr::sign_no_aux_rand(&id, &keypair)
            .to_string()
            .to_ascii_uppercase();
        assert!(
            crate::nips::nip01::verify(&ev).is_ok(),
            "the uppercase token must be cryptographically valid, or the test proves nothing"
        );
        assert_eq!(
            validate_auth_event(&ev, host, host, "upload", Some(&sha), now),
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
    fn auth_token_accepts_padded_base64url() {
        // Base64 libraries commonly emit padding by default, in either
        // alphabet: a padded base64url token must decode like the spec's
        // unpadded form and the padded standard variant (previously it
        // failed both engines and answered 401).
        // Find a deterministic fixture whose padded base64url form carries
        // both padding and url-safe characters: only then does this test
        // discriminate the padded url-safe engine from the unpadded and
        // standard fallbacks. Pure-ASCII event JSON almost never produces
        // the 62/63 symbols, so the content carries multibyte characters
        // (id/sig stay stale afterwards, which decoding does not check).
        // Deterministic: all inputs are fixed, the first hit is pinned.
        let mut fixture: Option<(Event, String)> = None;
        for content in ["\u{7ff}", "\u{ffff}", "\u{20ac}", "\u{1f389}"] {
            for repeats in 1..=16 {
                let mut ev = auth_event_with_key(
                    &[9u8; 32],
                    1_700_000_000,
                    "list",
                    Some(1_700_000_600),
                    None,
                    None,
                );
                ev.content = content.repeat(repeats);
                let raw = serde_json::to_vec(&ev).unwrap();
                let token = base64::engine::general_purpose::URL_SAFE.encode(&raw);
                if token.contains('=') && (token.contains('-') || token.contains('_')) {
                    fixture = Some((ev, token));
                    break;
                }
            }
            if fixture.is_some() {
                break;
            }
        }
        let (ev, token) = fixture.expect("fixture must reach padded url-safe alphabet");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Nostr {token}").parse().unwrap(),
        );
        let decoded = decode_auth_event(&headers).expect("padded base64url must decode");
        assert_eq!(decoded.pubkey, ev.pubkey);
    }

    #[test]
    fn auth_server_host_requires_a_bare_domain() {
        // BUD-11: the tag value is a domain name, not a URL.
        assert_eq!(
            auth_server_host("media.example.com").as_deref(),
            Some("media.example.com")
        );
        assert_eq!(
            auth_server_host("  MEDIA.EXAMPLE.COM  ").as_deref(),
            Some("media.example.com"),
            "hostname comparison folds case and trims surrounding space"
        );
        // Anything that names a *different* identity must not match: a
        // port, a scheme, a path/query/fragment, userinfo before the real
        // host (`media.example.com:443@evil.example`), or IPv6 brackets.
        for bad in [
            "media.example.com:8080",
            "https://media.example.com",
            "https://media.example.com/path",
            "media.example.com/path",
            "media.example.com?x=1",
            "media.example.com#frag",
            "media.example.com:443@evil.example",
            "user@media.example.com",
            "[::1]",
            "[::1]:8080",
            "http://[::1]/upload",
            "",
        ] {
            assert_eq!(
                auth_server_host(bad),
                None,
                "{bad:?} must not name the bare host"
            );
        }
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
        assert!(!is_blossom_path("/health"));
        assert!(!is_blossom_path("/metrics"));
        assert!(!is_blossom_path("/inbox"));
        assert!(!is_blossom_path("/outbox"));
        assert!(!is_blossom_path("/api/v1/npub1..."));
        // A malformed blob hash is still the blob route: the handler must
        // answer 400 (BUD-01), not be short-circuited by the host split.
        assert!(is_blossom_path(&format!("/{}", "a".repeat(63))));
        assert!(is_blossom_path("/not-a-sha256"));
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

        // RFC 7233 §3.1: a Range on HEAD is ignored — always 200 with
        // the full length (never a 206), keeping the immutable cache
        // header and no Range variance marker.
        let mut headers = HeaderMap::new();
        headers.insert(axum::http::header::RANGE, "bytes=100-199".parse().unwrap());
        let resp = head_blob(State(relay.clone()), headers, AxPath(sha.clone())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()[axum::http::header::CONTENT_LENGTH],
            data.len().to_string()
        );
        assert!(
            resp.headers()
                .get(axum::http::header::CONTENT_RANGE)
                .is_none(),
            "HEAD must ignore Range, not answer 206"
        );
        assert_eq!(
            resp.headers()[axum::http::header::CACHE_CONTROL],
            "public, max-age=31536000, immutable"
        );
        assert!(resp.headers().get(axum::http::header::VARY).is_none());
        // A full HEAD keeps the immutable cache header and needs no Vary.
        let resp = head_blob(State(relay.clone()), HeaderMap::new(), AxPath(sha.clone())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()[axum::http::header::CACHE_CONTROL],
            "public, max-age=31536000, immutable"
        );
        assert!(resp.headers().get(axum::http::header::VARY).is_none());
        // An unsatisfiable range is ignored the same way (200, not 416).
        let mut headers = HeaderMap::new();
        headers.insert(axum::http::header::RANGE, "bytes=999999-".parse().unwrap());
        let resp = head_blob(State(relay.clone()), headers, AxPath(sha.clone())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            resp.headers()
                .get(axum::http::header::CONTENT_RANGE)
                .is_none(),
            "HEAD must ignore even an unsatisfiable Range"
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
        let (headers, pk) = auth_headers("list");
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
        // An uppercase spelling of the same cursor must paginate
        // identically (stored hashes are lowercase; the lookup is
        // case-sensitive).
        let upper = list(
            State(relay.clone()),
            headers.clone(),
            AxPath(pk.clone()),
            query(Some("2"), Some(&cursor.to_ascii_uppercase())),
        )
        .await;
        let upper = page(upper).await;
        assert_eq!(
            upper,
            serde_json::Value::Array(second.to_vec()),
            "an uppercase cursor must advance like its lowercase spelling"
        );
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
        let (headers, pk) = auth_headers("list");
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
        let (headers, pk) = auth_headers("list");
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
        let (headers, pk) = auth_headers("list");
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
        let (headers, pk) = auth_headers("list");
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

    #[test]
    fn upload_descriptor_uses_the_request_host() {
        // Buzz uploads to the relay origin; returning the Blossom host there
        // would make the descriptor URL unreachable.
        assert_eq!(
            response_url_host(
                "media.example.com",
                "relay.example.com",
                Some("relay.example.com")
            ),
            "relay.example.com"
        );
        // An upload that really arrived on the media host keeps that host.
        assert_eq!(
            response_url_host(
                "media.example.com",
                "relay.example.com",
                Some("media.example.com")
            ),
            "media.example.com"
        );
        // The host split canonicalizes the authority without its port; the
        // descriptor echoes the same spelling.
        assert_eq!(
            response_url_host(
                "media.example.com",
                "relay.example.com",
                Some("relay.example.com:443")
            ),
            "relay.example.com"
        );
        // A wildcard bind has no externally reachable name: keep the
        // configured media host when a proxy omitted the Host header.
        assert_eq!(
            response_url_host("media.example.com", "0.0.0.0", None),
            "media.example.com"
        );
    }
}
