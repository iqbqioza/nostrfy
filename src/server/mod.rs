//! HTTP server: the WebSocket/NIP-11/NIP-86 endpoint, CORS, the
//! daemon background tasks (stats, expiry purge, signals, config
//! reload) and the NIP-29 LiveKit integration in [`livekit`].

mod api;
pub(crate) mod blossom;
mod livekit;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::body::Body;
use axum::extract::FromRequestParts;
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use log::{error, info, warn};
use serde_json::json;
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;
use tokio::time::{MissedTickBehavior, interval};
use tower::util::ServiceExt;

use crate::config::Config;
use crate::db::DbClient;
use crate::error::{Result, config_err};
use crate::nips::nip11::stats_handler;
use crate::nips::nip86;
use crate::relay::Relay;
use crate::stats::Stats;
use crate::util::{TrustedProxy, accounting_ip, client_ip, normalize_ip, unix_now};
use crate::ws::handle_connection;
use api::{
    api_count_handler, api_daily_handler, api_follows_handler, api_handler, api_hourly_handler,
    api_id_handler, api_kind_handler, api_kinds_handler, api_monthly_handler, api_query_handler,
    api_related_handler, api_relay_kinds_handler, api_relays_handler, api_stats_handler,
    api_top_authors_handler,
};
use livekit::{livekit_supported, livekit_token};

/// Minimum interval between rate-limited WARNs for connection refusals: the
/// refusal paths run per connection, so an unthrottled warning would flood
/// the log during exactly the incident it reports.
const REFUSAL_WARN_INTERVAL_SECS: u64 = 10;

/// Emits at most one refusal WARN per [`REFUSAL_WARN_INTERVAL_SECS`],
/// process-wide. The counters still move on every refusal.
fn warn_refusal(message: &str) {
    static LAST_WARN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let now = unix_now();
    let last = LAST_WARN.load(std::sync::atomic::Ordering::Relaxed);
    if now.saturating_sub(last) >= REFUSAL_WARN_INTERVAL_SECS
        && LAST_WARN
            .compare_exchange(
                last,
                now,
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
            )
            .is_ok()
    {
        warn!("{message}");
    }
}

/// Worst-case graceful-shutdown budget, per phase. `nostrfy stop` must wait
/// at least this long (see `cli::wait_for_stop`), because exceeding it means
/// the process is force-killed after writes may already be committed.
///
/// Phases, run in order by [`run_server`]:
/// 1. HTTP connections drain in `serve_limited` (`HTTP_DRAIN_GRACE`);
/// 2. background tasks are joined with `TASK_JOIN_GRACE`;
/// 3. upgraded WebSocket connections flush their final batches
///    (`WS_DRAIN_GRACE`);
/// 4. the database flushes and joins its threads (`DB_SHUTDOWN_MARGIN`; the
///    join itself has no timeout, this is the margin).
pub(crate) const HTTP_DRAIN_GRACE: std::time::Duration = std::time::Duration::from_secs(5);
pub(crate) const TASK_JOIN_GRACE: std::time::Duration = std::time::Duration::from_secs(5);
pub(crate) const WS_DRAIN_GRACE: std::time::Duration = std::time::Duration::from_secs(7);
pub(crate) const DB_SHUTDOWN_MARGIN: std::time::Duration = std::time::Duration::from_secs(10);
pub(crate) const SHUTDOWN_BUDGET: std::time::Duration = std::time::Duration::from_secs(
    HTTP_DRAIN_GRACE.as_secs()
        + TASK_JOIN_GRACE.as_secs()
        + WS_DRAIN_GRACE.as_secs()
        + DB_SHUTDOWN_MARGIN.as_secs(),
);

/// Sets an integer socket option on a TCP stream.
///
/// # Safety
/// `fd` must be a valid open socket descriptor.
unsafe fn set_sock_opt(stream: &tokio::net::TcpStream, opt: libc::c_int, value: i32) {
    use std::os::fd::AsRawFd;
    let value: libc::c_int = value;
    // SAFETY: `stream` holds a valid socket descriptor and the option value
    // is a valid pointer to a `libc::c_int`.
    let ret = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            opt,
            &value as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        log::warn!(
            "setsockopt({opt}) failed: {}",
            std::io::Error::last_os_error()
        );
    }
}

/// NIP-11: relays MUST accept CORS requests.
pub async fn cors_middleware(request: Request, next: Next) -> Response {
    if request.method() == Method::OPTIONS {
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::NO_CONTENT;
        add_cors_headers(response.headers_mut());
        return response;
    }
    let mut response = next.run(request).await;
    add_cors_headers(response.headers_mut());
    response
}

/// Bounds how long a request body may take to arrive: the header timeout
/// (see [`serve_limited`]) only covers the request head, so a slow-body
/// client could otherwise hold a connection — and with it its share of the
/// accept-layer caps — indefinitely while trickling the body. The body is
/// read under the deadline and re-injected, so the handler's extractors
/// still see the exact bytes (and `DefaultBodyLimit` still applies).
/// The documented `0 = disabled` config passes through untouched.
async fn body_read_timeout_middleware(
    request: Request,
    next: Next,
    timeout: Option<Duration>,
    limit: usize,
) -> Response {
    let Some(timeout) = timeout else {
        return next.run(request).await;
    };
    // Oversized bodies are refused before buffering them, mirroring the
    // `DefaultBodyLimit` status.
    if let Some(len) = request
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        && len > limit as u64
    {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    let (parts, body) = request.into_parts();
    let bytes = match tokio::time::timeout(timeout, axum::body::to_bytes(body, limit)).await {
        Ok(Ok(bytes)) => bytes,
        // Oversized or aborted body: the extractors would answer 400 for a
        // read error, so keep that status rather than claiming a size
        // problem that was not observed.
        Ok(Err(_)) => return StatusCode::BAD_REQUEST.into_response(),
        Err(_) => return StatusCode::REQUEST_TIMEOUT.into_response(),
    };
    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}

fn add_cors_headers(headers: &mut HeaderMap) {
    headers.insert(
        axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        axum::http::header::ACCESS_CONTROL_ALLOW_METHODS,
        // PUT/DELETE are used by the Blossom file server (upload / delete).
        HeaderValue::from_static("GET, POST, PUT, DELETE, HEAD, OPTIONS"),
    );
    headers.insert(
        axum::http::header::ACCESS_CONTROL_ALLOW_HEADERS,
        // X-SHA-256 is the optional preflight hash header of BUD-02;
        // X-Content-Length / X-Content-Type are the BUD-05/06 pre-flight
        // headers (nostter sends X-Content-Length on PUT /media).
        HeaderValue::from_static(
            "Authorization, Content-Type, Accept, X-SHA-256, X-Content-Length, X-Content-Type",
        ),
    );
    headers.insert(
        axum::http::header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static("86400"),
    );
}

/// Pending-connection backlog for the TCP listeners. `TcpListener::bind`
/// uses a fixed small backlog (1024): a burst of new connections beyond it
/// (benchmarks, reconnect storms) overflows the queue and the SYN
/// retransmit timeout (~1 s) dominates the measured open rate, even though
/// the accept loop itself drains thousands per second. An explicit large
/// backlog absorbs such bursts; the kernel clamps it to `somaxconn`
/// anyway, so this is headroom, not a commitment.
const LISTEN_BACKLOG: u32 = 4096;

/// Binds a TCP listener on `addr` and logs the given label with the
/// address, turning a bind failure into a configuration error.
async fn bind_listener(addr: &(String, u16), label: &str) -> Result<TcpListener> {
    let bound: anyhow::Result<TcpListener> = async {
        // Try every resolved address like `TcpListener::bind` does, so a
        // hostname resolving to both families keeps working.
        let mut bound = None;
        let mut last_err = anyhow::anyhow!("no address resolved");
        for sock_addr in tokio::net::lookup_host((addr.0.as_str(), addr.1)).await? {
            let attempt = (|| -> anyhow::Result<_> {
                let socket = if sock_addr.is_ipv4() {
                    tokio::net::TcpSocket::new_v4()?
                } else {
                    tokio::net::TcpSocket::new_v6()?
                };
                // SO_REUSEADDR is mandatory, not optional: without it a
                // restart fails with EADDRINUSE while any TIME_WAIT socket
                // for the port exists (constant traffic = always), and the
                // accepted connections inherit the flag — so a listener
                // without it *also* poisons the next restart even after
                // this is fixed (both sides need the flag; the stale
                // TIME_WAITs age out in ~60 s). `TcpListener::bind` (mio)
                // sets this implicitly; `TcpSocket` does not.
                socket.set_reuseaddr(true)?;
                socket.bind(sock_addr)?;
                Ok(socket.listen(LISTEN_BACKLOG)?)
            })();
            match attempt {
                Ok(listener) => {
                    bound = Some(listener);
                    break;
                }
                Err(e) => last_err = e,
            }
        }
        bound.ok_or(last_err)
    }
    .await;
    let listener = match bound {
        Ok(listener) => listener,
        // Log through the logger too: in daemon mode the process stderr
        // goes to /dev/null, so a bind failure (e.g. the port is already
        // in use by another instance) would otherwise be invisible.
        Err(e) => {
            let msg = format!("cannot bind to {}:{}: {e}", addr.0, addr.1);
            log::error!("{msg}");
            return Err(config_err(msg));
        }
    };
    info!("{label}{}:{}", addr.0, addr.1);
    Ok(listener)
}

/// The relay's HTTP router: the WebSocket/NIP-11/NIP-86 endpoint, health
/// and stats routes, the NIP-29 LiveKit endpoints and the Blossom file
/// server when configured.
async fn build_router(
    relay: &Arc<Relay>,
    blossom_state: Option<Arc<blossom::BlossomState>>,
) -> Router {
    let api_routes = Router::new()
        .route("/query", get(api_query_handler))
        .route("/count", get(api_count_handler))
        .route("/relay/kinds", get(api_relay_kinds_handler))
        .route("/relay/top-authors", get(api_top_authors_handler))
        .route("/ids/{hex}", get(api_id_handler))
        .route("/ids/{hex}/related", get(api_related_handler))
        .route("/{identifier}", get(api_handler))
        .route("/{identifier}/{kind}", get(api_kind_handler))
        .route("/{identifier}/kinds", get(api_kinds_handler))
        .route("/{identifier}/stats", get(api_stats_handler))
        .route("/{identifier}/follows", get(api_follows_handler))
        .route("/{identifier}/relays", get(api_relays_handler))
        .route("/{identifier}/{kind}/monthly", get(api_monthly_handler))
        .route("/{identifier}/{kind}/daily", get(api_daily_handler))
        .route("/{identifier}/{kind}/hourly", get(api_hourly_handler))
        .layer(axum::middleware::from_fn(reject_ws_upgrade));
    // `server.ws_paths` selects which paths serve the WebSocket/NIP-11/NIP-86
    // endpoint: the default root paths, the inbox/outbox paths only, or all
    // of them. The inbox and outbox paths give the relay distinct endpoints
    // for the inbox/outbox routing model.
    let ws_paths = relay.config.read().await.server.ws_paths.trim().to_string();
    let (max_admin_body, body_read_timeout) = {
        let cfg = relay.config.read().await;
        (
            cfg.rpc.max_admin_body_bytes,
            // 0 = disabled (the documented convention): without the timeout
            // the body is passed through untouched.
            (cfg.limits.http_read_timeout_secs > 0)
                .then(|| Duration::from_secs(cfg.limits.http_read_timeout_secs)),
        )
    };
    let mut app = Router::new()
        .route("/health", get(health_handler))
        .route("/relay/stats", get(stats_handler))
        .nest("/api/v1", api_routes);
    // In `inbox-outbox` mode the root is not a WebSocket endpoint: it only
    // answers the Blossom server-info document on the Blossom host (every
    // other host gets a 404).
    if ws_paths == "inbox-outbox" {
        app = app.route("/", get(root_inbox_outbox));
    }
    for path in ws_paths_for(&ws_paths) {
        app = app.route(
            path,
            get(ws_handler)
                .post(nip86::rpc_handler)
                .layer(axum::extract::DefaultBodyLimit::max(max_admin_body))
                // The header timeout only covers the request head: without
                // this, a client could trickle the NIP-86 POST body and pin
                // its connection (and per-IP slot) indefinitely.
                .layer(axum::middleware::from_fn(move |request, next| async move {
                    body_read_timeout_middleware(request, next, body_read_timeout, max_admin_body)
                        .await
                })),
        );
    }
    let cfg = relay.config.read().await;
    if cfg.server.metrics_enabled {
        app = app.route("/metrics", get(metrics_handler));
    }
    if cfg.nip_enabled(29)
        && !cfg.relay.livekit_url.trim().is_empty()
        && !cfg.relay.livekit_api_key.is_empty()
        && !cfg.relay.livekit_api_secret.is_empty()
    {
        app = app
            .route("/.well-known/nip29/livekit", get(livekit_supported))
            .route("/.well-known/nip29/livekit/{group}", get(livekit_token));
    }
    // The Blossom routes are reachable only on the Blossom host (the host
    // split middleware gates them; the root `/` route stays with the relay
    // and is answered with the Blossom server info by `ws_handler` when the
    // Host names the Blossom host).
    let (api_host, blossom_host) = {
        let cfg = relay.config.read().await;
        (
            normalize_host(&cfg.server.api_host),
            normalize_host(&cfg.blossom.host),
        )
    };
    if let Some(state) = blossom_state.as_ref() {
        let max_upload = state.max_upload_bytes;
        app = app.merge(blossom::routes(relay, max_upload).await);
    }
    drop(cfg);
    if !api_host.is_empty() || !blossom_host.is_empty() {
        let api_host = api_host.clone();
        let blossom_host = blossom_host.clone();
        app = app.layer(axum::middleware::from_fn(move |req, next| {
            let api_host = api_host.clone();
            let blossom_host = blossom_host.clone();
            async move { host_split(&api_host, &blossom_host, req, next).await }
        }));
    }
    // CORS runs inside the blocked-IP layer: the blockip check must apply
    // to preflight requests too, so it is installed last (outermost).
    app = app.layer(axum::middleware::from_fn(cors_middleware));
    // NIP-86 `blockip` applies to every route on this listener (API,
    // Blossom, health/metrics/stats, NIP-11 and the WebSocket/RPC
    // endpoint), not only the WebSocket handler. The peer address is
    // injected as `ConnectInfo` by `serve_limited`.
    let blocked_relay = relay.clone();
    app = app.layer(axum::middleware::from_fn(
        move |req: Request, next: Next| {
            let relay = blocked_relay.clone();
            async move {
                if let Some(ip) = req
                    .extensions()
                    .get::<axum::extract::connect_info::ConnectInfo<std::net::SocketAddr>>()
                    .map(|info| info.0.ip())
                    && relay.access.read().await.is_ip_blocked(ip)
                {
                    // Debug, not WARN: a blocked peer can reconnect as fast
                    // as it likes, so a warning here would flood the log. The
                    // counter moves on every refusal.
                    log::debug!("refused {ip}: blocked by NIP-86 blockip");
                    relay.stats.bump(&relay.stats.conn_refused_blocked, 1);
                    return StatusCode::FORBIDDEN.into_response();
                }
                next.run(req).await
            }
        },
    ));
    app.with_state(relay.clone())
}

/// The paths serving the WebSocket/NIP-11/NIP-86 endpoint for a
/// `server.ws_paths` value. Unknown values fall back to the default root
/// path (the config validation rejects them, but the router must stay
/// safe even on an unvalidated reload path).
fn ws_paths_for(mode: &str) -> &'static [&'static str] {
    match mode {
        "inbox-outbox" => &["/inbox", "/outbox"],
        "all" => &["/", "/inbox", "/outbox"],
        _ => &["/"],
    }
}

/// Normalizes a configured split hostname (api_host / blossom.host):
/// lowercase, with IPv6 brackets stripped so it compares equal to the
/// normalized request Host (`[::1]` -> `::1`).
fn normalize_host(host: &str) -> String {
    host.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase()
}

/// The host part of an HTTP Host header value: strips an IPv6 literal's
/// brackets (`[::1]:8080` -> `::1`) or splits a DNS/IPv4 host from its
/// optional `:port` suffix (`relay.example.com:8080` -> `relay.example.com`).
fn host_header_host(header: &str) -> &str {
    let h = header.trim();
    if let Some(rest) = h.strip_prefix('[') {
        // IPv6 literal: the host ends at the closing bracket.
        rest.split(']').next().unwrap_or(rest)
    } else {
        // DNS name or IPv4 address: everything before the first ':'.
        h.split(':').next().unwrap_or(h)
    }
}

async fn host_split(api_host: &str, blossom_host: &str, request: Request, next: Next) -> Response {
    let host = request
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(host_header_host)
        .map(str::to_ascii_lowercase)
        .or_else(|| {
            // HTTP/2 (including h2c) carries the authority in the request
            // URI instead of a Host header: without the fallback every
            // h2 request looks host-less and the split routes 404.
            request
                .uri()
                .authority()
                .map(|authority| authority.host().to_ascii_lowercase())
        })
        .unwrap_or_default();
    if host_route_allowed(api_host, blossom_host, &host, request.uri().path()) {
        next.run(request).await
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

/// Decides whether a request (host + path) may reach the next handler:
/// the `api_host` serves only the API paths, the `blossom.host` serves only
/// the Blossom routes, and every other host serves only the relay endpoints.
/// API paths are relay-side when `api_host` is unset (so `restrict_uploads` /
/// blossom alone never hides `/health`, `/metrics` or `/api/v1`).
fn host_route_allowed(api_host: &str, blossom_host: &str, host: &str, path: &str) -> bool {
    let is_api = !api_host.is_empty() && host == api_host;
    let is_blossom = !blossom_host.is_empty() && host == blossom_host;
    let is_relay = !is_api && !is_blossom;
    let api_path = !api_host.is_empty()
        && (path.starts_with("/api/v1") || path == "/health" || path == "/metrics");
    // The root `/` is dispatched by the WS handler (relay info or Blossom
    // server info), so it must pass through on the Blossom host too.
    let blossom_path = blossom::is_blossom_path(path) || (is_blossom && path == "/");
    (is_api && api_path) || (is_blossom && blossom_path) || (is_relay && !api_path && !blossom_path)
}

/// Restores the persisted NIP-29 group state at startup, comparing the
/// snapshot's stamp and sequence against the database's current group-state
/// generation (`DbClient::state_stamp`, `DbClient::state_seq_group`). A
/// snapshot from before a group-state removal (stamp) or group-state event
/// (group seq) must not be restored (it would resurrect state a purge/vanish
/// invalidated, or predate an accepted event), and a generation the database
/// cannot answer is treated the same way: fail closed and rebuild from the
/// surviving events. A NIP-43 role event no longer invalidates the group
/// snapshot (the per-family sequence). A legacy snapshot (stamp and seq 0)
/// is accepted while both counters are still 0. The rebuild path only runs
/// when the NIP is enabled; with NIP-29 disabled the store stays empty
/// exactly as when no snapshot exists (the next start with the NIP
/// re-enabled rebuilds).
async fn restore_group_state(relay: &Relay, groups_enabled: bool) -> Result<()> {
    let snapshot = match relay.db.load_groups().await {
        crate::db::LoadGroupsOutcome::Loaded(snapshot) => snapshot,
        crate::db::LoadGroupsOutcome::Missing => {
            return rebuild_group_state(relay, groups_enabled).await;
        }
        crate::db::LoadGroupsOutcome::Failed => {
            // The store would start empty, and every unknown group id
            // reads as public: refuse to start rather than expose private
            // group content, regardless of the NIP toggle.
            return Err(anyhow::anyhow!(
                "cannot read the persisted NIP-29 group snapshot; refusing to start with an \
                 empty group store (missing groups would expose private content)"
            ));
        }
    };
    let stamp = relay.db.state_stamp().await;
    let seq = relay.db.state_seq_group().await;
    match (stamp, seq) {
        (Some(stamp), Some(seq)) => {
            if relay
                .groups
                .write()
                .await
                .restore_checked(snapshot, stamp, seq)
            {
                info!("NIP-29 group state restored from the database snapshot");
                return Ok(());
            }
            error!(
                "the persisted NIP-29 group snapshot predates the database's group-state \
                 generation (stamp {stamp}, seq {seq}); refusing to restore it and rebuilding \
                 from the surviving events instead"
            );
        }
        _ => {
            // The generation is unknown, so the snapshot's currency cannot
            // be established: restoring it could resurrect state a removal
            // invalidated.
            error!(
                "cannot read the database's group-state generation; refusing to restore the \
                 persisted NIP-29 group snapshot and rebuilding from the surviving events"
            );
        }
    }
    rebuild_group_state(relay, groups_enabled).await
}

/// The replay/rebuild migration of [`restore_group_state`]: replays the
/// stored moderation events and persists the result so later restarts skip
/// the replay. A failed rebuild is fatal: starting with an incomplete
/// group store would expose private/hidden content.
async fn rebuild_group_state(relay: &Relay, groups_enabled: bool) -> Result<()> {
    if !groups_enabled {
        // The replay migration only runs when the NIP is enabled (see the
        // caller). The store stays empty, the fail-closed state when no
        // snapshot is available; a start with NIP-29 re-enabled rebuilds.
        warn!(
            "NIP-29 group state was not restored and NIP-29 is disabled; the group store \
             starts empty until the NIP is re-enabled and the relay restarts"
        );
        return Ok(());
    }
    if !relay
        .groups
        .write()
        .await
        .rebuild(&relay.db, relay.relay_pubkey_ref())
        .await
    {
        return Err(anyhow::anyhow!(
            "NIP-29 group state rebuild failed: refusing to start with an \
             incomplete group store (missing groups would expose private content)"
        ));
    }
    // The rebuilt state has no (or stale) relay-signed metadata: publish the
    // current 39000/39001/39002/39005 for every group so clients can see
    // them (a migrated database never had them).
    relay.publish_group_metadata().await;
    relay.persist_groups().await;
    Ok(())
}

/// The startup NIP-29 sequence, run before the relay accepts traffic:
/// restore or rebuild the group state, then complete (or confirm) every
/// interrupted `kind:9008` purge so a ghosted group is either fully purged
/// or stays fail-closed, and publish the remaining pending count on the
/// metrics. A failed rebuild is fatal (see [`rebuild_group_state`]).
async fn startup_group_state(relay: &Relay, groups_enabled: bool) -> Result<()> {
    restore_group_state(relay, groups_enabled).await?;
    // Crash recovery for kind:9008 group purges: a purge accepted but not
    // finished (the process crashed mid-walk) is re-run here, before the
    // relay serves. Idempotent and a no-op when nothing is pending.
    relay.resume_pending_purges().await;
    // Surface the resume outcome on the metrics: after the resume the
    // pending table should be empty, and a non-zero gauge means a recorded
    // purge could not be completed (the group stays fail-closed until the
    // next restart retries).
    if let Some(pending) = relay.db.pending_purges().await {
        relay
            .stats
            .pending_purges
            .store(pending.len() as u64, std::sync::atomic::Ordering::Relaxed);
    }
    Ok(())
}

/// The startup NIP-43 sequence: restore the persisted role snapshot or
/// rebuild from the surviving events.
///
/// The snapshot's stamp and sequence are compared against the database's
/// state generation (`DbClient::state_stamp`, `DbClient::state_seq_role`):
/// a NIP-09 deletion of a role-state event (stamp) or a role-state event
/// itself (role seq) advances them, so a snapshot from before such a change
/// must not be restored (it would resurrect a deleted grant or predate a
/// state event). A NIP-29 group event no longer invalidates the role
/// snapshot (the per-family sequence), and an unreadable generation fails
/// closed the same way. Both cases fall through to the replay migration,
/// which rebuilds from the surviving events. A failed rebuild is fatal.
async fn restore_role_state(relay: &Relay) -> Result<()> {
    if !relay.config.read().await.nip_enabled(43) {
        return Ok(());
    }
    let needs_rebuild = match relay.db.load_roles().await {
        crate::db::LoadRolesOutcome::Loaded(snap) => match (
            relay.db.state_stamp().await,
            relay.db.state_seq_role().await,
        ) {
            (Some(stamp), Some(seq)) => {
                if relay.roles.write().await.restore_checked(snap, stamp, seq) {
                    info!("NIP-43 role state restored from the database snapshot");
                    false
                } else {
                    error!(
                        "the persisted NIP-43 role snapshot predates the database's state \
                         generation (stamp {stamp}, seq {seq}); refusing to restore it and \
                         rebuilding from the surviving events instead"
                    );
                    true
                }
            }
            _ => {
                // The generation is unknown, so the snapshot's currency
                // cannot be established: restoring it could resurrect a
                // deleted grant.
                error!(
                    "cannot read the database's state generation; refusing to restore \
                     the persisted NIP-43 role snapshot and rebuilding from the \
                     surviving events"
                );
                true
            }
        },
        crate::db::LoadRolesOutcome::Missing => true,
        crate::db::LoadRolesOutcome::Failed => {
            // An empty role store revokes every grant: refuse to start
            // rather than silently unauthorize the relay's own moderation.
            return Err(anyhow::anyhow!(
                "cannot read the persisted NIP-43 role snapshot; refusing to start with \
                 an empty role store"
            ));
        }
    };
    if needs_rebuild {
        if !relay
            .roles
            .write()
            .await
            .rebuild(&relay.db, &relay.relay_pubkey().unwrap_or_default())
            .await
        {
            return Err(anyhow::anyhow!(
                "NIP-43 role state rebuild failed: refusing to start with an \
                 incomplete role store"
            ));
        }
        // The rebuilt store has no (or stale) published membership list:
        // republish it so NIP-43 clients see the current members (a
        // migrated database never had it). Publish before the snapshot
        // persist: storing the 13534 event advances the role-state
        // sequence, and the snapshot must carry the post-publish
        // generation.
        if !relay.publish_membership(None).await {
            warn!("could not republish the NIP-43 membership list after the rebuild");
        }
        relay.persist_roles().await;
    }
    Ok(())
}

pub async fn run_server(
    config_path: PathBuf,
    config: Config,
    db: DbClient,
    signals: StartupSignals,
) -> Result<()> {
    // The signals were registered by the CLI before the database was opened
    // (see `StartupSignals`): the handler tasks below consume the streams,
    // and anything received in between is buffered by the tokio driver.
    let StartupSignals {
        terminate,
        interrupt,
        hangup,
    } = signals;
    let pid_file = config.daemon.pid_file.clone();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    // Detached on purpose: the supervisor's bounded join would abort it
    // mid-shutdown, and the second-signal escalation must stay armed until
    // the process actually exits (see `signal_handler`).
    let _signal_task = tokio::spawn(signal_handler(
        terminate,
        interrupt,
        shutdown_tx.clone(),
        Some(pid_file),
    ));
    let private_key = config.relay.private_key.clone();
    let live = crate::relay::LiveBusConfig {
        buffer: config.limits.live_buffer,
        batch_interval_ms: config.limits.live_batch_interval_ms,
        batch_size: config.limits.live_batch_size,
    };
    let config = Arc::new(tokio::sync::RwLock::new(config));
    let stats = Stats::new();
    let mut relay = Arc::new(Relay::new(config, db, stats, &private_key, live).await);
    match Arc::get_mut(&mut relay) {
        Some(relay) => relay.start_live_bus(),
        // Unreachable today (nothing cloned the Arc yet): fail soft instead
        // of panicking at startup if a future change adds a clone.
        None => log::error!("relay was already cloned; live bus not started"),
    }
    // Make the config file path known to the relay so NIP-86 runtime
    // changes (relay name/description/icon) can be persisted to disk.
    *relay.config_path.write().await = Some(config_path.clone());
    // The SIGHUP handler is registered early too (see above); the task can
    // run as soon as the relay exists, before the long state restore.
    let reload_task = tokio::spawn(reload_handler(
        config_path,
        relay.clone(),
        relay.db.clone(),
        relay.api_limit.clone(),
        shutdown_rx.clone(),
        hangup,
    ));
    // Startup barrier: the database's synchronous recovery may have removed
    // a NIP-29/NIP-43 state event while resuming interrupted deletions. The
    // relay marks its derived stores stale here, before any snapshot is
    // restored or rebuilt, so a recovered removal cannot be resurrected by
    // the startup state load (the persistent generation was bumped too, but
    // the fail-closed marking is what keeps the pending background rebuild
    // from certifying stale state).
    relay.recovery_done().await;

    // Restore the NIP-29 group state from the persisted snapshot. Only
    // when no snapshot was ever written (pre-persistence database) fall
    // back to replaying the stored moderation events, then persist the
    // result so later restarts skip the replay.
    // The group store gates read visibility (private/hidden groups) even
    // when NIP-29 is disabled: restoring the persisted snapshot must not
    // depend on the toggle, or disabling the NIP would make stored private
    // content world-readable until it is re-enabled. The replay/rebuild
    // migration only runs when the NIP is enabled.
    let groups_enabled = relay.config.read().await.nip_enabled(29);
    startup_group_state(&relay, groups_enabled).await?;
    if groups_enabled && relay.has_relay_key() {
        info!(
            "NIP-29 groups enabled (relay key {})",
            relay.relay_pubkey().unwrap_or_default()
        );
    }

    // Same lifecycle for the NIP-43 role store: snapshot first, replay
    // migration only when nothing usable was ever persisted (see
    // [`restore_role_state`]).
    restore_role_state(&relay).await?;

    let blossom_state = blossom::build_state(&relay.config.read().await.clone(), &relay).await?;
    *relay.blossom.write().await = blossom_state.clone();
    let app = build_router(&relay, blossom_state).await;

    let bind_addr = {
        let cfg = relay.config.read().await;
        (cfg.server.host.clone(), cfg.server.port)
    };
    let listener = bind_listener(&bind_addr, "relay listening on ws://").await?;

    let mut supervised: Vec<SupervisedTask> = Vec::new();

    // Supervisor: a background task that exits before shutdown would
    // silently lose its function (expiry purge, stats, discovery, SIGHUP).
    // Today that is unreachable (DB helpers return defaults, never panic),
    // but a future panic must be loud instead of silent. (The global panic
    // hook already logs the payload; the wrapper notes the loss.)
    for (name, work) in [
        (
            "stats_writer",
            Box::pin(stats_writer(relay.clone(), shutdown_rx.clone()))
                as std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
        ),
        (
            "purge_loop",
            Box::pin(purge_loop(relay.clone(), shutdown_rx.clone()))
                as std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
        ),
        (
            "nip66_publisher",
            Box::pin(nip66_publisher(relay.clone(), shutdown_rx.clone()))
                as std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
        ),
    ] {
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<bool>();
        let inner = tokio::spawn(async move {
            let panicked =
                futures_util::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(work))
                    .await
                    .is_err();
            let _ = done_tx.send(panicked);
        });
        let shutdown = shutdown_rx.clone();
        let outer = tokio::spawn(async move {
            match done_rx.await {
                Ok(false) => {
                    if !*shutdown.borrow() {
                        error!(
                            "background task {name} exited unexpectedly; its function is lost until restart"
                        );
                    }
                }
                // Panicked: the payload is in the panic log (the global
                // hook logs it before the unwind is caught), so keep the
                // word `panicked` here too — monitors match on it.
                Ok(true) => {
                    if !*shutdown.borrow() {
                        error!(
                            "background task {name} panicked; see the panic log for the payload, \
                             its function is lost until restart"
                        );
                    }
                }
                // The sender was dropped without a report: the shutdown
                // bound aborted the inner task. Loud outside shutdown,
                // quiet when the shutdown bound did it.
                Err(_) => {
                    if !*shutdown.borrow() {
                        error!(
                            "background task {name} ended without completing; its function is lost until restart"
                        );
                    }
                }
            }
        });
        supervised.push(SupervisedTask { outer, inner });
    }
    // Spawned before the startup work (see the top of `run_server`) and
    // kept out of the abortable set so its second-signal escalation
    // stays armed.
    let mut tasks = Vec::new();
    {
        let shutdown = shutdown_rx.clone();
        let handle = reload_task;
        tasks.push(tokio::spawn(async move {
            match handle.await {
                Ok(()) => {
                    if !*shutdown.borrow() {
                        error!(
                            "background task reload_handler exited unexpectedly; its function is lost until restart"
                        );
                    }
                }
                Err(e) => {
                    error!(
                        "background task reload_handler panicked: {e}; its function is lost until restart"
                    );
                }
            }
        }));
    }

    let (
        header_timeout,
        max_connections,
        max_connections_per_ip,
        per_sec_per_ip,
        trusted_proxies,
        recv_buf_kb,
    ) = {
        let cfg = relay.config.read().await;
        (
            // 0 = disabled (the documented convention): hyper treats
            // `Some(Duration::ZERO)` as an immediate timeout, so the
            // config value is mapped to `None` here.
            (cfg.limits.http_read_timeout_secs > 0)
                .then(|| std::time::Duration::from_secs(cfg.limits.http_read_timeout_secs)),
            cfg.limits.max_connections,
            cfg.limits.max_connections_per_ip,
            IpConnLimiter::new(cfg.limits.max_connections_per_sec_per_ip).map(Arc::new),
            // Validation already rejected malformed entries; a stray
            // unparsable one (unvalidated reload path) is simply not trusted
            // (fail closed).
            std::sync::Arc::<[TrustedProxy]>::from(
                cfg.server
                    .trusted_proxies
                    .iter()
                    .filter_map(|entry| TrustedProxy::parse(entry))
                    .collect::<Vec<_>>(),
            ),
            cfg.limits.socket_recv_buffer_kb,
        )
    };
    let _ = serve_limited(
        listener,
        app,
        max_connections,
        max_connections_per_ip,
        header_timeout,
        per_sec_per_ip,
        trusted_proxies,
        recv_buf_kb,
        relay.stats.clone(),
        shutdown_rx,
    )
    .await;

    let _ = shutdown_tx.send(true);
    // Signal the WebSocket drain before joining the background tasks: the
    // WS teardown then overlaps the joins instead of running after them, so
    // the total shutdown stays close to the longest single step. The
    // database stays up until the drain wait below ends.
    relay.signal_drain();
    // Bound the background-task joins: a task stuck in a long database walk
    // (e.g. a mid-flight `purge_expired`) must not delay the process exit
    // without limit. Aborting drops the loop at its next await point; the
    // database is stopped afterwards. Both sets join concurrently so the
    // phase stays within a single grace (the `SHUTDOWN_BUDGET` phase
    // accounting counts it once).
    let join_grace = TASK_JOIN_GRACE;
    let (tasks_done, supervised_done) = tokio::join!(
        join_tasks_bounded(&mut tasks, join_grace),
        join_supervised_bounded(&mut supervised, join_grace)
    );
    if !tasks_done {
        warn!(
            "background tasks did not stop within {}s; aborted them",
            join_grace.as_secs()
        );
    }
    if !supervised_done {
        warn!(
            "supervised tasks did not stop within {}s; aborted them",
            join_grace.as_secs()
        );
    }
    // Graceful WebSocket drain: the upgraded connection tasks are detached
    // from the HTTP connections `serve_limited` tracks, so signal them
    // explicitly and give them a bounded window to flush their pending
    // event batches before the database is stopped. Without this wait the
    // process would exit with accepted-but-uncommitted events (and no OKs).
    // The window covers the WebSocket teardown grace (5 s, see
    // `ws::handler`) plus a margin for the final flush and close.
    // `SHUTDOWN_BUDGET` covers this phase for the `nostrfy stop` timeout.
    let ws_deadline = std::time::Instant::now() + WS_DRAIN_GRACE;
    while relay
        .stats
        .connections_active
        .load(std::sync::atomic::Ordering::Relaxed)
        > 0
        && std::time::Instant::now() < ws_deadline
    {
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    relay.db.shutdown();
    info!("relay stopped");
    Ok(())
}

#[cfg(test)]
async fn await_shutdown(mut rx: watch::Receiver<bool>) {
    while !*rx.borrow() {
        if rx.changed().await.is_err() {
            break;
        }
    }
}

/// Awaits every background-task handle with a bound. Returns `true` when all
/// finished within `grace`; on expiry the tasks are aborted, so a task stuck
/// in a long database walk (e.g. a mid-flight `purge_expired`) cannot delay
/// the shutdown without limit. Aborting drops the task at its next await
/// point.
async fn join_tasks_bounded(
    tasks: &mut [tokio::task::JoinHandle<()>],
    grace: std::time::Duration,
) -> bool {
    let joined = tokio::time::timeout(grace, async {
        for task in tasks.iter_mut() {
            let _ = task.await;
        }
    })
    .await;
    if joined.is_err() {
        for task in tasks.iter() {
            task.abort();
        }
    }
    joined.is_ok()
}

/// A background task paired with its supervisor wrapper. The wrapper only
/// observes completion and logs unexpected exits; the shutdown bound must
/// abort the inner handle. Aborting a wrapper alone would merely detach
/// the inner task, which would keep running (and using the database) past
/// the bound the shutdown budget promises.
struct SupervisedTask {
    outer: tokio::task::JoinHandle<()>,
    inner: tokio::task::JoinHandle<()>,
}

/// Awaits every supervised task's observer with a bound. Returns `true`
/// when all finished within `grace`; on expiry the shutdown aborts the
/// *inner* tasks — aborting only the observer would detach the real work,
/// which would keep running (and using the database) past the bound.
/// Aborting the observers too keeps no handle behind.
async fn join_supervised_bounded(tasks: &mut [SupervisedTask], grace: std::time::Duration) -> bool {
    let joined = tokio::time::timeout(grace, async {
        for task in tasks.iter_mut() {
            let _ = (&mut task.outer).await;
        }
    })
    .await;
    if joined.is_err() {
        for task in tasks.iter() {
            task.inner.abort();
        }
        for task in tasks.iter_mut() {
            task.outer.abort();
        }
    }
    joined.is_ok()
}

/// Returns `true` when the request is a valid WebSocket handshake: the
/// standard upgrade headers must be present (`Upgrade: websocket`,
/// `Connection: upgrade`, `Sec-WebSocket-Version: 13` and a non-empty
/// `Sec-WebSocket-Key`), and a proxy-provided `X-Forwarded-Proto` must name
/// a WebSocket-capable scheme (`ws`/`wss`, or `http`/`https` when the proxy
/// terminates TLS). Anything else is a plain HTTP request.
fn is_websocket_request(headers: &HeaderMap) -> bool {
    let upgrade = headers
        .get(axum::http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    let connection = headers
        .get(axum::http::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.to_ascii_lowercase()
                .split(',')
                .any(|t| t.trim() == "upgrade")
        })
        .unwrap_or(false);
    let version = headers
        .get(axum::http::header::SEC_WEBSOCKET_VERSION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v == "13")
        .unwrap_or(false);
    let key = headers
        .get(axum::http::header::SEC_WEBSOCKET_KEY)
        .and_then(|v| v.to_str().ok())
        .map(|v| !v.is_empty())
        .unwrap_or(false);
    if !(upgrade && connection && version && key) {
        return false;
    }
    // Behind a proxy the request scheme is announced with
    // X-Forwarded-Proto. The value is the scheme the client used to reach
    // the proxy: `wss`/`ws` for a direct WebSocket connection, or
    // `https`/`http` when the proxy terminates TLS (e.g. Cloudflare
    // Tunnel), in which case the WebSocket upgrade is decided by the
    // upgrade headers alone.
    match headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
    {
        // The header carries one value per proxy hop, comma-separated: the
        // handshake is recognized when any token names a WebSocket-capable
        // scheme, so a value appended by another hop cannot disable the
        // WebSocket detection.
        Some(proto) => proto
            .to_ascii_lowercase()
            .split(',')
            .any(|t| matches!(t.trim(), "ws" | "wss" | "http" | "https")),
        None => true,
    }
}

/// Rejects WebSocket upgrade requests, returning 403 Forbidden.
/// Applied as a layer to `/api/v1` routes so that they are only
/// accessible over plain HTTP/HTTPS.
async fn reject_ws_upgrade(request: Request, next: Next) -> Response {
    if is_websocket_request(request.headers()) {
        return StatusCode::FORBIDDEN.into_response();
    }
    next.run(request).await
}

/// The Blossom server-info document (BUD-01) when the request Host names
/// the configured Blossom host and the storage backend initialized. On the
/// configured Blossom host the answer is 404 (never the relay's NIP-11
/// document or a WebSocket upgrade) when the storage is unavailable; `None`
/// means the Host is not the Blossom host. Used by the shared root route
/// and by the dedicated root route of the `inbox-outbox` mode, so the info
/// document stays available on the Blossom host whatever the WebSocket path
/// selection is. Takes the Host header value (not the whole request) so the
/// future never borrows the request across the await.
async fn blossom_root_info(
    relay: Arc<Relay>,
    host_header: Option<&str>,
    is_websocket: bool,
) -> Option<Response> {
    let cfg = relay.config.read().await;
    if cfg.blossom.host.trim().is_empty()
        || !blossom::host_is_blossom(&cfg.blossom.host, host_header)
    {
        return None;
    }
    // The request Host names the configured Blossom host: fail closed. The
    // `None` fall-through would serve the relay's NIP-11 document and,
    // worse, accept WebSocket upgrades on the media host when only
    // `blossom.host` is configured but the storage initialization failed
    // (no live `relay.blossom`). Answer 404 instead, upgrades included.
    // `None` is reserved for "this is not the Blossom host", so callers
    // can tell the two cases apart.
    if relay.blossom.read().await.is_none() {
        return Some(StatusCode::NOT_FOUND.into_response());
    }
    // WebSocket upgrades are never accepted on the Blossom host's root.
    if is_websocket {
        return Some(StatusCode::NOT_FOUND.into_response());
    }
    let relay_name = cfg.relay.name.trim();
    let name = if relay_name.is_empty() {
        "nostrfy".to_string()
    } else {
        relay_name.to_string()
    };
    let info = json!({
        "name": format!("{name} (media)"),
        // File-related NIPs this server implements: 94 (file-metadata
        // events are stored and served) and 98 (HTTP auth, used for the
        // uploads). NIP-96 (HTTP file storage) is a different protocol and
        // is not implemented: the file server speaks Blossom/BUD.
        "supported_nips": [94, 98],
        "supported_file_hashes": ["sha256"],
        "tos_url": null,
        "payment_required": false,
        "upload_url": format!("https://{}/upload", cfg.blossom.host.trim()),
        "max_file_size": relay
            .blossom
            .read()
            .await
            .as_ref()
            .map(|state| state.max_upload_bytes)
            .unwrap_or(cfg.blossom.max_upload_bytes),
        "storage": cfg.blossom.storage,
    });
    let mut response = Json(info).into_response();
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    Some(response)
}

/// The NIP-11 relay information document, served with `application/nostr+json`
/// when the client asked for it.
async fn nip11_doc(relay: Arc<Relay>, wants_nostr_json: bool) -> Response {
    let body = Json(relay.relay_info_document().await);
    let mut response = body.into_response();
    if wants_nostr_json {
        response.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/nostr+json"),
        );
    }
    response
}

/// The root path in `ws_paths = "inbox-outbox"` mode: only the Blossom
/// server-info answer is served (on the Blossom host); every other request
/// gets a 404, keeping the relay's WebSocket endpoint and the NIP-11
/// document exclusive to `/inbox` and `/outbox`.
async fn root_inbox_outbox(State(relay): State<Arc<Relay>>, request: Request) -> Response {
    let host_header = request
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok());
    if is_websocket_request(request.headers()) {
        return StatusCode::NOT_FOUND.into_response();
    }
    match blossom_root_info(relay, host_header, false).await {
        Some(response) => response,
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Serves the WebSocket endpoint and the NIP-11 document on the same URI:
/// valid WebSocket handshakes are upgraded, plain HTTP requests (GET with
/// no upgrade headers) receive the relay information document, per NIP-11
/// ("on the same URI as the relay's websocket").
async fn ws_handler(State(relay): State<Arc<Relay>>, request: Request) -> Response {
    // NIP-86: blockip — refuse WebSocket connections from blocked peers.
    // Kept as defense in depth even though the global middleware layer
    // covers every route (the duplicate walk is per handshake, not per
    // frame).
    if let Some(ip) = request
        .extensions()
        .get::<axum::extract::connect_info::ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0.ip())
        && relay.access.read().await.is_ip_blocked(ip)
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    // `is_websocket_request` is evaluated once: it was parsed twice per
    // request (once for the Blossom root gate, once for the NIP-11 branch).
    let is_ws = is_websocket_request(request.headers());
    // The Blossom server shares the root `/` route with the relay: when
    // the request Host names the Blossom host, the root path is answered
    // with the Blossom server info instead of the NIP-11 document (and
    // WebSocket upgrades are refused there by the host split).
    let host_header = request
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok());
    if let Some(response) = blossom_root_info(relay.clone(), host_header, is_ws).await {
        return response;
    }
    if !is_ws {
        // Not a WebSocket handshake: serve the NIP-11 info document.
        let wants_nostr_json = request
            .headers()
            .get(axum::http::header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            // Media types are case-insensitive: `APPLICATION/NOSTR+JSON`
            // must get the JSON document too.
            .is_some_and(|a| a.to_ascii_lowercase().contains("application/nostr+json"));
        return nip11_doc(relay.clone(), wants_nostr_json).await;
    }
    let path = request.uri().path().to_string();
    let (mut parts, _) = request.into_parts();
    let peer_ip = parts
        .extensions
        .get::<axum::extract::connect_info::ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0.ip());
    match WebSocketUpgrade::from_request_parts(&mut parts, &()).await {
        Ok(upgrade) => {
            // Claim the accept-layer slot for the upgraded connection
            // before the HTTP task ends: the WebSocket then holds it for
            // its whole lifetime, so the global and per-IP caps count the
            // connection exactly once. The handover is synchronous (the
            // request is still being served), so the accept guard cannot
            // have released it yet. A trusted-proxy deployment carries the
            // derived per-IP slot in the separate `ClientIpGuard`; it is
            // moved into the WebSocket task below so the slot survives the
            // HTTP request.
            let slot = parts
                .extensions
                .remove::<Arc<crate::conn::ConnSlot>>()
                .and_then(|slot| slot.handover());
            let client_slot = parts.extensions.remove::<Arc<ClientIpGuard>>();
            // Start with small read/write buffers (they grow on demand) so
            // that hundreds of thousands of idle connections do not pin
            // megabytes each.
            let cfg = relay.config.read().await;
            let max_msg = cfg.limits.max_ws_message_bytes;
            // Initial read/write buffer size per connection (grows on
            // demand); bounded so that hundreds of thousands of idle
            // connections do not pin megabytes each.
            let buffer_size = cfg.database.db_buffer_size;
            // The outgoing buffer must fit the largest relay-generated
            // message: a NIP-77 NEG-MSG response carries every id of a
            // queried range as hex (up to neg_max_items ids), plus the JSON
            // envelope. Per-id worst case: 32 bytes as 64 hex chars, with
            // range headers amortized over the emitted ranges.
            let neg_max = cfg.limits.max_neg_items;
            let max_write = max_msg.max(neg_max.saturating_mul(80).saturating_add(64 * 1024));
            drop(cfg);
            upgrade
                .read_buffer_size(buffer_size)
                .write_buffer_size(buffer_size)
                // Reject oversized frames at the protocol layer: without
                // this the WebSocket stack buffers frames of up to its own
                // 64 MiB default into memory before the application check
                // runs, letting a client pin large allocations per frame.
                .max_message_size(max_msg)
                .max_frame_size(max_msg)
                .max_write_buffer_size(max_write)
                .on_upgrade(move |socket| async move {
                    // Holds the derived per-IP slot for the whole WebSocket
                    // lifetime (released when the connection task ends).
                    let _client_slot = client_slot;
                    handle_connection(
                        socket,
                        relay,
                        peer_ip
                            .map(crate::util::normalize_ip)
                            .unwrap_or_else(|| "0.0.0.0".parse().unwrap()),
                        path,
                        slot,
                    )
                    .await
                })
                .into_response()
        }
        Err(rejection) => rejection.into_response(),
    }
}

/// `GET /health`: liveness plus a write-path check.
///
/// Liveness (is the process serving?) is always observable: the handler
/// answers while the listener accepts. The body/status additionally reports
/// whether the database is accepting writes, because a full disk or an
/// exhausted LMDB map makes the relay read-only while the process is
/// otherwise healthy — a liveness-only `200` would hide that. `503` means
/// "up but refusing writes" (disk full / map full / writer gone); it is not
/// a restart signal, reads and live delivery keep working and the relay
/// recovers on its own once space is available.
async fn health_handler(State(relay): State<Arc<Relay>>) -> Response {
    if relay.db.disk_full() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "status": "unavailable",
                "reason": "database is refusing writes: storage is full (disk or map)",
            })),
        )
            .into_response();
    }
    if relay.db.cancelled() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "status": "unavailable",
                "reason": "database writer is not accepting work",
            })),
        )
            .into_response();
    }
    (StatusCode::OK, Json(json!({ "status": "ok" }))).into_response()
}

/// Prometheus metrics endpoint: the counters in text exposition format.
async fn metrics_handler(State(relay): State<Arc<Relay>>) -> impl IntoResponse {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        relay.stats.as_prometheus(),
    )
}

async fn stats_writer(relay: Arc<Relay>, mut shutdown: watch::Receiver<bool>) {
    let secs = relay.config.read().await.daemon.stats_interval_secs.max(1);
    let mut ticker = interval(Duration::from_secs(secs));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let path = relay.config.read().await.daemon.stats_file.clone();
                relay
                    .stats
                    .db_size_bytes
                    .store(relay.db.size_on_disk().await, std::sync::atomic::Ordering::Relaxed);
                relay.stats.bump(&relay.stats.db_errors, relay.db.take_errors());
                // Overload is distinct from faults: the fail-fast paths bump
                // their own database counter, and the database itself stays
                // healthy. Polled here so a stalled writer is visible even
                // though no request completed.
                relay
                    .stats
                    .bump(&relay.stats.db_overloaded, relay.db.take_overloads());
                relay.stats.db_pending_msgs.store(
                    relay.db.pending_msgs() as u64,
                    std::sync::atomic::Ordering::Relaxed,
                );
                relay.stats.db_pending_events.store(
                    relay.db.pending_events() as u64,
                    std::sync::atomic::Ordering::Relaxed,
                );
                relay.stats.db_pending_bytes.store(
                    relay.db.pending_bytes() as u64,
                    std::sync::atomic::Ordering::Relaxed,
                );
                relay.stats.db_pending_reads.store(
                    relay.db.pending_reads() as u64,
                    std::sync::atomic::Ordering::Relaxed,
                );
                relay.stats.db_pending_read_bytes.store(
                    relay.db.pending_read_bytes() as u64,
                    std::sync::atomic::Ordering::Relaxed,
                );
                relay.stats.db_api_pending.store(
                    relay.db.api_pending() as u64,
                    std::sync::atomic::Ordering::Relaxed,
                );
                relay.stats.db_api_pending_bytes.store(
                    relay.db.api_pending_bytes() as u64,
                    std::sync::atomic::Ordering::Relaxed,
                );
                // Storage-full gauge: unlike the counters, a failed read
                // must not flip a true refusal to false, so the free-space
                // gauge keeps its last value when the store cannot answer.
                relay.stats.db_disk_full.store(
                    u64::from(relay.db.disk_full()),
                    std::sync::atomic::Ordering::Relaxed,
                );
                if let Some(free) = relay.db.free_disk_bytes() {
                    relay
                        .stats
                        .db_free_bytes
                        .store(free, std::sync::atomic::Ordering::Relaxed);
                }
                // Runtime derived-state rebuild failures (the startup rebuild
                // is fatal and never reaches this counter).
                relay
                    .stats
                    .rebuild_failures
                    .store(relay.rebuild_failures(), std::sync::atomic::Ordering::Relaxed);
                // Bookkeeping-table gauges in one read: the permanent
                // removal markers and the pending recovery queues. A failed
                // read keeps the last values (the gauges must not flip to
                // zero on a timeout), and the compatibility fields
                // (vanish_markers / pending_vanishes / pending_purges) are
                // refreshed from the same snapshot.
                if let Some(counts) = relay.db.table_counts().await {
                    relay
                        .stats
                        .vanish_markers
                        .store(counts.vanish, std::sync::atomic::Ordering::Relaxed);
                    relay
                        .stats
                        .pending_vanishes
                        .store(counts.vanish_pending, std::sync::atomic::Ordering::Relaxed);
                    relay
                        .stats
                        .pending_purges
                        .store(counts.purge_pending, std::sync::atomic::Ordering::Relaxed);
                    relay
                        .stats
                        .db_table_deleted
                        .store(counts.deleted, std::sync::atomic::Ordering::Relaxed);
                    relay
                        .stats
                        .db_table_first_seen
                        .store(counts.first_seen, std::sync::atomic::Ordering::Relaxed);
                    relay
                        .stats
                        .db_table_purged_groups
                        .store(counts.purged_groups, std::sync::atomic::Ordering::Relaxed);
                    relay
                        .stats
                        .db_table_vanish
                        .store(counts.vanish, std::sync::atomic::Ordering::Relaxed);
                    relay
                        .stats
                        .db_table_vanish_pending
                        .store(counts.vanish_pending, std::sync::atomic::Ordering::Relaxed);
                    relay
                        .stats
                        .db_table_purge_pending
                        .store(counts.purge_pending, std::sync::atomic::Ordering::Relaxed);
                    relay
                        .stats
                        .db_table_delete_pending
                        .store(counts.delete_pending, std::sync::atomic::Ordering::Relaxed);
                }
                if let Some(blossom) = relay.blossom.read().await.as_ref() {
                    relay
                        .stats
                        .blossom_orphan_spools_swept
                        .store(blossom.store.orphan_spools_swept(), std::sync::atomic::Ordering::Relaxed);
                }
                if let Ok(json) = serde_json::to_string_pretty(&relay.stats.as_json()) {
                    // The atomic write (fsync + rename) is blocking I/O:
                    // run it on the blocking pool instead of stalling an
                    // async worker.
                    let path = path.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        write_atomic(&path, json.as_bytes())
                    })
                    .await;
                }
            }
            _ = shutdown.changed() => break,
        }
    }
}

/// Writes `data` to `path` atomically (temp file + rename) so a crash in
/// the middle of a write never leaves a truncated stats file behind. The
/// temp name is unique per write: a fixed `.tmp` name let two writers
/// truncate each other's temp.
fn write_atomic(path: &Path, data: &[u8]) {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = path.with_extension(format!("{}.{nanos}.{seq}.tmp", std::process::id()));
    let result = std::fs::write(&tmp, data).and_then(|()| std::fs::rename(&tmp, path));
    if let Err(e) = result {
        error!("cannot write {}: {e}", path.display());
        let _ = std::fs::remove_file(&tmp);
    }
}

/// NIP-66: publishes the relay's own kind 30166 discovery event at startup
/// (the first interval tick fires immediately) and every `REFRESH_SECS`
/// while a relay key is configured and NIP-66 is enabled (the addressable
/// event's newest version wins, so re-publishing keeps `created_at` recent
/// for clients and monitors).
async fn nip66_publisher(relay: Arc<Relay>, mut shutdown: watch::Receiver<bool>) {
    let mut ticker = interval(Duration::from_secs(crate::nips::nip66::REFRESH_SECS));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let cfg = relay.config.read().await;
                let enabled = cfg.nip_enabled(66);
                drop(cfg);
                if !enabled {
                    continue;
                }
                let Some(pubkey) = relay.relay_pubkey() else {
                    log::debug!(
                        "nip66: no relay.private_key configured — discovery event not published"
                    );
                    continue;
                };
                let (cfg, access) = {
                    let cfg = relay.config.read().await;
                    let access = relay.access.read().await;
                    (cfg, access)
                };
                // The monotonic stamp (store_relay_event's documented
                // requirement for every relay-generated event) guarantees a
                // strictly newer created_at on each publish, so the
                // addressable slot can never be retained by a stale version
                // on an equal-timestamp id tie-break.
                let stamp = relay.stamp_floor(crate::util::unix_now());
                let mut event = crate::nips::nip66::relay_discovery_event(
                    &cfg,
                    &access,
                    &pubkey,
                    &relay.stats,
                    stamp,
                );
                drop(cfg);
                drop(access);
                match relay.store_relay_event(&mut event).await {
                    Ok(true) => log::debug!("nip66: published the relay discovery event"),
                    Ok(false) => {
                        log::warn!("nip66: stored discovery event but live delivery failed")
                    }
                    Err(()) => log::warn!("nip66: failed to store the discovery event"),
                }
            }
            _ = shutdown.changed() => break,
        }
    }
}

async fn purge_loop(relay: Arc<Relay>, mut shutdown: watch::Receiver<bool>) {
    let secs = relay
        .config
        .read()
        .await
        .database
        .purge_interval_secs
        .max(10);
    let mut ticker = interval(Duration::from_secs(secs));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                // The purge can be a long walk over the expiry index: race it
                // against the shutdown signal so a stop is not stuck behind a
                // mid-flight purge (the join timeout in `run_server` bounds
                // the worst case, but this lets a clean shutdown complete
                // promptly instead of aborting the task).
                //
                // `first_seen` rows are reaped once a pubkey is older than
                // the new-pubkey gate: it can never reject that pubkey again,
                // so the row only grows the table (0 = gate disabled = no
                // reap, the database's documented convention). Read per tick
                // so a config reload applies.
                let (now, first_seen_min_age) = {
                    let cfg = relay.config.read().await;
                    (unix_now(), cfg.relay.new_pubkey_min_age_secs)
                };
                let purge = relay.db.purge_expired(now, first_seen_min_age);
                tokio::select! {
                    (removed, state_changed) = purge => {
                        if removed > 0 {
                            info!("purged {removed} expired events");
                        }
                        if state_changed {
                            // The purge removed group/role state events
                            // (NIP-40 expiration): the derived state must
                            // not keep authorizing members whose grant
                            // expired. The rebuild is coalesced and runs in
                            // the background.
                            relay.mark_group_state_stale().await;
                        }
                    }
                    _ = shutdown.changed() => break,
                }
            }
            _ = shutdown.changed() => break,
        }
    }
}

/// Per-IP connection-rate limiter: a host may open at most
/// `max_per_sec` connections per sliding second; excess sockets are
/// refused immediately. Bounded at 10,000 tracked IPs (the map is
/// evicted, not grown, when the bound is reached).
struct IpConnLimiter {
    max_per_sec: u64,
    /// The current second. Production reads the wall clock; tests inject a
    /// controllable clock so the window behavior is deterministic (the
    /// limiter would otherwise race a second boundary: a connection at
    /// `t = 0.999` followed by one at `t = 1.001` slides the window open).
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    seen: std::sync::Mutex<SeenIps>,
}

#[derive(Default)]
struct SeenIps {
    windows: std::collections::HashMap<std::net::IpAddr, std::collections::VecDeque<u64>>,
    /// The last time the full map was walked to evict expired windows. The
    /// walk is O(10k) and the map cannot shrink within a second (every
    /// window lives one second), so pruning at most once per second keeps
    /// the per-accept cost constant while the fail-closed refusal holds.
    last_prune: u64,
}

impl IpConnLimiter {
    fn new(max_per_sec: u64) -> Option<Self> {
        Self::with_clock(max_per_sec, Arc::new(unix_now))
    }

    /// Like [`Self::new`], with an injected clock. Tests use this to make
    /// the per-second window deterministic instead of sleeping across a
    /// wall-clock boundary.
    fn with_clock(max_per_sec: u64, clock: Arc<dyn Fn() -> u64 + Send + Sync>) -> Option<Self> {
        (max_per_sec > 0).then_some(IpConnLimiter {
            max_per_sec,
            clock,
            seen: std::sync::Mutex::new(SeenIps::default()),
        })
    }

    /// Whether a connection from `ip` may be accepted now, according to the
    /// limiter's clock (the production path; tests call [`Self::allow`]
    /// with explicit timestamps).
    fn allow_now(&self, ip: std::net::IpAddr) -> bool {
        self.allow(ip, (self.clock)())
    }

    /// Whether a connection from `ip` may be accepted at `now`.
    fn allow(&self, ip: std::net::IpAddr, now: u64) -> bool {
        const MAX_TRACKED_IPS: usize = 10_000;
        let mut seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
        // Already-tracked ips are always enforced: a full map can never
        // disable the limit for tracked ips.
        if let Some(window) = seen.windows.get_mut(&ip) {
            while window.front().is_some_and(|t| now.saturating_sub(*t) >= 1) {
                window.pop_front();
            }
            if window.len() >= self.max_per_sec as usize {
                return false;
            }
            window.push_back(now);
            return true;
        }
        // New ip: never clear the whole map (a clear would reset every
        // window and permanently disable the per-IP limit): expired
        // windows are evicted first, at most once per second (the retain
        // walks up to 10k entries; doing it on every accept while the map
        // is full turned a capacity probe into a per-connection pause). A
        // still-full map refuses the new ip (fail closed): passing it
        // through let a host with more than MAX_TRACKED_IPS addresses
        // bypass the limiter entirely.
        if seen.windows.len() >= MAX_TRACKED_IPS {
            if now.saturating_sub(seen.last_prune) >= 1 {
                seen.last_prune = now;
                seen.windows
                    .retain(|_, w| w.front().is_some_and(|t| now.saturating_sub(*t) < 1));
            }
            if seen.windows.len() >= MAX_TRACKED_IPS {
                return false;
            }
        }
        seen.windows.entry(ip).or_default().push_back(now);
        true
    }
}

/// A per-IP connection slot acquired at the request layer for a trusted
/// proxy peer (the client address is only known once the request head has
/// been read). Released when the request ends, or moved into the detached
/// WebSocket task by `ws_handler` so the upgraded connection keeps its slot
/// for its whole lifetime.
struct ClientIpGuard {
    counter: Arc<crate::conn::IpConnCounter>,
    ip: std::net::IpAddr,
}

impl Drop for ClientIpGuard {
    fn drop(&mut self) {
        self.counter.release(self.ip);
    }
}

/// Serves the main listener with the HTTP-layer hardening: a cap on
/// concurrent connections (`limits.max_connections`) and a per-IP
/// concurrent cap (`limits.max_connections_per_ip`), both also enforced on
/// plain HTTP (not only WebSocket upgrades), an optional per-IP connection
/// rate limit, and an HTTP/1.1 header read timeout that closes slow-loris
/// sockets that never complete a request head. On shutdown the accept
/// loop stops, active connections get a graceful-shutdown signal, and
/// stragglers are aborted after a bounded grace period.
///
/// When `trusted_proxies` is non-empty, a connection whose TCP peer
/// matches one is a reverse proxy: its per-IP accounting uses the client
/// address from `X-Forwarded-For` (the per-request middleware below, since
/// the header is only known with the request head), so a proxy deployment
/// is not capped at `max_connections_per_ip` under the proxy's single
/// address. Untrusted peers keep the accept-time accounting on their own
/// address, and their header is ignored (fail closed).
#[allow(clippy::too_many_arguments)]
async fn serve_limited(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    max_connections: usize,
    max_per_ip: usize,
    header_timeout: Option<std::time::Duration>,
    per_sec_per_ip: Option<Arc<IpConnLimiter>>,
    trusted_proxies: Arc<[TrustedProxy]>,
    recv_buf_kb: u32,
    stats: Arc<Stats>,
    mut shutdown: watch::Receiver<bool>,
) {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let active = Arc::new(AtomicUsize::new(0));
    let ip_counter = Arc::new(crate::conn::IpConnCounter::default());
    let (drain_tx, drain_rx) = watch::channel(());
    // Connection task handles, used to abort stragglers at shutdown. The
    // vector is pruned of finished handles above 1024 entries, so a
    // long-running relay cannot grow it without bound.
    let mut conn_tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    // Accepts since the last prune: scanning the whole handle vector on
    // every accept is O(live connections) per connection (~1 ms at 10k
    // conns), which stalls the accept loop exactly when a burst needs it
    // fastest. Pruning at most once per 128 accepts keeps the amortized
    // cost constant while still bounding the vector.
    let mut accepts_since_prune = 0usize;

    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => {
                let Ok((stream, peer)) = accepted else {
                    // An accept error (e.g. EMFILE with exhausted file
                    // descriptors) would otherwise spin the loop hot; back
                    // off briefly so the relay keeps serving existing
                    // connections while the OS recovers.
                    stats.bump(&stats.accept_errors, 1);
                    warn_refusal("accept() failed; backing off — the relay keeps serving existing connections (check the file-descriptor limit)");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                };
                // The address is normalized like every other per-IP
                // accounting: a dual-stack listener reports IPv4 peers as
                // ::ffff:a.b.c.d, which must not dodge the caps. IPv6
                // peers are aggregated by /64 so one host cannot rotate
                // suffixes to dodge them.
                let raw_ip = normalize_ip(peer.ip());
                // A peer matching `server.trusted_proxies` is a reverse
                // proxy: its own address must not consume the per-IP caps
                // (every client shares it), so the per-IP checks run in the
                // request middleware under the forwarded client address.
                let trusted = trusted_proxies.iter().any(|proxy| proxy.contains(raw_ip));
                let accounting = accounting_ip(raw_ip);
                if !trusted {
                    // Per-IP connection rate limit (slow-loris / socket flood).
                    if let Some(limiter) = &per_sec_per_ip
                        && !limiter.allow_now(accounting)
                    {
                        stats.bump(&stats.conn_refused_rate, 1);
                        warn_refusal(
                            "connections refused by limits.max_connections_per_sec_per_ip \
                             (per-IP connection rate limit)",
                        );
                        continue;
                    }
                }
                // Connection cap: refuse the socket outright at the cap so
                // established-but-idle sockets cannot pin file descriptors.
                if active.load(Ordering::Relaxed) >= max_connections {
                    stats.bump(&stats.conn_refused_global, 1);
                    warn_refusal(
                        "connections refused at limits.max_connections (global connection cap)",
                    );
                    continue;
                }
                // Per-IP concurrent cap: plain HTTP connections count too,
                // not only WebSocket upgrades. The slot is released by the
                // task guard on every exit path (including a panic), or by
                // the WebSocket layer after a handover.
                if !trusted && !ip_counter.try_acquire(accounting, max_per_ip) {
                    stats.bump(&stats.conn_refused_per_ip, 1);
                    warn_refusal(
                        "connections refused at limits.max_connections_per_ip \
                         (per-IP concurrent connection cap)",
                    );
                    continue;
                }
                active.fetch_add(1, Ordering::Relaxed);
                // The accept-layer slot for this connection: the global and
                // per-IP counts stay reserved until the HTTP task ends, or
                // until a WebSocket upgrade hands the slot over to the
                // detached WebSocket task (`crate::conn::ConnSlot`). For a
                // trusted proxy only the global count is reserved here (the
                // middleware acquires the per-IP slot under the forwarded
                // address); releasing the never-acquired peer key is a
                // no-op.
                let slot = crate::conn::ConnSlot::new(
                    Arc::clone(&active),
                    Arc::clone(&ip_counter),
                    accounting,
                );

                // Keep per-connection kernel buffers small so that hundreds
                // of thousands of idle connections do not pin gigabytes of
                // kernel memory (see the same tuning in `ws_handler`).
                // The receive buffer follows `limits.socket_recv_buffer_kb`
                // (default 64 KiB; the kernel may double it) so a fast
                // publisher's burst absorbs into one batch while the relay
                // commits; the send buffer stays 16 KiB (the outgoing path
                // flushes eagerly). The receive buffer only consumes real
                // memory while data is actually queued, so idle
                // connections cost nothing.
                let _ = stream.set_nodelay(true);
                unsafe {
                    set_sock_opt(
                        &stream,
                        libc::SO_RCVBUF,
                        i32::try_from(recv_buf_kb.saturating_mul(1024)).unwrap_or(i32::MAX),
                    );
                    set_sock_opt(&stream, libc::SO_SNDBUF, 16 * 1024);
                }

                let app = app.clone();
                let mut drain_rx = drain_rx.clone();
                let io = hyper_util::rt::TokioIo::new(stream);
                // Inject the client address as ConnectInfo (the axum
                // `ConnectInfo` extractor reads this extension) and the
                // accept-layer slot. For an untrusted peer the client is the
                // peer itself; for a trusted proxy it is derived from
                // `X-Forwarded-For` (falling back to the peer). The
                // middleware also enforces the per-IP caps for trusted
                // proxy peers, where the real client address is available.
                // The WebSocket handler removes and takes over the slot when
                // the request upgrades, so the WS connection keeps exactly
                // one reserved slot (no second counter, no double release).
                let slot_handle = Arc::clone(&slot);
                let proxies = Arc::clone(&trusted_proxies);
                let per_sec = per_sec_per_ip.clone();
                let ip_counter_handle = Arc::clone(&ip_counter);
                let stats_handle = Arc::clone(&stats);
                let svc = app.layer(axum::middleware::from_fn(
                    move |mut req: axum::extract::Request,
                          next: axum::middleware::Next| {
                        let peer = peer;
                        let slot = Arc::clone(&slot_handle);
                        let proxies = Arc::clone(&proxies);
                        let per_sec = per_sec.clone();
                        let ip_counter = Arc::clone(&ip_counter_handle);
                        let stats = Arc::clone(&stats_handle);
                        async move {
                            let raw_ip = normalize_ip(peer.ip());
                            let client = if trusted {
                                client_ip(
                                    raw_ip,
                                    req.headers()
                                        .get("x-forwarded-for")
                                        .and_then(|value| value.to_str().ok()),
                                    &proxies,
                                )
                            } else {
                                raw_ip
                            };
                            req.extensions_mut().insert(axum::extract::ConnectInfo(
                                std::net::SocketAddr::new(client, peer.port()),
                            ));
                            let mut request_guard = None;
                            if trusted {
                                // The accept layer skipped the per-IP caps
                                // for this proxy; enforce them under the
                                // real client address (aggregated by /64 for
                                // IPv6). A refused request is answered with
                                // 429 and `Connection: close` instead of the
                                // accept-layer drop, because the TCP socket
                                // is already established.
                                let accounting = accounting_ip(client);
                                if let Some(limiter) = &per_sec
                                    && !limiter.allow_now(accounting)
                                {
                                    stats.bump(&stats.conn_refused_proxy, 1);
                                    warn_refusal(
                                        "trusted-proxy requests refused with 429: per-IP \
                                         connection rate limit",
                                    );
                                    return StatusCode::TOO_MANY_REQUESTS.into_response();
                                }
                                if !ip_counter.try_acquire(accounting, max_per_ip) {
                                    stats.bump(&stats.conn_refused_proxy, 1);
                                    warn_refusal(
                                        "trusted-proxy requests refused with 429: per-IP \
                                         concurrent connection cap",
                                    );
                                    return StatusCode::TOO_MANY_REQUESTS.into_response();
                                }
                                // Two handles to the guard: one in the
                                // request extensions (removed and moved into
                                // the WebSocket task by `ws_handler`) and one
                                // held here. The extension clone alone is not
                                // enough: axum may drop the request parts
                                // after extraction, before a slow handler
                                // ends, which would release the slot early.
                                let guard = Arc::new(ClientIpGuard {
                                    counter: Arc::clone(&ip_counter),
                                    ip: accounting,
                                });
                                req.extensions_mut().insert(Arc::clone(&guard));
                                request_guard = Some(guard);
                            }
                            req.extensions_mut().insert(slot);
                            let response = next.run(req).await;
                            // Released on every exit path; for a WebSocket
                            // the extension handle keeps it alive in the
                            // upgraded connection task.
                            drop(request_guard);
                            response
                        }
                    },
                ));
                let hyper_service = hyper_util::service::TowerToHyperService::new(
                    svc.map_request(|req: hyper::Request<hyper::body::Incoming>| {
                        req.map(axum::body::Body::new)
                    }),
                );
                conn_tasks.push(tokio::spawn(async move {
                    // Releases the accept-layer slot (global and per-IP) on
                    // every exit path of this task, including a panic. A
                    // WebSocket upgrade moves the release responsibility to
                    // the detached WS task instead, so the counts are never
                    // released here while the socket is still served.
                    let _slot = crate::conn::AcceptSlotGuard::new(slot);
                    // HTTP/1 only: the auto builder's version sniff waited
                    // for up to 24 bytes before the header timer was armed,
                    // so a silent socket (or an `PRI * HTTP/2.0` prefix) was
                    // never reaped by `header_read_timeout`; HTTP/2 is also
                    // undocumented and WebSocket-over-h2 cannot be routed
                    // (the GET-only upgrade route answers CONNECT with 405).
                    let mut builder = hyper::server::conn::http1::Builder::new();
                    // Slow-loris defense: a connection must complete its
                    // request head within the window or it is closed
                    // (`None` disables the timeout — the config maps 0 to
                    // None so the documented "0 = disabled" holds). The
                    // timer is armed before the first byte is read.
                    builder
                        .timer(hyper_util::rt::TokioTimer::new())
                        .header_read_timeout(header_timeout);
                    let mut conn = std::pin::pin!(
                        builder
                            .serve_connection(io, hyper_service)
                            .with_upgrades()
                    );
                    tokio::select! {
                        result = conn.as_mut() => {
                            if let Err(e) = result {
                                log::debug!("connection {peer} ended: {e}");
                            }
                        }
                        _ = drain_rx.changed() => {
                            conn.as_mut().graceful_shutdown();
                            let _ = conn.as_mut().await;
                        }
                    }
                    // Released by `_guard` on every exit path including panic.
                }));
                // Bound the handle vector: prune the finished tasks once
                // it grows past 1024 entries (live tasks are never pruned).
                // Throttled to one scan per 128 accepts (see above): an
                // unthrottled scan is O(live) on every accept.
                accepts_since_prune += 1;
                if conn_tasks.len() > 1024 && accepts_since_prune >= 128 {
                    accepts_since_prune = 0;
                    conn_tasks.retain(|task| !task.is_finished());
                }
            }
        }
    }
    // Graceful drain: signal every connection, wait a bounded grace, then
    // abort the stragglers so shutdown never hangs on a stuck peer. The
    // grace is one phase of `SHUTDOWN_BUDGET`, which the CLI stop timeout
    // covers.
    let _ = drain_tx.send(());
    // Wait for the HTTP connection tasks to finish. The `active` count is
    // not usable here: upgraded WebSocket connections keep their slot
    // reserved until the relay's own drain signal runs (after this
    // function returns), so waiting on `active` would always burn the full
    // grace period while any WebSocket connection is open.
    tokio::time::timeout(HTTP_DRAIN_GRACE, async {
        while conn_tasks.iter().any(|task| !task.is_finished()) {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .ok();
    for task in conn_tasks {
        task.abort();
    }
}

/// The termination/reload signal streams, registered by the CLI *before*
/// the long startup work (database open and recovery, relay construction,
/// state restore, bind). `Signal` creation installs the handler; until then
/// the default action applies and a SIGHUP received during startup
/// terminates the process. Signals that arrive before the handler tasks
/// run are buffered by the tokio driver and handled as soon as it is
/// polled, so behavior after startup is unchanged.
pub(crate) struct StartupSignals {
    pub(crate) terminate: Option<tokio::signal::unix::Signal>,
    pub(crate) interrupt: Option<tokio::signal::unix::Signal>,
    pub(crate) hangup: Option<tokio::signal::unix::Signal>,
}

impl StartupSignals {
    /// Registers SIGTERM, SIGINT and SIGHUP. A registration failure is
    /// logged and leaves that signal unhandled (the others still work).
    pub(crate) fn register() -> Self {
        StartupSignals {
            terminate: register_signal(SignalKind::terminate()),
            interrupt: register_signal(SignalKind::interrupt()),
            hangup: register_signal(SignalKind::hangup()),
        }
    }
}

/// Registers one Unix signal with the tokio driver. Registration installs
/// the process-wide handler, so it must run before the long startup work:
/// until then the default action applies (a SIGHUP during startup
/// terminates the process). A registration failure is logged and leaves the
/// signal unhandled (the other signals still work).
fn register_signal(kind: SignalKind) -> Option<tokio::signal::unix::Signal> {
    match signal(kind) {
        Ok(s) => Some(s),
        Err(e) => {
            error!("cannot register {kind:?} handler: {e}");
            None
        }
    }
}

/// Awaits the next termination signal from either stream; pending forever
/// when neither could be registered.
async fn await_termination_signal(
    terminate: &mut Option<tokio::signal::unix::Signal>,
    interrupt: &mut Option<tokio::signal::unix::Signal>,
) {
    match (terminate, interrupt) {
        (Some(terminate), Some(interrupt)) => {
            tokio::select! {
                _ = terminate.recv() => {}
                _ = interrupt.recv() => {}
            }
        }
        (Some(terminate), None) => {
            let _ = terminate.recv().await;
        }
        (None, Some(interrupt)) => {
            let _ = interrupt.recv().await;
        }
        (None, None) => std::future::pending().await,
    }
}

/// Handles SIGTERM/SIGINT. The first signal starts the graceful shutdown;
/// a second one forces an immediate exit: once shutdown is under way the
/// grace windows can add up to `SHUTDOWN_BUDGET`, and an operator asking
/// twice wants out now. The pid file is removed first (the normal `Drop`
/// guards do not run on `process::exit`), so the next `start` is not
/// blocked by a stale file.
async fn signal_handler(
    mut terminate: Option<tokio::signal::unix::Signal>,
    mut interrupt: Option<tokio::signal::unix::Signal>,
    shutdown: watch::Sender<bool>,
    pid_file: Option<PathBuf>,
) {
    await_termination_signal(&mut terminate, &mut interrupt).await;
    info!("shutdown signal received");
    let _ = shutdown.send(true);
    await_termination_signal(&mut terminate, &mut interrupt).await;
    warn!("second shutdown signal received; forcing an immediate exit");
    if let Some(path) = &pid_file {
        let _ = std::fs::remove_file(path);
    }
    // SIGINT's conventional status (128 + 2); the test harness and shells
    // only need "stopped by signal", the exact value is informational.
    std::process::exit(130);
}

async fn reload_handler(
    config_path: PathBuf,
    relay: Arc<Relay>,
    db: DbClient,
    api_limit: Arc<crate::relay::ApiLimiter>,
    mut shutdown: watch::Receiver<bool>,
    hangup: Option<tokio::signal::unix::Signal>,
) {
    // `None` (registration failed, see `register_signal`) leaves the task
    // running only for the shutdown watch: the relay serves without SIGHUP
    // reload instead of the task returning and the supervisor reporting it.
    let Some(mut hangup) = hangup else {
        let _ = shutdown.changed().await;
        return;
    };
    loop {
        tokio::select! {
            _ = hangup.recv() => handle_reload(&config_path, &relay, &db, &api_limit).await,
            _ = shutdown.changed() => break,
        }
    }
}

/// Handles one SIGHUP: loads and validates the configuration file, applies
/// it when valid, and re-reads the database-backed lists on the applied and
/// the rejected path alike (a NIP-86 change committed since the last reload
/// must not be skipped just because the config edit was invalid). No config
/// lock is held across `Relay::reload_db_state`, which reads the config
/// itself: a held read guard plus a queued writer deadlocks.
async fn handle_reload(
    config_path: &Path,
    relay: &Arc<Relay>,
    db: &DbClient,
    api_limit: &Arc<crate::relay::ApiLimiter>,
) {
    match Config::load(config_path) {
        Ok(mut new_config) => {
            new_config.absolutize_paths(config_path);
            // Validate before applying: a parseable-but-invalid file (zero
            // limits, bad keys, map layout) must not silently disable the
            // relay at runtime. The old configuration stays in force on
            // failure.
            if let Err(e) = new_config.validate() {
                error!("config reload rejected: {e}");
            } else {
                // Snapshot the running config and drop the read guard before
                // applying: `apply_reloaded_config` must never hold a config
                // lock across `reload_db_state` (see the function doc).
                let old = relay.config.read().await.clone();
                apply_reloaded_config(&old, new_config, relay, db, api_limit).await;
                info!("configuration reloaded from {}", config_path.display());
            }
        }
        Err(e) => error!("config reload failed: {e}"),
    }
    // The Blossom upload allowlist and the relay pubkey deny/allow lists
    // live in the database: re-read them on every reload (a failed load
    // keeps the previous lists — see `Relay::reload_db_state`).
    relay.reload_db_state().await;
}

/// Applies a validated, reloaded config to the live relay: live settings
/// take effect, startup-only settings keep their running value (the router,
/// accept loop and database environment cannot be rebuilt), and the
/// database-backed lists are re-read by the caller. `old` is the running
/// config snapshot taken by value so no read guard can be alive while the
/// new config is written or while `reload_db_state` reads the config.
async fn apply_reloaded_config(
    old: &Config,
    mut new_config: Config,
    relay: &Arc<Relay>,
    db: &DbClient,
    api_limit: &Arc<crate::relay::ApiLimiter>,
) {
    // The relay's signing key is fixed at startup: a reloaded private_key
    // is not applied (NIP-29/NIP-43 keep signing and NIP-11 `self` keeps
    // advertising the old key). Warn so the operator knows a restart is
    // required for it to take effect.
    if old.relay.private_key != new_config.relay.private_key {
        warn!(
            "relay.private_key changed in the reloaded config but is fixed \
             at startup; a restart is required to apply it"
        );
    }
    // Settings that shape the HTTP router are fixed at
    // startup: a reload cannot rebuild the routes. A
    // change is warned about and the running value is
    // kept below (restart required), so the in-memory
    // config never lies about the wire behavior.
    let static_routes = [
        (
            "server.api_host",
            old.server.api_host != new_config.server.api_host,
        ),
        ("server.host", old.server.host != new_config.server.host),
        ("server.port", old.server.port != new_config.server.port),
        (
            "server.ws_paths",
            old.server.ws_paths != new_config.server.ws_paths,
        ),
        (
            "server.trusted_proxies",
            old.server.trusted_proxies != new_config.server.trusted_proxies,
        ),
        (
            "server.metrics_enabled",
            old.server.metrics_enabled != new_config.server.metrics_enabled,
        ),
        (
            "relay.livekit_url",
            old.relay.livekit_url != new_config.relay.livekit_url,
        ),
        (
            "relay.livekit_api_key",
            old.relay.livekit_api_key != new_config.relay.livekit_api_key,
        ),
        (
            "relay.livekit_api_secret",
            old.relay.livekit_api_secret != new_config.relay.livekit_api_secret,
        ),
        (
            "relay.enabled_nips",
            old.relay.enabled_nips != new_config.relay.enabled_nips,
        ),
        (
            "relay.disabled_nips",
            old.relay.disabled_nips != new_config.relay.disabled_nips,
        ),
        (
            "database.map_size",
            old.database.map_size != new_config.database.map_size,
        ),
        (
            "database.max_map_size",
            old.database.max_map_size != new_config.database.max_map_size,
        ),
        (
            "database.search_index",
            old.database.search_index != new_config.database.search_index,
        ),
        (
            "database.meta_index",
            old.database.meta_index != new_config.database.meta_index,
        ),
        (
            "database.reader_threads",
            old.database.reader_threads != new_config.database.reader_threads,
        ),
        (
            "database.disabled_fsync",
            old.database.disabled_fsync != new_config.database.disabled_fsync,
        ),
        (
            "database.max_dbs",
            old.database.max_dbs != new_config.database.max_dbs,
        ),
        (
            "database.max_readers",
            old.database.max_readers != new_config.database.max_readers,
        ),
        ("blossom.host", old.blossom.host != new_config.blossom.host),
        (
            "blossom.storage",
            old.blossom.storage != new_config.blossom.storage,
        ),
        (
            "blossom.min_free_bytes",
            old.blossom.min_free_bytes != new_config.blossom.min_free_bytes,
        ),
        (
            "blossom.local_path",
            old.blossom.local_path != new_config.blossom.local_path,
        ),
        (
            "blossom.max_upload_bytes",
            old.blossom.max_upload_bytes != new_config.blossom.max_upload_bytes,
        ),
        (
            "blossom.s3_*",
            old.blossom.s3_endpoint != new_config.blossom.s3_endpoint
                || old.blossom.s3_region != new_config.blossom.s3_region
                || old.blossom.s3_bucket != new_config.blossom.s3_bucket
                || old.blossom.s3_access_key != new_config.blossom.s3_access_key
                || old.blossom.s3_secret_key != new_config.blossom.s3_secret_key,
        ),
        (
            "database.path",
            old.database.path != new_config.database.path,
        ),
        (
            "database.purge_interval_secs",
            old.database.purge_interval_secs != new_config.database.purge_interval_secs,
        ),
        (
            "daemon.max_log_size_bytes",
            old.daemon.max_log_size_bytes != new_config.daemon.max_log_size_bytes,
        ),
        (
            "daemon.max_log_files",
            old.daemon.max_log_files != new_config.daemon.max_log_files,
        ),
        (
            "daemon.stats_interval_secs",
            old.daemon.stats_interval_secs != new_config.daemon.stats_interval_secs,
        ),
        (
            "database.db_request_timeout_secs",
            old.database.db_request_timeout_secs != new_config.database.db_request_timeout_secs,
        ),
        (
            "database.max_db_queue_msgs",
            old.database.max_db_queue_msgs != new_config.database.max_db_queue_msgs,
        ),
        (
            "database.max_db_queue_events",
            old.database.max_db_queue_events != new_config.database.max_db_queue_events,
        ),
        (
            "database.max_db_queue_bytes",
            old.database.max_db_queue_bytes != new_config.database.max_db_queue_bytes,
        ),
        (
            "database.max_indexed_words",
            old.database.max_indexed_words != new_config.database.max_indexed_words,
        ),
        (
            "limits.live_buffer",
            old.limits.live_buffer != new_config.limits.live_buffer,
        ),
        (
            "limits.live_batch_size",
            old.limits.live_batch_size != new_config.limits.live_batch_size,
        ),
        (
            "limits.live_batch_interval_ms",
            old.limits.live_batch_interval_ms != new_config.limits.live_batch_interval_ms,
        ),
        (
            "limits.max_connections",
            old.limits.max_connections != new_config.limits.max_connections,
        ),
        (
            // The accept-layer per-IP cap is captured
            // when the listener starts and no handshake
            // reads it anymore, so the reloaded config
            // must not leave `config.read()` claiming a
            // cap that is not enforced.
            "limits.max_connections_per_ip",
            old.limits.max_connections_per_ip != new_config.limits.max_connections_per_ip,
        ),
        (
            "limits.http_read_timeout_secs",
            old.limits.http_read_timeout_secs != new_config.limits.http_read_timeout_secs,
        ),
        (
            "limits.max_connections_per_sec_per_ip",
            old.limits.max_connections_per_sec_per_ip
                != new_config.limits.max_connections_per_sec_per_ip,
        ),
        (
            "limits.socket_recv_buffer_kb",
            old.limits.socket_recv_buffer_kb != new_config.limits.socket_recv_buffer_kb,
        ),
        (
            "rpc.max_admin_body_bytes",
            old.rpc.max_admin_body_bytes != new_config.rpc.max_admin_body_bytes,
        ),
        (
            "relay.max_groups",
            old.relay.max_groups != new_config.relay.max_groups,
        ),
        (
            "daemon.log_file",
            old.daemon.log_file != new_config.daemon.log_file,
        ),
        (
            "daemon.pid_file",
            old.daemon.pid_file != new_config.daemon.pid_file,
        ),
    ];
    for (name, changed) in static_routes {
        if changed {
            warn!(
                "{name} changed in the reloaded config but the routes are \
                                     fixed at startup; a restart is required to apply it"
            );
        }
    }
    // Every changed startup-only setting is rejected
    // individually above (warning + value kept below),
    // while the live settings are still applied: a
    // reload must never be all-or-nothing, or an
    // unrelated edit would silently disable a
    // CLI-visible change.
    db.set_expiry_enabled(new_config.nip_enabled(40));
    api_limit.set_max(new_config.limits.max_api_concurrent);
    db.set_max_api_pending(new_config.limits.max_api_queue_msgs);
    // The kind/IP access lists are runtime-managed via NIP-86
    // and persisted in the database: editing them in the
    // config file has no effect after the first run (the
    // persisted state wins). Warn so the operator uses the
    // management API instead of wondering why the file is
    // ignored. `restrict_relay` is config-owned and applies.
    if old.access.blocked_kinds != new_config.access.blocked_kinds
        || old.access.allowed_kinds != new_config.access.allowed_kinds
        || old.access.blocked_ips != new_config.access.blocked_ips
    {
        warn!(
            "access.blocked_kinds/allowed_kinds/blocked_ips changed in the \
                                 reloaded config but access lists are runtime-managed (NIP-86) \
                                 and persisted in the database; the file change is ignored"
        );
    }
    // Apply-live-keep-startup-only: `new_config`'s live
    // settings are applied at the end (config swap,
    // database/API limiters), while every startup-only
    // setting keeps its running value. Overwriting them
    // in memory while the router, database and threads
    // still run the old values would leave
    // `config.read()` lying about actual behavior.
    new_config.server.api_host = old.server.api_host.clone();
    new_config.server.host = old.server.host.clone();
    new_config.server.port = old.server.port;
    new_config.server.ws_paths = old.server.ws_paths.clone();
    new_config.server.trusted_proxies = old.server.trusted_proxies.clone();
    new_config.server.metrics_enabled = old.server.metrics_enabled;
    new_config.rpc.max_admin_body_bytes = old.rpc.max_admin_body_bytes;
    new_config.relay.private_key = old.relay.private_key.clone();
    new_config.relay.livekit_url = old.relay.livekit_url.clone();
    new_config.relay.livekit_api_key = old.relay.livekit_api_key.clone();
    new_config.relay.livekit_api_secret = old.relay.livekit_api_secret.clone();
    // NIP toggles shape routing and stored behavior: keep
    // them restart-required so a reload cannot half-apply
    // (dynamic gates would flip while routes stay old).
    new_config.relay.enabled_nips = old.relay.enabled_nips.clone();
    new_config.relay.disabled_nips = old.relay.disabled_nips.clone();
    new_config.relay.max_groups = old.relay.max_groups;
    new_config.database.map_size = old.database.map_size;
    new_config.database.max_map_size = old.database.max_map_size;
    new_config.database.search_index = old.database.search_index;
    new_config.database.meta_index = old.database.meta_index;
    new_config.database.reader_threads = old.database.reader_threads;
    new_config.database.disabled_fsync = old.database.disabled_fsync;
    new_config.database.max_dbs = old.database.max_dbs;
    new_config.database.max_readers = old.database.max_readers;
    new_config.database.path = old.database.path.clone();
    new_config.database.purge_interval_secs = old.database.purge_interval_secs;
    new_config.database.db_request_timeout_secs = old.database.db_request_timeout_secs;
    new_config.database.max_db_queue_msgs = old.database.max_db_queue_msgs;
    new_config.database.max_db_queue_events = old.database.max_db_queue_events;
    new_config.database.max_db_queue_bytes = old.database.max_db_queue_bytes;
    new_config.database.max_indexed_words = old.database.max_indexed_words;
    new_config.blossom.host = old.blossom.host.clone();
    new_config.blossom.storage = old.blossom.storage.clone();
    new_config.blossom.min_free_bytes = old.blossom.min_free_bytes;
    new_config.blossom.local_path = old.blossom.local_path.clone();
    new_config.blossom.max_upload_bytes = old.blossom.max_upload_bytes;
    new_config.blossom.s3_endpoint = old.blossom.s3_endpoint.clone();
    new_config.blossom.s3_region = old.blossom.s3_region.clone();
    new_config.blossom.s3_bucket = old.blossom.s3_bucket.clone();
    new_config.blossom.s3_access_key = old.blossom.s3_access_key.clone();
    new_config.blossom.s3_secret_key = old.blossom.s3_secret_key.clone();
    new_config.daemon.max_log_size_bytes = old.daemon.max_log_size_bytes;
    new_config.daemon.max_log_files = old.daemon.max_log_files;
    new_config.daemon.stats_interval_secs = old.daemon.stats_interval_secs;
    new_config.daemon.log_file = old.daemon.log_file.clone();
    new_config.daemon.pid_file = old.daemon.pid_file.clone();
    new_config.limits.live_buffer = old.limits.live_buffer;
    new_config.limits.live_batch_size = old.limits.live_batch_size;
    new_config.limits.live_batch_interval_ms = old.limits.live_batch_interval_ms;
    new_config.limits.max_connections = old.limits.max_connections;
    new_config.limits.max_connections_per_ip = old.limits.max_connections_per_ip;
    new_config.limits.http_read_timeout_secs = old.limits.http_read_timeout_secs;
    new_config.limits.max_connections_per_sec_per_ip = old.limits.max_connections_per_sec_per_ip;
    new_config.limits.socket_recv_buffer_kb = old.limits.socket_recv_buffer_kb;
    // The kind/IP access lists are runtime-managed
    // (persisted in the database); only `restrict_relay`
    // is config-owned.
    new_config.access.blocked_kinds = old.access.blocked_kinds.clone();
    new_config.access.allowed_kinds = old.access.allowed_kinds.clone();
    new_config.access.blocked_ips = old.access.blocked_ips.clone();
    *relay.config.write().await = new_config;
    // Bump the config version: connections refresh
    // their cached NIP-40/NIP-42 flags on the next
    // live batch (see `Conn::config_version`).
    relay
        .config_version
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpStream;

    /// A relay with a configured Blossom host, for the info-document tests.
    async fn blossom_relay() -> Arc<Relay> {
        blossom_relay_with_key("").await
    }

    /// Like [`blossom_relay`], with a relay key (NIP-29/43 relay-signed
    /// event generation).
    async fn blossom_relay_with_key(key: &str) -> Arc<Relay> {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut cfg = crate::config::Config::default();
        cfg.relay.name = "example relay".into();
        cfg.blossom.host = "media.example.com".into();
        cfg.blossom.storage = "local".into();
        cfg.database.map_size = 16 * 1024 * 1024;
        cfg.database.max_map_size = 64 * 1024 * 1024;
        cfg.database.path = std::env::temp_dir()
            .join("nostrfy-server-test")
            .join(format!("{:x}-{id}", std::process::id()));
        cfg.blossom.local_path = cfg.database.path.join("blobs");
        let _ = std::fs::remove_dir_all(&cfg.database.path);
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
        let relay = Relay::new(
            config,
            db,
            crate::stats::Stats::new(),
            key,
            crate::relay::LiveBusConfig {
                buffer: 1024,
                batch_interval_ms: 10,
                batch_size: 64,
            },
        )
        .await;
        // The Blossom handlers (and the root info document) require a live
        // storage state, exactly like `run_server`.
        let state = blossom::build_state(&relay.config.read().await.clone(), &relay)
            .await
            .expect("test Blossom backend must initialize");
        *relay.blossom.write().await = state;
        Arc::new(relay)
    }

    /// A stored group-state event with an arbitrary (unverified) signature:
    /// the rebuild trusts stored events, so tests seed history this way.
    fn stored_event(kind: u64, pubkey: &str, tags: Vec<Vec<String>>, created: u64) -> Event {
        let mut event = Event {
            id: String::new(),
            pubkey: pubkey.to_string(),
            created_at: created,
            kind,
            tags,
            content: String::new(),
            sig: "00".repeat(64),
        };
        event.id = crate::nips::nip01::compute_id(&event);
        event
    }

    #[tokio::test]
    async fn group_rebuild_republishes_metadata() {
        // A database rebuilt from events (a migration, or a dropped
        // snapshot) has no stored 39000-39005; the startup rebuild must
        // publish the current state so clients can display the groups.
        let key = "01".repeat(32);
        let relay = blossom_relay_with_key(&key).await;
        let admin = "aa".repeat(32);
        let member = "bb".repeat(32);
        let now = crate::util::unix_now();
        let events = [
            stored_event(9007, &admin, vec![vec!["h".into(), "g1".into()]], now - 30),
            stored_event(
                9002,
                &admin,
                vec![
                    vec!["h".into(), "g1".into()],
                    vec!["name".into(), "Group One".into()],
                ],
                now - 20,
            ),
            stored_event(
                9000,
                &admin,
                vec![
                    vec!["h".into(), "g1".into()],
                    vec!["p".into(), member.clone()],
                ],
                now - 10,
            ),
        ];
        for event in events {
            assert!(
                matches!(
                    relay.db.put(event, now).await,
                    crate::db::PutOutcome::Stored
                ),
                "the seed event must store"
            );
        }
        startup_group_state(&relay, true)
            .await
            .expect("the rebuild must succeed");
        let filter: crate::filter::Filter =
            serde_json::from_value(serde_json::json!({"kinds": [39000]})).unwrap();
        let (meta, _) = relay.db.query(vec![filter], 10, now).await;
        assert_eq!(meta.len(), 1, "the group metadata must be republished");
        assert!(
            meta[0]
                .tags
                .iter()
                .any(|t| t.len() == 2 && t[0] == "name" && t[1] == "Group One"),
            "the metadata must carry the rebuilt settings: {:?}",
            meta[0].tags
        );
        let filter: crate::filter::Filter =
            serde_json::from_value(serde_json::json!({"kinds": [39002]})).unwrap();
        let (members, _) = relay.db.query(vec![filter], 10, now).await;
        assert_eq!(members.len(), 1, "the member list must be republished");
        assert!(
            members[0]
                .tags
                .iter()
                .any(|t| t.len() >= 2 && t[1] == member),
            "the member must be listed: {:?}",
            members[0].tags
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn role_rebuild_republishes_the_membership_list() {
        // Same for NIP-43: a rebuilt role store must publish the current
        // 13534 membership list, or clients see no members after a
        // migration.
        let key = "01".repeat(32);
        let relay = blossom_relay_with_key(&key).await;
        let relay_pubkey = relay.relay_pubkey().unwrap();
        let member = "bb".repeat(32);
        let now = crate::util::unix_now();
        let role = stored_event(
            33534,
            &relay_pubkey,
            vec![
                vec!["d".into(), "mod".into()],
                vec!["label".into(), "Moderator".into()],
            ],
            now - 30,
        );
        let membership = stored_event(
            13534,
            &relay_pubkey,
            vec![vec!["member".into(), member.clone(), "mod".into()]],
            now - 20,
        );
        for event in [role, membership] {
            assert!(matches!(
                relay.db.put(event, now).await,
                crate::db::PutOutcome::Stored
            ));
        }
        restore_role_state(&relay)
            .await
            .expect("the role rebuild must succeed");
        assert!(
            relay.roles.read().await.is_member_of(&member),
            "the rebuilt store must know the member"
        );
        // The republished list replaced the stored one (it is newer), so
        // exactly one 13534 exists and it is not the seed event.
        let filter: crate::filter::Filter =
            serde_json::from_value(serde_json::json!({"kinds": [13534]})).unwrap();
        let (lists, _) = relay.db.query(vec![filter], 10, now).await;
        assert_eq!(lists.len(), 1, "the membership list must be republished");
        assert!(
            lists[0]
                .tags
                .iter()
                .any(|t| t.len() >= 2 && t[0] == "member" && t[1] == member),
            "the republished list must name the member: {:?}",
            lists[0].tags
        );
        assert_eq!(
            lists[0].pubkey, relay_pubkey,
            "the list must be signed by the relay key"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn startup_refuses_an_unreadable_group_snapshot_even_when_disabled() {
        // A snapshot that cannot be read (corrupt bytes, dead reader) must
        // stop the relay even with NIP-29 disabled: the store would start
        // empty, and every unknown group id reads as public, so starting
        // would silently expose private group content.
        let relay = blossom_relay().await;
        relay.db.shutdown();
        let err = restore_group_state(&relay, false).await.unwrap_err();
        assert!(
            err.to_string().contains("refusing to start"),
            "an unreadable snapshot must stop startup, got: {err}"
        );
        // The pre-existing snapshot path still distinguishes a first run:
        // tested through the stale-snapshot test below.
    }

    #[tokio::test]
    async fn startup_refuses_an_unreadable_role_snapshot() {
        // Same fail-closed rule for roles: an empty role store revokes
        // every grant, so an unreadable snapshot must stop startup rather
        // than silently unauthorize the relay's own moderation.
        let relay = blossom_relay().await;
        relay.db.shutdown();
        let err = restore_role_state(&relay).await.unwrap_err();
        assert!(
            err.to_string().contains("refusing to start"),
            "an unreadable snapshot must stop startup, got: {err}"
        );
    }

    #[tokio::test]
    async fn startup_rejects_a_stale_group_snapshot_and_resumes_purges() {
        // A snapshot stamped before a group-state removal must not be
        // restored: startup rebuilds from the surviving events instead
        // (fail-closed). The resume then runs safely as a no-op.
        let relay = blossom_relay().await;
        // A completed NIP-29 purge advances the database generation, exactly
        // like the removal that invalidates the snapshot below.
        relay.db.group_purge("gone".to_string(), unix_now()).await;
        let current = relay
            .db
            .state_stamp()
            .await
            .expect("the generation must be readable");
        assert!(current > 0, "a completed purge must advance the generation");
        let mut stale = crate::nips::nip29::GroupsSnapshot::default();
        stale.groups.insert("stale".to_string(), Default::default());
        assert!(
            relay.db.save_groups(stale).await,
            "the stale snapshot must be persisted for the test"
        );
        // The full startup sequence: restore rejected, rebuild runs, and
        // the resume completes with nothing pending.
        startup_group_state(&relay, true)
            .await
            .expect("the rebuild must succeed over an empty database");
        assert!(
            relay.groups.read().await.group("stale").is_none(),
            "a snapshot older than the database generation must not be restored"
        );
        // The rebuild persisted a current snapshot (not the stale one), so
        // the next start restores instead of rebuilding again.
        let persisted = relay
            .db
            .load_groups()
            .await
            .expect_loaded("the rebuild must persist");
        assert!(
            persisted.stamp >= current,
            "the rebuilt snapshot must carry the current generation (got {})",
            persisted.stamp
        );
        assert!(
            persisted.groups.is_empty(),
            "the stale group must not survive the rebuild"
        );
        // Nothing is pending: the resume (part of the startup sequence) is a
        // safe no-op, and the gauge reports zero.
        assert!(
            relay
                .db
                .pending_purges()
                .await
                .is_some_and(|pending| pending.is_empty()),
            "the resume must leave no pending purges behind"
        );
        assert_eq!(
            relay
                .stats
                .pending_purges
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "the startup sequence must publish the pending-purge count"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn startup_restores_a_legacy_snapshot_at_generation_zero() {
        // A snapshot written before the stamp existed deserializes with
        // stamp 0; while the database generation is still 0 it is current
        // and must restore (the fail-closed check must not reject it).
        let relay = blossom_relay().await;
        assert_eq!(
            relay.db.state_stamp().await,
            Some(0),
            "a fresh database has no stamp"
        );
        let mut legacy = crate::nips::nip29::GroupsSnapshot::default();
        legacy
            .groups
            .insert("legacy".to_string(), Default::default());
        assert!(relay.db.save_groups(legacy).await);
        startup_group_state(&relay, true)
            .await
            .expect("the legacy restore must succeed");
        assert!(
            relay.groups.read().await.group("legacy").is_some(),
            "a legacy snapshot (stamp 0) at generation 0 must restore"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn per_family_sequences_reject_a_stale_group_snapshot_and_restore_current_roles() {
        // The startup restore blocks compare each snapshot against its own
        // family sequence: a role event advances only the role sequence, so
        // a group snapshot that predates a group event is rejected (and
        // rebuilt from the surviving events) while the role snapshot saved
        // after the role event still restores.
        let relay = blossom_relay().await;
        let now = unix_now();
        let authored = |kind: u64, content: &str| {
            let mut event = crate::event::Event {
                id: String::new(),
                pubkey: "aa".repeat(32),
                created_at: now,
                kind,
                tags: vec![],
                content: content.to_string(),
                sig: "00".repeat(64),
            };
            event.id = crate::nips::nip01::compute_id(&event);
            event
        };

        // One group event advances the group sequence to 1; one role event
        // advances the role sequence to 1. Neither crosses over.
        assert_eq!(
            relay.db.put(authored(9002, "group"), now).await,
            crate::db::PutOutcome::Stored
        );
        assert_eq!(
            relay
                .db
                .put(authored(crate::nips::nip43::ROLE_DEFINITION, "role"), now)
                .await,
            crate::db::PutOutcome::Stored
        );
        assert_eq!(relay.db.state_seq_group().await, Some(1));
        assert_eq!(relay.db.state_seq_role().await, Some(1));
        let stamp = relay.db.state_stamp().await.expect("stamp");

        // A stale group snapshot (sequence 0 < current 1).
        let mut stale_group = crate::nips::nip29::GroupsSnapshot::default();
        stale_group
            .groups
            .insert("stale".to_string(), Default::default());
        stale_group.stamp = stamp;
        stale_group.seq = 0;
        assert!(relay.db.save_groups(stale_group).await);

        // A current role snapshot (sequence 1 == current 1).
        let mut current_roles = crate::nips::nip43::RolesSnapshot::default();
        current_roles
            .roles
            .insert("king".to_string(), Default::default());
        current_roles.stamp = stamp;
        current_roles.seq = 1;
        assert!(relay.db.save_roles(current_roles).await);

        // The group restore rejects the stale snapshot and rebuilds.
        startup_group_state(&relay, true)
            .await
            .expect("the group rebuild must succeed");
        assert!(
            relay.groups.read().await.group("stale").is_none(),
            "the stale group snapshot must not be restored"
        );

        // The role snapshot is still current: the group event did not
        // advance the role sequence, so it restores instead of rebuilding.
        restore_role_state(&relay)
            .await
            .expect("the role restore must succeed");
        assert!(
            relay.roles.read().await.roles.contains_key("king"),
            "a role snapshot at the current role sequence must restore"
        );
        relay.db.shutdown();
    }

    /// Writes `cfg` to a fresh temp config file and returns `(dir, path)`,
    /// so a SIGHUP test can exercise the real load/validate path.
    fn write_temp_config(name: &str, cfg: &Config) -> (PathBuf, PathBuf) {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir()
            .join(name)
            .join(format!("{:x}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nostrfy.toml");
        std::fs::write(&path, toml::to_string_pretty(cfg).unwrap()).unwrap();
        (dir, path)
    }

    #[tokio::test]
    async fn reload_applies_live_settings_and_keeps_startup_only() {
        let relay = blossom_relay().await;
        let old = relay.config.read().await.clone();
        let mut new_config = old.clone();
        new_config.relay.name = "reloaded relay".into();
        new_config.access.restrict_relay = !old.access.restrict_relay;
        new_config.limits.max_api_concurrent = 1;
        // Startup-only values: the router/accept loop and the database
        // environment keep running with the old values (restart required).
        new_config.server.port = old.server.port.wrapping_add(1);
        new_config.database.map_size = old.database.map_size / 2;
        new_config.limits.max_connections = old.limits.max_connections + 1;
        apply_reloaded_config(&old, new_config, &relay, &relay.db, &relay.api_limit).await;

        let applied = relay.config.read().await;
        assert_eq!(
            applied.relay.name, "reloaded relay",
            "a live setting must apply"
        );
        assert_eq!(
            applied.access.restrict_relay, !old.access.restrict_relay,
            "access.restrict_relay is config-owned and live"
        );
        assert_eq!(
            applied.server.port, old.server.port,
            "a startup-only setting must keep its running value"
        );
        assert_eq!(
            applied.database.map_size, old.database.map_size,
            "the database layout is startup-only"
        );
        assert_eq!(
            applied.limits.max_connections, old.limits.max_connections,
            "the accept loop is built at startup"
        );
        drop(applied);
        assert_eq!(
            relay
                .config_version
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "the config version must bump so connections refresh cached flags"
        );
        // The API concurrency ceiling was applied live.
        let first = relay.api_limit.try_acquire().expect("the first slot");
        assert!(
            relay.api_limit.try_acquire().is_none(),
            "the reloaded ceiling of 1 must be enforced"
        );
        drop(first);
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn reload_re_reads_the_database_lists_on_success_and_failure() {
        // `handle_reload` must refresh the database-owned lists on both the
        // applied and the rejected path: a NIP-86 change committed since the
        // last reload must not be skipped because the config edit was bad.
        let relay = blossom_relay().await;
        let base = relay.config.read().await.clone();
        let (dir, config_path) = write_temp_config("nostrfy-reload-test", &base);
        let mut updated = base.clone();
        updated.relay.name = "from file".into();
        std::fs::write(&config_path, toml::to_string_pretty(&updated).unwrap()).unwrap();
        assert!(
            relay
                .db
                .save_blossom_allow(&["sha256:aaa".to_string()])
                .await
        );
        handle_reload(&config_path, &relay, &relay.db, &relay.api_limit).await;
        assert_eq!(
            relay.config.read().await.relay.name,
            "from file",
            "a valid file must be applied"
        );
        assert_eq!(
            *relay.blossom_allow.read().await,
            vec!["sha256:aaa".to_string()],
            "the applied path must re-read the database lists"
        );

        // An invalid file (zero limit) rejects the config as a whole but the
        // database lists still refresh.
        std::fs::write(&config_path, "[limits]\nmax_connections = 0\n").unwrap();
        assert!(
            relay
                .db
                .save_blossom_allow(&["sha256:bbb".to_string()])
                .await
        );
        handle_reload(&config_path, &relay, &relay.db, &relay.api_limit).await;
        assert_eq!(
            relay.config.read().await.relay.name,
            "from file",
            "a rejected reload must keep the running config"
        );
        assert_eq!(
            *relay.blossom_allow.read().await,
            vec!["sha256:bbb".to_string()],
            "the rejected path must still re-read the database lists"
        );
        let _ = std::fs::remove_dir_all(&dir);
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn reload_does_not_deadlock_with_a_contending_config_writer() {
        // Regression guard: the SIGHUP path must never hold a config read
        // guard across `reload_db_state` (which reads the config itself).
        // The apply takes a snapshot and releases its guard, so it completes
        // even while another task continuously queues for the write lock.
        let relay = blossom_relay().await;
        let base = relay.config.read().await.clone();
        let (dir, config_path) = write_temp_config("nostrfy-reload-contend-test", &base);
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let writer = tokio::spawn({
            let relay = Arc::clone(&relay);
            let stop = Arc::clone(&stop);
            async move {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let _guard = relay.config.write().await;
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
        });
        let reload = tokio::time::timeout(
            Duration::from_secs(10),
            handle_reload(&config_path, &relay, &relay.db, &relay.api_limit),
        )
        .await;
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        writer.await.unwrap();
        assert!(
            reload.is_ok(),
            "the reload must complete while a config writer contends for the lock"
        );
        let _ = std::fs::remove_dir_all(&dir);
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn cors_websocket_and_blossom_root_helpers() {
        // cors_middleware: OPTIONS answers 204 with the CORS headers.
        let app = axum::Router::new()
            .route("/", axum::routing::get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(cors_middleware));
        let request = Request::builder()
            .method(Method::OPTIONS)
            .uri("/")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(
            response
                .headers()
                .get("access-control-allow-origin")
                .is_some(),
            "the preflight must carry the CORS headers"
        );
        // A regular request passes through and gets the CORS headers.
        let request = Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response
                .headers()
                .get("access-control-allow-origin")
                .is_some()
        );

        // is_websocket_request: the full upgrade set passes; a missing
        // header or an invalid X-Forwarded-Proto fails.
        let mut h = HeaderMap::new();
        h.insert(axum::http::header::UPGRADE, "websocket".parse().unwrap());
        h.insert(
            axum::http::header::CONNECTION,
            "keep-alive, Upgrade".parse().unwrap(),
        );
        h.insert(
            axum::http::header::SEC_WEBSOCKET_VERSION,
            "13".parse().unwrap(),
        );
        h.insert(
            axum::http::header::SEC_WEBSOCKET_KEY,
            "abcd".parse().unwrap(),
        );
        assert!(is_websocket_request(&h));
        let mut no_key = h.clone();
        no_key.remove(axum::http::header::SEC_WEBSOCKET_KEY);
        assert!(!is_websocket_request(&no_key));
        let mut bad_proto = h.clone();
        bad_proto.insert("x-forwarded-proto", "ftp".parse().unwrap());
        assert!(
            !is_websocket_request(&bad_proto),
            "an unknown proxy proto fails"
        );
        let mut good_proto = h.clone();
        good_proto.insert("x-forwarded-proto", "WSS".parse().unwrap());
        assert!(
            is_websocket_request(&good_proto),
            "WSS is accepted case-insensitively"
        );

        // reject_ws_upgrade: a WebSocket handshake is refused with 403.
        let app = axum::Router::new()
            .route("/", axum::routing::get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(reject_ws_upgrade));
        let request = Request::builder()
            .method(Method::GET)
            .uri("/")
            .header(axum::http::header::UPGRADE, "websocket")
            .header(axum::http::header::CONNECTION, "upgrade")
            .header(axum::http::header::SEC_WEBSOCKET_VERSION, "13")
            .header(axum::http::header::SEC_WEBSOCKET_KEY, "abcd")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let request = Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // await_shutdown returns once the watch flips.
        let (tx, rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(await_shutdown(rx));
        tx.send(true).unwrap();
        task.await.unwrap();
    }

    #[test]
    fn ws_detection_accepts_multi_valued_forwarded_proto() {
        // Regression: a comma-separated X-Forwarded-Proto (one value per
        // proxy hop) used to compare as a whole, so "https,http" from a
        // proxy chain disabled WebSocket detection and the handshake was
        // served as a plain HTTP request.
        let headers = |proto: &str| {
            let mut h = HeaderMap::new();
            h.insert(axum::http::header::UPGRADE, "websocket".parse().unwrap());
            h.insert(
                axum::http::header::CONNECTION,
                "keep-alive, Upgrade".parse().unwrap(),
            );
            h.insert(
                axum::http::header::SEC_WEBSOCKET_VERSION,
                "13".parse().unwrap(),
            );
            h.insert(
                axum::http::header::SEC_WEBSOCKET_KEY,
                "abcd".parse().unwrap(),
            );
            h.insert("x-forwarded-proto", proto.parse().unwrap());
            h
        };
        assert!(
            is_websocket_request(&headers("https,http")),
            "any WebSocket-capable token must be accepted"
        );
        assert!(is_websocket_request(&headers("ftp, wss")));
        assert!(!is_websocket_request(&headers("ftp,spdy")));
    }

    #[tokio::test]
    async fn ws_handler_and_blossom_root_gate() {
        let relay = blossom_relay().await;
        // A WebSocket handshake from a blocked IP is refused with 403.
        relay
            .access
            .write()
            .await
            .blocked_ips
            .push("198.51.100.7".into(), String::new());
        let mut request = Request::builder()
            .method(Method::GET)
            .uri("/")
            .header(axum::http::header::UPGRADE, "websocket")
            .header(axum::http::header::CONNECTION, "upgrade")
            .header(axum::http::header::SEC_WEBSOCKET_VERSION, "13")
            .header(axum::http::header::SEC_WEBSOCKET_KEY, "abcd")
            .body(Body::empty())
            .unwrap();
        request
            .extensions_mut()
            .insert(axum::extract::connect_info::ConnectInfo::<
                std::net::SocketAddr,
            >("198.51.100.7:1234".parse().unwrap()));
        let response = ws_handler(State(relay.clone()), request).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // Blossom host root: a WebSocket upgrade is 404, a plain GET gets
        // the server-info document.
        let request = Request::builder()
            .method(Method::GET)
            .uri("/")
            .header(axum::http::header::HOST, "media.example.com")
            .header(axum::http::header::UPGRADE, "websocket")
            .header(axum::http::header::CONNECTION, "upgrade")
            .header(axum::http::header::SEC_WEBSOCKET_VERSION, "13")
            .header(axum::http::header::SEC_WEBSOCKET_KEY, "abcd")
            .body(Body::empty())
            .unwrap();
        let response = root_inbox_outbox(State(relay.clone()), request).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let request = Request::builder()
            .method(Method::GET)
            .uri("/")
            .header(axum::http::header::HOST, "media.example.com")
            .body(Body::empty())
            .unwrap();
        let response = root_inbox_outbox(State(relay.clone()), request).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let info: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(info["name"], "example relay (media)");
        // The relay host gets no blossom info on the inbox-outbox root.
        let request = Request::builder()
            .method(Method::GET)
            .uri("/")
            .header(axum::http::header::HOST, "relay.example.com")
            .body(Body::empty())
            .unwrap();
        let response = root_inbox_outbox(State(relay.clone()), request).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn blockip_applies_to_every_main_route() {
        let relay = blossom_relay().await;
        // Block the v4-mapped spelling: the plain IPv4 peer must be refused
        // on every route, not only the WebSocket handler.
        relay
            .access
            .write()
            .await
            .blocked_ips
            .push("::ffff:198.51.100.7".into(), String::new());
        let app = build_router(&relay, None).await;
        for uri in ["/health", "/api/v1/count", "/relay/stats"] {
            let mut request = Request::builder()
                .method(Method::GET)
                .uri(uri)
                .body(Body::empty())
                .unwrap();
            request
                .extensions_mut()
                .insert(axum::extract::connect_info::ConnectInfo::<
                    std::net::SocketAddr,
                >("198.51.100.7:1234".parse().unwrap()));
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "{uri} must be refused for a blocked peer"
            );
        }
        // A different peer passes the middleware and reaches the route.
        let mut request = Request::builder()
            .method(Method::GET)
            .uri("/health")
            .body(Body::empty())
            .unwrap();
        request
            .extensions_mut()
            .insert(axum::extract::connect_info::ConnectInfo::<
                std::net::SocketAddr,
            >("198.51.100.8:1234".parse().unwrap()));
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        // Every blocked-IP refusal bumped the counter (three above).
        assert_eq!(
            relay
                .stats
                .conn_refused_blocked
                .load(std::sync::atomic::Ordering::Relaxed),
            3,
            "blocked-IP 403s must be counted"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn rpc_body_read_is_bounded_by_the_read_timeout() {
        let relay = blossom_relay().await;
        relay.config.write().await.limits.http_read_timeout_secs = 1;
        let app = build_router(&relay, None).await;
        // A body that never produces a byte must be cut with 408 instead of
        // pinning the connection (and its per-IP slot) indefinitely.
        let stalled = Body::from_stream(futures_util::stream::pending::<
            std::result::Result<axum::body::Bytes, std::io::Error>,
        >());
        let request = Request::builder()
            .method(Method::POST)
            .uri("/")
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(stalled)
            .unwrap();
        let started = std::time::Instant::now();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the body read must be cut at the configured deadline"
        );
        // A complete body is re-injected and reaches the RPC handler (the
        // missing auth is answered with 401, so the handler ran).
        let mut request = Request::builder()
            .method(Method::POST)
            .uri("/")
            .header(
                axum::http::header::CONTENT_TYPE,
                "application/nostr+json+rpc",
            )
            .body(Body::from("{}"))
            .unwrap();
        request
            .extensions_mut()
            .insert(axum::extract::connect_info::ConnectInfo::<
                std::net::SocketAddr,
            >("198.51.100.7:1234".parse().unwrap()));
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        // An over-limit Content-Length is refused up front, like
        // `DefaultBodyLimit` would.
        let request = Request::builder()
            .method(Method::POST)
            .uri("/")
            .header(axum::http::header::CONTENT_LENGTH, "100000000")
            .body(Body::from("{}"))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn blossom_root_info_requires_live_storage() {
        let relay = blossom_relay().await;
        // With live storage the info document is served.
        assert!(
            blossom_root_info(relay.clone(), Some("media.example.com"), false)
                .await
                .is_some()
        );
        // Storage initialization failed: the configured Blossom host fails
        // closed with a 404 instead of returning `None`, which would let
        // the root fall through to the relay (NIP-11 document and WebSocket
        // upgrades) on the media host.
        *relay.blossom.write().await = None;
        let resp = blossom_root_info(relay.clone(), Some("media.example.com"), false)
            .await
            .expect("the configured Blossom host must not fall through");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        // A plain GET on that host gets the 404, not the NIP-11 document…
        let request = Request::builder()
            .method(Method::GET)
            .uri("/")
            .header(axum::http::header::HOST, "media.example.com")
            .body(Body::empty())
            .unwrap();
        let response = ws_handler(State(relay.clone()), request).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        // …and a WebSocket upgrade there is refused (never upgraded).
        let request = Request::builder()
            .method(Method::GET)
            .uri("/")
            .header(axum::http::header::HOST, "media.example.com")
            .header(axum::http::header::UPGRADE, "websocket")
            .header(axum::http::header::CONNECTION, "upgrade")
            .header(axum::http::header::SEC_WEBSOCKET_VERSION, "13")
            .header(axum::http::header::SEC_WEBSOCKET_KEY, "abcd")
            .body(Body::empty())
            .unwrap();
        let response = ws_handler(State(relay.clone()), request).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        // The relay host is unaffected: it still gets the NIP-11 document.
        let request = Request::builder()
            .method(Method::GET)
            .uri("/")
            .header(axum::http::header::HOST, "relay.example.com")
            .header(axum::http::header::ACCEPT, "application/nostr+json")
            .body(Body::empty())
            .unwrap();
        let response = ws_handler(State(relay.clone()), request).await;
        assert_eq!(response.status(), StatusCode::OK);
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn blossom_server_info_carries_name_and_file_nips() {
        let relay = blossom_relay().await;
        let resp = blossom_root_info(relay.clone(), Some("media.example.com"), false)
            .await
            .expect("the Blossom host is answered");
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["name"], "example relay (media)");
        assert_eq!(
            json["supported_nips"],
            serde_json::json!([94, 98]),
            "file-related NIPs are advertised (NIP-96 is not implemented)"
        );
        assert_eq!(json["upload_url"], "https://media.example.com/upload");
        assert_eq!(json["supported_file_hashes"], serde_json::json!(["sha256"]));
        // Any other host is not answered.
        assert!(
            blossom_root_info(relay.clone(), Some("relay.example.com"), false)
                .await
                .is_none()
        );
        relay.db.shutdown();
    }

    fn test_app() -> axum::Router {
        axum::Router::new().route("/", axum::routing::get(|| async { "ok" }))
    }

    async fn serve_limited_for_test(
        max_connections: usize,
        max_per_ip: usize,
        header_timeout: Option<Duration>,
        per_sec: Option<IpConnLimiter>,
    ) -> (SocketAddr, watch::Sender<bool>, tokio::task::JoinHandle<()>) {
        serve_limited_with_proxies(
            max_connections,
            max_per_ip,
            header_timeout,
            per_sec,
            Vec::new(),
        )
        .await
    }

    async fn serve_limited_with_proxies(
        max_connections: usize,
        max_per_ip: usize,
        header_timeout: Option<Duration>,
        per_sec: Option<IpConnLimiter>,
        trusted: Vec<TrustedProxy>,
    ) -> (SocketAddr, watch::Sender<bool>, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(serve_limited(
            listener,
            test_app(),
            max_connections,
            max_per_ip,
            header_timeout,
            per_sec.map(Arc::new),
            Arc::from(trusted),
            16,
            crate::stats::Stats::new(),
            rx,
        ));
        (addr, tx, handle)
    }

    /// Like [`serve_limited_for_test`], but returns the shared stats so a
    /// test can assert the refusal counters.
    async fn serve_limited_with_stats(
        max_connections: usize,
        max_per_ip: usize,
        per_sec: Option<IpConnLimiter>,
        stats: Arc<crate::stats::Stats>,
    ) -> (SocketAddr, watch::Sender<bool>, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(serve_limited(
            listener,
            test_app(),
            max_connections,
            max_per_ip,
            Some(Duration::from_secs(30)),
            per_sec.map(Arc::new),
            Arc::from(Vec::new()),
            16,
            stats,
            rx,
        ));
        (addr, tx, handle)
    }

    /// Opens a keep-alive HTTP connection, sends `GET /`, and reads until
    /// the response head (`200 OK`) arrives; the socket stays open so the
    /// connection remains active on the server.
    async fn http_keepalive(addr: SocketAddr) -> (TcpStream, Vec<u8>) {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET / HTTP/1.1\r\nHost: t\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        let deadline = tokio::time::sleep(Duration::from_secs(5));
        tokio::pin!(deadline);
        while !String::from_utf8_lossy(&buf).contains("200 OK") {
            tokio::select! {
                n = s.read(&mut tmp) => {
                    match n {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    }
                }
                _ = &mut deadline => break,
            }
        }
        (s, buf)
    }

    /// Polls until the server serves `GET /` (a 200 response head) or the
    /// deadline passes: used after closing a connection to wait for the
    /// slot release without a fixed sleep that could be too short on a
    /// loaded machine.
    async fn wait_for_served(addr: SocketAddr) -> (TcpStream, Vec<u8>) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let (conn, body) = http_keepalive(addr).await;
            if String::from_utf8_lossy(&body).contains("200 OK") {
                return (conn, body);
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the server did not release the slot within the deadline (last body: {:?})",
                String::from_utf8_lossy(&body)
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Reads the connection until it closes (or the timeout passes),
    /// returning the bytes received and whether the close was observed: a
    /// timed-out read is *not* a close, so callers can assert the server
    /// actually closed the socket instead of the test merely giving up.
    async fn read_to_eof(mut s: TcpStream, timeout: Duration) -> (Vec<u8>, bool) {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                n = s.read(&mut tmp) => {
                    match n {
                        Ok(0) | Err(_) => return (buf, true),
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    }
                }
                _ = &mut deadline => return (buf, false),
            }
        }
    }

    #[tokio::test]
    async fn serve_limited_serves_http_and_applies_the_connection_cap() {
        let (addr, tx, handle) =
            serve_limited_for_test(1, 0, Some(Duration::from_secs(30)), None).await;
        // A normal request is served.
        let (conn1, body) = http_keepalive(addr).await;
        assert!(
            String::from_utf8_lossy(&body).contains("200 OK"),
            "the first connection must be served"
        );
        // With max_connections = 1 the second connection is dropped at the
        // socket level: the TCP connect succeeds but the server refuses
        // (and the close must be observed, not a read timeout).
        let refused = http_get_with_xff(addr, None).await;
        assert!(
            refused.is_empty(),
            "the capped connection must be dropped without a response"
        );
        // Closing the first connection releases the slot; poll for the
        // release instead of sleeping a fixed interval.
        drop(conn1);
        let (conn3, _) = wait_for_served(addr).await;
        drop(conn3);
        tx.send(true).unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn serve_limited_counts_each_refusal_reason() {
        use std::sync::atomic::Ordering;
        // Global cap.
        let stats = crate::stats::Stats::new();
        let (addr, tx, handle) = serve_limited_with_stats(1, 0, None, stats.clone()).await;
        let (conn1, body) = http_keepalive(addr).await;
        assert!(String::from_utf8_lossy(&body).contains("200 OK"));
        assert!(http_get_with_xff(addr, None).await.is_empty());
        assert_eq!(
            stats.conn_refused_global.load(Ordering::Relaxed),
            1,
            "a global-cap drop must be counted"
        );
        drop(conn1);
        tx.send(true).unwrap();
        handle.await.unwrap();

        // Per-IP concurrent cap.
        let stats = crate::stats::Stats::new();
        let (addr, tx, handle) = serve_limited_with_stats(10, 1, None, stats.clone()).await;
        let (conn1, body) = http_keepalive(addr).await;
        assert!(String::from_utf8_lossy(&body).contains("200 OK"));
        assert!(http_get_with_xff(addr, None).await.is_empty());
        assert_eq!(
            stats.conn_refused_per_ip.load(Ordering::Relaxed),
            1,
            "a per-IP-cap drop must be counted"
        );
        drop(conn1);
        tx.send(true).unwrap();
        handle.await.unwrap();

        // Per-IP rate limit: the injected clock pins the one-second window,
        // so the second connection is deterministically over the limit.
        let stats = crate::stats::Stats::new();
        let (addr, tx, handle) = serve_limited_with_stats(
            10,
            0,
            IpConnLimiter::with_clock(1, Arc::new(|| 0)),
            stats.clone(),
        )
        .await;
        let (conn1, body) = http_keepalive(addr).await;
        assert!(String::from_utf8_lossy(&body).contains("200 OK"));
        assert!(http_get_with_xff(addr, None).await.is_empty());
        assert_eq!(
            stats.conn_refused_rate.load(Ordering::Relaxed),
            1,
            "a rate-limit drop must be counted"
        );
        drop(conn1);
        tx.send(true).unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn health_reports_ok_for_a_healthy_database() {
        // A healthy database (and, until the database accessors land, the
        // fallback) keeps the liveness answer 200.
        let relay = blossom_relay().await;
        let response = health_handler(State(relay.clone())).await;
        assert_eq!(response.status(), StatusCode::OK);
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn termination_wait_pends_without_registered_signals() {
        // A failed signal registration must leave the handler waiting for
        // the shutdown watch instead of returning (which the supervisor
        // would report as a lost background task).
        let mut terminate = None;
        let mut interrupt = None;
        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                await_termination_signal(&mut terminate, &mut interrupt),
            )
            .await
            .is_err(),
            "no signal stream means pending forever"
        );
    }

    #[tokio::test]
    async fn serve_limited_caps_plain_http_connections_per_ip() {
        // The per-IP cap must cover plain HTTP, not only WebSocket
        // upgrades: one host opening many idle HTTP sockets used to consume
        // the whole global connection budget.
        let (addr, tx, handle) =
            serve_limited_for_test(10, 2, Some(Duration::from_secs(30)), None).await;
        let (conn1, body1) = http_keepalive(addr).await;
        assert!(String::from_utf8_lossy(&body1).contains("200 OK"));
        let (conn2, body2) = http_keepalive(addr).await;
        assert!(String::from_utf8_lossy(&body2).contains("200 OK"));
        // The third connection from the same IP is refused at the socket.
        let refused = http_get_with_xff(addr, None).await;
        assert!(
            refused.is_empty(),
            "the per-IP capped connection must be dropped"
        );
        // Closing one connection releases its per-IP slot; poll for it.
        drop(conn1);
        let (conn3, _) = wait_for_served(addr).await;
        drop(conn2);
        drop(conn3);
        tx.send(true).unwrap();
        handle.await.unwrap();
    }

    /// One `GET /` with an optional `X-Forwarded-For` header; the request
    /// carries `Connection: close`, so the whole response is read and the
    /// close must actually be observed (a mere read timeout would otherwise
    /// make the `is_empty()` refusal assertions vacuously pass).
    async fn http_get_with_xff(addr: SocketAddr, xff: Option<&str>) -> Vec<u8> {
        let mut s = TcpStream::connect(addr).await.unwrap();
        let forwarded = xff.map_or(String::new(), |xff| format!("X-Forwarded-For: {xff}\r\n"));
        s.write_all(
            format!("GET / HTTP/1.1\r\nHost: t\r\n{forwarded}Connection: close\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
        let (buf, closed) = read_to_eof(s, Duration::from_secs(3)).await;
        assert!(
            closed,
            "the server must close a `Connection: close` request (read timed out instead)"
        );
        buf
    }

    /// Reads whatever arrives within `within`, without waiting for EOF.
    async fn read_available(s: &mut TcpStream, within: Duration) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        let deadline = tokio::time::sleep(within);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                n = s.read(&mut tmp) => match n {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                },
                _ = &mut deadline => break,
            }
        }
        buf
    }

    /// A router whose requests park until the returned semaphore is
    /// released, so several connections can be kept in flight at once. The
    /// `Notify` fires when a request reaches the handler, letting a test
    /// wait for the parking connection deterministically instead of
    /// sleeping.
    fn gated_app() -> (
        axum::Router,
        Arc<tokio::sync::Semaphore>,
        Arc<tokio::sync::Notify>,
    ) {
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let arrived = Arc::new(tokio::sync::Notify::new());
        let app = axum::Router::new().route(
            "/",
            axum::routing::get({
                let gate = Arc::clone(&gate);
                let arrived = Arc::clone(&arrived);
                move || {
                    let gate = Arc::clone(&gate);
                    let arrived = Arc::clone(&arrived);
                    async move {
                        arrived.notify_one();
                        let permit = gate.acquire().await.expect("the gate is open");
                        permit.forget();
                        "ok"
                    }
                }
            }),
        );
        (app, gate, arrived)
    }

    /// Waits (bounded) until the gated handler reports that its first
    /// request arrived.
    async fn wait_for_arrival(arrived: &tokio::sync::Notify) {
        tokio::time::timeout(Duration::from_secs(5), arrived.notified())
            .await
            .expect("the first request must reach the handler");
    }

    #[tokio::test]
    async fn serve_limited_caps_forwarded_clients_of_trusted_proxies() {
        // In a trusted-proxy deployment the per-IP cap must count the
        // forwarded client, not the proxy: two connections from the same
        // client are capped even though they share the proxy's TCP
        // address, and a different client gets its own slot.
        let (app, gate, arrived) = gated_app();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = watch::channel(false);
        let stats = crate::stats::Stats::new();
        let handle = tokio::spawn(serve_limited(
            listener,
            app,
            10,
            1,
            Some(Duration::from_secs(30)),
            None,
            Arc::from(vec![TrustedProxy::parse("127.0.0.1/32").unwrap()]),
            16,
            stats.clone(),
            rx,
        ));
        // The first client's request stays in flight, holding its slot.
        let mut first = TcpStream::connect(addr).await.unwrap();
        first
            .write_all(
                b"GET / HTTP/1.1\r\nHost: t\r\nX-Forwarded-For: 203.0.113.9\r\n\
                  Connection: keep-alive\r\n\r\n",
            )
            .await
            .unwrap();
        wait_for_arrival(&arrived).await;
        // A second connection for the same forwarded client is refused with
        // 429 (the HTTP layer must not drop the already-established socket).
        let refused = http_get_with_xff(addr, Some("203.0.113.9")).await;
        assert!(
            String::from_utf8_lossy(&refused).contains("429"),
            "the forwarded client must be capped: {:?}",
            String::from_utf8_lossy(&refused)
        );
        assert_eq!(
            stats
                .conn_refused_proxy
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "a trusted-proxy 429 must be counted"
        );
        // A different forwarded client is admitted and parks in the handler.
        let mut other = TcpStream::connect(addr).await.unwrap();
        other
            .write_all(
                b"GET / HTTP/1.1\r\nHost: t\r\nX-Forwarded-For: 203.0.113.10\r\n\
                  Connection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let pending = read_available(&mut other, Duration::from_millis(400)).await;
        assert!(
            !String::from_utf8_lossy(&pending).contains("429"),
            "a different forwarded client must not be capped"
        );
        // Opening the gate completes both requests; the slots are released
        // (the guard held by the in-flight request must not leak).
        gate.add_permits(8);
        let (first_body, _) = read_to_eof(first, Duration::from_secs(3)).await;
        assert!(String::from_utf8_lossy(&first_body).contains("200 OK"));
        let (other_body, other_closed) = read_to_eof(other, Duration::from_secs(3)).await;
        assert!(String::from_utf8_lossy(&other_body).contains("200 OK"));
        assert!(
            other_closed,
            "the `Connection: close` request must be answered and closed"
        );
        tx.send(true).unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn serve_limited_ignores_forwarded_for_from_untrusted_peers() {
        // Without `server.trusted_proxies` the header is attacker-controlled:
        // two connections from the same peer stay capped however they vary
        // `X-Forwarded-For`.
        let (app, gate, arrived) = gated_app();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(serve_limited(
            listener,
            app,
            10,
            1,
            Some(Duration::from_secs(30)),
            None,
            Arc::from(Vec::new()),
            16,
            crate::stats::Stats::new(),
            rx,
        ));
        let mut first = TcpStream::connect(addr).await.unwrap();
        first
            .write_all(
                b"GET / HTTP/1.1\r\nHost: t\r\nX-Forwarded-For: 203.0.113.9\r\n\
                  Connection: keep-alive\r\n\r\n",
            )
            .await
            .unwrap();
        wait_for_arrival(&arrived).await;
        // A spoofed, different address in the header must not lift the cap:
        // the peer is the accounting key and the second connection is
        // dropped at the accept layer (same as today).
        let refused = http_get_with_xff(addr, Some("203.0.113.10")).await;
        assert!(
            refused.is_empty(),
            "an untrusted peer must not change its accounting with X-Forwarded-For"
        );
        gate.add_permits(4);
        let (first_body, _) = read_to_eof(first, Duration::from_secs(3)).await;
        assert!(String::from_utf8_lossy(&first_body).contains("200 OK"));
        tx.send(true).unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn serve_limited_rate_limits_forwarded_clients_of_trusted_proxies() {
        // The per-IP connection rate limiter must key on the forwarded
        // client too, otherwise every client behind the proxy shares one
        // window. The injected clock keeps the window deterministic.
        let now = Arc::new(std::sync::atomic::AtomicU64::new(1_700_000_000));
        let limiter = IpConnLimiter::with_clock(
            1,
            Arc::new({
                let now = Arc::clone(&now);
                move || now.load(std::sync::atomic::Ordering::Relaxed)
            }),
        )
        .expect("a positive limit yields a limiter");
        let (addr, tx, handle) = serve_limited_with_proxies(
            10,
            0,
            Some(Duration::from_secs(30)),
            Some(limiter),
            vec![TrustedProxy::parse("127.0.0.1/32").unwrap()],
        )
        .await;
        let first = http_get_with_xff(addr, Some("203.0.113.9")).await;
        assert!(
            String::from_utf8_lossy(&first).contains("200 OK"),
            "the first forwarded connection must be served"
        );
        // The same client within the same second is refused with 429.
        let refused = http_get_with_xff(addr, Some("203.0.113.9")).await;
        assert!(
            String::from_utf8_lossy(&refused).contains("429"),
            "the forwarded address must feed the rate limiter"
        );
        // Another client has its own window.
        let other = http_get_with_xff(addr, Some("203.0.113.10")).await;
        assert!(
            String::from_utf8_lossy(&other).contains("200 OK"),
            "a different forwarded client must pass"
        );
        tx.send(true).unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn ws_connection_holds_the_per_ip_slot_after_upgrade() {
        // Regression: the accept layer and the WebSocket layer used to
        // count per-IP connections independently, so one host could hold
        // `2 * max_connections_per_ip` sockets and a WS connection released
        // its accept slot at the upgrade. The upgraded WebSocket now keeps
        // the single shared slot for its whole lifetime.
        let relay = blossom_relay().await;
        let app = axum::Router::new()
            .route("/", axum::routing::get(ws_handler))
            .with_state(Arc::clone(&relay));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(serve_limited(
            listener,
            app,
            10,
            1,
            Some(Duration::from_secs(30)),
            None,
            Arc::from(Vec::new()),
            16,
            crate::stats::Stats::new(),
            rx,
        ));
        // The handshake upgrades and the WebSocket holds the only per-IP
        // slot.
        let mut ws = TcpStream::connect(addr).await.unwrap();
        ws.write_all(
            b"GET / HTTP/1.1\r\nHost: t\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
              Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
        )
        .await
        .unwrap();
        let mut buf = [0u8; 1024];
        let n = ws.read(&mut buf).await.unwrap();
        assert!(
            String::from_utf8_lossy(&buf[..n]).contains("101"),
            "the handshake must upgrade"
        );
        // A plain HTTP connection from the same IP is refused while the
        // WebSocket is open (the old double counter let it through).
        let refused = http_get_with_xff(addr, None).await;
        assert!(
            refused.is_empty(),
            "the live WebSocket must occupy the per-IP slot"
        );
        // Closing the WebSocket releases the slot for the next connection;
        // poll for the release instead of sleeping a fixed interval.
        drop(ws);
        let (conn, _) = wait_for_served(addr).await;
        drop(conn);
        tx.send(true).unwrap();
        handle.await.unwrap();
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn serve_limited_applies_the_per_ip_rate_limit() {
        // The per-second window comes from an injected clock, so the test is
        // deterministic: a wall-clock race across a second boundary can no
        // longer turn the expected refusals into successes.
        let now = Arc::new(std::sync::atomic::AtomicU64::new(1_700_000_000));
        let limiter = IpConnLimiter::with_clock(
            1,
            Arc::new({
                let now = Arc::clone(&now);
                move || now.load(std::sync::atomic::Ordering::Relaxed)
            }),
        )
        .expect("a positive limit yields a limiter");
        let (addr, tx, handle) =
            serve_limited_for_test(10, 0, Some(Duration::from_secs(30)), Some(limiter)).await;
        // The first connection of the second is accepted.
        let (conn1, body) = http_keepalive(addr).await;
        assert!(String::from_utf8_lossy(&body).contains("200 OK"));
        // A second connection from the same IP within the same second is
        // refused by the rate limiter.
        let refused = http_get_with_xff(addr, None).await;
        assert!(
            refused.is_empty(),
            "the rate-limited connection must be dropped"
        );
        // Advancing the injected clock slides the window open, with no
        // sleep and no wall-clock race.
        now.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (conn3, body) = http_keepalive(addr).await;
        assert!(
            String::from_utf8_lossy(&body).contains("200 OK"),
            "the window must slide open after one second"
        );
        drop(conn1);
        drop(conn3);
        tx.send(true).unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn serve_limited_closes_slow_loris_sockets() {
        let (addr, tx, handle) =
            serve_limited_for_test(10, 0, Some(Duration::from_secs(2)), None).await;
        // A connection that never completes its request head is closed
        // after the header read timeout.
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(b"G").await.unwrap();
        let started = std::time::Instant::now();
        let (got, closed) = read_to_eof(s, Duration::from_secs(10)).await;
        assert!(
            closed && got.is_empty(),
            "the slow-loris socket must be closed without a response"
        );
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(1500) && elapsed < Duration::from_secs(9),
            "the timeout must fire near the configured 2s (took {elapsed:?})"
        );
        tx.send(true).unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn serve_limited_closes_silent_sockets() {
        // Regression: the auto builder sniffed the HTTP version by reading
        // up to 24 bytes before arming the header timer, so a socket that
        // sent nothing (or an HTTP/2 preface) pinned a connection — and its
        // share of the accept-layer caps — past `http_read_timeout_secs`.
        // With the HTTP/1 builder the timer is armed on the first read.
        let (addr, tx, handle) =
            serve_limited_for_test(10, 0, Some(Duration::from_secs(2)), None).await;
        let s = TcpStream::connect(addr).await.unwrap();
        let started = std::time::Instant::now();
        let (got, closed) = read_to_eof(s, Duration::from_secs(10)).await;
        assert!(
            closed && got.is_empty(),
            "the silent socket must be closed without a response"
        );
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(1500) && elapsed < Duration::from_secs(9),
            "the timeout must fire near the configured 2s (took {elapsed:?})"
        );
        tx.send(true).unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn serve_limited_header_timeout_can_be_disabled() {
        // `None` (the config maps `http_read_timeout_secs = 0` to `None`):
        // a connection that never completes its request head stays open
        // instead of being closed.
        let (addr, tx, handle) = serve_limited_for_test(10, 0, None, None).await;
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(b"G").await.unwrap();
        let (got, closed) = read_to_eof(s, Duration::from_millis(1500)).await;
        assert!(
            !closed && got.is_empty(),
            "with the timeout disabled the socket must stay open"
        );
        // The socket is still usable: completing the request head gets a
        // response (the connection was not reaped by the header timer).
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let (got, closed) = read_to_eof(s, Duration::from_secs(5)).await;
        assert!(
            closed && String::from_utf8_lossy(&got).contains("200 OK"),
            "a complete request must still be served"
        );
        tx.send(true).unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn serve_limited_drains_on_shutdown() {
        let (addr, tx, handle) =
            serve_limited_for_test(10, 0, Some(Duration::from_secs(30)), None).await;
        let (conn, body) = http_keepalive(addr).await;
        assert!(String::from_utf8_lossy(&body).contains("200 OK"));
        // Shutdown: the accept loop stops and active connections are
        // gracefully closed. The close must be observed as EOF within a
        // short deadline; a read timeout is *not* a drain and must fail the
        // test (the old `is_empty() || contains("200")` assertion passed
        // vacuously in exactly that case).
        tx.send(true).unwrap();
        let started = std::time::Instant::now();
        let (got, closed) = read_to_eof(conn, Duration::from_secs(3)).await;
        assert!(
            closed,
            "the drained connection must reach EOF, not merely time out"
        );
        assert!(
            got.is_empty() || String::from_utf8_lossy(&got).contains("200"),
            "the drained connection must not receive a truncated response"
        );
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "the server must close the drained connection promptly"
        );
        // The accept loop must return promptly after the shutdown signal.
        let joined = tokio::time::timeout(Duration::from_secs(5), handle).await;
        assert!(joined.is_ok(), "the accept loop must stop promptly");
        joined.unwrap().unwrap();
    }

    #[tokio::test]
    async fn shutdown_task_join_is_bounded_and_aborts_stuck_tasks() {
        // The background-task join used to be unbounded: a task inside a
        // long `purge_expired` (or any stuck future) delayed the shutdown
        // forever. The bounded join must return, and the stuck task must be
        // aborted (its next await point cancels).
        let mut tasks: Vec<tokio::task::JoinHandle<()>> =
            vec![tokio::spawn(async { std::future::pending::<()>().await })];
        let started = std::time::Instant::now();
        assert!(
            !join_tasks_bounded(&mut tasks, Duration::from_millis(100)).await,
            "a stuck task must hit the join bound"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the join must not wait for the stuck task"
        );
        let err = tasks.remove(0).await.unwrap_err();
        assert!(err.is_cancelled(), "the stuck task must be aborted");
        // Finished tasks return `true` well before the grace.
        let mut quick: Vec<tokio::task::JoinHandle<()>> = vec![tokio::spawn(async {})];
        assert!(join_tasks_bounded(&mut quick, Duration::from_secs(5)).await);
    }

    #[tokio::test]
    async fn supervised_join_aborts_the_inner_task_not_just_the_wrapper() {
        // Regression: the shutdown bound used to abort only the supervisor
        // wrapper, which detached the real task — the inner walk kept
        // running (and using the database) past the bound. The abort must
        // land on the inner handle.
        use std::sync::atomic::{AtomicUsize, Ordering};
        let counter = std::sync::Arc::new(AtomicUsize::new(0));
        let work = {
            let counter = std::sync::Arc::clone(&counter);
            Box::pin(async move {
                loop {
                    counter.fetch_add(1, Ordering::Relaxed);
                    tokio::task::yield_now().await;
                }
                #[allow(unreachable_code)]
                ()
            }) as std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        };
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<bool>();
        let inner = tokio::spawn(async move {
            let _ = futures_util::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(work)).await;
            let _ = done_tx.send(false);
        });
        let mut supervised = vec![SupervisedTask {
            outer: tokio::spawn(async move {
                let _ = done_rx.await;
            }),
            inner,
        }];
        assert!(
            !join_supervised_bounded(&mut supervised, Duration::from_millis(100)).await,
            "a stuck inner task must hit the join bound"
        );
        // The inner task itself must be aborted, not just detached: its
        // counter stops advancing.
        let frozen = counter.load(Ordering::Relaxed);
        assert!(frozen > 0, "the stuck task must have been running");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            counter.load(Ordering::Relaxed),
            frozen,
            "the aborted inner task must stop making progress"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bind_listener_sets_reuseaddr() {
        // Regression: the backlog change briefly moved binding to a raw
        // `TcpSocket` without SO_REUSEADDR, so every restart failed with
        // EADDRINUSE while TIME_WAITs existed (constant traffic = always).
        let listener = bind_listener(&("127.0.0.1".to_string(), 0), "test")
            .await
            .expect("bind on an ephemeral port");
        let fd = std::os::unix::io::AsRawFd::as_raw_fd(&listener);
        let mut val: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `fd` is a live socket owned by `listener`; `val`/`len`
        // point at valid local memory for the duration of the call.
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                (&mut val as *mut libc::c_int).cast::<libc::c_void>(),
                &mut len,
            )
        };
        assert_eq!(ret, 0, "getsockopt must succeed");
        // Nonzero means set (Linux reports 1, FreeBSD reports 4).
        assert_ne!(
            val, 0,
            "SO_REUSEADDR must be set so restarts survive TIME_WAIT sockets"
        );
    }

    #[test]
    fn ip_conn_limiter_windows_per_second() {
        let limiter = IpConnLimiter::new(2).unwrap();
        let ip: std::net::IpAddr = "203.0.113.7".parse().unwrap();
        let now = 1_700_000_000u64;
        assert!(limiter.allow(ip, now));
        assert!(limiter.allow(ip, now));
        assert!(!limiter.allow(ip, now), "the third connection is refused");
        // The window slides after one second.
        assert!(limiter.allow(ip, now + 1));
        // Another IP has its own window.
        let other: std::net::IpAddr = "203.0.113.8".parse().unwrap();
        assert!(limiter.allow(other, now));
        // Disabled (0) returns no limiter.
        assert!(IpConnLimiter::new(0).is_none());
    }

    #[test]
    fn ip_conn_limiter_map_is_bounded_and_fails_closed() {
        let limiter = IpConnLimiter::new(1).unwrap();
        let mut accepted = 0usize;
        for i in 0..20_000u32 {
            let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, (i >> 8) as u8, i as u8));
            if limiter.allow(ip, 1_700_000_000) {
                accepted += 1;
            }
        }
        assert!(
            limiter.seen.lock().unwrap().windows.len() <= 10_000,
            "the tracked-IP map must not exceed its bound"
        );
        assert!(accepted <= 10_000, "the limiter must not bypass the cap");
        // A full map of unexpired windows refuses new IPs instead of
        // letting them through untracked.
        let extra: std::net::IpAddr = "198.51.100.9".parse().unwrap();
        assert!(!limiter.allow(extra, 1_700_000_000));
        // Once the windows expire, eviction resumes tracking.
        assert!(limiter.allow(extra, 1_700_000_002));
    }

    #[test]
    fn ip_conn_limiter_prunes_at_most_once_per_second() {
        let limiter = IpConnLimiter::new(1).unwrap();
        let now = 1_700_000_000u64;
        for i in 0..10_000u32 {
            let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, (i >> 8) as u8, i as u8));
            assert!(limiter.allow(ip, now));
        }
        // The first full-map refusal triggers the one walk for this second.
        let extra: std::net::IpAddr = "198.51.100.9".parse().unwrap();
        assert!(!limiter.allow(extra, now));
        assert_eq!(
            limiter.seen.lock().unwrap().last_prune,
            now,
            "the full map must be pruned on the first refusal"
        );
        // Further refusals within the same second do not re-walk the map
        // (the windows cannot have expired yet), but still fail closed.
        let other: std::net::IpAddr = "198.51.100.10".parse().unwrap();
        assert!(!limiter.allow(other, now));
        {
            let seen = limiter.seen.lock().unwrap();
            assert_eq!(
                seen.last_prune, now,
                "the O(10k) retain must not run on every accept"
            );
            assert_eq!(seen.windows.len(), 10_000);
        }
        // A second later the expired windows are evicted and new IPs are
        // tracked again.
        assert!(limiter.allow(extra, now + 1));
        assert_eq!(limiter.seen.lock().unwrap().last_prune, now + 1);
    }

    #[test]
    fn ws_paths_for_selects_endpoints() {
        assert_eq!(ws_paths_for("root"), &["/"]);
        assert_eq!(ws_paths_for("inbox-outbox"), &["/inbox", "/outbox"]);
        assert_eq!(
            ws_paths_for("all"),
            &["/", "/inbox", "/outbox"],
            "all serves the root and the inbox/outbox paths"
        );
        assert_eq!(
            ws_paths_for("anything-else"),
            &["/"],
            "unknown values fall back to the root path"
        );
    }

    #[test]
    fn host_split_matches_ports_case_and_ipv6() {
        // The middleware normalizes ports, case and IPv6 brackets through
        // host_header_host before comparing — mirror it here.
        let norm = |h: &str| host_header_host(h).to_ascii_lowercase();
        assert!(host_route_allowed(
            "api.example.com",
            "",
            &norm("api.example.com"),
            "/api/v1/x"
        ));
        assert!(host_route_allowed(
            "api.example.com",
            "",
            &norm("api.example.com:8080"),
            "/api/v1/x"
        ));
        assert!(host_route_allowed(
            "api.example.com",
            "",
            &norm("API.EXAMPLE.COM"),
            "/api/v1/x"
        ));
        assert!(!host_route_allowed(
            "api.example.com",
            "",
            &norm("notapi.example.com"),
            "/api/v1/x"
        ));
        // HTTP requires bracket form for IPv6 Host headers.
        assert!(host_route_allowed("", "::1", &norm("[::1]"), "/upload"));
        assert!(host_route_allowed(
            "",
            "::1",
            &norm("[::1]:8080"),
            "/upload"
        ));
    }

    #[test]
    fn host_route_allocation_matrix() {
        let sha = "ab".repeat(32);
        // blossom only (api_host unset): relay paths stay reachable.
        assert!(host_route_allowed(
            "",
            "media.test",
            "relay.example.com",
            "/health"
        ));
        assert!(host_route_allowed(
            "",
            "media.test",
            "relay.example.com",
            "/metrics"
        ));
        assert!(host_route_allowed(
            "",
            "media.test",
            "relay.example.com",
            "/api/v1/npub1x"
        ));
        assert!(host_route_allowed(
            "",
            "media.test",
            "relay.example.com",
            "/ws"
        ));
        assert!(host_route_allowed(
            "",
            "media.test",
            "media.test",
            &format!("/{sha}")
        ));
        assert!(host_route_allowed(
            "",
            "media.test",
            "media.test",
            "/upload"
        ));
        assert!(!host_route_allowed("", "media.test", "media.test", "/ws"));
        assert!(!host_route_allowed(
            "",
            "media.test",
            "relay.example.com",
            &format!("/{sha}")
        ));
        // api + blossom: each host serves only its own paths.
        assert!(host_route_allowed(
            "api.example.com",
            "media.test",
            "api.example.com",
            "/api/v1/npub1x"
        ));
        assert!(host_route_allowed(
            "api.example.com",
            "media.test",
            "api.example.com",
            "/health"
        ));
        assert!(!host_route_allowed(
            "api.example.com",
            "media.test",
            "api.example.com",
            "/ws"
        ));
        assert!(!host_route_allowed(
            "api.example.com",
            "media.test",
            "relay.example.com",
            "/health"
        ));
        assert!(host_route_allowed(
            "api.example.com",
            "media.test",
            "relay.example.com",
            "/ws"
        ));
        assert!(!host_route_allowed(
            "api.example.com",
            "media.test",
            "media.test",
            "/api/v1/npub1x"
        ));
        // neither split: everything is a relay path (a bare 64-hex path is
        // still a Blossom-shaped path and 404s — no Blossom routes are
        // mounted without `blossom.host`).
        assert!(host_route_allowed("", "", "relay.example.com", "/health"));
        assert!(!host_route_allowed(
            "",
            "",
            "relay.example.com",
            &format!("/{sha}")
        ));
        assert!(!host_route_allowed("", "", "relay.example.com", "/upload"));
    }

    #[test]
    fn host_header_host_extracts_host() {
        assert_eq!(host_header_host("api.example.com"), "api.example.com");
        assert_eq!(host_header_host("api.example.com:8080"), "api.example.com");
        assert_eq!(host_header_host("[::1]"), "::1");
        assert_eq!(host_header_host("[::1]:8080"), "::1");
        assert_eq!(host_header_host("192.0.2.1:80"), "192.0.2.1");
    }
}
