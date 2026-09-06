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
use crate::error::{Error, Result};
use crate::nips::nip11::{relay_info, stats_handler};
use crate::nips::nip86;
use crate::relay::Relay;
use crate::stats::Stats;
use crate::util::unix_now;
use crate::ws::handle_connection;
use api::{
    api_count_handler, api_daily_handler, api_follows_handler, api_handler, api_hourly_handler,
    api_id_handler, api_kind_handler, api_kinds_handler, api_monthly_handler, api_query_handler,
    api_related_handler, api_relay_kinds_handler, api_relays_handler, api_stats_handler,
    api_top_authors_handler,
};
use axum::serve::ListenerExt;
use livekit::{livekit_supported, livekit_token};

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

/// Binds a TCP listener on `addr` and logs the given label with the
/// address, turning a bind failure into a configuration error.
async fn bind_listener(addr: &(String, u16), label: &str) -> Result<TcpListener> {
    let listener = match TcpListener::bind(addr).await {
        Ok(listener) => listener,
        // Log through the logger too: in daemon mode the process stderr
        // goes to /dev/null, so a bind failure (e.g. the port is already
        // in use by another instance) would otherwise be invisible.
        Err(e) => {
            let msg = format!("cannot bind to {}:{}: {e}", addr.0, addr.1);
            log::error!("{msg}");
            return Err(Error::Config(msg));
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
    let max_admin_body = relay.config.read().await.rpc.max_admin_body_bytes;
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
                .layer(axum::extract::DefaultBodyLimit::max(max_admin_body)),
        );
    }
    let cfg = relay.config.read().await;
    if cfg.server.metrics_enabled {
        app = app.route("/metrics", get(metrics_handler));
    }
    if cfg.nip_enabled(29) && !cfg.relay.livekit_url.is_empty() {
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
    if blossom_state.is_some() {
        app = app.merge(blossom::routes(relay).await);
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
    app.layer(axum::middleware::from_fn(cors_middleware))
        .with_state(relay.clone())
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

pub async fn run_server(config_path: PathBuf, config: Config, db: DbClient) -> Result<()> {
    let private_key = config.relay.private_key.clone();
    let live = crate::relay::LiveBusConfig {
        buffer: config.limits.live_buffer,
        batch_interval_ms: config.limits.live_batch_interval_ms,
        batch_size: config.limits.live_batch_size,
    };
    let config = Arc::new(tokio::sync::RwLock::new(config));
    let stats = Stats::new();
    let mut relay = Arc::new(Relay::new(config, db, stats, &private_key, live).await);
    Arc::get_mut(&mut relay)
        .expect("relay not cloned yet")
        .start_live_bus();
    // Make the config file path known to the relay so NIP-86 runtime
    // changes (relay name/description/icon) can be persisted to disk.
    *relay.config_path.write().await = Some(config_path.clone());

    // Rebuild the NIP-29 group state from the stored moderation events.
    if relay.config.read().await.nip_enabled(29) {
        relay.groups.write().await.rebuild(&relay.db).await;
        if relay.has_relay_key() {
            info!(
                "NIP-29 groups enabled (relay key {})",
                relay.relay_pubkey().unwrap_or_default()
            );
        }
    }

    // Rebuild the NIP-43 role store from the stored role definitions and
    // membership lists.
    if relay.config.read().await.nip_enabled(43) {
        relay
            .roles
            .write()
            .await
            .rebuild(&relay.db, &relay.relay_pubkey().unwrap_or_default())
            .await;
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let blossom_state = blossom::build_state(&relay.config.read().await.clone(), &relay).await;
    *relay.blossom.write().await = blossom_state.clone();
    let app = build_router(&relay, blossom_state).await;

    let bind_addr = {
        let cfg = relay.config.read().await;
        (cfg.server.host.clone(), cfg.server.port)
    };
    let listener = bind_listener(&bind_addr, "relay listening on ws://").await?;

    let mut tasks = Vec::new();

    let mgmt = {
        let cfg = relay.config.read().await;
        if cfg.rpc.management_port > 0 {
            let mgmt_addr = (cfg.rpc.management_host.clone(), cfg.rpc.management_port);
            let listener = bind_listener(&mgmt_addr, "management listening on http://").await?;
            Some((mgmt_addr, listener))
        } else {
            None
        }
    };

    if let Some((addr, listener)) = mgmt {
        let max_admin_body = relay.config.read().await.rpc.max_admin_body_bytes;
        let mgmt_app = nip86::router(relay.clone(), shutdown_tx.clone(), max_admin_body);
        let rx = shutdown_rx.clone();
        tasks.push(tokio::spawn(async move {
            if let Err(e) = axum::serve(
                listener.tap_io(|stream| {
                    let _ = stream.set_nodelay(true);
                }),
                mgmt_app,
            )
            .with_graceful_shutdown(await_shutdown(rx))
            .await
            {
                error!("management server error: {e}");
            }
            info!("management server stopped ({addr:?})");
        }));
    }

    tasks.push(tokio::spawn(stats_writer(
        relay.clone(),
        shutdown_rx.clone(),
    )));
    tasks.push(tokio::spawn(purge_loop(relay.clone(), shutdown_rx.clone())));
    tasks.push(tokio::spawn(nip66_publisher(
        relay.clone(),
        shutdown_rx.clone(),
    )));
    tasks.push(tokio::spawn(signal_handler(shutdown_tx.clone())));
    tasks.push(tokio::spawn(reload_handler(
        config_path,
        relay.clone(),
        relay.db.clone(),
        relay.api_limit.clone(),
        shutdown_rx.clone(),
    )));

    let (header_timeout, max_connections, per_sec_per_ip, recv_buf_kb) = {
        let cfg = relay.config.read().await;
        (
            // 0 = disabled (the documented convention): hyper treats
            // `Some(Duration::ZERO)` as an immediate timeout, so the
            // config value is mapped to `None` here.
            (cfg.limits.http_read_timeout_secs > 0)
                .then(|| std::time::Duration::from_secs(cfg.limits.http_read_timeout_secs)),
            cfg.limits.max_connections,
            IpConnLimiter::new(cfg.limits.max_connections_per_sec_per_ip),
            cfg.limits.socket_recv_buffer_kb,
        )
    };
    let _ = serve_limited(
        listener,
        app,
        max_connections,
        header_timeout,
        per_sec_per_ip,
        recv_buf_kb,
        shutdown_rx,
    )
    .await;

    let _ = shutdown_tx.send(true);
    for task in tasks {
        task.await.ok();
    }
    relay.db.shutdown();
    info!("relay stopped");
    Ok(())
}

async fn await_shutdown(mut rx: watch::Receiver<bool>) {
    while !*rx.borrow() {
        if rx.changed().await.is_err() {
            break;
        }
    }
}

/// Returns `true` when the request is a valid WebSocket handshake: the
/// standard upgrade headers must be present (`Upgrade: websocket`,
/// `Connection: upgrade`, `Sec-WebSocket-Version: 13` and a non-empty
/// `Sec-WebSocket-Key`), and a proxy-provided `X-Forwarded-Proto` must be
/// `ws` or `wss`. Anything else is a plain HTTP request.
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
        Some(proto) => {
            let proto = proto.to_ascii_lowercase();
            matches!(proto.as_str(), "ws" | "wss" | "http" | "https")
        }
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
/// the configured Blossom host; `None` otherwise. Used by the shared root
/// route and by the dedicated root route of the `inbox-outbox` mode, so
/// the info document stays available on the Blossom host whatever the
/// WebSocket path selection is. Takes the Host header value (not the whole
/// request) so the future never borrows the request across the await.
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
        // events are stored and served), 96 (HTTP file storage) and
        // 98 (HTTP auth, used for the uploads).
        "supported_nips": [94, 96, 98],
        "supported_file_hashes": ["sha256"],
        "tos_url": null,
        "payment_required": false,
        "upload_url": format!("https://{}/upload", cfg.blossom.host.trim()),
        "max_file_size": cfg.blossom.max_upload_bytes,
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
    let cfg = relay.config.read().await;
    let access = relay.access.read().await;
    let body = Json(relay_info(
        &cfg,
        &access,
        &relay.stats,
        relay.relay_pubkey().as_deref(),
    ));
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
    if let Some(ip) = request
        .extensions()
        .get::<axum::extract::connect_info::ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0.ip())
        && relay
            .access
            .read()
            .await
            .blocked_ips
            .iter()
            .any(|(blocked, _)| {
                blocked
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|b| b == crate::util::normalize_ip(ip))
            })
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    // The Blossom server shares the root `/` route with the relay: when
    // the request Host names the Blossom host, the root path is answered
    // with the Blossom server info instead of the NIP-11 document (and
    // WebSocket upgrades are refused there by the host split).
    let host_header = request
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok());
    if let Some(response) = blossom_root_info(
        relay.clone(),
        host_header,
        is_websocket_request(request.headers()),
    )
    .await
    {
        return response;
    }
    if !is_websocket_request(request.headers()) {
        // Not a WebSocket handshake: serve the NIP-11 info document.
        let wants_nostr_json = request
            .headers()
            .get(axum::http::header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|a| a.contains("application/nostr+json"));
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
                .on_upgrade(move |socket| {
                    handle_connection(
                        socket,
                        relay,
                        peer_ip
                            .map(crate::util::normalize_ip)
                            .unwrap_or_else(|| "0.0.0.0".parse().unwrap()),
                        path,
                    )
                })
                .into_response()
        }
        Err(rejection) => rejection.into_response(),
    }
}

async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({ "status": "ok" })))
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
                if let Ok(json) = serde_json::to_string_pretty(&relay.stats.as_json()) {
                    write_atomic(&path, json.as_bytes());
                }
            }
            _ = shutdown.changed() => break,
        }
    }
}

/// Writes `data` to `path` atomically (temp file + rename) so a crash in
/// the middle of a write never leaves a truncated stats file behind.
fn write_atomic(path: &Path, data: &[u8]) {
    let tmp = path.with_extension("tmp");
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
                if relay.store_relay_event(&mut event).await {
                    log::debug!("nip66: published the relay discovery event");
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
                let removed = relay.db.purge_expired(unix_now()).await;
                if removed > 0 {
                    info!("purged {removed} expired events");
                }
            }
            _ = shutdown.changed() => break,
        }
    }
}

/// Per-IP connection-rate limiter: a host may open at most
/// `max_per_sec` connections per sliding second; excess sockets are
/// refused immediately. Bounded at 10,000 tracked IPs (the map is
/// cleared, not grown, when the bound is reached).
struct IpConnLimiter {
    max_per_sec: u64,
    seen: std::sync::Mutex<
        std::collections::HashMap<std::net::IpAddr, std::collections::VecDeque<u64>>,
    >,
}

impl IpConnLimiter {
    fn new(max_per_sec: u64) -> Option<Self> {
        (max_per_sec > 0).then_some(IpConnLimiter {
            max_per_sec,
            seen: std::sync::Mutex::new(std::collections::HashMap::new()),
        })
    }

    /// Whether a connection from `ip` may be accepted at `now`.
    fn allow(&self, ip: std::net::IpAddr, now: u64) -> bool {
        const MAX_TRACKED_IPS: usize = 10_000;
        let mut seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
        // Already-tracked ips are always enforced: a full map can never
        // disable the limit for tracked ips.
        if let Some(window) = seen.get_mut(&ip) {
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
        // windows are evicted first, a still-full map skips tracking the
        // new ip only.
        if seen.len() >= MAX_TRACKED_IPS {
            seen.retain(|_, w| w.front().is_some_and(|t| now.saturating_sub(*t) < 1));
            if seen.len() >= MAX_TRACKED_IPS {
                return true;
            }
        }
        seen.entry(ip).or_default().push_back(now);
        true
    }
}

/// Serves the main listener with the HTTP-layer hardening: a cap on
/// concurrent connections (`limits.max_connections`, also enforced on
/// plain HTTP and WebSocket upgrades), an optional per-IP connection rate
/// limit, and an HTTP/1.1 header read timeout that closes slow-loris
/// sockets that never complete a request head. On shutdown the accept
/// loop stops, active connections get a graceful-shutdown signal, and
/// stragglers are aborted after a bounded grace period.
#[allow(clippy::too_many_arguments)]
async fn serve_limited(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    max_connections: usize,
    header_timeout: Option<std::time::Duration>,
    per_sec_per_ip: Option<IpConnLimiter>,
    recv_buf_kb: u32,
    mut shutdown: watch::Receiver<bool>,
) {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let active = Arc::new(AtomicUsize::new(0));
    let (drain_tx, drain_rx) = watch::channel(());
    // Connection task handles, used to abort stragglers at shutdown. The
    // vector is pruned of finished handles above 1024 entries, so a
    // long-running relay cannot grow it without bound.
    let mut conn_tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => {
                let Ok((stream, peer)) = accepted else {
                    // An accept error (e.g. EMFILE with exhausted file
                    // descriptors) would otherwise spin the loop hot; back
                    // off briefly so the relay keeps serving existing
                    // connections while the OS recovers.
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                };
                // Per-IP connection rate limit (slow-loris / socket flood).
                // The address is normalized like every other per-IP
                // accounting: a dual-stack listener reports IPv4 peers as
                // ::ffff:a.b.c.d, which must not dodge the per-second cap.
                if let Some(limiter) = &per_sec_per_ip
                    && !limiter.allow(crate::util::normalize_ip(peer.ip()), crate::util::unix_now())
                {
                    continue;
                }
                // Connection cap: refuse the socket outright at the cap so
                // established-but-idle sockets cannot pin file descriptors.
                if active.load(Ordering::Relaxed) >= max_connections {
                    continue;
                }
                active.fetch_add(1, Ordering::Relaxed);

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
                    set_sock_opt(&stream, libc::SO_RCVBUF, (recv_buf_kb * 1024) as i32);
                    set_sock_opt(&stream, libc::SO_SNDBUF, 16 * 1024);
                }

                let app = app.clone();
                let active = Arc::clone(&active);
                let mut drain_rx = drain_rx.clone();
                let io = hyper_util::rt::TokioIo::new(stream);
                // Inject the peer address as ConnectInfo (the axum
                // `ConnectInfo` extractor reads this extension).
                let svc = app.layer(axum::middleware::from_fn(
                    move |mut req: axum::extract::Request,
                          next: axum::middleware::Next| {
                        let peer = peer;
                        async move {
                            req.extensions_mut()
                                .insert(axum::extract::ConnectInfo(peer));
                            next.run(req).await
                        }
                    },
                ));
                let hyper_service = hyper_util::service::TowerToHyperService::new(
                    svc.map_request(|req: hyper::Request<hyper::body::Incoming>| {
                        req.map(axum::body::Body::new)
                    }),
                );
                conn_tasks.push(tokio::spawn(async move {
                    let mut builder = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    );
                    // Slow-loris defense: a connection must complete its
                    // request head within the window or it is closed
                    // (`None` disables the timeout — the config maps 0 to
                    // None so the documented "0 = disabled" holds).
                    builder
                        .http1()
                        .timer(hyper_util::rt::TokioTimer::new())
                        .header_read_timeout(header_timeout);
                    // CONNECT protocol needed for HTTP/2 websockets.
                    builder.http2().enable_connect_protocol();
                    let mut conn = std::pin::pin!(
                        builder.serve_connection_with_upgrades(io, hyper_service)
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
                    active.fetch_sub(1, Ordering::Relaxed);
                }));
                // Bound the handle vector: prune the finished tasks once
                // it grows past 1024 entries (amortized constant work per
                // accept; live tasks are never pruned).
                if conn_tasks.len() > 1024 {
                    conn_tasks.retain(|task| !task.is_finished());
                }
            }
        }
    }
    // Graceful drain: signal every connection, wait a bounded grace, then
    // abort the stragglers so shutdown never hangs on a stuck peer. The
    // grace stays well under the CLI stop timeout (10 s), so a relay with
    // long-lived WebSocket connections still stops in time.
    let _ = drain_tx.send(());
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while active.load(Ordering::Relaxed) > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .ok();
    for task in conn_tasks {
        task.abort();
    }
}

async fn signal_handler(shutdown: watch::Sender<bool>) {
    let mut terminate = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            error!("cannot register SIGTERM handler: {e}");
            return;
        }
    };
    let mut interrupt = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(e) => {
            error!("cannot register SIGINT handler: {e}");
            return;
        }
    };
    tokio::select! {
        _ = terminate.recv() => {}
        _ = interrupt.recv() => {}
    }
    info!("shutdown signal received");
    let _ = shutdown.send(true);
}

async fn reload_handler(
    config_path: PathBuf,
    relay: Arc<Relay>,
    db: DbClient,
    api_limit: Arc<crate::relay::ApiLimiter>,
    mut shutdown: watch::Receiver<bool>,
) {
    let config = relay.config.clone();
    let mut hangup = match signal(SignalKind::hangup()) {
        Ok(s) => s,
        Err(e) => {
            error!("cannot register SIGHUP handler: {e}");
            return;
        }
    };
    loop {
        tokio::select! {
            _ = hangup.recv() => {
                match Config::load(&config_path) {
                    Ok(mut new_config) => {
                        new_config.absolutize_paths(&config_path);
                        // Validate before applying: a parseable-but-invalid
                        // file (zero limits, bad keys, map layout) must not
                        // silently disable the relay at runtime. The old
                        // configuration stays in force on failure.
                        if let Err(e) = new_config.validate() {
                            error!("config reload rejected: {e}");
                            continue;
                        }
                        db.set_expiry_enabled(new_config.nip_enabled(40));
                        api_limit.set_max(new_config.limits.max_api_concurrent);
                        // The relay's signing key is fixed at startup: a
                        // reloaded private_key is not applied (NIP-29/NIP-43
                        // keep signing and NIP-11 `self` keeps advertising
                        // the old key). Warn so the operator knows a restart
                        // is required for it to take effect.
                        let old = config.read().await;
                        if old.relay.private_key != new_config.relay.private_key {
                            warn!(
                                "relay.private_key changed in the reloaded config but is fixed \
                                 at startup; a restart is required to apply it"
                            );
                        }
                        // Settings that shape the HTTP router are also fixed
                        // at startup: a reload cannot rebuild the routes.
                        let static_routes = [
                            ("server.api_host", old.server.api_host != new_config.server.api_host),
                            ("server.host", old.server.host != new_config.server.host),
                            ("server.port", old.server.port != new_config.server.port),
                            ("server.ws_paths", old.server.ws_paths != new_config.server.ws_paths),
                            (
                                "rpc.management_port",
                                old.rpc.management_port != new_config.rpc.management_port,
                            ),
                            (
                                "rpc.management_host",
                                old.rpc.management_host != new_config.rpc.management_host,
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
                                old.relay.livekit_api_secret
                                    != new_config.relay.livekit_api_secret,
                            ),
                            ("relay.enabled_nips", old.relay.enabled_nips != new_config.relay.enabled_nips),
                            ("relay.disabled_nips", old.relay.disabled_nips != new_config.relay.disabled_nips),
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
                                "blossom.host",
                                old.blossom.host != new_config.blossom.host,
                            ),
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
                                old.blossom.max_upload_bytes
                                    != new_config.blossom.max_upload_bytes,
                            ),
                            (
                                "blossom.s3_*",
                                old.blossom.s3_endpoint != new_config.blossom.s3_endpoint
                                    || old.blossom.s3_region != new_config.blossom.s3_region
                                    || old.blossom.s3_bucket != new_config.blossom.s3_bucket
                                    || old.blossom.s3_access_key
                                        != new_config.blossom.s3_access_key
                                    || old.blossom.s3_secret_key
                                        != new_config.blossom.s3_secret_key,
                            ),
                            (
                                "database.path",
                                old.database.path != new_config.database.path,
                            ),
                            (
                                "database.purge_interval_secs",
                                old.database.purge_interval_secs
                                    != new_config.database.purge_interval_secs,
                            ),
                            (
                                "daemon.max_log_size_bytes",
                                old.daemon.max_log_size_bytes
                                    != new_config.daemon.max_log_size_bytes,
                            ),
                            (
                                "daemon.max_log_files",
                                old.daemon.max_log_files != new_config.daemon.max_log_files,
                            ),
                            (
                                "daemon.stats_interval_secs",
                                old.daemon.stats_interval_secs
                                    != new_config.daemon.stats_interval_secs,
                            ),
                            (
                                "database.db_request_timeout_secs",
                                old.database.db_request_timeout_secs
                                    != new_config.database.db_request_timeout_secs,
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
                                "database.max_indexed_words",
                                old.database.max_indexed_words
                                    != new_config.database.max_indexed_words,
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
                                old.limits.live_batch_interval_ms
                                    != new_config.limits.live_batch_interval_ms,
                            ),
                            (
                                "limits.max_connections",
                                old.limits.max_connections != new_config.limits.max_connections,
                            ),
                            (
                                "limits.http_read_timeout_secs",
                                old.limits.http_read_timeout_secs
                                    != new_config.limits.http_read_timeout_secs,
                            ),
                            (
                                "limits.max_connections_per_sec_per_ip",
                                old.limits.max_connections_per_sec_per_ip
                                    != new_config.limits.max_connections_per_sec_per_ip,
                            ),
                            (
                                "limits.socket_recv_buffer_kb",
                                old.limits.socket_recv_buffer_kb
                                    != new_config.limits.socket_recv_buffer_kb,
                            ),
                            (
                                "rpc.max_admin_body_bytes",
                                old.rpc.max_admin_body_bytes
                                    != new_config.rpc.max_admin_body_bytes,
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
                        drop(old);
                        *config.write().await = new_config;
                        // Bump the config version: connections refresh
                        // their cached NIP-40/NIP-42 flags on the next
                        // live batch (see `Conn::config_version`).
                        relay
                            .config_version
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        info!("configuration reloaded from {}", config_path.display());
                    }
                    Err(e) => error!("config reload failed: {e}"),
                }
                // The Blossom upload allowlist and the relay pubkey
                // deny/allow lists live in the database: re-read them (a
                // failed load keeps the previous lists — see
                // `Relay::reload_db_state`).
                relay.reload_db_state().await;
            }
            _ = shutdown.changed() => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpStream;

    /// A relay with a configured Blossom host, for the info-document tests.
    async fn blossom_relay() -> Arc<Relay> {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut cfg = crate::config::Config::default();
        cfg.relay.name = "example relay".into();
        cfg.blossom.host = "media.example.com".into();
        cfg.database.map_size = 16 * 1024 * 1024;
        cfg.database.max_map_size = 256 * 1024 * 1024;
        cfg.database.path = std::env::temp_dir()
            .join("nostrfy-server-test")
            .join(format!("{:x}-{id}", std::process::id()));
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
        Arc::new(
            Relay::new(
                config,
                db,
                crate::stats::Stats::new(),
                "",
                crate::relay::LiveBusConfig {
                    buffer: 1024,
                    batch_interval_ms: 10,
                    batch_size: 64,
                },
            )
            .await,
        )
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
            serde_json::json!([94, 96, 98]),
            "file-related NIPs are advertised"
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
        header_timeout: Option<Duration>,
        per_sec: Option<IpConnLimiter>,
    ) -> (SocketAddr, watch::Sender<bool>, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(serve_limited(
            listener,
            test_app(),
            max_connections,
            header_timeout,
            per_sec,
            16,
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

    /// Reads the connection to EOF (the server closed it), returning the
    /// bytes received.
    async fn read_to_eof(mut s: TcpStream, timeout: Duration) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);
        loop {
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
        buf
    }

    #[tokio::test]
    async fn serve_limited_serves_http_and_applies_the_connection_cap() {
        let (addr, tx, handle) =
            serve_limited_for_test(1, Some(Duration::from_secs(30)), None).await;
        // A normal request is served.
        let (conn1, body) = http_keepalive(addr).await;
        assert!(
            String::from_utf8_lossy(&body).contains("200 OK"),
            "the first connection must be served"
        );
        // With max_connections = 1 the second connection is dropped at the
        // socket level: the TCP connect succeeds but the server refuses.
        let refused = http_keepalive(addr).await;
        assert!(
            refused.1.is_empty(),
            "the capped connection must be dropped without a response"
        );
        // Closing the first connection releases the slot.
        drop(conn1);
        tokio::time::sleep(Duration::from_millis(200)).await;
        let (conn3, body) = http_keepalive(addr).await;
        assert!(
            String::from_utf8_lossy(&body).contains("200 OK"),
            "the slot must be released when the first connection closes"
        );
        drop(conn3);
        tx.send(true).unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn serve_limited_applies_the_per_ip_rate_limit() {
        let (addr, tx, handle) =
            serve_limited_for_test(10, Some(Duration::from_secs(30)), IpConnLimiter::new(1)).await;
        // The first connection of the second is accepted.
        let (conn1, body) = http_keepalive(addr).await;
        assert!(String::from_utf8_lossy(&body).contains("200 OK"));
        // A second connection from the same IP within the same second is
        // refused by the rate limiter.
        let refused = http_keepalive(addr).await;
        assert!(
            refused.1.is_empty(),
            "the rate-limited connection must be dropped"
        );
        // After the window slides, a new connection is accepted again.
        tokio::time::sleep(Duration::from_millis(1100)).await;
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
            serve_limited_for_test(10, Some(Duration::from_secs(2)), None).await;
        // A connection that never completes its request head is closed
        // after the header read timeout.
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(b"G").await.unwrap();
        let started = std::time::Instant::now();
        let got = read_to_eof(s, Duration::from_secs(10)).await;
        assert!(
            got.is_empty(),
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
    async fn serve_limited_header_timeout_can_be_disabled() {
        // `None` (the config maps `http_read_timeout_secs = 0` to `None`):
        // a connection that never completes its request head stays open
        // instead of being closed.
        let (addr, tx, handle) = serve_limited_for_test(10, None, None).await;
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(b"G").await.unwrap();
        let got = read_to_eof(s, Duration::from_millis(1500)).await;
        assert!(
            got.is_empty(),
            "with the timeout disabled the socket must stay open"
        );
        // The socket is still usable: completing the request head gets a
        // response (the connection was not reaped by the header timer).
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let got = read_to_eof(s, Duration::from_secs(5)).await;
        assert!(
            String::from_utf8_lossy(&got).contains("200 OK"),
            "a complete request must still be served"
        );
        tx.send(true).unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn serve_limited_drains_on_shutdown() {
        let (addr, tx, handle) =
            serve_limited_for_test(10, Some(Duration::from_secs(30)), None).await;
        let (conn, body) = http_keepalive(addr).await;
        assert!(String::from_utf8_lossy(&body).contains("200 OK"));
        // Shutdown: the accept loop stops and active connections are
        // gracefully closed.
        tx.send(true).unwrap();
        let got = read_to_eof(conn, Duration::from_secs(10)).await;
        assert!(
            got.is_empty() || String::from_utf8_lossy(&got).contains("200"),
            "the active connection must be closed on shutdown"
        );
        handle.await.unwrap();
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
    fn ip_conn_limiter_map_is_bounded() {
        let limiter = IpConnLimiter::new(1).unwrap();
        for i in 0..20_000u32 {
            let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, (i >> 8) as u8, i as u8));
            assert!(limiter.allow(ip, 1_700_000_000));
        }
        assert!(
            limiter.seen.lock().unwrap().len() <= 10_000,
            "the tracked-IP map must not exceed its bound"
        );
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
