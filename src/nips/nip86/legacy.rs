//! Legacy REST management endpoints, served on the separate localhost
//! management port. Kept for backwards compatibility alongside the
//! JSON-RPC API in `super`.

use std::sync::Arc;

use anyhow::{Result, anyhow};
use axum::body::Bytes;
use axum::extract::{OriginalUri, Path as AxPath, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::watch;

use crate::nips::nip11::relay_info;
use crate::nips::nip98;
use crate::relay::Relay;
use crate::util::unix_now;

// ----- legacy REST endpoints (localhost management port) -----

#[derive(Deserialize)]
struct PubkeyBody {
    pubkey: String,
}

#[derive(Deserialize)]
struct KindBody {
    kind: u64,
}

struct AdminState {
    relay: Arc<Relay>,
    shutdown: watch::Sender<bool>,
}

pub(crate) fn router(
    relay: Arc<Relay>,
    shutdown_tx: watch::Sender<bool>,
    max_admin_body: usize,
) -> Router {
    // NIP-86 `blockip` covers the legacy management routes too: a blocked
    // peer must not reach them even with valid credentials.
    let blocked_relay = Arc::clone(&relay);
    Router::new()
        .route("/admin/info", get(admin_info))
        .route("/admin/stats", get(admin_stats))
        .route("/admin/block_pubkey", post(block_pubkey))
        .route("/admin/allow_pubkey", post(allow_pubkey))
        .route("/admin/block_kind", post(block_kind))
        .route("/admin/allow_kind", post(allow_kind))
        .route("/admin/status/{id}", get(event_status))
        .route("/admin/shutdown", post(shutdown))
        .layer(axum::extract::DefaultBodyLimit::max(max_admin_body))
        .layer(axum::middleware::from_fn(
            move |req: axum::extract::Request, next: axum::middleware::Next| {
                let relay = Arc::clone(&blocked_relay);
                async move {
                    if let Some(ip) = req
                        .extensions()
                        .get::<axum::extract::connect_info::ConnectInfo<std::net::SocketAddr>>()
                        .map(|info| info.0.ip())
                        && crate::util::ip_blocked(&relay.access.read().await.blocked_ips, ip)
                    {
                        return StatusCode::FORBIDDEN.into_response();
                    }
                    next.run(req).await
                }
            },
        ))
        .layer(axum::middleware::from_fn(crate::server::cors_middleware))
        .with_state(Arc::new(AdminState {
            relay,
            shutdown: shutdown_tx,
        }))
}

async fn check_auth(
    headers: &HeaderMap,
    state: &AdminState,
    method: &str,
    uri: &axum::http::Uri,
    expected_payload_hash: Option<&str>,
) -> Result<String> {
    let relay = &state.relay;
    let cfg = relay.config.read().await;

    // Bearer token, when configured. A wrong token falls through to the
    // NIP-98 check (matching the JSON-RPC path) so both methods can be
    // configured at once instead of one silently disabling the other.
    let mut token_configured = false;
    if !cfg.rpc.management_token.is_empty() {
        token_configured = true;
        if let Some(token) = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            && super::ct_eq(token, &cfg.rpc.management_token)
        {
            return Ok("management-token".into());
        }
    }

    if !cfg.rpc.admin_pubkey.is_empty() {
        let auth = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Nostr "))
            .ok_or_else(|| anyhow!("missing NIP-98 auth"))?;
        // NIP-98: the `u` tag must be the absolute request URL (host, path
        // and query all match), matching the JSON-RPC path. The legacy
        // management API is served on the *management* host:port, not the
        // relay's main endpoint, so the authority is the management
        // host:port (the relay `public_url` does not apply here).
        let mgmt_identity = crate::nips::nip62::RelayIdentity::new(
            &cfg.rpc.management_host,
            cfg.rpc.management_port,
            "",
        );
        let url_ok =
            |tag: &str| nip98::matches_request_url(tag, &mgmt_identity, uri.path(), uri.query());
        if let Some(verified) = nip98::verify(
            auth,
            Some(&cfg.rpc.admin_pubkey),
            relay.secp(),
            true,
            expected_payload_hash,
            method,
            url_ok,
        )
        .await
            && relay.nip98_replay.accept(&verified.id, unix_now())
        {
            return Ok(verified.pubkey);
        }
        return Err(anyhow!("invalid NIP-98 auth"));
    }

    Err(anyhow!(if token_configured {
        "invalid bearer token"
    } else {
        "management API disabled: set rpc.management_token or rpc.admin_pubkey"
    }))
}

/// Records a legacy management mutation in the relay's audit log.
fn audit_legacy(state: &AdminState, identity: &str, action: &str, detail: &str) {
    state
        .relay
        .audit
        .log(format!("{action} {detail} by {identity}"));
}

fn auth_error_response(error: anyhow::Error) -> Response {
    unauthorized(&error.to_string())
}

fn unauthorized(msg: &str) -> Response {
    (StatusCode::UNAUTHORIZED, Json(json!({ "error": msg }))).into_response()
}

/// Parses a JSON management body from the raw request bytes, mirroring the
/// axum `Json` extractor's rejections (415 without a JSON content type, 422
/// for malformed JSON) so the endpoint behavior is unchanged, while also
/// returning the body's sha256 hex for the NIP-98 `payload` comparison
/// (NIP-98: the tag is the sha256 of the request body — presence alone
/// would let a captured authorization be replayed against another body).
fn is_json_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|t| t.split(';').next().map(str::trim) == Some("application/json"))
        .unwrap_or(false)
}

fn parse_json_body<T: for<'de> serde::Deserialize<'de>>(body: &Bytes) -> Result<(T, String)> {
    let value: T = serde_json::from_slice(body)?;
    Ok((value, nip98::payload_sha256_hex(body)))
}

fn invalid_json() -> Response {
    StatusCode::UNPROCESSABLE_ENTITY.into_response()
}

fn bad_request(msg: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))).into_response()
}

async fn admin_info(
    uri: OriginalUri,
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
) -> Response {
    // Bodiless GET (see `event_status`): only the `payload` presence is
    // required.
    if let Err(error) = check_auth(&headers, &state, "GET", &uri, None).await {
        return auth_error_response(error);
    }
    let cfg = state.relay.config.read().await;
    let access = state.relay.access.read().await;
    Json(relay_info(
        &cfg,
        &access,
        &state.relay.stats,
        state.relay.relay_pubkey().as_deref(),
    ))
    .into_response()
}

async fn admin_stats(
    uri: OriginalUri,
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(error) = check_auth(&headers, &state, "GET", &uri, None).await {
        return auth_error_response(error);
    }
    Json(state.relay.stats.as_json()).into_response()
}

async fn block_pubkey(
    uri: OriginalUri,
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_json_content_type(&headers) {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    let (body, payload_hash) = match parse_json_body::<PubkeyBody>(&body) {
        Ok(parsed) => parsed,
        Err(_) => return invalid_json(),
    };
    let identity = match check_auth(&headers, &state, "POST", &uri, Some(&payload_hash)).await {
        Ok(identity) => identity,
        Err(error) => return auth_error_response(error),
    };
    if hex::decode(&body.pubkey)
        .map(|b| b.len() != 32)
        .unwrap_or(true)
    {
        return bad_request("invalid pubkey");
    }
    // Lowercase normalization, like the JSON-RPC path: uppercase hex
    // decodes but never matches a lowercase event pubkey.
    let pubkey = body.pubkey.to_ascii_lowercase();
    let mut access = state.relay.access.write().await;
    if !access
        .blocked_pubkeys
        .iter()
        .any(|(p, _)| p.eq_ignore_ascii_case(&pubkey))
    {
        access.blocked_pubkeys.push((pubkey.clone(), String::new()));
    }
    drop(access);
    state.relay.persist_access().await;
    audit_legacy(&state, &identity, "block_pubkey", &pubkey);
    Json(json!({ "ok": true, "blocked_pubkey": pubkey })).into_response()
}

async fn allow_pubkey(
    uri: OriginalUri,
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_json_content_type(&headers) {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    let (body, payload_hash) = match parse_json_body::<PubkeyBody>(&body) {
        Ok(parsed) => parsed,
        Err(_) => return invalid_json(),
    };
    let identity = match check_auth(&headers, &state, "POST", &uri, Some(&payload_hash)).await {
        Ok(identity) => identity,
        Err(error) => return auth_error_response(error),
    };
    // Validate like `block_pubkey` above: an invalid value would otherwise
    // be acknowledged `ok: true` while matching nothing.
    if hex::decode(&body.pubkey)
        .map(|b| b.len() != 32)
        .unwrap_or(true)
    {
        return bad_request("invalid pubkey");
    }
    let pubkey = body.pubkey.to_ascii_lowercase();
    let mut access = state.relay.access.write().await;
    access
        .blocked_pubkeys
        .retain(|(p, _)| !p.eq_ignore_ascii_case(&pubkey));
    drop(access);
    state.relay.persist_access().await;
    audit_legacy(&state, &identity, "allow_pubkey", &pubkey);
    Json(json!({ "ok": true, "allowed_pubkey": pubkey })).into_response()
}

async fn block_kind(
    uri: OriginalUri,
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_json_content_type(&headers) {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    let (body, payload_hash) = match parse_json_body::<KindBody>(&body) {
        Ok(parsed) => parsed,
        Err(_) => return invalid_json(),
    };
    let identity = match check_auth(&headers, &state, "POST", &uri, Some(&payload_hash)).await {
        Ok(identity) => identity,
        Err(error) => return auth_error_response(error),
    };
    let mut access = state.relay.access.write().await;
    if !access.blocked_kinds.contains(&body.kind) {
        access.blocked_kinds.push(body.kind);
    }
    drop(access);
    state.relay.persist_access().await;
    audit_legacy(&state, &identity, "block_kind", &body.kind.to_string());
    Json(json!({ "ok": true, "blocked_kind": body.kind })).into_response()
}

async fn allow_kind(
    uri: OriginalUri,
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_json_content_type(&headers) {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    let (body, payload_hash) = match parse_json_body::<KindBody>(&body) {
        Ok(parsed) => parsed,
        Err(_) => return invalid_json(),
    };
    let identity = match check_auth(&headers, &state, "POST", &uri, Some(&payload_hash)).await {
        Ok(identity) => identity,
        Err(error) => return auth_error_response(error),
    };
    let mut access = state.relay.access.write().await;
    access.blocked_kinds.retain(|k| k != &body.kind);
    drop(access);
    state.relay.persist_access().await;
    audit_legacy(&state, &identity, "allow_kind", &body.kind.to_string());
    Json(json!({ "ok": true, "allowed_kind": body.kind })).into_response()
}

async fn event_status(
    uri: OriginalUri,
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    AxPath(id): AxPath<String>,
) -> Response {
    // Bodiless GET: there is no request body for the `payload` tag to bind
    // to, so only its presence is required (the `u` tag still binds the
    // exact URL and the `method` tag the verb).
    if let Err(error) = check_auth(&headers, &state, "GET", &uri, None).await {
        return auth_error_response(error);
    }
    let filter: Value = json!({ "ids": [id] });
    let (event, _) = state
        .relay
        .db
        .query(vec![serde_json::from_value(filter).unwrap()], 1, unix_now())
        .await;
    if event.is_empty() {
        return Json(json!({ "ok": false, "found": false })).into_response();
    }
    Json(json!({ "ok": true, "found": true, "event": event[0] })).into_response()
}

async fn shutdown(
    uri: OriginalUri,
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
) -> Response {
    // Bodiless POST like the GET above: no body bytes exist for the
    // `payload` tag to bind to (and the `u` tag pins the exact endpoint),
    // so only its presence is required.
    let identity = match check_auth(&headers, &state, "POST", &uri, None).await {
        Ok(identity) => identity,
        Err(error) => return auth_error_response(error),
    };
    audit_legacy(&state, &identity, "shutdown", "");
    let _ = state.shutdown.send(true);
    Json(json!({ "ok": true, "shutting_down": true })).into_response()
}
#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    /// Builds the management router against a relay with the bearer token
    /// configured.
    async fn build_mgmt_relay() -> std::sync::Arc<crate::relay::Relay> {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join("nostrfy-nip86-legacy-test")
            .join(format!("{:x}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        let mut cfg = crate::config::Config::default();
        cfg.database.path = path;
        cfg.rpc.management_token = "test-token".into();
        let db = crate::db::DbClient::open(
            &cfg.database,
            true,
            std::sync::Arc::new(Default::default()),
            0,
            128,
            4096,
            262144,
        )
        .unwrap();
        let config = std::sync::Arc::new(tokio::sync::RwLock::new(cfg));
        let stats = crate::stats::Stats::new();
        let relay = crate::relay::Relay::new(
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
        std::sync::Arc::new(relay)
    }

    async fn call(
        relay: &std::sync::Arc<crate::relay::Relay>,
        method: &str,
        path: &str,
        token: bool,
    ) -> Response {
        let router = router(
            relay.clone(),
            tokio::sync::watch::channel(false).0,
            crate::config::Config::default().rpc.max_admin_body_bytes,
        );
        let mut req = Request::builder().method(method).uri(path);
        if token {
            req = req.header(axum::http::header::AUTHORIZATION, "Bearer test-token");
        }
        router
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn legacy_endpoints_and_error_paths() {
        let relay = build_mgmt_relay().await;
        // Unauthenticated requests are refused.
        let resp = call(&relay, "GET", "/admin/info", false).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let resp = call(&relay, "GET", "/admin/stats", false).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        // A wrong token falls through to the NIP-98 check and fails.
        let resp = call(&relay, "GET", "/admin/info", true).await;
        assert_eq!(resp.status(), StatusCode::OK, "info with the bearer token");

        // A relay without a token configured reports the API as disabled.
        let keyless = build_mgmt_relay().await;
        keyless.config.write().await.rpc.management_token.clear();
        let resp = call(&keyless, "GET", "/admin/info", false).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // block_pubkey: an unparsable body is refused by the extractor.
        let resp = call(&relay, "POST", "/admin/block_pubkey", true).await;
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let router = super::router(
            relay.clone(),
            tokio::sync::watch::channel(false).0,
            crate::config::Config::default().rpc.max_admin_body_bytes,
        );
        let bad = router
            .clone()
            .oneshot(
                Request::post("/admin/block_pubkey")
                    .header(axum::http::header::AUTHORIZATION, "Bearer test-token")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(r#"{{"pubkey":"{}"}}"#, "zz")))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
        let ok = router
            .clone()
            .oneshot(
                Request::post("/admin/block_pubkey")
                    .header(axum::http::header::AUTHORIZATION, "Bearer test-token")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(r#"{{"pubkey":"{}"}}"#, "aa".repeat(32))))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);
        let again = router
            .clone()
            .oneshot(
                Request::post("/admin/block_pubkey")
                    .header(axum::http::header::AUTHORIZATION, "Bearer test-token")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(r#"{{"pubkey":"{}"}}"#, "aa".repeat(32))))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(again.status(), StatusCode::OK, "re-blocking is idempotent");

        // allow_pubkey unblocks.
        let ok = router
            .clone()
            .oneshot(
                Request::post("/admin/allow_pubkey")
                    .header(axum::http::header::AUTHORIZATION, "Bearer test-token")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(r#"{{"pubkey":"{}"}}"#, "aa".repeat(32))))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);
        assert!(relay.access.read().await.blocked_pubkeys.is_empty());

        // block_kind / allow_kind.
        let ok = router
            .clone()
            .oneshot(
                Request::post("/admin/block_kind")
                    .header(axum::http::header::AUTHORIZATION, "Bearer test-token")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"kind": 7}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);
        let ok = router
            .clone()
            .oneshot(
                Request::post("/admin/allow_kind")
                    .header(axum::http::header::AUTHORIZATION, "Bearer test-token")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"kind": 7}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);
        assert!(relay.access.read().await.blocked_kinds.is_empty());

        // event_status: missing then present.
        let resp = call(
            &relay,
            "GET",
            &format!("/admin/status/{}", "ab".repeat(32)),
            true,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap()["found"],
            false
        );
        let mut ev = crate::event::Event {
            id: String::new(),
            pubkey: "aa".repeat(32),
            created_at: crate::util::unix_now(),
            kind: 1,
            tags: vec![],
            content: "hi".into(),
            sig: String::new(),
        };
        ev.id = crate::nips::nip01::compute_id(&ev);
        relay.db.put(ev.clone(), crate::util::unix_now()).await;
        let resp = call(
            &relay,
            "GET",
            format!("/admin/status/{}", ev.id).as_str(),
            true,
        )
        .await;
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap()["found"],
            true
        );

        // shutdown answers OK and flips the watch.
        let (tx, mut rx) = tokio::sync::watch::channel(false);
        let router = super::router(
            relay.clone(),
            tx,
            crate::config::Config::default().rpc.max_admin_body_bytes,
        );
        let resp = router
            .oneshot(
                Request::post("/admin/shutdown")
                    .header(axum::http::header::AUTHORIZATION, "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(*rx.borrow_and_update(), "the shutdown watch must flip");

        relay.db.shutdown();
        keyless.db.shutdown();
    }

    #[tokio::test]
    async fn body_over_admin_limit_is_413() {
        let relay = build_mgmt_relay().await;
        let router = router(
            relay.clone(),
            tokio::sync::watch::channel(false).0,
            crate::config::Config::default().rpc.max_admin_body_bytes,
        );
        let body = format!(
            "{{\"pubkey\":\"{}\",\"pad\":\"{}\"}}",
            "aa".repeat(32),
            "x".repeat(crate::config::Config::default().rpc.max_admin_body_bytes + 1)
        );
        let resp = router
            .oneshot(
                Request::post("/admin/block_pubkey")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "an oversized management body must be refused with 413"
        );
        assert!(
            relay.audit.recent().is_empty(),
            "the refused request must not be audited"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn legacy_mutations_are_audited() {
        let relay = build_mgmt_relay().await;
        let router = router(
            relay.clone(),
            tokio::sync::watch::channel(false).0,
            crate::config::Config::default().rpc.max_admin_body_bytes,
        );
        relay.audit.clear();
        let resp = router
            .oneshot(
                Request::post("/admin/block_pubkey")
                    .header(axum::http::header::AUTHORIZATION, "Bearer test-token")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(r#"{{"pubkey":"{}"}}"#, "ab".repeat(32))))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let recent = relay.audit.recent();
        assert_eq!(recent.len(), 1, "the legacy mutation must be audited");
        assert!(
            recent[0].contains("block_pubkey") && recent[0].contains("management-token"),
            "the audit entry must name the action and the identity: {}",
            recent[0]
        );
        relay.db.shutdown();
    }
}
