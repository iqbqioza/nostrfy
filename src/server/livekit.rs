//! NIP-29 LiveKit integration: the well-known capability endpoint and the
//! per-group token endpoint authenticated with NIP-98 HTTP auth.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path as AxPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use serde_json::json;

use base64::Engine;

use crate::config::Config;
use anyhow::anyhow;

use crate::error::Result;
use crate::relay::Relay;
use crate::util::unix_now;

// ----- NIP-29 LiveKit integration -----

/// `GET /.well-known/nip29/livekit` — 204 when LiveKit rooms are supported.
/// All three credentials are required: with a URL but no key/secret every
/// mint would 404, so capability is not advertised either (fail-closed and
/// consistent with `livekit_token` below).
pub(crate) async fn livekit_supported(State(relay): State<Arc<Relay>>) -> impl IntoResponse {
    let cfg = relay.config.read().await;
    if cfg.nip_enabled(29)
        && !cfg.relay.livekit_url.trim().is_empty()
        && !cfg.relay.livekit_api_key.is_empty()
        && !cfg.relay.livekit_api_secret.is_empty()
    {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

/// `GET /.well-known/nip29/livekit/<group>` — issues a LiveKit JWT for a
/// group member, authenticated with a NIP-98 HTTP auth event.
pub(crate) async fn livekit_token(
    State(relay): State<Arc<Relay>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    AxPath(group): AxPath<String>,
) -> impl IntoResponse {
    let cfg = relay.config.read().await;
    // Gate on the URL too (mirroring `livekit_supported`): with `url == ""`
    // a minted token carries an empty endpoint and is unusable; fail closed
    // instead of issuing it.
    if !cfg.nip_enabled(29)
        || cfg.relay.livekit_url.trim().is_empty()
        || cfg.relay.livekit_api_key.is_empty()
        || cfg.relay.livekit_api_secret.is_empty()
    {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "livekit not configured" })),
        );
    }
    let encoded = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(crate::nips::nip98::strip_nostr_scheme)
        .map(str::to_string);
    let Some(encoded) = encoded else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized" })),
        );
    };
    // NIP-29: the auth event's `u` tag must point at this group's livekit
    // token endpoint (exact path and query), and its `method` tag must
    // match the GET request. The signed URL is the path as sent, so the
    // raw (percent-encoded) request path is compared — decoding the
    // `{group}` parameter would never match an id that needs encoding.
    let expected_path = uri.path().to_string();
    let authed =
        crate::nips::nip98::verify(&encoded, None, relay.secp(), false, None, "GET", |url| {
            crate::nips::nip98::matches_request_url(
                url,
                &cfg.relay_identity(),
                &expected_path,
                uri.query(),
            )
        });
    match authed {
        Some(verified)
            if relay.nip98_replay.accept(
                &verified.id,
                unix_now(),
                verified.created_at,
                &verified.pubkey,
            ) && group_allows(&relay, &group, &verified.pubkey.to_ascii_lowercase()).await =>
        {
            // NIP-29: the JWT `sub` starts with the *lowercase* hex
            // pubkey (plus a random suffix), and members are stored
            // lowercase — but wire pubkeys may be uppercase hex, so
            // normalize before minting (and the membership check above).
            let pubkey = verified.pubkey.to_ascii_lowercase();
            match issue_livekit_token(&cfg, &group, &pubkey) {
                Ok(token) => {
                    let url = cfg.relay.livekit_url.clone();
                    (StatusCode::OK, Json(json!({ "token": token, "url": url })))
                }
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": e.to_string() })),
                ),
            }
        }
        _ => (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized" })),
        ),
    }
}

async fn group_allows(relay: &Relay, group: &str, pubkey: &str) -> bool {
    // NIP-86 `banpubkey` applies to token minting too: a banned pubkey is
    // refused on every authenticated service, LiveKit included. The relay
    // allowlist gates minting like publishing: on a `restrict_relay`
    // relay a non-allowlisted pubkey cannot publish, so it must not mint
    // room tokens either (group membership alone is not enough there).
    if !relay.access.read().await.allows_pubkey(pubkey) {
        return false;
    }
    let groups = relay.groups.read().await;
    // The store is derived from state a removal invalidated and the rebuild
    // has not recomputed: membership and settings are no longer certain, so
    // no token is minted (the WS and API read paths fail closed the same
    // way, see `GroupStore::group_is_stale`). Without this a removed member
    // could mint a room token from the stale store.
    if groups.group_is_stale(group) {
        return false;
    }
    match groups.group(group) {
        // Unknown groups are not hosted here: the relay cannot judge
        // membership (the id may be a private group on another relay),
        // so no token is minted for them.
        None => false,
        // LiveKit rooms are opt-in per group (`livekit` tag on the group
        // metadata): a group without it never mints tokens, even when the
        // relay has LiveKit configured globally.
        Some(g) if !g.settings.livekit => false,
        Some(g) => !g.settings.private && !g.settings.restricted || g.is_member(pubkey),
    }
}
fn issue_livekit_token(cfg: &Config, group: &str, pubkey: &str) -> Result<String> {
    let mut suffix = [0u8; 4];
    getrandom::getrandom(&mut suffix).map_err(|e| anyhow!("rng failure: {e}"))?;
    let identity = format!("{pubkey}{}", hex::encode(suffix));
    let now = unix_now();
    let claims = json!({
        "iss": cfg.relay.livekit_api_key,
        "sub": identity,
        "iat": now,
        "nbf": now,
        "exp": now + 3600,
        // LiveKit VideoGrant: the permission fields are direct keys of the
        // `video` claim (a nested `permissions` object would be ignored).
        "video": {
            "room": group,
            "roomJoin": true,
            "canPublish": true,
            "canSubscribe": true,
            "canPublishData": true
        }
    });
    jwt_hs256(&cfg.relay.livekit_api_secret, &claims)
}

/// Minimal HS256 JWT implementation (base64url + HMAC-SHA256).
fn jwt_hs256(secret: &str, claims: &serde_json::Value) -> Result<String> {
    fn b64url(data: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
    }
    let header = b64url(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = b64url(serde_json::to_string(claims)?.as_bytes());
    let signing_input = format!("{header}.{payload}");
    let mac = crate::util::hmac_sha256(secret.as_bytes(), signing_input.as_bytes());
    Ok(format!("{signing_input}.{}", b64url(&mac)))
}

/// Shared HTTP client for the LiveKit Room Service API: the connection pool
/// survives between polls (a fresh client per poll would re-handshake TLS).
fn livekit_http_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(reqwest::Client::new)
}

/// Issues a LiveKit server API token scoped to one room (the `roomAdmin`
/// grant the Room Service API requires for `ListParticipants`).
fn issue_livekit_admin_token(api_key: &str, api_secret: &str, room: &str) -> Result<String> {
    let now = unix_now();
    let claims = json!({
        "iss": api_key,
        "sub": api_key,
        "iat": now,
        "nbf": now,
        "exp": now + 600,
        "video": {
            "room": room,
            "roomAdmin": true
        }
    });
    jwt_hs256(api_secret, &claims)
}

/// The hex pubkeys of the participants in a LiveKit `ListParticipants`
/// response. The relay's minted identities start with the lowercase hex
/// pubkey (NIP-29 requires the initial 64 characters to be the pubkey), so
/// each identity maps back to its participant; identities that do not carry
/// a valid pubkey (foreign tokens, or a multibyte prefix) are skipped.
/// Sorted and deduplicated for a deterministic event id.
pub(crate) fn participant_pubkeys(participants: &[serde_json::Value]) -> Vec<String> {
    let mut out: Vec<String> = participants
        .iter()
        .filter_map(|p| p.get("identity").and_then(|i| i.as_str()))
        .filter_map(|identity| {
            let pubkey = identity.get(..64)?;
            pubkey
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
                .then(|| pubkey.to_ascii_lowercase())
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Maps a Room Service response to the participant pubkeys. A `404` is the
/// Twirp `not_found` code LiveKit returns for a room that no longer exists:
/// a deleted room has nobody live, so it maps to an empty list (returning
/// an error would keep a stale list from before the room died, because
/// every later poll would skip the group the same way).
fn participants_from_response(status: u16, body: &str) -> Result<Vec<String>> {
    if status == 404 {
        return Ok(Vec::new());
    }
    if !(200..300).contains(&status) {
        return Err(anyhow!("livekit ListParticipants failed: HTTP {status}"));
    }
    let body: serde_json::Value =
        serde_json::from_str(body).map_err(|e| anyhow!("livekit response was not JSON: {e}"))?;
    let participants = body
        .get("participants")
        .and_then(|p| p.as_array())
        .map(Vec::as_slice)
        .unwrap_or_default();
    Ok(participant_pubkeys(participants))
}

/// Fetches the live participants of one LiveKit room through the Room
/// Service API (Twirp/JSON). Errors are reported so the caller can skip the
/// group instead of publishing an empty (wrong) list.
pub(crate) async fn fetch_livekit_participants(
    url: &str,
    api_key: &str,
    api_secret: &str,
    room: &str,
) -> Result<Vec<String>> {
    let url = format!(
        "{}/twirp/livekit.RoomService/ListParticipants",
        url.trim_end_matches('/')
    );
    let token = issue_livekit_admin_token(api_key, api_secret, room)?;
    let response = livekit_http_client()
        .post(&url)
        .bearer_auth(token)
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&json!({ "room": room }))?)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| anyhow!("livekit request failed: {e}"))?;
    let status = response.status().as_u16();
    let body = response
        .text()
        .await
        .map_err(|e| anyhow!("livekit response could not be read: {e}"))?;
    participants_from_response(status, &body)
}

/// `GET /.well-known/nip29/livekit/webhook` — the token endpoint for a
/// group literally named "webhook". NIP-29 allows a group id to be any
/// string, and the webhook receiver below shares this path as a static
/// route (which would otherwise shadow the `{group}` route for that id),
/// so the route's `get` half dispatches here.
pub(crate) async fn livekit_token_webhook_group(
    state: State<Arc<Relay>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
) -> impl IntoResponse {
    livekit_token(state, headers, uri, AxPath("webhook".to_string())).await
}

/// `POST /.well-known/nip29/livekit/webhook` — the LiveKit webhook receiver.
///
/// LiveKit signs the raw request body with the API secret: the
/// `Authorization` header carries an HS256 JWT whose `sha256` claim is the
/// base64 SHA-256 of the body (the scheme the LiveKit server SDKs verify).
/// On a participant or room event for a livekit-enabled group the relay
/// refreshes that group's `kind:39004` list immediately instead of waiting
/// for the next poll; anything else is acknowledged and ignored.
pub(crate) async fn livekit_webhook(
    State(relay): State<Arc<Relay>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let (api_key, api_secret) = {
        let cfg = relay.config.read().await;
        (
            cfg.relay.livekit_api_key.clone(),
            cfg.relay.livekit_api_secret.clone(),
        )
    };
    if api_key.is_empty() || api_secret.is_empty() {
        return StatusCode::NOT_FOUND;
    }
    let auth = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if !verify_webhook_auth(auth, &api_key, &api_secret, &body) {
        return StatusCode::UNAUTHORIZED;
    }
    let event: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(event) => event,
        Err(_) => return StatusCode::BAD_REQUEST,
    };
    let kind = event
        .get("event")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let room = event
        .get("room")
        .and_then(|room| room.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let relevant = matches!(
        kind,
        "participant_joined"
            | "participant_left"
            | "participant_connection_aborted"
            | "room_started"
            | "room_finished"
    );
    if !relevant || room.is_empty() {
        return StatusCode::NO_CONTENT;
    }
    let gid = room.to_string();
    if !relay.is_livekit_group(&gid).await {
        return StatusCode::NO_CONTENT;
    }
    // The ListParticipants fetch can take seconds: acknowledge LiveKit
    // first and refresh in the background (a lost refresh is reconciled by
    // the periodic poll).
    let relay = relay.clone();
    tokio::spawn(async move {
        relay.refresh_livekit_participants(&gid).await;
    });
    StatusCode::NO_CONTENT
}

/// Verifies a LiveKit webhook `Authorization` token: an HS256 JWT signed
/// with the API secret whose `iss` is the API key, whose `exp` has not
/// passed, and whose `sha256` matches the base64 SHA-256 of the raw body
/// (the three checks the LiveKit server SDKs perform). `alg: none` and any
/// other algorithm are rejected.
pub(crate) fn verify_webhook_auth(
    token: &str,
    api_key: &str,
    api_secret: &str,
    body: &[u8],
) -> bool {
    let mut segments = token.split('.');
    let (Some(header_seg), Some(payload_seg), Some(signature_seg)) =
        (segments.next(), segments.next(), segments.next())
    else {
        return false;
    };
    if segments.next().is_some() {
        return false;
    }
    let Some(header) = b64url_decode(header_seg) else {
        return false;
    };
    let Ok(header) = serde_json::from_slice::<serde_json::Value>(&header) else {
        return false;
    };
    if header.get("alg").and_then(|v| v.as_str()) != Some("HS256") {
        return false;
    }
    let Some(payload) = b64url_decode(payload_seg) else {
        return false;
    };
    let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&payload) else {
        return false;
    };
    if payload.get("iss").and_then(|v| v.as_str()) != Some(api_key) {
        return false;
    }
    let expired = payload
        .get("exp")
        .and_then(|v| v.as_u64())
        .is_none_or(|exp| exp <= unix_now());
    if expired {
        return false;
    }
    let expected_hash = {
        use base64::Engine as _;
        use sha2::Digest as _;
        base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(body))
    };
    if payload.get("sha256").and_then(|v| v.as_str()) != Some(expected_hash.as_str()) {
        return false;
    }
    let signing_input = format!("{header_seg}.{payload_seg}");
    let expected = crate::util::hmac_sha256(api_secret.as_bytes(), signing_input.as_bytes());
    let Some(signature) = b64url_decode(signature_seg) else {
        return false;
    };
    constant_time_eq(&signature, &expected)
}

fn b64url_decode(data: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(data)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(data))
        .ok()
}

/// Constant-time byte comparison for MACs (the length check is not secret).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;
    use crate::nips::nip01::compute_id;
    use secp256k1::{Keypair, XOnlyPublicKey};

    /// A relay with NIP-29 and LiveKit configured (empty group store).
    async fn build_relay() -> Arc<Relay> {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join("nostrfy-livekit-test")
            .join(format!("{:x}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        let mut cfg = Config::default();
        cfg.database.path = path;
        // Small mappings: the test VM cannot afford several default-sized
        // (1 GB / 1 TiB) LMDB reservations at once.
        cfg.database.map_size = 16 * 1024 * 1024;
        cfg.database.max_map_size = 32 * 1024 * 1024;
        cfg.relay.enabled_nips = vec![29];
        cfg.relay.livekit_api_key = "test-key".into();
        cfg.relay.livekit_api_secret = "test-secret".into();
        cfg.relay.livekit_url = "wss://livekit.example.com".into();
        // The NIP-98 URL check derives the HTTP origin from `public_url`
        // (wss -> https), so the test's signed URL is deterministic.
        cfg.relay.public_url = "wss://relay.example.com".into();
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
        Arc::new(relay)
    }

    /// A NIP-98 HTTP auth event for the token endpoint of `group`, tagged
    /// with the relay's own identity (authority + exact path).
    async fn signed_token_auth(
        relay: &Relay,
        secp: &secp256k1::Secp256k1<secp256k1::All>,
        group: &str,
    ) -> Event {
        let keypair = Keypair::from_seckey_slice(secp, &[7u8; 32]).unwrap();
        let pubkey = XOnlyPublicKey::from_keypair(&keypair).0.to_string();
        let authority = {
            let cfg = relay.config.read().await;
            crate::nips::nip62::authority_of(&cfg.relay_identity()).to_string()
        };
        let mut ev = Event {
            id: String::new(),
            pubkey,
            created_at: unix_now(),
            kind: crate::nips::nip98::AUTH_KIND,
            tags: vec![
                vec![
                    "u".into(),
                    format!("https://{authority}/.well-known/nip29/livekit/{group}"),
                ],
                vec!["method".into(), "GET".into()],
            ],
            content: String::new(),
            sig: String::new(),
        };
        ev.id = compute_id(&ev);
        let id = ev.id_bytes().unwrap();
        ev.sig = secp.sign_schnorr_no_aux_rand(&id, &keypair).to_string();
        ev
    }

    fn encode(ev: &Event) -> String {
        base64::engine::general_purpose::STANDARD.encode(serde_json::to_string(ev).unwrap())
    }

    /// Calls the token endpoint with `group`'s auth and returns the status.
    async fn token_status(
        relay: &Arc<Relay>,
        group: &str,
        auth: &Event,
    ) -> (StatusCode, axum::http::HeaderMap, axum::body::Bytes) {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Nostr {}", encode(auth)).parse().unwrap(),
        );
        let uri: axum::http::Uri = format!("/.well-known/nip29/livekit/{group}")
            .parse()
            .unwrap();
        let resp = livekit_token(
            State(relay.clone()),
            headers,
            uri,
            AxPath(group.to_string()),
        )
        .await
        .into_response();
        let status = resp.status();
        let h = resp.headers().clone();
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        (status, h, body)
    }

    #[tokio::test]
    async fn unknown_group_refuses_token() {
        let relay = build_relay().await;
        let secp = relay.secp().clone();
        let ev = signed_token_auth(&relay, &secp, "ghost-group").await;
        let (status, _, _) = token_status(&relay, "ghost-group", &ev).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a group the relay does not host must not mint a token"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn missing_url_refuses_token() {
        // `livekit_url == ""` must fail closed like `livekit_supported`'s
        // 404: a minted token with an empty endpoint is unusable.
        let relay = build_relay().await;
        relay.groups.write().await.groups.insert(
            "open".into(),
            crate::nips::nip29::Group {
                settings: crate::nips::nip29::GroupSettings::default(),
                ..Default::default()
            },
        );
        {
            let mut cfg = relay.config.write().await;
            cfg.relay.livekit_url = String::new();
        }
        let secp = relay.secp().clone();
        let ev = signed_token_auth(&relay, &secp, "open").await;
        let (status, _, _) = token_status(&relay, "open", &ev).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "an empty livekit_url must not mint a token"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn known_open_group_mints_token() {
        let relay = build_relay().await;
        let settings = crate::nips::nip29::GroupSettings {
            livekit: true,
            ..Default::default()
        };
        relay.groups.write().await.groups.insert(
            "open".into(),
            crate::nips::nip29::Group {
                settings,
                ..Default::default()
            },
        );
        let secp = relay.secp().clone();
        let ev = signed_token_auth(&relay, &secp, "open").await;
        let (status, _, body) = token_status(&relay, "open", &ev).await;
        assert_eq!(status, StatusCode::OK, "an open group admits anyone");
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json["token"].as_str().is_some_and(|t| !t.is_empty()),
            "the response must carry a minted JWT"
        );
        assert_eq!(json["url"], "wss://livekit.example.com");
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn webhook_group_id_mints_like_any_group() {
        // A group id may be any string (NIP-29): the static webhook route
        // shares the path with `{group}`, so its `get` half must still
        // serve the token endpoint for the id "webhook" instead of
        // shadowing it.
        let relay = build_relay().await;
        let settings = crate::nips::nip29::GroupSettings {
            livekit: true,
            ..Default::default()
        };
        relay.groups.write().await.groups.insert(
            "webhook".into(),
            crate::nips::nip29::Group {
                settings,
                ..Default::default()
            },
        );
        let secp = relay.secp().clone();
        let ev = signed_token_auth(&relay, &secp, "webhook").await;
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Nostr {}", encode(&ev)).parse().unwrap(),
        );
        let uri: axum::http::Uri = "/.well-known/nip29/livekit/webhook".parse().unwrap();
        let resp = livekit_token_webhook_group(State(relay.clone()), headers, uri)
            .await
            .into_response();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "the id \"webhook\" must reach the token endpoint"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn group_without_livekit_flag_mints_nothing() {
        // LiveKit rooms are opt-in per group: without the `livekit` tag no
        // token is minted even for an open group.
        let relay = build_relay().await;
        relay.groups.write().await.groups.insert(
            "nolive".into(),
            crate::nips::nip29::Group {
                settings: crate::nips::nip29::GroupSettings::default(),
                ..Default::default()
            },
        );
        let secp = relay.secp().clone();
        let ev = signed_token_auth(&relay, &secp, "nolive").await;
        let (status, _, _) = token_status(&relay, "nolive", &ev).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a group without the livekit flag must not mint"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn known_closed_group_refuses_non_member() {
        let relay = build_relay().await;
        let mut g = crate::nips::nip29::Group::default();
        g.settings.private = true;
        g.settings.livekit = true;
        relay.groups.write().await.groups.insert("closed".into(), g);
        let secp = relay.secp().clone();
        let ev = signed_token_auth(&relay, &secp, "closed").await;
        let (status, _, _) = token_status(&relay, "closed", &ev).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a non-member must be refused by a private group"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn known_closed_group_mints_for_member() {
        let relay = build_relay().await;
        let keypair = Keypair::from_seckey_slice(relay.secp(), &[7u8; 32]).unwrap();
        let pubkey = XOnlyPublicKey::from_keypair(&keypair).0.to_string();
        let mut g = crate::nips::nip29::Group::default();
        g.settings.private = true;
        g.settings.livekit = true;
        g.members.insert(pubkey.clone(), Default::default());
        relay.groups.write().await.groups.insert("closed".into(), g);
        let secp = relay.secp().clone();
        let ev = signed_token_auth(&relay, &secp, "closed").await;
        let (status, _, body) = token_status(&relay, "closed", &ev).await;
        assert_eq!(status, StatusCode::OK, "a member may mint a token");
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["token"].as_str().is_some_and(|t| !t.is_empty()));
        relay.db.shutdown();
    }
    #[tokio::test]
    async fn stale_group_mints_no_token() {
        // B-6: a group-state removal invalidates the derived membership
        // until the rebuild recomputes it — minting from the stale store
        // would hand a removed member a room token. The WS and API read
        // paths fail closed the same way.
        let relay = build_relay().await;
        let keypair = Keypair::from_seckey_slice(relay.secp(), &[7u8; 32]).unwrap();
        let pubkey = XOnlyPublicKey::from_keypair(&keypair).0.to_string();
        let mut g = crate::nips::nip29::Group::default();
        g.settings.private = true;
        g.settings.livekit = true;
        g.members.insert(pubkey.clone(), Default::default());
        relay.groups.write().await.groups.insert("closed".into(), g);
        assert!(
            group_allows(&relay, "closed", &pubkey).await,
            "control: a live store mints for the member"
        );
        // The group's state is invalidated (a removed state event): the
        // same member is refused until the rebuild completes.
        relay
            .groups
            .write()
            .await
            .mark_groups_stale(["closed".to_string()]);
        assert!(
            !group_allows(&relay, "closed", &pubkey).await,
            "a stale group must not mint a token"
        );
        // The global fallback gates every group too.
        relay.groups.write().await.mark_stale();
        assert!(
            !group_allows(&relay, "closed", &pubkey).await,
            "the global stale flag gates minting too"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn non_allowlisted_member_cannot_mint_on_restricted_relay() {
        // The relay allowlist gates minting like publishing: on a
        // `restrict_relay` relay a group member that is not allowlisted
        // cannot publish, so minting a room token for them would bypass
        // the relay policy for audio/video.
        let relay = build_relay().await;
        relay.groups.write().await.groups.insert(
            "open".into(),
            crate::nips::nip29::Group {
                settings: crate::nips::nip29::GroupSettings {
                    livekit: true,
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        relay.config.write().await.access.restrict_relay = true;
        // The gate reads the runtime access state (a SIGHUP reload copies
        // the config flag there); set it the way the reload would.
        relay.access.write().await.restrict_relay = true;
        let secp = relay.secp().clone();
        let ev = signed_token_auth(&relay, &secp, "open").await;
        let (status, _, _) = token_status(&relay, "open", &ev).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a non-allowlisted member must not mint on a restricted relay"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn banned_pubkey_cannot_mint_token() {
        // NIP-86 `banpubkey` applies to LiveKit token minting too.
        let relay = build_relay().await;
        relay.groups.write().await.groups.insert(
            "open".into(),
            crate::nips::nip29::Group {
                settings: crate::nips::nip29::GroupSettings {
                    livekit: true,
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        let secp = relay.secp().clone();
        let ev = signed_token_auth(&relay, &secp, "open").await;
        relay
            .access
            .write()
            .await
            .blocked_pubkeys
            .push((ev.pubkey.clone(), "spam".into()));
        let (status, _, _) = token_status(&relay, "open", &ev).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a banned pubkey must not mint a LiveKit token"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn uppercase_auth_mints_lowercase_subject() {
        // Wire pubkeys may be uppercase hex (hex-decode is
        // case-insensitive and the Schnorr signature verifies over the
        // verbatim string). NIP-29 requires the JWT `sub` to start with
        // the *lowercase* hex pubkey, and members are stored lowercase —
        // so the endpoint normalizes before the membership check and the
        // mint.
        use base64::Engine as _;
        let relay = build_relay().await;
        relay.groups.write().await.groups.insert(
            "open".into(),
            crate::nips::nip29::Group {
                settings: crate::nips::nip29::GroupSettings {
                    livekit: true,
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        let secp = relay.secp().clone();
        let keypair = Keypair::from_seckey_slice(&secp, &[7u8; 32]).unwrap();
        let mut ev = signed_token_auth(&relay, &secp, "open").await;
        ev.pubkey = ev.pubkey.to_ascii_uppercase();
        assert!(
            ev.pubkey.chars().any(|c| c.is_ascii_uppercase()),
            "the test needs hex letters to tell the cases apart"
        );
        ev.id = compute_id(&ev);
        let id = ev.id_bytes().unwrap();
        ev.sig = secp.sign_schnorr_no_aux_rand(&id, &keypair).to_string();
        let (status, _, body) = token_status(&relay, "open", &ev).await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let token = json["token"].as_str().expect("a JWT must be minted");
        let payload = token.split('.').nth(1).expect("a JWT has three parts");
        let claims: serde_json::Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(payload)
                .unwrap(),
        )
        .unwrap();
        let sub = claims["sub"].as_str().expect("sub must be a string");
        assert_eq!(
            &sub[..64],
            &ev.pubkey.to_ascii_lowercase(),
            "the subject must start with the lowercase pubkey"
        );
        // A closed-group member signing uppercase is still recognized.
        let mut g = crate::nips::nip29::Group::default();
        g.settings.private = true;
        g.settings.livekit = true;
        g.members
            .insert(ev.pubkey.to_ascii_lowercase(), Default::default());
        relay.groups.write().await.groups.insert("closed".into(), g);
        let mut ev2 = signed_token_auth(&relay, &secp, "closed").await;
        ev2.pubkey = ev2.pubkey.to_ascii_uppercase();
        ev2.id = compute_id(&ev2);
        let id2 = ev2.id_bytes().unwrap();
        ev2.sig = secp.sign_schnorr_no_aux_rand(&id2, &keypair).to_string();
        let (status, _, _) = token_status(&relay, "closed", &ev2).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "an uppercase-signed member must mint on a closed group"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn token_endpoint_refuses_unauthenticated() {
        let relay = build_relay().await;
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Nostr not-a-token".parse().unwrap(),
        );
        let resp = livekit_token(
            State(relay.clone()),
            headers,
            axum::http::Uri::from_static("/.well-known/nip29/livekit/x"),
            AxPath("x".to_string()),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        relay.db.shutdown();
    }

    #[test]
    fn participants_from_response_treats_a_deleted_room_as_empty() {
        let alice = "aa".repeat(32);
        // A 404 is Twirp's `not_found`: the room no longer exists, so
        // nobody is live (an error would keep a stale list forever).
        assert_eq!(
            participants_from_response(404, r#"{"code":"not_found","msg":"room not found"}"#)
                .unwrap(),
            Vec::<String>::new()
        );
        // A live room's list is parsed; an empty room yields no pubkeys.
        let body =
            json!({ "participants": [{ "identity": format!("{alice}deadbeef") }] }).to_string();
        assert_eq!(participants_from_response(200, &body).unwrap(), vec![alice]);
        assert_eq!(
            participants_from_response(200, r#"{"participants":[]}"#).unwrap(),
            Vec::<String>::new()
        );
        // Other failures stay errors: they must not clear the list.
        assert!(participants_from_response(500, "boom").is_err());
        assert!(participants_from_response(200, "not json").is_err());
    }

    #[test]
    fn participant_pubkeys_parse_identities() {
        // NIP-29: the initial 64 characters of the identity are the
        // lowercase hex pubkey. Foreign identities (invalid hex, short, or
        // multibyte) are skipped, and the result is sorted/deduplicated for
        // a deterministic 39004 event id.
        let alice = "aa".repeat(32);
        let bob = "bb".repeat(32);
        let participants = vec![
            json!({ "identity": format!("{alice}deadbeef") }),
            json!({ "identity": bob.to_uppercase() }),
            json!({ "identity": "zz".repeat(32) }),
            json!({ "identity": "abc" }),
            json!({ "identity": format!("{alice}00000000") }),
            json!({ "identity": "あ".repeat(40) }),
            json!({}),
            json!({ "identity": 42 }),
        ];
        assert_eq!(
            participant_pubkeys(&participants),
            vec![alice, bob],
            "only valid identities survive, sorted and deduplicated"
        );
    }

    /// Builds a webhook token the way LiveKit does (HS256 with a `sha256`
    /// claim over the raw body).
    fn webhook_token(api_key: &str, secret: &str, body: &[u8], exp: u64) -> String {
        use base64::Engine;
        use sha2::Digest;
        let claims = json!({
            "iss": api_key,
            "exp": exp,
            "sha256": base64::engine::general_purpose::STANDARD
                .encode(sha2::Sha256::digest(body)),
        });
        jwt_hs256(secret, &claims).unwrap()
    }

    #[test]
    fn webhook_auth_verifies_signature_issuer_expiry_and_body() {
        let body = br#"{"event":"participant_joined","room":{"name":"g1"}}"#;
        let token = webhook_token("key", "secret", body, unix_now() + 60);
        assert!(verify_webhook_auth(&token, "key", "secret", body));
        // A tampered body fails the sha256 check, and a wrong secret,
        // issuer, or expiry fails.
        assert!(!verify_webhook_auth(
            &token,
            "key",
            "secret",
            br#"{"event":"participant_left"}"#
        ));
        assert!(!verify_webhook_auth(&token, "key", "other", body));
        assert!(!verify_webhook_auth(&token, "other", "secret", body));
        let expired = webhook_token("key", "secret", body, unix_now() - 1);
        assert!(!verify_webhook_auth(&expired, "key", "secret", body));
        // `alg: none` is rejected even though the body hash would match,
        // and malformed tokens never pass.
        use base64::Engine;
        let none = format!(
            "{}.{}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#),
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(br#"{"iss":"key","exp":9999999999}"#),
            "",
        );
        assert!(!verify_webhook_auth(&none, "key", "secret", body));
        assert!(!verify_webhook_auth("", "key", "secret", body));
        assert!(!verify_webhook_auth("a.b", "key", "secret", body));
        assert!(!verify_webhook_auth("a.b.c.d", "key", "secret", body));
    }

    #[test]
    fn minted_token_is_a_verifiable_hs256_jwt() {
        // The endpoint tests cover mint/refuse but never decode the token:
        // a broken signer (wrong secret, malformed claims) would ship as a
        // 200 that no LiveKit server accepts. Mint one and verify it the
        // way a LiveKit server does: three base64url parts, HMAC-SHA256
        // over `header.payload` with the configured secret, and the
        // expected claims (issuer, subject pubkey, 1h expiry, room grant).
        use base64::Engine;
        let mut cfg = Config::default();
        cfg.relay.livekit_api_key = "test-key".into();
        cfg.relay.livekit_api_secret = "test-secret".into();
        let pubkey = "ab".repeat(32);
        let token = issue_livekit_token(&cfg, "room-a", &pubkey).unwrap();
        let mut parts = token.split('.');
        let (header, payload, sig) = (
            parts.next().unwrap(),
            parts.next().unwrap(),
            parts.next().unwrap(),
        );
        assert!(parts.next().is_none(), "a JWT has exactly three parts");
        let decode = |part: &str| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(part)
                .unwrap()
        };
        // The header pins the algorithm; the server must never mint (or a
        // client accept) `alg: none`.
        let header_json: serde_json::Value = serde_json::from_slice(&decode(header)).unwrap();
        assert_eq!(header_json["alg"], "HS256");
        // The signature verifies with the configured secret and nothing else.
        let signing_input = format!("{header}.{payload}");
        let mac = crate::util::hmac_sha256(
            cfg.relay.livekit_api_secret.as_bytes(),
            signing_input.as_bytes(),
        );
        assert_eq!(
            sig,
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac),
            "the token must verify with the configured secret"
        );
        let wrong = crate::util::hmac_sha256(b"wrong-secret", signing_input.as_bytes());
        assert_ne!(
            sig,
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(wrong),
            "a token for one secret must not verify with another"
        );
        // The claims carry the issuer, the pubkey subject, a 1h expiry and
        // the room grant.
        let claims: serde_json::Value = serde_json::from_slice(&decode(payload)).unwrap();
        assert_eq!(claims["iss"], "test-key");
        assert!(
            claims["sub"]
                .as_str()
                .is_some_and(|sub| sub.starts_with(&pubkey)),
            "the subject names the minting pubkey: {claims}"
        );
        let now = unix_now();
        let iat = claims["iat"].as_u64().expect("iat must be a timestamp");
        assert!(
            (iat as i64 - now as i64).abs() <= 5,
            "iat must be now: {claims}"
        );
        assert_eq!(
            claims["exp"].as_u64(),
            Some(iat + 3600),
            "the token lives one hour: {claims}"
        );
        assert_eq!(claims["video"]["room"], "room-a");
        assert_eq!(claims["video"]["roomJoin"], true);
    }
}
