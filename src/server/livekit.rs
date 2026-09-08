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
        .and_then(|v| v.strip_prefix("Nostr "))
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
    let authed = crate::nips::nip98::verify(&encoded, None, relay.secp(), false, "GET", |url| {
        crate::nips::nip98::matches_request_url(
            url,
            &cfg.relay_identity(),
            &expected_path,
            uri.query(),
        )
    })
    .await;
    match authed {
        Some(pubkey) if group_allows(&relay, &group, &pubkey).await => {
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
    let groups = relay.groups.read().await;
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
    getrandom::getrandom(&mut suffix)
        .map_err(|e| crate::error::Error::Other(format!("rng failure: {e}")))?;
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
        cfg.relay.enabled_nips = vec![29];
        cfg.relay.livekit_api_key = "test-key".into();
        cfg.relay.livekit_api_secret = "test-secret".into();
        cfg.relay.livekit_url = "wss://livekit.example.com".into();
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
}
