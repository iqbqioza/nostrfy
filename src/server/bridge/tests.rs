use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use base64::Engine as _;
use secp256k1::Keypair;
use serde_json::{Value, json};
use tower::util::ServiceExt;

use crate::config::Config;
use crate::event::Event;
use crate::nips::nip01;
use crate::relay::LiveBusConfig;

fn signed(
    keypair: &Keypair,
    kind: u64,
    tags: Vec<Vec<String>>,
    content: &str,
    created: u64,
) -> Event {
    let pubkey = secp256k1::XOnlyPublicKey::from_keypair(keypair)
        .0
        .to_string();
    let mut event = Event {
        id: String::new(),
        pubkey,
        created_at: created,
        kind,
        tags,
        content: content.to_string(),
        sig: String::new(),
    };
    nip01::sign(&mut event, keypair).unwrap();
    event
}

fn nip98(
    keypair: &Keypair,
    origin: &str,
    path: &str,
    method: &str,
    body: &[u8],
    salt: u64,
) -> String {
    let event = signed(
        keypair,
        crate::nips::nip98::AUTH_KIND,
        vec![
            vec!["u".into(), format!("{origin}{path}")],
            vec!["method".into(), method.into()],
            vec![
                "payload".into(),
                crate::nips::nip98::payload_sha256_hex(body),
            ],
        ],
        &format!("bridge-test-{salt}"),
        crate::util::unix_now(),
    );
    format!(
        "Nostr {}",
        base64::engine::general_purpose::STANDARD.encode(serde_json::to_string(&event).unwrap())
    )
}

fn request(method: Method, uri: &str, auth: Option<&str>, body: Vec<u8>) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(auth) = auth {
        builder = builder.header(axum::http::header::AUTHORIZATION, auth);
    }
    let mut request = builder.body(Body::from(body)).unwrap();
    request
        .extensions_mut()
        .insert(axum::extract::connect_info::ConnectInfo::<
            std::net::SocketAddr,
        >("127.0.0.1:1234".parse().unwrap()));
    request
}

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), 8 * 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn test_relay() -> Arc<crate::relay::Relay> {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir()
        .join("nostrfy-bridge-test")
        .join(format!("{:x}-{id}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    let mut cfg = Config::default();
    cfg.database.path = path;
    cfg.relay.private_key = "01".repeat(32);
    cfg.relay.enabled_buzz = true;
    cfg.database.map_size = 16 * 1024 * 1024;
    cfg.database.max_map_size = 64 * 1024 * 1024;
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
        crate::relay::Relay::new(
            Arc::clone(&config),
            db,
            crate::stats::Stats::new(),
            &"01".repeat(32),
            LiveBusConfig {
                buffer: 1024,
                batch_interval_ms: 10,
                batch_size: 64,
            },
        )
        .await,
    )
}

async fn origin(relay: &crate::relay::Relay) -> String {
    relay.config.read().await.relay_identity().http_origin()
}

#[tokio::test]
async fn info_is_served_without_auth_and_hides_open_membership() {
    let relay = test_relay().await;
    let app = super::super::build_router(&relay, None).await;
    let response = app
        .oneshot(request(Method::GET, "/info", None, Vec::new()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    let nips = body["supported_nips"].as_array().unwrap();
    assert!(nips.iter().any(|n| n == 29));
    assert!(
        !nips.iter().any(|n| n == 43),
        "an open relay must not gate Buzz onboarding on NIP-43"
    );
    assert!(
        body["supported_extensions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|ext| ext == "nip-cl"),
        "NIP-CL must be advertised for Buzz channel labels"
    );
    relay.db.shutdown();
}

#[tokio::test]
async fn bridge_routes_are_absent_when_buzz_is_disabled() {
    let relay = test_relay().await;
    relay.config.write().await.relay.enabled_buzz = false;
    let app = super::super::build_router(&relay, None).await;
    for (method, path) in [
        (Method::GET, "/info"),
        (Method::POST, "/query"),
        (Method::POST, "/count"),
        (Method::POST, "/events"),
    ] {
        let response = app
            .clone()
            .oneshot(request(method, path, None, Vec::new()))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "{path} must not be served when relay.enabled_buzz is false"
        );
    }
    relay.db.shutdown();
}

#[tokio::test]
async fn events_and_query_carry_buzz_channel_metadata() {
    let relay = test_relay().await;
    let app = super::super::build_router(&relay, None).await;
    let keypair = Keypair::from_secret_bytes([7u8; 32]).unwrap();
    let creator = secp256k1::XOnlyPublicKey::from_keypair(&keypair)
        .0
        .to_string();
    let channel = "11111111-1111-4111-8111-111111111111";
    let origin = origin(&relay).await;
    let create = signed(
        &keypair,
        9007,
        vec![
            vec!["h".into(), channel.into()],
            vec!["name".into(), "design".into()],
            vec!["about".into(), "design chat".into()],
            vec!["visibility".into(), "private".into()],
            vec!["channel_type".into(), "forum".into()],
            vec!["t".into(), "workspace".into()],
            vec!["ttl".into(), "3600".into()],
        ],
        "",
        crate::util::unix_now(),
    );
    let create_body = serde_json::to_vec(&create).unwrap();
    let auth = nip98(&keypair, &origin, "/events", "POST", &create_body, 1);
    let response = app
        .clone()
        .oneshot(request(Method::POST, "/events", Some(&auth), create_body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let accepted = body_json(response).await;
    assert_eq!(accepted["accepted"], true);

    let filter = json!([{ "kinds": [39000], "#d": [channel] }]);
    let filter_body = serde_json::to_vec(&filter).unwrap();
    let auth = nip98(&keypair, &origin, "/query", "POST", &filter_body, 2);
    let response = app
        .clone()
        .oneshot(request(Method::POST, "/query", Some(&auth), filter_body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let events = body_json(response).await;
    let meta = &events[0];
    let tags = meta["tags"].as_array().unwrap();
    let tag = |name: &str| {
        tags.iter()
            .find(|t| t[0] == name)
            .map(|t| t[1].as_str().unwrap_or_default())
    };
    assert_eq!(tag("d"), Some(channel));
    assert_eq!(tag("name"), Some("design"));
    assert_eq!(tag("t"), Some("forum"));
    assert_eq!(tag("P"), Some(creator.as_str()));
    assert!(tag("created_at").is_some());
    assert_eq!(tag("ttl"), Some("3600"));
    assert!(tags.iter().any(|t| t[0] == "private"));

    // The membership roster and the relay-signed timeline rows exist too.
    for (kind, expected_type) in [(39002u64, None), (40099u64, Some("channel_created"))] {
        let filter =
            json!([{ "kinds": [kind], "#h": [channel] }, { "kinds": [kind], "#d": [channel] }]);
        let filter_body = serde_json::to_vec(&filter).unwrap();
        let auth = nip98(&keypair, &origin, "/query", "POST", &filter_body, 10 + kind);
        let response = app
            .clone()
            .oneshot(request(Method::POST, "/query", Some(&auth), filter_body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let events = body_json(response).await;
        assert!(
            !events.as_array().unwrap().is_empty(),
            "kind {kind} missing"
        );
        if let Some(expected_type) = expected_type {
            let parsed: Value =
                serde_json::from_str(events[0]["content"].as_str().unwrap()).unwrap();
            assert_eq!(parsed["type"], expected_type);
        }
    }

    // A membership notice reaches its target through #p.
    let filter = json!([{ "kinds": [44100], "#p": [creator] }]);
    let filter_body = serde_json::to_vec(&filter).unwrap();
    let auth = nip98(&keypair, &origin, "/query", "POST", &filter_body, 30);
    let response = app
        .oneshot(request(Method::POST, "/query", Some(&auth), filter_body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let events = body_json(response).await;
    assert!(!events.as_array().unwrap().is_empty());
    relay.db.shutdown();
}

#[tokio::test]
async fn top_level_window_excludes_replies_and_emits_bounds() {
    let relay = test_relay().await;
    let app = super::super::build_router(&relay, None).await;
    let keypair = Keypair::from_secret_bytes([8u8; 32]).unwrap();
    let channel = "22222222-2222-4222-8222-222222222222";
    let origin = origin(&relay).await;
    let create = signed(
        &keypair,
        9007,
        vec![
            vec!["h".into(), channel.into()],
            vec!["name".into(), "stream".into()],
            vec!["visibility".into(), "open".into()],
            vec!["channel_type".into(), "stream".into()],
        ],
        "",
        crate::util::unix_now(),
    );
    let create_body = serde_json::to_vec(&create).unwrap();
    let auth = nip98(&keypair, &origin, "/events", "POST", &create_body, 1);
    app.clone()
        .oneshot(request(Method::POST, "/events", Some(&auth), create_body))
        .await
        .unwrap();

    let now = crate::util::unix_now();
    let root = signed(
        &keypair,
        9,
        vec![vec!["h".into(), channel.into()]],
        "hello",
        now,
    );
    let root_id = root.id.clone();
    let reply = signed(
        &keypair,
        9,
        vec![
            vec!["h".into(), channel.into()],
            vec!["e".into(), root_id.clone(), "".into(), "reply".into()],
        ],
        "reply",
        now + 1,
    );
    let reply_id = reply.id.clone();
    let nested = signed(
        &keypair,
        9,
        vec![
            vec!["h".into(), channel.into()],
            vec!["e".into(), reply_id, "".into(), "reply".into()],
        ],
        "nested",
        now + 2,
    );
    for (index, event) in [root, reply, nested].into_iter().enumerate() {
        let body = serde_json::to_vec(&event).unwrap();
        let auth = nip98(
            &keypair,
            &origin,
            "/events",
            "POST",
            &body,
            20 + index as u64,
        );
        let response = app
            .clone()
            .oneshot(request(Method::POST, "/events", Some(&auth), body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    let filter = json!([{
        "kinds": [9, 40099],
        "#h": [channel],
        "limit": 10,
        "top_level": true,
        "include_aux": true,
        "include_summaries": true,
    }]);
    let filter_body = serde_json::to_vec(&filter).unwrap();
    let auth = nip98(&keypair, &origin, "/query", "POST", &filter_body, 40);
    let response = app
        .oneshot(request(Method::POST, "/query", Some(&auth), filter_body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let events = body_json(response).await;
    let events = events.as_array().unwrap();
    let bounds: Vec<&Value> = events.iter().filter(|e| e["kind"] == 39006).collect();
    assert_eq!(bounds.len(), 1, "exactly one bounds event is required");
    let rows: Vec<&Value> = events.iter().filter(|e| e["kind"] == 9).collect();
    assert_eq!(
        rows.len(),
        1,
        "the reply must not appear as a top-level row"
    );
    assert_eq!(rows[0]["id"].as_str(), Some(root_id.as_str()));
    assert_eq!(
        bounds[0]["content"].as_str(),
        Some(
            json!({"has_more":false,"next_cursor":null})
                .to_string()
                .as_str()
        )
    );
    let summaries: Vec<&Value> = events.iter().filter(|e| e["kind"] == 39005).collect();
    assert_eq!(summaries.len(), 1);
    let summary: Value = serde_json::from_str(summaries[0]["content"].as_str().unwrap()).unwrap();
    assert_eq!(summary["reply_count"], 1);
    assert_eq!(
        summary["descendant_count"], 2,
        "the nested reply must be counted in the summary"
    );
    assert_eq!(summary["last_reply_at"], now + 2);
    relay.db.shutdown();
}

#[tokio::test]
async fn dense_same_second_hidden_prefix_does_not_stall_the_window() {
    // More non-top-level replies at one timestamp than the over-fetch
    // window used to make the next round re-read the same rows, return an
    // empty page and claim exhaustion even though the older root was
    // visible. Complete-second fallback must reach the root.
    let relay = test_relay().await;
    let app = super::super::build_router(&relay, None).await;
    let keypair = Keypair::from_secret_bytes([13u8; 32]).unwrap();
    let channel = "33333333-3333-4333-8333-333333333333";
    let origin = origin(&relay).await;
    let create = signed(
        &keypair,
        9007,
        vec![
            vec!["h".into(), channel.into()],
            vec!["name".into(), "stream".into()],
            vec!["visibility".into(), "open".into()],
            vec!["channel_type".into(), "stream".into()],
        ],
        "",
        crate::util::unix_now(),
    );
    let create_body = serde_json::to_vec(&create).unwrap();
    let auth = nip98(&keypair, &origin, "/events", "POST", &create_body, 1);
    app.clone()
        .oneshot(request(Method::POST, "/events", Some(&auth), create_body))
        .await
        .unwrap();

    let now = crate::util::unix_now();
    let root = signed(
        &keypair,
        9,
        vec![vec!["h".into(), channel.into()]],
        "root",
        now - 2,
    );
    let root_id = root.id.clone();
    assert_eq!(relay.db.put(root, now).await, crate::db::PutOutcome::Stored);
    for i in 0..500 {
        let reply = signed(
            &keypair,
            9,
            vec![
                vec!["h".into(), channel.into()],
                vec!["e".into(), root_id.clone(), "".into(), "reply".into()],
            ],
            &format!("reply-{i}"),
            now - 1,
        );
        assert_eq!(
            relay.db.put(reply, now).await,
            crate::db::PutOutcome::Stored
        );
    }

    let filter = json!([{
        "kinds": [9],
        "#h": [channel],
        "limit": 10,
        "top_level": true,
    }]);
    let body = serde_json::to_vec(&filter).unwrap();
    let auth = nip98(&keypair, &origin, "/query", "POST", &body, 20);
    let response = app
        .oneshot(request(Method::POST, "/query", Some(&auth), body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let events = body_json(response).await;
    let rounds: Vec<&Value> = events
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["kind"] == 9)
        .collect();
    assert_eq!(
        rounds.len(),
        1,
        "the older top-level root must be returned: {events}"
    );
    assert_eq!(rounds[0]["id"].as_str(), Some(root_id.as_str()));
    let bounds: Vec<&Value> = events
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["kind"] == 39006)
        .collect();
    assert_eq!(bounds.len(), 1);
    let bounds_content: Value =
        serde_json::from_str(bounds[0]["content"].as_str().unwrap()).unwrap();
    assert_eq!(bounds_content["has_more"], false);
    relay.db.shutdown();
}

#[tokio::test]
async fn hidden_prefix_across_seconds_fails_explicitly() {
    // Four over-fetch rounds can be filled entirely by rows the caller may
    // not see. There is no visible row to use as the 39006 cursor, so the
    // window must fail explicitly instead of returning an empty
    // "exhausted" page and losing the older visible root.
    let relay = test_relay().await;
    let app = super::super::build_router(&relay, None).await;
    let keypair = Keypair::from_secret_bytes([14u8; 32]).unwrap();
    let other =
        secp256k1::XOnlyPublicKey::from_keypair(&Keypair::from_secret_bytes([15u8; 32]).unwrap())
            .0
            .to_string();
    let channel = "44444444-4444-4444-8444-444444444444";
    let origin = origin(&relay).await;
    let create = signed(
        &keypair,
        9007,
        vec![
            vec!["h".into(), channel.into()],
            vec!["name".into(), "stream".into()],
            vec!["visibility".into(), "open".into()],
            vec!["channel_type".into(), "stream".into()],
        ],
        "",
        crate::util::unix_now(),
    );
    let create_body = serde_json::to_vec(&create).unwrap();
    let auth = nip98(&keypair, &origin, "/events", "POST", &create_body, 1);
    app.clone()
        .oneshot(request(Method::POST, "/events", Some(&auth), create_body))
        .await
        .unwrap();

    let now = crate::util::unix_now();
    let root = signed(
        &keypair,
        9,
        vec![vec!["h".into(), channel.into()]],
        "root",
        now - 1_000,
    );
    assert_eq!(relay.db.put(root, now).await, crate::db::PutOutcome::Stored);
    for i in 0..900 {
        let hidden = signed(
            &keypair,
            crate::nips::nip62::GIFT_WRAP_KIND,
            vec![
                vec!["h".into(), channel.into()],
                vec!["p".into(), other.clone()],
            ],
            "",
            now - 1 - i,
        );
        assert_eq!(
            relay.db.put(hidden, now).await,
            crate::db::PutOutcome::Stored
        );
    }

    let filter = json!([{
        "kinds": [9, 1059],
        "#h": [channel],
        "limit": 10,
        "top_level": true,
    }]);
    let body = serde_json::to_vec(&filter).unwrap();
    let auth = nip98(&keypair, &origin, "/query", "POST", &body, 20);
    let response = app
        .oneshot(request(Method::POST, "/query", Some(&auth), body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    relay.db.shutdown();
}

#[tokio::test]
async fn legacy_thread_frontier_over_1000_fails_explicitly() {
    // The legacy depth_limit path has no signed bounds and cannot represent
    // a DB frontier cut. Returning a short page here would silently lose
    // replies older than the newest 1,000 and their descendants.
    let relay = test_relay().await;
    let app = super::super::build_router(&relay, None).await;
    let keypair = Keypair::from_secret_bytes([16u8; 32]).unwrap();
    let channel = "55555555-5555-4555-8555-555555555555";
    let origin = origin(&relay).await;
    let create = signed(
        &keypair,
        9007,
        vec![
            vec!["h".into(), channel.into()],
            vec!["name".into(), "stream".into()],
            vec!["visibility".into(), "open".into()],
            vec!["channel_type".into(), "stream".into()],
        ],
        "",
        crate::util::unix_now(),
    );
    let create_body = serde_json::to_vec(&create).unwrap();
    let auth = nip98(&keypair, &origin, "/events", "POST", &create_body, 1);
    app.clone()
        .oneshot(request(Method::POST, "/events", Some(&auth), create_body))
        .await
        .unwrap();

    let now = crate::util::unix_now();
    let root = signed(
        &keypair,
        9,
        vec![vec!["h".into(), channel.into()]],
        "root",
        now - 2,
    );
    let root_id = root.id.clone();
    assert_eq!(relay.db.put(root, now).await, crate::db::PutOutcome::Stored);
    for i in 0..1_001 {
        let reply = signed(
            &keypair,
            9,
            vec![
                vec!["h".into(), channel.into()],
                vec!["e".into(), root_id.clone(), "".into(), "reply".into()],
            ],
            &format!("reply-{i}"),
            now - 1 - i,
        );
        assert_eq!(
            relay.db.put(reply, now).await,
            crate::db::PutOutcome::Stored
        );
    }

    let filter = json!([{
        "kinds": [9],
        "#h": [channel],
        "#e": [root_id],
        "depth_limit": 10,
        "limit": 100,
    }]);
    let body = serde_json::to_vec(&filter).unwrap();
    let auth = nip98(&keypair, &origin, "/query", "POST", &body, 20);
    let response = app
        .oneshot(request(Method::POST, "/query", Some(&auth), body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    relay.db.shutdown();
}

#[tokio::test]
async fn forged_dm_open_is_rejected_before_creating_a_dm() {
    let relay = test_relay().await;
    let app = super::super::build_router(&relay, None).await;
    let keypair = Keypair::from_secret_bytes([11u8; 32]).unwrap();
    let other =
        secp256k1::XOnlyPublicKey::from_keypair(&Keypair::from_secret_bytes([12u8; 32]).unwrap())
            .0
            .to_string();
    let origin = origin(&relay).await;

    let mut open = signed(
        &keypair,
        41010,
        vec![vec!["p".into(), other]],
        "",
        crate::util::unix_now(),
    );
    // The NIP-98 header authenticates the signer, not the event signature.
    // A forged event must still go through precheck before the relay runs
    // the DM command (which mutates group state).
    open.sig = "ff".repeat(64);
    let body = serde_json::to_vec(&open).unwrap();
    let auth = nip98(&keypair, &origin, "/events", "POST", &body, 1);
    let response = app
        .clone()
        .oneshot(request(Method::POST, "/events", Some(&auth), body))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "a forged DM command must be rejected"
    );

    // No DM group was created as a side effect.
    let filter = json!([{ "kinds": [39000], "#t": ["dm"], "limit": 10 }]);
    let body = serde_json::to_vec(&filter).unwrap();
    let auth = nip98(&keypair, &origin, "/query", "POST", &body, 2);
    let response = app
        .clone()
        .oneshot(request(Method::POST, "/query", Some(&auth), body))
        .await
        .unwrap();
    let events = body_json(response).await;
    assert!(
        events.as_array().unwrap().is_empty(),
        "a rejected DM command must not leave a DM group behind: {events}"
    );
    relay.db.shutdown();
}

#[tokio::test]
async fn buzz_dm_open_and_hide_publish_group_and_visibility() {
    let relay = test_relay().await;
    let app = super::super::build_router(&relay, None).await;
    let keypair = Keypair::from_secret_bytes([9u8; 32]).unwrap();
    let other =
        secp256k1::XOnlyPublicKey::from_keypair(&Keypair::from_secret_bytes([10u8; 32]).unwrap())
            .0
            .to_string();
    let origin = origin(&relay).await;

    let open = signed(
        &keypair,
        41010,
        vec![vec!["p".into(), other.clone()]],
        "",
        crate::util::unix_now(),
    );
    let body = serde_json::to_vec(&open).unwrap();
    let auth = nip98(&keypair, &origin, "/events", "POST", &body, 1);
    let response = app
        .clone()
        .oneshot(request(Method::POST, "/events", Some(&auth), body))
        .await
        .unwrap();
    let status = response.status();
    let ack = body_json(response).await;
    assert_eq!(status, StatusCode::OK, "event rejected: {ack}");
    let message = ack["message"].as_str().unwrap();
    let payload: Value = serde_json::from_str(message.strip_prefix("response:").unwrap()).unwrap();
    let channel = payload["channel_id"].as_str().unwrap().to_string();

    let filter = json!([{ "kinds": [39000], "#d": [channel] }]);
    let body = serde_json::to_vec(&filter).unwrap();
    let auth = nip98(&keypair, &origin, "/query", "POST", &body, 2);
    let response = app
        .clone()
        .oneshot(request(Method::POST, "/query", Some(&auth), body))
        .await
        .unwrap();
    let events = body_json(response).await;
    let tags = events[0]["tags"].as_array().unwrap();
    assert!(tags.iter().any(|t| t[0] == "t" && t[1] == "dm"));
    assert!(tags.iter().any(|t| t[0] == "private"));
    assert!(tags.iter().any(|t| t[0] == "hidden"));
    assert!(
        tags.iter()
            .any(|t| t[0] == "p" && t[1].as_str() == Some(other.as_str())),
        "the DM metadata must name its participants: {tags:?}"
    );

    let filter = json!([{ "kinds": [39002], "#d": [channel] }]);
    let body = serde_json::to_vec(&filter).unwrap();
    let auth = nip98(&keypair, &origin, "/query", "POST", &body, 3);
    let response = app
        .clone()
        .oneshot(request(Method::POST, "/query", Some(&auth), body))
        .await
        .unwrap();
    let events = body_json(response).await;
    let members: Vec<&str> = events[0]["tags"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|t| t[0] == "p")
        .map(|t| t[1].as_str().unwrap())
        .collect();
    assert!(members.contains(&other.as_str()));
    assert!(members.len() >= 2);

    let hide = signed(
        &keypair,
        41012,
        vec![vec!["h".into(), channel.clone()]],
        "",
        crate::util::unix_now(),
    );
    let body = serde_json::to_vec(&hide).unwrap();
    let auth = nip98(&keypair, &origin, "/events", "POST", &body, 4);
    let response = app
        .clone()
        .oneshot(request(Method::POST, "/events", Some(&auth), body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let me = secp256k1::XOnlyPublicKey::from_keypair(&keypair)
        .0
        .to_string();
    let filter = json!([{ "kinds": [30622], "#p": [me] }]);
    let body = serde_json::to_vec(&filter).unwrap();
    let auth = nip98(&keypair, &origin, "/query", "POST", &body, 5);
    let response = app
        .clone()
        .oneshot(request(Method::POST, "/query", Some(&auth), body))
        .await
        .unwrap();
    let events = body_json(response).await;
    assert_eq!(events[0]["kind"], 30622);
    assert!(
        events[0]["tags"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t[0] == "h" && t[1].as_str() == Some(channel.as_str()))
    );
    relay.db.shutdown();
}

#[tokio::test]
async fn count_excludes_system_channel_events_unless_the_filter_names_the_channel() {
    let relay = test_relay().await;
    let keypair = Keypair::from_secret_bytes([13u8; 32]).unwrap();
    let channel = "55555555-5555-4555-8555-555555555555";
    let now = crate::util::unix_now();
    let create = signed(
        &keypair,
        9007,
        vec![
            vec!["h".into(), channel.into()],
            vec!["name".into(), "system".into()],
            vec!["visibility".into(), "open".into()],
            vec!["channel_type".into(), "system".into()],
        ],
        "",
        now,
    );
    assert!(matches!(
        relay.accept_event(create, &[], None).await,
        crate::db::PutOutcome::Stored
    ));
    let message = signed(
        &keypair,
        9,
        vec![vec!["h".into(), channel.into()]],
        "system state",
        now + 1,
    );
    assert!(matches!(
        relay.accept_event(message, &[], None).await,
        crate::db::PutOutcome::Stored
    ));

    let app = super::super::build_router(&relay, None).await;
    let origin = origin(&relay).await;
    for (index, (filter, expected)) in [
        (json!([{ "kinds": [9] }]), 0u64),
        (json!([{ "kinds": [9], "#h": [channel] }]), 1u64),
    ]
    .into_iter()
    .enumerate()
    {
        let body = serde_json::to_vec(&filter).unwrap();
        let auth = nip98(
            &keypair,
            &origin,
            "/count",
            "POST",
            &body,
            60 + index as u64,
        );
        let response = app
            .clone()
            .oneshot(request(Method::POST, "/count", Some(&auth), body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let count = body_json(response).await;
        assert_eq!(
            count["count"], expected,
            "system-channel state must only count when named: {filter}"
        );
    }
    relay.db.shutdown();
}

#[tokio::test]
async fn before_id_cursor_splits_a_dense_second_without_duplicates() {
    let relay = test_relay().await;
    let app = super::super::build_router(&relay, None).await;
    let keypair = Keypair::from_secret_bytes([11u8; 32]).unwrap();
    let channel = "33333333-3333-4333-8333-333333333333";
    let origin = origin(&relay).await;
    let create = signed(
        &keypair,
        9007,
        vec![
            vec!["h".into(), channel.into()],
            vec!["name".into(), "dense".into()],
            vec!["visibility".into(), "open".into()],
            vec!["channel_type".into(), "stream".into()],
        ],
        "",
        crate::util::unix_now(),
    );
    let body = serde_json::to_vec(&create).unwrap();
    let auth = nip98(&keypair, &origin, "/events", "POST", &body, 1);
    app.clone()
        .oneshot(request(Method::POST, "/events", Some(&auth), body))
        .await
        .unwrap();

    let second = crate::util::unix_now();
    let mut ids = Vec::new();
    for index in 0..5 {
        let event = signed(
            &keypair,
            9,
            vec![vec!["h".into(), channel.into()]],
            &format!("message {index}"),
            second,
        );
        ids.push(event.id.clone());
        let body = serde_json::to_vec(&event).unwrap();
        let auth = nip98(&keypair, &origin, "/events", "POST", &body, 10 + index);
        let response = app
            .clone()
            .oneshot(request(Method::POST, "/events", Some(&auth), body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    for page in 0..5 {
        let mut filter = json!({
            "kinds": [9],
            "#h": [channel],
            "until": second,
            "limit": 2,
        });
        if let Some(id) = &cursor {
            filter["before_id"] = json!(id);
        }
        let body = serde_json::to_vec(&vec![filter]).unwrap();
        let auth = nip98(&keypair, &origin, "/query", "POST", &body, 30 + page);
        let response = app
            .clone()
            .oneshot(request(Method::POST, "/query", Some(&auth), body))
            .await
            .unwrap();
        let events = body_json(response).await;
        let events = events.as_array().unwrap();
        if events.is_empty() {
            break;
        }
        for event in events {
            let id = event["id"].as_str().unwrap().to_string();
            assert!(!seen.contains(&id), "duplicate across pages: {id}");
            seen.push(id);
        }
        cursor = events
            .last()
            .and_then(|event| event["id"].as_str())
            .map(str::to_string);
    }
    seen.sort();
    ids.sort();
    assert_eq!(seen, ids);
    relay.db.shutdown();
}

#[tokio::test]
async fn legacy_thread_path_returns_the_subtree_in_ascending_order() {
    let relay = test_relay().await;
    let app = super::super::build_router(&relay, None).await;
    let keypair = Keypair::from_secret_bytes([12u8; 32]).unwrap();
    let channel = "44444444-4444-4444-8444-444444444444";
    let origin = origin(&relay).await;
    let create = signed(
        &keypair,
        9007,
        vec![
            vec!["h".into(), channel.into()],
            vec!["name".into(), "threads".into()],
            vec!["visibility".into(), "open".into()],
            vec!["channel_type".into(), "stream".into()],
        ],
        "",
        crate::util::unix_now(),
    );
    let body = serde_json::to_vec(&create).unwrap();
    let auth = nip98(&keypair, &origin, "/events", "POST", &body, 1);
    app.clone()
        .oneshot(request(Method::POST, "/events", Some(&auth), body))
        .await
        .unwrap();

    let now = crate::util::unix_now();
    let root = signed(
        &keypair,
        9,
        vec![vec!["h".into(), channel.into()]],
        "root",
        now,
    );
    let root_id = root.id.clone();
    let reply = signed(
        &keypair,
        9,
        vec![
            vec!["h".into(), channel.into()],
            vec!["e".into(), root_id.clone(), "".into(), "reply".into()],
        ],
        "reply",
        now + 1,
    );
    let nested = signed(
        &keypair,
        9,
        vec![
            vec!["h".into(), channel.into()],
            vec!["e".into(), reply.id.clone(), "".into(), "reply".into()],
        ],
        "nested",
        now + 2,
    );
    for (index, event) in [root, reply, nested].into_iter().enumerate() {
        let body = serde_json::to_vec(&event).unwrap();
        let auth = nip98(
            &keypair,
            &origin,
            "/events",
            "POST",
            &body,
            10 + index as u64,
        );
        app.clone()
            .oneshot(request(Method::POST, "/events", Some(&auth), body))
            .await
            .unwrap();
    }

    let filter = json!([{
        "kinds": [9],
        "#h": [channel],
        "#e": [root_id],
        "depth_limit": 10,
        "limit": 100,
        "include_aux": true,
    }]);
    let body = serde_json::to_vec(&filter).unwrap();
    let auth = nip98(&keypair, &origin, "/query", "POST", &body, 20);
    let response = app
        .oneshot(request(Method::POST, "/query", Some(&auth), body))
        .await
        .unwrap();
    let events = body_json(response).await;
    let contents: Vec<&str> = events
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event["content"].as_str().unwrap())
        .collect();
    assert_eq!(contents, vec!["reply", "nested"]);
    relay.db.shutdown();
}

#[test]
fn bridge_url_matches_only_the_configured_relay_identity() {
    let mut cfg = Config::default();
    cfg.relay.public_url = "wss://relay.example.com".into();
    assert!(
        super::bridge_url_matches(&cfg, "https://relay.example.com/query", "/query"),
        "the configured public origin must authorize the bridge"
    );
    assert!(
        !super::bridge_url_matches(&cfg, "https://other.example/query", "/query"),
        "a captured token for another origin must not become valid just by changing Host"
    );
    assert!(
        !super::bridge_url_matches(&cfg, "https://relay.example.com.evil/query", "/query"),
        "the authority must match exactly"
    );
}

#[test]
fn bridge_url_allows_loopback_aliases_only_without_a_public_url() {
    let mut cfg = Config::default();
    cfg.relay.public_url.clear();
    cfg.server.host = "127.0.0.1".into();
    assert!(super::bridge_url_matches(
        &cfg,
        "http://localhost:8080/query",
        "/query"
    ));
    assert!(!super::bridge_url_matches(
        &cfg,
        "https://relay.example.com/query",
        "/query"
    ));
    assert!(!super::bridge_url_matches(
        &cfg,
        "http://localhost:9999/query",
        "/query"
    ));
    assert!(!super::bridge_url_matches(
        &cfg,
        "https://localhost:8080/query",
        "/query"
    ));
}
