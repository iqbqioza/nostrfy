//! NIP-86: Relay Management API.
//!
//! The current NIP-86 revision defines a JSON-RPC style protocol served on
//! the same URI as the relay's websocket, with `Content-Type:
//! application/nostr+json+rpc` and NIP-98 authentication. For backwards
//! compatibility the older REST endpoints remain available on a separate
//! localhost management port.

mod legacy;

pub(crate) use legacy::router;

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use crate::nips::nip98;
use crate::relay::Relay;

const RPC_CONTENT_TYPE: &str = "application/nostr+json+rpc";

// ----- new-style JSON-RPC API (served on the relay's HTTP endpoint) -----

/// Methods implemented by this relay (a subset of the NIP-86 list).
const SUPPORTED_METHODS: &[&str] = &[
    "supportedmethods",
    "banpubkey",
    "unbanpubkey",
    "listbannedpubkeys",
    "allowpubkey",
    "unallowpubkey",
    "listallowedpubkeys",
    "allowkind",
    "disallowkind",
    "listallowedkinds",
    "changerelayname",
    "changerelaydescription",
    "changerelayicon",
    "createrole",
    "editrole",
    "deleterole",
    "assignrole",
    "unassignrole",
    "blockip",
    "unblockip",
    "listblockedips",
    "banevent",
    "allowevent",
    "listbannedevents",
    "listeventsneedingmoderation",
];

/// Maximum length of a NIP-43 role id accepted through the NIP-86 RPC:
/// the id lands in a stored relay event and the in-memory role map, so it
/// must not be able to grow to the full RPC body size.
const MAX_ROLE_ID_LEN: usize = 64;
/// Bounds for the free-text role fields (same order as `changerelay*`):
/// without them a single 64 KiB `createrole` would persist as a relay event
/// and stay resident in the in-memory role map.
const MAX_ROLE_LABEL_LEN: usize = 200;
const MAX_ROLE_DESC_LEN: usize = 1000;
const MAX_ROLE_COLOR_LEN: usize = 64;

fn check_role_fields(label: &str, description: &str, color: &str) -> Result<(), String> {
    if label.chars().count() > MAX_ROLE_LABEL_LEN {
        return Err(format!(
            "role label exceeds the maximum of {MAX_ROLE_LABEL_LEN} characters"
        ));
    }
    if description.chars().count() > MAX_ROLE_DESC_LEN {
        return Err(format!(
            "role description exceeds the maximum of {MAX_ROLE_DESC_LEN} characters"
        ));
    }
    if color.chars().count() > MAX_ROLE_COLOR_LEN {
        return Err(format!(
            "role color exceeds the maximum of {MAX_ROLE_COLOR_LEN} characters"
        ));
    }
    Ok(())
}

/// Validates a NIP-43 role id: non-empty (after trimming), within the byte
/// length bound, and free of control characters (it lands in a stored relay
/// event's `d` tag and the in-memory role map). Character count is used for
/// the length bound like the other role fields so multibyte ids cannot
/// bypass the intent.
fn check_role_id(id: &str) -> Result<(), String> {
    if id.trim().is_empty() {
        return Err("role id must not be empty".into());
    }
    // Compare against the trimmed form so `" admin"` and `"admin"` cannot
    // become distinct map keys / `d` tags for the same logical role.
    if id != id.trim() {
        return Err("role id must not have leading or trailing whitespace".into());
    }
    // Byte length: the id lands in a stored event's `d` tag and the LMDB
    // index, so multibyte ids must not bypass the bound via char count.
    if id.len() > MAX_ROLE_ID_LEN {
        return Err(format!(
            "role id exceeds the maximum of {MAX_ROLE_ID_LEN} bytes"
        ));
    }
    if id.chars().any(|c| c.is_control()) {
        return Err("role id must not contain control characters".into());
    }
    Ok(())
}

fn rpc_ok(result: Value) -> Response {
    (StatusCode::OK, Json(json!({ "result": result }))).into_response()
}

fn rpc_err(message: &str) -> Response {
    (StatusCode::OK, Json(json!({ "error": message }))).into_response()
}

/// Records a management mutation in the relay's rate-limited audit
/// log: `method` + bounded params + the authenticated identity.
macro_rules! audit {
    ($relay:expr, $identity:expr, $method:expr, $params:expr) => {
        $relay.audit.log(format!(
            "{} {} by {}",
            $method,
            audit_params($params),
            $identity
        ))
    };
}

/// NIP-86 JSON-RPC handler, mounted on `POST /` and `POST /ws`.
pub async fn rpc_handler(
    State(relay): State<Arc<Relay>>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: String,
) -> Response {
    // NIP-86 `blockip` also applies to this endpoint: a blocked peer must
    // not reach the management RPC (the WebSocket handler already refuses
    // its connections).
    if relay.access.read().await.blocked_ips.iter().any(|(b, _)| {
        b.parse::<std::net::IpAddr>()
            .is_ok_and(|b| b == crate::util::normalize_ip(peer.ip()))
    }) {
        return StatusCode::FORBIDDEN.into_response();
    }
    // The spec requires the JSON-RPC content type (parameters such as
    // `; charset=utf-8` are tolerated).
    let is_rpc = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|t| t.split(';').next().map(str::trim) == Some(RPC_CONTENT_TYPE))
        .unwrap_or(false);
    if !is_rpc {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid content type" })),
        )
            .into_response();
    }
    let Some(identity) = rpc_authenticated(&relay, &headers, &uri, &body).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized" })),
        )
            .into_response();
    };
    let request: Value = match serde_json::from_str(&body) {
        Ok(request) => request,
        Err(_) => return rpc_err("invalid request"),
    };
    let Some(method) = request.get("method").and_then(Value::as_str) else {
        return rpc_err("missing method");
    };
    let params = request.get("params").and_then(Value::as_array).cloned();
    let params = params.as_deref().unwrap_or(&[]);

    match method {
        // NIP-86: the result lists "all the OTHER supported methods".
        "supportedmethods" => {
            let others: Vec<&str> = SUPPORTED_METHODS
                .iter()
                .copied()
                .filter(|m| *m != "supportedmethods")
                .collect();
            rpc_ok(json!(others))
        }
        "banpubkey" => {
            let (Some(pubkey), reason) = (
                params.first().and_then(Value::as_str),
                params.get(1).and_then(Value::as_str).unwrap_or(""),
            ) else {
                return rpc_err("invalid params");
            };
            if !is_pubkey(pubkey) {
                return rpc_err("invalid pubkey");
            }
            // Normalize to lowercase hex: `hex::decode` accepts uppercase,
            // but events carry lowercase pubkeys and the access checks
            // compare case-insensitively — storing the canonical form keeps
            // the lists (and their persisted JSON) unambiguous.
            let pubkey = pubkey.to_ascii_lowercase();
            {
                let mut access = relay.access.write().await;
                if !access
                    .blocked_pubkeys
                    .iter()
                    .any(|(p, _)| p.eq_ignore_ascii_case(&pubkey))
                {
                    access
                        .blocked_pubkeys
                        .push((pubkey.to_string(), reason.to_string()));
                }
            }
            relay.persist_access().await;
            audit!(&relay, &identity, "banpubkey", params);
            rpc_ok(json!(true))
        }
        "unbanpubkey" => {
            let Some(pubkey) = params.first().and_then(Value::as_str) else {
                return rpc_err("invalid params");
            };
            {
                let mut access = relay.access.write().await;
                access
                    .blocked_pubkeys
                    .retain(|(p, _)| !p.eq_ignore_ascii_case(pubkey));
            }
            relay.persist_access().await;
            audit!(&relay, &identity, "unbanpubkey", params);
            rpc_ok(json!(true))
        }
        "listbannedpubkeys" => {
            let access = relay.access.read().await;
            let list: Vec<Value> = access
                .blocked_pubkeys
                .iter()
                .map(|(pubkey, reason)| json!({ "pubkey": pubkey, "reason": reason }))
                .collect();
            rpc_ok(json!(list))
        }
        "allowpubkey" => {
            let (Some(pubkey), reason) = (
                params.first().and_then(Value::as_str),
                params.get(1).and_then(Value::as_str).unwrap_or(""),
            ) else {
                return rpc_err("invalid params");
            };
            if !is_pubkey(pubkey) {
                return rpc_err("invalid pubkey");
            }
            // Same lowercase normalization as `banpubkey` above.
            let pubkey = pubkey.to_ascii_lowercase();
            {
                let mut access = relay.access.write().await;
                // NIP-86: allowing a pubkey also un-bans it (matching the
                // legacy endpoint), so `banpubkey` can be reverted.
                access
                    .blocked_pubkeys
                    .retain(|(p, _)| !p.eq_ignore_ascii_case(&pubkey));
                if !access
                    .allowed_pubkeys
                    .iter()
                    .any(|(p, _)| p.eq_ignore_ascii_case(&pubkey))
                {
                    access
                        .allowed_pubkeys
                        .push((pubkey.to_string(), reason.to_string()));
                }
            }
            relay.persist_access().await;
            audit!(&relay, &identity, "allowpubkey", params);
            rpc_ok(json!(true))
        }
        "unallowpubkey" => {
            let Some(pubkey) = params.first().and_then(Value::as_str) else {
                return rpc_err("invalid params");
            };
            {
                let mut access = relay.access.write().await;
                access
                    .allowed_pubkeys
                    .retain(|(p, _)| !p.eq_ignore_ascii_case(pubkey));
            }
            relay.persist_access().await;
            audit!(&relay, &identity, "unallowpubkey", params);
            rpc_ok(json!(true))
        }
        "listallowedpubkeys" => {
            let access = relay.access.read().await;
            let list: Vec<Value> = access
                .allowed_pubkeys
                .iter()
                .map(|(pubkey, reason)| json!({ "pubkey": pubkey, "reason": reason }))
                .collect();
            rpc_ok(json!(list))
        }
        "allowkind" => {
            let Some(kind) = params.first().and_then(Value::as_u64) else {
                return rpc_err("invalid params");
            };
            {
                let mut access = relay.access.write().await;
                // NIP-86: allowing a kind also un-blocks it (matching the
                // legacy endpoint), so `disallowkind` can be reverted.
                access.blocked_kinds.retain(|k| *k != kind);
                if !access.allowed_kinds.contains(&kind) {
                    access.allowed_kinds.push(kind);
                }
            }
            relay.persist_access().await;
            audit!(&relay, &identity, "allowkind", params);
            rpc_ok(json!(true))
        }
        "disallowkind" => {
            let Some(kind) = params.first().and_then(Value::as_u64) else {
                return rpc_err("invalid params");
            };
            {
                let mut access = relay.access.write().await;
                if !access.blocked_kinds.contains(&kind) {
                    access.blocked_kinds.push(kind);
                }
            }
            relay.persist_access().await;
            audit!(&relay, &identity, "disallowkind", params);
            rpc_ok(json!(true))
        }
        "listallowedkinds" => {
            let access = relay.access.read().await;
            rpc_ok(json!(access.allowed_kinds))
        }
        "changerelayname" | "changerelaydescription" | "changerelayicon" => {
            let Some(value) = params.first().and_then(Value::as_str) else {
                return rpc_err("invalid params");
            };
            // Bound the value (it is served to every client in the NIP-11
            // document) and reject control characters, which some clients
            // may not render or may misinterpret.
            let max_len = match method {
                "changerelayname" => 200,
                "changerelaydescription" => 10_000,
                _ => 4_000, // icon URL
            };
            if value.len() > max_len
                || value
                    .chars()
                    .any(|c| c.is_control() && c != '\n' && c != '\t')
            {
                return rpc_err("invalid params: value too long or contains control characters");
            }
            let mut cfg = relay.config.write().await;
            let (field, _) = match method {
                "changerelayname" => ("name", cfg.relay.name = value.to_string()),
                "changerelaydescription" => {
                    ("description", cfg.relay.description = value.to_string())
                }
                _ => ("icon", cfg.relay.icon = value.to_string()),
            };
            // Persist the change to the config file so it survives a SIGHUP
            // reload and a restart (without persistence the reload handler
            // would silently revert it).
            relay.persist_relay_field(field, value).await;
            audit!(&relay, &identity, method, params);
            rpc_ok(json!(true))
        }
        // NIP-43 role management.
        "createrole" => {
            let Some(id) = params.first().and_then(Value::as_str) else {
                return rpc_err("invalid params");
            };
            if let Err(msg) = check_role_id(id) {
                return rpc_err(&msg);
            }
            let label = params.get(1).and_then(Value::as_str).unwrap_or("");
            let description = params.get(2).and_then(Value::as_str).unwrap_or("");
            let color = params.get(3).and_then(Value::as_str).unwrap_or("");
            let order = params.get(4).and_then(Value::as_i64);
            if let Err(msg) = check_role_fields(label, description, color) {
                return rpc_err(&msg);
            }
            if relay
                .create_role(id, label, description, color, order)
                .await
            {
                audit!(&relay, &identity, "createrole", params);
                rpc_ok(json!(true))
            } else {
                rpc_err(
                    "restricted: NIP-43 is disabled, the relay key is missing or the event could not be stored",
                )
            }
        }
        "editrole" => {
            let Some(id) = params.first().and_then(Value::as_str) else {
                return rpc_err("invalid params");
            };
            if let Err(msg) = check_role_id(id) {
                return rpc_err(&msg);
            }
            let label = params.get(1).and_then(Value::as_str).unwrap_or("");
            let description = params.get(2).and_then(Value::as_str).unwrap_or("");
            let color = params.get(3).and_then(Value::as_str).unwrap_or("");
            let order = params.get(4).and_then(Value::as_i64);
            if let Err(msg) = check_role_fields(label, description, color) {
                return rpc_err(&msg);
            }
            if relay.edit_role(id, label, description, color, order).await {
                audit!(&relay, &identity, "editrole", params);
                rpc_ok(json!(true))
            } else {
                rpc_err(
                    "restricted: role not found, NIP-43 is disabled or the relay key is not configured",
                )
            }
        }
        "deleterole" => {
            let Some(id) = params.first().and_then(Value::as_str) else {
                return rpc_err("invalid params");
            };
            if let Err(msg) = check_role_id(id) {
                return rpc_err(&msg);
            }
            if relay.delete_role(id).await {
                audit!(&relay, &identity, "deleterole", params);
                rpc_ok(json!(true))
            } else {
                rpc_err(
                    "restricted: NIP-43 is disabled, the relay key is missing or the event could not be stored",
                )
            }
        }
        "assignrole" => {
            let (Some(pubkey), Some(role)) = (
                params.first().and_then(Value::as_str),
                params.get(1).and_then(Value::as_str),
            ) else {
                return rpc_err("invalid params");
            };
            if !is_pubkey(pubkey) {
                return rpc_err("invalid pubkey");
            }
            if let Err(msg) = check_role_id(role) {
                return rpc_err(&msg);
            }
            if relay.assign_role(pubkey, role).await {
                audit!(&relay, &identity, "assignrole", params);
                rpc_ok(json!(true))
            } else {
                rpc_err(
                    "restricted: NIP-43 is disabled, the relay key is missing, the role does not exist or the event could not be stored",
                )
            }
        }
        "unassignrole" => {
            let (Some(pubkey), Some(role)) = (
                params.first().and_then(Value::as_str),
                params.get(1).and_then(Value::as_str),
            ) else {
                return rpc_err("invalid params");
            };
            if !is_pubkey(pubkey) {
                return rpc_err("invalid pubkey");
            }
            if let Err(msg) = check_role_id(role) {
                return rpc_err(&msg);
            }
            if relay.unassign_role(pubkey, role).await {
                audit!(&relay, &identity, "unassignrole", params);
                rpc_ok(json!(true))
            } else {
                rpc_err(
                    "restricted: NIP-43 is disabled, the relay key is missing or the assignment does not exist",
                )
            }
        }
        "blockip" => {
            let (Some(ip), reason) = (
                params.first().and_then(Value::as_str),
                params.get(1).and_then(Value::as_str).unwrap_or(""),
            ) else {
                return rpc_err("invalid params");
            };
            if ip.parse::<std::net::IpAddr>().is_err() {
                return rpc_err("invalid ip address");
            }
            {
                let mut access = relay.access.write().await;
                if !access.blocked_ips.iter().any(|(i, _)| i == ip) {
                    access
                        .blocked_ips
                        .push((ip.to_string(), reason.to_string()));
                }
            }
            relay.persist_access().await;
            // Drop existing connections from this IP, not just new ones.
            relay.note_ip_blocks_changed();
            audit!(&relay, &identity, "blockip", params);
            rpc_ok(json!(true))
        }
        "unblockip" => {
            let Some(ip) = params.first().and_then(Value::as_str) else {
                return rpc_err("invalid params");
            };
            {
                let mut access = relay.access.write().await;
                access.blocked_ips.retain(|(i, _)| i != ip);
            }
            relay.persist_access().await;
            // Re-connect checks: unblocking also bumps the version so
            // connections that were blocked mid-flight re-verify (a version
            // bump with an empty list is harmless).
            relay.note_ip_blocks_changed();
            audit!(&relay, &identity, "unblockip", params);
            rpc_ok(json!(true))
        }
        "listblockedips" => {
            let access = relay.access.read().await;
            let list: Vec<Value> = access
                .blocked_ips
                .iter()
                .map(|(ip, reason)| json!({ "ip": ip, "reason": reason }))
                .collect();
            rpc_ok(json!(list))
        }
        "banevent" => {
            let (Some(id), reason) = (
                params.first().and_then(Value::as_str),
                params.get(1).and_then(Value::as_str).unwrap_or(""),
            ) else {
                return rpc_err("invalid params");
            };
            let Ok(id) = hex::decode(id) else {
                return rpc_err("invalid event id");
            };
            let Ok(id): Result<[u8; 32], _> = id.try_into() else {
                return rpc_err("invalid event id");
            };
            relay.db.ban_event(id, reason).await;
            audit!(&relay, &identity, "banevent", params);
            rpc_ok(json!(true))
        }
        "allowevent" => {
            let Some(id) = params.first().and_then(Value::as_str) else {
                return rpc_err("invalid params");
            };
            let Ok(id) = hex::decode(id) else {
                return rpc_err("invalid event id");
            };
            let Ok(id): Result<[u8; 32], _> = id.try_into() else {
                return rpc_err("invalid event id");
            };
            relay.db.unban_event(id).await;
            audit!(&relay, &identity, "allowevent", params);
            rpc_ok(json!(true))
        }
        "listbannedevents" => {
            let list: Vec<Value> = relay
                .db
                .list_banned_events()
                .await
                .into_iter()
                .map(|(id, reason)| json!({ "id": id, "reason": reason }))
                .collect();
            rpc_ok(json!(list))
        }
        "listeventsneedingmoderation" => {
            // This relay has no moderation queue: no events await review.
            rpc_ok(json!([]))
        }
        _ => rpc_err("unsupported method"),
    }
}

/// Summarizes the mutation's params for the audit trail, bounded so a
/// long reason cannot bloat the log.
fn audit_params(params: &[Value]) -> String {
    let mut text = serde_json::to_string(params).unwrap_or_default();
    if text.len() > 200 {
        // Truncate on a char boundary: `String::truncate` panics when the
        // index lands inside a multi-byte UTF-8 sequence (e.g. a Japanese
        // relay name or an emoji in the reason).
        let mut end = 200;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push('…');
    }
    text
}

fn is_pubkey(value: &str) -> bool {
    hex::decode(value).map(|b| b.len() == 32).unwrap_or(false)
}

/// Constant-time comparison for the management token: the token must not be
/// recoverable through response-timing differences of the comparison. The
/// length check short-circuits (the length is not secret), and equal-length
/// inputs are compared with no early exit.
fn ct_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// NIP-86 authentication: either the bearer `management_token` or a NIP-98
/// event by `admin_pubkey` whose `payload` tag is present and whose `u` tag
/// matches this relay's URL, including the request path and query
/// (NIP-98: "the `u` tag MUST be exactly the same as the absolute request
/// URL"; the scheme is normalized so TLS-terminating proxies keep working).
/// Returns the identity for the audit trail: the NIP-98 pubkey or
/// `"management-token"`.
async fn rpc_authenticated(
    relay: &Relay,
    headers: &HeaderMap,
    uri: &axum::http::Uri,
    body: &str,
) -> Option<String> {
    let cfg = relay.config.read().await;
    if !cfg.rpc.management_token.is_empty()
        && let Some(token) = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
        && ct_eq(token, &cfg.rpc.management_token)
    {
        return Some("management-token".into());
    }
    if !cfg.rpc.admin_pubkey.is_empty()
        && let Some(auth) = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Nostr "))
        && let Some(pubkey) = nip98::verify(
            auth,
            Some(&cfg.rpc.admin_pubkey),
            relay.secp(),
            true,
            Some(&nip98::payload_sha256_hex(body.as_bytes())),
            "POST",
            |url| nip98::matches_request_url(url, &cfg.relay_identity(), uri.path(), uri.query()),
        )
        .await
    {
        return Some(pubkey);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::relay::Relay;

    /// A relay with `rpc.management_token` configured (the bearer
    /// token path, so the tests need no NIP-98 signing).
    async fn build_admin_relay() -> std::sync::Arc<Relay> {
        build_admin_relay_with_key(None).await
    }

    /// Like [`Self::build_admin_relay`], with NIP-43 and a relay key when
    /// `key` is given.
    async fn build_admin_relay_with_key(key: Option<&str>) -> std::sync::Arc<Relay> {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join("nostrfy-nip86-test")
            .join(format!("{:x}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        let mut cfg = Config::default();
        cfg.database.path = path;
        cfg.database.map_size = 16 * 1024 * 1024;
        cfg.database.max_map_size = 256 * 1024 * 1024;
        cfg.rpc.management_token = "test-token".into();
        if let Some(key) = key {
            cfg.relay.enabled_nips = vec![43];
            cfg.relay.private_key = key.to_string();
        }
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
        let relay = Relay::new(
            config,
            db,
            stats,
            key.unwrap_or(""),
            crate::relay::LiveBusConfig {
                buffer: 1024,
                batch_interval_ms: 10,
                batch_size: 64,
            },
        )
        .await;
        std::sync::Arc::new(relay)
    }

    fn bearer_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer test-token".parse().unwrap());
        headers.insert(header::CONTENT_TYPE, RPC_CONTENT_TYPE.parse().unwrap());
        headers
    }

    async fn rpc_call(relay: &std::sync::Arc<Relay>, method: &str, params: Vec<Value>) -> Response {
        rpc_handler(
            State(relay.clone()),
            axum::extract::ConnectInfo("127.0.0.1:1234".parse().unwrap()),
            axum::http::Uri::from_static("/"),
            bearer_headers(),
            serde_json::to_string(&json!({ "method": method, "params": params })).unwrap(),
        )
        .await
    }

    #[tokio::test]
    async fn rpc_error_paths_and_remaining_methods() {
        let relay = build_admin_relay().await;

        // The content type and the auth gate.
        let resp = rpc_handler(
            State(relay.clone()),
            axum::extract::ConnectInfo("127.0.0.1:1234".parse().unwrap()),
            axum::http::Uri::from_static("/"),
            HeaderMap::new(),
            "{}".into(),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "missing content type"
        );
        let resp = rpc_handler(
            State(relay.clone()),
            axum::extract::ConnectInfo("127.0.0.1:1234".parse().unwrap()),
            axum::http::Uri::from_static("/"),
            bearer_headers(),
            "not-json".into(),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "invalid JSON is a JSON-RPC error"
        );
        let resp = rpc_call(&relay, "", vec![]).await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "missing method is a JSON-RPC error"
        );
        let resp = rpc_call(&relay, "nosuchmethod", vec![]).await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "unsupported method is an rpc error"
        );

        // supportedmethods excludes itself.
        let resp = rpc_call(&relay, "supportedmethods", vec![]).await;
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        let list = body["result"].as_array().unwrap();
        assert!(!list.iter().any(|m| m == "supportedmethods"));

        // Access list mutations and their error paths.
        let resp = rpc_call(&relay, "banpubkey", vec![]).await;
        assert!(rpc_err_of(resp).await.contains("params"));
        let resp = rpc_call(&relay, "banpubkey", vec![json!("zz")]).await;
        assert!(rpc_err_of(resp).await.contains("pubkey"));
        let resp = rpc_call(&relay, "banpubkey", vec![json!("aa".repeat(32))]).await;
        assert!(rpc_ok_of(resp).await);
        let resp = rpc_call(&relay, "banpubkey", vec![json!("aa".repeat(32))]).await;
        assert!(rpc_ok_of(resp).await, "re-banning is idempotent");
        assert_eq!(
            rpc_call(&relay, "unbanpubkey", vec![]).await.status(),
            StatusCode::OK
        );
        let resp = rpc_call(&relay, "unbanpubkey", vec![json!("aa".repeat(32))]).await;
        assert!(rpc_ok_of(resp).await);
        let resp = rpc_call(&relay, "allowpubkey", vec![]).await;
        assert!(rpc_err_of(resp).await.contains("params"));
        let resp = rpc_call(&relay, "allowpubkey", vec![json!("zz")]).await;
        assert!(rpc_err_of(resp).await.contains("pubkey"));
        let resp = rpc_call(
            &relay,
            "allowpubkey",
            vec![json!("aa".repeat(32)), json!("r")],
        )
        .await;
        assert!(rpc_ok_of(resp).await);
        // Allowing also un-bans (the duplicate is a no-op).
        let _ = rpc_call(&relay, "banpubkey", vec![json!("aa".repeat(32))]).await;
        let resp = rpc_call(&relay, "allowpubkey", vec![json!("aa".repeat(32))]).await;
        assert!(rpc_ok_of(resp).await);
        let resp = rpc_call(&relay, "unallowpubkey", vec![]).await;
        assert!(rpc_err_of(resp).await.contains("params"));
        let resp = rpc_call(&relay, "unallowpubkey", vec![json!("aa".repeat(32))]).await;
        assert!(rpc_ok_of(resp).await);
        let resp = rpc_call(&relay, "listallowedpubkeys", vec![]).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Kind allow/disallow.
        let resp = rpc_call(&relay, "allowkind", vec![]).await;
        assert!(rpc_err_of(resp).await.contains("params"));
        let resp = rpc_call(&relay, "allowkind", vec![json!(5)]).await;
        assert!(rpc_ok_of(resp).await);
        let resp = rpc_call(&relay, "allowkind", vec![json!(5)]).await;
        assert!(rpc_ok_of(resp).await, "re-allowing is idempotent");
        let resp = rpc_call(&relay, "disallowkind", vec![]).await;
        assert!(rpc_err_of(resp).await.contains("params"));
        let resp = rpc_call(&relay, "disallowkind", vec![json!(5)]).await;
        assert!(rpc_ok_of(resp).await);
        let resp = rpc_call(&relay, "listallowedkinds", vec![]).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Relay name/description/icon changes.
        let resp = rpc_call(&relay, "changerelayname", vec![]).await;
        assert!(rpc_err_of(resp).await.contains("params"));
        let long = "x".repeat(201);
        let resp = rpc_call(&relay, "changerelayname", vec![json!(long)]).await;
        assert!(rpc_err_of(resp).await.contains("too long"));
        let resp = rpc_call(&relay, "changerelayname", vec![json!("\u{0}")]).await;
        assert!(rpc_err_of(resp).await.contains("control"));
        let resp = rpc_call(&relay, "changerelayname", vec![json!("newname")]).await;
        assert!(rpc_ok_of(resp).await);
        assert_eq!(relay.config.read().await.relay.name, "newname");
        let resp = rpc_call(&relay, "changerelaydescription", vec![json!("new desc")]).await;
        assert!(rpc_ok_of(resp).await);
        let resp = rpc_call(&relay, "changerelayicon", vec![json!("https://x/i.png")]).await;
        assert!(rpc_ok_of(resp).await);

        // Role methods through the RPC (the relay has no key: they fail
        // with the restricted error, which covers the else branches).
        let resp = rpc_call(&relay, "createrole", vec![]).await;
        assert!(rpc_err_of(resp).await.contains("params"));
        let resp = rpc_call(&relay, "createrole", vec![json!("x".repeat(65))]).await;
        assert!(rpc_err_of(resp).await.contains("maximum"));
        let resp = rpc_call(&relay, "createrole", vec![json!(" admin")]).await;
        assert!(rpc_err_of(resp).await.contains("whitespace"));
        let resp = rpc_call(&relay, "createrole", vec![json!("")]).await;
        assert!(rpc_err_of(resp).await.contains("empty"));
        let resp = rpc_call(&relay, "createrole", vec![json!("   ")]).await;
        assert!(rpc_err_of(resp).await.contains("empty"));
        let resp = rpc_call(&relay, "deleterole", vec![json!("")]).await;
        assert!(rpc_err_of(resp).await.contains("empty"));
        let resp = rpc_call(
            &relay,
            "createrole",
            vec![json!("r"), json!("l".repeat(201))],
        )
        .await;
        assert!(rpc_err_of(resp).await.contains("maximum"));
        let resp = rpc_call(
            &relay,
            "createrole",
            vec![json!("r"), json!(""), json!("d".repeat(1001))],
        )
        .await;
        assert!(rpc_err_of(resp).await.contains("maximum"));
        let resp = rpc_call(
            &relay,
            "createrole",
            vec![json!("r"), json!(""), json!(""), json!("c".repeat(65))],
        )
        .await;
        assert!(rpc_err_of(resp).await.contains("maximum"));
        let resp = rpc_call(&relay, "createrole", vec![json!("r1")]).await;
        assert!(rpc_err_of(resp).await.contains("restricted"));
        let resp = rpc_call(&relay, "editrole", vec![]).await;
        assert!(rpc_err_of(resp).await.contains("params"));
        let resp = rpc_call(&relay, "deleterole", vec![]).await;
        assert!(rpc_err_of(resp).await.contains("params"));
        let resp = rpc_call(&relay, "deleterole", vec![json!("r1")]).await;
        assert!(rpc_err_of(resp).await.contains("restricted"));
        let resp = rpc_call(&relay, "assignrole", vec![]).await;
        assert!(rpc_err_of(resp).await.contains("params"));
        let resp = rpc_call(&relay, "assignrole", vec![json!("zz"), json!("r1")]).await;
        assert!(rpc_err_of(resp).await.contains("pubkey"));
        let resp = rpc_call(
            &relay,
            "assignrole",
            vec![json!("aa".repeat(32)), json!("")],
        )
        .await;
        assert!(rpc_err_of(resp).await.contains("empty"));
        let resp = rpc_call(
            &relay,
            "assignrole",
            vec![json!("aa".repeat(32)), json!("r1")],
        )
        .await;
        assert!(rpc_err_of(resp).await.contains("restricted"));
        let resp = rpc_call(&relay, "unassignrole", vec![]).await;
        assert!(rpc_err_of(resp).await.contains("params"));
        let resp = rpc_call(&relay, "unassignrole", vec![json!("zz"), json!("r1")]).await;
        assert!(rpc_err_of(resp).await.contains("pubkey"));
        let resp = rpc_call(
            &relay,
            "unassignrole",
            vec![json!("aa".repeat(32)), json!("r1")],
        )
        .await;
        assert!(rpc_err_of(resp).await.contains("restricted"));

        // blockip / unblockip / listblockedips.
        let resp = rpc_call(&relay, "blockip", vec![]).await;
        assert!(rpc_err_of(resp).await.contains("params"));
        let resp = rpc_call(&relay, "blockip", vec![json!("not-an-ip")]).await;
        assert!(rpc_err_of(resp).await.contains("ip address"));
        let resp = rpc_call(&relay, "unblockip", vec![]).await;
        assert!(rpc_err_of(resp).await.contains("params"));
        let resp = rpc_call(&relay, "unblockip", vec![json!("127.0.0.1")]).await;
        assert!(rpc_ok_of(resp).await);
        let resp = rpc_call(&relay, "listblockedips", vec![]).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // banevent / allowevent / listbannedevents.
        let id = "ab".repeat(32);
        let resp = rpc_call(&relay, "banevent", vec![]).await;
        assert!(rpc_err_of(resp).await.contains("params"));
        let resp = rpc_call(&relay, "banevent", vec![json!("zz")]).await;
        assert!(rpc_err_of(resp).await.contains("event id"));
        let resp = rpc_call(&relay, "banevent", vec![json!("ab".repeat(31))]).await;
        assert!(rpc_err_of(resp).await.contains("event id"));
        let resp = rpc_call(&relay, "banevent", vec![json!(id.clone()), json!("bad")]).await;
        assert!(rpc_ok_of(resp).await);
        let resp = rpc_call(&relay, "allowevent", vec![]).await;
        assert!(rpc_err_of(resp).await.contains("params"));
        let resp = rpc_call(&relay, "allowevent", vec![json!("zz")]).await;
        assert!(rpc_err_of(resp).await.contains("event id"));
        let resp = rpc_call(&relay, "allowevent", vec![json!(id.clone())]).await;
        assert!(rpc_ok_of(resp).await);
        let resp = rpc_call(&relay, "listbannedevents", vec![]).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = rpc_call(&relay, "listeventsneedingmoderation", vec![]).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // A blocked peer gets 403 before anything else (blocked IPs apply
        // to the management endpoint too).
        let _ = rpc_call(&relay, "blockip", vec![json!("127.0.0.1"), json!("x")]).await;
        let resp = rpc_call(&relay, "listallowedkinds", vec![]).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // The audit params are bounded (a long reason is truncated).
        let long = "x".repeat(500);
        let _ = rpc_call(
            &relay,
            "banpubkey",
            vec![json!("cc".repeat(32)), json!(long)],
        )
        .await;
        let recent = relay.audit.recent();
        assert!(
            recent.iter().any(|l| l.len() < 400),
            "the audit trail must truncate long params: {:?}",
            recent
        );
        relay.db.shutdown();
    }

    async fn rpc_err_of(resp: Response) -> String {
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        serde_json::from_slice::<Value>(&body).unwrap()["error"]
            .as_str()
            .unwrap()
            .to_string()
    }

    async fn rpc_ok_of(resp: Response) -> bool {
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        serde_json::from_slice::<Value>(&body).unwrap()["result"] == json!(true)
    }

    #[tokio::test]
    async fn mutations_are_audited() {
        let relay = build_admin_relay().await;
        relay.audit.clear();
        let resp = rpc_call(
            &relay,
            "banpubkey",
            vec![json!("aa".repeat(32)), json!("spam")],
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let recent = relay.audit.recent();
        assert_eq!(recent.len(), 1, "the mutation must be audited");
        assert!(
            recent[0].contains("banpubkey") && recent[0].contains("management-token"),
            "the audit entry must name the method and the identity: {}",
            recent[0]
        );
        // Read-only methods are not audited.
        let _ = rpc_call(&relay, "listbannedpubkeys", vec![]).await;
        assert_eq!(relay.audit.recent().len(), 1);
        // Invalid params are not audited (nothing was changed).
        let _ = rpc_call(&relay, "banpubkey", vec![json!("not-a-pubkey")]).await;
        assert_eq!(relay.audit.recent().len(), 1);
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn role_rpc_reports_storage_failure() {
        // A role mutation whose relay-generated event cannot be stored
        // (the database is gone) must report failure, not success.
        let relay = build_admin_relay_with_key(Some(&"ab".repeat(32))).await;
        relay.db.shutdown();
        let resp = rpc_call(
            &relay,
            "createrole",
            vec![json!("admin"), json!("Administrator")],
        )
        .await;
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        assert!(
            body.windows(5).any(|w| w == b"error"),
            "a failed role save must be reported: {body:?}"
        );
        // The same applies to delete: the tombstone could not be stored.
        let resp = rpc_call(&relay, "deleterole", vec![json!("ghost")]).await;
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        assert!(body.windows(5).any(|w| w == b"error"));
    }

    #[tokio::test]
    async fn role_rpc_succeeds_when_events_are_stored() {
        let relay = build_admin_relay_with_key(Some(&"cd".repeat(32))).await;
        relay.audit.clear();
        let resp = rpc_call(&relay, "createrole", vec![json!("mod"), json!("Moderator")]).await;
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        assert!(
            body.windows(4).any(|w| w == b"true"),
            "a stored role must report success: {body:?}"
        );
        assert!(
            relay.roles.read().await.roles.contains_key("mod"),
            "the role must be in the in-memory store"
        );
        let recent = relay.audit.recent();
        assert!(
            recent.iter().any(|e| e.contains("createrole")),
            "the role mutation must be audited: {recent:?}"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn unauthorized_mutations_are_not_audited() {
        let relay = build_admin_relay().await;
        relay.audit.clear();
        let mut headers = bearer_headers();
        headers.insert(header::AUTHORIZATION, "Bearer wrong-token".parse().unwrap());
        let resp = rpc_handler(
            State(relay.clone()),
            axum::extract::ConnectInfo("127.0.0.1:1234".parse().unwrap()),
            axum::http::Uri::from_static("/"),
            headers,
            serde_json::to_string(&json!({ "method": "banpubkey", "params": [] })).unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(relay.audit.recent().is_empty());
        relay.db.shutdown();
    }

    #[test]
    fn ct_eq_rejects_unequal_lengths_and_nul_padding() {
        assert!(ct_eq("secret-token", "secret-token"));
        assert!(!ct_eq("secret-token", "secret-token2"));
        // The old comparator masked length differences that are multiples of
        // 256 and treated NUL bytes as "missing": these must never match.
        let mut padded = String::from("secret-token");
        padded.push_str(&"\0".repeat(256));
        assert!(!ct_eq("secret-token", &padded));
        assert!(!ct_eq("a", "a\0"));
        assert!(!ct_eq("", "x"));
        assert!(!ct_eq("x", ""));
        assert!(ct_eq("", ""));
    }
}
