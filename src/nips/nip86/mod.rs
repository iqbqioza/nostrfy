//! NIP-86: Relay Management API.
//!
//! The current NIP-86 revision defines a JSON-RPC style protocol served on
//! the same URI as the relay's websocket, with `Content-Type:
//! application/nostr+json+rpc` and NIP-98 authentication.
//!
//! Kind access (`allowkind` / `disallowkind` / `listallowedkinds`) operates
//! on the access-control state, which has two kind lists:
//!
//! - `blocked_kinds` is a denylist and is checked first: a kind on it is
//!   never accepted;
//! - `allowed_kinds` is the config allowlist. While it is empty it
//!   restricts nothing; while it is non-empty it is exhaustive, so a kind
//!   missing from it is rejected.
//!
//! `disallowkind(k)` adds `k` to the denylist and removes it from the
//! allowlist. `allowkind(k)` always un-blocks `k`; it extends
//! `allowed_kinds` only when that allowlist is already active. Populating
//! an empty allowlist would turn one `allowkind` into a global allowlist
//! and make the relay reject every other kind (bricking publishing), so on
//! a relay with no config allowlist the call leaves the list empty and
//! `listallowedkinds` keeps reporting `[]` — "no allowlist restriction":
//! every kind is accepted except the blocked ones, and the re-allowed kind
//! is not individually listed. With an active allowlist the list reports
//! exactly the config allowlist plus the kinds added by `allowkind`, which
//! is what a management client needs to verify the call's effect.

use std::sync::Arc;

use anyhow::anyhow;
use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use crate::nips::{nip43, nip98};
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
    "listdisallowedkinds",
    "changerelayname",
    "changerelaydescription",
    "changerelayicon",
    "createrole",
    "editrole",
    "deleterole",
    "assignrole",
    "unassignrole",
    "assignmethod",
    "unassignmethod",
    "listmethodassignees",
    "blockip",
    "unblockip",
    "listblockedips",
    "banevent",
    "allowevent",
    "unallowevent",
    "unbanevent",
    "listbannedevents",
    "listallowedevents",
    "listeventsneedingmoderation",
    "listclaims",
    "createclaim",
    "deleteclaim",
];

/// Methods a non-admin pubkey may be granted through NIP-86 PR #2439
/// `assignmethod`: the moderation verbs plus the read-only lists.
/// `supportedmethods` is implicitly available to every authenticated
/// caller (it shows their own subset), so it is not a grant target.
/// Everything else — permission management itself, role and
/// invite-claim management, and the relay identity — stays admin-only,
/// so a grantee can never escalate.
const GRANTABLE_METHODS: &[&str] = &[
    "banpubkey",
    "unbanpubkey",
    "listbannedpubkeys",
    "allowpubkey",
    "unallowpubkey",
    "listallowedpubkeys",
    "allowkind",
    "disallowkind",
    "listallowedkinds",
    "blockip",
    "unblockip",
    "listblockedips",
    "banevent",
    "allowevent",
    "unallowevent",
    "unbanevent",
    "listbannedevents",
    "listallowedevents",
    "listeventsneedingmoderation",
    "listdisallowedkinds",
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

fn check_role_fields(label: &str, description: &str, color: &str) -> anyhow::Result<()> {
    if label.chars().count() > MAX_ROLE_LABEL_LEN {
        return Err(anyhow!(
            "role label exceeds the maximum of {MAX_ROLE_LABEL_LEN} characters"
        ));
    }
    if description.chars().count() > MAX_ROLE_DESC_LEN {
        return Err(anyhow!(
            "role description exceeds the maximum of {MAX_ROLE_DESC_LEN} characters"
        ));
    }
    if color.chars().count() > MAX_ROLE_COLOR_LEN {
        return Err(anyhow!(
            "role color exceeds the maximum of {MAX_ROLE_COLOR_LEN} characters"
        ));
    }
    // NIP-43: a non-empty `color` is a hue from 0 to 360.
    nip43::check_role_color(color)?;
    Ok(())
}

/// Validates a NIP-43 role id: non-empty (after trimming), within the byte
/// length bound, and free of control characters (it lands in a stored relay
/// event's `d` tag and the in-memory role map). Character count is used for
/// the length bound like the other role fields so multibyte ids cannot
/// bypass the intent.
fn check_role_id(id: &str) -> anyhow::Result<()> {
    if id.trim().is_empty() {
        return Err(anyhow!("role id must not be empty"));
    }
    // Compare against the trimmed form so `" admin"` and `"admin"` cannot
    // become distinct map keys / `d` tags for the same logical role.
    if id != id.trim() {
        return Err(anyhow!(
            "role id must not have leading or trailing whitespace"
        ));
    }
    // Byte length: the id lands in a stored event's `d` tag and the LMDB
    // index, so multibyte ids must not bypass the bound via char count.
    if id.len() > MAX_ROLE_ID_LEN {
        return Err(anyhow!(
            "role id exceeds the maximum of {MAX_ROLE_ID_LEN} bytes"
        ));
    }
    if id.chars().any(|c| c.is_control()) {
        return Err(anyhow!("role id must not contain control characters"));
    }
    Ok(())
}

/// Validates a NIP-43 invite code for `createclaim` / `deleteclaim`:
/// non-empty, within the store bound, and free of control characters
/// (codes persist in the roles snapshot and are echoed in `listclaims`).
fn check_claim(claim: &str) -> anyhow::Result<()> {
    // Mirror `check_role_id` hygiene: a whitespace-only code would be a
    // useless invite that can never be typed or matched deliberately.
    if claim.trim().is_empty() {
        return Err(anyhow!("claim must not be empty"));
    }
    if claim != claim.trim() {
        return Err(anyhow!(
            "claim must not have leading or trailing whitespace"
        ));
    }
    if claim.chars().count() > crate::nips::nip43::RoleStore::MAX_CLAIM_LEN {
        return Err(anyhow!(
            "claim exceeds the maximum of {} characters",
            crate::nips::nip43::RoleStore::MAX_CLAIM_LEN
        ));
    }
    if claim.chars().any(|c| c.is_control()) {
        return Err(anyhow!("claim must not contain control characters"));
    }
    Ok(())
}

/// Refuses a grantee at an admin-only method. The per-method gate above
/// already refused grantees (grants can never name these methods), so
/// this is defense in depth against a future `GRANTABLE_METHODS`
/// expansion mistake.
fn require_admin(identity: &Identity) -> Option<Response> {
    if identity.is_admin() {
        None
    } else {
        Some(
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "unauthorized" })),
            )
                .into_response(),
        )
    }
}

fn rpc_ok(result: Value) -> Response {
    (StatusCode::OK, Json(json!({ "result": result }))).into_response()
}

fn rpc_err(message: &str) -> Response {
    (StatusCode::OK, Json(json!({ "error": message }))).into_response()
}

/// Reads an optional string param: absent or null means "not given"
/// (empty default); any other non-string type is invalid — silently
/// dropping a mistyped value would store data the operator did not send.
fn opt_param_str<'a>(params: &'a [Value], index: usize, what: &str) -> Result<&'a str, String> {
    match params.get(index) {
        None | Some(Value::Null) => Ok(""),
        Some(Value::String(s)) => Ok(s),
        Some(_) => Err(format!("invalid params: {what} must be a string")),
    }
}

/// Reads an optional integer param: absent or null means "not given";
/// any other non-integer type (including a string holding digits) is
/// invalid.
fn opt_param_i64(params: &[Value], index: usize, what: &str) -> Result<Option<i64>, String> {
    match params.get(index) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n
            .as_i64()
            .ok_or_else(|| format!("invalid params: {what} must be an integer"))
            .map(Some),
        Some(_) => Err(format!("invalid params: {what} must be an integer")),
    }
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
    if relay.access.read().await.is_ip_blocked(peer.ip()) {
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

    // Non-admin identities are gated per method (NIP-86 PR #2439): only
    // `assignmethod`-granted methods run, plus `supportedmethods` (every
    // authenticated caller may discover their own subset). Admins bypass
    // every check — `admin_pubkey` (and the management token) stay the
    // root login.
    if !identity.is_admin()
        && method != "supportedmethods"
        && !relay
            .access
            .read()
            .await
            .grants_method(identity.name(), method)
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized" })),
        )
            .into_response();
    }

    match method {
        // NIP-86: the result lists "all the OTHER supported methods" —
        // customized to the caller's grants for grantees.
        "supportedmethods" => {
            let access = relay.access.read().await;
            let others: Vec<&str> = SUPPORTED_METHODS
                .iter()
                .copied()
                .filter(|m| *m != "supportedmethods")
                .filter(|m| identity.is_admin() || access.grants_method(identity.name(), m))
                .collect();
            rpc_ok(json!(others))
        }
        "banpubkey" => {
            let Some(pubkey) = params.first().and_then(Value::as_str) else {
                return rpc_err("invalid params");
            };
            let reason = match opt_param_str(params, 1, "reason") {
                Ok(reason) => reason,
                Err(e) => return rpc_err(&e),
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
                let op = crate::config::AccessOp::BanPubkey {
                    pubkey: pubkey.clone(),
                    reason: reason.to_string(),
                    insensitive: true,
                };
                let mut access = relay.access.write().await;
                crate::config::apply_access_op(&mut access, &op);
                relay.push_access_ops(vec![op]);
            }
            // The in-memory mutation is live even when the write-through
            // persistence fails, so the audit entry must still be recorded;
            // the RPC reports the persistence error below.
            let persisted = relay.persist_access().await;
            audit!(&relay, &identity, "banpubkey", params);
            if !persisted {
                return rpc_err("error: cannot persist the access control state");
            }
            rpc_ok(json!(true))
        }
        "unbanpubkey" => {
            let Some(pubkey) = params.first().and_then(Value::as_str) else {
                return rpc_err("invalid params");
            };
            // Same validation as `banpubkey`: an unban must name a pubkey
            // (any string used to return a success reply).
            if !is_pubkey(pubkey) {
                return rpc_err("invalid pubkey");
            }
            {
                let op = crate::config::AccessOp::UnbanPubkey {
                    pubkey: pubkey.to_string(),
                    insensitive: true,
                };
                let mut access = relay.access.write().await;
                crate::config::apply_access_op(&mut access, &op);
                relay.push_access_ops(vec![op]);
            }
            // Same contract as `banpubkey`: the failed persistence is still
            // an applied in-memory mutation, so it must be audited.
            let persisted = relay.persist_access().await;
            audit!(&relay, &identity, "unbanpubkey", params);
            if !persisted {
                return rpc_err("error: cannot persist the access control state");
            }
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
            let Some(pubkey) = params.first().and_then(Value::as_str) else {
                return rpc_err("invalid params");
            };
            let reason = match opt_param_str(params, 1, "reason") {
                Ok(reason) => reason,
                Err(e) => return rpc_err(&e),
            };
            if !is_pubkey(pubkey) {
                return rpc_err("invalid pubkey");
            }
            // Same lowercase normalization as `banpubkey` above.
            let pubkey = pubkey.to_ascii_lowercase();
            {
                // NIP-86: allowing a pubkey also un-bans it (matching the
                // legacy endpoint), so `banpubkey` can be reverted.
                let ops = vec![
                    crate::config::AccessOp::UnbanPubkey {
                        pubkey: pubkey.clone(),
                        insensitive: true,
                    },
                    crate::config::AccessOp::AllowPubkey {
                        pubkey: pubkey.clone(),
                        reason: reason.to_string(),
                        insensitive: true,
                    },
                ];
                let mut access = relay.access.write().await;
                for op in &ops {
                    crate::config::apply_access_op(&mut access, op);
                }
                relay.push_access_ops(ops);
            }
            // Same contract as `banpubkey`: audit the applied mutation even
            // when persisting it failed.
            let persisted = relay.persist_access().await;
            audit!(&relay, &identity, "allowpubkey", params);
            if !persisted {
                return rpc_err("error: cannot persist the access control state");
            }
            rpc_ok(json!(true))
        }
        "unallowpubkey" => {
            let Some(pubkey) = params.first().and_then(Value::as_str) else {
                return rpc_err("invalid params");
            };
            // Same validation as `allowpubkey`.
            if !is_pubkey(pubkey) {
                return rpc_err("invalid pubkey");
            }
            {
                let op = crate::config::AccessOp::UnallowPubkey {
                    pubkey: pubkey.to_string(),
                    insensitive: true,
                };
                let mut access = relay.access.write().await;
                crate::config::apply_access_op(&mut access, &op);
                relay.push_access_ops(vec![op]);
            }
            // Same contract as `banpubkey`: audit the applied mutation even
            // when persisting it failed.
            let persisted = relay.persist_access().await;
            audit!(&relay, &identity, "unallowpubkey", params);
            if !persisted {
                return rpc_err("error: cannot persist the access control state");
            }
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
                // NIP-86: allowing a kind also un-blocks it (matching the
                // legacy endpoint), so `disallowkind` can be reverted. The
                // conditional allow mirrors the call-site rule below: an
                // unconditional push would turn a single `allowkind` into a
                // global allowlist that blocks every other kind.
                let mut ops = vec![crate::config::AccessOp::UndenyKind { kind }];
                let mut access = relay.access.write().await;
                // `allowed_kinds` is the config allowlist, which
                // `allows_kind` treats as exhaustive when non-empty. An
                // unconditional push would turn a single `allowkind` into a
                // global allowlist that blocks every other kind (and would
                // make a later `disallowkind` report the kind as allowed).
                if !access.allowed_kinds.is_empty() && !access.allowed_kinds.contains(&kind) {
                    ops.push(crate::config::AccessOp::AllowKind { kind });
                }
                for op in &ops {
                    crate::config::apply_access_op(&mut access, op);
                }
                relay.push_access_ops(ops);
            }
            // Same contract as `banpubkey`: audit the applied mutation even
            // when persisting it failed.
            let persisted = relay.persist_access().await;
            audit!(&relay, &identity, "allowkind", params);
            if !persisted {
                return rpc_err("error: cannot persist the access control state");
            }
            rpc_ok(json!(true))
        }
        "disallowkind" => {
            let Some(kind) = params.first().and_then(Value::as_u64) else {
                return rpc_err("invalid params");
            };
            {
                // A blocked kind must never be listed as allowed: drop it
                // from the config allowlist (`listallowedkinds` reports that
                // list, and `disallowkind` must leave a consistent state).
                let ops = vec![
                    crate::config::AccessOp::DenyKind { kind },
                    crate::config::AccessOp::UnallowKind { kind },
                ];
                let mut access = relay.access.write().await;
                for op in &ops {
                    crate::config::apply_access_op(&mut access, op);
                }
                relay.push_access_ops(ops);
            }
            // Same contract as `banpubkey`: audit the applied mutation even
            // when persisting it failed.
            let persisted = relay.persist_access().await;
            audit!(&relay, &identity, "disallowkind", params);
            if !persisted {
                return rpc_err("error: cannot persist the access control state");
            }
            rpc_ok(json!(true))
        }
        "listallowedkinds" => {
            let access = relay.access.read().await;
            // Report the kinds the relay actually accepts from the config
            // allowlist. `allows_kind` checks `blocked_kinds` first, so a
            // kind present in both lists is filtered out here (the config
            // may list it in both; `disallowkind` keeps the lists disjoint).
            //
            // A kind explicitly re-allowed by `allowkind` on a relay whose
            // config allowlist is empty (the default) cannot be reported
            // individually: there is no field for it in `AccessControl`, and
            // an empty `allowed_kinds` already means "no allowlist
            // restriction" — every non-blocked kind is accepted — so `[]`
            // stays the faithful answer. Only when the config allowlist is
            // active does `allowkind` extend it (see the module docs), which
            // makes the call's effect visible in this list.
            let list: Vec<u64> = access
                .allowed_kinds
                .iter()
                .copied()
                .filter(|kind| !access.blocked_kinds.contains(kind))
                .collect();
            rpc_ok(json!(list))
        }
        "listdisallowedkinds" => {
            let list: Vec<u64> = relay.access.read().await.blocked_kinds.clone();
            rpc_ok(json!(list))
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
            // Only the description is free text: the name and the icon
            // URL are single-line values, so embedded newlines/tabs are
            // rejected there (they would land verbatim in the NIP-11
            // document served to every client).
            let newline_allowed = method == "changerelaydescription";
            if value.len() > max_len
                || value
                    .chars()
                    .any(|c| c.is_control() && !(newline_allowed && (c == '\n' || c == '\t')))
            {
                return rpc_err("invalid params: value too long or contains control characters");
            }
            let field = match method {
                "changerelayname" => "name",
                "changerelaydescription" => "description",
                _ => "icon",
            };
            {
                let mut cfg = relay.config.write().await;
                match method {
                    "changerelayname" => cfg.relay.name = value.to_string(),
                    "changerelaydescription" => cfg.relay.description = value.to_string(),
                    _ => cfg.relay.icon = value.to_string(),
                }
            }
            // Bump the config version like a SIGHUP reload does: the NIP-11
            // document caches its static part against this version, so
            // without the bump clients would see the old name/description/
            // icon until the next reload or restart.
            relay
                .config_version
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // Persist the change to the config file so it survives a SIGHUP
            // reload and a restart (without persistence the reload handler
            // would silently revert it). The lock is released first: the
            // (blocking) file write must not stall every config reader.
            // A failed persist must not report success (like the access
            // mutations below): the change would vanish on reload.
            if !relay.persist_relay_field(field, value).await {
                audit!(&relay, &identity, method, params);
                return rpc_err("error: cannot persist the relay field");
            }
            audit!(&relay, &identity, method, params);
            rpc_ok(json!(true))
        }
        // NIP-43 role management.
        "createrole" => {
            let Some(id) = params.first().and_then(Value::as_str) else {
                return rpc_err("invalid params");
            };
            if let Err(e) = check_role_id(id) {
                return rpc_err(&e.to_string());
            }
            let label = match opt_param_str(params, 1, "label") {
                Ok(label) => label,
                Err(e) => return rpc_err(&e),
            };
            let description = match opt_param_str(params, 2, "description") {
                Ok(description) => description,
                Err(e) => return rpc_err(&e),
            };
            let color = match opt_param_str(params, 3, "color") {
                Ok(color) => color,
                Err(e) => return rpc_err(&e),
            };
            let order = match opt_param_i64(params, 4, "order") {
                Ok(order) => order,
                Err(e) => return rpc_err(&e),
            };
            if let Err(e) = check_role_fields(label, description, color) {
                return rpc_err(&e.to_string());
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
            if let Err(e) = check_role_id(id) {
                return rpc_err(&e.to_string());
            }
            let label = match opt_param_str(params, 1, "label") {
                Ok(label) => label,
                Err(e) => return rpc_err(&e),
            };
            let description = match opt_param_str(params, 2, "description") {
                Ok(description) => description,
                Err(e) => return rpc_err(&e),
            };
            let color = match opt_param_str(params, 3, "color") {
                Ok(color) => color,
                Err(e) => return rpc_err(&e),
            };
            let order = match opt_param_i64(params, 4, "order") {
                Ok(order) => order,
                Err(e) => return rpc_err(&e),
            };
            if let Err(e) = check_role_fields(label, description, color) {
                return rpc_err(&e.to_string());
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
            if let Err(e) = check_role_id(id) {
                return rpc_err(&e.to_string());
            }
            // Deleting a missing role is a no-op success (like the other
            // removal methods). Only a disabled NIP-43, a missing relay
            // key, or a failed tombstone publish surfaces an error.
            match relay.delete_role(id).await {
                crate::relay::roles::RoleChange::Applied
                | crate::relay::roles::RoleChange::Noop => {
                    audit!(&relay, &identity, "deleterole", params);
                    rpc_ok(json!(true))
                }
                crate::relay::roles::RoleChange::Unknown => {
                    audit!(&relay, &identity, "deleterole", params);
                    rpc_ok(json!(true))
                }
                crate::relay::roles::RoleChange::Failed => rpc_err(
                    "restricted: NIP-43 is disabled, the relay key is missing or the event could not be stored",
                ),
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
            // Normalize to lowercase like `banpubkey`/`allowpubkey`:
            // `hex::decode` accepts uppercase, but events always carry
            // lowercase pubkeys, so an uppercase assignment would report
            // success while matching no event (and would be echoed in the
            // relay's membership list in the wrong case).
            let pubkey = pubkey.to_ascii_lowercase();
            if let Err(e) = check_role_id(role) {
                return rpc_err(&e.to_string());
            }
            // NIP-86: the result is always `true` — a duplicate grant is
            // a no-op success. Only an unknown role, a disabled NIP-43, a
            // missing relay key, or a failed persistence surfaces an error.
            match relay.assign_role(&pubkey, role).await {
                crate::relay::roles::RoleChange::Applied
                | crate::relay::roles::RoleChange::Noop => {
                    audit!(&relay, &identity, "assignrole", params);
                    rpc_ok(json!(true))
                }
                crate::relay::roles::RoleChange::Unknown => {
                    rpc_err("restricted: the role does not exist")
                }
                crate::relay::roles::RoleChange::Failed => rpc_err(
                    "restricted: NIP-43 is disabled, the relay key is missing or the event could not be stored",
                ),
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
            // Same lowercase normalization as `assignrole` above.
            let pubkey = pubkey.to_ascii_lowercase();
            if let Err(e) = check_role_id(role) {
                return rpc_err(&e.to_string());
            }
            // NIP-86: the result is always `true` — revoking an absent
            // grant is a no-op success. Only a disabled NIP-43, a missing
            // relay key, or a failed persistence surfaces an error.
            match relay.unassign_role(&pubkey, role).await {
                crate::relay::roles::RoleChange::Applied
                | crate::relay::roles::RoleChange::Noop => {
                    audit!(&relay, &identity, "unassignrole", params);
                    rpc_ok(json!(true))
                }
                // Unreachable for revocations (an unknown role revokes
                // nothing, which is a `Noop`), kept for exhaustiveness.
                crate::relay::roles::RoleChange::Unknown => {
                    audit!(&relay, &identity, "unassignrole", params);
                    rpc_ok(json!(true))
                }
                crate::relay::roles::RoleChange::Failed => rpc_err(
                    "restricted: NIP-43 is disabled, the relay key is missing or the event could not be stored",
                ),
            }
        }
        "assignmethod" => {
            if let Some(denied) = require_admin(&identity) {
                return denied;
            }
            let (Some(pubkey), Some(method)) = (
                params.first().and_then(Value::as_str),
                params.get(1).and_then(Value::as_str),
            ) else {
                return rpc_err("invalid params");
            };
            if !is_pubkey(pubkey) {
                return rpc_err("invalid pubkey");
            }
            // Normalize like the other pubkey arms: the grant check is
            // case-insensitive, but the stored form stays canonical.
            let pubkey = pubkey.to_ascii_lowercase();
            if !GRANTABLE_METHODS.contains(&method) {
                return rpc_err(
                    "invalid method: only moderation and read methods can be granted (supportedmethods needs no grant)",
                );
            }
            {
                let op = crate::config::AccessOp::GrantMethod {
                    pubkey: pubkey.clone(),
                    method: method.to_string(),
                };
                let mut access = relay.access.write().await;
                crate::config::apply_access_op(&mut access, &op);
                relay.push_access_ops(vec![op]);
            }
            // Same contract as the neighboring mutations: the in-memory
            // grant is live even when persistence fails, so it is still
            // audited; the RPC reports the persistence error.
            let persisted = relay.persist_access().await;
            audit!(&relay, &identity, "assignmethod", params);
            if !persisted {
                return rpc_err("error: cannot persist the access control state");
            }
            rpc_ok(json!([true, format!("granted {method} to {pubkey}")]))
        }
        "unassignmethod" => {
            if let Some(denied) = require_admin(&identity) {
                return denied;
            }
            let (Some(pubkey), Some(method)) = (
                params.first().and_then(Value::as_str),
                params.get(1).and_then(Value::as_str),
            ) else {
                return rpc_err("invalid params");
            };
            if !is_pubkey(pubkey) {
                return rpc_err("invalid pubkey");
            }
            let pubkey = pubkey.to_ascii_lowercase();
            // Revoking an absent grant is a no-op success (like the other
            // removal methods); an ungrantable name is still rejected so
            // typos surface instead of silently succeeding.
            if !GRANTABLE_METHODS.contains(&method) {
                return rpc_err(
                    "invalid method: only moderation and read methods can be granted (supportedmethods needs no grant)",
                );
            }
            {
                let op = crate::config::AccessOp::UngrantMethod {
                    pubkey: pubkey.clone(),
                    method: method.to_string(),
                };
                let mut access = relay.access.write().await;
                crate::config::apply_access_op(&mut access, &op);
                relay.push_access_ops(vec![op]);
            }
            let persisted = relay.persist_access().await;
            audit!(&relay, &identity, "unassignmethod", params);
            if !persisted {
                return rpc_err("error: cannot persist the access control state");
            }
            rpc_ok(json!([true, format!("revoked {method} from {pubkey}")]))
        }
        "listmethodassignees" => {
            if let Some(denied) = require_admin(&identity) {
                return denied;
            }
            let access = relay.access.read().await;
            let list: Vec<Value> = access
                .method_grants
                .iter()
                .map(|(pubkey, methods)| json!({ "pubkey": pubkey, "methods": methods }))
                .collect();
            rpc_ok(json!(list))
        }
        "blockip" => {
            let Some(ip) = params.first().and_then(Value::as_str) else {
                return rpc_err("invalid params");
            };
            let reason = match opt_param_str(params, 1, "reason") {
                Ok(reason) => reason,
                Err(e) => return rpc_err(&e),
            };
            let Ok(ip) = ip.parse::<std::net::IpAddr>() else {
                return rpc_err("invalid ip address");
            };
            // Normalize so a dual-stack `::ffff:a.b.c.d` block and a plain
            // IPv4 block refer to the same peer (and an equivalent-spelling
            // entry is not duplicated).
            let ip = crate::util::normalize_ip(ip);
            {
                let op = crate::config::AccessOp::BlockIp {
                    ip,
                    reason: reason.to_string(),
                };
                let mut access = relay.access.write().await;
                crate::config::apply_access_op(&mut access, &op);
                relay.push_access_ops(vec![op]);
            }
            // The in-memory block is live even when persistence fails, so
            // existing connections must still be dropped and the mutation
            // audited; the RPC reports the persistence error below.
            let persisted = relay.persist_access().await;
            // Drop existing connections from this IP, not just new ones.
            relay.note_ip_blocks_changed();
            audit!(&relay, &identity, "blockip", params);
            if !persisted {
                return rpc_err("error: cannot persist the access control state");
            }
            rpc_ok(json!(true))
        }
        "unblockip" => {
            let Some(ip) = params.first().and_then(Value::as_str) else {
                return rpc_err("invalid params");
            };
            let Ok(ip) = ip.parse::<std::net::IpAddr>() else {
                return rpc_err("invalid ip address");
            };
            let ip = crate::util::normalize_ip(ip);
            {
                // Remove equivalently-spelled entries too (`::1` versus
                // `0:0:0:0:0:0:0:1`, v4-mapped versus IPv4).
                let op = crate::config::AccessOp::UnblockIp { ip };
                let mut access = relay.access.write().await;
                crate::config::apply_access_op(&mut access, &op);
                relay.push_access_ops(vec![op]);
            }
            // Same contract as `blockip`: the in-memory unblock is live even
            // when persistence fails, so the version must still be bumped
            // and the mutation audited.
            let persisted = relay.persist_access().await;
            // Re-connect checks: unblocking also bumps the version so
            // connections that were blocked mid-flight re-verify (a version
            // bump with an empty list is harmless).
            relay.note_ip_blocks_changed();
            audit!(&relay, &identity, "unblockip", params);
            if !persisted {
                return rpc_err("error: cannot persist the access control state");
            }
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
            let Some(id) = params.first().and_then(Value::as_str) else {
                return rpc_err("invalid params");
            };
            let reason = match opt_param_str(params, 1, "reason") {
                Ok(reason) => reason,
                Err(e) => return rpc_err(&e),
            };
            let Ok(id) = hex::decode(id) else {
                return rpc_err("invalid event id");
            };
            let Ok(id): Result<[u8; 32], _> = id.try_into() else {
                return rpc_err("invalid event id");
            };
            // NIP-86: the result is always `true` — a ban lands even
            // for an unknown (future) id, pre-banning it. Only a store
            // failure must not be reported as success (the ban would
            // silently disappear on the next restart).
            let outcome = relay.db.ban_event(id, reason).await;
            audit!(&relay, &identity, "banevent", params);
            let (_, state_removed) = match outcome {
                Ok(outcome) => outcome,
                Err(e) => {
                    log::error!("banevent store failure: {e}");
                    return rpc_err("error: cannot persist the event ban");
                }
            };
            if state_removed {
                // A banned NIP-29/NIP-43 state event invalidates the live
                // derived state like any other removal of one (the database
                // already advanced its stamp, so a restart rebuilds instead
                // of resurrecting the banned grant).
                relay.mark_group_state_stale().await;
                relay.mark_roles_stale().await;
            }
            rpc_ok(json!(true))
        }
        "allowevent" => {
            let Some(id) = params.first().and_then(Value::as_str) else {
                return rpc_err("invalid params");
            };
            // The optional reason slot is validated like its siblings
            // (a non-string there is a client bug), though unbanning
            // carries no reason.
            let reason = match opt_param_str(params, 1, "reason") {
                Ok(reason) => reason,
                Err(e) => return rpc_err(&e),
            };
            let Ok(id) = hex::decode(id) else {
                return rpc_err("invalid event id");
            };
            let Ok(id): Result<[u8; 32], _> = id.try_into() else {
                return rpc_err("invalid event id");
            };
            // NIP-86: adding to the allow list removes the event from
            // the ban list (mutually exclusive, atomically). The result
            // is always `true` — allowing an unknown id pre-allows it,
            // like banning pre-bans. Only a store failure surfaces an
            // error.
            let outcome = relay.db.allow_event(id, reason).await;
            audit!(&relay, &identity, "allowevent", params);
            if let Err(e) = outcome {
                log::error!("allowevent store failure: {e}");
                return rpc_err("error: cannot persist the event allow");
            }
            rpc_ok(json!(true))
        }
        "unallowevent" => {
            let Some(id) = params.first().and_then(Value::as_str) else {
                return rpc_err("invalid params");
            };
            let Ok(id) = hex::decode(id) else {
                return rpc_err("invalid event id");
            };
            let Ok(id): Result<[u8; 32], _> = id.try_into() else {
                return rpc_err("invalid event id");
            };
            // NIP-86: the result is always `true` — removing a missing
            // marker is a no-op success. Only a store failure surfaces
            // an error.
            let outcome = relay.db.unallow_event(id).await;
            audit!(&relay, &identity, "unallowevent", params);
            if let Err(e) = outcome {
                log::error!("unallowevent store failure: {e}");
                return rpc_err("error: cannot persist the event unallow");
            }
            rpc_ok(json!(true))
        }
        "unbanevent" => {
            let Some(id) = params.first().and_then(Value::as_str) else {
                return rpc_err("invalid params");
            };
            let Ok(id) = hex::decode(id) else {
                return rpc_err("invalid event id");
            };
            let Ok(id): Result<[u8; 32], _> = id.try_into() else {
                return rpc_err("invalid event id");
            };
            // NIP-86: the result is always `true` — unbanning a
            // never-banned id is a no-op success. Only a store failure
            // surfaces an error.
            let outcome = relay.db.unban_event(id).await;
            audit!(&relay, &identity, "unbanevent", params);
            if let Err(e) = outcome {
                log::error!("unbanevent store failure: {e}");
                return rpc_err("error: cannot persist the event unban");
            }
            rpc_ok(json!(true))
        }
        "listbannedevents" => {
            let list = match relay.db.list_banned_events().await {
                Ok(list) => list,
                Err(e) => {
                    log::error!("listbannedevents read failure: {e}");
                    return rpc_err("error: cannot list banned events");
                }
            };
            let list: Vec<Value> = list
                .into_iter()
                .map(|(id, reason)| json!({ "id": id, "reason": reason }))
                .collect();
            rpc_ok(json!(list))
        }
        "listallowedevents" => {
            let list = match relay.db.list_allowed_events().await {
                Ok(list) => list,
                Err(e) => {
                    log::error!("listallowedevents read failure: {e}");
                    return rpc_err("error: cannot list allowed events");
                }
            };
            let list: Vec<Value> = list
                .into_iter()
                .map(|(id, reason)| json!({ "id": id, "reason": reason }))
                .collect();
            rpc_ok(json!(list))
        }
        "listeventsneedingmoderation" => {
            // This relay has no moderation queue: no events await review.
            rpc_ok(json!([]))
        }
        "listclaims" => {
            if let Some(denied) = require_admin(&identity) {
                return denied;
            }
            // Invite codes admit members: listing them is admin-only.
            let roles = relay.roles.read().await;
            let list: Vec<&str> = roles.claims.iter().map(String::as_str).collect();
            rpc_ok(json!(list))
        }
        "createclaim" => {
            if let Some(denied) = require_admin(&identity) {
                return denied;
            }
            let Some(claim) = params.first().and_then(Value::as_str) else {
                return rpc_err("invalid params");
            };
            if let Err(e) = check_claim(claim) {
                return rpc_err(&e.to_string());
            }
            if relay.create_claim(claim).await {
                audit!(&relay, &identity, "createclaim", params);
                rpc_ok(json!(true))
            } else {
                rpc_err("restricted: NIP-43 is disabled or the relay key is missing")
            }
        }
        "deleteclaim" => {
            if let Some(denied) = require_admin(&identity) {
                return denied;
            }
            let Some(claim) = params.first().and_then(Value::as_str) else {
                return rpc_err("invalid params");
            };
            if let Err(e) = check_claim(claim) {
                return rpc_err(&e.to_string());
            }
            // Revoking an absent code is a no-op success.
            if relay.delete_claim(claim).await {
                audit!(&relay, &identity, "deleteclaim", params);
                rpc_ok(json!(true))
            } else {
                rpc_err("restricted: NIP-43 is disabled or the relay key is missing")
            }
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

/// Extracts the token from an `Authorization: Bearer <token>` header
/// value. The scheme is case-insensitive (RFC 9110, like the NIP-98
/// `Nostr` scheme): a case-sensitive comparison 401s clients sending
/// `bearer` or `BEARER`. Returns `None` for another scheme or a scheme
/// with no token.
fn strip_bearer_scheme(value: &str) -> Option<&str> {
    let (scheme, token) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("Bearer").then_some(token)
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

/// Who called the NIP-86 RPC: a full administrator (the management
/// token or the configured admin pubkey, bypassing every per-method
/// check) or a pubkey holding `assignmethod` grants (gated per call).
/// `admin_pubkey` stays the root login; other users are controlled
/// within their granted method scope.
enum Identity {
    Admin(String),
    Grantee(String),
}

impl Identity {
    fn name(&self) -> &str {
        match self {
            Identity::Admin(name) | Identity::Grantee(name) => name,
        }
    }

    fn is_admin(&self) -> bool {
        matches!(self, Identity::Admin(_))
    }
}

impl std::fmt::Display for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// NIP-86 authentication: either the bearer `management_token` or a NIP-98
/// event by `admin_pubkey` whose `payload` tag is present and whose `u` tag
/// matches this relay's URL, including the request path and query
/// (NIP-98: "the `u` tag MUST be exactly the same as the absolute request
/// URL"; the scheme is normalized so TLS-terminating proxies keep working).
/// Otherwise any valid NIP-98 identity is admitted as a grantee: the
/// signature, `u`, `method`, `payload` and replay checks are identical —
/// only the pubkey restriction is lifted — and the per-method gate below
/// decides. A banned pubkey is refused on every authenticated service.
/// Returns the identity for the audit trail: the NIP-98 pubkey or
/// `"management-token"`.
async fn rpc_authenticated(
    relay: &Relay,
    headers: &HeaderMap,
    uri: &axum::http::Uri,
    body: &str,
) -> Option<Identity> {
    let cfg = relay.config.read().await;
    if !cfg.rpc.management_token.is_empty()
        && let Some(token) = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(strip_bearer_scheme)
        && ct_eq(token, &cfg.rpc.management_token)
    {
        return Some(Identity::Admin("management-token".into()));
    }
    let payload = nip98::payload_sha256_hex(body.as_bytes());
    // Full administrator: the configured admin pubkey.
    if !cfg.rpc.admin_pubkey.is_empty()
        && let Some(encoded) = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(nip98::strip_nostr_scheme)
        && let Some(verified) = nip98::verify(
            encoded,
            Some(&cfg.rpc.admin_pubkey),
            relay.secp(),
            true,
            Some(&payload),
            "POST",
            |url| nip98::matches_request_url(url, &cfg.relay_identity(), uri.path(), uri.query()),
        )
        && relay
            .nip98_replay
            .accept(&verified.id, crate::util::unix_now(), verified.created_at)
    {
        return Some(Identity::Admin(verified.pubkey));
    }
    // Grantee: any other valid NIP-98 identity (the admin attempt above
    // short-circuits before consuming the replay on a pubkey mismatch, so
    // a fresh event still verifies here). A banned pubkey is refused.
    if let Some(encoded) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(nip98::strip_nostr_scheme)
        && let Some(verified) = nip98::verify(
            encoded,
            None,
            relay.secp(),
            true,
            Some(&payload),
            "POST",
            |url| nip98::matches_request_url(url, &cfg.relay_identity(), uri.path(), uri.query()),
        )
        && relay
            .nip98_replay
            .accept(&verified.id, crate::util::unix_now(), verified.created_at)
        && !relay
            .access
            .read()
            .await
            .blocked_pubkeys
            .iter()
            .any(|(banned, _)| banned.eq_ignore_ascii_case(&verified.pubkey))
    {
        return Some(Identity::Grantee(verified.pubkey));
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
        cfg.database.max_map_size = 64 * 1024 * 1024;
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

    #[test]
    fn bearer_scheme_is_case_insensitive() {
        // RFC 9110: auth-schemes are case-insensitive; a client sending
        // `bearer` must authenticate like one sending `Bearer`.
        assert_eq!(strip_bearer_scheme("Bearer tok"), Some("tok"));
        assert_eq!(strip_bearer_scheme("bearer tok"), Some("tok"));
        assert_eq!(strip_bearer_scheme("BEARER tok"), Some("tok"));
        assert_eq!(strip_bearer_scheme("BeArEr tok"), Some("tok"));
        assert_eq!(strip_bearer_scheme("Nostr tok"), None);
        assert_eq!(strip_bearer_scheme("Bearer"), None);
        assert_eq!(strip_bearer_scheme(""), None);
    }

    /// Calls the RPC as a non-admin pubkey with a fresh NIP-98 signature
    /// (the grantee path: `u` = this endpoint, `method` = POST, payload =
    /// the body hash). A per-call salt in the auth event's `content` keeps
    /// the event id unique: the relay's 60-second replay guard would
    /// otherwise reject two identical calls in the same second. The salt
    /// rides `content` (which this relay leniently ignores) rather than
    /// the RPC body, so strict param validation sees pristine inputs.
    /// Returns the keypair's pubkey with the response.
    async fn nip98_call(
        relay: &std::sync::Arc<Relay>,
        seckey: &[u8; 32],
        method: &str,
        params: Vec<Value>,
    ) -> (String, Response) {
        use base64::Engine as _;
        static SALT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let salt = SALT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let secp = secp256k1::Secp256k1::new();
        let keypair = secp256k1::Keypair::from_seckey_slice(&secp, seckey).unwrap();
        let pubkey = secp256k1::XOnlyPublicKey::from_keypair(&keypair)
            .0
            .to_string();
        let body = serde_json::to_string(&json!({ "method": method, "params": params })).unwrap();
        let origin = relay.config.read().await.relay_identity().http_origin();
        let mut ev = crate::event::Event {
            id: String::new(),
            pubkey: pubkey.clone(),
            created_at: crate::util::unix_now(),
            kind: crate::nips::nip98::AUTH_KIND,
            tags: vec![
                vec!["u".into(), format!("{origin}/")],
                vec!["method".into(), "POST".into()],
                vec![
                    "payload".into(),
                    crate::nips::nip98::payload_sha256_hex(body.as_bytes()),
                ],
            ],
            content: format!("test-call-{salt}"),
            sig: String::new(),
        };
        ev.id = crate::nips::nip01::compute_id(&ev);
        let id = ev.id_bytes().unwrap();
        ev.sig = secp.sign_schnorr_no_aux_rand(&id, &keypair).to_string();
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(serde_json::to_string(&ev).unwrap());
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Nostr {encoded}").parse().unwrap(),
        );
        headers.insert(header::CONTENT_TYPE, RPC_CONTENT_TYPE.parse().unwrap());
        let resp = rpc_handler(
            State(relay.clone()),
            axum::extract::ConnectInfo("127.0.0.1:1234".parse().unwrap()),
            axum::http::Uri::from_static("/"),
            headers,
            body,
        )
        .await;
        (pubkey, resp)
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

        // Kind allow/disallow. With no config allowlist active,
        // `allowkind` must not populate `allowed_kinds` (which would turn
        // the kind list into a global allowlist and block every other kind).
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
        {
            let access = relay.access.read().await;
            assert!(
                access.allowed_kinds.is_empty(),
                "allowkind must not activate an empty config allowlist"
            );
            assert!(!access.allows_kind(5), "disallowkind must block the kind");
            assert!(access.allows_kind(1), "other kinds must stay allowed");
        }
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
        // The file-less test relay cannot persist: the in-memory change
        // applies but the RPC reports the failure (not `true`).
        assert!(rpc_err_of(resp).await.contains("persist"));
        assert_eq!(relay.config.read().await.relay.name, "newname");
        let resp = rpc_call(&relay, "changerelaydescription", vec![json!("new desc")]).await;
        assert!(rpc_err_of(resp).await.contains("persist"));
        let resp = rpc_call(&relay, "changerelayicon", vec![json!("https://x/i.png")]).await;
        assert!(rpc_err_of(resp).await.contains("persist"));

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
        // NIP-43: a color outside the documented 0-360 hue range is rejected
        // before the role can be stored or published.
        let resp = rpc_call(
            &relay,
            "createrole",
            vec![json!("r"), json!(""), json!(""), json!("361")],
        )
        .await;
        assert!(rpc_err_of(resp).await.contains("0 to 360"));
        let resp = rpc_call(
            &relay,
            "createrole",
            vec![json!("r"), json!(""), json!(""), json!("red")],
        )
        .await;
        assert!(rpc_err_of(resp).await.contains("0 to 360"));
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
        let resp = rpc_call(&relay, "unblockip", vec![json!("not-an-ip")]).await;
        assert!(rpc_err_of(resp).await.contains("ip address"));
        let resp = rpc_call(&relay, "listblockedips", vec![]).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // blockip normalizes v4-mapped IPv6 to IPv4, unblockip accepts any
        // equivalent spelling, and equivalent entries are not duplicated.
        let resp = rpc_call(
            &relay,
            "blockip",
            vec![json!("::ffff:127.0.0.9"), json!("mapped")],
        )
        .await;
        assert!(rpc_ok_of(resp).await);
        assert!(
            relay
                .access
                .read()
                .await
                .blocked_ips
                .iter()
                .any(|(i, r)| i == "127.0.0.9" && r == "mapped"),
            "the v4-mapped address must be stored normalized"
        );
        let resp = rpc_call(&relay, "unblockip", vec![json!("127.0.0.9")]).await;
        assert!(rpc_ok_of(resp).await);
        assert!(
            !relay
                .access
                .read()
                .await
                .blocked_ips
                .iter()
                .any(|(i, _)| i == "127.0.0.9"),
            "the equivalent spelling must remove the entry"
        );
        let resp = rpc_call(
            &relay,
            "blockip",
            vec![json!("0:0:0:0:0:0:0:9"), json!("expanded")],
        )
        .await;
        assert!(rpc_ok_of(resp).await);
        let resp = rpc_call(&relay, "blockip", vec![json!("::9"), json!("again")]).await;
        assert!(rpc_ok_of(resp).await);
        assert_eq!(
            relay
                .access
                .read()
                .await
                .blocked_ips
                .iter()
                .filter(|(i, _)| i == "::9")
                .count(),
            1,
            "equivalent spellings must not duplicate the entry"
        );
        let _ = rpc_call(&relay, "unblockip", vec![json!("::9")]).await;

        // banevent / allowevent / listbannedevents. NIP-86 reports
        // `true` (always) for these mutations: banning an unknown id
        // pre-bans it (future publications are refused), and unbanning
        // a never-banned id is a no-op success. Only a genuine store
        // failure surfaces an error.
        let secp = secp256k1::Secp256k1::new();
        let keypair = secp256k1::Keypair::from_seckey_slice(&secp, &[13u8; 32]).unwrap();
        let mut banned_event = crate::event::Event {
            id: String::new(),
            pubkey: secp256k1::XOnlyPublicKey::from_keypair(&keypair)
                .0
                .to_string(),
            created_at: crate::util::unix_now(),
            kind: 1,
            tags: vec![],
            content: "ban me".into(),
            sig: String::new(),
        };
        banned_event.id = crate::nips::nip01::compute_id(&banned_event);
        let id = banned_event.id.clone();
        let raw = banned_event.id_bytes().unwrap();
        banned_event.sig = secp.sign_schnorr_no_aux_rand(&raw, &keypair).to_string();
        assert_eq!(
            relay.db.put(banned_event, crate::util::unix_now()).await,
            crate::db::PutOutcome::Stored
        );
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
        // Pre-ban: an unknown (future) id is banned, not an error.
        let unknown = "cd".repeat(32);
        let resp = rpc_call(&relay, "banevent", vec![json!(unknown.clone())]).await;
        assert!(rpc_ok_of(resp).await);
        assert!(
            relay
                .db
                .list_banned_events()
                .await
                .unwrap()
                .iter()
                .any(|(banned, _)| banned == &unknown),
            "a pre-banned id must be listed"
        );
        // Idempotent unban: a never-banned id (and a repeat) succeeds.
        let resp = rpc_call(&relay, "allowevent", vec![json!(unknown.clone())]).await;
        assert!(rpc_ok_of(resp).await);
        let resp = rpc_call(&relay, "allowevent", vec![json!(unknown.clone())]).await;
        assert!(rpc_ok_of(resp).await);
        // A reply that reports the store as failed must surface an error,
        // not a `true` result (the next call runs against the dead writer).
        relay.db.shutdown();
        let resp = rpc_call(&relay, "banevent", vec![json!(id.clone())]).await;
        assert!(rpc_err_of(resp).await.contains("persist"));
        let resp = rpc_call(&relay, "allowevent", vec![json!(id.clone())]).await;
        assert!(rpc_err_of(resp).await.contains("persist"));
        // A failed ban lookup must surface an error, not an empty list
        // (the operator would believe "no bans").
        let resp = rpc_call(&relay, "listbannedevents", vec![]).await;
        assert!(rpc_err_of(resp).await.contains("cannot list banned events"));
        // The audit trail still records the attempted mutations.
        let recent = relay.audit.recent();
        assert!(recent.iter().any(|entry| entry.starts_with("banevent")));
        assert!(recent.iter().any(|entry| entry.starts_with("allowevent")));
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

    async fn rpc_result_of(resp: Response) -> Value {
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        serde_json::from_slice::<Value>(&body).unwrap()["result"].clone()
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
    async fn kind_allow_disallow_round_trip() {
        let relay = build_admin_relay().await;
        // Block, then allow: the kind is usable again and other kinds were
        // never affected.
        let resp = rpc_call(&relay, "disallowkind", vec![json!(7)]).await;
        assert!(rpc_ok_of(resp).await);
        {
            let access = relay.access.read().await;
            assert!(!access.allows_kind(7), "disallowkind must block the kind");
            assert!(access.allows_kind(1), "other kinds must stay allowed");
        }
        let resp = rpc_call(&relay, "allowkind", vec![json!(7)]).await;
        assert!(rpc_ok_of(resp).await);
        {
            let access = relay.access.read().await;
            assert!(
                access.allows_kind(7),
                "allowkind must re-enable a blocked kind"
            );
            assert!(
                access.allowed_kinds.is_empty(),
                "allowkind must not activate an empty allowlist"
            );
            assert!(access.allows_kind(1), "other kinds must stay allowed");
        }
        // The empty allowlist means "no allowlist restriction", so
        // `listallowedkinds` reports [] both before and after: on such a
        // relay every non-blocked kind is accepted.
        let list = rpc_result_of(rpc_call(&relay, "listallowedkinds", vec![]).await).await;
        assert_eq!(list, json!([]), "an empty allowlist means unrestricted");
        // Disallow again, and the kind disappears from `listallowedkinds`:
        // a blocked kind must never be reported as allowed.
        let resp = rpc_call(&relay, "allowkind", vec![json!(7)]).await;
        assert!(rpc_ok_of(resp).await);
        let resp = rpc_call(&relay, "disallowkind", vec![json!(7)]).await;
        assert!(rpc_ok_of(resp).await);
        {
            let access = relay.access.read().await;
            assert!(!access.allows_kind(7));
            assert!(
                !access.allowed_kinds.contains(&7),
                "a blocked kind must not be listed as allowed"
            );
        }
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn allowkind_extends_an_active_config_allowlist() {
        let relay = build_admin_relay().await;
        // Simulate a config allowlist through the op log (as a fresh seed
        // would): `allowed_kinds` is exhaustive while non-empty, so
        // `allowkind` must extend it or the call would report success while
        // `allows_kind` still rejects the kind. A direct in-memory write
        // would bypass the op log and be dropped by the next merge.
        {
            let op = crate::config::AccessOp::AllowKind { kind: 1 };
            let mut access = relay.access.write().await;
            crate::config::apply_access_op(&mut access, &op);
            relay.push_access_ops(vec![op]);
        }
        assert!(relay.persist_access().await, "the seed must persist");
        assert!(!relay.access.read().await.allows_kind(7));
        assert_eq!(
            rpc_result_of(rpc_call(&relay, "listallowedkinds", vec![]).await).await,
            json!([1]),
            "the active allowlist must be reported before the change"
        );
        let resp = rpc_call(&relay, "allowkind", vec![json!(7)]).await;
        assert!(rpc_ok_of(resp).await);
        {
            let access = relay.access.read().await;
            assert!(
                access.allows_kind(7),
                "allowkind must extend the active allowlist"
            );
            assert!(access.allows_kind(1), "the existing allowlist survives");
        }
        // The management client can now verify the call's effect: the
        // re-allowed kind shows up in `listallowedkinds`.
        assert_eq!(
            rpc_result_of(rpc_call(&relay, "listallowedkinds", vec![]).await).await,
            json!([1, 7]),
            "listallowedkinds must report the extended allowlist"
        );
        let resp = rpc_call(&relay, "disallowkind", vec![json!(7)]).await;
        assert!(rpc_ok_of(resp).await);
        {
            let access = relay.access.read().await;
            assert!(!access.allows_kind(7));
            assert!(
                !access.allowed_kinds.contains(&7),
                "disallowkind must remove the kind from the allowlist"
            );
            assert!(access.allows_kind(1));
        }
        assert_eq!(
            rpc_result_of(rpc_call(&relay, "listallowedkinds", vec![]).await).await,
            json!([1]),
            "listallowedkinds must drop the disallowed kind"
        );
        // A kind that the config lists as both allowed and blocked is not
        // accepted (`allows_kind` checks the denylist first) and must not be
        // reported as allowed either.
        {
            let mut access = relay.access.write().await;
            access.allowed_kinds = vec![1, 3];
            access.blocked_kinds = vec![3];
        }
        assert!(!relay.access.read().await.allows_kind(3));
        assert_eq!(
            rpc_result_of(rpc_call(&relay, "listallowedkinds", vec![]).await).await,
            json!([1]),
            "a blocked kind must never be reported as allowed"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn failed_persistence_still_notifies_and_audits() {
        // Every write-through persist fails (the database is gone), but the
        // in-memory mutation is live: the audit entry (and the blocked-IP
        // notification) must not be skipped. The RPC still reports the
        // persistence error so the operator knows a restart loses the change.
        let relay = build_admin_relay().await;
        relay.audit.clear();
        // Watch the IP-block version: `blockip`/`unblockip` must still drop
        // or re-check existing connections when persistence failed.
        let mut ip_changes = relay.ip_blocks_tx.subscribe();
        let before = *ip_changes.borrow_and_update();
        relay.db.shutdown();
        let calls: Vec<(&str, Vec<Value>)> = vec![
            ("banpubkey", vec![json!("aa".repeat(32))]),
            ("unbanpubkey", vec![json!("cc".repeat(32))]),
            ("allowpubkey", vec![json!("bb".repeat(32))]),
            ("unallowpubkey", vec![json!("dd".repeat(32))]),
            ("allowkind", vec![json!(7)]),
            ("disallowkind", vec![json!(7)]),
            ("blockip", vec![json!("127.0.0.9")]),
            ("unblockip", vec![json!("127.0.0.10")]),
        ];
        for (method, params) in &calls {
            let resp = rpc_call(&relay, method, params.clone()).await;
            assert!(
                rpc_err_of(resp).await.contains("persist"),
                "{method} must report the persistence failure"
            );
        }
        let recent = relay.audit.recent();
        assert_eq!(
            recent.len(),
            calls.len(),
            "every applied mutation must be audited: {recent:?}"
        );
        for (method, _) in &calls {
            assert!(
                recent.iter().any(|entry| entry.starts_with(method)),
                "{method} must be in the audit trail: {recent:?}"
            );
        }
        assert_ne!(
            before,
            *ip_changes.borrow_and_update(),
            "a failed persist must not skip the blocked-IP notification"
        );
        // The mutations are live in memory even though persisting failed.
        let access = relay.access.read().await;
        assert!(
            access
                .blocked_pubkeys
                .iter()
                .any(|(p, _)| p == &"aa".repeat(32)),
            "the ban mutation must be live"
        );
        assert!(
            access
                .allowed_pubkeys
                .iter()
                .any(|(p, _)| p == &"bb".repeat(32)),
            "the allow mutation must be live"
        );
        assert!(
            access.blocked_kinds.contains(&7),
            "the disallow mutation must be live"
        );
        assert!(
            access.is_ip_blocked("127.0.0.9".parse().unwrap()),
            "the block mutation must be live"
        );
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
        // The same applies to deleting an existing role: the tombstone
        // could not be stored. (Deleting a *missing* role is a no-op
        // success that needs no store access.)
        let relay = build_admin_relay_with_key(Some(&"ab".repeat(32))).await;
        let resp = rpc_call(&relay, "createrole", vec![json!("t")]).await;
        assert!(rpc_ok_of(resp).await);
        relay.db.shutdown();
        let resp = rpc_call(&relay, "deleterole", vec![json!("t")]).await;
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        assert!(
            body.windows(5).any(|w| w == b"error"),
            "a failed tombstone save must be reported: {body:?}"
        );
        let resp = rpc_call(&relay, "deleterole", vec![json!("ghost")]).await;
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        assert!(
            body.windows(4).any(|w| w == b"true"),
            "deleting a missing role needs no store: {body:?}"
        );
        relay.db.shutdown();
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
    async fn assignrole_normalizes_pubkey_case() {
        let relay = build_admin_relay_with_key(Some(&"cd".repeat(32))).await;
        let resp = rpc_call(&relay, "createrole", vec![json!("mod")]).await;
        assert!(rpc_ok_of(resp).await);
        // Uppercase hex is valid to `hex::decode`, but events always carry
        // lowercase pubkeys: the assignment must be stored lowercased, or it
        // would report success while matching nothing.
        let upper = "AB".repeat(32);
        let lower = "ab".repeat(32);
        let resp = rpc_call(&relay, "assignrole", vec![json!(upper), json!("mod")]).await;
        assert!(rpc_ok_of(resp).await);
        {
            let roles = relay.roles.read().await;
            assert!(
                roles.is_member_of(&lower),
                "the assignment must be stored lowercased"
            );
            assert!(!roles.is_member_of(&upper));
        }
        // Unassign accepts either case too.
        let resp = rpc_call(&relay, "unassignrole", vec![json!(upper), json!("mod")]).await;
        assert!(rpc_ok_of(resp).await);
        assert!(!relay.roles.read().await.is_member_of(&lower));
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn role_grant_revoke_are_idempotent() {
        // NIP-86: the `assignrole`/`unassignrole` result is always `true`
        // — a duplicate grant and a missing revocation are no-op
        // successes. Only an unknown grant target, a disabled NIP-43, a
        // missing relay key, or a failed persistence surfaces an error.
        let relay = build_admin_relay_with_key(Some(&"cd".repeat(32))).await;
        let member = "aa".repeat(32);
        let resp = rpc_call(&relay, "createrole", vec![json!("mod")]).await;
        assert!(rpc_ok_of(resp).await);
        let resp = rpc_call(
            &relay,
            "assignrole",
            vec![json!(member.clone()), json!("mod")],
        )
        .await;
        assert!(rpc_ok_of(resp).await);
        let resp = rpc_call(
            &relay,
            "assignrole",
            vec![json!(member.clone()), json!("mod")],
        )
        .await;
        assert!(
            rpc_ok_of(resp).await,
            "a duplicate grant must still report true"
        );
        let resp = rpc_call(
            &relay,
            "assignrole",
            vec![json!(member.clone()), json!("ghost")],
        )
        .await;
        assert!(
            rpc_err_of(resp).await.contains("does not exist"),
            "a grant to an unknown role stays an error"
        );
        let resp = rpc_call(
            &relay,
            "unassignrole",
            vec![json!("bb".repeat(32)), json!("mod")],
        )
        .await;
        assert!(
            rpc_ok_of(resp).await,
            "revoking a missing grant must still report true"
        );
        let resp = rpc_call(
            &relay,
            "unassignrole",
            vec![json!(member.clone()), json!("mod")],
        )
        .await;
        assert!(rpc_ok_of(resp).await);
        let resp = rpc_call(
            &relay,
            "unassignrole",
            vec![json!(member.clone()), json!("mod")],
        )
        .await;
        assert!(
            rpc_ok_of(resp).await,
            "a repeat revocation must still report true"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn method_grants_scope_non_admin_callers() {
        // NIP-86 PR #2439: `admin_pubkey` stays the root login; other
        // pubkeys only run their granted methods. `assignmethod` validates
        // its target, grants are idempotent, ungranted calls 401, and
        // `supportedmethods` shows the grantee only their subset.
        let relay = build_admin_relay().await;
        let agent = [11u8; 32];
        let (agent_pk, resp) = nip98_call(&relay, &agent, "listbannedevents", vec![]).await;
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "an ungranted pubkey calls nothing"
        );
        // Only grantable methods can be granted.
        let resp = rpc_call(
            &relay,
            "assignmethod",
            vec![json!(agent_pk), json!("createrole")],
        )
        .await;
        assert!(rpc_err_of(resp).await.contains("invalid method"));
        let resp = rpc_call(
            &relay,
            "assignmethod",
            vec![json!(agent_pk), json!("no-such-method")],
        )
        .await;
        assert!(rpc_err_of(resp).await.contains("invalid method"));
        let resp = rpc_call(&relay, "assignmethod", vec![json!("zz"), json!("banevent")]).await;
        assert!(rpc_err_of(resp).await.contains("pubkey"));
        // Grant + idempotent re-grant: the PR's `[true, message]` shape.
        let resp = rpc_call(
            &relay,
            "assignmethod",
            vec![json!(agent_pk.clone()), json!("banevent")],
        )
        .await;
        let granted = rpc_result_of(resp).await;
        assert_eq!(granted[0], true);
        let resp = rpc_call(
            &relay,
            "assignmethod",
            vec![json!(agent_pk.clone()), json!("banevent")],
        )
        .await;
        assert_eq!(rpc_result_of(resp).await[0], true);
        let resp = rpc_call(
            &relay,
            "assignmethod",
            vec![json!(agent_pk.clone()), json!("listbannedevents")],
        )
        .await;
        assert_eq!(rpc_result_of(resp).await[0], true);
        // The grantee runs the granted methods…
        let (_, resp) = nip98_call(&relay, &agent, "listbannedevents", vec![]).await;
        assert_eq!(resp.status(), StatusCode::OK);
        // …including a granted mutation end to end: the ban lands and is
        // audited under the grantee's pubkey.
        let target = "cd".repeat(32);
        let (_, resp) = nip98_call(&relay, &agent, "banevent", vec![json!(target.clone())]).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            relay
                .db
                .list_banned_events()
                .await
                .unwrap()
                .iter()
                .any(|(id, _)| id == &target),
            "a grantee-called banevent must take effect"
        );
        assert!(
            relay
                .audit
                .recent()
                .iter()
                .any(|e| e.starts_with("banevent") && e.contains(&agent_pk)),
            "the mutation must be audited as the grantee: {:?}",
            relay.audit.recent()
        );
        // …but nothing else: admin-only arms without their own guard
        // rely on the gate alone, so probe each family.
        for method in [
            "createrole",
            "deleterole",
            "assignrole",
            "createclaim",
            "deleteclaim",
            "listclaims",
            "changerelayname",
            "unassignmethod",
        ] {
            let (_, resp) = nip98_call(&relay, &agent, method, vec![]).await;
            assert_eq!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "a grantee must not reach {method}"
            );
        }
        // Unknown methods: admins get the rpc error, grantees a 401.
        let resp = rpc_call(&relay, "nosuchmethod", vec![]).await;
        assert!(rpc_err_of(resp).await.contains("unsupported"));
        let (_, resp) = nip98_call(&relay, &agent, "nosuchmethod", vec![]).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        // …but nothing else, including the permission methods themselves.
        let (_, resp) = nip98_call(&relay, &agent, "listbannedpubkeys", vec![]).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let (_, resp) = nip98_call(
            &relay,
            &agent,
            "assignmethod",
            vec![json!(agent_pk), json!("banevent")],
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "a grantee must never escalate"
        );
        // Discovery shows the subset only.
        let (_, resp) = nip98_call(&relay, &agent, "supportedmethods", vec![]).await;
        let list = rpc_result_of(resp).await;
        let list = list.as_array().unwrap();
        assert!(list.iter().any(|m| m == "banevent"));
        assert!(!list.iter().any(|m| m == "assignmethod"));
        assert!(!list.iter().any(|m| m == "supportedmethods"));
        // Admins still see everything.
        let admin_list = rpc_result_of(rpc_call(&relay, "supportedmethods", vec![]).await).await;
        assert!(
            admin_list
                .as_array()
                .unwrap()
                .iter()
                .any(|m| m == "assignmethod")
        );
        // listmethodassignees reports the grant (admin-only).
        let reported = rpc_result_of(rpc_call(&relay, "listmethodassignees", vec![]).await).await;
        assert_eq!(reported[0]["pubkey"], agent_pk);
        assert_eq!(
            reported[0]["methods"],
            json!(["banevent", "listbannedevents"])
        );
        let (_, resp) = nip98_call(&relay, &agent, "listmethodassignees", vec![]).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        // Revoke: the grants disappear, calls 401 again (idempotent).
        let resp = rpc_call(
            &relay,
            "unassignmethod",
            vec![json!(agent_pk.clone()), json!("banevent")],
        )
        .await;
        assert_eq!(rpc_result_of(resp).await[0], true);
        let resp = rpc_call(
            &relay,
            "unassignmethod",
            vec![json!(agent_pk.clone()), json!("banevent")],
        )
        .await;
        assert_eq!(rpc_result_of(resp).await[0], true);
        let resp = rpc_call(
            &relay,
            "unassignmethod",
            vec![json!(agent_pk.clone()), json!("listbannedevents")],
        )
        .await;
        assert_eq!(rpc_result_of(resp).await[0], true);
        let (_, resp) = nip98_call(&relay, &agent, "listbannedevents", vec![]).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(
            rpc_result_of(rpc_call(&relay, "listmethodassignees", vec![]).await)
                .await
                .as_array()
                .unwrap()
                .is_empty()
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn banned_grantee_is_refused() {
        // A banned pubkey is refused on every authenticated service: a
        // grant does not override a ban.
        let relay = build_admin_relay().await;
        let agent = [12u8; 32];
        let (agent_pk, _) = nip98_call(&relay, &agent, "supportedmethods", vec![]).await;
        let resp = rpc_call(
            &relay,
            "assignmethod",
            vec![json!(agent_pk.clone()), json!("listbannedevents")],
        )
        .await;
        assert_eq!(rpc_result_of(resp).await[0], true);
        let _ = rpc_call(&relay, "banpubkey", vec![json!(agent_pk.clone())]).await;
        let (_, resp) = nip98_call(&relay, &agent, "listbannedevents", vec![]).await;
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "a banned grantee must be refused"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn invite_claims_roundtrip_and_admit() {
        // NIP-86 PR #2408 + NIP-43: `createclaim` issues codes,
        // `listclaims` shows them (admin-only), `deleteclaim` revokes,
        // and a `kind:28934` carrying a listed code admits its author.
        let relay = build_admin_relay_with_key(Some(&"cd".repeat(32))).await;
        // Validation first.
        let resp = rpc_call(&relay, "createclaim", vec![]).await;
        assert!(rpc_err_of(resp).await.contains("params"));
        let resp = rpc_call(&relay, "createclaim", vec![json!("")]).await;
        assert!(rpc_err_of(resp).await.contains("empty"));
        // Issue + idempotent re-issue.
        let resp = rpc_call(&relay, "createclaim", vec![json!("welcome-1")]).await;
        assert!(rpc_ok_of(resp).await);
        let resp = rpc_call(&relay, "createclaim", vec![json!("welcome-1")]).await;
        assert!(rpc_ok_of(resp).await);
        let listed = rpc_result_of(rpc_call(&relay, "listclaims", vec![]).await).await;
        assert_eq!(listed, json!(["welcome-1"]));
        // A join with the code is admitted (OK true, welcome).
        let secp = secp256k1::Secp256k1::new();
        let keypair = secp256k1::Keypair::from_seckey_slice(&secp, &[21u8; 32]).unwrap();
        let pubkey = secp256k1::XOnlyPublicKey::from_keypair(&keypair)
            .0
            .to_string();
        let join = || crate::event::Event {
            id: String::new(),
            pubkey: pubkey.clone(),
            created_at: crate::util::unix_now(),
            kind: crate::nips::nip43::JOIN,
            tags: vec![vec!["-".into()], vec!["claim".into(), "welcome-1".into()]],
            content: String::new(),
            sig: String::new(),
        };
        let mut ev = join();
        ev.id = crate::nips::nip01::compute_id(&ev);
        let id = ev.id_bytes().unwrap();
        ev.sig = secp.sign_schnorr_no_aux_rand(&id, &keypair).to_string();
        assert!(
            matches!(
                relay.accept_event(ev, std::slice::from_ref(&pubkey), None).await,
                crate::db::PutOutcome::Duplicate(msg) if msg.starts_with("info:")
            ),
            "a valid claim admits the joiner with a welcome"
        );
        assert!(
            relay.roles.read().await.is_member_of(&pubkey),
            "the joiner is recorded on the member list"
        );
        // Rejoin with the same code: the spec's `duplicate:` verdict.
        let mut ev = join();
        ev.id = crate::nips::nip01::compute_id(&ev);
        let id = ev.id_bytes().unwrap();
        ev.sig = secp.sign_schnorr_no_aux_rand(&id, &keypair).to_string();
        assert!(
            matches!(
                relay.accept_event(ev, std::slice::from_ref(&pubkey), None).await,
                crate::db::PutOutcome::Duplicate(msg) if msg.starts_with("duplicate:")
            ),
            "a member rejoining gets the duplicate verdict"
        );
        // A bogus code is refused with the spec's wording.
        let other = secp256k1::Keypair::from_seckey_slice(&secp, &[22u8; 32]).unwrap();
        let other_pk = secp256k1::XOnlyPublicKey::from_keypair(&other)
            .0
            .to_string();
        let mut ev = crate::event::Event {
            id: String::new(),
            pubkey: other_pk.clone(),
            created_at: crate::util::unix_now(),
            kind: crate::nips::nip43::JOIN,
            tags: vec![vec!["-".into()], vec!["claim".into(), "bogus".into()]],
            content: String::new(),
            sig: String::new(),
        };
        ev.id = crate::nips::nip01::compute_id(&ev);
        let id = ev.id_bytes().unwrap();
        ev.sig = secp.sign_schnorr_no_aux_rand(&id, &other).to_string();
        assert!(
            matches!(
                relay.accept_event(ev, std::slice::from_ref(&other_pk), None).await,
                crate::db::PutOutcome::Invalid(msg) if msg.starts_with("restricted:")
            ),
            "an unknown code is refused"
        );
        // Revoke + idempotent re-revoke; joins fail again.
        let resp = rpc_call(&relay, "deleteclaim", vec![json!("welcome-1")]).await;
        assert!(rpc_ok_of(resp).await);
        let resp = rpc_call(&relay, "deleteclaim", vec![json!("welcome-1")]).await;
        assert!(rpc_ok_of(resp).await);
        assert!(
            rpc_result_of(rpc_call(&relay, "listclaims", vec![]).await)
                .await
                .as_array()
                .unwrap()
                .is_empty()
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn changerelay_reports_persist_failure() {
        // The test relay has no config file to persist to: the in-memory
        // change applies, but the RPC must report the failure instead of
        // `true` (the change would vanish on reload).
        let relay = build_admin_relay().await;
        let resp = rpc_call(&relay, "changerelayname", vec![json!("x")]).await;
        assert!(
            rpc_err_of(resp).await.contains("persist"),
            "an unpersisted relay change must surface an error"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn role_params_reject_wrong_types() {
        // A mistyped field must fail instead of silently storing a role
        // the operator did not describe (absent/null still means default).
        let relay = build_admin_relay_with_key(Some(&"cd".repeat(32))).await;
        let resp = rpc_call(
            &relay,
            "createrole",
            vec![json!("r1"), json!(1), json!(""), json!("")],
        )
        .await;
        assert!(
            rpc_err_of(resp).await.contains("label must be a string"),
            "a numeric label must be rejected"
        );
        let resp = rpc_call(
            &relay,
            "createrole",
            vec![json!("r1"), json!(""), json!(""), json!(""), json!("1")],
        )
        .await;
        assert!(
            rpc_err_of(resp).await.contains("order must be an integer"),
            "a string order must be rejected"
        );
        let resp = rpc_call(
            &relay,
            "createrole",
            vec![
                json!("r1"),
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
            ],
        )
        .await;
        assert!(rpc_ok_of(resp).await, "null fields mean defaults");
        let resp = rpc_call(
            &relay,
            "editrole",
            vec![json!("r1"), json!(true), json!(""), json!("")],
        )
        .await;
        assert!(
            rpc_err_of(resp).await.contains("label must be a string"),
            "editrole validates types too"
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn reason_params_reject_non_strings() {
        // A non-string reason must fail instead of being silently dropped
        // (absent/null still means no reason).
        let relay = build_admin_relay().await;
        for method in ["banpubkey", "allowpubkey"] {
            let resp = rpc_call(&relay, method, vec![json!("aa".repeat(32)), json!(7)]).await;
            assert!(
                rpc_err_of(resp).await.contains("reason must be a string"),
                "{method} must reject a numeric reason"
            );
            let resp = rpc_call(&relay, method, vec![json!("aa".repeat(32)), Value::Null]).await;
            assert!(rpc_ok_of(resp).await, "{method} accepts a null reason");
        }
        let resp = rpc_call(&relay, "blockip", vec![json!("127.0.0.1"), json!(true)]).await;
        assert!(rpc_err_of(resp).await.contains("reason must be a string"));
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn deleterole_missing_is_noop_success() {
        // Deleting a missing role is a no-op success like the other
        // removal methods (spec: result `true`).
        let relay = build_admin_relay_with_key(Some(&"cd".repeat(32))).await;
        let resp = rpc_call(&relay, "deleterole", vec![json!("ghost")]).await;
        assert!(rpc_ok_of(resp).await);
        let resp = rpc_call(&relay, "createrole", vec![json!("r1")]).await;
        assert!(rpc_ok_of(resp).await);
        let resp = rpc_call(&relay, "deleterole", vec![json!("r1")]).await;
        assert!(rpc_ok_of(resp).await);
        let resp = rpc_call(&relay, "deleterole", vec![json!("r1")]).await;
        assert!(rpc_ok_of(resp).await, "repeat deletion stays a success");
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn changerelay_rejects_newlines_outside_description() {
        // The name and icon URL are single-line values served in NIP-11;
        // only the description keeps the newline/tab allowance.
        let relay = build_admin_relay().await;
        let resp = rpc_call(&relay, "changerelayname", vec![json!("a\nb")]).await;
        assert!(rpc_err_of(resp).await.contains("control characters"));
        let resp = rpc_call(&relay, "changerelayicon", vec![json!("https://x\ny")]).await;
        assert!(rpc_err_of(resp).await.contains("control characters"));
        // A newline description passes validation (persistence still
        // fails on the file-less test relay, proving the refusal above
        // came from validation, not persistence).
        let resp = rpc_call(&relay, "changerelaydescription", vec![json!("a\nb")]).await;
        assert!(rpc_err_of(resp).await.contains("persist"));
        relay.db.shutdown();
        // Whitespace-only invite codes are rejected like role ids.
        let relay = build_admin_relay_with_key(Some(&"cd".repeat(32))).await;
        let resp = rpc_call(&relay, "createclaim", vec![json!("   ")]).await;
        assert!(rpc_err_of(resp).await.contains("empty"));
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn event_allowlist_roundtrip_and_coupling() {
        // NIP-86 event allowlist: `allowevent` records a marker and lifts
        // the ban, `banevent` drops the marker, `unallowevent` removes it,
        // `unbanevent` only lifts the ban — all idempotent `true`.
        let relay = build_admin_relay().await;
        for method in ["allowevent", "unallowevent", "unbanevent"] {
            let resp = rpc_call(&relay, method, vec![]).await;
            assert!(
                rpc_err_of(resp).await.contains("params"),
                "{method} validates params"
            );
            let resp = rpc_call(&relay, method, vec![json!("zz")]).await;
            assert!(
                rpc_err_of(resp).await.contains("event id"),
                "{method} validates ids"
            );
        }
        let id = "ab".repeat(32);
        // Unknown id: allow records the marker (pre-allow, like pre-ban).
        let resp = rpc_call(&relay, "allowevent", vec![json!(id.clone()), json!("mine")]).await;
        assert!(rpc_ok_of(resp).await);
        let listed = rpc_result_of(rpc_call(&relay, "listallowedevents", vec![]).await).await;
        assert_eq!(listed, json!([{ "id": id, "reason": "mine" }]));
        // Banning drops the marker atomically.
        let resp = rpc_call(&relay, "banevent", vec![json!(id.clone())]).await;
        assert!(rpc_ok_of(resp).await);
        assert!(
            rpc_result_of(rpc_call(&relay, "listallowedevents", vec![]).await)
                .await
                .as_array()
                .unwrap()
                .is_empty(),
            "a ban removes the allow marker"
        );
        // Allowing lifts the ban and re-records the marker.
        let resp = rpc_call(&relay, "allowevent", vec![json!(id.clone())]).await;
        assert!(rpc_ok_of(resp).await);
        assert!(
            rpc_result_of(rpc_call(&relay, "listbannedevents", vec![]).await)
                .await
                .as_array()
                .unwrap()
                .is_empty(),
            "an allow lifts the ban"
        );
        assert_eq!(
            rpc_result_of(rpc_call(&relay, "listallowedevents", vec![]).await).await[0]["id"],
            json!(id)
        );
        // Unallow removes the marker (idempotent); unban on a clean id
        // succeeds without touching the marker.
        let resp = rpc_call(&relay, "unallowevent", vec![json!(id.clone())]).await;
        assert!(rpc_ok_of(resp).await);
        let resp = rpc_call(&relay, "unallowevent", vec![json!(id.clone())]).await;
        assert!(rpc_ok_of(resp).await);
        let resp = rpc_call(&relay, "unbanevent", vec![json!(id.clone())]).await;
        assert!(rpc_ok_of(resp).await);
        assert!(
            rpc_result_of(rpc_call(&relay, "listallowedevents", vec![]).await)
                .await
                .as_array()
                .unwrap()
                .is_empty()
        );
        // Denied kinds are listed back.
        let resp = rpc_call(&relay, "disallowkind", vec![json!(7)]).await;
        assert!(rpc_ok_of(resp).await);
        assert_eq!(
            rpc_result_of(rpc_call(&relay, "listdisallowedkinds", vec![]).await).await,
            json!([7])
        );
        relay.db.shutdown();
    }

    #[tokio::test]
    async fn supportedmethods_advertises_every_implemented_method() {
        // Every implemented method (except itself) must be advertised:
        // clients discover capabilities through this list.
        let relay = build_admin_relay().await;
        let list = rpc_result_of(rpc_call(&relay, "supportedmethods", vec![]).await).await;
        let list = list.as_array().unwrap();
        for method in SUPPORTED_METHODS {
            if *method == "supportedmethods" {
                continue;
            }
            assert!(
                list.iter().any(|m| m == *method),
                "{method} is implemented but not advertised"
            );
        }
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

    #[tokio::test]
    async fn changerelayname_refreshes_the_nip11_cache() {
        // The NIP-11 document caches its static part against the relay's
        // config version; the management RPC must bump it like a SIGHUP
        // reload, or the old value is served until the next restart. A
        // writable config file lets the change persist (and report `true`).
        let relay = build_admin_relay().await;
        let dir = std::env::temp_dir().join("nostrfy-changerelay-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nostrfy.toml");
        std::fs::write(&path, "[relay]\nname = \"before\"\n").unwrap();
        *relay.config_path.write().await = Some(path);
        let before = relay.relay_info_document().await;
        let resp = rpc_call(&relay, "changerelayname", vec![json!("after-change")]).await;
        assert!(rpc_ok_of(resp).await);
        let after = relay.relay_info_document().await;
        assert_eq!(after["name"], "after-change");
        assert_ne!(before["name"], after["name"]);
        let _ = std::fs::remove_dir_all(&dir);
        relay.db.shutdown();
    }
}
