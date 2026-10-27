//! Buzz-compatible Nostr HTTP bridge.
//!
//! Buzz (the Block desktop app) talks to a relay over WebSocket for live
//! subscriptions but uses an HTTP bridge for read models and writes:
//!
//! - `GET  /info`   — NIP-11 relay information document
//! - `POST /query`  — one-shot filters, returns a flat JSON array of events
//! - `POST /events` — publish one signed event
//! - `POST /count`  — NIP-45-style count
//!
//! Every bridge request except `/info` is authenticated with NIP-98
//! (`Authorization: Nostr <base64 kind:27235>`), including the request-body
//! hash in the `payload` tag. The authenticated pubkey then drives the same
//! visibility rules as an authenticated WebSocket connection: NIP-70
//! protected events, NIP-59 gift-wrap recipients, NIP-78 owner-only events
//! and NIP-29 private/hidden groups.

use std::collections::HashSet;
use std::sync::Arc;

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use crate::db::PutOutcome;
use crate::event::Event;
use crate::filter::Filter;
use crate::nips::{nip29, nip62, nip70, nip78, nip98};
use crate::relay::Relay;
use crate::util::unix_now;

#[cfg(test)]
mod tests;

/// Maximum number of filters a `/query` request may carry. Buzz batches
/// channel history filters; 256 is far above its own bounds and still keeps
/// one request from pinning unbounded memory.
const MAX_BRIDGE_FILTERS: usize = 256;

/// Fallback per-filter limit when the client omitted `limit`. Buzz's channel
/// directory queries omit it and expect the relay's full page (500 here, the
/// default `limits.max_limit`), not a 100-row truncation.
const DEFAULT_FILTER_LIMIT: usize = 500;

/// Hard cap for the over-fetch window used by the composite `before_id`
/// cursor. The database's own API queue limits still apply.
const MAX_BRIDGE_FETCH: usize = 2_000;

/// Buzz's `before_id` extension: a composite cursor with `until`.
#[allow(clippy::result_large_err)]
fn parse_before_id(raw: &Value) -> Result<Option<String>, Response> {
    let Some(value) = raw.get("before_id") else {
        return Ok(None);
    };
    match value.as_str() {
        Some(id) if id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()) => {
            Ok(Some(id.to_ascii_lowercase()))
        }
        _ => Err(bad_request("before_id must be a 64-hex event id")),
    }
}

/// True when the raw filter opts into a bridge extension flag.
fn extension_flag(raw: &Value, key: &str) -> bool {
    raw.get(key).and_then(Value::as_bool).unwrap_or(false)
}

pub(crate) fn bad_request(message: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": message }))).into_response()
}

fn unauthorized(message: &str) -> Response {
    (StatusCode::UNAUTHORIZED, Json(json!({ "error": message }))).into_response()
}

/// NIP-98 `u` matching for the bridge.
///
/// Buzz signs the absolute URL it requested. The configured relay identity
/// is authoritative. When `relay.public_url` is unset (a direct local
/// deployment), accept the configured bind host and loopback aliases as a
/// fixed allowlist; never compare against the request `Host` header, which
/// an attacker controls and could use to replay a captured authorization
/// from another origin. Deployments behind a proxy must set
/// `relay.public_url` to the externally visible origin.
fn bridge_url_matches(cfg: &crate::config::Config, url: &str, path: &str) -> bool {
    if nip98::matches_request_url(url, &cfg.relay_identity(), path, None) {
        return true;
    }
    if !cfg.relay.public_url.trim().is_empty() {
        return false;
    }
    let Some((scheme, rest)) = url.split_once("://") else {
        return false;
    };
    // The direct fallback is plain HTTP only; a TLS-proxied deployment must
    // configure `relay.public_url` so its scheme and authority are pinned.
    if !scheme.eq_ignore_ascii_case("http") {
        return false;
    }
    let rest = rest.split('#').next().unwrap_or(rest);
    let (authority, signed_path) = rest.split_once('/').unwrap_or((rest, ""));
    if authority.contains('@') || signed_path.is_empty() {
        return false;
    }
    if format!("/{signed_path}") != path {
        return false;
    }
    let (authority_host, signed_port) = crate::nips::nip62::split_host_port(authority);
    let signed_port = signed_port.unwrap_or(80);
    if signed_port != cfg.server.port {
        return false;
    }
    let signed_host = super::normalize_host(authority_host);
    let configured = super::normalize_host(&cfg.server.host);
    let loopback = matches!(
        configured.as_str(),
        "" | "0.0.0.0" | "::" | "127.0.0.1" | "::1" | "localhost"
    );
    signed_host == configured
        || (loopback && matches!(signed_host.as_str(), "127.0.0.1" | "::1" | "localhost"))
}

/// Verifies the NIP-98 authorization of a bridge request.
///
/// Always requires the `payload` tag with the SHA-256 of the exact request
/// body: a captured header must not authorize a different filter or event.
#[allow(clippy::result_large_err)]
async fn authenticate(
    relay: &Arc<Relay>,
    cfg: &crate::config::Config,
    headers: &HeaderMap,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<String, Response> {
    let encoded = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(nip98::strip_nostr_scheme)
        .ok_or_else(|| unauthorized("auth-required: missing Nostr authorization"))?;
    let payload_hash = nip98::payload_sha256_hex(body);
    let verified = nip98::verify(encoded, None, true, Some(&payload_hash), method, |url| {
        bridge_url_matches(cfg, url, path)
    })
    .ok_or_else(|| unauthorized("auth-required: verification failed"))?;
    if !relay.nip98_replay.accept(
        &verified.id,
        unix_now(),
        verified.created_at,
        &verified.pubkey,
    ) {
        return Err(unauthorized(
            "auth-required: authorization was already used",
        ));
    }
    if relay
        .access
        .read()
        .await
        .blocked_pubkeys
        .iter()
        .any(|(banned, _)| banned.eq_ignore_ascii_case(&verified.pubkey))
    {
        return Err(unauthorized("restricted: this pubkey is blocked"));
    }
    Ok(verified.pubkey)
}

/// NIP-CL read rule for system channels. A filter sees a system channel's
/// state only when it names the channel (`#h`, or `#d` on the channel-state
/// kinds), asks for `#t:["system"]`, or has a `#P` creator constraint.
/// Membership notices carry the channel type too.
pub(crate) fn nip_cl_visible(filter: &Filter, event: &Event, groups: &nip29::GroupStore) -> bool {
    let gid = nip29::group_id_any(event).or_else(|| {
        if nip29::is_membership_notice_kind(event.kind) {
            event
                .tags
                .iter()
                .find(|t| t.len() >= 2 && t[0] == "h")
                .map(|t| t[1].as_str())
        } else {
            None
        }
    });
    let Some(gid) = gid else {
        return true;
    };
    nip_cl_group_visible(filter, groups, gid)
}

/// The group-id half of [`nip_cl_visible`], shared with NIP-77 where only
/// the lightweight record's group id is available.
pub(crate) fn nip_cl_group_visible(filter: &Filter, groups: &nip29::GroupStore, gid: &str) -> bool {
    let Some(group) = groups.groups.get(gid) else {
        return true;
    };
    if group.channel_type != "system" {
        return true;
    }
    let values = |name: &str| {
        filter
            .tags
            .get(name)
            .map(|value| {
                value
                    .as_str()
                    .into_iter()
                    .chain(
                        value
                            .as_array()
                            .into_iter()
                            .flatten()
                            .filter_map(Value::as_str),
                    )
                    .any(|value| value == gid || (name == "#t" && value == "system"))
            })
            .unwrap_or(false)
    };
    if values("#h") || values("#t") {
        return true;
    }
    if filter.tags.get("#d").is_some_and(|_| {
        filter.kinds.as_ref().is_some_and(|kinds| {
            !kinds.is_empty()
                && kinds
                    .iter()
                    .all(|kind| (nip29::GROUP_META..=nip29::GROUP_PINS).contains(kind))
        })
    }) && values("#d")
    {
        return true;
    }
    filter.tags.contains_key("#P")
}

/// Whether a stored event may be served to the authenticated bridge caller.
pub(crate) fn bridge_visible(
    event: &Event,
    authed: &str,
    groups: Option<&nip29::GroupStore>,
    nip78_restricted: bool,
    relay_pubkey: Option<&str>,
) -> bool {
    if let Some(groups) = groups
        && groups.channel_ttl_expired(event, unix_now())
    {
        return false;
    }

    // NIP-70: the `-` tag constrains publication; authenticated readers may
    // read protected events exactly like an authenticated WebSocket client.
    if nip70::hidden_from_anonymous(event, relay_pubkey) && authed.is_empty() {
        return false;
    }
    // NIP-59 gift wraps are addressed to their recipients.
    if matches!(
        event.kind,
        nip62::GIFT_WRAP_KIND | nip62::EPHEMERAL_GIFT_WRAP_KIND
    ) && !event
        .tags
        .iter()
        .any(|t| t.len() >= 2 && t[0] == "p" && t[1].eq_ignore_ascii_case(authed))
    {
        return false;
    }
    // NIP-78 application-specific state is owner-only.
    if nip78_restricted && nip78::is_app_specific(event) && event.pubkey != authed {
        return false;
    }
    // Membership notices and DM visibility snapshots are per-pubkey state;
    // even an `ids` filter must not reveal another member's row.
    if matches!(event.kind, 44100 | 44101 | 30622)
        && !event
            .tags
            .iter()
            .any(|t| t.len() >= 2 && t[0] == "p" && t[1].eq_ignore_ascii_case(authed))
    {
        return false;
    }
    if let Some(groups) = groups
        && nip29::is_group_event(event)
    {
        return groups.visible_to(event, Some(authed));
    }
    true
}

/// Orders events the way Buzz's read models expect: `created_at DESC, id ASC`.
pub(crate) fn sort_desc_id_asc(events: &mut [Event]) {
    events.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
            .then_with(|| a.id.cmp(&b.id))
    });
}

/// Applies the composite `(created_at, id)` cursor.
fn after_cursor(event: &Event, until: u64, before_id: &str) -> bool {
    event.created_at < until || (event.created_at == until && event.id.as_str() > before_id)
}

pub(crate) fn event_json(event: &Event) -> Value {
    serde_json::to_value(event).unwrap_or(Value::Null)
}

/// `GET /info` — NIP-11 relay information document.
pub async fn info(State(relay): State<Arc<Relay>>) -> Response {
    let mut response = Json(relay.relay_info_document().await).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/nostr+json"),
    );
    response
}

/// `POST /events` — publish one signed event.
pub async fn events(State(relay): State<Arc<Relay>>, headers: HeaderMap, body: Bytes) -> Response {
    let cfg = relay.config.read().await.clone();
    let pubkey = match authenticate(&relay, &cfg, &headers, "POST", "/events", &body).await {
        Ok(pubkey) => pubkey,
        Err(response) => return response,
    };
    let event: Event = match serde_json::from_slice(&body) {
        Ok(event) => event,
        Err(e) => return bad_request(&format!("invalid event JSON: {e}")),
    };
    // NIP-98 authenticates the publisher, not just the transport: a caller
    // must not submit an event signed by another identity (the signature
    // would be valid, but the HTTP authorization would name someone else).
    if !event.pubkey.eq_ignore_ascii_case(&pubkey) {
        return unauthorized("auth-required: the event author must match the NIP-98 signer");
    }
    let outcomes = relay
        .accept_events_batch(vec![event.clone()], &[pubkey])
        .await;
    let Some((event_id, outcome)) = outcomes.into_iter().next() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "database overloaded" })),
        )
            .into_response();
    };
    match outcome {
        PutOutcome::Stored | PutOutcome::Replaced | PutOutcome::Ephemeral => (
            StatusCode::OK,
            Json(json!({
                "event_id": event_id,
                "accepted": true,
                "message": "",
            })),
        )
            .into_response(),
        PutOutcome::Duplicate(message) => (
            StatusCode::OK,
            Json(json!({
                "event_id": event_id,
                "accepted": true,
                "message": message,
            })),
        )
            .into_response(),
        PutOutcome::Invalid(reason) => {
            let status = if reason.starts_with("restricted:") || reason.starts_with("blocked:") {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::BAD_REQUEST
            };
            (status, Json(json!({ "error": reason }))).into_response()
        }
        PutOutcome::Expired => bad_request("invalid: event has expired"),
        PutOutcome::PreviouslyDeleted => bad_request("blocked: event has been deleted"),
        PutOutcome::Failed(reason) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": reason })),
        )
            .into_response(),
    }
}

/// `POST /query` — one-shot filter query, returns a flat event array.
pub async fn query(State(relay): State<Arc<Relay>>, headers: HeaderMap, body: Bytes) -> Response {
    let cfg = relay.config.read().await.clone();
    let pubkey = match authenticate(&relay, &cfg, &headers, "POST", "/query", &body).await {
        Ok(pubkey) => pubkey,
        Err(response) => return response,
    };
    if body.len() > cfg.limits.max_ws_message_bytes {
        return bad_request("query body is too large");
    }
    let raw_filters: Vec<Value> = match serde_json::from_slice(&body) {
        Ok(filters) => filters,
        Err(e) => return bad_request(&format!("invalid filters: {e}")),
    };
    if raw_filters.is_empty() || raw_filters.len() > MAX_BRIDGE_FILTERS {
        return bad_request("query requires between 1 and 256 filters");
    }
    // The thread-mode bounds binding names the server-resolved authority.
    // The Host header is the authority the client addressed (behind a proxy
    // the deployment must preserve it; there is no trusted forwarded-host
    // header here). Fall back to the configured bind host for direct use.
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .map(|host| host.trim_end_matches('.').to_ascii_lowercase())
        .unwrap_or_else(|| {
            cfg.server
                .host
                .trim()
                .trim_end_matches('.')
                .to_ascii_lowercase()
        });
    let events = if raw_filters
        .iter()
        .any(|raw| extension_flag(raw, "top_level"))
        || raw_filters
            .iter()
            .any(|raw| raw.get("depth_limit").is_some())
        || raw_filters
            .iter()
            .any(|raw| raw.get("thread_window").is_some())
    {
        match super::bridge_window::query_all(&relay, &cfg, &pubkey, &raw_filters, &host).await {
            Ok(events) => events,
            Err(response) => return response,
        }
    } else {
        match execute_filters(&relay, &cfg, &pubkey, &raw_filters).await {
            Ok(events) => events,
            Err(response) => return response,
        }
    };
    let values = match encode_events(&events, cfg.limits.max_req_response_bytes) {
        Ok(values) => values,
        Err(response) => return response,
    };
    Json(Value::Array(values)).into_response()
}

/// Serializes the response within the same byte budget as a WebSocket REQ
/// page. A bridge request must not be able to pin an unbounded response in
/// memory; the client narrows the filter or lowers `limit` on a 413.
#[allow(clippy::result_large_err)]
fn encode_events(events: &[Event], max_bytes: u64) -> Result<Vec<Value>, Response> {
    let mut values = Vec::with_capacity(events.len());
    let mut used = 0u64;
    for event in events {
        let value = event_json(event);
        let size = serde_json::to_string(&value).map_or(0, |text| text.len() as u64);
        if max_bytes > 0 && !values.is_empty() && used.saturating_add(size) > max_bytes {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(json!({ "error": "response too large; narrow the filter or lower limit" })),
            )
                .into_response());
        }
        used = used.saturating_add(size);
        values.push(value);
    }
    Ok(values)
}

/// Executes ordinary (non-window) filters for an authenticated caller.
///
/// The database applies its own per-filter limits; this function widens the
/// scan and then re-applies the client's limits after visibility and the
/// composite `before_id` cursor, so hidden rows and dense same-second bursts
/// do not silently shorten a page.
#[allow(clippy::result_large_err)]
pub(crate) async fn execute_filters(
    relay: &Arc<Relay>,
    cfg: &crate::config::Config,
    pubkey: &str,
    raw_filters: &[Value],
) -> Result<Vec<Event>, Response> {
    struct Parsed {
        filter: Filter,
        /// The client's requested limit (the filter's own limit is widened
        /// for the visibility/cursor post-filter).
        limit: usize,
        cursor: Option<(u64, String)>,
        search: bool,
    }

    let mut parsed = Vec::with_capacity(raw_filters.len());
    let mut fetch_limit = 0usize;
    let max_limit = cfg.limits.max_limit.max(1);
    for raw in raw_filters {
        let mut filter: Filter = match serde_json::from_value(raw.clone()) {
            Ok(filter) => filter,
            Err(e) => return Err(bad_request(&format!("invalid filter: {e}"))),
        };
        if !cfg.nip_enabled(50) {
            filter.search = None;
        }
        if filter.too_many_members() {
            return Err(bad_request(
                "too many ids, authors, kinds or tag values in a filter",
            ));
        }
        if filter.invalid_tag_values() {
            return Err(bad_request("tag constraint values must be strings"));
        }
        let before_id = match parse_before_id(raw) {
            Ok(before_id) => before_id,
            Err(response) => return Err(response),
        };
        let cursor = match (filter.until, before_id) {
            (Some(until), Some(id)) => Some((until, id)),
            // A plain `until` is the ordinary NIP-01 timestamp cursor; only
            // `before_id` on its own is malformed (it has no timestamp to
            // anchor the composite order).
            (Some(_), None) | (None, None) => None,
            (None, Some(_)) => {
                return Err(bad_request("before_id requires until"));
            }
        };
        let limit = filter.limit.unwrap_or(DEFAULT_FILTER_LIMIT).min(max_limit);
        let search = filter.has_search();
        // Visibility and the composite cursor are applied after the scan, so
        // widen the database limit: otherwise a batch of hidden rows or a
        // dense same-second burst would make a visible page look exhausted.
        // A zero-limit filter must stay zero instead of turning into a scan.
        let widened = if limit == 0 {
            0
        } else {
            limit
                .saturating_mul(4)
                .saturating_add(16)
                .min(MAX_BRIDGE_FETCH)
        };
        if limit > 0 {
            fetch_limit = fetch_limit.saturating_add(widened);
        }
        filter.limit = Some(widened);
        parsed.push(Parsed {
            filter,
            limit,
            cursor,
            search,
        });
    }
    if parsed.iter().all(|p| p.limit == 0) {
        return Ok(Vec::new());
    }
    let fetch_limit = fetch_limit.clamp(1, MAX_BRIDGE_FETCH);
    let filters: Vec<Filter> = parsed.iter().map(|p| p.filter.clone()).collect();
    let Some((mut events, _more)) = relay
        .db
        .api_query(filters, fetch_limit, unix_now(), false)
        .await
    else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "database is overloaded, try again shortly" })),
        )
            .into_response());
    };
    // NIP-50 search results keep the database's relevance order; every other
    // query is served in the total order Buzz's read models assume.
    if !parsed.iter().any(|p| p.search) {
        sort_desc_id_asc(&mut events);
    }

    let nip78_restricted = cfg.nip_enabled(78) && cfg.relay.enabled_nip78_auth;
    let groups = relay.groups.read().await;
    let mut counts = vec![0usize; parsed.len()];
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(events.len());
    for event in events {
        if !bridge_visible(
            &event,
            pubkey,
            Some(&groups),
            nip78_restricted,
            relay.relay_pubkey_ref(),
        ) {
            continue;
        }
        if seen.contains(&event.id) {
            continue;
        }
        for (index, parsed) in parsed.iter().enumerate() {
            if parsed.limit == 0 || counts[index] >= parsed.limit {
                continue;
            }
            if !parsed.filter.matches(&event) || !nip_cl_visible(&parsed.filter, &event, &groups) {
                continue;
            }
            if let Some((until, before_id)) = &parsed.cursor
                && !after_cursor(&event, *until, before_id)
            {
                continue;
            }
            counts[index] += 1;
            seen.insert(event.id.clone());
            out.push(event);
            break;
        }
    }
    drop(groups);

    Ok(out)
}

/// `POST /count` — NIP-45-style count for the supplied filters.
pub async fn count(State(relay): State<Arc<Relay>>, headers: HeaderMap, body: Bytes) -> Response {
    let cfg = relay.config.read().await.clone();
    let pubkey = match authenticate(&relay, &cfg, &headers, "POST", "/count", &body).await {
        Ok(pubkey) => pubkey,
        Err(response) => return response,
    };
    let raw_filters: Vec<Value> = match serde_json::from_slice(&body) {
        Ok(filters) => filters,
        Err(e) => return bad_request(&format!("invalid filters: {e}")),
    };
    if raw_filters.is_empty() || raw_filters.len() > MAX_BRIDGE_FILTERS {
        return bad_request("count requires between 1 and 256 filters");
    }
    let mut filters = Vec::with_capacity(raw_filters.len());
    for raw in raw_filters {
        let mut filter: Filter = match serde_json::from_value(raw) {
            Ok(filter) => filter,
            Err(e) => return bad_request(&format!("invalid filter: {e}")),
        };
        if !cfg.nip_enabled(50) {
            filter.search = None;
        }
        if filter.too_many_members() || filter.invalid_tag_values() {
            return bad_request("invalid filter bounds");
        }
        filters.push(filter);
    }
    let Some((events, approximate)) = relay
        .db
        .api_count(filters.clone(), cfg.limits.max_count, unix_now())
        .await
    else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "database is overloaded, try again shortly" })),
        )
            .into_response();
    };
    let nip78_restricted = cfg.nip_enabled(78) && cfg.relay.enabled_nip78_auth;
    let groups = relay.groups.read().await;
    let count = events
        .iter()
        .filter(|event| {
            bridge_visible(
                event,
                &pubkey,
                Some(&groups),
                nip78_restricted,
                relay.relay_pubkey_ref(),
            ) && filters
                .iter()
                .any(|filter| filter.matches(*event) && nip_cl_visible(filter, event, &groups))
        })
        .count();
    drop(groups);
    let approximate = approximate && cfg.limits.max_count > 0 && count >= cfg.limits.max_count;
    Json(json!({ "count": count, "approximate": approximate })).into_response()
}
