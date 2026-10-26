//! NIP-CW channel and thread windows for the Buzz HTTP bridge.
//!
//! Buzz's timeline does not page raw NIP-01 rows: it asks for top-level
//! channel rows with a composite `(created_at, id)` cursor and expects one
//! relay-signed `kind:39006` bounds event per served page. Threads use the
//! older `#e` + `depth_limit` path. Both are query-time read models: the
//! rows are ordinary stored events, the overlays are signed but never
//! stored.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::event::Event;
use crate::filter::Filter;
use crate::nips::nip29;
use crate::relay::Relay;
use crate::util::unix_now;

use super::bridge::{bad_request, bridge_visible, nip_cl_visible};

const WINDOW_DEFAULT_LIMIT: usize = 50;
const WINDOW_MAX_LIMIT: usize = 200;
const WINDOW_FETCH_MIN: usize = 200;
const WINDOW_FETCH_MAX: usize = 2_000;
const THREAD_DEFAULT_LIMIT: usize = 100;
const THREAD_MAX_LIMIT: usize = 500;
const THREAD_DEPTH_DEFAULT: u32 = 64;
const THREAD_DEPTH_MAX: u32 = 100;
const AUX_LIMIT: usize = 1_000;
/// Cap on events walked for one set of thread-summary trees.
const SUMMARY_TREE_MAX: usize = 10_000;

/// NIP-CW's thread-summary kind. The same integer is NIP-29's group-pins
/// event; Buzz never asks for pins in a window, so the two never mix.
const THREAD_SUMMARY: u64 = 39005;
const AUX_KINDS: &[u64] = &[5, 7, 9005, 40003];
const AUX_DELETE_KINDS: &[u64] = &[5, 9005];
const THREAD_CONTENT_KINDS: &[u64] = &[9, 40002, 45001, 45003];
/// Aggregate output bound for one mixed window request. Individual windows
/// are already bounded; this keeps 256 repeated filters from materializing
/// hundreds of thousands of events before the response-size check runs.
const MAX_WINDOW_EVENTS: usize = 20_000;

/// Executes a mixed `/query` request: window filters, legacy thread filters
/// and ordinary NIP-01 filters, concatenated in request order.
#[allow(clippy::result_large_err)]
pub(crate) async fn query_all(
    relay: &Arc<Relay>,
    cfg: &crate::config::Config,
    authed: &str,
    raw_filters: &[Value],
    host: &str,
) -> Result<Vec<Event>, Response> {
    let mut out = Vec::new();
    let mut ordinary = Vec::new();
    for raw in raw_filters {
        if raw.get("thread_window").and_then(Value::as_bool) == Some(true) {
            if raw.get("top_level").and_then(Value::as_bool) == Some(true) {
                return Err(bad_request(
                    "thread_window cannot be combined with top_level",
                ));
            }
            out.extend(thread_mode_window(relay, cfg, authed, host, raw).await?);
        } else if raw.get("top_level").and_then(Value::as_bool) == Some(true) {
            out.extend(channel_window(relay, cfg, authed, raw).await?);
        } else if raw.get("depth_limit").is_some() {
            out.extend(thread_window(relay, cfg, authed, raw).await?);
        } else {
            ordinary.push(raw.clone());
        }
        if out.len() > MAX_WINDOW_EVENTS {
            return Err(window_too_large());
        }
    }
    if !ordinary.is_empty() {
        out.extend(super::bridge::execute_filters(relay, cfg, authed, &ordinary).await?);
        if out.len() > MAX_WINDOW_EVENTS {
            return Err(window_too_large());
        }
    }
    Ok(out)
}

fn window_too_large() -> Response {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        Json(json!({ "error": "window response too large; narrow the filters" })),
    )
        .into_response()
}

fn is_hex_64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A NIP-10 marked reply target. Only the `reply` marker counts; positional
/// or `root`-only e-tags are not replies (NIP-CW).
fn reply_parent(event: &Event) -> Option<&str> {
    event
        .tags
        .iter()
        .find(|t| {
            t.len() >= 4
                && t[0] == "e"
                && t[3] == "reply"
                && is_hex_64(t.get(1).map_or("", String::as_str))
        })
        .map(|t| t[1].as_str())
}

fn is_broadcast(event: &Event) -> bool {
    event
        .tags
        .iter()
        .any(|t| t.len() >= 2 && t[0] == "broadcast" && t[1] == "1")
}

/// Top-level classification for a channel window.
///
/// Without a persisted depth index this treats every broadcast reply as
/// depth 1. That is the only form Buzz emits; a deeper reply that carries
/// `broadcast` would also surface, which is a display-only deviation from
/// NIP-CW, never an access-control issue.
fn is_top_level(event: &Event) -> bool {
    reply_parent(event).is_none() || is_broadcast(event)
}

fn sort_desc_id_asc(events: &mut [Event]) {
    events.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
            .then_with(|| a.id.cmp(&b.id))
    });
}

fn sort_asc_id_asc(events: &mut [Event]) {
    events.sort_by(|a, b| {
        a.created_at
            .cmp(&b.created_at)
            .then_with(|| a.id.cmp(&b.id))
    });
}

fn cursor_after(event: &Event, until: u64, before_id: &str) -> bool {
    event.created_at < until || (event.created_at == until && event.id.as_str() > before_id)
}

#[allow(clippy::result_large_err)]
fn channel_id(raw: &Value) -> Result<String, Response> {
    let Some(values) = raw.get("#h").and_then(Value::as_array) else {
        return Err(bad_request("window requires exactly one #h channel"));
    };
    if values.len() != 1 {
        return Err(bad_request("window requires exactly one #h channel"));
    }
    values[0]
        .as_str()
        .map(str::to_string)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| bad_request("window requires exactly one #h channel"))
}

#[allow(clippy::result_large_err)]
fn before_id(raw: &Value) -> Result<Option<String>, Response> {
    let Some(value) = raw.get("before_id") else {
        return Ok(None);
    };
    match value.as_str() {
        Some(id) if is_hex_64(id) => Ok(Some(id.to_ascii_lowercase())),
        _ => Err(bad_request("before_id must be a 64-hex event id")),
    }
}

#[allow(clippy::result_large_err)]
fn parse_cursor(raw: &Value) -> Result<Option<(u64, String)>, Response> {
    let before = before_id(raw)?;
    let until = raw.get("until").and_then(Value::as_u64);
    match (until, before) {
        (Some(until), Some(id)) => Ok(Some((until, id))),
        (None, None) => Ok(None),
        _ => Err(bad_request("until and before_id must be provided together")),
    }
}

fn raw_limit(raw: &Value, default: usize, max: usize) -> usize {
    // NIP-01 defines zero as "no events"; only a missing limit gets the
    // window/thread default. A positive value is still capped.
    raw.get("limit")
        .and_then(Value::as_u64)
        .map(|value| value as usize)
        .unwrap_or(default)
        .min(max)
}

/// Channel-mode window (NIP-CW §Channel-mode).
#[allow(clippy::result_large_err)]
async fn channel_window(
    relay: &Arc<Relay>,
    cfg: &crate::config::Config,
    authed: &str,
    raw: &Value,
) -> Result<Vec<Event>, Response> {
    let channel = channel_id(raw)?;
    let cursor = parse_cursor(raw)?;
    let limit = raw_limit(raw, WINDOW_DEFAULT_LIMIT, WINDOW_MAX_LIMIT);
    if limit == 0 {
        return Ok(Vec::new());
    }
    let include_aux = raw.get("include_aux").and_then(Value::as_bool) == Some(true);
    let include_summaries = raw.get("include_summaries").and_then(Value::as_bool) == Some(true);

    {
        let groups = relay.groups.read().await;
        let Some(_group) = groups.groups.get(&channel) else {
            // An unknown channel is indistinguishable from an inaccessible
            // one: no rows and no overlays.
            return Ok(Vec::new());
        };
        if !groups.visible_kind(&channel, 9, Some(authed)) {
            return Ok(Vec::new());
        }
    }

    let mut base_filter: Filter = serde_json::from_value(raw.clone())
        .map_err(|e| bad_request(&format!("invalid window filter: {e}")))?;
    if base_filter.too_many_members() || base_filter.invalid_tag_values() {
        return Err(bad_request("invalid window filter bounds"));
    }
    if !cfg.nip_enabled(50) {
        base_filter.search = None;
    }
    if cfg.limits.max_api_search_bytes > 0
        && let Some(search) = &base_filter.search
        && search.len() > cfg.limits.max_api_search_bytes
    {
        return Err(bad_request(&format!(
            "search exceeds the maximum of {} bytes",
            cfg.limits.max_api_search_bytes
        )));
    }
    let fetch = limit
        .saturating_mul(8)
        .saturating_add(64)
        .clamp(WINDOW_FETCH_MIN, WINDOW_FETCH_MAX);
    let nip78_restricted = cfg.nip_enabled(78) && cfg.relay.enabled_nip78_auth;

    let mut rows: Vec<Event> = Vec::with_capacity(limit);
    let mut page_cursor = cursor.clone();
    let mut last_scanned: Option<(u64, String)> = None;
    // The published 39006 cursor must name a row the caller may see; using
    // the last scanned row would disclose a hidden event's id/timestamp.
    let mut last_visible: Option<(u64, String)> = None;
    let mut scanned_ids: HashSet<String> = HashSet::new();
    let mut has_more = false;
    let mut rounds = 0usize;
    loop {
        rounds += 1;
        let mut filter = base_filter.clone();
        if let Some((until, _)) = &page_cursor {
            filter.until = Some(*until);
        }
        filter.limit = Some(fetch);
        let Some((mut candidates, db_more)) = relay
            .db
            .api_query(vec![filter], fetch, unix_now(), false)
            .await
        else {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "database is overloaded, try again shortly" })),
            )
                .into_response());
        };
        sort_desc_id_asc(&mut candidates);

        let groups = relay.groups.read().await;
        let mut examined_this_round = 0usize;
        let mut eligible_this_round = 0usize;
        for event in candidates {
            if let Some((until, before)) = &page_cursor
                && !cursor_after(&event, *until, before)
            {
                continue;
            }
            if !scanned_ids.insert(event.id.clone()) {
                continue;
            }
            examined_this_round += 1;
            last_scanned = Some((event.created_at, event.id.clone()));
            if !bridge_visible(
                &event,
                authed,
                Some(&groups),
                nip78_restricted,
                relay.relay_pubkey_ref(),
            ) {
                continue;
            }
            last_visible = Some((event.created_at, event.id.clone()));
            if is_top_level(&event) {
                eligible_this_round += 1;
                if rows.len() < limit {
                    rows.push(event);
                }
            }
        }
        drop(groups);

        if eligible_this_round > limit || (rows.len() == limit && db_more) {
            has_more = true;
            break;
        }
        if rows.len() == limit && !db_more {
            // An exact-multiple final page: no extra row exists, so this is
            // exhaustion even though the page is full.
            has_more = false;
            break;
        }
        // A dense timestamp can fill the over-fetch window with rows all
        // newer than the cursor. Re-reading `until` then makes no progress.
        // Fetch that complete second explicitly, so hidden replies cannot
        // strand an older visible top-level row.
        if examined_this_round == 0
            && db_more
            && let Some((boundary, _)) = last_scanned
        {
            let mut second_filter = base_filter.clone();
            second_filter.since = Some(boundary);
            second_filter.until = Some(boundary);
            second_filter.limit = Some(WINDOW_FETCH_MAX);
            let Some((mut second, second_more)) = relay
                .db
                .api_query(vec![second_filter], WINDOW_FETCH_MAX, unix_now(), false)
                .await
            else {
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({ "error": "database is overloaded, try again shortly" })),
                )
                    .into_response());
            };
            if second_more {
                // More events than one complete-second fetch can hold. A
                // partial page would publish a cursor that cannot advance
                // through the same second; fail explicitly instead of
                // returning an empty/exhausted page.
                return Err(window_too_large());
            }
            sort_desc_id_asc(&mut second);
            let groups = relay.groups.read().await;
            for event in second {
                if !scanned_ids.insert(event.id.clone()) {
                    continue;
                }
                last_scanned = Some((event.created_at, event.id.clone()));
                if !bridge_visible(
                    &event,
                    authed,
                    Some(&groups),
                    nip78_restricted,
                    relay.relay_pubkey_ref(),
                ) {
                    continue;
                }
                last_visible = Some((event.created_at, event.id.clone()));
                if is_top_level(&event) {
                    if rows.len() < limit {
                        rows.push(event);
                    } else {
                        // The visible page would have to split this second;
                        // a composite cursor cannot represent that safely.
                        drop(groups);
                        return Err(window_too_large());
                    }
                }
            }
            drop(groups);
            if boundary == 0 {
                // The completed second is the oldest possible one; an exact
                // page is exhaustion, not a split-second cursor.
                has_more = false;
                break;
            }
            if rows.len() == limit {
                return Err(window_too_large());
            }
            // `since`/`until` are inclusive; start strictly before the
            // completed second.
            page_cursor = Some((boundary - 1, String::new()));
            continue;
        }
        if !db_more || examined_this_round == 0 {
            // The scan is exhausted (or cannot make progress without
            // re-reading the same rows). A full page with db_more still set
            // means the next page exists even though this scan found no
            // extra row.
            has_more = db_more && rows.len() == limit;
            break;
        }
        if rounds >= 4 {
            // The bounded over-fetch stopped early. If every scanned row was
            // hidden there is no visible cursor to hand back; returning an
            // empty/exhausted page would silently truncate the channel.
            // Fail explicitly instead.
            if db_more && last_visible.is_none() {
                return Err(window_too_large());
            }
            // There may still be older rows, so hand the client a cursor
            // rather than claiming exhaustion; an empty page can progress via
            // the last visible candidate.
            has_more = last_visible.is_some();
            break;
        }
        // Advance strictly past the last candidate of this round. The next
        // query uses `until` inclusively; the post-filter keeps the scan
        // exact under same-second bursts.
        page_cursor = last_scanned.clone();
        if page_cursor.is_none() {
            break;
        }
    }

    let next_cursor = if has_more {
        rows.last()
            .map(|event| (event.created_at, event.id.clone()))
            .or(last_visible)
    } else {
        None
    };
    let has_more = next_cursor.is_some();

    let mut out = rows.clone();
    if include_aux && !rows.is_empty() {
        let row_ids: Vec<String> = rows.iter().map(|event| event.id.clone()).collect();
        let aux = fetch_aux(relay, cfg, authed, &base_filter, &row_ids).await?;
        out.extend(aux);
    }
    if include_summaries && !rows.is_empty() {
        let summaries = thread_summaries(relay, cfg, authed, &channel, &rows).await?;
        out.extend(summaries);
    }
    if let Some(bounds) = window_bounds(relay, &channel, cursor.as_ref(), has_more, next_cursor) {
        out.push(bounds);
    }
    // Refresh access for the whole served page. A channel that became
    // inaccessible while the scan ran must not release rows or bounds.
    let still_visible = {
        let groups = relay.groups.read().await;
        groups.group(&channel).is_some() && groups.visible_kind(&channel, 9, Some(authed))
    };
    if !still_visible {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "group access changed; retry the query" })),
        )
            .into_response());
    }
    Ok(out)
}

/// Fetches the two-hop aux closure for a set of rows.
#[allow(clippy::result_large_err)]
async fn fetch_aux(
    relay: &Arc<Relay>,
    cfg: &crate::config::Config,
    authed: &str,
    visible_filter: &Filter,
    row_ids: &[String],
) -> Result<Vec<Event>, Response> {
    let nip78_restricted = cfg.nip_enabled(78) && cfg.relay.enabled_nip78_auth;
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut hop = row_ids.to_vec();
    for kinds in [AUX_KINDS, AUX_DELETE_KINDS] {
        if hop.is_empty() {
            break;
        }
        let mut next = Vec::new();
        for chunk in hop.chunks(crate::filter::MAX_FILTER_MEMBERS) {
            let mut filter = Filter {
                kinds: Some(kinds.to_vec()),
                limit: Some(AUX_LIMIT),
                ..Filter::default()
            };
            filter.tags.insert("#e".to_string(), json!(chunk));
            let Some((events, _)) = relay
                .db
                .api_query(vec![filter], AUX_LIMIT, unix_now(), false)
                .await
            else {
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({ "error": "database is overloaded, try again shortly" })),
                )
                    .into_response());
            };
            let groups = relay.groups.read().await;
            for event in events {
                if !seen.insert(event.id.clone()) {
                    continue;
                }
                if !bridge_visible(
                    &event,
                    authed,
                    Some(&groups),
                    nip78_restricted,
                    relay.relay_pubkey_ref(),
                ) || !nip_cl_visible(visible_filter, &event, &groups)
                {
                    continue;
                }
                next.push(event.id.clone());
                out.push(event);
            }
            drop(groups);
        }
        hop = next;
    }
    Ok(out)
}

/// One relay-signed `kind:39005` per row that has at least one direct reply.
///
/// Counts, participants and `last_reply_at` cover the visible subtree, not
/// just the direct replies. The walk is bounded by `THREAD_DEPTH_MAX` and
/// `SUMMARY_TREE_MAX` so a hostile or very large thread cannot make one
/// channel window materialize an unbounded tree.
#[allow(clippy::result_large_err)]
async fn thread_summaries(
    relay: &Arc<Relay>,
    cfg: &crate::config::Config,
    authed: &str,
    channel: &str,
    rows: &[Event],
) -> Result<Vec<Event>, Response> {
    let row_ids: Vec<String> = rows.iter().map(|event| event.id.clone()).collect();
    let mut filter = Filter {
        kinds: Some(THREAD_CONTENT_KINDS.to_vec()),
        limit: Some(AUX_LIMIT),
        ..Filter::default()
    };
    filter.tags.insert("#e".to_string(), json!(row_ids.clone()));
    filter.tags.insert("#h".to_string(), json!([channel]));
    let Some((events, _)) = relay
        .db
        .api_query(vec![filter], AUX_LIMIT, unix_now(), false)
        .await
    else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "database is overloaded, try again shortly" })),
        )
            .into_response());
    };
    let nip78_restricted = cfg.nip_enabled(78) && cfg.relay.enabled_nip78_auth;
    let groups = relay.groups.read().await;
    let row_set: HashSet<&str> = rows.iter().map(|event| event.id.as_str()).collect();
    // (direct replies, all descendants, last reply, recent participants)
    type Summary = (usize, usize, u64, Vec<(u64, String)>);
    let mut per_row: HashMap<String, Summary> = HashMap::new();
    let mut root_for: HashMap<String, String> = HashMap::new();
    let mut frontier: Vec<String> = Vec::new();
    for event in events {
        if !bridge_visible(
            &event,
            authed,
            Some(&groups),
            nip78_restricted,
            relay.relay_pubkey_ref(),
        ) {
            continue;
        }
        // Count only the marked reply parent. A nested reply also carries
        // the root in an `e` tag, so taking the first `e` that names a row
        // would count the whole subtree as direct replies.
        let parent = reply_parent(&event).filter(|id| row_set.contains(id));
        let Some(parent) = parent else {
            continue;
        };
        let entry =
            per_row
                .entry(parent.to_string())
                .or_insert((0, 0, event.created_at, Vec::new()));
        entry.0 += 1;
        entry.2 = entry.2.max(event.created_at);
        record_summary_participant(&mut entry.3, event.created_at, &event.pubkey);
        root_for.insert(event.id.clone(), parent.to_string());
        frontier.push(event.id.clone());
    }

    // Walk descendants breadth-first. A child is counted only when its
    // marked parent survived visibility, so a hidden intermediate cannot
    // contribute a visible-looking count to the root summary.
    let mut seen: HashSet<String> = root_for.keys().cloned().collect();
    let mut depth = 1u32;
    while !frontier.is_empty() && depth < THREAD_DEPTH_MAX && seen.len() < SUMMARY_TREE_MAX {
        let mut next = Vec::new();
        for chunk in frontier.chunks(crate::filter::MAX_FILTER_MEMBERS) {
            let mut filter = Filter {
                kinds: Some(THREAD_CONTENT_KINDS.to_vec()),
                limit: Some(AUX_LIMIT),
                ..Filter::default()
            };
            filter.tags.insert("#e".to_string(), json!(chunk));
            filter.tags.insert("#h".to_string(), json!([channel]));
            let Some((events, _)) = relay
                .db
                .api_query(vec![filter], AUX_LIMIT, unix_now(), false)
                .await
            else {
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({ "error": "database is overloaded, try again shortly" })),
                )
                    .into_response());
            };
            for event in events {
                if !seen.insert(event.id.clone()) {
                    continue;
                }
                if seen.len() > SUMMARY_TREE_MAX {
                    break;
                }
                if !bridge_visible(
                    &event,
                    authed,
                    Some(&groups),
                    nip78_restricted,
                    relay.relay_pubkey_ref(),
                ) {
                    continue;
                }
                let Some(parent) = reply_parent(&event) else {
                    continue;
                };
                let Some(root) = root_for.get(parent).cloned() else {
                    continue;
                };
                root_for.insert(event.id.clone(), root.clone());
                next.push(event.id.clone());
                if let Some(entry) = per_row.get_mut(&root) {
                    entry.1 += 1;
                    entry.2 = entry.2.max(event.created_at);
                    record_summary_participant(&mut entry.3, event.created_at, &event.pubkey);
                }
            }
        }
        frontier = next;
        depth += 1;
    }
    drop(groups);

    let mut out = Vec::new();
    for row in rows {
        let Some((reply_count, descendants, last_reply_at, participants)) = per_row.get(&row.id)
        else {
            continue;
        };
        let content = json!({
            "reply_count": reply_count,
            "descendant_count": reply_count + descendants,
            "last_reply_at": last_reply_at,
            "participants": participants.iter().map(|(_, pubkey)| pubkey).collect::<Vec<_>>(),
        });
        if let Some(event) = sign_overlay(
            relay,
            THREAD_SUMMARY,
            vec![
                vec!["e".to_string(), row.id.clone()],
                vec!["d".to_string(), row.id.clone()],
                vec!["h".to_string(), channel.to_string()],
            ],
            content.to_string(),
        ) {
            out.push(event);
        }
    }
    Ok(out)
}

/// Keeps the ten most recent distinct participants for a summary. Sorting
/// on every insert is cheap at ten entries and avoids retaining a huge
/// thread's whole author list.
fn record_summary_participant(
    participants: &mut Vec<(u64, String)>,
    created_at: u64,
    pubkey: &str,
) {
    if let Some(existing) = participants
        .iter_mut()
        .find(|(_, existing)| existing.eq_ignore_ascii_case(pubkey))
    {
        existing.0 = existing.0.max(created_at);
    } else {
        participants.push((created_at, pubkey.to_string()));
    }
    participants.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    participants.truncate(10);
}

fn window_bounds(
    relay: &Arc<Relay>,
    channel: &str,
    cursor: Option<&(u64, String)>,
    has_more: bool,
    next_cursor: Option<(u64, String)>,
) -> Option<Event> {
    let suffix = match cursor {
        Some((until, before)) => format!("{until}:{before}"),
        None => "head".to_string(),
    };
    let content = json!({
        "has_more": has_more,
        "next_cursor": next_cursor.map(|(created_at, id)| json!({
            "created_at": created_at,
            "id": id,
        })),
    });
    sign_overlay(
        relay,
        nip29::WINDOW_BOUNDS,
        vec![
            vec!["d".to_string(), format!("{channel}:{suffix}")],
            vec!["h".to_string(), channel.to_string()],
        ],
        content.to_string(),
    )
}

fn sign_overlay(
    relay: &Relay,
    kind: u64,
    tags: Vec<Vec<String>>,
    content: String,
) -> Option<Event> {
    let pubkey = relay.relay_pubkey()?;
    let mut event = Event {
        id: String::new(),
        pubkey,
        created_at: unix_now(),
        kind,
        tags,
        content,
        sig: String::new(),
    };
    relay.sign_relay_event(&mut event).then_some(event)
}

/// NIP-CW thread mode: newest-first descendants of one root, with the
/// request-bound `kind:39007` bounds overlay.
#[allow(clippy::result_large_err)]
async fn thread_mode_window(
    relay: &Arc<Relay>,
    cfg: &crate::config::Config,
    authed: &str,
    host: &str,
    raw: &Value,
) -> Result<Vec<Event>, Response> {
    let channel = channel_id(raw)?;
    let root = raw
        .get("#e")
        .and_then(Value::as_array)
        .filter(|values| values.len() == 1)
        .and_then(|values| values[0].as_str())
        .filter(|id| is_hex_64(id))
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| bad_request("thread_window requires exactly one #e root"))?;
    let Some(raw_kinds) = raw.get("kinds").and_then(Value::as_array) else {
        return Err(bad_request("thread_window requires kinds"));
    };
    let mut kinds = Vec::with_capacity(raw_kinds.len());
    for value in raw_kinds {
        let Some(kind) = value.as_u64() else {
            return Err(bad_request("thread_window kinds must be integers"));
        };
        if !THREAD_CONTENT_KINDS.contains(&kind) {
            return Err(bad_request("thread_window kind is not supported"));
        }
        kinds.push(kind);
    }
    if kinds.is_empty() || kinds.len() > 4 {
        return Err(bad_request("thread_window requires 1 to 4 kinds"));
    }
    kinds.sort_unstable();
    kinds.dedup();
    let limit = raw_limit(raw, 50, 200);
    if limit == 0 {
        return Err(bad_request("thread_window limit must be positive"));
    }
    let depth = match raw.get("depth_limit").and_then(Value::as_u64) {
        None => THREAD_DEPTH_MAX,
        Some(value) if (1..=u64::from(THREAD_DEPTH_MAX)).contains(&value) => value as u32,
        Some(_) => return Err(bad_request("thread_window depth_limit must be 1 to 100")),
    };
    let include_aux = raw.get("include_aux").and_then(Value::as_bool) == Some(true);
    let cursor = parse_cursor(raw)?;
    let visible_filter: Filter = serde_json::from_value(raw.clone())
        .map_err(|e| bad_request(&format!("invalid thread filter: {e}")))?;
    if visible_filter.too_many_members() || visible_filter.invalid_tag_values() {
        return Err(bad_request("invalid thread filter bounds"));
    }

    let groups = relay.groups.read().await;
    if groups.group(&channel).is_none() || !groups.visible_kind(&channel, 9, Some(authed)) {
        return Ok(Vec::new());
    }
    let Some((mut roots, _)) = relay
        .db
        .api_query(
            vec![Filter {
                ids: Some(vec![root.clone()]),
                limit: Some(1),
                ..Filter::default()
            }],
            1,
            unix_now(),
            false,
        )
        .await
    else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "database is overloaded, try again shortly" })),
        )
            .into_response());
    };
    let Some(root_event) = roots.pop() else {
        return Ok(Vec::new());
    };
    if !THREAD_CONTENT_KINDS.contains(&root_event.kind)
        || nip29::group_id(&root_event) != Some(channel.as_str())
        || !bridge_visible(
            &root_event,
            authed,
            Some(&groups),
            cfg.nip_enabled(78) && cfg.relay.enabled_nip78_auth,
            relay.relay_pubkey_ref(),
        )
    {
        return Ok(Vec::new());
    }

    let mut replies = Vec::new();
    let mut seen = HashSet::from([root.clone()]);
    let mut frontier = vec![root.clone()];
    for _ in 0..depth {
        if frontier.is_empty() {
            break;
        }
        let frontier_set: HashSet<&str> = frontier.iter().map(String::as_str).collect();
        let mut next = Vec::new();
        for chunk in frontier.chunks(crate::filter::MAX_FILTER_MEMBERS) {
            let mut filter = Filter {
                kinds: Some(kinds.clone()),
                limit: Some(AUX_LIMIT),
                ..Filter::default()
            };
            filter.tags.insert("#e".to_string(), json!(chunk));
            filter.tags.insert("#h".to_string(), json!([channel]));
            let Some((events, more)) = relay
                .db
                .api_query(vec![filter], AUX_LIMIT, unix_now(), false)
                .await
            else {
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({ "error": "database is overloaded, try again shortly" })),
                )
                    .into_response());
            };
            if more {
                return Err(window_too_large());
            }
            for event in events {
                if !seen.insert(event.id.clone()) {
                    continue;
                }
                if !bridge_visible(
                    &event,
                    authed,
                    Some(&groups),
                    cfg.nip_enabled(78) && cfg.relay.enabled_nip78_auth,
                    relay.relay_pubkey_ref(),
                ) {
                    continue;
                }
                let Some(parent) = reply_parent(&event) else {
                    continue;
                };
                if !frontier_set.contains(parent) {
                    continue;
                }
                next.push(event.id.clone());
                replies.push(event);
                if replies.len() > 8_192 {
                    return Err(window_too_large());
                }
            }
        }
        frontier = next;
    }
    drop(groups);

    let mut candidates: Vec<Event> = replies
        .into_iter()
        .filter(|event| match &cursor {
            Some((until, before)) => cursor_after(event, *until, before),
            None => true,
        })
        .collect();
    sort_desc_id_asc(&mut candidates);
    let has_more = candidates.len() > limit;
    candidates.truncate(limit);
    let next_cursor = if has_more {
        candidates
            .last()
            .map(|event| (event.created_at, event.id.clone()))
    } else {
        None
    };
    let mut out = candidates.clone();
    if include_aux && !candidates.is_empty() {
        let mut targets = vec![root_event.id.clone()];
        targets.extend(candidates.iter().map(|event| event.id.clone()));
        out.extend(fetch_aux(relay, cfg, authed, &visible_filter, &targets).await?);
    }
    let binding = thread_binding(
        host,
        authed,
        &channel,
        &root,
        limit,
        depth,
        &kinds,
        cursor.as_ref(),
        include_aux,
    );
    let content = json!({
        "version": 1,
        "direction": "older",
        "has_more": has_more,
        "next_cursor": next_cursor.as_ref().map(|(created_at, id)| json!({
            "created_at": created_at,
            "id": id,
        })),
    });
    if let Some(bounds) = sign_overlay(
        relay,
        nip29::THREAD_WINDOW_BOUNDS,
        vec![
            vec!["d".to_string(), format!("tw:1:{binding}")],
            vec!["h".to_string(), channel.clone()],
            vec!["e".to_string(), root],
        ],
        content.to_string(),
    ) {
        out.push(bounds);
    }
    // NIP-CW requires the whole thread-mode batch to be access-checked
    // again before it is released. A visibility change during the BFS must
    // not return rows or a signed bounds event.
    let still_visible = {
        let groups = relay.groups.read().await;
        groups.group(&channel).is_some() && groups.visible_kind(&channel, 9, Some(authed))
    };
    if !still_visible {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "group access changed; retry the query" })),
        )
            .into_response());
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn thread_binding(
    host: &str,
    reader: &str,
    channel: &str,
    root: &str,
    limit: usize,
    depth: u32,
    kinds: &[u64],
    cursor: Option<&(u64, String)>,
    include_aux: bool,
) -> String {
    let cursor = cursor.map(|(created_at, id)| json!([created_at, id]));
    let value = json!([
        "tw",
        1,
        "older",
        host,
        reader,
        channel,
        root,
        limit,
        depth,
        kinds,
        cursor,
        include_aux,
    ]);
    let bytes = serde_json::to_vec(&value).expect("thread binding is serializable");
    hex::encode(Sha256::digest(bytes))
}

/// Legacy thread subtree path: `#e` root plus `depth_limit`.
#[allow(clippy::result_large_err)]
async fn thread_window(
    relay: &Arc<Relay>,
    cfg: &crate::config::Config,
    authed: &str,
    raw: &Value,
) -> Result<Vec<Event>, Response> {
    let Some(root) = raw
        .get("#e")
        .and_then(Value::as_array)
        .filter(|values| values.len() == 1)
        .and_then(|values| values[0].as_str())
        .filter(|id| is_hex_64(id))
    else {
        return Err(bad_request("thread requires exactly one #e root"));
    };
    let channel = raw
        .get("#h")
        .and_then(Value::as_array)
        .filter(|values| values.len() == 1)
        .and_then(|values| values[0].as_str())
        .filter(|id| !id.is_empty());
    if let Some(channel) = channel {
        let groups = relay.groups.read().await;
        let Some(_group) = groups.groups.get(channel) else {
            return Ok(Vec::new());
        };
        if !groups.visible_kind(channel, 9, Some(authed)) {
            return Ok(Vec::new());
        }
    }

    // The raw filter's own channel constraints decide whether a system
    // channel's state is visible on this path too. Without this a thread
    // query that names only an `#e` root could materialize replies from a
    // system channel it never named, bypassing the NIP-CL exclusion applied
    // to the ordinary and channel-window paths.
    let visible_filter: Filter = serde_json::from_value(raw.clone())
        .map_err(|e| bad_request(&format!("invalid thread filter: {e}")))?;
    if visible_filter.too_many_members() || visible_filter.invalid_tag_values() {
        return Err(bad_request("invalid thread filter bounds"));
    }
    let depth_limit = raw
        .get("depth_limit")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or(THREAD_DEPTH_DEFAULT)
        .min(THREAD_DEPTH_MAX);
    let limit = raw_limit(raw, THREAD_DEFAULT_LIMIT, THREAD_MAX_LIMIT);
    if limit == 0 {
        return Ok(Vec::new());
    }
    let include_aux = raw.get("include_aux").and_then(Value::as_bool) == Some(true);
    let cursor = thread_cursor(raw);

    let mut seen = HashSet::new();
    seen.insert(root.to_string());
    let mut frontier = vec![root.to_string()];
    let mut replies = Vec::new();
    let nip78_restricted = cfg.nip_enabled(78) && cfg.relay.enabled_nip78_auth;
    for _ in 0..depth_limit {
        if frontier.is_empty() {
            break;
        }
        let mut next = Vec::new();
        for chunk in frontier.chunks(crate::filter::MAX_FILTER_MEMBERS) {
            let mut filter = Filter {
                kinds: raw
                    .get("kinds")
                    .and_then(|value| serde_json::from_value(value.clone()).ok()),
                limit: Some(AUX_LIMIT),
                ..Filter::default()
            };
            filter.tags.insert("#e".to_string(), json!(chunk));
            if let Some(channel) = channel {
                filter.tags.insert("#h".to_string(), json!([channel]));
            }
            let Some((events, more)) = relay
                .db
                .api_query(vec![filter], AUX_LIMIT, unix_now(), false)
                .await
            else {
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({ "error": "database is overloaded, try again shortly" })),
                )
                    .into_response());
            };
            if more {
                // The legacy thread path has no signed bounds/cursor for
                // the DB frontier. Silently truncating at the newest
                // AUX_LIMIT direct replies would lose older replies (and
                // their descendants); fail explicitly instead.
                return Err(window_too_large());
            }
            let groups = relay.groups.read().await;
            for event in events {
                if !seen.insert(event.id.clone()) {
                    continue;
                }
                if !bridge_visible(
                    &event,
                    authed,
                    Some(&groups),
                    nip78_restricted,
                    relay.relay_pubkey_ref(),
                ) || !nip_cl_visible(&visible_filter, &event, &groups)
                {
                    continue;
                }
                next.push(event.id.clone());
                replies.push(event);
            }
            drop(groups);
        }
        frontier = next;
        if replies.len() > THREAD_MAX_LIMIT.saturating_mul(4) {
            // Bound the subtree walk: the client can page from the returned
            // cursor instead of making one request materialize a huge tree.
            break;
        }
    }
    sort_asc_id_asc(&mut replies);

    if let Some((created_at, id)) = cursor {
        replies.retain(|event| {
            event.created_at > created_at
                || (event.created_at == created_at && event.id.as_str() > id.as_str())
        });
    }
    replies.truncate(limit);

    let mut out = replies.clone();
    if include_aux && !replies.is_empty() {
        let ids: Vec<String> = replies.iter().map(|event| event.id.clone()).collect();
        out.extend(fetch_aux(relay, cfg, authed, &visible_filter, &ids).await?);
    }
    Ok(out)
}

fn thread_cursor(raw: &Value) -> Option<(u64, String)> {
    let created_at = raw.get("thread_cursor").and_then(Value::as_i64)?;
    if created_at < 0 {
        return None;
    }
    let id = raw.get("thread_cursor_id")?.as_str()?.to_ascii_lowercase();
    if !is_hex_64(&id) {
        return None;
    }
    Some((created_at as u64, id))
}
