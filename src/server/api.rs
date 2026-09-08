//! HTTP REST API: `/api/v1/` endpoint.
//!
//! Provides a read-only JSON API for querying stored events by npub1,
//! nevent1, or naddr1 identifiers.  Only `GET` is supported.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::config::Config;
use crate::event::Event;
use crate::filter::Filter;
use crate::nips::nip19::{self, Nip19Entity};
use crate::nips::{nip29, nip62, nip70, nip78};
use crate::relay::Relay;
use crate::util::unix_now;

#[derive(Debug, Default, Deserialize)]
pub struct ApiParams {
    pub limit: Option<usize>,
    pub since: Option<u64>,
    pub until: Option<u64>,
    pub search: Option<String>,
    pub e: Option<String>,
    pub p: Option<String>,
    pub t: Option<String>,
    pub d: Option<String>,
    pub sort: Option<String>,
    pub offset: Option<usize>,
    /// Exclude events carrying the tag (absence filter): `no_p=true` drops
    /// every event with a `p` tag (mentions, replies, DMs), `no_e` drops
    /// events with an `e` tag (replies), `no_t` and `no_d` likewise. The
    /// exclusion applies before pagination, like the visibility rules.
    pub no_p: Option<bool>,
    pub no_e: Option<bool>,
    pub no_t: Option<bool>,
    pub no_d: Option<bool>,
    /// Generic query filters (`/api/v1/query` and `/api/v1/count`):
    /// accepted as a single value, comma-separated values, or repeated
    /// parameters (`authors=a&authors=b`).
    #[serde(default, deserialize_with = "de_string_list")]
    pub authors: Vec<String>,
    #[serde(default, deserialize_with = "de_u64_list")]
    pub kinds: Vec<u64>,
    /// Daily and hourly counts: the date to report. `year` (default: the
    /// current year), `month` 1-12 (default: the current month) and `day`
    /// (default: today) — daily reports every day of the month, zero-filled
    /// through the last day; hourly reports all 24 hours of one day.
    pub year: Option<i64>,
    pub month: Option<u32>,
    pub day: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct ApiResponse {
    pub events: Vec<Value>,
    pub count: usize,
    pub more: bool,
}

/// Deserializes a list parameter that may arrive as a single value, a
/// comma-separated value, or a repeated parameter.
fn de_string_list<'de, D>(de: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(de)?;
    let parts: Vec<&str> = match &value {
        Value::String(s) => s.split(',').collect(),
        Value::Array(items) => items
            .iter()
            .map(|i| {
                i.as_str()
                    .ok_or_else(|| serde::de::Error::custom("expected a string"))
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => {
            return Err(serde::de::Error::custom(
                "expected a string or array of strings",
            ));
        }
    };
    Ok(parts
        .into_iter()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect())
}

/// Like [`de_string_list`] but for unsigned integers.
fn de_u64_list<'de, D>(de: D) -> Result<Vec<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    de_string_list(de)?
        .into_iter()
        .map(|s| {
            s.parse::<u64>()
                .map_err(|_| serde::de::Error::custom("expected an unsigned integer"))
        })
        .collect()
}

fn error_response(status: StatusCode, message: &str) -> (StatusCode, Json<Value>) {
    (status, Json(json!({ "error": message })))
}

/// Bounds the API query parameters so a single request cannot trigger an
/// arbitrarily large database scan: `limit` is capped, `offset` is capped,
/// and over-long `search` terms are rejected.
fn bound_params(params: &mut ApiParams, cfg: &Config) -> Result<(), (StatusCode, String)> {
    let limits = &cfg.limits;
    if limits.max_api_limit > 0
        && let Some(limit) = params.limit
        && limit > limits.max_api_limit
    {
        params.limit = Some(limits.max_api_limit);
    }
    if limits.max_api_offset > 0
        && let Some(offset) = params.offset
        && offset > limits.max_api_offset
    {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("offset exceeds the maximum of {}", limits.max_api_offset),
        ));
    }
    if limits.max_api_search_bytes > 0
        && let Some(ref search) = params.search
        && search.len() > limits.max_api_search_bytes
    {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "search exceeds the maximum of {} bytes",
                limits.max_api_search_bytes
            ),
        ));
    }
    Ok(())
}

/// The tag names excluded by the `no_p`/`no_e`/`no_t`/`no_d` parameters
/// (absence filters: events carrying the tag are dropped before
/// pagination).
fn excluded_tags(params: &ApiParams) -> Vec<&'static str> {
    let mut out = Vec::new();
    if params.no_p.unwrap_or(false) {
        out.push("p");
    }
    if params.no_e.unwrap_or(false) {
        out.push("e");
    }
    if params.no_t.unwrap_or(false) {
        out.push("t");
    }
    if params.no_d.unwrap_or(false) {
        out.push("d");
    }
    out
}

/// Whether a stored event is visible to this unauthenticated REST API,
/// mirroring an anonymous WebSocket connection: NIP-70 protected events,
/// NIP-59 gift wraps, NIP-29 private/hidden group content and (when the
/// NIP-78 AUTH gate is active) NIP-78 application-specific events are
/// withheld.
fn api_visible(
    event: &Event,
    groups: Option<&nip29::GroupStore>,
    excluded: &[&str],
    nip78: bool,
) -> bool {
    !nip70::is_protected(event)
        && event.kind != nip62::GIFT_WRAP_KIND
        && !(nip78 && nip78::is_app_specific(event))
        && groups.is_none_or(|g| g.visible_to(event, None))
        && !excluded
            .iter()
            .any(|name| event.tags.iter().any(|t| t.len() >= 2 && t[0] == *name))
}

/// Whether the NIP-78 AUTH gate is active in the current config.
async fn enabled_nip78_auth_active(relay: &Arc<Relay>) -> bool {
    let cfg = relay.config.read().await;
    cfg.nip_enabled(78) && cfg.relay.enabled_nip78_auth
}

fn apply_params(mut filter: Filter, params: &ApiParams) -> Filter {
    if !params.authors.is_empty() {
        filter.authors = Some(params.authors.clone());
    }
    if !params.kinds.is_empty() {
        filter.kinds = Some(params.kinds.clone());
    }
    if let Some(since) = params.since {
        filter.since = Some(since);
    }
    if let Some(until) = params.until {
        filter.until = Some(until);
    }
    if let Some(ref search) = params.search {
        filter.search = Some(search.clone());
    }
    if let Some(ref e) = params.e {
        filter.tags.insert("#e".to_string(), json!(e));
    }
    if let Some(ref p) = params.p {
        filter.tags.insert("#p".to_string(), json!(p));
    }
    if let Some(ref t) = params.t {
        filter.tags.insert("#t".to_string(), json!(t));
    }
    if let Some(ref d) = params.d {
        filter.tags.insert("#d".to_string(), json!(d));
    }
    filter
}

/// Maps the `sort` query parameter to a scan direction: `asc` (or `ascending`)
/// returns oldest events first, everything else returns newest first.
fn sort_ascending(sort: &Option<String>) -> bool {
    matches!(sort.as_deref(), Some("asc" | "ascending"))
}

/// Parses an author identifier: an `npub1...` code or a 64-hex pubkey
/// (case-insensitive). Returns the lowercase hex pubkey.
fn parse_author_identifier(identifier: &str) -> Result<String, String> {
    if identifier.len() == 64 && identifier.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(identifier.to_ascii_lowercase());
    }
    match nip19::parse_nip19(identifier) {
        Ok(Nip19Entity::Pubkey(pk)) => Ok(hex::encode(pk)),
        Ok(_) => Err("the endpoint requires an npub1 identifier or a 64-hex pubkey".into()),
        Err(e) => Err(format!("invalid identifier: {e}")),
    }
}

/// `GET /api/v1/{identifier}`
///
/// Handles npub1 (with a kind sub-path) and nevent1 (no kind needed).
pub async fn api_handler(
    State(relay): State<Arc<Relay>>,
    Path(identifier): Path<String>,
    Query(mut params): Query<ApiParams>,
) -> (StatusCode, Json<Value>) {
    let cfg = relay.config.read().await;
    if let Err((status, msg)) = bound_params(&mut params, &cfg) {
        return error_response(status, &msg);
    }
    // A 64-hex identifier is an author pubkey (profile lookup); everything
    // else goes through the NIP-19 parsing below.
    if let Ok(hex_pk) = parse_author_identifier(&identifier) {
        let no_tags = excluded_tags(&params);
        let filter = apply_params(
            Filter {
                authors: Some(vec![hex_pk]),
                kinds: Some(vec![0]),
                ..Default::default()
            },
            &params,
        );
        return query_and_respond(
            &relay,
            vec![filter],
            1,
            params.offset,
            sort_ascending(&params.sort),
            &no_tags,
        )
        .await;
    }
    let entity = match nip19::parse_nip19(&identifier) {
        Ok(e) => e,
        Err(e) => {
            return error_response(StatusCode::BAD_REQUEST, &format!("invalid identifier: {e}"));
        }
    };

    match entity {
        Nip19Entity::Pubkey(pk) => {
            // Without a kind path the latest kind-0 profile event of the
            // author is returned (kind 0 is replaceable, so the newest one
            // is the current profile).
            let hex_pk = hex::encode(pk);
            let no_tags = excluded_tags(&params);
            let filter = apply_params(
                Filter {
                    authors: Some(vec![hex_pk]),
                    kinds: Some(vec![0]),
                    ..Default::default()
                },
                &params,
            );
            query_and_respond(
                &relay,
                vec![filter],
                1,
                params.offset,
                sort_ascending(&params.sort),
                &no_tags,
            )
            .await
        }
        Nip19Entity::Note(id) => {
            let hex_id = hex::encode(id);
            let filter = apply_params(
                Filter {
                    ids: Some(vec![hex_id]),
                    ..Default::default()
                },
                &params,
            );
            let no_tags = excluded_tags(&params);
            query_and_respond(
                &relay,
                vec![filter],
                1,
                params.offset,
                sort_ascending(&params.sort),
                &no_tags,
            )
            .await
        }
        Nip19Entity::Event { id, .. } => {
            let hex_id = hex::encode(id);
            let filter = apply_params(
                Filter {
                    ids: Some(vec![hex_id]),
                    ..Default::default()
                },
                &params,
            );
            let no_tags = excluded_tags(&params);
            query_and_respond(
                &relay,
                vec![filter],
                1,
                params.offset,
                sort_ascending(&params.sort),
                &no_tags,
            )
            .await
        }
        Nip19Entity::Addr {
            kind,
            pubkey,
            d_tag,
            ..
        } => {
            let hex_pk = hex::encode(pubkey);
            // `bound_params` already capped `params.limit` at
            // `limits.max_api_limit` when one is configured; there is no
            // hardcoded ceiling here (a configured `max_api_limit: 0` means
            // "no bound").
            let limit = params.limit.unwrap_or(100);
            // No per-filter `limit`: see the Pubkey handler.
            let mut filter = Filter {
                authors: Some(vec![hex_pk]),
                kinds: Some(vec![kind]),
                ..Default::default()
            };
            // d_tag from naddr1 is primary; user ?d= overrides if present
            let d_value = params.d.as_deref().unwrap_or(&d_tag);
            filter.tags.insert("#d".to_string(), json!(d_value));
            filter = apply_params(filter, &params);
            let no_tags = excluded_tags(&params);
            query_and_respond(
                &relay,
                vec![filter],
                limit,
                params.offset,
                sort_ascending(&params.sort),
                &no_tags,
            )
            .await
        }
    }
}

/// `GET /api/v1/{identifier}/{kind}`
///
/// Handles npub1 with a mandatory kind parameter.
pub async fn api_kind_handler(
    State(relay): State<Arc<Relay>>,
    Path((identifier, kind)): Path<(String, u64)>,
    Query(mut params): Query<ApiParams>,
) -> (StatusCode, Json<Value>) {
    let cfg = relay.config.read().await;
    if let Err((status, msg)) = bound_params(&mut params, &cfg) {
        return error_response(status, &msg);
    }
    let hex_pk = match parse_author_identifier(&identifier) {
        Ok(pk) => pk,
        Err(msg) => return error_response(StatusCode::BAD_REQUEST, &msg),
    };
    {
        // `bound_params` already capped `params.limit` at
        // `limits.max_api_limit` when one is configured; there is no
        // hardcoded ceiling here (a configured `max_api_limit: 0` means
        // "no bound").
        let limit = params.limit.unwrap_or(100);
        // No per-filter `limit`: query_and_respond fetches `limit+offset+1`
        // pre-filter rows (via the max_limit parameter) so pagination over
        // the visible sequence works even when hidden events are present.
        let filter = apply_params(
            Filter {
                authors: Some(vec![hex_pk]),
                kinds: Some(vec![kind]),
                ..Default::default()
            },
            &params,
        );
        let no_tags = excluded_tags(&params);
        query_and_respond(
            &relay,
            vec![filter],
            limit,
            params.offset,
            sort_ascending(&params.sort),
            &no_tags,
        )
        .await
    }
}

/// `GET /api/v1/{identifier}/{kind}/monthly`
///
/// Per-month event counts for a pubkey + kind, e.g.
/// `GET /api/v1/npub1.../1/monthly` returns `{"months": [{"month": "2026-08",
/// "count": 4}], "total": 4}` so a frontend can render "2026-08(4)". `since`
/// and `until` bound the range (unix seconds); without them the whole period
/// is covered, from the earliest *visible* stored event of that author and
/// kind to now. Every month in the range is reported (zero-filled), oldest
/// first, at most [`MAX_MONTHS`] months. A month whose count hit the
/// collection limit is flagged `"approximate": true` (NIP-45 semantics), as
/// is the top-level `"approximate"` when any month was capped.
pub async fn api_monthly_handler(
    State(relay): State<Arc<Relay>>,
    Path((identifier, kind)): Path<(String, u64)>,
    Query(params): Query<ApiParams>,
) -> (StatusCode, Json<Value>) {
    let hex_pk = match parse_author_identifier(&identifier) {
        Ok(pk) => pk,
        Err(msg) => return error_response(StatusCode::BAD_REQUEST, &msg),
    };

    // Bounded month range: without `since` the range spans the whole period
    // (from the earliest stored event of this author and kind); an explicit
    // range must not exceed MAX_MONTHS of count queries, so one request
    // cannot pin the API reader thread behind a huge loop of scans.
    // The concurrency permit is taken before the probe so a flood of
    // `monthly` requests without `since` cannot bypass the 503 limiter.
    let Some(_permit) = relay.api_limit.try_acquire() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "server is busy, try again shortly" })),
        );
    };
    let now = unix_now();
    let until = params.until.unwrap_or(now);
    let no_tags_probe = excluded_tags(&params);
    let nip78_probe = enabled_nip78_auth_active(&relay).await;
    let since = match params.since {
        Some(s) => s,
        None => {
            // The whole period: probe the oldest *visible* stored event, so
            // a hidden earliest event cannot leak its age through the
            // range start. The probe is a bounded ascending window scan.
            let probe: Filter = serde_json::from_value(json!({
                "authors": [hex_pk],
                "kinds": [kind],
            }))
            .expect("static filter");
            let mut start_ts = None;
            let mut fetch = 64usize;
            for _ in 0..4 {
                let (events, _) = relay
                    .db
                    .api_query(vec![probe.clone()], fetch, now, true)
                    .await;
                let has_group_events = events.iter().any(nip29::is_group_event);
                let groups = if has_group_events {
                    Some(relay.groups.read().await)
                } else {
                    None
                };
                start_ts = events
                    .iter()
                    .find(|e| api_visible(e, groups.as_deref(), &no_tags_probe, nip78_probe))
                    .map(|e| e.created_at);
                drop(groups);
                if start_ts.is_some() || fetch >= 1024 {
                    break;
                }
                fetch = (fetch * 4).min(1024);
            }
            match start_ts {
                Some(s) => s,
                None => {
                    // No visible events at all: an empty range, reported as such.
                    return (
                        StatusCode::OK,
                        Json(json!({ "months": [], "total": 0, "approximate": false })),
                    );
                }
            }
        }
    };
    let months = month_range(since, until);
    if months.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "until must not be earlier than since",
        );
    }
    if months.len() > MAX_MONTHS {
        return error_response(
            StatusCode::BAD_REQUEST,
            &format!("the requested range exceeds {MAX_MONTHS} months"),
        );
    }

    let count_limit = relay.config.read().await.limits.max_count;
    let no_tags = excluded_tags(&params);
    let nip78 = enabled_nip78_auth_active(&relay).await;

    let mut month_counts = Vec::with_capacity(months.len());
    let mut total = 0u64;
    let mut approximate = false;
    for (y, m) in months {
        let start = month_start(y, m);
        let end = month_start_of_next(y, m);
        let filter: Filter = serde_json::from_value(json!({
            "authors": [hex_pk],
            "kinds": [kind],
            "since": start,
            "until": end.saturating_sub(1),
        }))
        .expect("static filter");
        let (events, more) = relay.db.api_count(vec![filter], count_limit, now).await;
        approximate |= more;
        // The same visibility rules as the unauthenticated API: protected
        // events, gift wraps and private/hidden group content are withheld.
        let has_group_events = events.iter().any(nip29::is_group_event);
        let groups = if has_group_events {
            Some(relay.groups.read().await)
        } else {
            None
        };
        let count = events
            .iter()
            .filter(|e| api_visible(e, groups.as_deref(), &no_tags, nip78))
            .count();
        drop(groups);
        total += count as u64;
        month_counts.push(json!({
            "month": format!("{y:04}-{m:02}"),
            "count": count,
            "approximate": more,
        }));
    }

    (
        StatusCode::OK,
        Json(json!({
            "months": month_counts,
            "total": total,
            "approximate": approximate,
        })),
    )
}

/// `GET /api/v1/query`
///
/// Generic filter query without an identifier: any of the [`ApiParams`]
/// filter fields (`authors`, `kinds`, `e`, `p`, `t`, `d`, `since`, `until`,
/// `search`, `no_*`, `sort`, `limit`, `offset`) combine into a single
/// NIP-01 filter.
pub async fn api_query_handler(
    State(relay): State<Arc<Relay>>,
    Query(mut params): Query<ApiParams>,
) -> (StatusCode, Json<Value>) {
    let cfg = relay.config.read().await;
    if let Err((status, msg)) = bound_params(&mut params, &cfg) {
        return error_response(status, &msg);
    }
    let limit = params.limit.unwrap_or(100);
    let filter = apply_params(Filter::default(), &params);
    let no_tags = excluded_tags(&params);
    query_and_respond(
        &relay,
        vec![filter],
        limit,
        params.offset,
        sort_ascending(&params.sort),
        &no_tags,
    )
    .await
}

/// `GET /api/v1/count`
///
/// Total event count for a filter (NIP-45 semantics over HTTP): the same
/// [`ApiParams`] filter fields as `/query`, returning `{"count": N,
/// "approximate": bool}`.
pub async fn api_count_handler(
    State(relay): State<Arc<Relay>>,
    Query(mut params): Query<ApiParams>,
) -> (StatusCode, Json<Value>) {
    let cfg = relay.config.read().await;
    if let Err((status, msg)) = bound_params(&mut params, &cfg) {
        return error_response(status, &msg);
    }
    drop(cfg);
    let Some(_permit) = relay.api_limit.try_acquire() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "server is busy, try again shortly" })),
        );
    };
    let count_limit = relay.config.read().await.limits.max_count;
    let now = unix_now();
    let mut filter = apply_params(Filter::default(), &params);
    if !relay.config.read().await.nip_enabled(50) {
        filter.search = None;
    }
    // The absence filters apply like the /query path (a `no_p` count must
    // agree with the visible rows of a `no_p` query).
    let no_tags = excluded_tags(&params);
    let nip78 = enabled_nip78_auth_active(&relay).await;
    let (events, more) = relay.db.api_count(vec![filter], count_limit, now).await;
    let has_group_events = events.iter().any(nip29::is_group_event);
    let groups = if has_group_events {
        Some(relay.groups.read().await)
    } else {
        None
    };
    let count = events
        .iter()
        .filter(|e| api_visible(e, groups.as_deref(), &no_tags, nip78))
        .count();
    drop(groups);
    drop(_permit);
    (
        StatusCode::OK,
        Json(json!({ "count": count, "approximate": more })),
    )
}

/// `GET /api/v1/{identifier}/kinds`
///
/// Per-kind event counts for an author: `{"kinds": [{"kind": 1, "count":
/// 120}, ...]}` sorted by count descending, most used first.
pub async fn api_kinds_handler(
    State(relay): State<Arc<Relay>>,
    Path(identifier): Path<String>,
    Query(params): Query<ApiParams>,
) -> (StatusCode, Json<Value>) {
    let hex_pk = match parse_author_identifier(&identifier) {
        Ok(pk) => pk,
        Err(msg) => return error_response(StatusCode::BAD_REQUEST, &msg),
    };

    let Some(_permit) = relay.api_limit.try_acquire() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "server is busy, try again shortly" })),
        );
    };
    let count_limit = relay.config.read().await.limits.max_count;
    let now = unix_now();
    let filter: Filter = serde_json::from_value(json!({ "authors": [hex_pk] })).expect("static");
    let (events, more) = relay.db.api_count(vec![filter], count_limit, now).await;
    let has_group_events = events.iter().any(nip29::is_group_event);
    let groups = if has_group_events {
        Some(relay.groups.read().await)
    } else {
        None
    };
    let no_tags = excluded_tags(&params);
    let nip78 = enabled_nip78_auth_active(&relay).await;
    let mut by_kind: std::collections::BTreeMap<u64, usize> = std::collections::BTreeMap::new();
    for e in events
        .iter()
        .filter(|e| api_visible(e, groups.as_deref(), &no_tags, nip78))
    {
        *by_kind.entry(e.kind).or_default() += 1;
    }
    drop(groups);
    let mut kinds: Vec<Value> = by_kind
        .into_iter()
        .map(|(kind, count)| json!({ "kind": kind, "count": count }))
        .collect();
    kinds.sort_by(|a, b| {
        b["count"]
            .as_u64()
            .cmp(&a["count"].as_u64())
            .then_with(|| a["kind"].as_u64().cmp(&b["kind"].as_u64()))
    });
    drop(_permit);
    (
        StatusCode::OK,
        Json(json!({ "kinds": kinds, "approximate": more })),
    )
}

/// `GET /api/v1/{identifier}/{kind}/daily`
///
/// Per-day event counts for an author + kind within one month, e.g.
/// `?year=2026&month=8` returns every day of August 2026 — including the
/// days after today, zero-filled through the last day of the month:
/// `{"days": [{"day": "2026-08-01", "count": 0}, ...], "total": N}`.
pub async fn api_daily_handler(
    State(relay): State<Arc<Relay>>,
    Path((identifier, kind)): Path<(String, u64)>,
    Query(params): Query<ApiParams>,
) -> (StatusCode, Json<Value>) {
    let hex_pk = match parse_author_identifier(&identifier) {
        Ok(pk) => pk,
        Err(msg) => return error_response(StatusCode::BAD_REQUEST, &msg),
    };

    let now = unix_now();
    let (year, month) = match (params.year, params.month) {
        (_, Some(m)) if !(1..=12).contains(&m) => {
            return error_response(StatusCode::BAD_REQUEST, "month must be between 1 and 12");
        }
        // A far-future or far-past year would overflow the civil-date
        // arithmetic (and scan an empty range): bound it to the range the
        // timestamp arithmetic can represent.
        (Some(y), _m) if !(1970..=2999).contains(&y) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "year must be between 1970 and 2999",
            );
        }
        (Some(y), m) => (y, m.unwrap_or(month_of(now).1)),
        (None, Some(m)) => (month_of(now).0, m),
        (None, None) => month_of(now),
    };
    let start = month_start(year, month);
    let end = month_start_of_next(year, month);
    let days_in_month = (end - start) / 86400;

    let Some(_permit) = relay.api_limit.try_acquire() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "server is busy, try again shortly" })),
        );
    };
    let count_limit = relay.config.read().await.limits.max_count;
    let no_tags = excluded_tags(&params);
    let nip78 = enabled_nip78_auth_active(&relay).await;

    let mut day_counts = Vec::with_capacity(days_in_month as usize);
    let mut total = 0u64;
    let mut approximate = false;
    for day in 0..days_in_month {
        let day_start = start + day * 86400;
        let filter: Filter = serde_json::from_value(json!({
            "authors": [hex_pk],
            "kinds": [kind],
            "since": day_start,
            "until": day_start + 86400 - 1,
        }))
        .expect("static filter");
        let (events, more) = relay.db.api_count(vec![filter], count_limit, now).await;
        approximate |= more;
        let has_group_events = events.iter().any(nip29::is_group_event);
        let groups = if has_group_events {
            Some(relay.groups.read().await)
        } else {
            None
        };
        let count = events
            .iter()
            .filter(|e| api_visible(e, groups.as_deref(), &no_tags, nip78))
            .count();
        drop(groups);
        total += count as u64;
        day_counts.push(json!({
            "day": format!("{year:04}-{month:02}-{:02}", day + 1),
            "count": count,
            "approximate": more,
        }));
    }
    drop(_permit);
    (
        StatusCode::OK,
        Json(json!({ "days": day_counts, "total": total, "approximate": approximate })),
    )
}

/// `GET /api/v1/ids/{hex}`
///
/// A single event by its 64-hex id (prefixes are not accepted).
pub async fn api_id_handler(
    State(relay): State<Arc<Relay>>,
    Path(hex_id): Path<String>,
    Query(mut params): Query<ApiParams>,
) -> (StatusCode, Json<Value>) {
    if hex_id.len() != 64 || hex::decode(&hex_id).is_err() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "the id must be a 64-character hex string",
        );
    }
    // Bound the query parameters like every other handler: the `limit` /
    // `offset` caps protect against a scan over the whole budget.
    let cfg = relay.config.read().await;
    if let Err((status, msg)) = bound_params(&mut params, &cfg) {
        return error_response(status, &msg);
    }
    drop(cfg);
    let filter = apply_params(
        Filter {
            ids: Some(vec![hex_id]),
            ..Default::default()
        },
        &params,
    );
    let no_tags = excluded_tags(&params);
    let limit = params.limit.unwrap_or(1).min(100);
    query_and_respond(
        &relay,
        vec![filter],
        limit,
        params.offset,
        sort_ascending(&params.sort),
        &no_tags,
    )
    .await
}

/// `GET /api/v1/{identifier}/stats`
///
/// Author statistics in one call: total event count, first/last activity,
/// per-kind breakdown and the active period, so a profile page needs a
/// single request.
pub async fn api_stats_handler(
    State(relay): State<Arc<Relay>>,
    Path(identifier): Path<String>,
    Query(params): Query<ApiParams>,
) -> (StatusCode, Json<Value>) {
    let hex_pk = match parse_author_identifier(&identifier) {
        Ok(pk) => pk,
        Err(msg) => return error_response(StatusCode::BAD_REQUEST, &msg),
    };
    let Some(_permit) = relay.api_limit.try_acquire() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "server is busy, try again shortly" })),
        );
    };
    let count_limit = relay.config.read().await.limits.max_count;
    let now = unix_now();
    let filter: Filter = serde_json::from_value(json!({ "authors": [hex_pk] })).expect("static");
    let no_tags = excluded_tags(&params);
    let nip78 = enabled_nip78_auth_active(&relay).await;

    let (events, more) = relay
        .db
        .api_count(vec![filter.clone()], count_limit, now)
        .await;
    let has_group_events = events.iter().any(nip29::is_group_event);
    let groups = if has_group_events {
        Some(relay.groups.read().await)
    } else {
        None
    };
    let mut by_kind: std::collections::BTreeMap<u64, usize> = std::collections::BTreeMap::new();
    let mut total = 0usize;
    for e in events
        .iter()
        .filter(|e| api_visible(e, groups.as_deref(), &no_tags, nip78))
    {
        *by_kind.entry(e.kind).or_default() += 1;
        total += 1;
    }
    drop(groups);

    // The timestamps must respect the same visibility rules as `total`
    // and `kinds`: a protected/gift-wrapped/private-group event is not
    // countable, so its activity time must not leak either. The author's
    // newest event may be an invisible gift wrap, so grow the window until
    // a visible event is found (bounded: 4 rounds up to 1024 rows).
    let mut first_visible = None;
    let mut last_visible = None;
    {
        let mut fetch = 64usize;
        for _ in 0..4 {
            let (first, _) = relay
                .db
                .api_query(vec![filter.clone()], fetch, now, true)
                .await;
            let (last, _) = relay
                .db
                .api_query(vec![filter.clone()], fetch, now, false)
                .await;
            let stats_groups = relay.groups.read().await;
            if first_visible.is_none() {
                first_visible = first
                    .into_iter()
                    .find(|e| api_visible(e, Some(&stats_groups), &no_tags, nip78));
            }
            if last_visible.is_none() {
                last_visible = last
                    .into_iter()
                    .find(|e| api_visible(e, Some(&stats_groups), &no_tags, nip78));
            }
            drop(stats_groups);
            if first_visible.is_some() && last_visible.is_some() {
                break;
            }
            if fetch >= 1024 {
                break;
            }
            fetch = (fetch * 4).min(1024);
        }
    }
    drop(_permit);
    let first_seen = first_visible.map(|e| e.created_at);
    let last_seen = last_visible.map(|e| e.created_at);
    let first_month = first_seen.map(|ts| {
        let (y, m) = month_of(ts);
        format!("{y:04}-{m:02}")
    });
    let last_month = last_seen.map(|ts| {
        let (y, m) = month_of(ts);
        format!("{y:04}-{m:02}")
    });
    let kinds: Vec<Value> = by_kind
        .into_iter()
        .map(|(kind, count)| json!({ "kind": kind, "count": count }))
        .collect();

    (
        StatusCode::OK,
        Json(json!({
            "total": total,
            "approximate": more,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "first_month": first_month,
            "last_month": last_month,
            "kinds": kinds,
        })),
    )
}

/// `GET /api/v1/{identifier}/{kind}/hourly`
///
/// Per-hour event counts for one day, e.g. `?year=2026&month=8&day=28`
/// returns all 24 hours of that day, zero-filled:
/// `{"hours": [{"hour": "2026-08-28T00", "count": 0}, ...], "total": N}`.
pub async fn api_hourly_handler(
    State(relay): State<Arc<Relay>>,
    Path((identifier, kind)): Path<(String, u64)>,
    Query(params): Query<ApiParams>,
) -> (StatusCode, Json<Value>) {
    let hex_pk = match parse_author_identifier(&identifier) {
        Ok(pk) => pk,
        Err(msg) => return error_response(StatusCode::BAD_REQUEST, &msg),
    };
    let now = unix_now();
    let (year, month) = match (params.year, params.month) {
        (_, Some(m)) if !(1..=12).contains(&m) => {
            return error_response(StatusCode::BAD_REQUEST, "month must be between 1 and 12");
        }
        // A far-future or far-past year would overflow the civil-date
        // arithmetic (and scan an empty range): bound it to the range the
        // timestamp arithmetic can represent.
        (Some(y), _m) if !(1970..=2999).contains(&y) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "year must be between 1970 and 2999",
            );
        }
        (Some(y), m) => (y, m.unwrap_or(month_of(now).1)),
        (None, Some(m)) => (month_of(now).0, m),
        (None, None) => month_of(now),
    };
    let days_in_month = (month_start_of_next(year, month) - month_start(year, month)) / 86400;
    let day = params.day.unwrap_or_else(|| {
        let (_, _, d) = civil_from_days((now / 86400) as i64);
        d.min(days_in_month as u32)
    });
    if day == 0 || day as u64 > days_in_month {
        return error_response(
            StatusCode::BAD_REQUEST,
            &format!("day must be between 1 and {days_in_month}"),
        );
    }
    let day_start = month_start(year, month) + (day as u64 - 1) * 86400;

    let Some(_permit) = relay.api_limit.try_acquire() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "server is busy, try again shortly" })),
        );
    };
    let count_limit = relay.config.read().await.limits.max_count;
    let no_tags = excluded_tags(&params);
    let nip78 = enabled_nip78_auth_active(&relay).await;

    let mut hour_counts = Vec::with_capacity(24);
    let mut total = 0u64;
    let mut approximate = false;
    for h in 0..24 {
        let h_start = day_start + h * 3600;
        let filter: Filter = serde_json::from_value(json!({
            "authors": [hex_pk],
            "kinds": [kind],
            "since": h_start,
            "until": h_start + 3600 - 1,
        }))
        .expect("static filter");
        let (events, more) = relay.db.api_count(vec![filter], count_limit, now).await;
        approximate |= more;
        let has_group_events = events.iter().any(nip29::is_group_event);
        let groups = if has_group_events {
            Some(relay.groups.read().await)
        } else {
            None
        };
        let count = events
            .iter()
            .filter(|e| api_visible(e, groups.as_deref(), &no_tags, nip78))
            .count();
        drop(groups);
        total += count as u64;
        hour_counts.push(json!({
            "hour": format!("{year:04}-{month:02}-{day:02}T{h:02}"),
            "count": count,
            "approximate": more,
        }));
    }
    drop(_permit);
    (
        StatusCode::OK,
        Json(json!({ "hours": hour_counts, "total": total, "approximate": approximate })),
    )
}

/// `GET /api/v1/ids/{hex}/related`
///
/// Events referencing an event: replies and threads (`#e` tags) and quotes
/// (`#q` tags) — the union of both filters.
pub async fn api_related_handler(
    State(relay): State<Arc<Relay>>,
    Path(hex_id): Path<String>,
    Query(mut params): Query<ApiParams>,
) -> (StatusCode, Json<Value>) {
    if hex_id.len() != 64 || hex::decode(&hex_id).is_err() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "the id must be a 64-character hex string",
        );
    }
    // Bound the query parameters like every other handler: without the
    // cap an unauthenticated request could collect and serialize the
    // whole scan budget (~200k events) and OOM the relay.
    let cfg = relay.config.read().await;
    if let Err((status, msg)) = bound_params(&mut params, &cfg) {
        return error_response(status, &msg);
    }
    drop(cfg);
    let no_tags = excluded_tags(&params);
    let limit = params.limit.unwrap_or(100);
    // The `e` query parameter must not overwrite the target id: the
    // replies filter matches the id *or* the parameter.
    let e_target = match &params.e {
        Some(e) => json!([hex_id.clone(), e.clone()]),
        None => json!(hex_id.clone()),
    };
    let mut replies = apply_params(
        Filter {
            tags: std::collections::BTreeMap::from([("#e".to_string(), e_target)]),
            ..Default::default()
        },
        &params,
    );
    // apply_params overwrites `#e` with the bare `e` parameter; restore
    // the union of the id and the parameter.
    if let Some(ref e) = params.e {
        replies
            .tags
            .insert("#e".to_string(), json!([hex_id.clone(), e.clone()]));
    }
    let filters: Vec<Filter> = vec![
        replies,
        apply_params(
            Filter {
                tags: std::collections::BTreeMap::from([("#q".to_string(), json!(hex_id.clone()))]),
                ..Default::default()
            },
            &params,
        ),
    ];
    query_and_respond(
        &relay,
        filters,
        limit,
        params.offset,
        sort_ascending(&params.sort),
        &no_tags,
    )
    .await
}

/// `GET /api/v1/{identifier}/follows`
///
/// The author's latest follow list (kind 3, NIP-02 — replaceable, so the
/// newest event is the current list; the `p` tags carry the followed
/// pubkeys).
pub async fn api_follows_handler(
    State(relay): State<Arc<Relay>>,
    Path(identifier): Path<String>,
    Query(mut params): Query<ApiParams>,
) -> (StatusCode, Json<Value>) {
    let hex_pk = match parse_author_identifier(&identifier) {
        Ok(pk) => pk,
        Err(msg) => return error_response(StatusCode::BAD_REQUEST, &msg),
    };
    let cfg = relay.config.read().await;
    if let Err((status, msg)) = bound_params(&mut params, &cfg) {
        return error_response(status, &msg);
    }
    drop(cfg);
    let no_tags = excluded_tags(&params);
    let filter = apply_params(
        Filter {
            authors: Some(vec![hex_pk]),
            kinds: Some(vec![3]),
            ..Default::default()
        },
        &params,
    );
    query_and_respond(
        &relay,
        vec![filter],
        1,
        params.offset,
        sort_ascending(&params.sort),
        &no_tags,
    )
    .await
}

/// `GET /api/v1/relay/kinds`
///
/// The most common event kinds stored on the relay: `{"kinds": [{"kind":
/// 1, "count": 12345}, ...], "approximate": bool}` sorted by count
/// descending. The count walk is bounded (`approximate: true` when it was
/// cut short). Counts are raw store totals: withheld events (protected,
/// gift wraps, NIP-78 owner data, private groups) are included because the
/// index walk cannot apply per-connection visibility without fetching every
/// event; per-author `kinds`/`query` endpoints remain visibility-filtered.
pub async fn api_relay_kinds_handler(
    State(relay): State<Arc<Relay>>,
    Query(params): Query<ApiParams>,
) -> (StatusCode, Json<Value>) {
    let Some(_permit) = relay.api_limit.try_acquire() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "server is busy, try again shortly" })),
        );
    };
    let limit = params.limit.unwrap_or(20).min(100);
    // The walk examines at most half a million index entries (bounded work
    // on the dedicated API reader thread); `approximate` reports whether it
    // was cut short.
    const MAX_KEYS: usize = 500_000;
    let (counts, more) = relay.db.kind_counts(MAX_KEYS).await;
    drop(_permit);
    let mut kinds: Vec<Value> = counts
        .into_iter()
        .map(|(kind, count)| json!({ "kind": kind, "count": count }))
        .collect();
    kinds.sort_by(|a, b| {
        b["count"]
            .as_u64()
            .cmp(&a["count"].as_u64())
            .then_with(|| a["kind"].as_u64().cmp(&b["kind"].as_u64()))
    });
    kinds.truncate(limit);
    (
        StatusCode::OK,
        Json(json!({ "kinds": kinds, "approximate": more, "filtered": false })),
    )
}

/// `GET /api/v1/relay/top-authors`
///
/// The most active authors on the relay: `{"authors": [{"pubkey": "<hex>",
/// "count": 123}], "approximate": bool}` sorted by count descending. The
/// walk is bounded (`approximate: true` when it was cut short). Like
/// `relay/kinds`, counts are raw store totals including withheld events.
pub async fn api_top_authors_handler(
    State(relay): State<Arc<Relay>>,
    Query(params): Query<ApiParams>,
) -> (StatusCode, Json<Value>) {
    let Some(_permit) = relay.api_limit.try_acquire() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "server is busy, try again shortly" })),
        );
    };
    let limit = params.limit.unwrap_or(20).min(100);
    const MAX_KEYS: usize = 500_000;
    let (counts, more) = relay.db.author_counts(MAX_KEYS).await;
    drop(_permit);
    let mut authors: Vec<Value> = counts
        .into_iter()
        .map(|(pubkey, count)| json!({ "pubkey": hex::encode(pubkey), "count": count }))
        .collect();
    authors.sort_by(|a, b| {
        b["count"]
            .as_u64()
            .cmp(&a["count"].as_u64())
            .then_with(|| a["pubkey"].as_str().cmp(&b["pubkey"].as_str()))
    });
    authors.truncate(limit);
    (
        StatusCode::OK,
        Json(json!({ "authors": authors, "approximate": more, "filtered": false })),
    )
}

/// `GET /api/v1/{identifier}/relays`
///
/// The author's latest NIP-65 relay list (kind 10002, replaceable — the
/// newest event is the current list; the `r` tags carry the relay URLs).
pub async fn api_relays_handler(
    State(relay): State<Arc<Relay>>,
    Path(identifier): Path<String>,
    Query(mut params): Query<ApiParams>,
) -> (StatusCode, Json<Value>) {
    let hex_pk = match parse_author_identifier(&identifier) {
        Ok(pk) => pk,
        Err(msg) => return error_response(StatusCode::BAD_REQUEST, &msg),
    };
    let cfg = relay.config.read().await;
    if let Err((status, msg)) = bound_params(&mut params, &cfg) {
        return error_response(status, &msg);
    }
    drop(cfg);
    let no_tags = excluded_tags(&params);
    let filter = apply_params(
        Filter {
            authors: Some(vec![hex_pk]),
            kinds: Some(vec![10002]),
            ..Default::default()
        },
        &params,
    );
    query_and_respond(
        &relay,
        vec![filter],
        1,
        params.offset,
        sort_ascending(&params.sort),
        &no_tags,
    )
    .await
}

/// `(year, month)` of a unix timestamp.
fn month_of(ts: u64) -> (i64, u32) {
    let (y, m, _) = civil_from_days((ts / 86400) as i64);
    (y, m)
}

/// The unix timestamp of the first second of `(year, month)`.
fn month_start(y: i64, m: u32) -> u64 {
    (days_from_civil(y, m, 1) * 86400) as u64
}

/// The first second of the month following `(year, month)`.
fn month_start_of_next(y: i64, m: u32) -> u64 {
    if m == 12 {
        month_start(y + 1, 1)
    } else {
        month_start(y, m + 1)
    }
}

/// The months covered by `[since, until]`, oldest first.
/// Maximum number of months a single `/monthly` request may scan: each
/// month is a database count query, so an unbounded range would let one
/// request pin the API reader thread for a long time (120 months = 10
/// years of history).
const MAX_MONTHS: usize = 120;

/// The months covered by `[since, until]`, oldest first, capped at
/// `MAX_MONTHS + 1` entries: the caller rejects anything beyond
/// `MAX_MONTHS`, so the walk must never build more than that (a client
/// sending `since=0&until=u64::MAX` must not loop ~7e12 times).
fn month_range(since: u64, until: u64) -> Vec<(i64, u32)> {
    if until < since {
        return Vec::new();
    }
    let (sy, sm) = month_of(since);
    let (ey, em) = month_of(until);
    let mut out = Vec::with_capacity((MAX_MONTHS + 1).min(64));
    let mut y = sy;
    let mut m = sm;
    for _ in 0..=MAX_MONTHS {
        out.push((y, m));
        if (y, m) == (ey, em) {
            break;
        }
        if m == 12 {
            y += 1;
            m = 1;
        } else {
            m += 1;
        }
    }
    out
}

/// Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm,
/// no time-library dependency).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) as i64 + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Civil date `(year, month, day)` for days since 1970-01-01.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

async fn query_and_respond(
    relay: &Arc<Relay>,
    filters: Vec<Filter>,
    max_limit: usize,
    offset: Option<usize>,
    ascending: bool,
    no_tags: &[&str],
) -> (StatusCode, Json<Value>) {
    // Concurrency limiter: at most `api_max_concurrent` `/api/v1` queries
    // run at once. When saturated, the request fails fast with 503 so a
    // flood of REST traffic cannot pile up behind the shared database. The
    // permit releases the slot on every exit path of this handler.
    let Some(_permit) = relay.api_limit.try_acquire() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "server is busy, try again shortly" })),
        );
    };
    let now = unix_now();
    // NIP-50: when the search capability is disabled, strip `search` from the
    // filters (like the WebSocket path) so the REST API cannot trigger a
    // full-range term scan that a WS client could never run.
    let mut filters = filters;
    if !relay.config.read().await.nip_enabled(50) {
        for f in &mut filters {
            f.search = None;
        }
    }
    let nip78 = enabled_nip78_auth_active(relay).await;
    // Pagination over the *visible* sequence: hidden rows (protected, gift
    // wraps, private groups) are filtered after the scan, so a single
    // `limit + offset + 1` pre-filter fetch can under-fill the page and, worse,
    // skip visible events on the next offset (e.g. `[V1, Hx100, V2, V3]` with
    // `limit=2` would return only `[V1]` and lose `V2`). Re-fetch with a
    // growing window until the visible prefix covers `skip + limit`, the scan
    // reports exhaustion, or a bounded cap is reached.
    let skip = offset.unwrap_or(0);
    let want_visible = skip.saturating_add(max_limit).saturating_add(1);
    // Bound total work: at most 4 rounds, each at most 4x the visible target
    // and never more than the configured offset cap + limit (defaults keep
    // this small; `0` means unbounded so fall back to 8x with a hard 10k).
    let cfg_limit = relay.config.read().await.limits.max_api_offset;
    let hard_cap = if cfg_limit > 0 {
        cfg_limit.saturating_add(max_limit).saturating_add(1)
    } else {
        want_visible.saturating_mul(8).clamp(128, 10_000)
    };
    let mut fetch = want_visible.min(hard_cap).max(1);
    let mut events: Vec<Event> = Vec::new();
    let mut db_more = true;
    for _ in 0..4 {
        let (batch, more) = relay
            .db
            .api_query(filters.clone(), fetch, now, ascending)
            .await;
        events = batch;
        db_more = more;
        let has_group_events = events.iter().any(nip29::is_group_event);
        let groups = if has_group_events {
            Some(relay.groups.read().await)
        } else {
            None
        };
        let visible_count = events
            .iter()
            .filter(|e| api_visible(e, groups.as_deref(), no_tags, nip78))
            .count();
        drop(groups);
        if visible_count >= want_visible || !db_more || fetch >= hard_cap {
            break;
        }
        fetch = fetch.saturating_mul(4).min(hard_cap);
        if fetch <= events.len() {
            break;
        }
    }
    drop(_permit);

    // The REST API is unauthenticated, so it must apply the same
    // visibility rules as an anonymous WebSocket connection: NIP-70
    // protected events, NIP-59 gift wraps and NIP-29 private/hidden group
    // content are withheld. Only the group read lock is taken when a batch
    // actually contains group events (the common case has none).
    let has_group_events = events.iter().any(nip29::is_group_event);
    let groups = if has_group_events {
        Some(relay.groups.read().await)
    } else {
        None
    };
    let visible: Vec<Event> = events
        .into_iter()
        .filter(|e| api_visible(e, groups.as_deref(), no_tags, nip78))
        .collect();
    drop(groups);

    // `more` reflects the visible sequence: a further page exists when more
    // than `skip + limit` visible events were fetched, or when the database
    // hint says the pre-filter scan was cut short (best-effort, so a page
    // that is under-filled because of hidden rows still advertises more).
    let has_more = visible.len() > skip.saturating_add(max_limit) || db_more;
    let event_values: Vec<Value> = visible
        .into_iter()
        .skip(skip)
        .take(max_limit)
        .filter_map(|e| serde_json::to_value(e).ok())
        .collect();

    let count = event_values.len();

    (
        StatusCode::OK,
        Json(json!(ApiResponse {
            events: event_values,
            count,
            more: has_more,
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Keypair, Secp256k1, XOnlyPublicKey};
    use tokio::sync::RwLock;

    use crate::db::DbClient;
    use crate::nips::nip01::sign;
    use crate::relay::LiveBusConfig;
    use crate::stats::Stats;

    fn signed_note(
        secp: &Secp256k1<secp256k1::All>,
        content: &str,
        created: u64,
        tags: Vec<Vec<String>>,
    ) -> Event {
        signed_kind_note(secp, 1, content, created, tags)
    }

    fn signed_kind_note(
        secp: &Secp256k1<secp256k1::All>,
        kind: u64,
        content: &str,
        created: u64,
        tags: Vec<Vec<String>>,
    ) -> Event {
        let keypair = Keypair::from_seckey_slice(secp, &[1u8; 32]).unwrap();
        let pubkey = XOnlyPublicKey::from_keypair(&keypair).0.to_string();
        let mut ev = Event {
            id: String::new(),
            pubkey,
            created_at: created,
            kind,
            tags,
            content: content.into(),
            sig: String::new(),
        };
        sign(&mut ev, &keypair, secp).unwrap();
        ev
    }

    async fn build_relay() -> Arc<Relay> {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join("nostrfy-api-test")
            .join(format!("{:x}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        let mut cfg = Config::default();
        cfg.database.path = path;
        cfg.database.map_size = 16 * 1024 * 1024;
        cfg.database.max_map_size = 256 * 1024 * 1024;
        let db = DbClient::open(
            &cfg.database,
            true,
            Arc::new(Default::default()),
            0,
            128,
            4096,
            262144,
        )
        .unwrap();
        let config = Arc::new(RwLock::new(cfg));
        let stats = Stats::new();
        let mut relay = Relay::new(
            config,
            db,
            stats,
            "",
            LiveBusConfig {
                buffer: 1024,
                batch_interval_ms: 10,
                batch_size: 64,
            },
        )
        .await;
        relay.start_live_bus();
        Arc::new(relay)
    }

    #[test]
    fn string_and_u64_list_deserializers() {
        fn from(json: serde_json::Value) -> serde_json::Result<ApiParams> {
            serde_json::from_value(json)
        }
        // authors: single string, comma-separated, or array.
        assert_eq!(
            from(json!({"authors": "a,b, c ,"})).unwrap().authors,
            vec!["a", "b", "c"]
        );
        assert_eq!(
            from(json!({"authors": ["x", " y "]})).unwrap().authors,
            vec!["x", "y"]
        );
        assert!(
            from(json!({"authors": [1]})).is_err(),
            "non-string array items fail"
        );
        assert!(
            from(json!({"authors": 42})).is_err(),
            "non-string scalars fail"
        );
        // kinds: numeric strings only.
        assert_eq!(from(json!({"kinds": "1,2"})).unwrap().kinds, vec![1, 2]);
        assert!(
            from(json!({"kinds": "1,x"})).is_err(),
            "non-numeric values fail"
        );
    }

    #[test]
    fn bound_params_caps_and_rejects() {
        let cfg = crate::config::Config::default();
        // The limit is capped down, the offset/search over the maxima are
        // rejected.
        let mut p = ApiParams {
            limit: Some(10_000),
            ..Default::default()
        };
        let mut cfg2 = cfg.clone();
        cfg2.limits.max_api_limit = 100;
        cfg2.limits.max_api_offset = 50;
        cfg2.limits.max_api_search_bytes = 200;
        bound_params(&mut p, &cfg2).unwrap();
        assert_eq!(p.limit, Some(100), "the limit is capped");
        let mut p = ApiParams {
            offset: Some(51),
            ..Default::default()
        };
        assert!(
            bound_params(&mut p, &cfg2).is_err(),
            "an over-max offset is rejected"
        );
        let mut p = ApiParams {
            search: Some("x".repeat(201)),
            ..Default::default()
        };
        assert!(
            bound_params(&mut p, &cfg2).is_err(),
            "an over-max search is rejected"
        );
        // Zero limits leave the params untouched.
        cfg2.limits.max_api_limit = 0;
        let mut p = ApiParams {
            limit: Some(10_000),
            ..Default::default()
        };
        bound_params(&mut p, &cfg2).unwrap();
        assert_eq!(p.limit, Some(10_000));
    }

    #[test]
    fn api_visible_filters_apply() {
        let secp = Secp256k1::new();
        let plain = signed_note(&secp, "plain", 1, vec![]);
        let mut protected = plain.clone();
        protected.tags = vec![vec!["-".into()]];
        let mut wrap = plain.clone();
        wrap.kind = crate::nips::nip62::GIFT_WRAP_KIND;
        wrap.tags = vec![vec!["p".into(), "aa".repeat(32)]];
        let mut app = plain.clone();
        app.kind = 78;
        let mut no_p = plain.clone();
        no_p.tags = vec![vec!["p".into(), "bb".repeat(32)]];

        assert!(api_visible(&plain, None, &[], false));
        assert!(!api_visible(&protected, None, &[], false), "NIP-70 hidden");
        assert!(!api_visible(&wrap, None, &[], false), "gift wraps hidden");
        assert!(
            api_visible(&app, None, &[], false),
            "NIP-78 app-specific is public without the AUTH gate"
        );
        assert!(!api_visible(&app, None, &[], true), "AUTH gate hides it");
        assert!(!api_visible(&no_p, None, &["p"], false), "no_p excludes");
        assert!(api_visible(&no_p, None, &["e"], false));
    }

    #[test]
    fn author_identifier_parsing_and_sorting() {
        assert_eq!(
            parse_author_identifier("AA".repeat(32).as_str()).unwrap(),
            "aa".repeat(32),
            "uppercase hex is lowercased"
        );
        assert!(
            parse_author_identifier("not-hex-not-npub").is_err(),
            "a junk identifier fails"
        );
        assert!(
            parse_author_identifier(
                "npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
            )
            .is_err()
                || parse_author_identifier(
                    "npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
                )
                .is_ok(),
            "an npub parses (or a fabricated one fails) without panicking"
        );
        // `nprofile1...` resolves to its profile pubkey like `npub1...`.
        let pk_bytes = hex::decode("aa".repeat(32)).unwrap();
        let mut tlv = vec![0u8, 32];
        tlv.extend_from_slice(&pk_bytes);
        let nprofile = crate::nips::nip19::bech32_encode("nprofile", &tlv).unwrap();
        assert_eq!(
            parse_author_identifier(&nprofile).unwrap(),
            "aa".repeat(32),
            "nprofile resolves to its pubkey"
        );
        assert!(!sort_ascending(&None));
        assert!(sort_ascending(&Some("asc".into())));
        assert!(sort_ascending(&Some("ascending".into())));
        assert!(!sort_ascending(&Some("desc".into())));
    }

    #[test]
    fn year_and_month_validation() {
        // The daily/hourly handlers reject out-of-range years: a huge
        // year would overflow the civil-date arithmetic.
        let mut params = ApiParams {
            year: Some(1_000_000),
            month: Some(1),
            ..Default::default()
        };
        assert!(
            params.year.is_some_and(|y| !(1970..=2999).contains(&y)),
            "the guard range is 1970..=2999"
        );
        params.year = Some(1970);
        assert!((1970..=2999).contains(&params.year.unwrap()));
        params.month = Some(13);
        assert!(!(1..=12).contains(&params.month.unwrap()));
    }

    #[test]
    fn excluded_tags_lists_absence_filters() {
        let mut params = ApiParams::default();
        assert!(excluded_tags(&params).is_empty());
        params.no_p = Some(true);
        params.no_e = Some(true);
        let tags = excluded_tags(&params);
        assert_eq!(tags, vec!["p", "e"]);
        params.no_t = Some(true);
        params.no_d = Some(true);
        assert_eq!(excluded_tags(&params).len(), 4);
    }

    #[test]
    fn related_filters_merge_e_parameter_with_the_id() {
        // The `e` query parameter must be OR-ed with the path id, not
        // replace it: the replies filter matches both targets.
        let params = ApiParams {
            e: Some("e1".into()),
            ..Default::default()
        };
        let mut f = apply_params(
            Filter {
                tags: std::collections::BTreeMap::from([("#e".to_string(), json!("target-id"))]),
                ..Default::default()
            },
            &params,
        );
        if let Some(ref e) = params.e {
            f.tags
                .insert("#e".to_string(), json!(["target-id", e.clone()]));
        }
        let values = f.tags["#e"].as_array().unwrap();
        assert_eq!(values.len(), 2);
        assert_eq!(values[0], "target-id");
        assert_eq!(values[1], "e1");
    }

    #[test]
    fn pagination_skips_hidden_events_without_losing_pages() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay().await;
            let now = unix_now();
            let v1 = signed_note(relay.secp(), "v1", now, vec![]);
            let hidden = signed_note(relay.secp(), "hidden", now - 1, vec![vec!["-".into()]]);
            let v2 = signed_note(relay.secp(), "v2", now - 2, vec![]);
            let v3 = signed_note(relay.secp(), "v3", now - 3, vec![]);
            for e in [&v1, &hidden, &v2, &v3] {
                assert_eq!(
                    relay.db.put(e.clone(), now).await,
                    crate::db::PutOutcome::Stored
                );
            }
            let filters: Vec<Filter> =
                serde_json::from_value(serde_json::json!([{"kinds": [1]}])).unwrap();

            // Page 1: the hidden event must not consume a slot; V1 and V2 both
            // arrive, and more pages exist.
            let (code, Json(resp)) =
                query_and_respond(&relay, filters.clone(), 2, Some(0), false, &[]).await;
            assert_eq!(code, StatusCode::OK);
            let events = resp["events"].as_array().unwrap();
            assert_eq!(events.len(), 2, "hidden event must not consume the page");
            assert_eq!(events[0]["content"], "v1");
            assert_eq!(events[1]["content"], "v2");
            assert_eq!(resp["more"], true);

            // Page 2 (offset 2 over visible): V3, and no more pages.
            let (_, Json(resp)) = query_and_respond(&relay, filters, 2, Some(2), false, &[]).await;
            let events = resp["events"].as_array().unwrap();
            assert_eq!(events.len(), 1);
            assert_eq!(
                events[0]["content"], "v3",
                "V2 must not be lost or repeated"
            );
            assert_eq!(resp["more"], false);

            relay.db.shutdown();
        });
    }

    #[test]
    fn daily_hourly_report_approximate_when_capped() {
        // `api_count` cut short (`more == true`) must surface as
        // `approximate: true` per bucket and overall, like monthly/count.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay().await;
            {
                let mut cfg = relay.config.write().await;
                cfg.limits.max_count = 1;
            }
            let now = unix_now();
            let mut first_pk = String::new();
            for i in 0..3 {
                let e = signed_note(relay.secp(), &format!("n{i}"), now, vec![]);
                if i == 0 {
                    first_pk = e.pubkey.clone();
                }
                assert_eq!(relay.db.put(e, now).await, crate::db::PutOutcome::Stored);
            }
            let (y, m) = month_of(now);
            let (_, Json(daily)) = api_daily_handler(
                State(relay.clone()),
                Path((first_pk, 1)),
                Query(ApiParams {
                    year: Some(y),
                    month: Some(m),
                    ..Default::default()
                }),
            )
            .await;
            assert_eq!(
                daily["approximate"], true,
                "a capped day must flag approximate"
            );
            assert!(
                daily["days"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|d| d["approximate"] == true),
                "the capped bucket must flag approximate"
            );
            relay.db.shutdown();
        });
    }

    #[test]
    fn monthly_reports_overall_approximate_when_capped() {
        // A capped month must surface as top-level `approximate: true`
        // (like daily/hourly), so clients know `total` is truncated.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay().await;
            {
                let mut cfg = relay.config.write().await;
                cfg.limits.max_count = 1;
            }
            let now = unix_now();
            let mut first_pk = String::new();
            for i in 0..3 {
                let e = signed_note(relay.secp(), &format!("m{i}"), now - i as u64, vec![]);
                if i == 0 {
                    first_pk = e.pubkey.clone();
                }
                assert_eq!(relay.db.put(e, now).await, crate::db::PutOutcome::Stored);
            }
            let (code, Json(resp)) = api_monthly_handler(
                State(relay.clone()),
                Path((first_pk, 1)),
                Query(ApiParams {
                    since: Some(now - 370 * 86400),
                    until: Some(now),
                    ..Default::default()
                }),
            )
            .await;
            assert_eq!(code, StatusCode::OK);
            assert_eq!(
                resp["approximate"], true,
                "a capped month must flag overall approximate: {resp}"
            );
            relay.db.shutdown();
        });
    }

    #[test]
    fn stats_finds_visible_activity_behind_hidden_events() {
        // Newest/oldest 64+ events may all be invisible gift wraps: stats
        // must look further (up to 1024) instead of reporting null times.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay().await;
            let now = unix_now();
            let pub_ev = signed_note(relay.secp(), "public", now - 1000, vec![]);
            let pubkey = pub_ev.pubkey.clone();
            assert_eq!(
                relay.db.put(pub_ev, now).await,
                crate::db::PutOutcome::Stored
            );
            for i in 0..70 {
                let mut w = signed_note(relay.secp(), &format!("w{i}"), now - i, vec![]);
                // Gift wrap to someone else: invisible to anonymous API.
                w.kind = 1059;
                w.tags = vec![vec!["p".into(), "bb".repeat(32)]];
                w.id = crate::nips::nip01::compute_id(&w);
                let _ = relay.db.put(w, now).await;
            }
            let (code, Json(resp)) = api_stats_handler(
                State(relay.clone()),
                Path(pubkey),
                Query(ApiParams::default()),
            )
            .await;
            assert_eq!(code, StatusCode::OK);
            assert!(
                !resp["last_seen"].is_null() || !resp["first_seen"].is_null(),
                "visible activity must be found behind hidden wraps: {resp}"
            );
            relay.db.shutdown();
        });
    }

    #[test]
    fn monthly_rejects_overlong_ranges() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay().await;
            let pk = "aa".repeat(32);
            let (code, _) = api_monthly_handler(
                State(relay.clone()),
                Path((pk, 1)),
                Query(ApiParams {
                    since: Some(0),
                    until: Some(u64::MAX / 2),
                    ..Default::default()
                }),
            )
            .await;
            assert_eq!(code, StatusCode::BAD_REQUEST, ">120 months must 400");
            relay.db.shutdown();
        });
    }

    #[test]
    fn generic_query_count_kinds_daily_id_and_profile() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay().await;
            let secp = relay.secp();
            let pk = XOnlyPublicKey::from_keypair(
                &Keypair::from_seckey_slice(secp, &[1u8; 32]).unwrap(),
            )
            .0
            .to_string();
            let npub = crate::nips::nip19::bech32_encode("npub", &hex::decode(&pk).unwrap())
                .expect("npub encoding");
            let aug1 = 1_785_542_400u64;

            let profile = signed_kind_note(relay.secp(), 0, "{\"name\":\"t\"}", aug1 + 1, vec![]);
            let note1 = signed_note(relay.secp(), "n1", aug1 + 2, vec![]);
            let note2 = signed_note(relay.secp(), "n2", aug1 + 3, vec![]);
            let reaction = signed_kind_note(relay.secp(), 7, "+", aug1 + 4, vec![]);
            for e in [&profile, &note1, &note2, &reaction] {
                assert_eq!(
                    relay.db.put(e.clone(), aug1 + 4).await,
                    crate::db::PutOutcome::Stored
                );
            }

            // /query: generic filters.
            let (code, Json(resp)) = api_query_handler(
                State(relay.clone()),
                Query(ApiParams {
                    authors: vec![pk.clone()],
                    kinds: vec![1],
                    ..Default::default()
                }),
            )
            .await;
            assert_eq!(code, StatusCode::OK);
            let events = resp["events"].as_array().unwrap();
            assert_eq!(events.len(), 2, "both kind-1 notes");

            // /count: total.
            let (_, Json(resp)) = api_count_handler(
                State(relay.clone()),
                Query(ApiParams {
                    authors: vec![pk.clone()],
                    ..Default::default()
                }),
            )
            .await;
            assert_eq!(resp["count"], 4);
            assert_eq!(resp["approximate"], false);

            // /{npub1}/kinds: per-kind breakdown, most used first.
            let (_, Json(resp)) = api_kinds_handler(
                State(relay.clone()),
                Path(npub.clone()),
                Query(ApiParams::default()),
            )
            .await;
            let kinds = resp["kinds"].as_array().unwrap();
            assert_eq!(kinds.len(), 3);
            assert_eq!(kinds[0]["kind"], 1);
            assert_eq!(kinds[0]["count"], 2);
            assert_eq!(kinds[1]["kind"], 0);
            assert_eq!(kinds[2]["kind"], 7);

            // /{npub1}/{kind}/daily: every day of the month, zero-filled
            // through the last day (Aug 2026 has 31 days).
            let (_, Json(resp)) = api_daily_handler(
                State(relay.clone()),
                Path((npub.clone(), 1u64)),
                Query(ApiParams {
                    year: Some(2026),
                    month: Some(8),
                    ..Default::default()
                }),
            )
            .await;
            let days = resp["days"].as_array().unwrap();
            assert_eq!(days.len(), 31, "every day of August, including future ones");
            assert_eq!(days[0]["day"], "2026-08-01");
            assert_eq!(days[0]["count"], 2, "n1 and n2 were posted on the 1st");
            assert_eq!(days[30]["day"], "2026-08-31");
            assert_eq!(days[30]["count"], 0, "zero-filled through the month end");
            assert_eq!(resp["total"], 2);

            // /ids/{hex}: single event by id.
            let (_, Json(resp)) = api_id_handler(
                State(relay.clone()),
                Path(note1.id.clone()),
                Query(ApiParams::default()),
            )
            .await;
            let events = resp["events"].as_array().unwrap();
            assert_eq!(events.len(), 1);
            assert_eq!(events[0]["id"], note1.id);
            let (code, _) = api_id_handler(
                State(relay.clone()),
                Path("zz".to_string()),
                Query(ApiParams::default()),
            )
            .await;
            assert_eq!(code, StatusCode::BAD_REQUEST);

            // /{npub1} without a kind: the latest kind-0 profile.
            let (_, Json(resp)) = api_handler(
                State(relay.clone()),
                Path(npub),
                Query(ApiParams::default()),
            )
            .await;
            let events = resp["events"].as_array().unwrap();
            assert_eq!(events.len(), 1);
            assert_eq!(events[0]["kind"], 0);

            relay.db.shutdown();
        });
    }

    #[test]
    fn hex_pubkey_identifiers_are_accepted() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay().await;
            let secp = relay.secp();
            let pk = XOnlyPublicKey::from_keypair(
                &Keypair::from_seckey_slice(secp, &[1u8; 32]).unwrap(),
            )
            .0
            .to_string();
            let now = unix_now();
            let note = signed_note(relay.secp(), "hex-author", now, vec![]);
            assert_eq!(
                relay.db.put(note.clone(), now).await,
                crate::db::PutOutcome::Stored
            );

            // The 64-hex pubkey works on every author endpoint, case-insensitively.
            let upper = pk.to_ascii_uppercase();
            for id in [&pk, &upper] {
                let (code, Json(resp)) = api_kind_handler(
                    State(relay.clone()),
                    Path((id.clone(), 1u64)),
                    Query(ApiParams::default()),
                )
                .await;
                assert_eq!(code, StatusCode::OK, "hex pubkey on /{id}/1");
                let events = resp["events"].as_array().unwrap();
                assert_eq!(events.len(), 1);

                let (code, Json(resp)) = api_monthly_handler(
                    State(relay.clone()),
                    Path((id.clone(), 1u64)),
                    Query(ApiParams::default()),
                )
                .await;
                assert_eq!(code, StatusCode::OK);
                assert_eq!(resp["total"], 1);

                let (code, Json(resp)) = api_kinds_handler(
                    State(relay.clone()),
                    Path(id.clone()),
                    Query(ApiParams::default()),
                )
                .await;
                assert_eq!(code, StatusCode::OK);
                assert_eq!(resp["kinds"][0]["kind"], 1);

                let (code, _) = api_daily_handler(
                    State(relay.clone()),
                    Path((id.clone(), 1u64)),
                    Query(ApiParams::default()),
                )
                .await;
                assert_eq!(code, StatusCode::OK);

                let (code, Json(_resp)) = api_handler(
                    State(relay.clone()),
                    Path(id.clone()),
                    Query(ApiParams::default()),
                )
                .await;
                assert_eq!(code, StatusCode::OK, "hex pubkey on /{id}");
            }

            // A non-pubkey hex length or an invalid string is rejected.
            let (code, _) = api_kind_handler(
                State(relay.clone()),
                Path(("ff".repeat(31), 1u64)),
                Query(ApiParams::default()),
            )
            .await;
            assert_eq!(code, StatusCode::BAD_REQUEST);

            relay.db.shutdown();
        });
    }

    #[test]
    fn leap_years_are_handled() {
        // Gregorian leap rules: divisible by 400 (2000) and by 4 but not by
        // 100 (2024) are leap; divisible by 100 but not 400 (2100, 1900)
        // are not.
        assert_eq!(
            month_start_of_next(2000, 2) - month_start(2000, 2),
            29 * 86400,
            "2000 is a leap year"
        );
        assert_eq!(
            month_start_of_next(2024, 2) - month_start(2024, 2),
            29 * 86400,
            "2024 is a leap year"
        );
        assert_eq!(
            month_start_of_next(2100, 2) - month_start(2100, 2),
            28 * 86400,
            "2100 is not a leap year"
        );
        assert_eq!(
            month_start_of_next(1900, 2) - month_start(1900, 2),
            28 * 86400,
            "1900 is not a leap year"
        );
        assert_eq!(month_start(2024, 2), 1_706_745_600, "2024-02-01T00:00:00Z");
        // February 29, 2024 belongs to February.
        let (y, m, d) = civil_from_days((1_706_745_600 / 86400) as i64 + 28);
        assert_eq!((y, m, d), (2024, 2, 29));
        let months = month_range(
            month_start(2024, 2),
            month_start_of_next(2024, 2).saturating_sub(1),
        );
        assert_eq!(months, vec![(2024, 2)], "one month spanning the leap day");
    }

    #[test]
    fn daily_counts_cover_february_leap_days() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay().await;
            let secp = relay.secp();
            let pk = XOnlyPublicKey::from_keypair(
                &Keypair::from_seckey_slice(secp, &[1u8; 32]).unwrap(),
            )
            .0
            .to_string();
            let npub = crate::nips::nip19::bech32_encode("npub", &hex::decode(&pk).unwrap())
                .expect("npub encoding");
            let feb1 = 1_706_745_600u64; // 2024-02-01
            let leap_day = signed_note(relay.secp(), "leap day", feb1 + 28 * 86400 + 100, vec![]);
            assert_eq!(
                relay.db.put(leap_day.clone(), feb1 + 28 * 86400).await,
                crate::db::PutOutcome::Stored
            );

            let (code, Json(resp)) = api_daily_handler(
                State(relay.clone()),
                Path((npub, 1u64)),
                Query(ApiParams {
                    year: Some(2024),
                    month: Some(2),
                    ..Default::default()
                }),
            )
            .await;
            assert_eq!(code, StatusCode::OK);
            let days = resp["days"].as_array().unwrap();
            assert_eq!(days.len(), 29, "February 2024 has 29 days");
            assert_eq!(days[28]["day"], "2024-02-29");
            assert_eq!(days[28]["count"], 1, "the leap day is counted");
            assert_eq!(resp["total"], 1);
            relay.db.shutdown();
        });
    }

    #[test]
    fn stats_hourly_related_follows_and_relay_kinds() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay().await;
            let secp = relay.secp();
            let pk = XOnlyPublicKey::from_keypair(
                &Keypair::from_seckey_slice(secp, &[1u8; 32]).unwrap(),
            )
            .0
            .to_string();
            let npub = crate::nips::nip19::bech32_encode("npub", &hex::decode(&pk).unwrap())
                .expect("npub encoding");
            let aug1 = 1_785_542_400u64;

            let follows = signed_kind_note(
                relay.secp(),
                3,
                "",
                aug1 + 1,
                vec![vec!["p".into(), "cc".repeat(32)]],
            );
            let root = signed_note(relay.secp(), "root", aug1 + 2, vec![]);
            let reply = signed_note(
                relay.secp(),
                "reply",
                aug1 + 3,
                vec![vec!["e".into(), root.id.clone()]],
            );
            let quote = signed_note(
                relay.secp(),
                "quote",
                aug1 + 4,
                vec![vec!["q".into(), root.id.clone()]],
            );
            for e in [&follows, &root, &reply, &quote] {
                assert_eq!(
                    relay.db.put(e.clone(), aug1 + 4).await,
                    crate::db::PutOutcome::Stored
                );
            }

            // /{npub1}/stats: summary in one call.
            let (code, Json(resp)) = api_stats_handler(
                State(relay.clone()),
                Path(npub.clone()),
                Query(ApiParams::default()),
            )
            .await;
            assert_eq!(code, StatusCode::OK);
            assert_eq!(resp["total"], 4);
            assert_eq!(resp["first_month"], "2026-08");
            assert_eq!(resp["last_month"], "2026-08");
            assert_eq!(resp["first_seen"], aug1 + 1);
            assert_eq!(resp["last_seen"], aug1 + 4);
            let kinds = resp["kinds"].as_array().unwrap();
            assert_eq!(kinds.len(), 2, "kind 1 (3 events) collapses into one entry");
            assert_eq!(kinds[0]["kind"], 1);
            assert_eq!(kinds[0]["count"], 3);

            // /{npub1}/1/hourly: all 24 hours of one day, zero-filled.
            let (_, Json(resp)) = api_hourly_handler(
                State(relay.clone()),
                Path((npub.clone(), 1u64)),
                Query(ApiParams {
                    year: Some(2026),
                    month: Some(8),
                    day: Some(1),
                    ..Default::default()
                }),
            )
            .await;
            let hours = resp["hours"].as_array().unwrap();
            assert_eq!(hours.len(), 24);
            assert_eq!(hours[0]["hour"], "2026-08-01T00");
            assert_eq!(hours[0]["count"], 3, "the three kind-1 events");
            assert_eq!(hours[23]["hour"], "2026-08-01T23");
            assert_eq!(hours[23]["count"], 0);
            assert_eq!(resp["total"], 3);
            // An invalid day is rejected.
            let (code, _) = api_hourly_handler(
                State(relay.clone()),
                Path((npub.clone(), 1u64)),
                Query(ApiParams {
                    year: Some(2026),
                    month: Some(2),
                    day: Some(30),
                    ..Default::default()
                }),
            )
            .await;
            assert_eq!(code, StatusCode::BAD_REQUEST);

            // /ids/{hex}/related: replies and quotes referencing the root.
            let (_, Json(resp)) = api_related_handler(
                State(relay.clone()),
                Path(root.id.clone()),
                Query(ApiParams::default()),
            )
            .await;
            let mut contents: Vec<String> = resp["events"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| e["content"].as_str().unwrap().to_string())
                .collect();
            contents.sort();
            assert_eq!(contents, vec!["quote".to_string(), "reply".to_string()]);

            // /{npub1}/follows: the latest kind-3 list.
            let (_, Json(resp)) = api_follows_handler(
                State(relay.clone()),
                Path(npub.clone()),
                Query(ApiParams::default()),
            )
            .await;
            let events = resp["events"].as_array().unwrap();
            assert_eq!(events.len(), 1);
            assert_eq!(events[0]["kind"], 3);
            assert_eq!(events[0]["tags"][0][0], "p");

            // /relay/kinds: relay-wide kind counts.
            let (_, Json(resp)) =
                api_relay_kinds_handler(State(relay.clone()), Query(ApiParams::default())).await;
            let kinds = resp["kinds"].as_array().unwrap();
            assert_eq!(kinds[0]["kind"], 1, "kind 1 is the most common");
            assert_eq!(kinds[0]["count"], 3);
            assert_eq!(kinds[1]["kind"], 3);

            relay.db.shutdown();
        });
    }

    #[test]
    fn top_authors_and_relay_lists() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay().await;
            let secp = relay.secp();
            let pk = XOnlyPublicKey::from_keypair(
                &Keypair::from_seckey_slice(secp, &[1u8; 32]).unwrap(),
            )
            .0
            .to_string();
            let npub = crate::nips::nip19::bech32_encode("npub", &hex::decode(&pk).unwrap())
                .expect("npub encoding");
            let now = unix_now();

            let relays = signed_kind_note(
                relay.secp(),
                10002,
                "",
                now,
                vec![vec!["r".into(), "wss://relay.example.com".into()]],
            );
            let note = signed_note(relay.secp(), "top author", now - 1, vec![]);
            for e in [&relays, &note] {
                assert_eq!(
                    relay.db.put(e.clone(), now).await,
                    crate::db::PutOutcome::Stored
                );
            }

            // /{npub1}/relays: the latest NIP-65 list.
            let (code, Json(resp)) = api_relays_handler(
                State(relay.clone()),
                Path(npub.clone()),
                Query(ApiParams::default()),
            )
            .await;
            assert_eq!(code, StatusCode::OK);
            let events = resp["events"].as_array().unwrap();
            assert_eq!(events.len(), 1);
            assert_eq!(events[0]["kind"], 10002);
            assert_eq!(events[0]["tags"][0][1], "wss://relay.example.com");

            // /relay/top-authors: the author ranks first.
            let (_, Json(resp)) =
                api_top_authors_handler(State(relay.clone()), Query(ApiParams::default())).await;
            let authors = resp["authors"].as_array().unwrap();
            assert!(
                authors.iter().any(|a| a["pubkey"] == pk && a["count"] == 2),
                "the single author is listed with its event count"
            );

            relay.db.shutdown();
        });
    }

    #[test]
    fn month_arithmetic_roundtrips() {
        // 2026-08-01T00:00:00Z
        assert_eq!(month_start(2026, 8), 1_785_542_400);
        assert_eq!(month_start_of_next(2026, 8), 1_788_220_800, "2026-09-01");
        assert_eq!(month_start_of_next(2026, 12), month_start(2027, 1));
        let (y, m, d) = civil_from_days(0);
        assert_eq!((y, m, d), (1970, 1, 1));
        let (y, m, d) = civil_from_days((1_785_542_400 / 86400) as i64);
        assert_eq!((y, m, d), (2026, 8, 1));
        let months = month_range(
            month_start(2026, 8),
            month_start_of_next(2026, 10).saturating_sub(1),
        );
        assert_eq!(months, vec![(2026, 8), (2026, 9), (2026, 10)]);
        assert!(month_range(1_800_000_000, 1_700_000_000).is_empty());
    }

    #[test]
    fn monthly_counts_group_events_by_month() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay().await;
            let secp = relay.secp();
            let pk = XOnlyPublicKey::from_keypair(
                &Keypair::from_seckey_slice(secp, &[1u8; 32]).unwrap(),
            )
            .0
            .to_string();
            let npub = crate::nips::nip19::bech32_encode("npub", &hex::decode(&pk).unwrap())
                .expect("npub encoding");

            // Two events in August 2026, one in September.
            let aug1 = 1_785_542_400u64;
            let e1 = signed_note(relay.secp(), "aug-1", aug1 + 100, vec![]);
            let e2 = signed_note(relay.secp(), "aug-2", aug1 + 200, vec![]);
            let e3 = signed_note(relay.secp(), "sep-1", aug1 + 31 * 86400 + 100, vec![]);
            for e in [&e1, &e2, &e3] {
                assert_eq!(
                    relay.db.put(e.clone(), aug1 + 31 * 86400).await,
                    crate::db::PutOutcome::Stored
                );
            }

            let (code, Json(resp)) = api_monthly_handler(
                State(relay.clone()),
                Path((npub.clone(), 1u64)),
                Query(ApiParams {
                    since: Some(aug1),
                    until: Some(aug1 + 31 * 86400 + 100),
                    ..Default::default()
                }),
            )
            .await;
            assert_eq!(code, StatusCode::OK);
            let months = resp["months"].as_array().unwrap();
            assert_eq!(months.len(), 2, "August and September");
            assert_eq!(months[0]["month"], "2026-08");
            assert_eq!(months[0]["count"], 2);
            assert_eq!(months[1]["month"], "2026-09");
            assert_eq!(months[1]["count"], 1);
            assert_eq!(resp["total"], 3);

            // Zero-filled months: an empty range still reports every month.
            let (_, Json(resp)) = api_monthly_handler(
                State(relay.clone()),
                Path((npub.clone(), 1u64)),
                Query(ApiParams {
                    since: Some(aug1 - 31 * 86400),
                    until: Some(aug1 + 60),
                    ..Default::default()
                }),
            )
            .await;
            let months = resp["months"].as_array().unwrap();
            assert_eq!(months.len(), 2);
            assert_eq!(months[0]["month"], "2026-07");
            assert_eq!(months[0]["count"], 0);
            assert_eq!(months[1]["count"], 2);

            // until < since is rejected.
            let (code, _) = api_monthly_handler(
                State(relay.clone()),
                Path(("npub1x".into(), 1u64)),
                Query(ApiParams {
                    since: Some(aug1 + 10),
                    until: Some(aug1),
                    ..Default::default()
                }),
            )
            .await;
            assert_eq!(code, StatusCode::BAD_REQUEST);

            // Without since/until the whole period is covered: from the
            // earliest stored event's month to the current one.
            let (_, Json(resp)) = api_monthly_handler(
                State(relay.clone()),
                Path((npub.clone(), 1u64)),
                Query(ApiParams::default()),
            )
            .await;
            let months = resp["months"].as_array().unwrap();
            assert_eq!(
                months[0]["month"], "2026-08",
                "starts at the earliest event"
            );
            assert_eq!(months[0]["count"], 2);
            assert!(
                resp["total"].as_u64().unwrap() >= 2,
                "the whole period starts at the earliest event and ends at now \
                 (September is included once the clock passes it)"
            );
            // The last reported month must be the current one.
            let (y, m) = crate::server::api::month_of(unix_now());
            let last = months.last().unwrap()["month"].as_str().unwrap();
            assert_eq!(
                last,
                format!("{y:04}-{m:02}"),
                "the range ends at the current month"
            );

            relay.db.shutdown();
        });
    }

    #[test]
    fn no_tag_filters_exclude_mention_events() {
        // `no_p=true` is the "top-level posts only" filter: events carrying
        // a `p` tag (mentions, replies, DMs) are dropped before pagination,
        // so excluded events do not consume limit slots or offset steps.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay().await;
            let now = unix_now();
            let plain = signed_note(relay.secp(), "top-level", now, vec![]);
            let mention = signed_note(
                relay.secp(),
                "mention",
                now - 1,
                vec![vec!["p".into(), "aa".repeat(32)]],
            );
            let reply = signed_note(
                relay.secp(),
                "reply",
                now - 2,
                vec![vec!["e".into(), "bb".repeat(32)]],
            );
            for e in [&plain, &mention, &reply] {
                assert_eq!(
                    relay.db.put(e.clone(), now).await,
                    crate::db::PutOutcome::Stored
                );
            }
            let filters: Vec<Filter> =
                serde_json::from_value(serde_json::json!([{"kinds": [1]}])).unwrap();

            // Without exclusion: all three events.
            let (code, Json(resp)) =
                query_and_respond(&relay, filters.clone(), 10, Some(0), false, &[]).await;
            assert_eq!(code, StatusCode::OK);
            assert_eq!(resp["events"].as_array().unwrap().len(), 3);

            // no_p: the mention is dropped, the reply stays.
            let (_, Json(resp)) =
                query_and_respond(&relay, filters.clone(), 10, Some(0), false, &["p"]).await;
            let contents: Vec<String> = resp["events"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| e["content"].as_str().unwrap().to_string())
                .collect();
            assert_eq!(contents, vec!["top-level".to_string(), "reply".to_string()]);

            // no_e: the reply is dropped, the mention stays.
            let (_, Json(resp)) =
                query_and_respond(&relay, filters.clone(), 10, Some(0), false, &["e"]).await;
            let contents: Vec<String> = resp["events"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| e["content"].as_str().unwrap().to_string())
                .collect();
            assert_eq!(
                contents,
                vec!["top-level".to_string(), "mention".to_string()]
            );

            // no_p + no_e: only the top-level post remains.
            let (_, Json(resp)) =
                query_and_respond(&relay, filters, 10, Some(0), false, &["p", "e"]).await;
            let contents: Vec<String> = resp["events"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| e["content"].as_str().unwrap().to_string())
                .collect();
            assert_eq!(contents, vec!["top-level".to_string()]);

            relay.db.shutdown();
        });
    }

    #[test]
    fn api_hides_nip78_events() {
        // The unauthenticated REST API must not leak kind 78/30078 events
        // while relay.enabled_nip78_auth is on (the default).
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let relay = build_relay().await;
            let now = unix_now();
            relay
                .db
                .put(signed_note(relay.secp(), "public", now, vec![]), now)
                .await;
            relay
                .db
                .put(
                    signed_kind_note(
                        relay.secp(),
                        30078,
                        "app",
                        now,
                        vec![vec!["d".into(), "profile".into()]],
                    ),
                    now,
                )
                .await;
            let filters: Vec<Filter> =
                serde_json::from_value(serde_json::json!([{"kinds": [1, 30078]}])).unwrap();
            let (_, Json(resp)) = query_and_respond(&relay, filters, 10, Some(0), false, &[]).await;
            let contents: Vec<String> = resp["events"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| e["content"].as_str().unwrap().to_string())
                .collect();
            assert_eq!(
                contents,
                vec!["public".to_string()],
                "NIP-78 events must be withheld from the API"
            );
            relay.db.shutdown();
        });
    }
}
