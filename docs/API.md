# nostrfy HTTP REST API Reference

nostrfy provides a **read-only** HTTP REST API for querying stored events. It is served on `GET /api/v1/...`.

> **Media uploads** (images, files) are **not** part of this API: they go through the Blossom file server on the `[blossom]` hostname (`PUT /upload`, kind-24242 auth) — see the [Blossom chapter of the manual](MANUAL.md#11-blossom-file-server-media-hosting).

## Table of Contents

1. [Base URL and Host Routing](#1-base-url-and-host-routing)
2. [Endpoints](#2-endpoints)
3. [Query Parameters](#3-query-parameters)
4. [Response Format](#4-response-format)
5. [Pagination](#5-pagination)
6. [Visibility Rules](#6-visibility-rules)
7. [Error Responses](#7-error-responses)
8. [Status Codes](#8-status-codes)
9. [Examples](#9-examples)

---

## 1. Base URL and Host Routing

The API is served on the same port as the WebSocket relay, under the `/api/v1` prefix:

```
http://<host>:<port>/api/v1/{identifier}
http://<host>:<port>/api/v1/{identifier}/{kind}
```

### Generic query, count, kinds, daily and id endpoints

`GET /api/v1/query` — generic filter query without an identifier. All filter parameters combine into one NIP-01 filter: `authors` (single, comma-separated or repeated), `kinds` (same), `e`, `p`, `t`, `d`, `since`, `until`, `search`, `no_p`, `no_e`, `no_t`, `no_d`, `sort`, `limit`, `offset`.

`GET /api/v1/count` — total count for the same filter parameters: `{"count": N, "approximate": bool}` (NIP-45 semantics; `approximate` when the collection limit was hit).

`GET /api/v1/{npub1...}/kinds` — per-kind event counts for an author: `{"kinds": [{"kind": 1, "count": 120}], "approximate": bool}`, sorted by count descending.

Author identifiers (`{npub1...}`) may also be given as a **64-hex pubkey** (case-insensitive) on every endpoint.

`GET /api/v1/{npub1...}/{kind}/daily?year=2026&month=8` — per-day counts for one month (default: the current month; `month` must be 1-12). **Every day of the month is reported, zero-filled through the last day** — 8/31 comes back as 0 even when today is the 28th: `{"days": [{"day": "2026-08-01", "count": 0}], "total": N}`.

`GET /api/v1/ids/{hex}` — a single event by its 64-hex id (prefixes rejected).

`GET /api/v1/{npub1...}` — the author's latest kind-0 profile event (kind 0 is replaceable, so the newest one is the current profile).

### Stats, hourly, related, follows and relay kinds

`GET /api/v1/{npub1...}/stats` — author statistics in one call: `{"total": N, "approximate": bool, "first_seen": unix, "last_seen": unix, "first_month": "2026-08", "last_month": "2026-08", "kinds": [{"kind": 1, "count": 120}]}`.

`GET /api/v1/{npub1...}/{kind}/hourly?year=&month=&day=` — per-hour counts for one day (defaults: the current date; `day` validated against the month). All **24 hours are reported, zero-filled**: `{"hours": [{"hour": "2026-08-28T00", "count": 0}], "total": N}`.

`GET /api/v1/ids/{hex}/related` — events referencing the event: the union of `#e` (replies, threads) and `#q` (quotes) filters.

`GET /api/v1/{npub1...}/follows` — the author's latest follow list (kind 3, NIP-02; replaceable, so the newest event is the current list).

`GET /api/v1/relay/kinds?limit=` — the most common kinds stored on the relay, sorted by count descending (`{"kinds": [{"kind": 1, "count": 12345}], "approximate": bool}`). The count walk examines at most 500,000 index entries; `approximate: true` when it was cut short.

### Top authors and relay lists

`GET /api/v1/relay/top-authors?limit=` — the most active authors on the relay, sorted by count descending (`{"authors": [{"pubkey": "<hex>", "count": 123}], "approximate": bool}`). The walk examines at most 500,000 index entries; `approximate: true` when it was cut short.

`GET /api/v1/{npub1...}/relays` — the author's latest NIP-65 relay list (kind 10002, replaceable — the newest event is the current list; the `r` tags carry the relay URLs).

### Monthly counts

`GET /api/v1/{npub1...}/{kind}/monthly` returns per-month event counts for an author's events of a kind, so a frontend can render e.g. `2026-08(4)`:

```json
{
  "months": [
    { "month": "2026-08", "count": 4, "approximate": false },
    { "month": "2026-09", "count": 0, "approximate": false }
  ],
  "total": 4
}
```

- `since` / `until` bound the range (unix seconds); without them the **whole period** is covered, from the earliest stored event of that author and kind to now (an author with no events returns an empty list).
- Every month in the range is reported, zero-filled, oldest first; the range is capped at **1200 months** (exceeding it returns `400`, as does `until < since`).
- `approximate: true` marks a month whose count hit the collection limit (`limits.max_count`), mirroring NIP-45.
- The same visibility rules as the rest of the API apply (protected events, gift wraps and private/hidden group content are withheld).

### `server.api_host` (host-based routing)

When `server.api_host` is configured (e.g. `api.example.com`), the API and the WebSocket relay are split by the **Host header**:

| Host header | `/api/v1`, `/health`, `/metrics` | WebSocket relay & NIP-11 |
| --- | --- | --- |
| `api.example.com` | served | `404` |
| any other host | `404` | served — the paths are selected by `server.ws_paths`: `/` by default, `/inbox` and `/outbox` in `inbox-outbox` mode, or all of them |

Without `api_host`, the API is served on every host, next to the WebSocket endpoint.

> **Note**: Only `GET` is supported. WebSocket upgrade requests to `/api/v1` are rejected with `403 Forbidden`.

---

## 2. Endpoints

### 2.1 `GET /api/v1/{identifier}`

`{identifier}` is a NIP-19 entity:

| Identifier | Returns | `limit` default |
| --- | --- | --- |
| `npub1...` | the author's latest kind-0 profile event | `1` (fixed) |
| `note1...` | the single event with this id | `1` (fixed) |
| `nevent1...` | the single event with this id (relays/author/kind hints ignored) | `1` (fixed) |
| `naddr1...` | events of the address: kind + author + `d` tag from the address | `100` |

### 2.2 `GET /api/v1/{identifier}/{kind}`

Only valid for `npub1...`. Returns events by the pubkey, filtered by `kind` (a decimal number).

```
GET /api/v1/npub1.../1        # notes
GET /api/v1/npub1.../7        # reactions
GET /api/v1/npub1.../30023    # long-form articles
```

Any other identifier with a kind path returns `400`.

---

## 3. Query Parameters

All parameters are optional and passed as URL query strings.

| Parameter | Type | Description |
| --- | --- | --- |
| `limit` | integer | Max results (default `100` for npub queries; capped by `limits.max_api_limit`; `0` in the config means "no bound") |
| `offset` | integer | Number of visible results to skip (pagination; capped by `limits.max_api_offset` — exceeding it returns `400`) |
| `since` | integer | Only events with `created_at >= since` |
| `until` | integer | Only events with `created_at <= until` |
| `sort` | string | `asc` or `ascending` = oldest first; anything else (default) = newest first |
| `search` | string | NIP-50 full-text search on content (whole-word matching; length capped by `limits.max_api_search_bytes` — exceeding it returns `400`) |
| `e` | string | Require an `e` tag with this value |
| `p` | string | Require a `p` tag with this value |
| `t` | string | Require a `t` tag with this value |
| `d` | string | Require a `d` tag with this value. For `naddr1...` the address's own `d` is used unless `d` is given (which overrides it) |
| `no_p` | boolean | Exclude events carrying a `p` tag (mentions, replies, DMs — `no_p=true` is a "top-level posts only" filter) |
| `no_e` | boolean | Exclude events carrying an `e` tag (replies) |
| `no_t` | boolean | Exclude events carrying a `t` tag (hashtags) |
| `no_d` | boolean | Exclude events carrying a `d` tag (addressable events) |

> **Exclusion note**: `no_*` filters are applied before pagination, like the visibility rules — excluded events never consume `limit` slots or offset steps. Multiple exclusions combine (e.g. `no_p=true&no_e=true` keeps only top-level posts).

> **Search note**: like the WebSocket path, search matches **whole words** — `search=ru` does not match the word "rust". When NIP-50 is disabled, `search` is silently ignored.

---

## 4. Response Format

Successful responses return `200 OK` with the following JSON body:

```json
{
  "events": [
    {
      "id": "32-byte hex event id",
      "pubkey": "32-byte hex pubkey",
      "created_at": 1700000000,
      "kind": 1,
      "tags": [["t", "example"]],
      "content": "hello",
      "sig": "64-byte hex signature"
    }
  ],
  "count": 1,
  "more": false
}
```

| Field | Description |
| --- | --- |
| `events` | The events of this page (newest first by default) |
| `count` | The number of events in this page |
| `more` | `true` when further pages exist (use `offset` to fetch them) |

---

## 5. Pagination

Pagination is done with `offset` and the `more` flag:

```
GET /api/v1/npub1.../1?limit=50&offset=0     # page 1
GET /api/v1/npub1.../1?limit=50&offset=50    # page 2 (when more was true)
```

Pagination is computed over the **visible** sequence (see [Visibility Rules](#6-visibility-rules)), so hidden events never skip or duplicate a page.

---

## 6. Visibility Rules

The API is unauthenticated, so it applies the same visibility rules as an **anonymous** WebSocket connection. The following events are withheld:

- **NIP-70 protected events** (carrying a `-` tag)
- **NIP-59 gift wraps** (kind 1059)
- **NIP-29 private/hidden group content** (visible only to members)

These events are excluded before pagination, so they do not consume `limit` slots or corrupt the `offset` sequence.

---

## 7. Error Responses

Errors return a JSON body with an `error` field:

```json
{"error": "invalid identifier: invalid bech32m checksum"}
```

| Error example | When |
| --- | --- |
| `invalid identifier: ...` | The NIP-19 identifier cannot be decoded (400) |
| `the endpoint requires an npub1 identifier or a 64-hex pubkey` | A kind path given with a note1/nevent1/naddr1 identifier, or an unrecognized path (400) |
| `offset exceeds the maximum of 10000` | `offset` above `max_api_offset` (400) |
| `search exceeds the maximum of 1024 bytes` | `search` longer than `max_api_search_bytes` (400) |
| `server is busy, try again shortly` | Too many concurrent API requests (`max_api_concurrent` reached) (503) |
| `not found` | The path does not exist, or the Host header does not match `api_host` (404) |

---

## 8. Status Codes

| Code | Meaning |
| --- | --- |
| `200` | Success |
| `400` | Invalid identifier or query parameter |
| `403` | WebSocket upgrade attempt to `/api/v1` |
| `404` | Unknown path, or wrong Host for the API (`api_host` configured) |
| `503` | API concurrency limit reached — retry shortly |

---

## 9. Examples

### Fetch a user's notes (newest first)

```bash
curl "http://127.0.0.1:8080/api/v1/npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkws3w8ktc/1"
```

### Paginate

```bash
curl "http://127.0.0.1:8080/api/v1/npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkws3w8ktc/1?limit=10&offset=10&sort=asc"
```

### Fetch a single event by id

```bash
# note1 or nevent1 both work
curl "http://127.0.0.1:8080/api/v1/note1..."
curl "http://127.0.0.1:8080/api/v1/nevent1..."
```

### Fetch an addressable event (naddr)

```bash
curl "http://127.0.0.1:8080/api/v1/naddr1..."
# override the d tag from the address:
curl "http://127.0.0.1:8080/api/v1/naddr1...?d=another-d"
```

### Search

```bash
curl "http://127.0.0.1:8080/api/v1/npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkws3w8ktc/1?search=rust"
```

### Tag filters

```bash
curl "http://127.0.0.1:8080/api/v1/npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkws3w8ktc/7?e=<event-id>&limit=100"
```

---

## Related

- [Manual (MANUAL.md)](MANUAL.md) — configuration reference for the API limits (`max_api_concurrent`, `max_api_limit`, `max_api_offset`, `max_api_search_bytes`)
- [Troubleshooting (TROUBLESHOOTING.md)](TROUBLESHOOTING.md)